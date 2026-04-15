/**
 * AST-based static analysis for skill source code.
 *
 * Replaces regex pattern matching with a real JS parser to close trivial
 * obfuscation bypasses:
 *   - string concatenation of dangerous identifiers ("ev" + "al")
 *   - Function() / new Function() (equivalent to eval)
 *   - require() / import() with non-literal arguments (atob, Buffer.from, …)
 *   - bracket-notation member access (process["env"], obj["__" + "proto__"])
 *   - scheme concatenation in fetch URLs ('ht' + 'tp:')
 *   - patterns inside string literals or comments (no longer false positives —
 *     the walker only visits executable positions)
 *
 * When acorn cannot parse the source (TypeScript syntax, JSX, …) we return
 * `parseOk: false` and the caller falls back to the legacy regex path so we
 * never end up with *less* protection than before.
 */
import * as acorn from 'acorn';
import * as walk from 'acorn-walk';

export interface AstFinding {
  /** Stable rule identifier for tests and reporting. */
  rule: string;
  /** Human-readable description of what was detected. */
  message: string;
  /** 1-based line number in the source. */
  line: number;
}

export interface AstCheckResult {
  /** True when the source parsed as JS/ESM. False means the caller should fall back. */
  parseOk: boolean;
  findings: AstFinding[];
}

/** Node modules we never want a skill to pull in from user land. */
const DANGEROUS_MODULES = new Set([
  'fs',
  'fs/promises',
  'node:fs',
  'node:fs/promises',
  'child_process',
  'node:child_process',
  'cluster',
  'node:cluster',
  'net',
  'node:net',
  'dgram',
  'node:dgram',
  'vm',
  'node:vm',
]);

/**
 * Identifiers that, when accessed via bracket notation, indicate obfuscation.
 * Nobody writes `globalThis["eval"]` for legitimate reasons — direct use would
 * be `eval(…)`. Bracket access is how attackers smuggle these past regex.
 */
const DANGEROUS_BRACKET_IDENTIFIERS = new Set(['eval', 'Function']);

/**
 * Fold a string-producing expression down to its concrete value when possible.
 * Handles plain string literals, plain template literals (no interpolation),
 * and `+` concatenation trees. Returns null for anything dynamic.
 */
function foldString(node: acorn.Node | null | undefined): string | null {
  if (!node) return null;
  const n = node as unknown as {
    type: string;
    value?: unknown;
    operator?: string;
    left?: acorn.Node;
    right?: acorn.Node;
    expressions?: acorn.Node[];
    quasis?: Array<{ value: { cooked?: string | null } }>;
  };

  if (n.type === 'Literal' && typeof n.value === 'string') {
    return n.value;
  }
  if (n.type === 'TemplateLiteral' && n.expressions && n.expressions.length === 0 && n.quasis) {
    return n.quasis[0]?.value.cooked ?? null;
  }
  if (n.type === 'BinaryExpression' && n.operator === '+') {
    const left = foldString(n.left ?? null);
    const right = foldString(n.right ?? null);
    if (left !== null && right !== null) return left + right;
  }
  return null;
}

/**
 * Resolve the property name of a MemberExpression, handling both
 * `obj.foo` and `obj["foo"]` (including folded `obj["f" + "oo"]`).
 */
function resolvePropertyName(node: acorn.Node): string | null {
  const n = node as unknown as {
    computed: boolean;
    property: acorn.Node & { type: string; name?: string };
  };
  if (!n.computed) {
    return n.property?.name ?? null;
  }
  return foldString(n.property);
}

function lineOf(node: acorn.Node | undefined): number {
  const loc = (node as unknown as { loc?: { start?: { line?: number } } } | undefined)?.loc;
  return loc?.start?.line ?? 0;
}

export function runAstChecks(sourceCode: string): AstCheckResult {
  let ast: acorn.Node;
  try {
    ast = acorn.parse(sourceCode, {
      ecmaVersion: 'latest',
      sourceType: 'module',
      locations: true,
      allowHashBang: true,
      allowReturnOutsideFunction: true,
      allowAwaitOutsideFunction: true,
    });
  } catch {
    return { parseOk: false, findings: [] };
  }

  const findings: AstFinding[] = [];
  const push = (rule: string, message: string, node: acorn.Node | undefined) => {
    findings.push({ rule, message, line: lineOf(node) });
  };

  walk.simple(ast, {
    CallExpression(rawNode) {
      const node = rawNode as unknown as {
        callee: acorn.Node & { type: string; name?: string };
        arguments: acorn.Node[];
      };
      const callee = node.callee;

      // eval(...)
      if (callee.type === 'Identifier' && callee.name === 'eval') {
        push('eval-call', 'Direct eval() call', rawNode);
      }

      // Function(...) used as a call (same effect as eval)
      if (callee.type === 'Identifier' && callee.name === 'Function') {
        push('function-constructor', 'Function() used as constructor (equivalent to eval)', rawNode);
      }

      // require(...)
      if (callee.type === 'Identifier' && callee.name === 'require') {
        const arg = node.arguments[0];
        const folded = arg ? foldString(arg) : null;
        if (folded !== null) {
          if (DANGEROUS_MODULES.has(folded)) {
            push('require-dangerous-module', `require('${folded}') loads dangerous module`, rawNode);
          }
        } else if (arg) {
          // Non-literal argument — runtime-computed module name (atob, Buffer.from, variable, …)
          push(
            'require-dynamic',
            'require() with non-literal argument (possible obfuscation)',
            rawNode,
          );
        }
      }

      // fetch(...) — flag non-HTTPS URLs, including string-concat obfuscation
      if (callee.type === 'Identifier' && callee.name === 'fetch') {
        const arg = node.arguments[0];
        const folded = arg ? foldString(arg) : null;
        if (folded !== null && /^http:/i.test(folded)) {
          push('fetch-http', `fetch() uses non-HTTPS URL: ${folded}`, rawNode);
        }
      }
    },

    NewExpression(rawNode) {
      const node = rawNode as unknown as {
        callee: acorn.Node & { type: string; name?: string };
      };
      if (node.callee.type === 'Identifier' && node.callee.name === 'Function') {
        push('function-constructor', 'new Function() (equivalent to eval)', rawNode);
      }
    },

    MemberExpression(rawNode) {
      const node = rawNode as unknown as {
        object: acorn.Node & { type: string; name?: string };
        computed: boolean;
      };
      const propName = resolvePropertyName(rawNode);

      // process.env / process["env"] / process["en" + "v"]
      if (
        node.object?.type === 'Identifier' &&
        node.object.name === 'process' &&
        propName === 'env'
      ) {
        push('process-env', 'process.env access', rawNode);
      }

      // __proto__ access via either dot or bracket notation
      if (propName === '__proto__') {
        push('proto-access', '__proto__ access', rawNode);
      }

      // constructor reached via computed property (classic Function-chain escape)
      if (node.computed && propName === 'constructor') {
        push(
          'constructor-bracket',
          'constructor access via computed property (possible obfuscation)',
          rawNode,
        );
      }

      // Bracket-notation access to eval/Function — the canonical string-concat
      // bypass for the direct identifier check (e.g. globalThis["ev" + "al"]).
      if (node.computed && propName !== null && DANGEROUS_BRACKET_IDENTIFIERS.has(propName)) {
        push(
          'dangerous-identifier-bracket',
          `Bracket-notation access to dangerous identifier "${propName}"`,
          rawNode,
        );
      }
    },

    ImportDeclaration(rawNode) {
      const node = rawNode as unknown as { source: { value?: unknown } };
      const src = node.source?.value;
      if (typeof src === 'string' && DANGEROUS_MODULES.has(src)) {
        push('import-dangerous-module', `import from '${src}' (dangerous module)`, rawNode);
      }
    },

    // Dynamic import() — acorn emits this as a dedicated ImportExpression node,
    // NOT a CallExpression with an Import callee.
    ImportExpression(rawNode) {
      const node = rawNode as unknown as { source: acorn.Node };
      const folded = foldString(node.source ?? null);
      if (folded !== null) {
        if (DANGEROUS_MODULES.has(folded)) {
          push('import-dangerous-module', `import('${folded}') loads dangerous module`, rawNode);
        }
      } else {
        push('import-dynamic', 'Dynamic import() with non-literal argument', rawNode);
      }
    },
  });

  return { parseOk: true, findings };
}
