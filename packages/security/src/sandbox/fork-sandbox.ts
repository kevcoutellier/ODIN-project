/**
 * ForkSandbox — Real process-level isolation via child_process.fork
 *
 * Unlike the in-process `SandboxManager.execute` (which is a timeout wrapper
 * only), this runs the tool in a **separate Node.js process**:
 *
 *   - Memory is isolated — a crash or OOM in the child does not take down
 *     the agent.
 *   - The IPC channel only accepts structured-cloneable messages, so the
 *     child cannot return closures / symbols / live references back to the
 *     parent.
 *   - The child runs a single task then exits (`setImmediate(() => exit(0))`)
 *     — no cross-task state leaks, no long-lived child to take over.
 *   - Timeouts are enforced twice: once inside the child (Promise.race) and
 *     once in the parent via SIGKILL, so a stuck task is always reaped.
 *   - Node's experimental `--permission` model can be enabled per-ring to
 *     restrict filesystem access. Network egress is out of scope for the
 *     permission model and must still be enforced at the policy layer.
 *
 * This is intentionally a small, auditable surface (~200 lines) — it is not
 * a replacement for gVisor/Docker for production workloads, but it is a real
 * isolate, not a marketing claim.
 */

import { fork, type ChildProcess } from 'node:child_process';
import { mkdir, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import {
  type ConfidentialityLevel,
  type IntegrityLevel,
  type SandboxRing,
  type TaintLabel,
  type ToolResult,
} from '@odin/core';

/**
 * Auto-materialized runner. Kept as a plain string so the compiled package
 * has no extra asset files to ship — we write it to tmpdir() on first use.
 * The filename includes a content hash, so bumping this source forces a
 * rematerialization and the next fork() picks up the new code.
 */
const RUNNER_SOURCE = String.raw`/* odin fork-runner — auto-generated, do not edit */
if (!process.send) { console.error('[odin-fork-runner] must be forked via child_process.fork'); process.exit(2); }
try { process.stdin && process.stdin.destroy && process.stdin.destroy(); } catch (_) {}

let handled = false;
process.on('message', async (m) => {
  if (handled) return;
  handled = true;
  const start = Date.now();
  try {
    if (!m || typeof m.modulePath !== 'string' || typeof m.exportName !== 'string') {
      throw new Error('invalid task spec');
    }
    const mod = await import(m.modulePath);
    const fn = mod[m.exportName];
    if (typeof fn !== 'function') {
      throw new Error('export "' + m.exportName + '" is not a function in ' + m.modulePath);
    }
    const timeoutMs = Math.max(1, Number(m.timeoutMs) || 5000);
    const timeout = new Promise((_, reject) => {
      const t = setTimeout(() => reject(new Error('timed out after ' + timeoutMs + 'ms')), timeoutMs);
      if (t && t.unref) t.unref();
    });
    const args = Array.isArray(m.args) ? m.args : [];
    const value = await Promise.race([
      Promise.resolve().then(() => fn.apply(null, args)),
      timeout,
    ]);
    process.send({ id: m.id, ok: true, value, elapsedMs: Date.now() - start });
  } catch (e) {
    const message = (e && e.message) ? String(e.message) : String(e);
    process.send({ id: m.id, ok: false, error: message, elapsedMs: Date.now() - start });
  } finally {
    setImmediate(() => process.exit(0));
  }
});
`;

let runnerPathCache: string | null = null;

async function materializeRunner(): Promise<string> {
  if (runnerPathCache && existsSync(runnerPathCache)) return runnerPathCache;
  const hash = createHash('sha256').update(RUNNER_SOURCE).digest('hex').slice(0, 12);
  const dir = join(tmpdir(), 'odin-sandbox');
  const file = join(dir, `fork-runner.${hash}.mjs`);
  if (!existsSync(file)) {
    await mkdir(dir, { recursive: true });
    await writeFile(file, RUNNER_SOURCE, 'utf-8');
  }
  runnerPathCache = file;
  return file;
}

export interface ForkTaskSpec {
  /** Absolute path or a specifier resolvable in the child's import graph. */
  modulePath: string;
  /** Named export of the module. Must be a function accepting `args`. */
  exportName: string;
  /** Arguments to pass. Must be structured-cloneable (no functions/symbols). */
  args: unknown[];
}

export interface ForkSandboxOptions {
  /**
   * Enable Node's experimental `--permission` model on the child. Filesystem
   * access is restricted per ring; network egress still goes through the
   * policy layer (no OS-level block here).
   */
  usePermissionModel?: boolean;
  /** Override where the runner script is written. Defaults to os.tmpdir(). */
  runnerPathOverride?: string;
}

function execArgvForRing(
  ring: SandboxRing,
  usePermission: boolean,
  allowedPaths: string[],
): string[] {
  if (!usePermission) return [];
  const flags: string[] = ['--permission'];
  if (ring === 2) {
    flags.push('--allow-fs-read=*', '--allow-fs-write=*');
    return flags;
  }
  // Ring 0/1: read is required to import the target module; we widen read
  // and narrow write. Callers should still pass `allowedPaths` tightly.
  flags.push('--allow-fs-read=*');
  if (ring === 1) {
    for (const p of allowedPaths) flags.push(`--allow-fs-write=${p}`);
  }
  return flags;
}

interface ChildResponse {
  id?: unknown;
  ok?: unknown;
  value?: unknown;
  error?: unknown;
  elapsedMs?: unknown;
}

function integrityFor(ring: SandboxRing, input: TaintLabel): IntegrityLevel {
  return (ring === 2 ? input.integrity : 'UNTRUSTED') as IntegrityLevel;
}

export class ForkSandbox {
  constructor(private readonly opts: ForkSandboxOptions = {}) {}

  /**
   * Run a named export of a module in a forked child. Resolves with a
   * `ToolResult` — never throws. Timeouts and crashes are captured and
   * reported as `success: false`.
   */
  async run(params: {
    ring: SandboxRing;
    toolName: string;
    task: ForkTaskSpec;
    timeoutMs: number;
    inputLabel: TaintLabel;
    allowedPaths?: string[];
  }): Promise<ToolResult> {
    const executionId = randomUUID();
    const start = Date.now();
    const runner = this.opts.runnerPathOverride ?? (await materializeRunner());
    const execArgv = execArgvForRing(
      params.ring,
      !!this.opts.usePermissionModel,
      params.allowedPaths ?? [],
    );

    const inheritedPath = process.env.PATH ?? '';
    const childEnv: NodeJS.ProcessEnv = {
      NODE_ENV: process.env.NODE_ENV ?? 'production',
      PATH: inheritedPath,
    };

    let child: ChildProcess | undefined;
    let settled = false;

    return new Promise<ToolResult>((resolve) => {
      const finish = (result: ToolResult) => {
        if (settled) return;
        settled = true;
        clearTimeout(hardKillTimer);
        if (child && !child.killed && child.exitCode === null) {
          try { child.kill('SIGKILL'); } catch { /* ignore */ }
        }
        resolve(result);
      };

      const makeErrorResult = (msg: string, src: string): ToolResult => ({
        toolCallId: executionId,
        content: `Error: ${msg}`,
        label: {
          integrity: 'UNTRUSTED' as IntegrityLevel,
          confidentiality: 'PUBLIC' as ConfidentialityLevel,
          source: `fork-sandbox:ring${params.ring}:${params.toolName}:${src}`,
          timestamp: Date.now(),
        },
        success: false,
        executionTimeMs: Date.now() - start,
      });

      try {
        child = fork(runner, [], {
          execArgv,
          silent: true,
          serialization: 'advanced',
          env: childEnv,
          stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
        });
      } catch (err) {
        finish(makeErrorResult(
          err instanceof Error ? err.message : String(err),
          'spawn',
        ));
        return;
      }

      // Parent-side hard-kill — SIGKILL if the child is still alive after
      // timeoutMs + slack. Belt-and-braces for a child that ignores signals.
      const hardKillTimer = setTimeout(() => {
        if (child && !child.killed) {
          try { child.kill('SIGKILL'); } catch { /* ignore */ }
        }
      }, params.timeoutMs + 500);

      child.on('message', (msg: ChildResponse) => {
        if (!msg || msg.id !== executionId) return;
        if (msg.ok === true) {
          const value = (msg as { value: unknown }).value;
          finish({
            toolCallId: executionId,
            content: typeof value === 'string' ? value : JSON.stringify(value),
            label: {
              integrity: integrityFor(params.ring, params.inputLabel),
              confidentiality: params.inputLabel.confidentiality,
              source: `fork-sandbox:ring${params.ring}:${params.toolName}`,
              timestamp: Date.now(),
            },
            success: true,
            executionTimeMs: Date.now() - start,
          });
        } else {
          finish(makeErrorResult(String(msg.error ?? 'unknown error'), 'task'));
        }
      });

      child.on('exit', (code, signal) => {
        if (settled) return;
        if (signal === 'SIGKILL') {
          finish(makeErrorResult(`timed out after ${params.timeoutMs}ms`, 'timeout'));
        } else {
          finish(makeErrorResult(`child exited code=${code} signal=${signal ?? 'none'}`, 'exit'));
        }
      });

      child.on('error', (err) => {
        finish(makeErrorResult(err.message, 'ipc'));
      });

      child.send({
        id: executionId,
        modulePath: params.task.modulePath,
        exportName: params.task.exportName,
        args: params.task.args,
        timeoutMs: params.timeoutMs,
      });
    });
  }
}
