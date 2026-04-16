/**
 * Sandbox Manager — Isolated execution environments
 *
 * Each tool call runs in a sandbox with three isolation levels:
 * - Ring 0: Read-only, no network (untrusted/unsigned skills)
 * - Ring 1: Read/write limited, controlled network (scanned SAFE)
 * - Ring 2: Full access with approval (signed + audited)
 *
 * Two execution backends are provided:
 *
 * - `execute(fn)` — in-process timeout wrapper. Fast, but no real isolation.
 *   Use for trusted in-tree tools where a bug in the tool should not crash
 *   the agent but memory is still shared.
 * - `executeIsolated(taskSpec)` — `child_process.fork`-based real isolate.
 *   Separate V8 heap, single-shot child, structured-clone IPC boundary,
 *   belt-and-braces SIGKILL timeout. Use for third-party skills and any
 *   tool whose trust tier < 2.
 *
 * For heavier workloads the agent can still be deployed inside a Docker /
 * gVisor container — that is an orchestration decision, not a runtime one.
 */

import type { SandboxRing, ToolResult, TaintLabel, IntegrityLevel, ConfidentialityLevel } from '@odin/core';
import { randomUUID } from 'node:crypto';
import { ForkSandbox, type ForkSandboxOptions, type ForkTaskSpec } from './fork-sandbox.js';

export interface SandboxConfig {
  ring: SandboxRing;
  timeoutMs: number;
  maxMemoryMb: number;
  allowNetwork: boolean;
  allowFileWrite: boolean;
  allowedPaths: string[];
}

export interface SandboxExecution {
  id: string;
  ring: SandboxRing;
  toolName: string;
  startTime: number;
  endTime?: number;
  status: 'running' | 'completed' | 'failed' | 'timeout';
}

const RING_CONFIGS: Record<SandboxRing, Partial<SandboxConfig>> = {
  0: {
    allowNetwork: false,
    allowFileWrite: false,
    maxMemoryMb: 64,
    timeoutMs: 5000,
    allowedPaths: [],
  },
  1: {
    allowNetwork: true,
    allowFileWrite: true,
    maxMemoryMb: 256,
    timeoutMs: 30000,
    allowedPaths: ['/tmp/odin'],
  },
  2: {
    allowNetwork: true,
    allowFileWrite: true,
    maxMemoryMb: 512,
    timeoutMs: 60000,
    allowedPaths: ['*'],
  },
};

export class SandboxManager {
  private executions: Map<string, SandboxExecution> = new Map();
  private fork: ForkSandbox;

  constructor(forkOpts: ForkSandboxOptions = {}) {
    this.fork = new ForkSandbox(forkOpts);
  }

  /**
   * Get the sandbox config for a given ring level.
   */
  getConfig(ring: SandboxRing): SandboxConfig {
    const defaults = RING_CONFIGS[ring];
    return {
      ring,
      timeoutMs: defaults.timeoutMs ?? 5000,
      maxMemoryMb: defaults.maxMemoryMb ?? 64,
      allowNetwork: defaults.allowNetwork ?? false,
      allowFileWrite: defaults.allowFileWrite ?? false,
      allowedPaths: defaults.allowedPaths ?? [],
    };
  }

  /**
   * Execute a tool function in a sandboxed environment.
   *
   * For the PoC, this uses a timeout wrapper and permission checks.
   * In production, this spawns a Docker/gVisor container.
   */
  async execute(
    toolName: string,
    ring: SandboxRing,
    fn: () => Promise<string>,
    inputLabel: TaintLabel,
  ): Promise<ToolResult> {
    const config = this.getConfig(ring);
    const executionId = randomUUID();
    const startTime = Date.now();

    const execution: SandboxExecution = {
      id: executionId,
      ring,
      toolName,
      startTime,
      status: 'running',
    };
    this.executions.set(executionId, execution);

    try {
      // Execute with timeout
      const result = await this.withTimeout(fn(), config.timeoutMs);

      execution.endTime = Date.now();
      execution.status = 'completed';

      return {
        toolCallId: executionId,
        content: result,
        label: {
          // Tool output inherits the lowest integrity between input and UNTRUSTED
          // (because external tools are untrusted by default)
          integrity: ring === 2 ? inputLabel.integrity : ('UNTRUSTED' as IntegrityLevel),
          confidentiality: inputLabel.confidentiality,
          source: `sandbox:ring${ring}:${toolName}`,
          timestamp: Date.now(),
        },
        success: true,
        executionTimeMs: execution.endTime - startTime,
      };
    } catch (error) {
      execution.endTime = Date.now();
      execution.status = error instanceof TimeoutError ? 'timeout' : 'failed';

      return {
        toolCallId: executionId,
        content: `Error: ${error instanceof Error ? error.message : String(error)}`,
        label: {
          integrity: 'UNTRUSTED' as IntegrityLevel,
          confidentiality: 'PUBLIC' as ConfidentialityLevel,
          source: `sandbox:ring${ring}:${toolName}:error`,
          timestamp: Date.now(),
        },
        success: false,
        executionTimeMs: (execution.endTime ?? Date.now()) - startTime,
      };
    } finally {
      // Cleanup completed/failed/timeout executions older than 5 minutes
      const fiveMinAgo = Date.now() - 5 * 60 * 1000;
      for (const [id, exec] of this.executions) {
        if (exec.status !== 'running' && exec.endTime && exec.endTime < fiveMinAgo) {
          this.executions.delete(id);
        }
      }
    }
  }

  /**
   * Execute a tool in a **separate process** via child_process.fork.
   *
   * Unlike `execute`, this accepts a serializable task spec (module path +
   * export + args) — no closures, because closures cannot cross process
   * boundaries. The child runs once and exits; crashes/timeouts are turned
   * into `success: false` results rather than thrown exceptions.
   */
  async executeIsolated(
    toolName: string,
    ring: SandboxRing,
    task: ForkTaskSpec,
    inputLabel: TaintLabel,
  ): Promise<ToolResult> {
    const config = this.getConfig(ring);
    const executionId = randomUUID();
    const startTime = Date.now();
    const execution: SandboxExecution = {
      id: executionId,
      ring,
      toolName,
      startTime,
      status: 'running',
    };
    this.executions.set(executionId, execution);

    const result = await this.fork.run({
      ring,
      toolName,
      task,
      timeoutMs: config.timeoutMs,
      inputLabel,
      allowedPaths: config.allowedPaths,
    });

    execution.endTime = Date.now();
    if (result.success) {
      execution.status = 'completed';
    } else if (
      result.label.source.endsWith(':timeout') ||
      /timed out/i.test(result.content)
    ) {
      execution.status = 'timeout';
    } else {
      execution.status = 'failed';
    }

    // Swap the tool-call id so callers that look up the execution find it.
    return { ...result, toolCallId: executionId };
  }

  getExecution(id: string): SandboxExecution | undefined {
    return this.executions.get(id);
  }

  getActiveExecutions(): SandboxExecution[] {
    return [...this.executions.values()].filter(e => e.status === 'running');
  }

  private async withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
    let timer: ReturnType<typeof setTimeout>;
    const timeoutPromise = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new TimeoutError(`Execution timed out after ${timeoutMs}ms`)), timeoutMs);
    });
    try {
      return await Promise.race([promise, timeoutPromise]);
    } finally {
      clearTimeout(timer!);
    }
  }
}

class TimeoutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TimeoutError';
  }
}
