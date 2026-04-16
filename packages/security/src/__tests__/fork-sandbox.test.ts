import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import { SandboxManager, ForkSandbox } from '../sandbox/index.js';
import { IntegrityLevel, ConfidentialityLevel, type TaintLabel } from '@odin/core';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const FIXTURE = pathToFileURL(join(__dirname, 'fixtures', 'fork-target.mjs')).href;

const TRUSTED_LABEL: TaintLabel = {
  integrity: IntegrityLevel.TRUSTED,
  confidentiality: ConfidentialityLevel.PUBLIC,
  source: 'test',
  timestamp: Date.now(),
};

describe('ForkSandbox (real process isolation)', () => {
  const originalEnv = { ...process.env };
  beforeEach(() => {
    process.env.ODIN_SECRET_DB_URL = 'postgres://secret';
    process.env.ODIN_SECRET_API_KEY = 'sk-shouldnotleak';
  });
  afterEach(() => {
    process.env = { ...originalEnv };
  });

  it('runs a module export in a forked child and returns the value', async () => {
    const fork = new ForkSandbox();
    const result = await fork.run({
      ring: 0,
      toolName: 'echo',
      task: { modulePath: FIXTURE, exportName: 'echo', args: ['hello'] },
      timeoutMs: 5000,
      inputLabel: TRUSTED_LABEL,
    });
    expect(result.success).toBe(true);
    expect(result.content).toBe('hello');
  });

  it('serializes non-string return values as JSON', async () => {
    const fork = new ForkSandbox();
    const result = await fork.run({
      ring: 0,
      toolName: 'addOne',
      task: { modulePath: FIXTURE, exportName: 'addOne', args: [41] },
      timeoutMs: 5000,
      inputLabel: TRUSTED_LABEL,
    });
    expect(result.success).toBe(true);
    expect(result.content).toBe('42');
  });

  it('captures thrown errors without crashing the parent', async () => {
    const fork = new ForkSandbox();
    const result = await fork.run({
      ring: 0,
      toolName: 'boom',
      task: { modulePath: FIXTURE, exportName: 'boom', args: [] },
      timeoutMs: 5000,
      inputLabel: TRUSTED_LABEL,
    });
    expect(result.success).toBe(false);
    expect(result.content).toContain('deliberate failure');
  });

  it('kills the child when it exceeds the ring timeout', async () => {
    const fork = new ForkSandbox();
    const result = await fork.run({
      ring: 0,
      toolName: 'slow',
      task: { modulePath: FIXTURE, exportName: 'slow', args: [3000] },
      timeoutMs: 300,
      inputLabel: TRUSTED_LABEL,
    });
    expect(result.success).toBe(false);
    expect(result.content.toLowerCase()).toContain('timed out');
  }, 8000);

  it('does not inherit parent env secrets (ODIN_SECRET_* unset in child)', async () => {
    const fork = new ForkSandbox();
    const result = await fork.run({
      ring: 0,
      toolName: 'leakEnv',
      task: { modulePath: FIXTURE, exportName: 'leakEnv', args: [] },
      timeoutMs: 5000,
      inputLabel: TRUSTED_LABEL,
    });
    expect(result.success).toBe(true);
    const leaked = JSON.parse(result.content);
    expect(leaked.hasDbUrl).toBe(false);
    expect(leaked.hasApiKey).toBe(false);
  });

  it('fails cleanly when the requested export is not a function', async () => {
    const fork = new ForkSandbox();
    const result = await fork.run({
      ring: 0,
      toolName: 'missing',
      task: { modulePath: FIXTURE, exportName: 'doesNotExist', args: [] },
      timeoutMs: 5000,
      inputLabel: TRUSTED_LABEL,
    });
    expect(result.success).toBe(false);
    expect(result.content).toContain('not a function');
  });

  it('Ring 0 output is tagged UNTRUSTED; Ring 2 inherits input integrity', async () => {
    const fork = new ForkSandbox();
    const r0 = await fork.run({
      ring: 0,
      toolName: 'echo',
      task: { modulePath: FIXTURE, exportName: 'echo', args: ['ok'] },
      timeoutMs: 5000,
      inputLabel: TRUSTED_LABEL,
    });
    expect(r0.label.integrity).toBe('UNTRUSTED');

    const r2 = await fork.run({
      ring: 2,
      toolName: 'echo',
      task: { modulePath: FIXTURE, exportName: 'echo', args: ['ok'] },
      timeoutMs: 5000,
      inputLabel: TRUSTED_LABEL,
    });
    expect(r2.label.integrity).toBe('TRUSTED');
  });
});

describe('SandboxManager.executeIsolated', () => {
  it('routes through ForkSandbox and tracks the execution', async () => {
    const mgr = new SandboxManager();
    const result = await mgr.executeIsolated(
      'echo',
      1,
      { modulePath: FIXTURE, exportName: 'echo', args: ['via-manager'] },
      TRUSTED_LABEL,
    );
    expect(result.success).toBe(true);
    expect(result.content).toBe('via-manager');

    const exec = mgr.getExecution(result.toolCallId);
    expect(exec).toBeDefined();
    expect(exec?.status).toBe('completed');
  });

  it('flags timeout status on the tracked execution', async () => {
    const mgr = new SandboxManager();
    // Ring 0 has a 5000 ms timeout; 8000 ms exceeds it and should trigger SIGKILL.
    const result = await mgr.executeIsolated(
      'slow',
      0,
      { modulePath: FIXTURE, exportName: 'slow', args: [8000] },
      TRUSTED_LABEL,
    );
    expect(result.success).toBe(false);
    const exec = mgr.getExecution(result.toolCallId);
    expect(exec?.status).toBe('timeout');
  }, 12000);
});
