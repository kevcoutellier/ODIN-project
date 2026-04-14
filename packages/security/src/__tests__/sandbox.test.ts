import { describe, it, expect } from 'vitest';
import { SandboxManager } from '../sandbox/manager.js';
import { IntegrityLevel, ConfidentialityLevel, type TaintLabel } from '@odin/core';

const TRUSTED_LABEL: TaintLabel = {
  integrity: IntegrityLevel.TRUSTED,
  confidentiality: ConfidentialityLevel.PUBLIC,
  source: 'test',
  timestamp: Date.now(),
};

describe('SandboxManager', () => {
  it('executes Ring 0 tasks (read-only)', async () => {
    const sandbox = new SandboxManager();
    const result = await sandbox.execute('test_tool', 0, async () => 'hello world', TRUSTED_LABEL);
    expect(result.success).toBe(true);
    expect(result.content).toBe('hello world');
  });

  it('executes Ring 2 tasks (full access)', async () => {
    const sandbox = new SandboxManager();
    const result = await sandbox.execute('full_tool', 2, async () => 'full result', TRUSTED_LABEL);
    expect(result.success).toBe(true);
    expect(result.content).toBe('full result');
  });

  it('catches task errors', async () => {
    const sandbox = new SandboxManager();
    const result = await sandbox.execute('bad_tool', 0, async () => {
      throw new Error('Task failed');
    }, TRUSTED_LABEL);
    expect(result.success).toBe(false);
    expect(result.content).toContain('Task failed');
  });

  it('applies correct taint labels per ring', async () => {
    const sandbox = new SandboxManager();
    // Ring 0 — output should be UNTRUSTED
    const r0 = await sandbox.execute('r0', 0, async () => 'data', TRUSTED_LABEL);
    expect(r0.label.integrity).toBe('UNTRUSTED');

    // Ring 2 — output inherits input integrity
    const r2 = await sandbox.execute('r2', 2, async () => 'data', TRUSTED_LABEL);
    expect(r2.label.integrity).toBe('TRUSTED');
  });

  it('respects timeout (Ring 0 = 5s)', async () => {
    const sandbox = new SandboxManager();
    const result = await sandbox.execute('slow_tool', 0, async () => {
      await new Promise(r => setTimeout(r, 10000));
      return 'never';
    }, TRUSTED_LABEL);
    expect(result.success).toBe(false);
    expect(result.content).toContain('timed out');
  }, 10000);
});
