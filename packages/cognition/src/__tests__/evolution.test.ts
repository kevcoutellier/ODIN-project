import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { EvolutionSandbox, SafetyGate } from '../evolution/sandbox.js';
import { CIKStore } from '../cik/stores.js';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { unlinkSync } from 'node:fs';

const TEST_DB = join(tmpdir(), `odin-test-evolution-${Date.now()}.db`);

describe('SafetyGate', () => {
  let store: CIKStore;
  let gate: SafetyGate;

  beforeEach(async () => {
    store = new CIKStore(TEST_DB);
    await store.init();
    gate = new SafetyGate();
  });

  afterEach(async () => {
    await store.close();
    try { unlinkSync(TEST_DB); } catch {}
    try { unlinkSync(TEST_DB + '-wal'); } catch {}
    try { unlinkSync(TEST_DB + '-shm'); } catch {}
  });

  it('blocks tier skip', async () => {
    const k = await store.addKnowledge('Fact', 'is', 'true', 'tool:x', 'T4');
    if ('error' in k) throw new Error('Failed');

    const result = await gate.evaluate(store, k.id, 'T4', 'T1', 'skip attempt');
    expect(result.passed).toBe(false);
    expect(result.overallRisk).toBe('critical');
  });

  it('blocks insufficient evidence', async () => {
    const k = await store.addKnowledge('Weak', 'is', 'unverified', 'tool:x', 'T4');
    if ('error' in k) throw new Error('Failed');

    // T4→T3 requires 2 verifications, this has 0
    const result = await gate.evaluate(store, k.id, 'T4', 'T3', 'no evidence');
    expect(result.passed).toBe(false);
    expect(result.checks.find(c => c.name === 'evidence')?.passed).toBe(false);
  });

  it('blocks T1 evolution from non-user source', async () => {
    const k = await store.addKnowledge('Auto', 'is', 'derived', 'tool:llm', 'T2');
    if ('error' in k) throw new Error('Failed');

    const result = await gate.evaluate(store, k.id, 'T2', 'T1', 'auto-promote');
    expect(result.passed).toBe(false);
    expect(result.checks.find(c => c.name === 'source')?.passed).toBe(false);
  });
});

describe('EvolutionSandbox', () => {
  let store: CIKStore;
  let sandbox: EvolutionSandbox;

  beforeEach(async () => {
    store = new CIKStore(TEST_DB);
    await store.init();
    sandbox = new EvolutionSandbox(store);
  });

  afterEach(async () => {
    await store.close();
    try { unlinkSync(TEST_DB); } catch {}
    try { unlinkSync(TEST_DB + '-wal'); } catch {}
    try { unlinkSync(TEST_DB + '-shm'); } catch {}
  });

  it('proposes and auto-rejects unsafe evolutions', async () => {
    const k = await store.addKnowledge('Test', 'is', 'new', 'tool:x', 'T4');
    if ('error' in k) throw new Error('Failed');

    const proposal = await sandbox.propose(k.id, 'T4', 'T3', 'no evidence');
    expect(proposal.status).toBe('rejected');
  });

  it('tracks proposals', async () => {
    const k = await store.addKnowledge('A', 'is', 'B', 'tool:x', 'T4');
    if ('error' in k) throw new Error('Failed');

    await sandbox.propose(k.id, 'T4', 'T3', 'test');
    expect(sandbox.getProposals()).toHaveLength(1);
  });

  it('rolls back proposals', async () => {
    const k = await store.addKnowledge('A', 'is', 'B', 'tool:x', 'T4');
    if ('error' in k) throw new Error('Failed');

    const proposal = await sandbox.propose(k.id, 'T4', 'T3', 'test');
    const result = sandbox.rollback(proposal.id);
    expect(result.success).toBe(true);
    expect(sandbox.getProposals()[0].status).toBe('rolled_back');
  });
});
