import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { CIKInvariantVerifier } from '../invariants/formal.js';
import { CIKStore } from '../cik/stores.js';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { unlinkSync } from 'node:fs';

const TEST_DB = join(tmpdir(), `odin-test-invariants-${Date.now()}.db`);

describe('CIKInvariantVerifier', () => {
  let store: CIKStore;
  let verifier: CIKInvariantVerifier;

  beforeEach(async () => {
    store = new CIKStore(TEST_DB);
    await store.init();
    verifier = new CIKInvariantVerifier();
  });

  afterEach(async () => {
    await store.close();
    try { unlinkSync(TEST_DB); } catch {}
    try { unlinkSync(TEST_DB + '-wal'); } catch {}
    try { unlinkSync(TEST_DB + '-shm'); } catch {}
  });

  it('reports healthy on clean store', async () => {
    await store.setIdentity('did', 'did:odin:test', 'did', 'system', 'T1');
    const report = await verifier.verify(store);
    expect(report.overallHealth).toBe('healthy');
    expect(report.passed).toBeGreaterThan(0);
  });

  it('detects missing DID', async () => {
    const report = await verifier.verify(store);
    const identityResult = report.results.find(r => r.invariant === 'IDENTITY_IMMUTABILITY');
    expect(identityResult).toBeDefined();
    expect(identityResult!.passed).toBe(false);
    expect(identityResult!.violations[0].message).toContain('DID');
  });

  it('checks temporal ordering', async () => {
    await store.setIdentity('did', 'did:odin:ok', 'did', 'system', 'T1');
    await store.addKnowledge('A', 'is', 'B', 'user:direct', 'T1');

    const report = await verifier.verify(store);
    const temporal = report.results.find(r => r.invariant === 'TEMPORAL_ORDERING');
    expect(temporal).toBeDefined();
    expect(temporal!.passed).toBe(true); // Normal entries should pass
  });

  it('checks confidence bounds', async () => {
    await store.setIdentity('did', 'did:odin:ok', 'did', 'system', 'T1');
    await store.addKnowledge('Test', 'is', 'valid', 'user:direct', 'T1');

    const report = await verifier.verify(store);
    const bounds = report.results.find(r => r.invariant === 'CONFIDENCE_BOUNDS');
    expect(bounds).toBeDefined();
    expect(bounds!.passed).toBe(true);
  });

  it('generates invariant prompt', async () => {
    await store.setIdentity('did', 'did:odin:test', 'did', 'system', 'T1');
    await verifier.verify(store);
    const prompt = verifier.getInvariantPrompt();
    expect(prompt).toContain('CIK Formal Invariants');
    expect(prompt).toContain('HEALTHY');
  });

  it('stores verification history', async () => {
    await store.setIdentity('did', 'did:odin:test', 'did', 'system', 'T1');
    await verifier.verify(store);
    await verifier.verify(store);
    expect(verifier.getHistory()).toHaveLength(2);
  });

  it('supports custom invariants', async () => {
    verifier.addInvariant({
      id: 'CUSTOM_CHECK',
      name: 'Custom Check',
      description: 'Always passes',
      severity: 'info',
      check: async () => ({
        invariant: 'CUSTOM_CHECK',
        passed: true,
        violations: [],
        checkedAt: Date.now(),
        durationMs: 0,
      }),
    });

    await store.setIdentity('did', 'did:odin:test', 'did', 'system', 'T1');
    const report = await verifier.verify(store);
    const custom = report.results.find(r => r.invariant === 'CUSTOM_CHECK');
    expect(custom).toBeDefined();
    expect(custom!.passed).toBe(true);
  });
});
