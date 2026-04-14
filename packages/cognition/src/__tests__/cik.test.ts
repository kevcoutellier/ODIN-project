import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { CIKStore, CIKPolicyEngine, TRUST_TIER_CONFIDENCE } from '../cik/stores.js';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { unlinkSync } from 'node:fs';

const TEST_DB = join(tmpdir(), `odin-test-cik-${Date.now()}.db`);

describe('CIKPolicyEngine', () => {
  it('permits by default', () => {
    const engine = new CIKPolicyEngine();
    const result = engine.evaluate('knowledge', 'read', {});
    expect(result.allowed).toBe(true);
  });

  it('forbids T1 knowledge write from non-user source', () => {
    const engine = new CIKPolicyEngine();
    const result = engine.evaluate('knowledge', 'write', { tier: 'T1', source: 'tool:web' });
    expect(result.allowed).toBe(false);
    expect(result.policyId).toBe('cik-knowledge-t1-write');
  });

  it('allows T1 knowledge write from user', () => {
    const engine = new CIKPolicyEngine();
    const result = engine.evaluate('knowledge', 'write', { tier: 'T1', source: 'user:direct' });
    expect(result.allowed).toBe(true);
  });

  it('forbids T4→T1 tier skip', () => {
    const engine = new CIKPolicyEngine();
    const result = engine.evaluate('knowledge', 'evolve', { currentTier: 'T4', targetTier: 'T1' });
    expect(result.allowed).toBe(false);
  });

  it('forbids DID modification', () => {
    const engine = new CIKPolicyEngine();
    const result = engine.evaluate('identity', 'write', { key: 'did', exists: true });
    expect(result.allowed).toBe(false);
  });
});

describe('CIKStore', () => {
  let store: CIKStore;

  beforeEach(async () => {
    store = new CIKStore(TEST_DB);
    await store.init();
  });

  afterEach(async () => {
    await store.close();
    try { unlinkSync(TEST_DB); } catch {}
    try { unlinkSync(TEST_DB + '-wal'); } catch {}
    try { unlinkSync(TEST_DB + '-shm'); } catch {}
  });

  // ─── Capabilities ───

  it('adds capabilities', async () => {
    const result = await store.addCapability({
      name: 'shell_exec', type: 'tool', description: 'Execute shell commands',
      successRate: 0.9, usageCount: 10, lastUsed: Date.now(), tier: 'T2',
    });
    expect('error' in result).toBe(false);
    if (!('error' in result)) {
      expect(result.name).toBe('shell_exec');
      expect(result.tier).toBe('T2');
    }
  });

  it('records capability usage', async () => {
    await store.addCapability({
      name: 'web_search', type: 'tool', description: 'Search the web',
      successRate: 1.0, usageCount: 0, lastUsed: 0, tier: 'T2',
    });
    await store.recordCapabilityUsage('web_search', true);
    await store.recordCapabilityUsage('web_search', false);

    const caps = await store.getCapabilities();
    const ws = caps.find(c => c.name === 'web_search');
    expect(ws).toBeDefined();
    expect(ws!.usageCount).toBe(2);
    expect(ws!.successRate).toBe(0.5); // 1 success / 2 total
  });

  // ─── Identity ───

  it('sets identity entries', async () => {
    const result = await store.setIdentity('did', 'did:odin:abc123', 'did', 'system', 'T1');
    expect('error' in result).toBe(false);
    if (!('error' in result)) {
      expect(result.key).toBe('did');
      expect(result.value).toBe('did:odin:abc123');
    }
  });

  it('retrieves identity by key', async () => {
    await store.setIdentity('name', 'Odin', 'preference', 'user', 'T1');
    const entry = await store.getIdentity('name');
    expect(entry).not.toBeNull();
    expect(entry!.value).toBe('Odin');
  });

  it('blocks DID modification (policy)', async () => {
    await store.setIdentity('did', 'did:odin:first', 'did', 'system');
    const result = await store.setIdentity('did', 'did:odin:tampered', 'did', 'attacker');
    expect('error' in result).toBe(true);
  });

  // ─── Knowledge ───

  it('adds knowledge triples', async () => {
    const result = await store.addKnowledge('TypeScript', 'is_a', 'programming language', 'user:direct', 'T1');
    expect('error' in result).toBe(false);
    if (!('error' in result)) {
      expect(result.subject).toBe('TypeScript');
      expect(result.confidence).toBe(TRUST_TIER_CONFIDENCE.T1);
    }
  });

  it('reinforces existing knowledge', async () => {
    await store.addKnowledge('Python', 'is_a', 'language', 'user:direct', 'T1');
    const reinforced = await store.addKnowledge('Python', 'is_a', 'language', 'tool:verify', 'T2');
    if (!('error' in reinforced)) {
      expect(reinforced.verifications).toBe(1);
    }
  });

  it('detects contradictions', async () => {
    await store.addKnowledge('Earth', 'shape', 'sphere', 'user:direct', 'T1');
    await store.addKnowledge('Earth', 'shape', 'flat', 'external:bad', 'T4');
    // The T4 entry should have been created, and the contradiction recorded
    const about = await store.getKnowledgeAbout('Earth');
    expect(about.length).toBe(2);
  });

  it('searches knowledge with FTS', async () => {
    await store.addKnowledge('Node.js', 'uses', 'V8 engine', 'user:direct', 'T1');
    await store.addKnowledge('Deno', 'uses', 'V8 engine', 'user:direct', 'T1');

    const results = await store.queryKnowledge('V8 engine');
    expect(results.length).toBeGreaterThanOrEqual(2);
  });

  it('blocks T1 write from non-user source', async () => {
    const result = await store.addKnowledge('Test', 'is', 'blocked', 'tool:web', 'T1');
    expect('error' in result).toBe(true);
  });

  // ─── Tier Evolution ───

  it('evolves knowledge tier one step at a time', async () => {
    const k = await store.addKnowledge('Fact', 'status', 'verified', 'tool:check', 'T4');
    if ('error' in k) throw new Error('Failed to add knowledge');

    const result = await store.evolveKnowledgeTier(k.id, 'T3', 'Verified by tool');
    expect(result.success).toBe(true);
    expect(result.message).toContain('T4 → T3');
  });

  it('blocks tier skip', async () => {
    const k = await store.addKnowledge('Skip', 'test', 'skip', 'tool:x', 'T4');
    if ('error' in k) throw new Error('Failed');

    const result = await store.evolveKnowledgeTier(k.id, 'T1', 'Trying to skip');
    expect(result.success).toBe(false);
    expect(result.message).toContain('skip');
  });

  // ─── Stats ───

  it('returns accurate stats', async () => {
    await store.addKnowledge('A', 'is', 'B', 'user:direct', 'T1');
    await store.addKnowledge('C', 'is', 'D', 'tool:x', 'T4');
    await store.setIdentity('name', 'Odin', 'preference', 'system');

    const stats = store.getStats();
    expect(stats.knowledge).toBe(2);
    expect(stats.identity).toBeGreaterThanOrEqual(1);
    expect(stats.knowledgeByTier).toHaveProperty('T1', 1);
    expect(stats.knowledgeByTier).toHaveProperty('T4', 1);
  });
});
