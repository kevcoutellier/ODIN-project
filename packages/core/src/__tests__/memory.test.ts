import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { MemoryStore } from '../memory/store.js';
import { MerkleTree, sha256 } from '../memory/merkle.js';
import { IntegrityLevel, ConfidentialityLevel, type TaintLabel } from '../types.js';
import { existsSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const TEST_DB = join(tmpdir(), `odin-test-memory-${Date.now()}.db`);

const TRUSTED_LABEL: TaintLabel = {
  integrity: IntegrityLevel.TRUSTED,
  confidentiality: ConfidentialityLevel.PUBLIC,
  source: 'test',
  timestamp: Date.now(),
};

describe('MerkleTree', () => {
  it('computes sha256 correctly', () => {
    const hash = sha256('hello');
    expect(hash).toHaveLength(64); // 32 bytes hex
    expect(hash).toBe(sha256('hello')); // Deterministic
    expect(hash).not.toBe(sha256('world'));
  });

  it('builds tree and returns root', () => {
    const tree = new MerkleTree();
    tree.addLeaf('leaf1');
    tree.addLeaf('leaf2');
    const root = tree.getRoot();
    expect(root).toBeTruthy();
    expect(root.length).toBe(64);
  });

  it('root changes when new leaf is added', () => {
    const tree = new MerkleTree();
    tree.addLeaf('leaf1');
    const root1 = tree.getRoot();
    tree.addLeaf('leaf2');
    const root2 = tree.getRoot();
    expect(root1).not.toBe(root2);
  });

  it('generates valid proof', () => {
    const tree = new MerkleTree();
    const hash = tree.addLeaf('test-data');
    const proof = tree.getProof(hash);
    expect(proof).toBeTruthy();
  });
});

describe('MemoryStore', () => {
  let store: MemoryStore;

  beforeEach(async () => {
    store = new MemoryStore({ dbPath: TEST_DB, maxEntries: 100 });
    await store.init();
  });

  afterEach(async () => {
    await store.close();
    try { unlinkSync(TEST_DB); } catch {}
    try { unlinkSync(TEST_DB + '-wal'); } catch {}
    try { unlinkSync(TEST_DB + '-shm'); } catch {}
  });

  it('writes and reads entries', async () => {
    const entry = await store.write('session1', 'note', 'Hello world', TRUSTED_LABEL);
    expect(entry.id).toBeTruthy();
    expect(entry.content).toBe('Hello world');
    expect(entry.type).toBe('note');
    expect(entry.merkleHash).toHaveLength(64);
  });

  it('searches with FTS5', async () => {
    await store.write('s1', 'note', 'The quick brown fox jumps over the lazy dog', TRUSTED_LABEL);
    await store.write('s1', 'note', 'TypeScript is a superset of JavaScript', TRUSTED_LABEL);
    await store.write('s1', 'note', 'The lazy fox sleeps all day', TRUSTED_LABEL);

    const results = await store.search('fox');
    expect(results.length).toBeGreaterThanOrEqual(2);
    expect(results.every(r => r.content.toLowerCase().includes('fox'))).toBe(true);
  });

  it('gets entries by session', async () => {
    await store.write('sess-a', 'session', 'Message A', TRUSTED_LABEL);
    await store.write('sess-b', 'session', 'Message B', TRUSTED_LABEL);

    const sessA = await store.getBySession('sess-a');
    expect(sessA).toHaveLength(1);
    expect(sessA[0].content).toBe('Message A');
  });

  it('gets entries by type', async () => {
    await store.write('s1', 'note', 'My note', TRUSTED_LABEL);
    await store.write('s1', 'session', 'Chat message', TRUSTED_LABEL);

    const notes = await store.getByType('note');
    expect(notes).toHaveLength(1);
    expect(notes[0].content).toBe('My note');
  });

  it('enforces maxEntries', async () => {
    const small = new MemoryStore({ dbPath: TEST_DB + '-small', maxEntries: 3 });
    await small.init();

    for (let i = 0; i < 5; i++) {
      await small.write('s', 'note', `Entry ${i}`, TRUSTED_LABEL);
    }

    const all = await small.getBySession('s');
    expect(all.length).toBeLessThanOrEqual(3);
    await small.close();
    try { unlinkSync(TEST_DB + '-small'); } catch {}
  });

  it('computes Merkle root per session', async () => {
    await store.write('merkle-test', 'note', 'Data 1', TRUSTED_LABEL);
    const root = store.getMerkleRoot('merkle-test');
    expect(root).toBeTruthy();
    expect(root!.length).toBe(64);
  });

  it('sanitizes FTS5 query injection', async () => {
    await store.write('s1', 'note', 'test content', TRUSTED_LABEL);
    // These should not crash
    const r1 = await store.search('"DROP TABLE"');
    const r2 = await store.search('test OR (1=1)');
    const r3 = await store.search('hello*world');
    expect(Array.isArray(r1)).toBe(true);
    expect(Array.isArray(r2)).toBe(true);
  });
});
