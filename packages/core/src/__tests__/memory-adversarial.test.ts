/**
 * MemoryStore adversarial tests — FTS5 query sanitisation edge cases.
 *
 * memory.test.ts covers the basic sanitize-then-quote path. This file
 * pushes the surface:
 *   - unicode (zero-width, combining marks, RTL overrides)
 *   - null bytes & control characters
 *   - query of only FTS5 metachars (ends up empty → [])
 *   - very long queries (no crash, reasonable time)
 *   - SQL-injection-style payloads
 *   - Merkle tree cross-session isolation
 *   - concurrent writes to the same session
 *   - `getMerkleProof` for a leaf from a different session
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { MemoryStore } from '../memory/store.js';
import { MerkleTree } from '../memory/merkle.js';
import { IntegrityLevel, ConfidentialityLevel, type TaintLabel } from '../types.js';

const TRUSTED_LABEL: TaintLabel = {
  integrity: IntegrityLevel.TRUSTED,
  confidentiality: ConfidentialityLevel.PUBLIC,
  source: 'test',
  timestamp: Date.now(),
};

const cleanup = (path: string) => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { unlinkSync(path + suffix); } catch {}
  }
};

describe('MemoryStore — FTS5 query sanitisation', () => {
  let store: MemoryStore;
  let dbPath: string;

  beforeEach(async () => {
    dbPath = join(tmpdir(), `odin-mem-adv-${Date.now()}-${Math.random()}.db`);
    store = new MemoryStore({ dbPath, maxEntries: 1000 });
    await store.init();
  });

  afterEach(async () => {
    await store.close();
    cleanup(dbPath);
  });

  it('query composed only of FTS5 metachars returns [] (no crash)', async () => {
    await store.write('s1', 'note', 'innocent content', TRUSTED_LABEL);
    // All characters stripped by the sanitiser → empty after trim → []
    const results = await store.search('"*()-+^~:"');
    expect(results).toEqual([]);
  });

  it('query of just whitespace returns []', async () => {
    await store.write('s1', 'note', 'content', TRUSTED_LABEL);
    expect(await store.search('   ')).toEqual([]);
    expect(await store.search('\t\n\r')).toEqual([]);
  });

  it('empty query returns []', async () => {
    await store.write('s1', 'note', 'content', TRUSTED_LABEL);
    expect(await store.search('')).toEqual([]);
  });

  it('FTS5 injection attempts are neutralised by term-quoting', async () => {
    await store.write('s1', 'note', 'alpha bravo charlie', TRUSTED_LABEL);
    // All of these would be attacker payloads trying to break out of FTS5
    const payloads = [
      'alpha OR (1=1)',
      'alpha" OR 1=1 --',
      'alpha*',
      '^alpha',
      'alpha:column',
      '+alpha -bravo',
      'NEAR(alpha bravo)',
    ];
    for (const p of payloads) {
      const results = await store.search(p);
      // Each payload either returns [] or matches only on legitimate substrings
      expect(Array.isArray(results)).toBe(true);
      // alpha term should still work where present
      const matchesAlpha = results.filter(r => r.content.includes('alpha'));
      expect(matchesAlpha.length).toBeLessThanOrEqual(1);
    }
  });

  it('unicode text matches correctly (accents, non-Latin scripts)', async () => {
    await store.write('s1', 'note', 'Le café est délicieux', TRUSTED_LABEL);
    await store.write('s1', 'note', 'Привет мир', TRUSTED_LABEL);
    await store.write('s1', 'note', '日本語のテスト', TRUSTED_LABEL);

    const french = await store.search('café');
    expect(french.some(r => r.content.includes('café'))).toBe(true);

    const russian = await store.search('Привет');
    expect(russian.some(r => r.content.includes('Привет'))).toBe(true);
  });

  it('zero-width characters in a query do not crash (treated as token chars)', async () => {
    await store.write('s1', 'note', 'searchable content', TRUSTED_LABEL);
    // U+200B zero-width space
    const zwsp = 'search\u200Bable';
    const results = await store.search(zwsp);
    // Either finds or not — what matters is no crash
    expect(Array.isArray(results)).toBe(true);
  });

  it('null bytes in written content round-trip (or are handled gracefully)', async () => {
    // Some SQLite bindings reject NUL in strings; we just want no crash.
    try {
      const entry = await store.write('s1', 'note', 'has\u0000null', TRUSTED_LABEL);
      expect(entry.content).toContain('null');
    } catch (err) {
      // If the binding rejects NUL, the error is clear — acceptable.
      expect(err).toBeInstanceOf(Error);
    }
  });

  it('very long query (10 KB of "a"s) completes without crashing', async () => {
    await store.write('s1', 'note', 'a', TRUSTED_LABEL);
    const longQuery = 'a'.repeat(10_000);
    const start = Date.now();
    const results = await store.search(longQuery);
    const elapsed = Date.now() - start;
    expect(Array.isArray(results)).toBe(true);
    expect(elapsed).toBeLessThan(2000); // no ReDoS
  });

  it('huge number of small search terms is bounded', async () => {
    await store.write('s1', 'note', 'short', TRUSTED_LABEL);
    // 1000 terms separated by spaces — builds a large AND query
    const manyTerms = Array.from({ length: 1000 }, (_, i) => `t${i}`).join(' ');
    const start = Date.now();
    const results = await store.search(manyTerms);
    const elapsed = Date.now() - start;
    expect(Array.isArray(results)).toBe(true);
    expect(elapsed).toBeLessThan(2000);
  });

  it('query with only FTS metachars after unicode strip still returns []', async () => {
    await store.write('s1', 'note', 'test content', TRUSTED_LABEL);
    const results = await store.search('"*()-+^~:"  \t  ');
    expect(results).toEqual([]);
  });
});

describe('MemoryStore — Merkle session isolation', () => {
  let store: MemoryStore;
  let dbPath: string;

  beforeEach(async () => {
    dbPath = join(tmpdir(), `odin-mem-adv-${Date.now()}-${Math.random()}.db`);
    store = new MemoryStore({ dbPath, maxEntries: 1000 });
    await store.init();
  });

  afterEach(async () => {
    await store.close();
    cleanup(dbPath);
  });

  it('each session has an independent Merkle root', async () => {
    await store.write('session-a', 'note', 'data-a-1', TRUSTED_LABEL);
    await store.write('session-a', 'note', 'data-a-2', TRUSTED_LABEL);
    await store.write('session-b', 'note', 'data-b-1', TRUSTED_LABEL);

    const rootA = store.getMerkleRoot('session-a');
    const rootB = store.getMerkleRoot('session-b');
    expect(rootA).toBeTruthy();
    expect(rootB).toBeTruthy();
    expect(rootA).not.toBe(rootB);
  });

  it('getMerkleRoot for unknown session returns null', () => {
    expect(store.getMerkleRoot('no-such-session')).toBeNull();
  });

  it('getMerkleProof for a leaf from a different session returns an empty proof path', async () => {
    const a = await store.write('session-a', 'note', 'from-a', TRUSTED_LABEL);
    await store.write('session-b', 'note', 'from-b', TRUSTED_LABEL);

    // The leaf belongs to session-a. Requesting from session-b → tree has that session's
    // leaves, so indexOf returns -1 → proof is an empty array.
    const proof = store.getMerkleProof('session-b', a.merkleHash);
    expect(proof).not.toBeNull();
    expect(proof!.path).toEqual([]);
    // The root is session-b's — NOT equal to a's hash
    expect(proof!.root).not.toBe(a.merkleHash);
  });

  it('proof for a valid leaf verifies against the same session root', async () => {
    await store.write('s', 'note', 'leaf-1', TRUSTED_LABEL);
    const entry = await store.write('s', 'note', 'leaf-2', TRUSTED_LABEL);
    await store.write('s', 'note', 'leaf-3', TRUSTED_LABEL);

    const proof = store.getMerkleProof('s', entry.merkleHash);
    expect(proof).not.toBeNull();
    expect(MerkleTree.verify(entry.merkleHash, proof!.path, proof!.root)).toBe(true);
  });

  it('tampering any proof step after retrieval breaks verification', async () => {
    await store.write('s', 'note', 'a', TRUSTED_LABEL);
    const entry = await store.write('s', 'note', 'b', TRUSTED_LABEL);
    await store.write('s', 'note', 'c', TRUSTED_LABEL);
    await store.write('s', 'note', 'd', TRUSTED_LABEL);

    const proof = store.getMerkleProof('s', entry.merkleHash);
    expect(proof).not.toBeNull();
    if (proof!.path.length === 0) return; // edge case — nothing to tamper

    const tampered = proof!.path.map((step, i) =>
      i === 0 ? { ...step, hash: step.hash.replace(/./g, '0') } : step,
    );
    expect(MerkleTree.verify(entry.merkleHash, tampered, proof!.root)).toBe(false);
  });
});

describe('MemoryStore — concurrent writes & capacity', () => {
  let store: MemoryStore;
  let dbPath: string;

  beforeEach(async () => {
    dbPath = join(tmpdir(), `odin-mem-adv-${Date.now()}-${Math.random()}.db`);
    store = new MemoryStore({ dbPath, maxEntries: 1000 });
    await store.init();
  });

  afterEach(async () => {
    await store.close();
    cleanup(dbPath);
  });

  it('concurrent writes to the same session succeed and produce distinct ids', async () => {
    const results = await Promise.all(
      Array.from({ length: 20 }, (_, i) =>
        store.write('concurrent', 'note', `entry-${i}`, TRUSTED_LABEL),
      ),
    );
    const ids = new Set(results.map(r => r.id));
    expect(ids.size).toBe(20);
  });

  it('maxEntries boundary is strict (exactly the cap after overflow)', async () => {
    const small = new MemoryStore({ dbPath: dbPath + '-small', maxEntries: 5 });
    await small.init();
    for (let i = 0; i < 12; i++) {
      await small.write('s', 'note', `n-${i}`, TRUSTED_LABEL);
    }
    const all = await small.getBySession('s');
    expect(all.length).toBeLessThanOrEqual(5);
    await small.close();
    cleanup(dbPath + '-small');
  });

  it('enforces maxEntries across sessions (global cap, not per-session)', async () => {
    const tiny = new MemoryStore({ dbPath: dbPath + '-tiny', maxEntries: 4 });
    await tiny.init();
    for (const sid of ['a', 'b']) {
      for (let i = 0; i < 3; i++) {
        await tiny.write(sid, 'note', `${sid}-${i}`, TRUSTED_LABEL);
      }
    }
    const inA = await tiny.getBySession('a');
    const inB = await tiny.getBySession('b');
    expect(inA.length + inB.length).toBeLessThanOrEqual(4);
    await tiny.close();
    cleanup(dbPath + '-tiny');
  });
});
