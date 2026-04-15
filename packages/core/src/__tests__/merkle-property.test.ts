/**
 * Merkle property-based tests — fuzz over tree sizes and tampering vectors.
 *
 * Complements merkle.test.ts (hand-written cases) with randomised checks
 * that scale across many shapes. Uses a seeded PRNG for reproducibility.
 *
 * Invariants tested (for all shapes):
 *   1. Round-trip: every leaf's proof verifies against the tree root.
 *   2. Anti-tamper: flipping the leaf, any proof step hash, any proof
 *      step position, or the root hash breaks verification.
 *   3. Order sensitivity: permuting leaves yields a different root.
 *   4. Idempotence: getRoot() is stable across repeated calls.
 *   5. Inclusion scoping: a proof for leaf X does not verify leaf Y.
 */

import { describe, it, expect } from 'vitest';
import { MerkleTree, sha256 } from '../memory/merkle.js';

/** Mulberry32 — small, seeded, uniform PRNG. */
function makeRng(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function buildTree(leafValues: string[]): { tree: MerkleTree; hashes: string[]; root: string } {
  const tree = new MerkleTree();
  const hashes = leafValues.map(v => tree.addLeaf(v));
  return { tree, hashes, root: tree.getRoot() };
}

const SIZES = [1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 31, 32, 33, 50];

describe('MerkleTree — property: round-trip verification', () => {
  for (const n of SIZES) {
    it(`every leaf's proof verifies for a tree of size ${n}`, () => {
      const rng = makeRng(1234 + n);
      const leaves = Array.from({ length: n }, (_, i) => `L${i}:${rng().toFixed(12)}`);
      const { tree, hashes, root } = buildTree(leaves);

      for (const h of hashes) {
        const proof = tree.getProof(h);
        expect(MerkleTree.verify(h, proof, root)).toBe(true);
      }
    });
  }
});

describe('MerkleTree — property: anti-tamper (random fuzzing)', () => {
  it('flipping a random byte in the leaf hash breaks verification', () => {
    const rng = makeRng(42);
    for (let trial = 0; trial < 20; trial++) {
      const n = 2 + Math.floor(rng() * 30);
      const leaves = Array.from({ length: n }, (_, i) => `entry-${i}-${rng()}`);
      const { tree, hashes, root } = buildTree(leaves);
      const targetIdx = Math.floor(rng() * n);
      const targetHash = hashes[targetIdx];
      const proof = tree.getProof(targetHash);
      // Flip one hex char of the leaf hash (guarantees different hash)
      const tampered = targetHash.slice(0, -1) + (targetHash.slice(-1) === '0' ? '1' : '0');
      expect(MerkleTree.verify(tampered, proof, root)).toBe(false);
    }
  });

  it('flipping any single proof-step hash breaks verification', () => {
    const rng = makeRng(99);
    for (let trial = 0; trial < 15; trial++) {
      const n = 4 + Math.floor(rng() * 20);
      const leaves = Array.from({ length: n }, (_, i) => `e-${i}-${rng()}`);
      const { tree, hashes, root } = buildTree(leaves);
      const targetIdx = Math.floor(rng() * n);
      const targetHash = hashes[targetIdx];
      const proof = tree.getProof(targetHash);
      if (proof.length === 0) continue; // single-leaf tree has empty proof

      // Try flipping every proof step, one at a time
      for (let i = 0; i < proof.length; i++) {
        const tampered = proof.map((step, j) =>
          j === i ? { ...step, hash: sha256(step.hash + 'evil') } : step,
        );
        expect(MerkleTree.verify(targetHash, tampered, root)).toBe(false);
      }
    }
  });

  it('inverting a proof-step position breaks verification for power-of-2 trees (no padding)', () => {
    // Note: for odd-size trees, padding duplicates the last hash; at the
    // padded level, flipping position yields the same result because both
    // siblings are identical. We therefore restrict this property to
    // power-of-2 sizes, where every sibling is distinct.
    const rng = makeRng(7);
    const powerOf2Sizes = [2, 4, 8, 16];
    for (const n of powerOf2Sizes) {
      const leaves = Array.from({ length: n }, (_, i) => `p-${i}-${rng()}`);
      const { tree, hashes, root } = buildTree(leaves);
      for (const h of hashes) {
        const proof = tree.getProof(h);
        for (let i = 0; i < proof.length; i++) {
          const flipped = proof.map((step, j) =>
            j === i
              ? { ...step, position: (step.position === 'left' ? 'right' : 'left') as 'left' | 'right' }
              : step,
          );
          expect(MerkleTree.verify(h, flipped, root)).toBe(false);
        }
      }
    }
  });

  it('replacing a proof step (hash + position) with random garbage breaks verification', () => {
    // Universal invariant: regardless of padding, if both the hash AND the
    // position of a step are replaced with random values, the proof cannot
    // coincidentally re-verify.
    const rng = makeRng(101);
    for (let trial = 0; trial < 25; trial++) {
      const n = 3 + Math.floor(rng() * 20);
      const leaves = Array.from({ length: n }, (_, i) => `q-${i}-${rng()}`);
      const { tree, hashes, root } = buildTree(leaves);
      const h = hashes[Math.floor(rng() * n)];
      const proof = tree.getProof(h);
      if (proof.length === 0) continue;

      const i = Math.floor(rng() * proof.length);
      const tampered = proof.map((step, j) =>
        j === i
          ? { hash: sha256('garbage-' + rng()), position: 'right' as const }
          : step,
      );
      expect(MerkleTree.verify(h, tampered, root)).toBe(false);
    }
  });

  it('any random root alteration breaks verification', () => {
    const rng = makeRng(5);
    for (let trial = 0; trial < 15; trial++) {
      const n = 3 + Math.floor(rng() * 20);
      const leaves = Array.from({ length: n }, (_, i) => `r-${i}-${rng()}`);
      const { tree, hashes, root } = buildTree(leaves);
      const h = hashes[0];
      const proof = tree.getProof(h);

      const alteredRoot = sha256(root + String(trial));
      expect(MerkleTree.verify(h, proof, alteredRoot)).toBe(false);
    }
  });
});

describe('MerkleTree — property: inclusion scoping', () => {
  it("leaf X's proof does NOT verify leaf Y against the same root (when X ≠ Y)", () => {
    const rng = makeRng(2026);
    for (let trial = 0; trial < 20; trial++) {
      const n = 3 + Math.floor(rng() * 15);
      const leaves = Array.from({ length: n }, (_, i) => `s-${i}-${rng()}`);
      const { tree, hashes, root } = buildTree(leaves);
      if (n < 2) continue;

      const xIdx = 0;
      const yIdx = 1 + Math.floor(rng() * (n - 1));
      const x = hashes[xIdx];
      const y = hashes[yIdx];
      if (x === y) continue;

      const proofX = tree.getProof(x);
      // Attacker claims leaf Y is in the tree by using X's proof. Must fail.
      expect(MerkleTree.verify(y, proofX, root)).toBe(false);
    }
  });
});

describe('MerkleTree — property: structural invariants', () => {
  it('getRoot is idempotent across repeated calls (no mutation)', () => {
    const rng = makeRng(3);
    for (let n of SIZES) {
      const leaves = Array.from({ length: n }, (_, i) => `k-${i}-${rng()}`);
      const { tree } = buildTree(leaves);
      const r1 = tree.getRoot();
      const r2 = tree.getRoot();
      const r3 = tree.getRoot();
      expect(r1).toBe(r2);
      expect(r2).toBe(r3);
    }
  });

  it('shuffling leaves yields a different root (order-sensitive)', () => {
    const rng = makeRng(11);
    for (let trial = 0; trial < 10; trial++) {
      const n = 3 + Math.floor(rng() * 15);
      const original = Array.from({ length: n }, (_, i) => `o-${i}-${rng()}`);

      // Fisher-Yates shuffle with the same PRNG; ensure at least one swap
      const shuffled = [...original];
      for (let i = shuffled.length - 1; i > 0; i--) {
        const j = Math.floor(rng() * (i + 1));
        [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
      }

      // Skip degenerate case where shuffle happened to be identity
      if (shuffled.every((v, i) => v === original[i])) continue;

      const rootA = buildTree(original).root;
      const rootB = buildTree(shuffled).root;
      expect(rootA).not.toBe(rootB);
    }
  });

  it('two trees built with identical inputs in identical order share the same root', () => {
    const rng = makeRng(22);
    for (let trial = 0; trial < 10; trial++) {
      const n = 2 + Math.floor(rng() * 20);
      const leaves = Array.from({ length: n }, (_, i) => `d-${i}-${rng()}`);
      expect(buildTree(leaves).root).toBe(buildTree(leaves).root);
    }
  });

  it('leafCount strictly matches the number of addLeaf calls', () => {
    for (const n of SIZES) {
      const tree = new MerkleTree();
      for (let i = 0; i < n; i++) tree.addLeaf(`x${i}`);
      expect(tree.leafCount).toBe(n);
    }
  });
});

describe('MerkleTree — property: append stability', () => {
  it('appending a new leaf never matches the pre-append root', () => {
    const rng = makeRng(77);
    for (let trial = 0; trial < 15; trial++) {
      const n = 1 + Math.floor(rng() * 20);
      const tree = new MerkleTree();
      for (let i = 0; i < n; i++) tree.addLeaf(`a-${i}-${rng()}`);
      const before = tree.getRoot();
      tree.addLeaf('new-leaf');
      const after = tree.getRoot();
      expect(after).not.toBe(before);
    }
  });
});
