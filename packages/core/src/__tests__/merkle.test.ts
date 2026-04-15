/**
 * Merkle tree tamper-detection tests.
 *
 * The Merkle tree is the core of Odin's tamper-evident memory: every
 * write is added as a leaf, and the session root is signed with the
 * instance's Ed25519 key. These tests verify that any modification to
 * a leaf, a proof step, or the root causes proof verification to fail.
 *
 * Companion to memory.test.ts, which covers shallow construction cases.
 */

import { describe, it, expect } from 'vitest';
import { MerkleTree, sha256 } from '../memory/merkle.js';

describe('MerkleTree — determinism', () => {
  it('produces identical roots for identical leaf sequences', () => {
    const a = new MerkleTree();
    const b = new MerkleTree();
    for (const leaf of ['alpha', 'bravo', 'charlie', 'delta']) {
      a.addLeaf(leaf);
      b.addLeaf(leaf);
    }
    expect(a.getRoot()).toBe(b.getRoot());
  });

  it('produces different roots when leaf order differs', () => {
    const a = new MerkleTree();
    const b = new MerkleTree();
    a.addLeaf('alpha'); a.addLeaf('bravo');
    b.addLeaf('bravo'); b.addLeaf('alpha');
    expect(a.getRoot()).not.toBe(b.getRoot());
  });

  it('root is stable across repeated getRoot() calls', () => {
    const tree = new MerkleTree();
    tree.addLeaf('x'); tree.addLeaf('y');
    const first = tree.getRoot();
    const second = tree.getRoot();
    expect(first).toBe(second);
  });

  it('adding a leaf invalidates the cached root', () => {
    const tree = new MerkleTree();
    tree.addLeaf('x'); tree.addLeaf('y');
    const before = tree.getRoot();
    tree.addLeaf('z');
    const after = tree.getRoot();
    expect(after).not.toBe(before);
  });
});

describe('MerkleTree — edge cases', () => {
  it('empty tree root equals sha256("")', () => {
    const tree = new MerkleTree();
    expect(tree.getRoot()).toBe(sha256(''));
  });

  it('leafCount reflects added leaves', () => {
    const tree = new MerkleTree();
    expect(tree.leafCount).toBe(0);
    tree.addLeaf('a'); tree.addLeaf('b'); tree.addLeaf('c');
    expect(tree.leafCount).toBe(3);
  });

  it('getProof returns empty array for unknown hash', () => {
    const tree = new MerkleTree();
    tree.addLeaf('known');
    expect(tree.getProof(sha256('never-added'))).toEqual([]);
  });

  it('single-leaf tree: leaf is the root, empty proof verifies', () => {
    const tree = new MerkleTree();
    const h = tree.addLeaf('lone-entry');
    const root = tree.getRoot();
    expect(root).toBe(h);
    const proof = tree.getProof(h);
    expect(proof).toEqual([]);
    expect(MerkleTree.verify(h, proof, root)).toBe(true);
  });

  it('single-leaf tree: tampered leaf fails verification', () => {
    const tree = new MerkleTree();
    const h = tree.addLeaf('lone-entry');
    const root = tree.getRoot();
    const tampered = sha256('tampered');
    expect(MerkleTree.verify(tampered, [], root)).toBe(false);
  });

  it('handles odd number of leaves (3)', () => {
    const tree = new MerkleTree();
    const h1 = tree.addLeaf('one');
    tree.addLeaf('two');
    tree.addLeaf('three');
    const root = tree.getRoot();
    const proof = tree.getProof(h1);
    expect(MerkleTree.verify(h1, proof, root)).toBe(true);
  });

  it('handles odd number of leaves (5)', () => {
    const tree = new MerkleTree();
    const hashes = ['a', 'b', 'c', 'd', 'e'].map(l => tree.addLeaf(l));
    const root = tree.getRoot();
    for (const h of hashes) {
      expect(MerkleTree.verify(h, tree.getProof(h), root)).toBe(true);
    }
  });

  it('handles 7 leaves (non-power-of-two)', () => {
    const tree = new MerkleTree();
    const hashes = ['a', 'b', 'c', 'd', 'e', 'f', 'g'].map(l => tree.addLeaf(l));
    const root = tree.getRoot();
    for (const h of hashes) {
      expect(MerkleTree.verify(h, tree.getProof(h), root)).toBe(true);
    }
  });
});

describe('MerkleTree — tamper detection (adversarial)', () => {
  const buildTree = (leaves: string[]) => {
    const tree = new MerkleTree();
    const hashes = leaves.map(l => tree.addLeaf(l));
    return { tree, hashes, root: tree.getRoot() };
  };

  it('verify succeeds for an untampered leaf+proof+root', () => {
    const { tree, hashes, root } = buildTree(['log1', 'log2', 'log3', 'log4']);
    const proof = tree.getProof(hashes[1]);
    expect(MerkleTree.verify(hashes[1], proof, root)).toBe(true);
  });

  it('verify fails if the leaf hash is tampered', () => {
    const { tree, hashes, root } = buildTree(['log1', 'log2', 'log3', 'log4']);
    const proof = tree.getProof(hashes[1]);
    const tamperedLeaf = sha256('log2-tampered');
    expect(MerkleTree.verify(tamperedLeaf, proof, root)).toBe(false);
  });

  it('verify fails if a proof step hash is tampered', () => {
    const { tree, hashes, root } = buildTree(['log1', 'log2', 'log3', 'log4']);
    const proof = tree.getProof(hashes[1]);
    const tamperedProof = proof.map((step, i) =>
      i === 0 ? { ...step, hash: sha256('evil') } : step,
    );
    expect(MerkleTree.verify(hashes[1], tamperedProof, root)).toBe(false);
  });

  it('verify fails if the root is tampered', () => {
    const { tree, hashes, root } = buildTree(['log1', 'log2', 'log3', 'log4']);
    const proof = tree.getProof(hashes[1]);
    const tamperedRoot = sha256(root + 'x');
    expect(MerkleTree.verify(hashes[1], proof, tamperedRoot)).toBe(false);
  });

  it('verify fails if a proof step position is flipped', () => {
    const { tree, hashes, root } = buildTree(['log1', 'log2', 'log3', 'log4']);
    const proof = tree.getProof(hashes[1]);
    const flipped = proof.map(step => ({
      ...step,
      position: step.position === 'left' ? ('right' as const) : ('left' as const),
    }));
    expect(MerkleTree.verify(hashes[1], flipped, root)).toBe(false);
  });

  it('verify fails if a proof step is removed', () => {
    const { tree, hashes, root } = buildTree(['log1', 'log2', 'log3', 'log4']);
    const proof = tree.getProof(hashes[1]);
    expect(proof.length).toBeGreaterThan(1);
    const truncated = proof.slice(0, -1);
    expect(MerkleTree.verify(hashes[1], truncated, root)).toBe(false);
  });

  it('verify fails when an extra proof step is injected', () => {
    const { tree, hashes, root } = buildTree(['log1', 'log2', 'log3', 'log4']);
    const proof = tree.getProof(hashes[1]);
    const padded = [...proof, { hash: sha256('extra'), position: 'right' as const }];
    expect(MerkleTree.verify(hashes[1], padded, root)).toBe(false);
  });

  it('swapping two leaves produces a different root', () => {
    const a = buildTree(['log1', 'log2', 'log3', 'log4']);
    const b = buildTree(['log2', 'log1', 'log3', 'log4']);
    expect(a.root).not.toBe(b.root);
  });
});
