import { describe, it, expect } from 'vitest';
import { MerkleTree, sha256 } from '../memory/merkle.js';

describe('MerkleTree single-leaf tamper-evidence', () => {
  it('accepts an empty proof when leafHash === rootHash', () => {
    const h = sha256('only-entry');
    expect(MerkleTree.verify(h, [], h)).toBe(true);
  });

  it('rejects an empty proof when leafHash !== rootHash', () => {
    const h = sha256('only-entry');
    const other = sha256('something-else');
    expect(MerkleTree.verify(h, [], other)).toBe(false);
  });

  it('round-trips a single-leaf tree through getProof + verify', () => {
    const tree = new MerkleTree();
    const h = tree.addLeaf('only-entry');
    const root = tree.getRoot();

    // For a single leaf, root must equal the leaf hash.
    expect(root).toBe(h);

    const proof = tree.getProof(h);
    // Fix: single-leaf proofs are empty, not a self-referential padding step.
    expect(proof).toEqual([]);

    expect(MerkleTree.verify(h, proof, root)).toBe(true);
  });

  it('detects tampering in a single-leaf tree', () => {
    const tree = new MerkleTree();
    const h = tree.addLeaf('only-entry');
    const root = tree.getRoot();
    const proof = tree.getProof(h);

    const tamperedLeaf = sha256('tampered');
    expect(MerkleTree.verify(tamperedLeaf, proof, root)).toBe(false);
  });
});
