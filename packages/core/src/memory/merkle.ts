/**
 * Merkle Tree for Memory Integrity
 *
 * Each memory write produces an entry in a session-scoped Merkle tree.
 * The root is signed with the instance's Ed25519 key, making memory
 * tamper-evident and auditable.
 */

import { createHash } from 'node:crypto';

export function sha256(data: string): string {
  return createHash('sha256').update(data).digest('hex');
}

export interface MerkleNode {
  hash: string;
  left?: MerkleNode;
  right?: MerkleNode;
  data?: string;
}

export class MerkleTree {
  private leaves: string[] = [];
  private root: MerkleNode | null = null;

  addLeaf(data: string): string {
    const hash = sha256(data);
    this.leaves.push(hash);
    this.root = null; // invalidate cached root
    return hash;
  }

  getRoot(): string {
    if (this.leaves.length === 0) return sha256('');
    if (!this.root) {
      this.root = this.buildTree(this.leaves);
    }
    return this.root.hash;
  }

  /**
   * Generate a proof that a specific leaf is part of the tree.
   */
  getProof(leafHash: string): Array<{ hash: string; position: 'left' | 'right' }> {
    const index = this.leaves.indexOf(leafHash);
    if (index === -1) return [];

    // Single-leaf tree: root === leaf, so no proof steps are needed.
    // An empty proof combined with leafHash === rootHash is accepted by verify().
    if (this.leaves.length === 1) return [];

    const proof: Array<{ hash: string; position: 'left' | 'right' }> = [];
    let currentLevel = [...this.leaves];

    // Pad to even
    if (currentLevel.length % 2 !== 0) {
      currentLevel.push(currentLevel[currentLevel.length - 1]);
    }

    let currentIndex = index;

    while (currentLevel.length > 1) {
      const nextLevel: string[] = [];

      for (let i = 0; i < currentLevel.length; i += 2) {
        const left = currentLevel[i];
        const right = currentLevel[i + 1] ?? left;

        if (i === currentIndex || i + 1 === currentIndex) {
          if (currentIndex % 2 === 0) {
            proof.push({ hash: right, position: 'right' });
          } else {
            proof.push({ hash: left, position: 'left' });
          }
        }

        nextLevel.push(sha256(left + right));
      }

      currentIndex = Math.floor(currentIndex / 2);
      currentLevel = nextLevel;
    }

    return proof;
  }

  /**
   * Verify a proof against a root hash.
   */
  static verify(
    leafHash: string,
    proof: Array<{ hash: string; position: 'left' | 'right' }>,
    rootHash: string,
  ): boolean {
    // Single-leaf trees have no siblings to hash against, so the proof is
    // empty and the leaf itself is the root.
    if (proof.length === 0) return leafHash === rootHash;

    let currentHash = leafHash;

    for (const step of proof) {
      if (step.position === 'left') {
        currentHash = sha256(step.hash + currentHash);
      } else {
        currentHash = sha256(currentHash + step.hash);
      }
    }

    return currentHash === rootHash;
  }

  get leafCount(): number {
    return this.leaves.length;
  }

  private buildTree(hashes: string[]): MerkleNode {
    if (hashes.length === 1) {
      return { hash: hashes[0] };
    }

    // Pad to even
    const padded = [...hashes];
    if (padded.length % 2 !== 0) {
      padded.push(padded[padded.length - 1]);
    }

    const nextLevel: MerkleNode[] = [];
    for (let i = 0; i < padded.length; i += 2) {
      const left: MerkleNode = { hash: padded[i] };
      const right: MerkleNode = { hash: padded[i + 1] };
      const parent: MerkleNode = {
        hash: sha256(padded[i] + padded[i + 1]),
        left,
        right,
      };
      nextLevel.push(parent);
    }

    if (nextLevel.length === 1) return nextLevel[0];

    return this.buildTree(nextLevel.map(n => n.hash));
  }
}
