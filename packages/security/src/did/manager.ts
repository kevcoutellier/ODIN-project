/**
 * DID Manager — Decentralized Identity for Odin Instances
 *
 * Each Odin instance gets a unique did:odin:<fingerprint> based on
 * an Ed25519 keypair generated at first launch. The DID Document
 * contains the public key, capabilities, and trust score.
 *
 * Credentials are ephemeral and scoped per task (Intent-Scoped
 * Ephemeral Credentials).
 */

import { randomBytes } from 'node:crypto';
import type { OdinDID, DIDDocument } from '@odin/core';

// tweetnacl for Ed25519 signing
import nacl from 'tweetnacl';

export interface KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export interface EphemeralCredential {
  id: string;
  agentDid: string;
  scope: string[];
  issuedAt: number;
  expiresAt: number;
  signature: string;
}

export class DIDManager {
  private keyPair: KeyPair | null = null;
  private did: OdinDID | null = null;
  private credentials: Map<string, EphemeralCredential> = new Map();

  /**
   * Initialize or restore the DID from a stored keypair.
   */
  async init(storedSecretKey?: Uint8Array): Promise<OdinDID> {
    if (storedSecretKey) {
      this.keyPair = nacl.sign.keyPair.fromSecretKey(storedSecretKey);
    } else {
      this.keyPair = nacl.sign.keyPair();
    }

    const fingerprint = this.computeFingerprint(this.keyPair.publicKey);

    this.did = {
      id: `did:odin:${fingerprint}`,
      publicKey: Buffer.from(this.keyPair.publicKey).toString('base64'),
      created: Date.now(),
      capabilities: [],
    };

    return this.did;
  }

  getDID(): OdinDID {
    if (!this.did) throw new Error('DID not initialized. Call init() first.');
    return this.did;
  }

  getSecretKey(): Uint8Array {
    if (!this.keyPair) throw new Error('KeyPair not initialized.');
    return this.keyPair.secretKey;
  }

  /**
   * Generate the DID Document (W3C compliant).
   */
  getDIDDocument(): DIDDocument {
    const did = this.getDID();

    return {
      '@context': [
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/ed25519-2020/v1',
      ],
      id: did.id,
      verificationMethod: [
        {
          id: `${did.id}#key-1`,
          type: 'Ed25519VerificationKey2020',
          controller: did.id,
          publicKeyBase64: did.publicKey,
        },
      ],
      authentication: [`${did.id}#key-1`],
      capabilities: did.capabilities,
      trustScore: did.trustScore,
    };
  }

  /**
   * Sign data with the instance's Ed25519 private key.
   */
  sign(data: string): string {
    if (!this.keyPair) throw new Error('KeyPair not initialized.');
    const message = new TextEncoder().encode(data);
    const signature = nacl.sign.detached(message, this.keyPair.secretKey);
    return Buffer.from(signature).toString('base64');
  }

  /**
   * Verify a signature against a public key.
   */
  static verify(data: string, signature: string, publicKeyBase64: string): boolean {
    const message = new TextEncoder().encode(data);
    const sig = Buffer.from(signature, 'base64');
    const publicKey = Buffer.from(publicKeyBase64, 'base64');
    return nacl.sign.detached.verify(message, sig, publicKey);
  }

  /**
   * Issue an ephemeral credential scoped to a specific task.
   * These credentials expire and cannot be reused.
   */
  issueEphemeralCredential(
    scope: string[],
    ttlSeconds: number,
  ): EphemeralCredential {
    const did = this.getDID();
    const now = Date.now();
    const id = `cred:${randomBytes(16).toString('hex')}`;

    const credentialData = JSON.stringify({
      id,
      agentDid: did.id,
      scope,
      issuedAt: now,
      expiresAt: now + ttlSeconds * 1000,
    });

    const credential: EphemeralCredential = {
      id,
      agentDid: did.id,
      scope,
      issuedAt: now,
      expiresAt: now + ttlSeconds * 1000,
      signature: this.sign(credentialData),
    };

    this.credentials.set(id, credential);
    return credential;
  }

  /**
   * Validate an ephemeral credential: check expiry and signature.
   */
  validateCredential(credential: EphemeralCredential): boolean {
    // Check expiry
    if (Date.now() > credential.expiresAt) {
      this.credentials.delete(credential.id);
      return false;
    }

    // Verify signature
    const credentialData = JSON.stringify({
      id: credential.id,
      agentDid: credential.agentDid,
      scope: credential.scope,
      issuedAt: credential.issuedAt,
      expiresAt: credential.expiresAt,
    });

    return DIDManager.verify(credentialData, credential.signature, this.getDID().publicKey);
  }

  /**
   * Revoke an ephemeral credential.
   */
  revokeCredential(credentialId: string): void {
    this.credentials.delete(credentialId);
  }

  /**
   * Clean up expired credentials.
   */
  pruneExpiredCredentials(): number {
    const now = Date.now();
    let pruned = 0;
    for (const [id, cred] of this.credentials) {
      if (now > cred.expiresAt) {
        this.credentials.delete(id);
        pruned++;
      }
    }
    return pruned;
  }

  updateTrustScore(score: number): void {
    if (!this.did) throw new Error('DID not initialized.');
    this.did.trustScore = score;
  }

  private computeFingerprint(publicKey: Uint8Array): string {
    // Use first 16 bytes of the public key as fingerprint, hex-encoded
    return Buffer.from(publicKey.slice(0, 16)).toString('hex');
  }
}
