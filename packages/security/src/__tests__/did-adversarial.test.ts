/**
 * DID adversarial tests — Ed25519 signature forgery & credential tampering.
 *
 * Complements did.test.ts (basic sign/verify). Focuses on:
 *   - cross-key verification (attacker's pubkey ≠ ours)
 *   - malformed signatures (base64 garbage, empty, wrong length)
 *   - ephemeral credential tampering (scope / expiry / agentDid mutation)
 *   - expiry enforcement + automatic cache eviction
 *   - key restoration: storedSecretKey → same DID + same signatures
 *   - lifecycle edge cases (pre-init accessors, revoke unknown, prune count)
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { DIDManager } from '../did/manager.js';

describe('DIDManager — signature forgery resistance', () => {
  it('signature from instance A cannot be verified with instance B public key', async () => {
    const a = new DIDManager(); await a.init();
    const b = new DIDManager(); await b.init();

    const data = 'authorize: task-42';
    const signatureA = a.sign(data);
    // Verify with A's public key → ok
    expect(DIDManager.verify(data, signatureA, a.getDID().publicKey)).toBe(true);
    // Verify with B's public key → MUST fail (forgery attempt)
    expect(DIDManager.verify(data, signatureA, b.getDID().publicKey)).toBe(false);
  });

  it('verify returns false for an all-zero signature (no exception)', async () => {
    const d = new DIDManager(); await d.init();
    const zeroSig = Buffer.alloc(64).toString('base64');
    expect(DIDManager.verify('data', zeroSig, d.getDID().publicKey)).toBe(false);
  });

  it('verify returns false for an empty signature', async () => {
    const d = new DIDManager(); await d.init();
    expect(DIDManager.verify('data', '', d.getDID().publicKey)).toBe(false);
  });

  it('verify returns false when the signature is valid base64 but wrong length', async () => {
    const d = new DIDManager(); await d.init();
    const tooShort = Buffer.from('abc').toString('base64');
    expect(DIDManager.verify('data', tooShort, d.getDID().publicKey)).toBe(false);
  });

  it('flipping any byte in a valid signature breaks verification', async () => {
    const d = new DIDManager(); await d.init();
    const sig = d.sign('message');
    const buf = Buffer.from(sig, 'base64');
    buf[0] = buf[0] ^ 0xff; // flip high bit of first byte
    const tampered = buf.toString('base64');
    expect(DIDManager.verify('message', tampered, d.getDID().publicKey)).toBe(false);
  });

  it('swapping the public key produces a different DID id', async () => {
    const a = new DIDManager(); await a.init();
    const b = new DIDManager(); await b.init();
    expect(a.getDID().id).not.toBe(b.getDID().id);
    expect(a.getDID().publicKey).not.toBe(b.getDID().publicKey);
  });
});

describe('DIDManager — key restoration', () => {
  it('init with a stored secret key yields the same DID', async () => {
    const original = new DIDManager();
    const originalDID = await original.init();
    const secret = original.getSecretKey();

    const restored = new DIDManager();
    await restored.init(secret);

    expect(restored.getDID().id).toBe(originalDID.id);
    expect(restored.getDID().publicKey).toBe(originalDID.publicKey);
  });

  it('a signature produced by the restored instance verifies against the original pubkey', async () => {
    const original = new DIDManager();
    await original.init();
    const secret = original.getSecretKey();

    const restored = new DIDManager();
    await restored.init(secret);

    const sig = restored.sign('data');
    // Cross-verify: restored's signature verifies with original's pubkey
    expect(DIDManager.verify('data', sig, original.getDID().publicKey)).toBe(true);
  });
});

describe('DIDManager — credential tampering', () => {
  let did: DIDManager;
  beforeEach(async () => { did = new DIDManager(); await did.init(); });

  it('issued credential validates out of the box', () => {
    const cred = did.issueEphemeralCredential(['task:read'], 3600);
    expect(did.validateCredential(cred)).toBe(true);
  });

  it('scope mutation breaks the signature', () => {
    const cred = did.issueEphemeralCredential(['task:read'], 3600);
    const tampered = { ...cred, scope: ['task:read', 'task:delete'] };
    expect(did.validateCredential(tampered)).toBe(false);
  });

  it('expiresAt mutation breaks the signature', () => {
    const cred = did.issueEphemeralCredential(['task:read'], 3600);
    const extended = { ...cred, expiresAt: cred.expiresAt + 10_000_000 };
    expect(did.validateCredential(extended)).toBe(false);
  });

  it('agentDid substitution (impersonation attempt) breaks the signature', () => {
    const cred = did.issueEphemeralCredential(['task:read'], 3600);
    const impersonated = { ...cred, agentDid: 'did:odin:attacker' };
    expect(did.validateCredential(impersonated)).toBe(false);
  });

  it('id collision with different contents is rejected', () => {
    const cred = did.issueEphemeralCredential(['task:read'], 3600);
    const injected = { ...cred, id: 'cred:attacker-crafted' };
    expect(did.validateCredential(injected)).toBe(false);
  });
});

describe('DIDManager — credential lifecycle', () => {
  let did: DIDManager;
  beforeEach(async () => { did = new DIDManager(); await did.init(); });

  it('expired credential fails validation and is evicted from the cache', () => {
    // Issue with negative TTL so it's immediately expired
    const cred = did.issueEphemeralCredential(['task:x'], -1);
    expect(did.validateCredential(cred)).toBe(false);
    // After validation, the expired credential is removed from the manager's cache.
    // We verify indirectly via pruneExpiredCredentials → returns 0 (already gone).
    expect(did.pruneExpiredCredentials()).toBe(0);
  });

  it('revokeCredential on an unknown id is a silent no-op', () => {
    expect(() => did.revokeCredential('cred:does-not-exist')).not.toThrow();
  });

  it('revoke an active credential does NOT invalidate its signature (revocation is cache-only)', () => {
    // Document current behaviour: validateCredential only checks expiry + signature;
    // it does NOT consult the cache, so a revoked-but-unexpired credential still
    // passes signature validation if the holder replays it. This is a known
    // design limitation — worth documenting.
    const cred = did.issueEphemeralCredential(['task:x'], 3600);
    did.revokeCredential(cred.id);
    expect(did.validateCredential(cred)).toBe(true);
  });

  it('pruneExpiredCredentials counts and removes expired entries only', () => {
    did.issueEphemeralCredential(['a'], 3600);      // fresh
    did.issueEphemeralCredential(['b'], -1);         // expired
    did.issueEphemeralCredential(['c'], -1);         // expired
    did.issueEphemeralCredential(['d'], 3600);      // fresh

    expect(did.pruneExpiredCredentials()).toBe(2);
    // Second call: nothing left to prune
    expect(did.pruneExpiredCredentials()).toBe(0);
  });
});

describe('DIDManager — lifecycle edge cases', () => {
  it('getDID throws when called before init', () => {
    const d = new DIDManager();
    expect(() => d.getDID()).toThrow(/not initialized/i);
  });

  it('sign throws when called before init', () => {
    const d = new DIDManager();
    expect(() => d.sign('data')).toThrow(/not initialized/i);
  });

  it('getSecretKey throws when called before init', () => {
    const d = new DIDManager();
    expect(() => d.getSecretKey()).toThrow(/not initialized/i);
  });

  it('updateTrustScore throws when called before init', () => {
    const d = new DIDManager();
    expect(() => d.updateTrustScore(80)).toThrow(/not initialized/i);
  });

  it('updateTrustScore sets the field on the current DID', async () => {
    const d = new DIDManager(); await d.init();
    d.updateTrustScore(73);
    expect(d.getDID().trustScore).toBe(73);
  });

  it('DID document embeds trustScore when set', async () => {
    const d = new DIDManager(); await d.init();
    d.updateTrustScore(90);
    const doc = d.getDIDDocument();
    expect(doc.trustScore).toBe(90);
  });
});
