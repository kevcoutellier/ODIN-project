import { describe, it, expect, beforeEach } from 'vitest';
import { DIDManager } from '../did/manager.js';

describe('DIDManager', () => {
  let did: DIDManager;

  beforeEach(async () => {
    did = new DIDManager();
    await did.init();
  });

  it('generates a valid DID', () => {
    const identity = did.getDID();
    expect(identity.id).toMatch(/^did:odin:[a-f0-9]+$/);
  });

  it('signs and verifies data', () => {
    const data = 'test data to sign';
    const signature = did.sign(data);
    expect(signature).toBeTruthy();
    expect(typeof signature).toBe('string');
    // Verify using the static method
    const valid = DIDManager.verify(data, signature, did.getDID().publicKey);
    expect(valid).toBe(true);
  });

  it('rejects tampered data', () => {
    const signature = did.sign('original');
    const valid = DIDManager.verify('tampered', signature, did.getDID().publicKey);
    expect(valid).toBe(false);
  });

  it('creates ephemeral credentials', () => {
    const cred = did.issueEphemeralCredential(['task:build'], 3600);
    expect(cred.scope).toContain('task:build');
    expect(cred.expiresAt).toBeGreaterThan(Date.now());
    expect(cred.signature).toBeTruthy();
  });

  it('generates DID document', () => {
    const doc = did.getDIDDocument();
    expect(doc['@context']).toContain('https://www.w3.org/ns/did/v1');
    expect(doc.id).toMatch(/^did:odin:/);
    expect(doc.verificationMethod).toHaveLength(1);
  });

  it('generates unique DIDs per instance', async () => {
    const did2 = new DIDManager();
    await did2.init();
    expect(did.getDID().id).not.toBe(did2.getDID().id);
  });
});
