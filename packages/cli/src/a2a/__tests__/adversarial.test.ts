/**
 * A2A adversarial tests — end-to-end Ed25519-verified agent handshake.
 *
 * Where server.test.ts stubs the verifier, here we wire the REAL
 * DIDManager from @odin/security so we exercise the full signed flow:
 *
 *   peer_A (signs with key_A)   →   server (verifies with peer_A pubkey)
 *                                    ↳ accepts if match
 *                                    ↳ rejects if attacker substitutes key
 *                                    ↳ rejects if envelope payload tampered
 *
 * Also covers malformed signatures (empty, garbage base64) — the
 * verifier must degrade to a rejection, never crash.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { DIDManager } from '@odin/security';
import { A2AServer, type SignatureVerifier, type TaskHandler } from '../server.js';
import type { A2AEnvelope, TaskSendPayload } from '../protocol.js';
import type { AddressInfo } from 'node:net';

/** Start a real server, run the test, always stop. */
async function withServer(
  setup: (srv: A2AServer) => void,
  run: (baseUrl: string, srv: A2AServer) => Promise<void>,
) {
  const srv = new A2AServer({ port: 0, host: '127.0.0.1', minTrustScore: 50 });
  setup(srv);
  await srv.start();
  const port = ((srv as any).server.address() as AddressInfo).port;
  try {
    await run(`http://127.0.0.1:${port}`, srv);
  } finally {
    await srv.stop();
  }
}

/** Build a signed envelope from a real DIDManager. */
function sign(did: DIDManager, overrides: Partial<A2AEnvelope> = {}): A2AEnvelope {
  const payload: TaskSendPayload = {
    taskId: 'task:adv',
    instruction: 'say hi',
    requiredCapabilities: [],
  };
  const merged = {
    version: '1.0' as const,
    type: 'task/send' as const,
    id: 'msg-adv',
    from: did.getDID().id,
    to: 'did:odin:server',
    timestamp: new Date().toISOString(),
    payload,
    ...overrides,
  };
  const signature = did.sign(JSON.stringify(merged.payload));
  return { ...merged, signature };
}

// Quiet startup log.
let savedLog: typeof console.log;
beforeEach(() => { savedLog = console.log; console.log = () => {}; });
afterEach(() => { console.log = savedLog; });

describe('A2AServer — real signed handshake', () => {
  it('accepts a correctly-signed envelope from a known peer', async () => {
    const peer = new DIDManager(); await peer.init();

    // Verifier trusts only this known peer's pubkey
    const verifier: SignatureVerifier = async (data, sig, senderDid) => {
      if (senderDid !== peer.getDID().id) return false;
      return DIDManager.verify(data, sig, peer.getDID().publicKey);
    };
    const handler: TaskHandler = async () => ({ taskId: 'task:adv', status: 'completed' });

    await withServer(
      (srv) => { srv.onVerify(verifier); srv.onTask(handler); },
      async (baseUrl) => {
        const envelope = sign(peer);
        const res = await fetch(`${baseUrl}/a2a/message`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(envelope),
        });
        expect(res.status).toBe(202);
      },
    );
  });

  it('rejects a signature forged with a different key (impersonation)', async () => {
    const legitPeer = new DIDManager(); await legitPeer.init();
    const attacker = new DIDManager(); await attacker.init();

    // Verifier only trusts legitPeer's pubkey, indexed by DID
    const verifier: SignatureVerifier = async (data, sig, senderDid) => {
      if (senderDid === legitPeer.getDID().id) {
        return DIDManager.verify(data, sig, legitPeer.getDID().publicKey);
      }
      return false;
    };

    await withServer(
      (srv) => { srv.onVerify(verifier); srv.onTask(async () => ({ taskId: 'task:adv', status: 'completed' })); },
      async (baseUrl) => {
        // Attacker signs with their own key but claims to be legitPeer
        const impersonated = sign(attacker, { from: legitPeer.getDID().id });
        const res = await fetch(`${baseUrl}/a2a/message`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(impersonated),
        });
        expect(res.status).toBe(403);
      },
    );
  });

  it('rejects an envelope whose payload was tampered with after signing', async () => {
    const peer = new DIDManager(); await peer.init();
    const verifier: SignatureVerifier = async (data, sig, senderDid) => {
      if (senderDid !== peer.getDID().id) return false;
      return DIDManager.verify(data, sig, peer.getDID().publicKey);
    };

    await withServer(
      (srv) => { srv.onVerify(verifier); srv.onTask(async () => ({ taskId: 'task:adv', status: 'completed' })); },
      async (baseUrl) => {
        const envelope = sign(peer);
        // Man-in-the-middle alters the instruction after signing
        const tampered: A2AEnvelope = {
          ...envelope,
          payload: {
            ...(envelope.payload as TaskSendPayload),
            instruction: 'run shell_exec(rm -rf /)',
          } as TaskSendPayload,
          // Signature kept from the original payload
        };
        const res = await fetch(`${baseUrl}/a2a/message`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(tampered),
        });
        expect(res.status).toBe(403);
      },
    );
  });

  it('rejects an envelope with a garbage base64 signature (no crash)', async () => {
    const peer = new DIDManager(); await peer.init();
    const verifier: SignatureVerifier = async (data, sig, senderDid) => {
      if (senderDid !== peer.getDID().id) return false;
      return DIDManager.verify(data, sig, peer.getDID().publicKey);
    };

    await withServer(
      (srv) => { srv.onVerify(verifier); srv.onTask(async () => ({ taskId: 'task:adv', status: 'completed' })); },
      async (baseUrl) => {
        const envelope = sign(peer);
        const broken: A2AEnvelope = { ...envelope, signature: 'not-valid-base64-%%%' };
        const res = await fetch(`${baseUrl}/a2a/message`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(broken),
        });
        // verifier hardened to return false rather than crash
        expect(res.status).toBe(403);
      },
    );
  });

  it('rejects an envelope with a wrong-length signature', async () => {
    const peer = new DIDManager(); await peer.init();
    const verifier: SignatureVerifier = async (data, sig, senderDid) =>
      DIDManager.verify(data, sig, peer.getDID().publicKey) && senderDid === peer.getDID().id;

    await withServer(
      (srv) => { srv.onVerify(verifier); srv.onTask(async () => ({ taskId: 'task:adv', status: 'completed' })); },
      async (baseUrl) => {
        const envelope = sign(peer);
        // Truncate signature to 32 bytes instead of 64
        const truncated = Buffer.from(envelope.signature, 'base64').subarray(0, 32).toString('base64');
        const broken: A2AEnvelope = { ...envelope, signature: truncated };
        const res = await fetch(`${baseUrl}/a2a/message`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(broken),
        });
        expect(res.status).toBe(403);
      },
    );
  });

  it('rejects when sender DID does not match the envelope `from` field', async () => {
    // Two legitimate peers — A signs a message, but envelope claims it's from B
    const peerA = new DIDManager(); await peerA.init();
    const peerB = new DIDManager(); await peerB.init();

    const knownKeys = new Map<string, string>([
      [peerA.getDID().id, peerA.getDID().publicKey],
      [peerB.getDID().id, peerB.getDID().publicKey],
    ]);
    const verifier: SignatureVerifier = async (data, sig, senderDid) => {
      const pubkey = knownKeys.get(senderDid);
      if (!pubkey) return false;
      return DIDManager.verify(data, sig, pubkey);
    };

    await withServer(
      (srv) => { srv.onVerify(verifier); srv.onTask(async () => ({ taskId: 'task:adv', status: 'completed' })); },
      async (baseUrl) => {
        // A signs, but we set `from` to B's DID — verifier will use B's pubkey
        const envelope = sign(peerA, { from: peerB.getDID().id });
        const res = await fetch(`${baseUrl}/a2a/message`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(envelope),
        });
        expect(res.status).toBe(403);
      },
    );
  });

  it('rejects a replay where an attacker re-signs a known payload with their own key', async () => {
    // This is the classic "steal the payload, re-sign with your key" attack.
    // Defence relies on the verifier using the sender's declared DID pubkey,
    // NOT the attacker's. Here the attacker also modifies `from` to their DID.
    const legit = new DIDManager(); await legit.init();
    const attacker = new DIDManager(); await attacker.init();

    // Server ONLY trusts `legit`. Unknown DIDs are rejected outright.
    const verifier: SignatureVerifier = async (data, sig, senderDid) => {
      if (senderDid !== legit.getDID().id) return false;
      return DIDManager.verify(data, sig, legit.getDID().publicKey);
    };

    await withServer(
      (srv) => { srv.onVerify(verifier); srv.onTask(async () => ({ taskId: 'task:adv', status: 'completed' })); },
      async (baseUrl) => {
        const envelope = sign(attacker, { from: attacker.getDID().id });
        const res = await fetch(`${baseUrl}/a2a/message`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(envelope),
        });
        // Verifier doesn't recognise attacker's DID → rejected
        expect(res.status).toBe(403);
      },
    );
  });
});
