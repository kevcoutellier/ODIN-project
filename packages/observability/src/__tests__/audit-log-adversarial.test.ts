/**
 * Audit log adversarial tests — tamper detection & ordering integrity.
 *
 * The audit log is an append-only file signed by the agent's Ed25519 key.
 * A downstream verifier (operator, compliance auditor) must be able to
 * detect:
 *   - on-disk line tampering (signature mismatch per entry)
 *   - line reordering (signature is per-entry so order is weakly
 *     preserved only by file position — no inter-entry chaining today)
 *   - truncation / deletion of entries
 *
 * This file tests what CAN currently be caught and documents what CANNOT.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, readFileSync, writeFileSync, rmSync, appendFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { AuditLog } from '../audit-log.js';
import {
  IntegrityLevel,
  ConfidentialityLevel,
  type PolicyDecision,
  type TaintLabel,
} from '@odin/core';

const TRUSTED: TaintLabel = {
  integrity: IntegrityLevel.TRUSTED,
  confidentiality: ConfidentialityLevel.PUBLIC,
  source: 'test',
  timestamp: Date.now(),
};

const ALLOW: PolicyDecision = {
  allowed: true, reason: 'ok', policy: 'p', evaluationTimeMs: 1, conditions: {},
};
const DENY: PolicyDecision = {
  allowed: false, reason: 'nope', policy: 'p', evaluationTimeMs: 1, conditions: {},
};

/** Toy "HMAC" sign/verify pair using a shared secret — replaces Ed25519
 *  for testing purposes, so the whole flow is deterministic. */
function makeSignVerify(secret: string) {
  const sign = (data: string) => {
    // Tiny hash-chaining: sign = SHA-256 of (secret || data), lifted into hex.
    // Not cryptographically secure — sufficient for tamper-detection tests.
    let h = 5381;
    const combined = secret + data;
    for (let i = 0; i < combined.length; i++) {
      h = ((h << 5) + h + combined.charCodeAt(i)) | 0;
    }
    return (h >>> 0).toString(16).padStart(8, '0');
  };
  const verifyEntry = (entry: any): boolean => {
    const payload = JSON.stringify({
      id: entry.id,
      timestamp: entry.timestamp,
      agentDid: entry.agentDid,
      action: entry.action,
      resource: entry.resource,
      decision: entry.decision.allowed,
    });
    return sign(payload) === entry.signature;
  };
  return { sign, verifyEntry };
}

describe('AuditLog — on-disk tamper detection', () => {
  let dir: string;
  let logPath: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'odin-audit-adv-'));
    logPath = join(dir, 'audit.log');
  });

  afterEach(() => {
    try { rmSync(dir, { recursive: true, force: true }); } catch {}
  });

  it('all entries verify when the log is untouched', async () => {
    const { sign, verifyEntry } = makeSignVerify('k1');
    const log = new AuditLog({ logPath, signFn: sign });
    for (let i = 0; i < 5; i++) {
      await log.record({
        agentDid: 'did:odin:a', action: `op${i}`, resource: 'r',
        decision: ALLOW, taintLabel: TRUSTED, trustScore: 80,
      });
    }
    const entries = readFileSync(logPath, 'utf-8').trim().split('\n').map(l => JSON.parse(l));
    expect(entries.every(verifyEntry)).toBe(true);
  });

  it('changing an entry\'s action is detected by per-line signature verification', async () => {
    const { sign, verifyEntry } = makeSignVerify('k2');
    const log = new AuditLog({ logPath, signFn: sign });
    await log.record({
      agentDid: 'did:odin:a', action: 'read', resource: 'secret.db',
      decision: DENY, taintLabel: TRUSTED, trustScore: 10,
    });

    // Post-hoc attacker rewrites the log file to flip 'read' → 'noop'
    const original = readFileSync(logPath, 'utf-8');
    const tampered = original.replace('"action":"read"', '"action":"noop"');
    writeFileSync(logPath, tampered);

    const lines = readFileSync(logPath, 'utf-8').trim().split('\n').map(l => JSON.parse(l));
    expect(lines[0].action).toBe('noop');           // attack succeeded at parse level
    expect(verifyEntry(lines[0])).toBe(false);      // but signature verification catches it
  });

  it('changing a decision.allowed flips the signed subset and is detected', async () => {
    const { sign, verifyEntry } = makeSignVerify('k3');
    const log = new AuditLog({ logPath, signFn: sign });
    await log.record({
      agentDid: 'did:odin:a', action: 'shell_exec', resource: 'rm -rf',
      decision: DENY, taintLabel: TRUSTED, trustScore: 10,
    });

    const original = readFileSync(logPath, 'utf-8');
    // Most adversarial edit possible: flip the DENY → ALLOW
    const tampered = original.replace('"allowed":false', '"allowed":true');
    writeFileSync(logPath, tampered);

    const lines = readFileSync(logPath, 'utf-8').trim().split('\n').map(l => JSON.parse(l));
    expect(lines[0].decision.allowed).toBe(true);   // attack visible
    expect(verifyEntry(lines[0])).toBe(false);      // but detected
  });

  it('KNOWN LIMITATION: trustScore mutation is NOT detected (not covered by signed subset)', async () => {
    // The signing payload covers only {id, timestamp, agentDid, action, resource, decision.allowed}.
    // An attacker who mutates trustScore, taintLabel, or any other field will pass
    // verification. This is a compliance gap worth documenting.
    const { sign, verifyEntry } = makeSignVerify('k4');
    const log = new AuditLog({ logPath, signFn: sign });
    await log.record({
      agentDid: 'did:odin:a', action: 'read', resource: 'r',
      decision: ALLOW, taintLabel: TRUSTED, trustScore: 90,
    });

    const original = readFileSync(logPath, 'utf-8');
    const tampered = original.replace('"trustScore":90', '"trustScore":42');
    writeFileSync(logPath, tampered);

    const lines = readFileSync(logPath, 'utf-8').trim().split('\n').map(l => JSON.parse(l));
    expect(lines[0].trustScore).toBe(42);
    // Signature still verifies — mutation undetected
    expect(verifyEntry(lines[0])).toBe(true);
  });

  it('KNOWN LIMITATION: taintLabel mutation is NOT detected', async () => {
    const { sign, verifyEntry } = makeSignVerify('k5');
    const log = new AuditLog({ logPath, signFn: sign });
    await log.record({
      agentDid: 'did:odin:a', action: 'read', resource: 'r',
      decision: ALLOW, taintLabel: TRUSTED, trustScore: 90,
    });

    const original = readFileSync(logPath, 'utf-8');
    const tampered = original.replace('"integrity":"TRUSTED"', '"integrity":"UNTRUSTED"');
    writeFileSync(logPath, tampered);

    const lines = readFileSync(logPath, 'utf-8').trim().split('\n').map(l => JSON.parse(l));
    expect(lines[0].taintLabel.integrity).toBe('UNTRUSTED');
    expect(verifyEntry(lines[0])).toBe(true);
  });

  it('KNOWN LIMITATION: entry deletion is NOT detected (no append-chain)', async () => {
    // The log is append-only on disk but entries are independent. An attacker
    // with file write access can delete a middle line, and the remaining lines
    // still verify individually. A true chain would require each entry to
    // include the previous signature / hash.
    const { sign, verifyEntry } = makeSignVerify('k6');
    const log = new AuditLog({ logPath, signFn: sign });
    for (const action of ['benign-op', 'shell_exec', 'another-benign']) {
      await log.record({
        agentDid: 'did:odin:a', action, resource: 'r',
        decision: action === 'shell_exec' ? DENY : ALLOW,
        taintLabel: TRUSTED, trustScore: 80,
      });
    }

    const lines = readFileSync(logPath, 'utf-8').trim().split('\n');
    // Delete the compromising middle entry
    const tampered = [lines[0], lines[2]].join('\n') + '\n';
    writeFileSync(logPath, tampered);

    const remaining = readFileSync(logPath, 'utf-8').trim().split('\n').map(l => JSON.parse(l));
    expect(remaining).toHaveLength(2);
    // Both survivors verify individually
    expect(remaining.every(verifyEntry)).toBe(true);
    // … but the `shell_exec` incident is gone
    expect(remaining.some((e: any) => e.action === 'shell_exec')).toBe(false);
  });

  it('KNOWN LIMITATION: entry reordering is NOT detected', async () => {
    const { sign, verifyEntry } = makeSignVerify('k7');
    const log = new AuditLog({ logPath, signFn: sign });
    for (const action of ['first', 'second', 'third']) {
      await log.record({
        agentDid: 'did:odin:a', action, resource: 'r',
        decision: ALLOW, taintLabel: TRUSTED, trustScore: 80,
      });
    }

    const lines = readFileSync(logPath, 'utf-8').trim().split('\n');
    // Swap first and last
    const reordered = [lines[2], lines[1], lines[0]].join('\n') + '\n';
    writeFileSync(logPath, reordered);

    const remaining = readFileSync(logPath, 'utf-8').trim().split('\n').map(l => JSON.parse(l));
    // All still verify individually despite being in the wrong order
    expect(remaining.every(verifyEntry)).toBe(true);
    // Timestamps reveal the inversion, if a verifier thinks to look
    expect(remaining[0].timestamp).toBeGreaterThan(remaining[2].timestamp);
  });

  it('appending a forged entry without the secret fails signature verification', async () => {
    const { sign, verifyEntry } = makeSignVerify('real-secret');
    const log = new AuditLog({ logPath, signFn: sign });
    await log.record({
      agentDid: 'did:odin:a', action: 'read', resource: 'r',
      decision: ALLOW, taintLabel: TRUSTED, trustScore: 80,
    });

    // Attacker appends an entry with a plausible signature field but crafted
    // without the secret.
    const attackerSign = makeSignVerify('attacker-guess').sign;
    const forgedId = 'cafebabe-0000-0000-0000-000000000000';
    const forgedTs = Date.now();
    const forgedPayload = {
      id: forgedId, timestamp: forgedTs,
      agentDid: 'did:odin:a', action: 'delete_audit_log',
      resource: 'self', decision: true,
    };
    const forged = {
      ...forgedPayload,
      decision: { ...ALLOW, allowed: true },
      taintLabel: TRUSTED,
      trustScore: 100,
      signature: attackerSign(JSON.stringify(forgedPayload)),
    };
    appendFileSync(logPath, JSON.stringify(forged) + '\n');

    const lines = readFileSync(logPath, 'utf-8').trim().split('\n').map(l => JSON.parse(l));
    expect(lines).toHaveLength(2);
    expect(verifyEntry(lines[0])).toBe(true);   // original entry still good
    expect(verifyEntry(lines[1])).toBe(false);  // forged entry detected
  });
});

describe('AuditLog — ordering & time integrity', () => {
  let dir: string;
  let logPath: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'odin-audit-order-'));
    logPath = join(dir, 'audit.log');
  });

  afterEach(() => {
    try { rmSync(dir, { recursive: true, force: true }); } catch {}
  });

  it('timestamps are monotonically non-decreasing for serial record() calls', async () => {
    const log = new AuditLog({ logPath });
    const entries = [];
    for (let i = 0; i < 10; i++) {
      entries.push(await log.record({
        agentDid: 'a', action: `op${i}`, resource: 'r',
        decision: ALLOW, taintLabel: TRUSTED, trustScore: 80,
      }));
      // small delay to pull timestamps apart
      await new Promise(r => setTimeout(r, 1));
    }
    for (let i = 1; i < entries.length; i++) {
      expect(entries[i].timestamp).toBeGreaterThanOrEqual(entries[i - 1].timestamp);
    }
  });

  it('each entry has a unique id (UUIDv4) regardless of identical content', async () => {
    const log = new AuditLog({ logPath });
    const ids = new Set<string>();
    for (let i = 0; i < 50; i++) {
      const e = await log.record({
        agentDid: 'a', action: 'read', resource: 'r',
        decision: ALLOW, taintLabel: TRUSTED, trustScore: 80,
      });
      ids.add(e.id);
    }
    expect(ids.size).toBe(50);
  });
});
