/**
 * Audit log tests — append-only, tamper-evident, EU AI Act compliance.
 *
 * These tests verify the core promises made to the dashboard's Compliance
 * card: every security decision is recorded, signed over a stable subset
 * of fields, and persisted to disk in append-only fashion.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { AuditLog } from '../audit-log.js';
import {
  IntegrityLevel,
  ConfidentialityLevel,
  type PolicyDecision,
  type TaintLabel,
} from '@odin/core';

const TRUSTED_LABEL: TaintLabel = {
  integrity: IntegrityLevel.TRUSTED,
  confidentiality: ConfidentialityLevel.PUBLIC,
  source: 'test',
  timestamp: Date.now(),
};

const ALLOW: PolicyDecision = {
  allowed: true,
  reason: 'ok',
  policy: 'default',
  evaluationTimeMs: 1,
  conditions: {},
};

const DENY: PolicyDecision = {
  allowed: false,
  reason: 'blocked',
  policy: 'default',
  evaluationTimeMs: 1,
  conditions: {},
};

describe('AuditLog', () => {
  let dir: string;
  let logPath: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'odin-audit-'));
    logPath = join(dir, 'nested', 'audit.log');
  });

  afterEach(() => {
    try { rmSync(dir, { recursive: true, force: true }); } catch {}
  });

  it('creates nested log directory on init', async () => {
    const log = new AuditLog({ logPath });
    await log.record({
      agentDid: 'did:odin:test',
      action: 'read',
      resource: '/file',
      decision: ALLOW,
      taintLabel: TRUSTED_LABEL,
      trustScore: 80,
    });
    expect(existsSync(logPath)).toBe(true);
  });

  it('record() returns an entry with id, timestamp and no signature when signFn absent', async () => {
    const log = new AuditLog({ logPath });
    const entry = await log.record({
      agentDid: 'did:odin:test',
      action: 'tool_call',
      resource: 'shell',
      decision: ALLOW,
      taintLabel: TRUSTED_LABEL,
      trustScore: 70,
    });
    expect(entry.id).toBeTruthy();
    expect(entry.timestamp).toBeGreaterThan(0);
    expect(entry.signature).toBe('');
  });

  it('record() invokes signFn and stores the signature', async () => {
    const signed: string[] = [];
    const signFn = (data: string) => {
      signed.push(data);
      return `sig:${data.length}`;
    };
    const log = new AuditLog({ logPath, signFn });
    const entry = await log.record({
      agentDid: 'did:odin:abc',
      action: 'read',
      resource: '/secret',
      decision: DENY,
      taintLabel: TRUSTED_LABEL,
      trustScore: 42,
    });
    expect(signed).toHaveLength(1);
    expect(entry.signature).toBe(`sig:${signed[0].length}`);
  });

  it('signed payload covers id/timestamp/agentDid/action/resource/decision.allowed', async () => {
    let captured = '';
    const log = new AuditLog({
      logPath,
      signFn: (data) => { captured = data; return 'sig'; },
    });
    const entry = await log.record({
      agentDid: 'did:odin:x',
      action: 'read',
      resource: '/r',
      decision: DENY,
      taintLabel: TRUSTED_LABEL,
      trustScore: 10,
    });
    const parsed = JSON.parse(captured);
    expect(parsed).toEqual({
      id: entry.id,
      timestamp: entry.timestamp,
      agentDid: 'did:odin:x',
      action: 'read',
      resource: '/r',
      decision: false,
    });
    // trustScore and full taintLabel are NOT in the signed payload — document this.
    expect(parsed).not.toHaveProperty('trustScore');
    expect(parsed).not.toHaveProperty('taintLabel');
  });

  it('appends every record to disk on a new line (append-only)', async () => {
    const log = new AuditLog({ logPath });
    await log.record({ agentDid: 'a', action: 'read', resource: 'x', decision: ALLOW, taintLabel: TRUSTED_LABEL, trustScore: 80 });
    await log.record({ agentDid: 'a', action: 'write', resource: 'y', decision: DENY, taintLabel: TRUSTED_LABEL, trustScore: 20 });

    const raw = readFileSync(logPath, 'utf-8');
    const lines = raw.trim().split('\n');
    expect(lines).toHaveLength(2);
    const [first, second] = lines.map(l => JSON.parse(l));
    expect(first.action).toBe('read');
    expect(second.action).toBe('write');
    expect(second.decision.allowed).toBe(false);
  });

  it('getEntries respects the limit and returns the latest entries', async () => {
    const log = new AuditLog({ logPath });
    for (let i = 0; i < 10; i++) {
      await log.record({
        agentDid: 'a', action: `op${i}`, resource: 'r', decision: ALLOW, taintLabel: TRUSTED_LABEL, trustScore: 50,
      });
    }
    const last3 = log.getEntries(3);
    expect(last3).toHaveLength(3);
    expect(last3.map(e => e.action)).toEqual(['op7', 'op8', 'op9']);
  });

  it('getEntriesByAction filters by action name', async () => {
    const log = new AuditLog({ logPath });
    await log.record({ agentDid: 'a', action: 'read', resource: 'r', decision: ALLOW, taintLabel: TRUSTED_LABEL, trustScore: 80 });
    await log.record({ agentDid: 'a', action: 'write', resource: 'r', decision: ALLOW, taintLabel: TRUSTED_LABEL, trustScore: 80 });
    await log.record({ agentDid: 'a', action: 'read', resource: 'r', decision: DENY, taintLabel: TRUSTED_LABEL, trustScore: 10 });

    const reads = log.getEntriesByAction('read');
    expect(reads).toHaveLength(2);
    expect(reads.every(e => e.action === 'read')).toBe(true);
  });

  it('getDeniedEntries returns only blocked decisions', async () => {
    const log = new AuditLog({ logPath });
    await log.record({ agentDid: 'a', action: 'read', resource: 'r', decision: ALLOW, taintLabel: TRUSTED_LABEL, trustScore: 80 });
    await log.record({ agentDid: 'a', action: 'write', resource: 'r', decision: DENY, taintLabel: TRUSTED_LABEL, trustScore: 10 });

    const denied = log.getDeniedEntries();
    expect(denied).toHaveLength(1);
    expect(denied[0].action).toBe('write');
  });

  it('exportComplianceReport aggregates counts, trust range and time range', async () => {
    const log = new AuditLog({ logPath });
    await log.record({ agentDid: 'a', action: 'read', resource: 'r', decision: ALLOW, taintLabel: TRUSTED_LABEL, trustScore: 90 });
    await log.record({ agentDid: 'a', action: 'read', resource: 'r', decision: ALLOW, taintLabel: TRUSTED_LABEL, trustScore: 60 });
    await log.record({ agentDid: 'a', action: 'write', resource: 'r', decision: DENY, taintLabel: TRUSTED_LABEL, trustScore: 30 });

    const report = log.exportComplianceReport();
    expect(report.totalDecisions).toBe(3);
    expect(report.deniedDecisions).toBe(1);
    expect(report.trustScoreRange).toEqual({ min: 30, max: 90 });
    expect(report.actionSummary).toEqual({ read: 2, write: 1 });
    expect(report.timeRange.from).toBeLessThanOrEqual(report.timeRange.to);
  });

  it('exportComplianceReport tolerates an empty log', async () => {
    const log = new AuditLog({ logPath });
    await log.init();
    const report = log.exportComplianceReport();
    expect(report.totalDecisions).toBe(0);
    expect(report.deniedDecisions).toBe(0);
    expect(report.trustScoreRange).toEqual({ min: 0, max: 0 });
    expect(report.actionSummary).toEqual({});
    expect(report.timeRange).toEqual({ from: 0, to: 0 });
  });

  it('caps in-memory entries at 5000 while persisting all to disk', async () => {
    const log = new AuditLog({ logPath });
    for (let i = 0; i < 5010; i++) {
      await log.record({
        agentDid: 'a', action: `op${i}`, resource: 'r', decision: ALLOW, taintLabel: TRUSTED_LABEL, trustScore: 50,
      });
    }
    // In-memory cap
    expect(log.getEntries(10000).length).toBe(5000);
    // The oldest memory entry is op10 (0-9 have been dropped)
    expect(log.getEntries(5000)[0].action).toBe('op10');
    // But disk has every line
    const lines = readFileSync(logPath, 'utf-8').trim().split('\n');
    expect(lines).toHaveLength(5010);
  });
});
