import { describe, it, expect } from 'vitest';
import { EuAiActComplianceChecker } from '../eu-ai-act.js';
import type { AuditLogEntry } from '@odin/core';
import { IntegrityLevel, ConfidentialityLevel } from '@odin/core';

function makeEntry(overrides: Partial<AuditLogEntry> = {}): AuditLogEntry {
  return {
    id: overrides.id ?? crypto.randomUUID(),
    timestamp: overrides.timestamp ?? Date.now(),
    agentDid: overrides.agentDid ?? 'did:odin:test',
    action: overrides.action ?? 'chat.send',
    resource: overrides.resource ?? 'conversation',
    decision: overrides.decision ?? {
      allowed: true,
      reason: 'trust score above threshold',
      policy: 'default.allow',
      evaluationTimeMs: 1,
      conditions: {},
    },
    taintLabel: overrides.taintLabel ?? {
      integrity: IntegrityLevel.TRUSTED,
      confidentiality: ConfidentialityLevel.PUBLIC,
      source: 'test',
      timestamp: Date.now(),
    },
    trustScore: overrides.trustScore ?? 85,
    signature: overrides.signature ?? 'deadbeef',
  };
}

describe('EuAiActComplianceChecker — Article 13 (transparency)', () => {
  it('passes when every entry has reason, trust, policy, and signature', () => {
    const checker = new EuAiActComplianceChecker({ overrideMechanismPresent: true });
    const entries = Array.from({ length: 100 }, () => makeEntry());
    const report = checker.check(entries);
    expect(report.article13.compliant).toBe(true);
    expect(report.article13.reasonRate).toBe(1);
    expect(report.article13.signatureRate).toBe(1);
    expect(report.article13.violations).toEqual([]);
  });

  it('flags entries missing the reason field', () => {
    const checker = new EuAiActComplianceChecker({ overrideMechanismPresent: true });
    const entries: AuditLogEntry[] = [
      ...Array.from({ length: 80 }, () => makeEntry()),
      ...Array.from({ length: 20 }, () =>
        makeEntry({
          decision: {
            allowed: true,
            reason: '',
            policy: 'p',
            evaluationTimeMs: 1,
            conditions: {},
          },
        }),
      ),
    ];
    const report = checker.check(entries);
    expect(report.article13.compliant).toBe(false);
    expect(report.article13.reasonRate).toBeCloseTo(0.8, 2);
    expect(report.article13.violations.some(v => v.includes('reason coverage'))).toBe(true);
  });

  it('flags unsigned audit entries', () => {
    const checker = new EuAiActComplianceChecker({ overrideMechanismPresent: true });
    const entries: AuditLogEntry[] = [
      ...Array.from({ length: 50 }, () => makeEntry()),
      ...Array.from({ length: 50 }, () => makeEntry({ signature: '' })),
    ];
    const report = checker.check(entries);
    expect(report.article13.signatureRate).toBeCloseTo(0.5, 2);
    expect(report.article13.compliant).toBe(false);
    expect(report.article13.violations.some(v => v.includes('signature coverage'))).toBe(true);
  });

  it('flags missing policy identifiers', () => {
    const checker = new EuAiActComplianceChecker({ overrideMechanismPresent: true });
    const entries: AuditLogEntry[] = Array.from({ length: 10 }, () =>
      makeEntry({
        decision: { allowed: true, reason: 'ok', policy: '', evaluationTimeMs: 1, conditions: {} },
      }),
    );
    const report = checker.check(entries);
    expect(report.article13.policyIdentifiedRate).toBe(0);
    expect(report.article13.compliant).toBe(false);
    expect(report.article13.violations.some(v => v.includes('policy identification'))).toBe(true);
  });

  it('treats an empty log as trivially compliant for article 13', () => {
    const checker = new EuAiActComplianceChecker({ overrideMechanismPresent: true });
    const report = checker.check([]);
    expect(report.article13.compliant).toBe(true);
    expect(report.article13.entriesTotal).toBe(0);
  });
});

describe('EuAiActComplianceChecker — Article 14 (human oversight)', () => {
  it('fails when no override mechanism is asserted by the runtime', () => {
    const checker = new EuAiActComplianceChecker({
      overrideMechanismPresent: false,
    });
    const report = checker.check([makeEntry()]);
    expect(report.article14.compliant).toBe(false);
    expect(report.article14.violations.some(v => v.includes('override'))).toBe(true);
  });

  it('passes when override is asserted and no high-risk actions were taken', () => {
    const checker = new EuAiActComplianceChecker({ overrideMechanismPresent: true });
    const report = checker.check([makeEntry({ action: 'chat.send' })]);
    expect(report.article14.compliant).toBe(true);
  });

  it('flags high-risk actions missing humanApproval', () => {
    const checker = new EuAiActComplianceChecker({
      overrideMechanismPresent: true,
      highRiskActions: ['terminal.exec'],
    });
    const entries = [
      makeEntry({
        action: 'terminal.exec',
        decision: {
          allowed: true,
          reason: 'ran rm -rf',
          policy: 'dangerous.allow',
          evaluationTimeMs: 1,
          conditions: {}, // no humanApproval
        },
      }),
    ];
    const report = checker.check(entries);
    expect(report.article14.highRiskEntriesTotal).toBe(1);
    expect(report.article14.highRiskWithHumanApproval).toBe(0);
    expect(report.article14.humanOversightRate).toBe(0);
    expect(report.article14.compliant).toBe(false);
    expect(report.article14.violations.some(v => v.includes('human oversight'))).toBe(true);
  });

  it('passes when every high-risk action has humanApproval=true', () => {
    const checker = new EuAiActComplianceChecker({
      overrideMechanismPresent: true,
      highRiskActions: ['skill.install'],
    });
    const entries = [
      makeEntry({
        action: 'skill.install',
        decision: {
          allowed: true,
          reason: 'approved by operator',
          policy: 'skill.install.with-approval',
          evaluationTimeMs: 1,
          conditions: { humanApproval: true },
        },
      }),
    ];
    const report = checker.check(entries);
    expect(report.article14.humanOversightRate).toBe(1);
    expect(report.article14.compliant).toBe(true);
  });

  it('counts blocked decisions as enforcement evidence', () => {
    const checker = new EuAiActComplianceChecker({ overrideMechanismPresent: true });
    const entries = [
      makeEntry({
        action: 'chat.send',
        decision: {
          allowed: false,
          reason: 'blocked',
          policy: 'x',
          evaluationTimeMs: 1,
          conditions: {},
        },
      }),
      makeEntry(),
    ];
    const report = checker.check(entries);
    expect(report.article14.blockedDecisions).toBe(1);
    expect(report.article14.enforcementRate).toBe(0.5);
  });
});

describe('EuAiActComplianceChecker — aggregate report', () => {
  it('overallCompliant is the AND of article 13 and 14', () => {
    const checker = new EuAiActComplianceChecker({ overrideMechanismPresent: true });
    const goodReport = checker.check([makeEntry()]);
    expect(goodReport.overallCompliant).toBe(true);

    const badReport = checker.check([makeEntry({ signature: '' })]);
    expect(badReport.overallCompliant).toBe(false);
  });

  it('formatReport produces a non-empty human-readable string', () => {
    const checker = new EuAiActComplianceChecker({ overrideMechanismPresent: true });
    const report = checker.check([makeEntry()]);
    const formatted = checker.formatReport(report);
    expect(formatted).toContain('Article 13');
    expect(formatted).toContain('Article 14');
    expect(formatted).toContain('PASS');
  });

  it('formatReport lists every violation', () => {
    const checker = new EuAiActComplianceChecker({
      overrideMechanismPresent: false,
      highRiskActions: ['terminal.exec'],
    });
    const report = checker.check([
      makeEntry({ action: 'terminal.exec', signature: '' }),
    ]);
    const formatted = checker.formatReport(report);
    expect(formatted).toContain('FAIL');
    expect(formatted).toContain('override');
    expect(formatted).toContain('signature');
    expect(formatted).toContain('human oversight');
  });
});
