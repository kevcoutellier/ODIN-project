/**
 * EU AI Act compliance checker — Articles 13 & 14
 *
 * Consumes `AuditLogEntry[]` and answers two questions:
 *
 *   - **Article 13 (Transparency to users).** Are decisions auditable?
 *     Every entry should carry a human-readable reason, the trust score
 *     that was in effect, the policy that was applied, and a tamper-
 *     evident signature. We compute per-field coverage rates and flag
 *     anything below the configured threshold.
 *
 *   - **Article 14 (Human oversight).** Can a human stop or override?
 *     Two signals: (1) the agent exposes an override/stop mechanism
 *     (asserted by the caller — the checker cannot see it from logs
 *     alone), and (2) every high-risk action in the log carries a
 *     `humanApproval: true` condition on its policy decision.
 *
 * This is a **compliance *check*** — not a certification. A green report
 * means the log file contains the evidence the regulator expects, not
 * that the deployment is legally compliant. That determination still
 * belongs to the operator and their DPO.
 *
 * References: Regulation (EU) 2024/1689, Articles 13 & 14.
 */

import type { AuditLogEntry } from '@odin/core';

export interface ComplianceThresholds {
  /** Fraction of entries that must carry a non-empty `decision.reason`. */
  minReasonRate: number;
  /** Fraction of entries that must record the trust score that was active. */
  minTrustDisclosureRate: number;
  /** Fraction of entries whose `decision.policy` identifies the applied rule. */
  minPolicyIdentifiedRate: number;
  /** Fraction of entries carrying a non-empty Ed25519 signature. */
  minSignatureRate: number;
  /** Fraction of high-risk entries that must carry humanApproval=true. */
  minHumanOversightRate: number;
}

export const DEFAULT_THRESHOLDS: ComplianceThresholds = {
  minReasonRate: 0.95,
  minTrustDisclosureRate: 0.95,
  minPolicyIdentifiedRate: 0.9,
  minSignatureRate: 0.95,
  minHumanOversightRate: 1.0,
};

/** Actions treated as high-risk by default. Callers should override. */
export const DEFAULT_HIGH_RISK_ACTIONS = [
  'terminal.exec',
  'skill.install',
  'mcp.connect',
  'file.write',
];

export interface EuAiActCheckerOptions {
  thresholds?: Partial<ComplianceThresholds>;
  highRiskActions?: string[];
  /**
   * Whether the runtime exposes an operator-accessible kill / override
   * mechanism. Cannot be derived from the log — the caller must assert it.
   * Default is `false`: absent evidence, assume absent mechanism.
   */
  overrideMechanismPresent?: boolean;
}

export interface Article13Result {
  entriesTotal: number;
  entriesWithReason: number;
  entriesWithTrustScore: number;
  entriesWithPolicy: number;
  entriesSigned: number;
  reasonRate: number;
  trustDisclosureRate: number;
  policyIdentifiedRate: number;
  signatureRate: number;
  compliant: boolean;
  violations: string[];
}

export interface Article14Result {
  entriesTotal: number;
  highRiskEntriesTotal: number;
  highRiskWithHumanApproval: number;
  blockedDecisions: number;
  overrideMechanismPresent: boolean;
  humanOversightRate: number;
  enforcementRate: number;
  compliant: boolean;
  violations: string[];
}

export interface ComplianceReport {
  timestamp: number;
  entriesExamined: number;
  article13: Article13Result;
  article14: Article14Result;
  overallCompliant: boolean;
}

function pct(x: number): string {
  return `${(x * 100).toFixed(1)}%`;
}

export class EuAiActComplianceChecker {
  constructor(private readonly opts: EuAiActCheckerOptions = {}) {}

  check(entries: readonly AuditLogEntry[]): ComplianceReport {
    const t: ComplianceThresholds = { ...DEFAULT_THRESHOLDS, ...this.opts.thresholds };
    const highRisk = new Set(this.opts.highRiskActions ?? DEFAULT_HIGH_RISK_ACTIONS);
    const overridePresent = !!this.opts.overrideMechanismPresent;

    const total = entries.length;
    let withReason = 0;
    let withTrust = 0;
    let withPolicy = 0;
    let signed = 0;
    let blocked = 0;
    let hrTotal = 0;
    let hrApproved = 0;

    for (const e of entries) {
      if (e.decision?.reason && e.decision.reason.trim().length > 0) withReason++;
      if (typeof e.trustScore === 'number' && Number.isFinite(e.trustScore)) withTrust++;
      if (e.decision?.policy && e.decision.policy.length > 0) withPolicy++;
      if (e.signature && e.signature.length > 0) signed++;
      if (e.decision && e.decision.allowed === false) blocked++;
      if (highRisk.has(e.action)) {
        hrTotal++;
        if (e.decision?.conditions?.humanApproval === true) hrApproved++;
      }
    }

    const rate = (n: number, d: number) => (d === 0 ? 1 : n / d);
    const reasonRate = rate(withReason, total);
    const trustRate = rate(withTrust, total);
    const policyRate = rate(withPolicy, total);
    const sigRate = rate(signed, total);
    const oversightRate = rate(hrApproved, hrTotal);
    const enforcementRate = total === 0 ? 0 : blocked / total;

    const a13Violations: string[] = [];
    if (reasonRate < t.minReasonRate)
      a13Violations.push(`reason coverage ${pct(reasonRate)} < required ${pct(t.minReasonRate)}`);
    if (trustRate < t.minTrustDisclosureRate)
      a13Violations.push(`trust score disclosure ${pct(trustRate)} < required ${pct(t.minTrustDisclosureRate)}`);
    if (policyRate < t.minPolicyIdentifiedRate)
      a13Violations.push(`policy identification ${pct(policyRate)} < required ${pct(t.minPolicyIdentifiedRate)}`);
    if (sigRate < t.minSignatureRate)
      a13Violations.push(`signature coverage ${pct(sigRate)} < required ${pct(t.minSignatureRate)}`);

    const a14Violations: string[] = [];
    if (!overridePresent)
      a14Violations.push('override/stop mechanism not asserted by runtime');
    if (oversightRate < t.minHumanOversightRate)
      a14Violations.push(
        `human oversight on high-risk actions ${pct(oversightRate)} < required ${pct(t.minHumanOversightRate)} ` +
          `(${hrApproved}/${hrTotal})`,
      );

    const a13: Article13Result = {
      entriesTotal: total,
      entriesWithReason: withReason,
      entriesWithTrustScore: withTrust,
      entriesWithPolicy: withPolicy,
      entriesSigned: signed,
      reasonRate,
      trustDisclosureRate: trustRate,
      policyIdentifiedRate: policyRate,
      signatureRate: sigRate,
      compliant: a13Violations.length === 0,
      violations: a13Violations,
    };
    const a14: Article14Result = {
      entriesTotal: total,
      highRiskEntriesTotal: hrTotal,
      highRiskWithHumanApproval: hrApproved,
      blockedDecisions: blocked,
      overrideMechanismPresent: overridePresent,
      humanOversightRate: oversightRate,
      enforcementRate,
      compliant: a14Violations.length === 0,
      violations: a14Violations,
    };

    return {
      timestamp: Date.now(),
      entriesExamined: total,
      article13: a13,
      article14: a14,
      overallCompliant: a13.compliant && a14.compliant,
    };
  }

  /** Compact human-readable summary suitable for logs / dashboards. */
  formatReport(r: ComplianceReport): string {
    const lines: string[] = [];
    lines.push(
      `EU AI Act compliance — ${r.overallCompliant ? 'PASS' : 'FAIL'} ` +
        `(${r.entriesExamined} entries examined)`,
    );
    lines.push(
      `  Article 13 (Transparency): ${r.article13.compliant ? 'PASS' : 'FAIL'}`,
    );
    lines.push(`    reason=${pct(r.article13.reasonRate)} trust=${pct(r.article13.trustDisclosureRate)} ` +
      `policy=${pct(r.article13.policyIdentifiedRate)} signed=${pct(r.article13.signatureRate)}`);
    for (const v of r.article13.violations) lines.push(`    - ${v}`);
    lines.push(
      `  Article 14 (Human oversight): ${r.article14.compliant ? 'PASS' : 'FAIL'}`,
    );
    lines.push(
      `    override=${r.article14.overrideMechanismPresent} ` +
        `oversight=${pct(r.article14.humanOversightRate)} ` +
        `enforcement=${pct(r.article14.enforcementRate)} ` +
        `highRisk=${r.article14.highRiskEntriesTotal}`,
    );
    for (const v of r.article14.violations) lines.push(`    - ${v}`);
    return lines.join('\n');
  }
}
