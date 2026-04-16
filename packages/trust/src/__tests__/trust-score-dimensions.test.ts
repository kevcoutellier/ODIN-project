import { describe, it, expect } from 'vitest';
import { AgentLayersClient, TrustScoreManager, type LocalTrustMetrics } from '../agentlayers-client.js';

function makeManager(): TrustScoreManager {
  const client = new AgentLayersClient({ baseUrl: 'http://unused' });
  return new TrustScoreManager(client, 'did:odin:test');
}

const baseMetrics: LocalTrustMetrics = {
  uptime: 95,
  successRate: 0.9,
  violationCount: 0,
};

describe('TrustScoreManager.computeLocalBaseline — transparency dimension', () => {
  it('is marked neutral-baseline when no audit entries exist', () => {
    const mgr = makeManager();
    const score = mgr.computeLocalBaseline(baseMetrics);
    expect(score.dimensions.transparency).toBe(70);
    expect(mgr.getLastExplanation()?.dimensionEvidence.transparency).toBe('neutral-baseline');
  });

  it('is 100 when every audit entry is signed and has a reason', () => {
    const mgr = makeManager();
    const score = mgr.computeLocalBaseline({
      ...baseMetrics,
      auditEntriesTotal: 50,
      auditEntriesSigned: 50,
      auditEntriesWithReason: 50,
    });
    expect(score.dimensions.transparency).toBe(100);
    expect(mgr.getLastExplanation()?.dimensionEvidence.transparency).toBe('computed');
  });

  it('reflects a mix of signed/unsigned and reasoned/un-reasoned entries', () => {
    const mgr = makeManager();
    // 50% signed, 80% reasoned → 0.4*0.5 + 0.6*0.8 = 0.2 + 0.48 = 0.68 → 68
    const score = mgr.computeLocalBaseline({
      ...baseMetrics,
      auditEntriesTotal: 100,
      auditEntriesSigned: 50,
      auditEntriesWithReason: 80,
    });
    expect(score.dimensions.transparency).toBeCloseTo(68, 0);
  });

  it('is 0 when entries exist but none are signed or reasoned', () => {
    const mgr = makeManager();
    const score = mgr.computeLocalBaseline({
      ...baseMetrics,
      auditEntriesTotal: 10,
      auditEntriesSigned: 0,
      auditEntriesWithReason: 0,
    });
    expect(score.dimensions.transparency).toBe(0);
  });
});

describe('TrustScoreManager.computeLocalBaseline — compliance dimension', () => {
  it('is marked neutral-baseline when no policy evaluations have run', () => {
    const mgr = makeManager();
    const score = mgr.computeLocalBaseline(baseMetrics);
    expect(score.dimensions.compliance).toBe(50);
    expect(mgr.getLastExplanation()?.dimensionEvidence.compliance).toBe('neutral-baseline');
  });

  it('gives +40 enforcement points for a policy engine that actually denies', () => {
    const mgr = makeManager();
    // 20% denial rate → enforcement bonus = 40 (capped); oversight 20 → 100
    const score = mgr.computeLocalBaseline({
      ...baseMetrics,
      policyEvaluationsTotal: 100,
      policyEvaluationsDenied: 20,
      humanApprovalRequiredCount: 5,
      humanApprovalGrantedCount: 5,
    });
    expect(score.dimensions.compliance).toBe(100);
    expect(mgr.getLastExplanation()?.dimensionEvidence.compliance).toBe('computed');
  });

  it('penalises missing human approvals when they were required', () => {
    const mgr = makeManager();
    // No denials, 10 approvals required but only 5 granted → oversightFrac=0.5
    // → 40 + 0 + 10 = 50
    const score = mgr.computeLocalBaseline({
      ...baseMetrics,
      policyEvaluationsTotal: 100,
      policyEvaluationsDenied: 0,
      humanApprovalRequiredCount: 10,
      humanApprovalGrantedCount: 5,
    });
    expect(score.dimensions.compliance).toBe(50);
  });

  it('rewards a rubber-stamp-free policy engine (no evals yet still means unknown)', () => {
    const mgr = makeManager();
    const score = mgr.computeLocalBaseline({
      ...baseMetrics,
      policyEvaluationsTotal: 0,
    });
    expect(score.dimensions.compliance).toBe(50);
    expect(mgr.getLastExplanation()?.dimensionEvidence.compliance).toBe('neutral-baseline');
  });
});

describe('TrustScoreManager.computeLocalBaseline — reputation dimension', () => {
  it('is marked neutral-baseline when there is no peer or operational history', () => {
    const mgr = makeManager();
    const score = mgr.computeLocalBaseline(baseMetrics);
    expect(score.dimensions.reputation).toBe(50);
    expect(mgr.getLastExplanation()?.dimensionEvidence.reputation).toBe('neutral-baseline');
  });

  it('credits successful peer verifications', () => {
    const mgr = makeManager();
    // 100% peer verification rate, 0 days maturity → 0.6*1 + 0.4*0 = 0.6 → 60
    const score = mgr.computeLocalBaseline({
      ...baseMetrics,
      peerInteractionsCount: 20,
      peerSuccessfulVerifications: 20,
      operationalDays: 0,
    });
    expect(score.dimensions.reputation).toBe(60);
    expect(mgr.getLastExplanation()?.dimensionEvidence.reputation).toBe('computed');
  });

  it('credits operational maturity up to 90 days', () => {
    const mgr = makeManager();
    // No peers, 90 days → peerFrac=0, maturity=1 → 0.6*0 + 0.4*1 = 0.4 → 40
    const score = mgr.computeLocalBaseline({
      ...baseMetrics,
      peerInteractionsCount: 0,
      operationalDays: 90,
    });
    expect(score.dimensions.reputation).toBe(40);
  });

  it('caps maturity at 90 days (180 days is not worth more than 90)', () => {
    const mgr = makeManager();
    const s90 = makeManager().computeLocalBaseline({
      ...baseMetrics,
      peerInteractionsCount: 10,
      peerSuccessfulVerifications: 10,
      operationalDays: 90,
    });
    const s180 = mgr.computeLocalBaseline({
      ...baseMetrics,
      peerInteractionsCount: 10,
      peerSuccessfulVerifications: 10,
      operationalDays: 180,
    });
    expect(s180.dimensions.reputation).toBe(s90.dimensions.reputation);
  });

  it('penalises peers that failed verification', () => {
    const mgr = makeManager();
    // 5 of 20 verified → 0.25, 0 days → 0.6*0.25 + 0.4*0 = 0.15 → 15
    const score = mgr.computeLocalBaseline({
      ...baseMetrics,
      peerInteractionsCount: 20,
      peerSuccessfulVerifications: 5,
      operationalDays: 0,
    });
    expect(score.dimensions.reputation).toBe(15);
  });
});

describe('TrustScoreManager.computeLocalBaseline — overall aggregation', () => {
  it('weights all six dimensions into the overall score', () => {
    const mgr = makeManager();
    const score = mgr.computeLocalBaseline({
      uptime: 100,
      successRate: 1.0,
      violationCount: 0,
      auditEntriesTotal: 10,
      auditEntriesSigned: 10,
      auditEntriesWithReason: 10,
      policyEvaluationsTotal: 100,
      policyEvaluationsDenied: 20,
      humanApprovalRequiredCount: 1,
      humanApprovalGrantedCount: 1,
      peerInteractionsCount: 10,
      peerSuccessfulVerifications: 10,
      operationalDays: 90,
    });
    // All dimensions at 100 → overall = 100
    expect(score.overall).toBe(100);
    expect(score.dimensions.performance).toBe(100);
    expect(score.dimensions.transparency).toBe(100);
    expect(score.dimensions.security).toBe(100);
    expect(score.dimensions.compliance).toBe(100);
    expect(score.dimensions.reputation).toBe(100);
    expect(score.dimensions.reliability).toBe(100);
  });

  it('keeps backward compatibility with the original 3-metric call signature', () => {
    const mgr = makeManager();
    // Only uptime / successRate / violationCount — the way the CLI called it
    const score = mgr.computeLocalBaseline({
      uptime: 100,
      successRate: 1.0,
      violationCount: 0,
    });
    expect(score.dimensions.performance).toBe(100);
    expect(score.dimensions.security).toBe(100);
    expect(score.dimensions.reliability).toBe(100);
    // The three new dims fall back to neutral baselines, not hardcoded 80/50/50
    // — but their values are explicitly flagged as neutral-baseline
    const ev = mgr.getLastExplanation()!.dimensionEvidence;
    expect(ev.transparency).toBe('neutral-baseline');
    expect(ev.compliance).toBe('neutral-baseline');
    expect(ev.reputation).toBe('neutral-baseline');
    expect(ev.performance).toBe('computed');
    expect(ev.security).toBe('computed');
    expect(ev.reliability).toBe('computed');
  });

  it('clamps all dimensions to [0, 100]', () => {
    const mgr = makeManager();
    const score = mgr.computeLocalBaseline({
      uptime: 9999,
      successRate: 2,
      violationCount: -5,
      auditEntriesTotal: 10,
      auditEntriesSigned: 10,
      auditEntriesWithReason: 10,
    });
    expect(score.dimensions.performance).toBe(100);
    expect(score.dimensions.reliability).toBe(100);
    expect(score.dimensions.security).toBe(100);
    expect(score.overall).toBeLessThanOrEqual(100);
    expect(score.overall).toBeGreaterThanOrEqual(0);
  });
});
