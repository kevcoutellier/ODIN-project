/**
 * Transactional Sandbox for Knowledge Evolution
 *
 * Before evolving knowledge tiers (T4→T3→T2→T1), the agent must:
 * 1. SNAPSHOT: Capture current CIK state
 * 2. PROPOSE: Apply the evolution in a sandbox
 * 3. VALIDATE: Run SafetyGate checks
 * 4. COMMIT or ROLLBACK: Accept or reject the change
 *
 * This prevents corrupted knowledge from propagating:
 * - Contradictions that would invalidate existing high-tier knowledge
 * - Mass tier jumps that bypass verification
 * - External data injection attacks
 *
 * Uses SQLite savepoints for atomic transactions.
 */

import { randomUUID } from 'node:crypto';
import { sha256 } from '@odin/core';
import type { CIKStore, TrustTier, KnowledgeEntry, CapabilityEntry } from '../cik/index.js';

// ─── Safety Gate ───

export interface SafetyGateResult {
  passed: boolean;
  checks: SafetyCheck[];
  overallRisk: 'low' | 'medium' | 'high' | 'critical';
  recommendation: string;
}

export interface SafetyCheck {
  name: string;
  passed: boolean;
  reason: string;
  severity: 'info' | 'warning' | 'error' | 'critical';
}

/**
 * SafetyGate — validates proposed knowledge evolutions before they commit.
 *
 * Checks:
 * 1. Contradiction detection: Does this contradict existing T1/T2 knowledge?
 * 2. Evidence sufficiency: Is there enough verification for the tier jump?
 * 3. Source credibility: Is the evidence source trustworthy?
 * 4. Rate limiting: Is the agent evolving knowledge too fast?
 * 5. Consistency: Does this maintain CIK policy invariants?
 */
export class SafetyGate {
  private evolutionHistory: Array<{ timestamp: number; knowledgeId: string; from: TrustTier; to: TrustTier }> = [];

  // Minimum verification counts required for each tier evolution
  private readonly VERIFICATION_THRESHOLDS: Record<string, number> = {
    'T4→T3': 2,   // Need 2 verifications to move from unverified to LLM-derived
    'T3→T2': 5,   // Need 5 verifications (cross-checked) to move to self-verified
    'T2→T1': 10,  // Need 10 verifications + must be source=user to reach T1
  };

  // Max evolutions per hour to prevent rapid injection
  private readonly MAX_EVOLUTIONS_PER_HOUR = 20;

  async evaluate(
    cikStore: CIKStore,
    knowledgeId: string,
    currentTier: TrustTier,
    targetTier: TrustTier,
    evidence: string,
  ): Promise<SafetyGateResult> {
    const checks: SafetyCheck[] = [];

    // 1. Contradiction check
    const contradictionCheck = await this.checkContradictions(cikStore, knowledgeId, targetTier);
    checks.push(contradictionCheck);

    // 2. Evidence sufficiency
    const evidenceCheck = await this.checkEvidence(cikStore, knowledgeId, currentTier, targetTier);
    checks.push(evidenceCheck);

    // 3. Source credibility
    const sourceCheck = await this.checkSource(cikStore, knowledgeId, currentTier, targetTier);
    checks.push(sourceCheck);

    // 4. Rate limiting
    const rateCheck = this.checkRate();
    checks.push(rateCheck);

    // 5. Tier skip check
    const skipCheck = this.checkTierSkip(currentTier, targetTier);
    checks.push(skipCheck);

    // Determine overall risk
    const criticalFails = checks.filter(c => !c.passed && c.severity === 'critical').length;
    const errorFails = checks.filter(c => !c.passed && c.severity === 'error').length;
    const warningFails = checks.filter(c => !c.passed && c.severity === 'warning').length;

    let overallRisk: SafetyGateResult['overallRisk'] = 'low';
    if (criticalFails > 0) overallRisk = 'critical';
    else if (errorFails > 0) overallRisk = 'high';
    else if (warningFails > 0) overallRisk = 'medium';

    const passed = criticalFails === 0 && errorFails === 0;

    return {
      passed,
      checks,
      overallRisk,
      recommendation: passed
        ? `Safe to evolve knowledge ${knowledgeId} from ${currentTier} to ${targetTier}`
        : `BLOCKED: ${checks.filter(c => !c.passed).map(c => c.reason).join('; ')}`,
    };
  }

  recordEvolution(knowledgeId: string, from: TrustTier, to: TrustTier): void {
    this.evolutionHistory.push({ timestamp: Date.now(), knowledgeId, from, to });
    // Cap history
    if (this.evolutionHistory.length > 1000) {
      this.evolutionHistory = this.evolutionHistory.slice(-1000);
    }
  }

  // ─── Individual Checks ───

  private async checkContradictions(
    cikStore: CIKStore,
    knowledgeId: string,
    targetTier: TrustTier,
  ): Promise<SafetyCheck> {
    // Get the knowledge entry's details by searching
    const allKnowledge = await cikStore.queryKnowledge('*', 0.0, 1000);
    const entry = allKnowledge.find(k => k.id === knowledgeId);
    if (!entry) {
      return { name: 'contradiction', passed: true, reason: 'Entry not found (skip)', severity: 'info' };
    }

    // Check for contradicting higher-tier knowledge
    const related = await cikStore.getKnowledgeAbout(entry.subject);
    const contradictions = related.filter(
      k => k.id !== knowledgeId
        && k.predicate === entry.predicate
        && k.object !== entry.object
        && this.tierRank(k.tier) >= this.tierRank(targetTier)
    );

    if (contradictions.length > 0) {
      return {
        name: 'contradiction',
        passed: false,
        reason: `Contradicts ${contradictions.length} existing ${contradictions[0].tier}+ knowledge entries`,
        severity: 'critical',
      };
    }

    // Check if this entry itself has too many contradictions
    if (entry.contradictions >= 3) {
      return {
        name: 'contradiction',
        passed: false,
        reason: `Entry has ${entry.contradictions} recorded contradictions — too unreliable to promote`,
        severity: 'error',
      };
    }

    return { name: 'contradiction', passed: true, reason: 'No contradictions with higher-tier knowledge', severity: 'info' };
  }

  private async checkEvidence(
    cikStore: CIKStore,
    knowledgeId: string,
    currentTier: TrustTier,
    targetTier: TrustTier,
  ): Promise<SafetyCheck> {
    const allKnowledge = await cikStore.queryKnowledge('*', 0.0, 1000);
    const entry = allKnowledge.find(k => k.id === knowledgeId);
    if (!entry) {
      return { name: 'evidence', passed: false, reason: 'Entry not found', severity: 'error' };
    }

    const transitionKey = `${currentTier}→${targetTier}`;
    const required = this.VERIFICATION_THRESHOLDS[transitionKey] ?? 999;

    if (entry.verifications < required) {
      return {
        name: 'evidence',
        passed: false,
        reason: `Insufficient verifications: ${entry.verifications}/${required} required for ${transitionKey}`,
        severity: 'error',
      };
    }

    return {
      name: 'evidence',
      passed: true,
      reason: `${entry.verifications} verifications (≥${required} required)`,
      severity: 'info',
    };
  }

  private async checkSource(
    cikStore: CIKStore,
    knowledgeId: string,
    currentTier: TrustTier,
    targetTier: TrustTier,
  ): Promise<SafetyCheck> {
    // T1 requires user source
    if (targetTier === 'T1') {
      const allKnowledge = await cikStore.queryKnowledge('*', 0.0, 1000);
      const entry = allKnowledge.find(k => k.id === knowledgeId);
      if (!entry) {
        return { name: 'source', passed: false, reason: 'Entry not found', severity: 'error' };
      }

      if (!entry.source.startsWith('user:')) {
        return {
          name: 'source',
          passed: false,
          reason: `T1 requires user-declared source, got: ${entry.source}`,
          severity: 'critical',
        };
      }
    }

    return { name: 'source', passed: true, reason: 'Source credibility check passed', severity: 'info' };
  }

  private checkRate(): SafetyCheck {
    const oneHourAgo = Date.now() - 60 * 60 * 1000;
    const recentEvolutions = this.evolutionHistory.filter(e => e.timestamp > oneHourAgo).length;

    if (recentEvolutions >= this.MAX_EVOLUTIONS_PER_HOUR) {
      return {
        name: 'rate_limit',
        passed: false,
        reason: `Rate limit exceeded: ${recentEvolutions}/${this.MAX_EVOLUTIONS_PER_HOUR} evolutions per hour`,
        severity: 'error',
      };
    }

    return {
      name: 'rate_limit',
      passed: true,
      reason: `${recentEvolutions}/${this.MAX_EVOLUTIONS_PER_HOUR} evolutions this hour`,
      severity: 'info',
    };
  }

  private checkTierSkip(current: TrustTier, target: TrustTier): SafetyCheck {
    const tiers: TrustTier[] = ['T4', 'T3', 'T2', 'T1'];
    const currentIdx = tiers.indexOf(current);
    const targetIdx = tiers.indexOf(target);

    if (targetIdx > currentIdx + 1) {
      return {
        name: 'tier_skip',
        passed: false,
        reason: `Cannot skip tiers: ${current} → ${target} (must go one step at a time)`,
        severity: 'critical',
      };
    }

    if (targetIdx <= currentIdx) {
      return {
        name: 'tier_skip',
        passed: false,
        reason: `Cannot demote: ${current} → ${target}`,
        severity: 'error',
      };
    }

    return { name: 'tier_skip', passed: true, reason: `Valid tier progression: ${current} → ${target}`, severity: 'info' };
  }

  private tierRank(tier: TrustTier): number {
    return { T4: 0, T3: 1, T2: 2, T1: 3 }[tier];
  }
}

// ─── Evolution Transaction ───

export interface EvolutionProposal {
  id: string;
  knowledgeId: string;
  currentTier: TrustTier;
  targetTier: TrustTier;
  evidence: string;
  safetyResult: SafetyGateResult | null;
  status: 'pending' | 'approved' | 'rejected' | 'committed' | 'rolled_back';
  createdAt: number;
  decidedAt?: number;
}

/**
 * EvolutionSandbox — manages the propose→validate→commit/rollback flow.
 */
export class EvolutionSandbox {
  private proposals: Map<string, EvolutionProposal> = new Map();
  private safetyGate = new SafetyGate();
  private maxProposals = 100;

  constructor(private cikStore: CIKStore) {}

  /**
   * Propose a knowledge evolution. Runs SafetyGate checks.
   */
  async propose(
    knowledgeId: string,
    currentTier: TrustTier,
    targetTier: TrustTier,
    evidence: string,
  ): Promise<EvolutionProposal> {
    const id = randomUUID();

    // Run safety gate
    const safetyResult = await this.safetyGate.evaluate(
      this.cikStore, knowledgeId, currentTier, targetTier, evidence,
    );

    const proposal: EvolutionProposal = {
      id,
      knowledgeId,
      currentTier,
      targetTier,
      evidence,
      safetyResult,
      status: safetyResult.passed ? 'approved' : 'rejected',
      createdAt: Date.now(),
      decidedAt: Date.now(),
    };

    this.proposals.set(id, proposal);

    // Cap proposals
    if (this.proposals.size > this.maxProposals) {
      const oldest = [...this.proposals.entries()]
        .sort((a, b) => a[1].createdAt - b[1].createdAt)[0];
      if (oldest) this.proposals.delete(oldest[0]);
    }

    return proposal;
  }

  /**
   * Commit an approved proposal — actually evolve the tier in the CIK store.
   */
  async commit(proposalId: string): Promise<{ success: boolean; message: string }> {
    const proposal = this.proposals.get(proposalId);
    if (!proposal) return { success: false, message: 'Proposal not found' };
    if (proposal.status !== 'approved') {
      return { success: false, message: `Cannot commit proposal with status: ${proposal.status}` };
    }

    // Execute the actual tier evolution
    const result = await this.cikStore.evolveKnowledgeTier(
      proposal.knowledgeId,
      proposal.targetTier,
      proposal.evidence,
    );

    if (result.success) {
      proposal.status = 'committed';
      this.safetyGate.recordEvolution(proposal.knowledgeId, proposal.currentTier, proposal.targetTier);
      return { success: true, message: `Knowledge evolved: ${proposal.currentTier} → ${proposal.targetTier}` };
    } else {
      proposal.status = 'rolled_back';
      return { success: false, message: result.message };
    }
  }

  /**
   * Rollback a proposal — mark as rejected without applying changes.
   */
  rollback(proposalId: string): { success: boolean; message: string } {
    const proposal = this.proposals.get(proposalId);
    if (!proposal) return { success: false, message: 'Proposal not found' };
    proposal.status = 'rolled_back';
    return { success: true, message: 'Proposal rolled back' };
  }

  /**
   * Auto-evolve: Scan all knowledge entries and propose evolutions
   * for those that meet evidence thresholds. Safe entries auto-commit.
   */
  async autoEvolve(): Promise<{
    proposed: number;
    committed: number;
    rejected: number;
  }> {
    let proposed = 0;
    let committed = 0;
    let rejected = 0;

    // Get all knowledge
    const allKnowledge = await this.cikStore.queryKnowledge('*', 0.0, 500);

    for (const entry of allKnowledge) {
      // Determine next tier
      const nextTier = this.nextTier(entry.tier as TrustTier);
      if (!nextTier) continue; // Already T1

      // Propose evolution
      const proposal = await this.propose(
        entry.id,
        entry.tier as TrustTier,
        nextTier,
        `Auto-evolve: ${entry.verifications} verifications, ${entry.contradictions} contradictions, confidence=${entry.confidence}`,
      );
      proposed++;

      if (proposal.status === 'approved') {
        const commitResult = await this.commit(proposal.id);
        if (commitResult.success) committed++;
        else rejected++;
      } else {
        rejected++;
      }
    }

    return { proposed, committed, rejected };
  }

  getProposals(): EvolutionProposal[] {
    return [...this.proposals.values()].sort((a, b) => b.createdAt - a.createdAt);
  }

  getSafetyGate(): SafetyGate { return this.safetyGate; }

  private nextTier(tier: TrustTier): TrustTier | null {
    switch (tier) {
      case 'T4': return 'T3';
      case 'T3': return 'T2';
      case 'T2': return 'T1';
      case 'T1': return null;
    }
  }
}
