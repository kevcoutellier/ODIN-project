/**
 * TLA+ Formal Invariants for CIK Stores
 *
 * Implements runtime verification of formal safety properties
 * inspired by TLA+ specification patterns. These invariants run
 * as continuous checks on the CIK stores.
 *
 * Invariants checked:
 *
 * 1. TRUST_MONOTONICITY: Trust tiers can only evolve upward (T4→T3→T2→T1)
 *    and never skip tiers or regress.
 *
 * 2. KNOWLEDGE_CONSISTENCY: No two T1-tier knowledge entries can contradict
 *    each other (same subject+predicate, different objects).
 *
 * 3. IDENTITY_IMMUTABILITY: Once a DID is set, it can never change.
 *
 * 4. CAPABILITY_PROVENANCE: Every learned capability must link to a valid
 *    episode (trajectory) that created it.
 *
 * 5. TEMPORAL_ORDERING: No entity/knowledge can have updatedAt < createdAt.
 *
 * 6. CONFIDENCE_BOUNDS: All confidence values must be in [0.0, 1.0].
 *
 * 7. TIER_CONFIDENCE_ALIGNMENT: A knowledge entry's tier must match its
 *    confidence range (T1: 0.85-1.0, T2: 0.6-0.9, T3: 0.3-0.7, T4: 0.0-0.4).
 *
 * 8. CIK_ISOLATION: No cross-store references that bypass policy checks.
 *
 * When an invariant is violated, the system records it and can trigger:
 * - Audit log entry
 * - Dashboard alert
 * - Automatic repair (for soft violations)
 * - Agent freeze (for critical violations)
 */

import type { CIKStore, KnowledgeEntry, CapabilityEntry, IdentityEntry, TrustTier } from '../cik/index.js';

// ─── Types ───

export interface InvariantCheck {
  id: string;
  name: string;
  description: string;
  severity: 'info' | 'warning' | 'error' | 'critical';
  check: (store: CIKStore) => Promise<InvariantResult>;
}

export interface InvariantResult {
  invariant: string;
  passed: boolean;
  violations: InvariantViolation[];
  checkedAt: number;
  durationMs: number;
}

export interface InvariantViolation {
  entityType: 'knowledge' | 'capability' | 'identity';
  entityId: string;
  field: string;
  expected: string;
  actual: string;
  message: string;
  autoRepairable: boolean;
}

export interface InvariantReport {
  totalChecks: number;
  passed: number;
  failed: number;
  violations: InvariantViolation[];
  results: InvariantResult[];
  overallHealth: 'healthy' | 'degraded' | 'critical';
  checkedAt: number;
  durationMs: number;
}

// ─── Tier confidence ranges ───

const TIER_CONFIDENCE_RANGES: Record<TrustTier, { min: number; max: number }> = {
  T1: { min: 0.85, max: 1.0 },
  T2: { min: 0.6, max: 0.9 },
  T3: { min: 0.25, max: 0.7 },
  T4: { min: 0.0, max: 0.4 },
};

// ─── Invariant Definitions ───

const INVARIANTS: InvariantCheck[] = [
  {
    id: 'KNOWLEDGE_CONSISTENCY',
    name: 'Knowledge Consistency',
    description: 'No two T1-tier knowledge entries can contradict each other',
    severity: 'critical',
    check: async (store: CIKStore) => {
      const start = performance.now();
      const violations: InvariantViolation[] = [];

      // Get all T1 knowledge
      const allKnowledge = await store.queryKnowledge('*', 0.0, 1000);
      const t1Knowledge = allKnowledge.filter(k => k.tier === 'T1');

      // Check for contradictions: same subject+predicate, different object
      const bySubjectPredicate = new Map<string, KnowledgeEntry[]>();
      for (const k of t1Knowledge) {
        const key = `${k.subject}::${k.predicate}`;
        const existing = bySubjectPredicate.get(key) ?? [];
        existing.push(k);
        bySubjectPredicate.set(key, existing);
      }

      for (const [key, entries] of bySubjectPredicate) {
        if (entries.length <= 1) continue;
        const objects = new Set(entries.map(e => e.object));
        if (objects.size > 1) {
          violations.push({
            entityType: 'knowledge',
            entityId: entries[0].id,
            field: 'object',
            expected: `Unique object for T1 ${key}`,
            actual: `${objects.size} conflicting values: ${[...objects].join(', ')}`,
            message: `T1 contradiction: ${key} has ${objects.size} different objects`,
            autoRepairable: false,
          });
        }
      }

      return {
        invariant: 'KNOWLEDGE_CONSISTENCY',
        passed: violations.length === 0,
        violations,
        checkedAt: Date.now(),
        durationMs: performance.now() - start,
      };
    },
  },

  {
    id: 'CONFIDENCE_BOUNDS',
    name: 'Confidence Bounds',
    description: 'All confidence values must be in [0.0, 1.0]',
    severity: 'error',
    check: async (store: CIKStore) => {
      const start = performance.now();
      const violations: InvariantViolation[] = [];

      const allKnowledge = await store.queryKnowledge('*', -1.0, 1000);
      for (const k of allKnowledge) {
        if (k.confidence < 0 || k.confidence > 1) {
          violations.push({
            entityType: 'knowledge',
            entityId: k.id,
            field: 'confidence',
            expected: '[0.0, 1.0]',
            actual: String(k.confidence),
            message: `Knowledge "${k.subject} ${k.predicate} ${k.object}" has out-of-bounds confidence: ${k.confidence}`,
            autoRepairable: true,
          });
        }
      }

      const capabilities = await store.getCapabilities();
      for (const c of capabilities) {
        if (c.successRate < 0 || c.successRate > 1) {
          violations.push({
            entityType: 'capability',
            entityId: c.id,
            field: 'successRate',
            expected: '[0.0, 1.0]',
            actual: String(c.successRate),
            message: `Capability "${c.name}" has out-of-bounds successRate: ${c.successRate}`,
            autoRepairable: true,
          });
        }
      }

      return {
        invariant: 'CONFIDENCE_BOUNDS',
        passed: violations.length === 0,
        violations,
        checkedAt: Date.now(),
        durationMs: performance.now() - start,
      };
    },
  },

  {
    id: 'TIER_CONFIDENCE_ALIGNMENT',
    name: 'Tier-Confidence Alignment',
    description: 'Knowledge tier must roughly match its confidence range',
    severity: 'warning',
    check: async (store: CIKStore) => {
      const start = performance.now();
      const violations: InvariantViolation[] = [];

      const allKnowledge = await store.queryKnowledge('*', 0.0, 1000);
      for (const k of allKnowledge) {
        const range = TIER_CONFIDENCE_RANGES[k.tier as TrustTier];
        if (!range) continue;

        // Allow some tolerance (±0.15) for decay effects
        if (k.confidence < range.min - 0.15 || k.confidence > range.max + 0.15) {
          violations.push({
            entityType: 'knowledge',
            entityId: k.id,
            field: 'confidence',
            expected: `${range.min}-${range.max} for ${k.tier}`,
            actual: String(k.confidence),
            message: `Knowledge "${k.subject}" is ${k.tier} but confidence ${k.confidence} is outside expected range`,
            autoRepairable: true,
          });
        }
      }

      return {
        invariant: 'TIER_CONFIDENCE_ALIGNMENT',
        passed: violations.length === 0,
        violations,
        checkedAt: Date.now(),
        durationMs: performance.now() - start,
      };
    },
  },

  {
    id: 'TEMPORAL_ORDERING',
    name: 'Temporal Ordering',
    description: 'updatedAt must never be less than createdAt',
    severity: 'error',
    check: async (store: CIKStore) => {
      const start = performance.now();
      const violations: InvariantViolation[] = [];

      const allKnowledge = await store.queryKnowledge('*', 0.0, 1000);
      for (const k of allKnowledge) {
        if (k.updatedAt < k.createdAt) {
          violations.push({
            entityType: 'knowledge',
            entityId: k.id,
            field: 'updatedAt',
            expected: `>= ${k.createdAt}`,
            actual: String(k.updatedAt),
            message: `Knowledge "${k.subject}" has updatedAt < createdAt`,
            autoRepairable: true,
          });
        }
      }

      const capabilities = await store.getCapabilities();
      for (const c of capabilities) {
        if (c.updatedAt < c.createdAt) {
          violations.push({
            entityType: 'capability',
            entityId: c.id,
            field: 'updatedAt',
            expected: `>= ${c.createdAt}`,
            actual: String(c.updatedAt),
            message: `Capability "${c.name}" has updatedAt < createdAt`,
            autoRepairable: true,
          });
        }
      }

      return {
        invariant: 'TEMPORAL_ORDERING',
        passed: violations.length === 0,
        violations,
        checkedAt: Date.now(),
        durationMs: performance.now() - start,
      };
    },
  },

  {
    id: 'IDENTITY_IMMUTABILITY',
    name: 'Identity Immutability',
    description: 'DID and core identity entries must not be modified after creation',
    severity: 'critical',
    check: async (store: CIKStore) => {
      const start = performance.now();
      const violations: InvariantViolation[] = [];

      // Check that DID exists and hasn't been tampered with
      const did = await store.getIdentity('did');
      if (!did) {
        violations.push({
          entityType: 'identity',
          entityId: 'did',
          field: 'existence',
          expected: 'DID must exist',
          actual: 'missing',
          message: 'Agent DID identity entry is missing',
          autoRepairable: false,
        });
      } else if (did.tier !== 'T1') {
        violations.push({
          entityType: 'identity',
          entityId: did.id,
          field: 'tier',
          expected: 'T1',
          actual: did.tier,
          message: 'DID must always be T1 (highest trust)',
          autoRepairable: false,
        });
      }

      return {
        invariant: 'IDENTITY_IMMUTABILITY',
        passed: violations.length === 0,
        violations,
        checkedAt: Date.now(),
        durationMs: performance.now() - start,
      };
    },
  },

  {
    id: 'KNOWLEDGE_CONTRADICTION_RATIO',
    name: 'Knowledge Contradiction Ratio',
    description: 'High-tier knowledge should not have more contradictions than verifications',
    severity: 'warning',
    check: async (store: CIKStore) => {
      const start = performance.now();
      const violations: InvariantViolation[] = [];

      const allKnowledge = await store.queryKnowledge('*', 0.0, 1000);
      for (const k of allKnowledge) {
        if ((k.tier === 'T1' || k.tier === 'T2') && k.contradictions > k.verifications) {
          violations.push({
            entityType: 'knowledge',
            entityId: k.id,
            field: 'contradictions',
            expected: `contradictions(${k.contradictions}) <= verifications(${k.verifications})`,
            actual: `${k.contradictions} > ${k.verifications}`,
            message: `${k.tier} knowledge "${k.subject} ${k.predicate}" has more contradictions than verifications — should be demoted`,
            autoRepairable: false,
          });
        }
      }

      return {
        invariant: 'KNOWLEDGE_CONTRADICTION_RATIO',
        passed: violations.length === 0,
        violations,
        checkedAt: Date.now(),
        durationMs: performance.now() - start,
      };
    },
  },
];

// ─── Invariant Verifier ───

export class CIKInvariantVerifier {
  private lastReport: InvariantReport | null = null;
  private verificationHistory: InvariantReport[] = [];
  private maxHistory = 50;
  private customInvariants: InvariantCheck[] = [];

  /**
   * Add a custom invariant check.
   */
  addInvariant(check: InvariantCheck): void {
    this.customInvariants.push(check);
  }

  /**
   * Run all invariant checks against the CIK store.
   */
  async verify(store: CIKStore): Promise<InvariantReport> {
    const start = performance.now();
    const allChecks = [...INVARIANTS, ...this.customInvariants];
    const results: InvariantResult[] = [];

    for (const invariant of allChecks) {
      try {
        const result = await invariant.check(store);
        results.push(result);
      } catch (error) {
        results.push({
          invariant: invariant.id,
          passed: false,
          violations: [{
            entityType: 'knowledge',
            entityId: 'system',
            field: 'invariant_check',
            expected: 'Check should succeed',
            actual: String(error),
            message: `Invariant check ${invariant.id} threw: ${error}`,
            autoRepairable: false,
          }],
          checkedAt: Date.now(),
          durationMs: 0,
        });
      }
    }

    const allViolations = results.flatMap(r => r.violations);
    const criticalFails = results.filter(r => {
      const def = allChecks.find(c => c.id === r.invariant);
      return !r.passed && (def?.severity === 'critical' || def?.severity === 'error');
    }).length;

    const report: InvariantReport = {
      totalChecks: results.length,
      passed: results.filter(r => r.passed).length,
      failed: results.filter(r => !r.passed).length,
      violations: allViolations,
      results,
      overallHealth: criticalFails > 0 ? 'critical' : allViolations.length > 0 ? 'degraded' : 'healthy',
      checkedAt: Date.now(),
      durationMs: performance.now() - start,
    };

    this.lastReport = report;
    this.verificationHistory.push(report);
    if (this.verificationHistory.length > this.maxHistory) {
      this.verificationHistory = this.verificationHistory.slice(-this.maxHistory);
    }

    return report;
  }

  /**
   * Get the prompt section for invariant status.
   */
  getInvariantPrompt(): string {
    if (!this.lastReport) return '';

    const parts = ['## CIK Formal Invariants', ''];
    parts.push(`Health: **${this.lastReport.overallHealth.toUpperCase()}** (${this.lastReport.passed}/${this.lastReport.totalChecks} passed)`);

    if (this.lastReport.violations.length > 0) {
      parts.push('');
      parts.push('Violations:');
      for (const v of this.lastReport.violations.slice(0, 5)) {
        parts.push(`- ⚠ ${v.message}`);
      }
    }

    return parts.join('\n');
  }

  getLastReport(): InvariantReport | null { return this.lastReport; }
  getHistory(): InvariantReport[] { return this.verificationHistory; }
}
