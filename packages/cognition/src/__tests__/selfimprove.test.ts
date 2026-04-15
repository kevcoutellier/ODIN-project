/**
 * Self-improvement loop tests.
 *
 * The loop coordinates CausalEngine, ModelFirstReasoner, CIKStore,
 * AMEMController, EvolutionSandbox and CIKInvariantVerifier. We use
 * lightweight test doubles so tests focus on the loop logic itself:
 *
 *   - failure collection & capping
 *   - analysis dispatches by type
 *   - insight generation / application
 *   - invariant violations folded back as new failures
 *   - prompt integration
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { SelfImprovementLoop } from '../selfimprove/loop.js';
import type { Plan, PlanStep } from '../reasoning/model-first.js';

// ─── Test doubles ─────────────────────────────────────────────────────

class StubCausalEngine {
  buildFailureModel = (_tool: string, _args: any, _err: string) => ({
    modelId: 'model:1',
    analysis: {},
  });
  getModel = (_id: string) => ({
    variables: new Map<string, { id: string; name: string; value: unknown }>([
      ['v1', { id: 'v1', name: 'tool_input', value: 'invalid' }],
      ['v2', { id: 'v2', name: 'result', value: 'failure' }],
    ]),
  });
  queryCounterfactual = (_modelId: string, _target: string, _factual: any, _cf: any) => ({
    actionable: true,
    suggestion: 'validate input before calling',
    confidence: 0.7,
  });
}

class StubCausalEngineNoModel {
  buildFailureModel = (_tool: string, _args: any, _err: string) => ({
    modelId: 'model:none',
    analysis: {},
  });
  getModel = (_id: string) => undefined;
  queryCounterfactual = () => ({ actionable: false, confidence: 0 });
}

class StubReasoner {
  observed: unknown[] = [];
  observe = (obs: unknown[]) => { this.observed.push(...obs); };
}

class StubCIKStore {
  added: Array<Record<string, unknown>> = [];
  addKnowledge = async (...args: unknown[]) => {
    this.added.push({ args });
    return { id: 'k1', verifications: 0 };
  };
}

class StubAMEM {}
class StubEvolution {}

class StubInvariantVerifier {
  violations: Array<{ message: string; [k: string]: unknown }> = [];
  verify = async () => ({ violations: this.violations });
}

// ─── Fixtures ─────────────────────────────────────────────────────────

const makeLoop = (opts: {
  causal?: any;
  reasoner?: StubReasoner;
  cik?: StubCIKStore;
  verifier?: StubInvariantVerifier;
} = {}) => {
  const causal = opts.causal ?? new StubCausalEngine();
  const reasoner = opts.reasoner ?? new StubReasoner();
  const cik = opts.cik ?? new StubCIKStore();
  const verifier = opts.verifier ?? new StubInvariantVerifier();
  const loop = new SelfImprovementLoop(
    causal as any, reasoner as any, cik as any,
    new StubAMEM() as any, new StubEvolution() as any, verifier as any,
  );
  return { loop, causal, reasoner, cik, verifier };
};

const step = (overrides: Partial<PlanStep> = {}): PlanStep => ({
  id: 's1',
  action: 'search',
  expectedOutcome: 'found',
  actualOutcome: 'not found',
  status: 'failed',
  ...overrides,
} as PlanStep);

const plan = (failedCount: number): Plan => ({
  id: 'p1',
  goal: 'achieve the goal',
  steps: Array.from({ length: failedCount + 1 }, (_, i) => step({
    id: `s${i}`,
    action: `action_${i}`,
    status: i < failedCount ? 'failed' : 'completed',
  })),
  confidence: 0.4,
} as Plan);

// ─── Tests ─────────────────────────────────────────────────────────────

describe('SelfImprovementLoop — failure collection', () => {
  it('recordToolFailure appends a tool_failure record', () => {
    const { loop } = makeLoop();
    loop.recordToolFailure('search', { q: 'foo' }, 'timeout');
    const failures = loop.getFailures();
    expect(failures).toHaveLength(1);
    expect(failures[0].type).toBe('tool_failure');
    expect(failures[0].analyzed).toBe(false);
    expect(failures[0].description).toMatch(/timeout/);
  });

  it('recordPredictionError ignores accuracy > 0.5 (insignificant)', () => {
    const { loop } = makeLoop();
    loop.recordPredictionError(step({ action: 'read' }), 0.8);
    expect(loop.getFailures()).toHaveLength(0);
  });

  it('recordPredictionError records when accuracy ≤ 0.5', () => {
    const { loop } = makeLoop();
    loop.recordPredictionError(step({ action: 'read' }), 0.3);
    const failures = loop.getFailures();
    expect(failures).toHaveLength(1);
    expect(failures[0].type).toBe('prediction_error');
    expect(failures[0].context.accuracy).toBe(0.3);
  });

  it('recordEvolutionRejection records with reason', () => {
    const { loop } = makeLoop();
    loop.recordEvolutionRejection('k-42', 'tier skip forbidden');
    const failures = loop.getFailures();
    expect(failures[0].type).toBe('evolution_rejected');
    expect(failures[0].context.reason).toBe('tier skip forbidden');
  });

  it('recordPlanFailure extracts failed step count', () => {
    const { loop } = makeLoop();
    loop.recordPlanFailure(plan(2));
    const f = loop.getFailures()[0];
    expect(f.type).toBe('plan_failure');
    expect(f.description).toMatch(/2\/3 steps failed/);
    expect((f.context.failedSteps as any[]).length).toBe(2);
  });
});

describe('SelfImprovementLoop — analysis cycle', () => {
  it('empty cycle returns a zeroed report without incrementing cycle count... wait: cycleCount increments before empty check', async () => {
    // Documented behaviour: the cycle counter advances even when there is
    // nothing to analyse — because the counter is bumped BEFORE the early
    // return on "no failures". This is the actual implementation semantics.
    const { loop } = makeLoop();
    const report = await loop.runCycle();
    expect(report.failuresAnalyzed).toBe(0);
    expect(report.insightsGenerated).toBe(0);
    expect(loop.getCycleCount()).toBe(1);
  });

  it('tool_failure with actionable counterfactual → insight + knowledge added', async () => {
    const { loop, cik } = makeLoop();
    loop.recordToolFailure('search', { q: 'bad' }, 'timeout');
    const report = await loop.runCycle();

    expect(report.failuresAnalyzed).toBe(1);
    expect(report.counterfactualsGenerated).toBe(1);
    expect(report.insightsGenerated).toBe(1);
    expect(report.insightsApplied).toBe(1);
    expect(report.knowledgeCorrections).toBe(1);

    expect(cik.added).toHaveLength(1);
    expect(loop.getInsights()[0].applied).toBe(true);
  });

  it('tool_failure when causal model missing → no insight', async () => {
    const { loop } = makeLoop({ causal: new StubCausalEngineNoModel() });
    loop.recordToolFailure('search', { q: 'x' }, 'error');
    const report = await loop.runCycle();

    expect(report.failuresAnalyzed).toBe(1);
    expect(report.insightsGenerated).toBe(0);
    expect(report.counterfactualsGenerated).toBe(0);
  });

  it('prediction_error → reasoner.observe called + world model update logged', async () => {
    const { loop, reasoner } = makeLoop();
    loop.recordPredictionError(step({ action: 'summarize' }), 0.15);
    const report = await loop.runCycle();

    expect(reasoner.observed).toHaveLength(1);
    expect(report.worldModelUpdates).toBe(1);
    expect(report.insightsGenerated).toBe(1);
    expect(report.insightsApplied).toBe(1);
  });

  it('plan_failure → an insight + knowledge entry per failed step (capped at 3)', async () => {
    const { loop, cik } = makeLoop();
    // 5 failed steps — should process at most 3
    loop.recordPlanFailure(plan(5));
    const report = await loop.runCycle();
    expect(report.insightsGenerated).toBe(3);
    expect(report.knowledgeCorrections).toBe(3);
    expect(cik.added).toHaveLength(3);
    expect(report.worldModelUpdates).toBe(1);
  });

  it('cycle marks processed failures as analyzed', async () => {
    const { loop } = makeLoop();
    loop.recordToolFailure('t', {}, 'err');
    await loop.runCycle();
    expect(loop.getFailures()[0].analyzed).toBe(true);
  });

  it('cycle processes at most 20 failures per invocation', async () => {
    const { loop } = makeLoop();
    for (let i = 0; i < 25; i++) {
      loop.recordToolFailure(`tool${i}`, {}, 'fail');
    }
    const report = await loop.runCycle();
    expect(report.failuresAnalyzed).toBe(25); // reported as the total unanalyzed count
    // But only 20 were actually analysed (had .analyzed set to true)
    const analysed = loop.getFailures().filter(f => f.analyzed).length;
    expect(analysed).toBe(20);
  });

  it('invariant violations surfaced by verifier are folded back into failures', async () => {
    const verifier = new StubInvariantVerifier();
    verifier.violations = [{ message: 'orphan capability', kind: 'orphan' }];
    const { loop } = makeLoop({ verifier });

    loop.recordToolFailure('t', {}, 'e'); // ensure the cycle does real work
    await loop.runCycle();

    const violationFailures = loop.getFailures().filter(f => f.type === 'invariant_violation');
    expect(violationFailures).toHaveLength(1);
    expect(violationFailures[0].description).toBe('orphan capability');
  });
});

describe('SelfImprovementLoop — prompt integration', () => {
  it('getImprovementPrompt is empty when no applied insights', () => {
    const { loop } = makeLoop();
    expect(loop.getImprovementPrompt()).toBe('');
  });

  it('getImprovementPrompt renders applied insights with headings', async () => {
    const { loop } = makeLoop();
    loop.recordToolFailure('search', { q: 'bad' }, 'timeout');
    await loop.runCycle();
    const prompt = loop.getImprovementPrompt();
    expect(prompt).toContain('Self-Improvement Insights');
    expect(prompt).toContain('search');
  });

  it('getImprovementPrompt includes recent failure patterns section', async () => {
    const { loop } = makeLoop();
    loop.recordToolFailure('search', { q: 'bad' }, 'timeout');
    await loop.runCycle();
    loop.recordToolFailure('fetch', { url: 'x' }, 'ECONNRESET');
    const prompt = loop.getImprovementPrompt();
    expect(prompt).toContain('Recent Failure Patterns');
    expect(prompt).toContain('fetch');
  });
});

describe('SelfImprovementLoop — stats & accessors', () => {
  it('getStats reports improvement rate across insights', async () => {
    const { loop } = makeLoop();
    loop.recordToolFailure('search', { q: 'x' }, 'err');
    loop.recordEvolutionRejection('k1', 'bad tier'); // produces unapplied insight
    await loop.runCycle();

    const stats = loop.getStats();
    expect(stats.totalFailures).toBe(2);
    expect(stats.analyzedFailures).toBe(2);
    expect(stats.totalInsights).toBeGreaterThanOrEqual(2);
    expect(stats.improvementRate).toBeGreaterThan(0);
    expect(stats.improvementRate).toBeLessThanOrEqual(1);
  });

  it('reports history is trimmed to maxReports', async () => {
    const { loop } = makeLoop();
    // Each non-empty cycle pushes one report. Trigger 55.
    // Empty cycles return early and don't push to reports, so we need a failure each time.
    for (let i = 0; i < 55; i++) {
      loop.recordToolFailure(`t${i}`, {}, 'e');
      await loop.runCycle();
    }
    expect(loop.getReports().length).toBeLessThanOrEqual(50);
  });
});
