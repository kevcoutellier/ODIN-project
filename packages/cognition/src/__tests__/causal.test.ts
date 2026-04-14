import { describe, it, expect } from 'vitest';
import { CausalEngine } from '../causal/engine.js';

describe('CausalEngine', () => {
  it('creates a causal model', () => {
    const engine = new CausalEngine();
    const model = engine.createModel('test-model');
    expect(model.id).toBeTruthy();
    expect(model.name).toBe('test-model');
  });

  it('adds variables and edges', () => {
    const engine = new CausalEngine();
    const model = engine.createModel('rain-model');

    const rain = engine.addVariable(model.id, {
      name: 'rain', type: 'binary', domain: [true, false],
      value: true, exogenous: true, description: 'Is it raining?',
    })!;

    const wet = engine.addVariable(model.id, {
      name: 'ground_wet', type: 'binary', domain: [true, false],
      exogenous: false, description: 'Is the ground wet?',
    })!;

    const added = engine.addEdge(model.id, rain.id, wet.id, 0.9, 'Rain causes wet ground');
    expect(added).toBe(true);
  });

  it('prevents cycles (DAG enforcement)', () => {
    const engine = new CausalEngine();
    const model = engine.createModel('cycle-test');

    const a = engine.addVariable(model.id, { name: 'A', type: 'binary', domain: [0, 1], exogenous: false, description: 'A' })!;
    const b = engine.addVariable(model.id, { name: 'B', type: 'binary', domain: [0, 1], exogenous: false, description: 'B' })!;

    engine.addEdge(model.id, a.id, b.id, 0.5, 'A→B');
    const cycleResult = engine.addEdge(model.id, b.id, a.id, 0.5, 'B→A would create cycle');
    expect(cycleResult).toBe(false);
  });

  it('prevents self-loops', () => {
    const engine = new CausalEngine();
    const model = engine.createModel('self-loop');
    const a = engine.addVariable(model.id, { name: 'A', type: 'binary', domain: [0, 1], exogenous: false, description: 'A' })!;
    expect(engine.addEdge(model.id, a.id, a.id, 0.5, 'self')).toBe(false);
  });

  it('queries association (L1)', () => {
    const engine = new CausalEngine();
    const model = engine.createModel('association');

    const x = engine.addVariable(model.id, { name: 'X', type: 'binary', domain: [0, 1], exogenous: true, description: 'Cause' })!;
    const y = engine.addVariable(model.id, { name: 'Y', type: 'binary', domain: [0, 1], exogenous: false, description: 'Effect' })!;

    engine.addEdge(model.id, x.id, y.id, 0.9, 'X causes Y');
    engine.addEquation(model.id, {
      variableId: y.id,
      parentIds: [x.id],
      compute: (parents) => parents[x.id] === 1 ? 1 : 0,
    });

    const result = engine.queryAssociation(model.id, y.id, { [x.id]: 1 });
    expect(result.result).toBe(1);
    expect(result.confidence).toBeGreaterThan(0);
  });

  it('queries intervention (L2 — do-calculus)', () => {
    const engine = new CausalEngine();
    const model = engine.createModel('intervention');

    const confound = engine.addVariable(model.id, { name: 'Confound', type: 'binary', domain: [0, 1], value: 1, exogenous: true, description: 'Confounding variable' })!;
    const x = engine.addVariable(model.id, { name: 'X', type: 'binary', domain: [0, 1], exogenous: false, description: 'Treatment' })!;
    const y = engine.addVariable(model.id, { name: 'Y', type: 'binary', domain: [0, 1], exogenous: false, description: 'Outcome' })!;

    engine.addEdge(model.id, confound.id, x.id, 0.7, 'Confound → X');
    engine.addEdge(model.id, confound.id, y.id, 0.5, 'Confound → Y');
    engine.addEdge(model.id, x.id, y.id, 0.9, 'X → Y');

    engine.addEquation(model.id, {
      variableId: x.id,
      parentIds: [confound.id],
      compute: (p) => p[confound.id] === 1 ? 1 : 0,
    });

    engine.addEquation(model.id, {
      variableId: y.id,
      parentIds: [x.id, confound.id],
      compute: (p) => (p[x.id] === 1 || p[confound.id] === 1) ? 1 : 0,
    });

    // do(X=0): Force X to 0 — this removes the confound→X edge
    const result = engine.queryIntervention(model.id, y.id, { [x.id]: 0 });
    expect(result).toBeDefined();
    expect(result.confidence).toBeGreaterThan(0);
  });

  it('queries counterfactuals (L3)', () => {
    const engine = new CausalEngine();
    const model = engine.createModel('counterfactual');

    const x = engine.addVariable(model.id, { name: 'Treatment', type: 'binary', domain: [0, 1], exogenous: true, description: 'Treatment given' })!;
    const y = engine.addVariable(model.id, { name: 'Outcome', type: 'binary', domain: [0, 1], exogenous: false, description: 'Recovery' })!;

    engine.addEdge(model.id, x.id, y.id, 0.9, 'Treatment causes recovery');
    engine.addEquation(model.id, {
      variableId: y.id,
      parentIds: [x.id],
      compute: (p) => p[x.id] === 1 ? 1 : 0,
    });

    // Factual: Treatment=1, Outcome=1
    // Counterfactual: What if Treatment=0?
    const cf = engine.queryCounterfactual(
      model.id, y.id,
      { [x.id]: 1, [y.id]: 1 }, // What happened
      { [x.id]: 0 }, // What if?
    );

    expect(cf.actionable).toBe(true);
    expect(cf.result).toBe(0); // Without treatment, no recovery
    expect(cf.explanation).toContain('would have been');
  });

  it('builds failure models for tool debugging', () => {
    const engine = new CausalEngine();
    const { modelId, analysis } = engine.buildFailureModel(
      'shell_exec',
      { command: 'rm -rf /' },
      'Permission denied',
      { hasPermission: false },
    );
    expect(modelId).toBeTruthy();
    expect(analysis.result).toBeDefined();
  });

  it('generates causal prompt', () => {
    const engine = new CausalEngine();
    const model = engine.createModel('prompt-test');

    const x = engine.addVariable(model.id, { name: 'X', type: 'binary', domain: [0, 1], exogenous: true, description: 'X' })!;
    const y = engine.addVariable(model.id, { name: 'Y', type: 'binary', domain: [0, 1], exogenous: false, description: 'Y' })!;
    engine.addEdge(model.id, x.id, y.id, 0.9, 'X→Y');
    engine.addEquation(model.id, {
      variableId: y.id, parentIds: [x.id],
      compute: (p) => p[x.id] === 1 ? 1 : 0,
    });

    engine.queryCounterfactual(model.id, y.id, { [x.id]: 1, [y.id]: 1 }, { [x.id]: 0 });

    const prompt = engine.getCausalPrompt();
    expect(prompt).toContain('Causal Insights');
  });

  it('tracks stats', () => {
    const engine = new CausalEngine();
    engine.createModel('m1');
    engine.createModel('m2');
    const stats = engine.getStats();
    expect(stats.models).toBe(2);
  });
});
