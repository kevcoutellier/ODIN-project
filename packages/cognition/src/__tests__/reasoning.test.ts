import { describe, it, expect } from 'vitest';
import { ModelFirstReasoner } from '../reasoning/model-first.js';

describe('ModelFirstReasoner', () => {
  it('starts with empty world state', () => {
    const reasoner = new ModelFirstReasoner();
    const state = reasoner.getWorldState();
    expect(state.entities).toHaveLength(0);
    expect(state.goals).toHaveLength(0);
  });

  it('observes entities', () => {
    const reasoner = new ModelFirstReasoner();
    reasoner.observe([
      { type: 'entity', data: { name: 'User', type: 'person', properties: { role: 'admin' } } },
    ]);
    expect(reasoner.getWorldState().entities).toHaveLength(1);
    expect(reasoner.getWorldState().entities[0].name).toBe('User');
  });

  it('reinforces existing entities', () => {
    const reasoner = new ModelFirstReasoner();
    reasoner.observe([
      { type: 'entity', data: { name: 'User', type: 'person' } },
    ]);
    reasoner.observe([
      { type: 'entity', data: { name: 'User', type: 'person', properties: { active: true } } },
    ]);
    expect(reasoner.getWorldState().entities).toHaveLength(1);
    expect(reasoner.getWorldState().entities[0].properties).toHaveProperty('active', true);
  });

  it('observes relationships', () => {
    const reasoner = new ModelFirstReasoner();
    reasoner.observe([
      { type: 'relationship', data: { from: 'Agent', to: 'shell_exec', relation: 'uses', strength: 0.5 } },
    ]);
    expect(reasoner.getWorldState().relationships).toHaveLength(1);
  });

  it('observes goals', () => {
    const reasoner = new ModelFirstReasoner();
    reasoner.observe([
      { type: 'goal', data: { description: 'Build the project', priority: 0.9 } },
    ]);
    expect(reasoner.getWorldState().goals).toHaveLength(1);
    expect(reasoner.getWorldState().goals[0].status).toBe('active');
  });

  it('creates plans', () => {
    const reasoner = new ModelFirstReasoner();
    const plan = reasoner.createPlan('Deploy app', [
      { action: 'Build', tool: 'shell_exec', expectedOutcome: 'Build succeeds' },
      { action: 'Test', tool: 'shell_exec', expectedOutcome: 'Tests pass' },
      { action: 'Deploy', tool: 'http_request', expectedOutcome: 'Deployed successfully' },
    ]);
    expect(plan.steps).toHaveLength(3);
    expect(plan.status).toBe('draft');
    expect(reasoner.getActivePlan()).toBe(plan);
  });

  it('verifies predictions', () => {
    const reasoner = new ModelFirstReasoner();
    reasoner.createPlan('Test', [
      { action: 'Run tests', expectedOutcome: 'All tests pass successfully' },
    ]);
    reasoner.markStepExecuting(1);
    const verification = reasoner.verify(1, 'All tests pass successfully', true);
    expect(verification.predictionAccuracy).toBeGreaterThan(0);
  });

  it('generates counterfactuals from failures', () => {
    const reasoner = new ModelFirstReasoner();
    reasoner.createPlan('Deploy', [
      { action: 'Build', expectedOutcome: 'Build succeeds' },
    ]);
    reasoner.markStepExecuting(1);
    reasoner.verify(1, 'Build failed with OOM error', false);

    const cfs = reasoner.generateCounterfactuals();
    expect(cfs.length).toBeGreaterThanOrEqual(1);
    expect(cfs[0].question).toContain('Build');
  });

  it('generates world model prompt', () => {
    const reasoner = new ModelFirstReasoner();
    reasoner.observe([
      { type: 'entity', data: { name: 'Odin', type: 'agent' } },
      { type: 'goal', data: { description: 'Secure the system', priority: 1.0 } },
      { type: 'uncertainty', data: { description: 'Network latency unknown', impact: 'medium' } },
    ]);
    const prompt = reasoner.getWorldModelPrompt();
    expect(prompt).toContain('Odin');
    expect(prompt).toContain('Secure the system');
    expect(prompt).toContain('Network latency');
    expect(prompt).toContain('Reasoning Directives');
  });

  it('tracks prediction accuracy', () => {
    const reasoner = new ModelFirstReasoner();
    expect(reasoner.getPredictionAccuracy()).toBe(1.0); // No predictions yet
    reasoner.createPlan('Test', [
      { action: 'Step 1', expectedOutcome: 'Something happens' },
    ]);
    reasoner.markStepExecuting(1);
    reasoner.verify(1, 'Completely different result', true);
    expect(reasoner.getPredictionAccuracy()).toBeLessThan(1.0);
  });
});
