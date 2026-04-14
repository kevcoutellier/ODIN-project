import { describe, it, expect } from 'vitest';
import { MCTSPlanner, HierarchicalPlanner } from '../planning/mcts.js';
import type { MCTSState } from '../planning/mcts.js';

describe('MCTSPlanner', () => {
  const initialState: MCTSState = {
    description: 'Initial state',
    entities: [{ name: 'agent', type: 'self' }],
    goals: [
      { description: 'Complete task A', achieved: false, priority: 0.8 },
      { description: 'Complete task B', achieved: false, priority: 0.5 },
    ],
    resources: { tokens: 10000, time: 300 },
    constraints: ['Must complete within time limit'],
  };

  it('generates a plan', () => {
    const planner = new MCTSPlanner({ maxIterations: 20, maxDepth: 4 });
    const plan = planner.plan(initialState, 'Complete all tasks');
    expect(plan.id).toBeTruthy();
    expect(plan.goal).toBe('Complete all tasks');
    expect(plan.actions.length).toBeGreaterThan(0);
    expect(plan.confidence).toBeGreaterThanOrEqual(0);
    expect(plan.confidence).toBeLessThanOrEqual(1);
  });

  it('produces tree statistics', () => {
    const planner = new MCTSPlanner({ maxIterations: 50 });
    const plan = planner.plan(initialState, 'Test');
    expect(plan.treeStats.totalNodes).toBeGreaterThan(1);
    expect(plan.treeStats.totalIterations).toBe(50);
    expect(plan.treeStats.maxDepthReached).toBeGreaterThanOrEqual(1);
  });

  it('respects maxDepth', () => {
    const planner = new MCTSPlanner({ maxIterations: 30, maxDepth: 2 });
    const plan = planner.plan(initialState, 'Shallow');
    expect(plan.treeStats.maxDepthReached).toBeLessThanOrEqual(2);
  });

  it('handles empty goals', () => {
    const emptyState: MCTSState = {
      ...initialState,
      goals: [],
    };
    const planner = new MCTSPlanner({ maxIterations: 10 });
    const plan = planner.plan(emptyState, 'Nothing to do');
    expect(plan).toBeDefined();
  });
});

describe('HierarchicalPlanner', () => {
  it('adds goals with sub-goals', () => {
    const planner = new HierarchicalPlanner({ maxIterations: 10 });
    const goal = planner.addGoal('Build project', 0.9, ['Compile', 'Test', 'Deploy']);
    expect(goal.subGoals).toHaveLength(3);
    expect(goal.status).toBe('pending');
  });

  it('plans next pending goal', () => {
    const planner = new HierarchicalPlanner({ maxIterations: 10, maxDepth: 3 });
    planner.addGoal('Simple task', 0.5);

    const state: MCTSState = {
      description: 'Current',
      entities: [],
      goals: [],
      resources: { tokens: 5000 },
      constraints: [],
    };

    const plan = planner.planNext(state);
    expect(plan).not.toBeNull();
    expect(plan!.actions.length).toBeGreaterThan(0);
  });

  it('completes goals', () => {
    const planner = new HierarchicalPlanner();
    const goal = planner.addGoal('Task', 0.5);
    planner.completeGoal(goal.id);
    expect(planner.getStats().completed).toBe(1);
  });

  it('propagates completion to parent', () => {
    const planner = new HierarchicalPlanner();
    const goal = planner.addGoal('Parent', 0.9, ['Sub A', 'Sub B']);
    for (const sub of goal.subGoals) {
      planner.completeGoal(sub.id);
    }
    expect(goal.status).toBe('completed');
  });

  it('generates planning prompt', () => {
    const planner = new HierarchicalPlanner();
    planner.addGoal('Build something', 0.9, ['Step 1', 'Step 2']);
    const prompt = planner.getPlanningPrompt();
    expect(prompt).toContain('Build something');
    expect(prompt).toContain('Step 1');
  });
});
