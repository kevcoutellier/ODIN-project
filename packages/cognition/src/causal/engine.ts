/**
 * Causal Reasoning Module — Structural Causal Model (SCM)
 *
 * Implements Pearl's causal inference framework for agent reasoning:
 *
 * 1. SCM (Structural Causal Model):
 *    - Variables (nodes) with parents → children causal relationships
 *    - Structural equations: X = f(parents(X), U_X)
 *    - Exogenous noise variables (U) for uncertainty
 *
 * 2. Three levels of the causal hierarchy:
 *    - L1: ASSOCIATION (observational): P(Y|X) — "seeing"
 *    - L2: INTERVENTION (do-calculus): P(Y|do(X)) — "doing"
 *    - L3: COUNTERFACTUAL: P(Y_x|X', Y') — "imagining"
 *
 * 3. Integration with the agent:
 *    - Tool failures → causal analysis (why did it fail?)
 *    - Knowledge contradictions → causal graph update
 *    - Planning → causal prediction (if I do X, what happens?)
 *    - Self-improvement → counterfactual reasoning
 *
 * This is a symbolic (non-neural) causal engine — it operates on
 * discrete variables and known structural equations. For continuous
 * domains, LLM-assisted causal discovery would extend this in future.
 */

import { randomUUID } from 'node:crypto';

// ─── Types ───

export interface CausalVariable {
  id: string;
  name: string;
  type: 'binary' | 'discrete' | 'continuous' | 'categorical';
  domain: unknown[]; // Possible values
  value?: unknown; // Observed value
  exogenous: boolean; // True = external noise
  description: string;
}

export interface CausalEdge {
  from: string; // Variable ID
  to: string; // Variable ID
  strength: number; // 0.0-1.0 causal strength
  mechanism: string; // Description of the causal mechanism
}

export interface StructuralEquation {
  variableId: string;
  parentIds: string[];
  /** Compute the variable value from parent values + noise */
  compute: (parentValues: Record<string, unknown>, noise?: number) => unknown;
}

export interface CausalModel {
  id: string;
  name: string;
  variables: Map<string, CausalVariable>;
  edges: CausalEdge[];
  equations: Map<string, StructuralEquation>;
  createdAt: number;
  updatedAt: number;
}

export interface CausalQuery {
  type: 'association' | 'intervention' | 'counterfactual';
  target: string; // Variable ID to query
  conditions: Record<string, unknown>; // Observed/set values
  interventions?: Record<string, unknown>; // do(X=x) values
  counterfactualPremise?: Record<string, unknown>; // What was observed
}

export interface CausalResult {
  query: CausalQuery;
  result: unknown;
  confidence: number;
  explanation: string;
  causalPath: string[]; // Variable IDs in the causal chain
}

export interface CounterfactualQuestion {
  id: string;
  premise: string; // "Given that X happened..."
  question: string; // "What if Y had been different?"
  antecedent: Record<string, unknown>; // What actually happened
  intervention: Record<string, unknown>; // What we're imagining
  result: unknown;
  explanation: string;
  confidence: number;
  actionable: boolean; // Can we act on this insight?
  suggestion?: string; // What to do differently
}

// ─── Causal Engine ───

export class CausalEngine {
  private models: Map<string, CausalModel> = new Map();
  private queryHistory: CausalResult[] = [];
  private counterfactualHistory: CounterfactualQuestion[] = [];
  private maxHistory = 200;

  /**
   * Create a new causal model.
   */
  createModel(name: string): CausalModel {
    const model: CausalModel = {
      id: randomUUID(),
      name,
      variables: new Map(),
      edges: [],
      equations: new Map(),
      createdAt: Date.now(),
      updatedAt: Date.now(),
    };
    this.models.set(model.id, model);
    return model;
  }

  /**
   * Add a variable to a causal model.
   */
  addVariable(modelId: string, variable: Omit<CausalVariable, 'id'>): CausalVariable | null {
    const model = this.models.get(modelId);
    if (!model) return null;

    const v: CausalVariable = { id: randomUUID(), ...variable };
    model.variables.set(v.id, v);
    model.updatedAt = Date.now();
    return v;
  }

  /**
   * Add a causal edge (X causes Y).
   */
  addEdge(modelId: string, fromId: string, toId: string, strength: number, mechanism: string): boolean {
    const model = this.models.get(modelId);
    if (!model) return false;
    if (!model.variables.has(fromId) || !model.variables.has(toId)) return false;

    // Check for cycles (causal models must be DAGs)
    if (this.wouldCreateCycle(model, fromId, toId)) return false;

    model.edges.push({ from: fromId, to: toId, strength, mechanism });
    model.updatedAt = Date.now();
    return true;
  }

  /**
   * Add a structural equation for a variable.
   */
  addEquation(modelId: string, equation: StructuralEquation): boolean {
    const model = this.models.get(modelId);
    if (!model) return false;
    if (!model.variables.has(equation.variableId)) return false;

    model.equations.set(equation.variableId, equation);
    model.updatedAt = Date.now();
    return true;
  }

  // ─── L1: Association (Observational) ───

  /**
   * P(Y|X=x): What is the probability/value of Y given that we OBSERVE X=x?
   */
  queryAssociation(modelId: string, targetId: string, observations: Record<string, unknown>): CausalResult {
    const model = this.models.get(modelId);
    if (!model) return this.errorResult({ type: 'association', target: targetId, conditions: observations }, 'Model not found');

    // Set observed values
    for (const [varId, value] of Object.entries(observations)) {
      const v = model.variables.get(varId);
      if (v) v.value = value;
    }

    // Forward propagation through the causal graph (topological order)
    const order = this.topologicalSort(model);
    for (const varId of order) {
      const eq = model.equations.get(varId);
      if (!eq) continue;
      if (observations[varId] !== undefined) continue; // Don't override observations

      const parentValues: Record<string, unknown> = {};
      for (const pid of eq.parentIds) {
        const pv = model.variables.get(pid);
        if (pv) parentValues[pid] = pv.value;
      }

      const v = model.variables.get(varId);
      if (v) v.value = eq.compute(parentValues);
    }

    const target = model.variables.get(targetId);
    const path = this.findCausalPath(model, Object.keys(observations), targetId);

    const result: CausalResult = {
      query: { type: 'association', target: targetId, conditions: observations },
      result: target?.value,
      confidence: 0.7,
      explanation: `Observing ${JSON.stringify(observations)} → ${target?.name} = ${JSON.stringify(target?.value)} (via ${path.map(id => model.variables.get(id)?.name ?? id).join(' → ')})`,
      causalPath: path,
    };

    this.recordResult(result);
    return result;
  }

  // ─── L2: Intervention (do-calculus) ───

  /**
   * P(Y|do(X=x)): What happens to Y if we INTERVENE and set X=x?
   * Key difference from association: intervention removes incoming edges to X
   * (the "mutilated" graph — Pearl's do-calculus).
   */
  queryIntervention(modelId: string, targetId: string, interventions: Record<string, unknown>, observations: Record<string, unknown> = {}): CausalResult {
    const model = this.models.get(modelId);
    if (!model) return this.errorResult({ type: 'intervention', target: targetId, conditions: observations, interventions }, 'Model not found');

    // Create a mutilated model: remove all incoming edges to intervened variables
    const mutilated = this.mutilateModel(model, Object.keys(interventions));

    // Set intervention values (these are FIXED, not observed)
    for (const [varId, value] of Object.entries(interventions)) {
      const v = mutilated.variables.get(varId);
      if (v) v.value = value;
    }

    // Set observations
    for (const [varId, value] of Object.entries(observations)) {
      const v = mutilated.variables.get(varId);
      if (v) v.value = value;
    }

    // Forward propagation on the mutilated graph
    const order = this.topologicalSort(mutilated);
    for (const varId of order) {
      if (interventions[varId] !== undefined) continue; // Don't override interventions
      if (observations[varId] !== undefined) continue;

      const eq = mutilated.equations.get(varId);
      if (!eq) continue;

      const parentValues: Record<string, unknown> = {};
      for (const pid of eq.parentIds) {
        // Check if parent still has an edge in the mutilated graph
        const hasEdge = mutilated.edges.some(e => e.from === pid && e.to === varId);
        if (hasEdge || interventions[pid] !== undefined) {
          const pv = mutilated.variables.get(pid);
          if (pv) parentValues[pid] = pv.value;
        }
      }

      const v = mutilated.variables.get(varId);
      if (v) v.value = eq.compute(parentValues);
    }

    const target = mutilated.variables.get(targetId);
    const path = this.findCausalPath(mutilated, Object.keys(interventions), targetId);

    const result: CausalResult = {
      query: { type: 'intervention', target: targetId, conditions: observations, interventions },
      result: target?.value,
      confidence: 0.8, // Interventions are more reliable than observations
      explanation: `do(${JSON.stringify(interventions)}) → ${target?.name} = ${JSON.stringify(target?.value)} (causal effect via mutilated graph)`,
      causalPath: path,
    };

    this.recordResult(result);
    return result;
  }

  // ─── L3: Counterfactual ───

  /**
   * "Given that Y was y when X was x, what would Y have been if X had been x'?"
   *
   * Three-step process (Pearl's algorithm):
   * 1. ABDUCTION: Use evidence to determine U (exogenous noise)
   * 2. ACTION: Modify the model with the counterfactual intervention
   * 3. PREDICTION: Propagate through the modified model
   */
  queryCounterfactual(
    modelId: string,
    targetId: string,
    factual: Record<string, unknown>, // What actually happened
    counterfactual: Record<string, unknown>, // What if this had been different?
  ): CounterfactualQuestion {
    const model = this.models.get(modelId);
    if (!model) {
      return this.errorCounterfactual(factual, counterfactual, 'Model not found');
    }

    // Step 1: ABDUCTION — determine what the world looked like
    // Set factual observations
    for (const [varId, value] of Object.entries(factual)) {
      const v = model.variables.get(varId);
      if (v) v.value = value;
    }

    // Forward propagate to establish baseline
    const order = this.topologicalSort(model);
    for (const varId of order) {
      if (factual[varId] !== undefined) continue;
      const eq = model.equations.get(varId);
      if (!eq) continue;

      const parentValues: Record<string, unknown> = {};
      for (const pid of eq.parentIds) {
        const pv = model.variables.get(pid);
        if (pv) parentValues[pid] = pv.value;
      }
      const v = model.variables.get(varId);
      if (v) v.value = eq.compute(parentValues);
    }

    const factualTargetValue = model.variables.get(targetId)?.value;

    // Step 2: ACTION — apply counterfactual intervention
    const mutilated = this.mutilateModel(model, Object.keys(counterfactual));
    for (const [varId, value] of Object.entries(counterfactual)) {
      const v = mutilated.variables.get(varId);
      if (v) v.value = value;
    }

    // Step 3: PREDICTION — propagate through modified model
    const cfOrder = this.topologicalSort(mutilated);
    for (const varId of cfOrder) {
      if (counterfactual[varId] !== undefined) continue;
      const eq = mutilated.equations.get(varId);
      if (!eq) continue;

      const parentValues: Record<string, unknown> = {};
      for (const pid of eq.parentIds) {
        const pv = mutilated.variables.get(pid);
        if (pv) parentValues[pid] = pv.value;
      }
      const v = mutilated.variables.get(varId);
      if (v) v.value = eq.compute(parentValues);
    }

    const counterfactualTargetValue = mutilated.variables.get(targetId)?.value;
    const targetName = model.variables.get(targetId)?.name ?? targetId;
    const changed = JSON.stringify(factualTargetValue) !== JSON.stringify(counterfactualTargetValue);

    const question: CounterfactualQuestion = {
      id: randomUUID(),
      premise: `Given: ${JSON.stringify(factual)}`,
      question: `What if ${JSON.stringify(counterfactual)} instead?`,
      antecedent: factual,
      intervention: counterfactual,
      result: counterfactualTargetValue,
      explanation: changed
        ? `${targetName} would have been ${JSON.stringify(counterfactualTargetValue)} instead of ${JSON.stringify(factualTargetValue)}`
        : `${targetName} would remain ${JSON.stringify(factualTargetValue)} — the intervention has no causal effect`,
      confidence: changed ? 0.7 : 0.9,
      actionable: changed,
      suggestion: changed
        ? `Consider modifying ${Object.keys(counterfactual).map(id => model.variables.get(id)?.name ?? id).join(', ')} to change ${targetName}`
        : undefined,
    };

    this.counterfactualHistory.push(question);
    if (this.counterfactualHistory.length > this.maxHistory) {
      this.counterfactualHistory = this.counterfactualHistory.slice(-this.maxHistory);
    }

    return question;
  }

  // ─── Agent Integration ───

  /**
   * Build a causal model from a tool failure event.
   * Useful for post-mortem analysis.
   */
  buildFailureModel(
    toolName: string,
    inputs: Record<string, unknown>,
    error: string,
    context: Record<string, unknown> = {},
  ): { modelId: string; analysis: CausalResult } {
    const model = this.createModel(`failure:${toolName}:${Date.now()}`);

    // Create standard failure variables
    const inputVar = this.addVariable(model.id, {
      name: 'tool_input', type: 'categorical', domain: ['valid', 'invalid', 'partial'],
      value: 'unknown', exogenous: false, description: 'Quality of tool input',
    })!;

    const envVar = this.addVariable(model.id, {
      name: 'environment', type: 'categorical', domain: ['stable', 'degraded', 'unavailable'],
      value: context.environment ?? 'stable', exogenous: true, description: 'Environment state',
    })!;

    const permVar = this.addVariable(model.id, {
      name: 'permissions', type: 'binary', domain: [true, false],
      value: context.hasPermission ?? true, exogenous: true, description: 'Has required permissions',
    })!;

    const resultVar = this.addVariable(model.id, {
      name: 'result', type: 'categorical', domain: ['success', 'failure', 'timeout', 'error'],
      value: 'failure', exogenous: false, description: 'Tool execution result',
    })!;

    // Add causal edges
    this.addEdge(model.id, inputVar.id, resultVar.id, 0.6, 'Input quality affects outcome');
    this.addEdge(model.id, envVar.id, resultVar.id, 0.3, 'Environment affects availability');
    this.addEdge(model.id, permVar.id, resultVar.id, 0.8, 'Permissions gate execution');

    // Add structural equation
    this.addEquation(model.id, {
      variableId: resultVar.id,
      parentIds: [inputVar.id, envVar.id, permVar.id],
      compute: (parents) => {
        if (parents[permVar.id] === false) return 'error';
        if (parents[envVar.id] === 'unavailable') return 'timeout';
        if (parents[inputVar.id] === 'invalid') return 'failure';
        return 'success';
      },
    });

    // Query: what caused the failure?
    const analysis = this.queryAssociation(model.id, resultVar.id, {
      [resultVar.id]: 'failure',
    });

    return { modelId: model.id, analysis };
  }

  /**
   * Get the prompt section for causal reasoning context.
   */
  getCausalPrompt(): string {
    const recentCounterfactuals = this.counterfactualHistory
      .filter(cf => cf.actionable)
      .slice(-3);

    if (recentCounterfactuals.length === 0) return '';

    const parts = ['## Causal Insights (from past reasoning)', ''];
    for (const cf of recentCounterfactuals) {
      parts.push(`- **${cf.question}**`);
      parts.push(`  ${cf.explanation}`);
      if (cf.suggestion) parts.push(`  → Suggestion: ${cf.suggestion}`);
    }
    parts.push('');
    return parts.join('\n');
  }

  // ─── Accessors ───

  getModel(modelId: string): CausalModel | undefined { return this.models.get(modelId); }
  getModels(): CausalModel[] { return [...this.models.values()]; }
  getQueryHistory(): CausalResult[] { return this.queryHistory.slice(-50); }
  getCounterfactualHistory(): CounterfactualQuestion[] { return this.counterfactualHistory.slice(-50); }

  getStats(): { models: number; queries: number; counterfactuals: number; actionableInsights: number } {
    return {
      models: this.models.size,
      queries: this.queryHistory.length,
      counterfactuals: this.counterfactualHistory.length,
      actionableInsights: this.counterfactualHistory.filter(cf => cf.actionable).length,
    };
  }

  // ─── Graph Utilities ───

  private topologicalSort(model: CausalModel): string[] {
    const visited = new Set<string>();
    const order: string[] = [];

    const dfs = (varId: string) => {
      if (visited.has(varId)) return;
      visited.add(varId);
      // Visit all parents first
      const parents = model.edges.filter(e => e.to === varId).map(e => e.from);
      for (const pid of parents) dfs(pid);
      order.push(varId);
    };

    for (const varId of model.variables.keys()) dfs(varId);
    return order;
  }

  private wouldCreateCycle(model: CausalModel, fromId: string, toId: string): boolean {
    // BFS from toId — if we can reach fromId, adding the edge would create a cycle
    const visited = new Set<string>();
    const queue = [toId];

    // Special case: self-loop
    if (fromId === toId) return true;

    while (queue.length > 0) {
      const current = queue.shift()!;
      if (current === fromId) return true;
      if (visited.has(current)) continue;
      visited.add(current);

      // Follow existing edges
      const children = model.edges.filter(e => e.from === current).map(e => e.to);
      queue.push(...children);
    }
    return false;
  }

  private mutilateModel(model: CausalModel, interventionVarIds: string[]): CausalModel {
    const mutilated: CausalModel = {
      ...model,
      variables: new Map(
        [...model.variables.entries()].map(([id, v]) => [id, { ...v }])
      ),
      edges: model.edges.filter(e => !interventionVarIds.includes(e.to)),
      equations: new Map(model.equations),
    };
    return mutilated;
  }

  private findCausalPath(model: CausalModel, sourceIds: string[], targetId: string): string[] {
    // BFS from sources to target through causal edges
    for (const sourceId of sourceIds) {
      const visited = new Map<string, string>(); // childId → parentId
      const queue = [sourceId];
      visited.set(sourceId, '');

      while (queue.length > 0) {
        const current = queue.shift()!;
        if (current === targetId) {
          // Reconstruct path
          const path: string[] = [];
          let c = current;
          while (c) {
            path.unshift(c);
            c = visited.get(c) === '' ? '' : visited.get(c)!;
          }
          return path;
        }

        const children = model.edges.filter(e => e.from === current).map(e => e.to);
        for (const child of children) {
          if (!visited.has(child)) {
            visited.set(child, current);
            queue.push(child);
          }
        }
      }
    }

    return [];
  }

  private recordResult(result: CausalResult): void {
    this.queryHistory.push(result);
    if (this.queryHistory.length > this.maxHistory) {
      this.queryHistory = this.queryHistory.slice(-this.maxHistory);
    }
  }

  private errorResult(query: CausalQuery, message: string): CausalResult {
    return { query, result: null, confidence: 0, explanation: message, causalPath: [] };
  }

  private errorCounterfactual(factual: Record<string, unknown>, counterfactual: Record<string, unknown>, message: string): CounterfactualQuestion {
    return {
      id: randomUUID(), premise: JSON.stringify(factual), question: JSON.stringify(counterfactual),
      antecedent: factual, intervention: counterfactual, result: null,
      explanation: message, confidence: 0, actionable: false,
    };
  }
}
