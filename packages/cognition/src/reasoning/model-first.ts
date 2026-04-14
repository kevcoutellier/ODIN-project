/**
 * Model-First Reasoning — World Model + Causal Planning
 *
 * Instead of linear ReAct (think → act → observe → repeat):
 * 1. OBSERVE: Build/update internal world model from context
 * 2. MODEL: Reason about the current state (what do I know? what's uncertain?)
 * 3. PLAN: Generate a plan using the world model (not just next action)
 * 4. PREDICT: Predict outcomes of planned actions BEFORE executing
 * 5. ACT: Execute with monitoring
 * 6. VERIFY: Compare prediction vs reality, update world model
 *
 * This enables:
 * - Counterfactual reasoning ("what if I had done X instead?")
 * - Multi-step planning (not just greedy next-action)
 * - Self-correction through prediction errors
 * - Causal understanding (not just correlations)
 */

export interface WorldState {
  entities: Array<{ name: string; type: string; properties: Record<string, unknown> }>;
  relationships: Array<{ from: string; to: string; relation: string; strength: number }>;
  goals: Array<{ description: string; status: 'active' | 'achieved' | 'failed' | 'deferred'; priority: number }>;
  constraints: string[];
  uncertainties: Array<{ description: string; impact: 'low' | 'medium' | 'high' }>;
  timestamp: number;
}

export interface ReasoningStep {
  phase: 'observe' | 'model' | 'plan' | 'predict' | 'act' | 'verify';
  input: string;
  output: string;
  confidence: number;
  timestamp: number;
  durationMs: number;
}

export interface Plan {
  id: string;
  goal: string;
  steps: PlanStep[];
  predictions: string[];
  status: 'draft' | 'executing' | 'completed' | 'failed' | 'revised';
  confidence: number;
  createdAt: number;
  revisedAt?: number;
  revisionReason?: string;
}

export interface PlanStep {
  id: number;
  action: string;
  tool?: string;
  args?: Record<string, unknown>;
  expectedOutcome: string;
  actualOutcome?: string;
  status: 'pending' | 'executing' | 'completed' | 'failed' | 'skipped';
  predictionAccuracy?: number; // 0.0-1.0 how close prediction was to reality
}

export interface Counterfactual {
  question: string; // "What if I had used web_search instead of file_read?"
  originalAction: string;
  alternativeAction: string;
  predictedDifference: string;
  confidence: number;
}

export class ModelFirstReasoner {
  private worldState: WorldState;
  private reasoningHistory: ReasoningStep[] = [];
  private activePlan: Plan | null = null;
  private predictionErrors: Array<{ step: PlanStep; error: number; timestamp: number }> = [];

  constructor() {
    this.worldState = {
      entities: [],
      relationships: [],
      goals: [],
      constraints: [],
      uncertainties: [],
      timestamp: Date.now(),
    };
  }

  // ─── PHASE 1: OBSERVE ───

  /**
   * Update the world model from new observations.
   */
  observe(observations: Array<{
    type: 'entity' | 'relationship' | 'constraint' | 'goal' | 'uncertainty';
    data: Record<string, unknown>;
  }>): void {
    const start = performance.now();

    for (const obs of observations) {
      switch (obs.type) {
        case 'entity': {
          const name = obs.data.name as string;
          const existing = this.worldState.entities.find(e => e.name === name);
          if (existing) {
            Object.assign(existing.properties, obs.data.properties ?? {});
          } else {
            this.worldState.entities.push({
              name,
              type: obs.data.type as string ?? 'unknown',
              properties: (obs.data.properties as Record<string, unknown>) ?? {},
            });
          }
          break;
        }
        case 'relationship': {
          const from = obs.data.from as string;
          const to = obs.data.to as string;
          const relation = obs.data.relation as string;
          const existing = this.worldState.relationships.find(
            r => r.from === from && r.to === to && r.relation === relation
          );
          if (existing) {
            existing.strength = Math.min(1.0, existing.strength + 0.1);
          } else {
            this.worldState.relationships.push({ from, to, relation, strength: obs.data.strength as number ?? 0.5 });
          }
          break;
        }
        case 'goal':
          this.worldState.goals.push({
            description: obs.data.description as string,
            status: 'active',
            priority: obs.data.priority as number ?? 0.5,
          });
          break;
        case 'constraint':
          this.worldState.constraints.push(obs.data.description as string);
          break;
        case 'uncertainty':
          this.worldState.uncertainties.push({
            description: obs.data.description as string,
            impact: obs.data.impact as 'low' | 'medium' | 'high' ?? 'medium',
          });
          break;
      }
    }

    this.worldState.timestamp = Date.now();
    this.recordStep('observe', JSON.stringify(observations), `World state updated: ${observations.length} observations`, 1.0, performance.now() - start);
  }

  // ─── PHASE 2: MODEL ───

  /**
   * Generate a structured summary of the current world model.
   * This is injected into the LLM prompt for reasoning.
   */
  getWorldModelPrompt(): string {
    const parts: string[] = [
      '## Current World Model',
      '',
    ];

    if (this.worldState.entities.length > 0) {
      parts.push('### Known Entities');
      for (const e of this.worldState.entities.slice(-20)) {
        const props = Object.entries(e.properties).map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(', ');
        parts.push(`- **${e.name}** (${e.type})${props ? `: ${props}` : ''}`);
      }
      parts.push('');
    }

    if (this.worldState.relationships.length > 0) {
      parts.push('### Known Relationships');
      for (const r of this.worldState.relationships.filter(r => r.strength > 0.3).slice(-15)) {
        parts.push(`- ${r.from} —[${r.relation} (${(r.strength * 100).toFixed(0)}%)]→ ${r.to}`);
      }
      parts.push('');
    }

    if (this.worldState.goals.filter(g => g.status === 'active').length > 0) {
      parts.push('### Active Goals');
      for (const g of this.worldState.goals.filter(g => g.status === 'active')) {
        parts.push(`- [P${(g.priority * 10).toFixed(0)}] ${g.description}`);
      }
      parts.push('');
    }

    if (this.worldState.uncertainties.length > 0) {
      parts.push('### Uncertainties (things I\'m not sure about)');
      for (const u of this.worldState.uncertainties.slice(-5)) {
        parts.push(`- [${u.impact}] ${u.description}`);
      }
      parts.push('');
    }

    if (this.worldState.constraints.length > 0) {
      parts.push('### Constraints');
      for (const c of this.worldState.constraints.slice(-5)) {
        parts.push(`- ${c}`);
      }
      parts.push('');
    }

    // Prediction accuracy feedback
    if (this.predictionErrors.length > 0) {
      const avgError = this.predictionErrors.reduce((s, e) => s + e.error, 0) / this.predictionErrors.length;
      parts.push(`### Self-Assessment`);
      parts.push(`- Prediction accuracy: ${((1 - avgError) * 100).toFixed(0)}% (${this.predictionErrors.length} predictions)`);
      if (avgError > 0.3) {
        parts.push('- ⚠ High prediction error — consider gathering more information before acting');
      }
      parts.push('');
    }

    if (this.activePlan) {
      const completed = this.activePlan.steps.filter(s => s.status === 'completed').length;
      const total = this.activePlan.steps.length;
      parts.push(`### Active Plan: ${this.activePlan.goal}`);
      parts.push(`Progress: ${completed}/${total} steps | Confidence: ${(this.activePlan.confidence * 100).toFixed(0)}%`);
      for (const step of this.activePlan.steps) {
        const icon = step.status === 'completed' ? '✓' : step.status === 'executing' ? '►' : step.status === 'failed' ? '✗' : '○';
        parts.push(`  ${icon} Step ${step.id}: ${step.action}`);
      }
      parts.push('');
    }

    parts.push('### Reasoning Directives');
    parts.push('Before acting, consider:');
    parts.push('1. What do I KNOW vs what am I ASSUMING?');
    parts.push('2. What could go wrong with my plan?');
    parts.push('3. Is there a simpler way to achieve the goal?');
    parts.push('4. What information am I missing?');

    return parts.join('\n');
  }

  // ─── PHASE 3: PLAN ───

  createPlan(goal: string, steps: Array<{ action: string; tool?: string; args?: Record<string, unknown>; expectedOutcome: string }>): Plan {
    const plan: Plan = {
      id: `plan-${Date.now()}`,
      goal,
      steps: steps.map((s, i) => ({
        id: i + 1,
        action: s.action,
        tool: s.tool,
        args: s.args,
        expectedOutcome: s.expectedOutcome,
        status: 'pending' as const,
      })),
      predictions: steps.map(s => s.expectedOutcome),
      status: 'draft',
      confidence: 0.7, // Default — will be adjusted based on world model
      createdAt: Date.now(),
    };

    this.activePlan = plan;
    this.recordStep('plan', goal, `Plan created: ${steps.length} steps`, plan.confidence, 0);
    return plan;
  }

  // ─── PHASE 4: PREDICT ───

  /**
   * Record a prediction for a plan step.
   */
  predict(stepId: number, prediction: string): void {
    if (!this.activePlan) return;
    const step = this.activePlan.steps.find(s => s.id === stepId);
    if (step) step.expectedOutcome = prediction;
  }

  // ─── PHASE 5: ACT ───

  markStepExecuting(stepId: number): void {
    if (!this.activePlan) return;
    const step = this.activePlan.steps.find(s => s.id === stepId);
    if (step) {
      step.status = 'executing';
      this.activePlan.status = 'executing';
    }
  }

  // ─── PHASE 6: VERIFY ───

  /**
   * Compare prediction vs actual outcome. Updates world model accuracy.
   */
  verify(stepId: number, actualOutcome: string, success: boolean): {
    predictionAccuracy: number;
    worldModelUpdate: string;
  } {
    if (!this.activePlan) return { predictionAccuracy: 0, worldModelUpdate: 'No active plan' };

    const step = this.activePlan.steps.find(s => s.id === stepId);
    if (!step) return { predictionAccuracy: 0, worldModelUpdate: 'Step not found' };

    step.actualOutcome = actualOutcome;
    step.status = success ? 'completed' : 'failed';

    // Compute prediction accuracy (simple text similarity as proxy)
    const predicted = step.expectedOutcome.toLowerCase();
    const actual = actualOutcome.toLowerCase();
    const commonWords = predicted.split(/\s+/).filter(w => actual.includes(w));
    const totalWords = new Set([...predicted.split(/\s+/), ...actual.split(/\s+/)]).size;
    const accuracy = totalWords > 0 ? commonWords.length / totalWords : 0;
    step.predictionAccuracy = accuracy;

    const error = 1 - accuracy;
    this.predictionErrors.push({ step, error, timestamp: Date.now() });
    if (this.predictionErrors.length > 100) this.predictionErrors = this.predictionErrors.slice(-100);

    // Update plan confidence based on step outcomes
    const completedSteps = this.activePlan.steps.filter(s => s.predictionAccuracy !== undefined);
    if (completedSteps.length > 0) {
      this.activePlan.confidence = completedSteps.reduce((s, st) => s + (st.predictionAccuracy ?? 0), 0) / completedSteps.length;
    }

    // Check if plan is done
    if (this.activePlan.steps.every(s => s.status === 'completed' || s.status === 'failed' || s.status === 'skipped')) {
      this.activePlan.status = this.activePlan.steps.some(s => s.status === 'failed') ? 'failed' : 'completed';
    }

    const worldModelUpdate = error > 0.5
      ? `High prediction error (${(error * 100).toFixed(0)}%) — world model needs updating for "${step.action}"`
      : `Prediction accurate (${(accuracy * 100).toFixed(0)}%) for "${step.action}"`;

    this.recordStep('verify', actualOutcome, worldModelUpdate, accuracy, 0);

    return { predictionAccuracy: accuracy, worldModelUpdate };
  }

  // ─── COUNTERFACTUALS ───

  /**
   * Generate counterfactual questions from completed plan steps.
   */
  generateCounterfactuals(): Counterfactual[] {
    if (!this.activePlan) return [];

    const counterfactuals: Counterfactual[] = [];
    const failedSteps = this.activePlan.steps.filter(s => s.status === 'failed');

    for (const step of failedSteps) {
      counterfactuals.push({
        question: `What if I had approached "${step.action}" differently?`,
        originalAction: step.action,
        alternativeAction: `Alternative approach to: ${step.action}`,
        predictedDifference: `The step failed with: ${step.actualOutcome}. An alternative might have succeeded.`,
        confidence: 0.5,
      });
    }

    // Low-accuracy predictions
    const poorPredictions = this.activePlan.steps.filter(s => (s.predictionAccuracy ?? 1) < 0.3);
    for (const step of poorPredictions) {
      counterfactuals.push({
        question: `Why was my prediction wrong for "${step.action}"?`,
        originalAction: step.expectedOutcome,
        alternativeAction: step.actualOutcome ?? '',
        predictedDifference: 'My world model was inaccurate — I should update my understanding.',
        confidence: 0.7,
      });
    }

    return counterfactuals;
  }

  // ─── ACCESSORS ───

  getWorldState(): WorldState { return this.worldState; }
  getActivePlan(): Plan | null { return this.activePlan; }
  getReasoningHistory(): ReasoningStep[] { return this.reasoningHistory.slice(-50); }

  getPredictionAccuracy(): number {
    if (this.predictionErrors.length === 0) return 1.0;
    return 1 - (this.predictionErrors.reduce((s, e) => s + e.error, 0) / this.predictionErrors.length);
  }

  clearPlan(): void {
    this.activePlan = null;
  }

  private recordStep(phase: ReasoningStep['phase'], input: string, output: string, confidence: number, durationMs: number): void {
    this.reasoningHistory.push({ phase, input: input.slice(0, 200), output: output.slice(0, 200), confidence, timestamp: Date.now(), durationMs });
    if (this.reasoningHistory.length > 100) this.reasoningHistory = this.reasoningHistory.slice(-100);
  }
}
