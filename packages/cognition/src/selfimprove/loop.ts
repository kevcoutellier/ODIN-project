/**
 * Counterfactual Self-Improvement Loop
 *
 * Continuously improves the agent by analyzing past failures
 * and generating actionable counterfactual insights.
 *
 * Flow:
 * 1. COLLECT: Gather failed tool calls, low-accuracy predictions,
 *    rejected evolution proposals, and invariant violations
 * 2. ANALYZE: Use the CausalEngine to build failure models
 * 3. HYPOTHESIZE: Generate counterfactual questions ("what if...")
 * 4. SYNTHESIZE: Extract actionable improvement suggestions
 * 5. APPLY: Update world model, procedures, and knowledge
 *
 * This creates a closed-loop learning system where the agent
 * genuinely improves from its mistakes — not just retries.
 */

import { randomUUID } from 'node:crypto';
import type { CausalEngine, CounterfactualQuestion } from '../causal/index.js';
import type { ModelFirstReasoner, Plan, PlanStep } from '../reasoning/index.js';
import type { CIKStore } from '../cik/index.js';
import type { AMEMController } from '../amem/index.js';
import type { EvolutionSandbox } from '../evolution/index.js';
import type { CIKInvariantVerifier, InvariantReport } from '../invariants/index.js';

// ─── Types ───

export interface FailureRecord {
  id: string;
  type: 'tool_failure' | 'prediction_error' | 'evolution_rejected' | 'invariant_violation' | 'plan_failure';
  description: string;
  context: Record<string, unknown>;
  timestamp: number;
  analyzed: boolean;
}

export interface ImprovementInsight {
  id: string;
  source: string; // FailureRecord ID
  type: 'procedure_update' | 'knowledge_correction' | 'world_model_update' | 'strategy_change';
  description: string;
  suggestion: string;
  confidence: number;
  applied: boolean;
  impact?: string;
  createdAt: number;
}

export interface SelfImprovementReport {
  cycleNumber: number;
  failuresAnalyzed: number;
  insightsGenerated: number;
  insightsApplied: number;
  counterfactualsGenerated: number;
  worldModelUpdates: number;
  knowledgeCorrections: number;
  procedureUpdates: number;
  startedAt: number;
  finishedAt: number;
}

// ─── Self-Improvement Controller ───

export class SelfImprovementLoop {
  private failures: FailureRecord[] = [];
  private insights: ImprovementInsight[] = [];
  private reports: SelfImprovementReport[] = [];
  private cycleCount = 0;
  private maxFailures = 500;
  private maxInsights = 200;
  private maxReports = 50;

  constructor(
    private causalEngine: CausalEngine,
    private reasoner: ModelFirstReasoner,
    private cikStore: CIKStore,
    private amem: AMEMController,
    private evolutionSandbox: EvolutionSandbox,
    private invariantVerifier: CIKInvariantVerifier,
  ) {}

  // ─── COLLECTION ───

  /**
   * Record a tool call failure for later analysis.
   */
  recordToolFailure(toolName: string, args: Record<string, unknown>, error: string): void {
    this.addFailure({
      type: 'tool_failure',
      description: `Tool "${toolName}" failed: ${error}`,
      context: { toolName, args, error },
    });
  }

  /**
   * Record a prediction error (from Model-First Reasoning).
   */
  recordPredictionError(step: PlanStep, predictionAccuracy: number): void {
    if (predictionAccuracy > 0.5) return; // Only record significant errors
    this.addFailure({
      type: 'prediction_error',
      description: `Prediction for "${step.action}" was ${(predictionAccuracy * 100).toFixed(0)}% accurate`,
      context: {
        action: step.action,
        expected: step.expectedOutcome,
        actual: step.actualOutcome,
        accuracy: predictionAccuracy,
      },
    });
  }

  /**
   * Record a rejected evolution proposal.
   */
  recordEvolutionRejection(knowledgeId: string, reason: string): void {
    this.addFailure({
      type: 'evolution_rejected',
      description: `Knowledge evolution rejected: ${reason}`,
      context: { knowledgeId, reason },
    });
  }

  /**
   * Record a plan failure.
   */
  recordPlanFailure(plan: Plan): void {
    const failedSteps = plan.steps.filter(s => s.status === 'failed');
    this.addFailure({
      type: 'plan_failure',
      description: `Plan "${plan.goal}" failed: ${failedSteps.length}/${plan.steps.length} steps failed`,
      context: {
        goal: plan.goal,
        totalSteps: plan.steps.length,
        failedSteps: failedSteps.map(s => ({ action: s.action, outcome: s.actualOutcome })),
        confidence: plan.confidence,
      },
    });
  }

  // ─── ANALYSIS CYCLE ───

  /**
   * Run a full self-improvement cycle.
   */
  async runCycle(): Promise<SelfImprovementReport> {
    const startedAt = Date.now();
    this.cycleCount++;
    let insightsGenerated = 0;
    let insightsApplied = 0;
    let counterfactualsGenerated = 0;
    let worldModelUpdates = 0;
    let knowledgeCorrections = 0;
    let procedureUpdates = 0;

    // 1. Get unanalyzed failures
    const unanalyzed = this.failures.filter(f => !f.analyzed);
    if (unanalyzed.length === 0) {
      return this.emptyReport(startedAt);
    }

    // 2. Analyze each failure type
    for (const failure of unanalyzed.slice(0, 20)) { // Process 20 at a time max
      failure.analyzed = true;

      try {
        switch (failure.type) {
          case 'tool_failure': {
            const { modelId, analysis } = this.causalEngine.buildFailureModel(
              failure.context.toolName as string,
              failure.context.args as Record<string, unknown>,
              failure.context.error as string,
            );

            // Generate counterfactual: "What if the input had been different?"
            const model = this.causalEngine.getModel(modelId);
            if (model) {
              const vars = [...model.variables.values()];
              const inputVar = vars.find(v => v.name === 'tool_input');
              const resultVar = vars.find(v => v.name === 'result');

              if (inputVar && resultVar) {
                const cf = this.causalEngine.queryCounterfactual(
                  modelId,
                  resultVar.id,
                  { [inputVar.id]: 'invalid', [resultVar.id]: 'failure' },
                  { [inputVar.id]: 'valid' },
                );
                counterfactualsGenerated++;

                if (cf.actionable) {
                  const insight = this.createInsight(failure.id, 'strategy_change',
                    `Tool "${failure.context.toolName}" failure analysis`,
                    cf.suggestion ?? 'Validate inputs before calling this tool',
                    cf.confidence);
                  insightsGenerated++;

                  // Apply: add knowledge about the failure pattern
                  await this.cikStore.addKnowledge(
                    failure.context.toolName as string,
                    'failure_pattern',
                    failure.context.error as string,
                    `selfimprove:cycle-${this.cycleCount}`,
                    'T3',
                    `Learned from failure at ${new Date(failure.timestamp).toISOString()}`,
                  );
                  knowledgeCorrections++;
                  insight.applied = true;
                  insightsApplied++;
                }
              }
            }
            break;
          }

          case 'prediction_error': {
            // Update world model with the prediction discrepancy
            this.reasoner.observe([{
              type: 'uncertainty',
              data: {
                description: `Prediction for "${failure.context.action}" was inaccurate (${((failure.context.accuracy as number) * 100).toFixed(0)}%)`,
                impact: (failure.context.accuracy as number) < 0.2 ? 'high' : 'medium',
              },
            }]);
            worldModelUpdates++;

            const insight = this.createInsight(failure.id, 'world_model_update',
              `Prediction model needs recalibration for: ${failure.context.action}`,
              `Expected: ${failure.context.expected}, Got: ${failure.context.actual}`,
              0.6);
            insightsGenerated++;
            insight.applied = true;
            insightsApplied++;
            break;
          }

          case 'plan_failure': {
            // Analyze which steps failed and why
            const failedSteps = failure.context.failedSteps as Array<{ action: string; outcome: string }>;
            for (const step of failedSteps.slice(0, 3)) {
              const insight = this.createInsight(failure.id, 'strategy_change',
                `Plan step failed: ${step.action}`,
                `Outcome was: ${step.outcome}. Consider alternative approaches.`,
                0.5);
              insightsGenerated++;

              // Record the failure pattern as knowledge
              await this.cikStore.addKnowledge(
                step.action,
                'tends_to_fail_when',
                step.outcome ?? 'unknown',
                `selfimprove:cycle-${this.cycleCount}`,
                'T4',
              );
              knowledgeCorrections++;
              insight.applied = true;
              insightsApplied++;
            }

            worldModelUpdates++;
            break;
          }

          case 'evolution_rejected': {
            const insight = this.createInsight(failure.id, 'knowledge_correction',
              `Knowledge evolution blocked: ${failure.context.reason}`,
              `Review knowledge entry ${failure.context.knowledgeId} for accuracy`,
              0.4);
            insightsGenerated++;
            break;
          }

          case 'invariant_violation': {
            const insight = this.createInsight(failure.id, 'knowledge_correction',
              `CIK invariant violated: ${failure.description}`,
              'Run invariant verifier and repair violations',
              0.8);
            insightsGenerated++;
            break;
          }
        }
      } catch {
        // Don't let analysis failures crash the loop
      }
    }

    // 3. Run invariant verification and record any new violations
    try {
      const invariantReport = await this.invariantVerifier.verify(this.cikStore);
      for (const violation of invariantReport.violations) {
        this.addFailure({
          type: 'invariant_violation',
          description: violation.message,
          context: { ...violation },
        });
      }
    } catch {
      // Non-critical
    }

    const report: SelfImprovementReport = {
      cycleNumber: this.cycleCount,
      failuresAnalyzed: unanalyzed.length,
      insightsGenerated,
      insightsApplied,
      counterfactualsGenerated,
      worldModelUpdates,
      knowledgeCorrections,
      procedureUpdates,
      startedAt,
      finishedAt: Date.now(),
    };

    this.reports.push(report);
    if (this.reports.length > this.maxReports) {
      this.reports = this.reports.slice(-this.maxReports);
    }

    return report;
  }

  // ─── PROMPT INTEGRATION ───

  /**
   * Generate prompt section with self-improvement insights.
   */
  getImprovementPrompt(): string {
    const recentInsights = this.insights
      .filter(i => i.applied && Date.now() - i.createdAt < 24 * 60 * 60 * 1000) // Last 24h
      .slice(-5);

    if (recentInsights.length === 0) return '';

    const parts = ['## Self-Improvement Insights', ''];
    for (const insight of recentInsights) {
      parts.push(`- **${insight.description}**`);
      parts.push(`  Suggestion: ${insight.suggestion} (confidence: ${(insight.confidence * 100).toFixed(0)}%)`);
    }

    // Add recent failure patterns
    const recentFailures = this.failures
      .filter(f => f.type === 'tool_failure' && Date.now() - f.timestamp < 60 * 60 * 1000)
      .slice(-3);

    if (recentFailures.length > 0) {
      parts.push('');
      parts.push('### Recent Failure Patterns');
      for (const f of recentFailures) {
        parts.push(`- ${f.description}`);
      }
      parts.push('> Learn from these — avoid repeating the same mistakes.');
    }

    return parts.join('\n');
  }

  // ─── ACCESSORS ───

  getFailures(): FailureRecord[] { return this.failures.slice(-50); }
  getInsights(): ImprovementInsight[] { return this.insights.slice(-50); }
  getReports(): SelfImprovementReport[] { return this.reports; }
  getCycleCount(): number { return this.cycleCount; }

  getStats(): {
    totalFailures: number;
    analyzedFailures: number;
    totalInsights: number;
    appliedInsights: number;
    improvementRate: number;
  } {
    const analyzed = this.failures.filter(f => f.analyzed).length;
    const applied = this.insights.filter(i => i.applied).length;
    return {
      totalFailures: this.failures.length,
      analyzedFailures: analyzed,
      totalInsights: this.insights.length,
      appliedInsights: applied,
      improvementRate: this.insights.length > 0 ? applied / this.insights.length : 0,
    };
  }

  // ─── HELPERS ───

  private addFailure(data: Omit<FailureRecord, 'id' | 'timestamp' | 'analyzed'>): void {
    this.failures.push({
      id: randomUUID(),
      ...data,
      timestamp: Date.now(),
      analyzed: false,
    });
    if (this.failures.length > this.maxFailures) {
      this.failures = this.failures.slice(-this.maxFailures);
    }
  }

  private createInsight(
    sourceId: string,
    type: ImprovementInsight['type'],
    description: string,
    suggestion: string,
    confidence: number,
  ): ImprovementInsight {
    const insight: ImprovementInsight = {
      id: randomUUID(),
      source: sourceId,
      type,
      description,
      suggestion,
      confidence,
      applied: false,
      createdAt: Date.now(),
    };
    this.insights.push(insight);
    if (this.insights.length > this.maxInsights) {
      this.insights = this.insights.slice(-this.maxInsights);
    }
    return insight;
  }

  private emptyReport(startedAt: number): SelfImprovementReport {
    return {
      cycleNumber: this.cycleCount,
      failuresAnalyzed: 0,
      insightsGenerated: 0,
      insightsApplied: 0,
      counterfactualsGenerated: 0,
      worldModelUpdates: 0,
      knowledgeCorrections: 0,
      procedureUpdates: 0,
      startedAt,
      finishedAt: Date.now(),
    };
  }
}
