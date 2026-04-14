/**
 * A-MEM — Agent Memory: Procedural Memory Module
 *
 * Compresses successful tool-call trajectories into reusable routines.
 * Inspired by biological procedural memory (muscle memory / habits).
 *
 * Flow:
 * 1. RECORD: Agent records tool call sequences during task execution
 * 2. COMPRESS: After success, compress the trajectory into a procedure
 * 3. STORE: Save as a CIK Capability entry (type=procedure)
 * 4. RECALL: When facing similar tasks, recall and suggest stored procedures
 * 5. REFINE: Re-execution updates success rates, refines parameters
 *
 * Key insight: Not all sequences are procedures — we only compress sequences
 * that led to SUCCESSFUL outcomes (positive reinforcement).
 */

import { randomUUID } from 'node:crypto';
import { sha256 } from '@odin/core';
import type { CIKStore, CapabilityEntry, TrustTier } from '../cik/index.js';
import type { EpisodicStore, Episode } from '../episodic/index.js';

// ─── Types ───

export interface ToolCallRecord {
  tool: string;
  args: Record<string, unknown>;
  result: string;
  success: boolean;
  durationMs: number;
  timestamp: number;
}

export interface Trajectory {
  id: string;
  taskDescription: string;
  calls: ToolCallRecord[];
  success: boolean;
  totalDurationMs: number;
  startedAt: number;
  finishedAt: number;
}

export interface Procedure {
  id: string;
  name: string;
  description: string;
  steps: ProcedureStep[];
  triggerPattern: string; // Regex or keyword pattern that triggers this procedure
  successRate: number;
  executionCount: number;
  avgDurationMs: number;
  learnedFromTrajectories: string[]; // trajectory IDs
  createdAt: number;
  updatedAt: number;
}

export interface ProcedureStep {
  order: number;
  tool: string;
  argsTemplate: Record<string, unknown>; // Template with placeholders
  expectedResult: string;
  optional: boolean;
  conditionToSkip?: string;
}

export interface ProcedureMatch {
  procedure: Procedure;
  similarity: number; // 0.0-1.0
  reason: string;
}

// ─── A-MEM Controller ───

export class AMEMController {
  private activeTrajectories: Map<string, Trajectory> = new Map();
  private completedTrajectories: Trajectory[] = [];
  private maxCompleted = 200; // Cap stored trajectories

  constructor(
    private cikStore: CIKStore,
    private episodicStore: EpisodicStore,
  ) {}

  // ─── RECORDING ───

  /**
   * Start recording a new trajectory for a task.
   */
  startTrajectory(taskDescription: string): string {
    const id = randomUUID();
    this.activeTrajectories.set(id, {
      id,
      taskDescription,
      calls: [],
      success: false,
      totalDurationMs: 0,
      startedAt: Date.now(),
      finishedAt: 0,
    });
    return id;
  }

  /**
   * Record a tool call in the active trajectory.
   */
  recordCall(trajectoryId: string, record: ToolCallRecord): void {
    const trajectory = this.activeTrajectories.get(trajectoryId);
    if (!trajectory) return;
    trajectory.calls.push(record);
  }

  /**
   * End a trajectory and mark its success/failure.
   * If successful & long enough, attempt to compress into a procedure.
   */
  async endTrajectory(trajectoryId: string, success: boolean): Promise<Procedure | null> {
    const trajectory = this.activeTrajectories.get(trajectoryId);
    if (!trajectory) return null;

    trajectory.success = success;
    trajectory.finishedAt = Date.now();
    trajectory.totalDurationMs = trajectory.finishedAt - trajectory.startedAt;

    this.activeTrajectories.delete(trajectoryId);
    this.completedTrajectories.push(trajectory);

    // Cap completed trajectories
    if (this.completedTrajectories.length > this.maxCompleted) {
      this.completedTrajectories = this.completedTrajectories.slice(-this.maxCompleted);
    }

    // Only compress successful trajectories with 2+ calls
    if (success && trajectory.calls.length >= 2) {
      return this.compressTrajectory(trajectory);
    }

    return null;
  }

  // ─── COMPRESSION ───

  /**
   * Compress a successful trajectory into a reusable procedure.
   * - Removes failed intermediate steps
   * - Abstracts specific args into templates
   * - Detects optional steps (steps that sometimes fail but trajectory still succeeds)
   */
  private async compressTrajectory(trajectory: Trajectory): Promise<Procedure | null> {
    const successfulCalls = trajectory.calls.filter(c => c.success);
    if (successfulCalls.length < 2) return null;

    // Check if a similar procedure already exists
    const existing = await this.findSimilarProcedure(trajectory);
    if (existing) {
      // Reinforce the existing procedure
      await this.reinforceProcedure(existing.procedure, trajectory);
      return existing.procedure;
    }

    // Generate procedure name from tool sequence
    const toolSequence = successfulCalls.map(c => c.tool);
    const uniqueTools = [...new Set(toolSequence)];
    const name = `proc_${uniqueTools.join('_then_')}`.slice(0, 64);

    // Create procedure steps from the trajectory
    const steps: ProcedureStep[] = successfulCalls.map((call, i) => ({
      order: i + 1,
      tool: call.tool,
      argsTemplate: this.abstractArgs(call.args),
      expectedResult: call.result.slice(0, 200),
      optional: false,
      conditionToSkip: undefined,
    }));

    // Mark steps as optional if they failed in other trajectories with the same overall success
    const optionalSteps = this.identifyOptionalSteps(trajectory);
    for (const idx of optionalSteps) {
      if (steps[idx]) steps[idx].optional = true;
    }

    const procedure: Procedure = {
      id: randomUUID(),
      name,
      description: `Learned procedure for: ${trajectory.taskDescription}`,
      steps,
      triggerPattern: this.extractTriggerPattern(trajectory.taskDescription),
      successRate: 1.0,
      executionCount: 1,
      avgDurationMs: trajectory.totalDurationMs,
      learnedFromTrajectories: [trajectory.id],
      createdAt: Date.now(),
      updatedAt: Date.now(),
    };

    // Store in CIK as a capability
    await this.cikStore.addCapability({
      name: procedure.name,
      type: 'procedure',
      description: procedure.description,
      parameters: {
        steps: procedure.steps,
        triggerPattern: procedure.triggerPattern,
        learnedFrom: procedure.learnedFromTrajectories,
        avgDurationMs: procedure.avgDurationMs,
      },
      learnedFrom: trajectory.id,
      successRate: 1.0,
      usageCount: 1,
      lastUsed: Date.now(),
      tier: 'T3', // LLM-derived — not yet verified by the user
    });

    // Record as episodic memory
    await this.episodicStore.recordEpisode(
      `amem-${Date.now()}`,
      `Learned procedure: ${procedure.name}\nSteps: ${steps.map(s => s.tool).join(' → ')}\nFrom task: ${trajectory.taskDescription}`,
      'reflection',
      [],
      [],
      0.7, // Important — learned procedures are valuable
      0,
      `Compressed ${trajectory.calls.length} tool calls into ${steps.length}-step procedure`,
    );

    return procedure;
  }

  // ─── RECALL ───

  /**
   * Given a task description, find matching procedures.
   */
  async recallProcedures(taskDescription: string, limit: number = 5): Promise<ProcedureMatch[]> {
    const capabilities = await this.cikStore.getCapabilities();
    const procedures = capabilities.filter(c => c.type === 'procedure');
    const matches: ProcedureMatch[] = [];

    const taskWords = new Set(
      taskDescription.toLowerCase().split(/\s+/).filter(w => w.length > 3)
    );

    for (const cap of procedures) {
      const params = cap.parameters as Record<string, unknown> | undefined;
      const triggerPattern = (params?.triggerPattern as string) ?? '';

      // Score: word overlap + trigger pattern match
      let similarity = 0;
      const descWords = cap.description.toLowerCase().split(/\s+/).filter(w => w.length > 3);
      const overlap = descWords.filter(w => taskWords.has(w)).length;
      similarity = descWords.length > 0 ? overlap / Math.max(taskWords.size, descWords.length) : 0;

      // Boost if trigger pattern matches
      if (triggerPattern) {
        try {
          const regex = new RegExp(triggerPattern, 'i');
          if (regex.test(taskDescription)) {
            similarity = Math.min(1.0, similarity + 0.4);
          }
        } catch {
          // Invalid regex — use keyword matching
          const patternWords = triggerPattern.toLowerCase().split(/\s+/);
          const keywordMatch = patternWords.filter(w => taskWords.has(w)).length / patternWords.length;
          similarity = Math.min(1.0, similarity + keywordMatch * 0.3);
        }
      }

      // Boost by success rate
      similarity *= (0.5 + cap.successRate * 0.5);

      if (similarity > 0.2) {
        matches.push({
          procedure: this.capabilityToProcedure(cap),
          similarity,
          reason: `${(similarity * 100).toFixed(0)}% match — ${cap.usageCount} executions, ${(cap.successRate * 100).toFixed(0)}% success`,
        });
      }
    }

    return matches
      .sort((a, b) => b.similarity - a.similarity)
      .slice(0, limit);
  }

  /**
   * Get the prompt section for procedural memory context.
   */
  async getProceduralPrompt(taskDescription: string): Promise<string> {
    const matches = await this.recallProcedures(taskDescription, 3);
    if (matches.length === 0) return '';

    const parts = [
      '## Known Procedures (from past experience)',
      '',
    ];

    for (const match of matches) {
      parts.push(`### ${match.procedure.name} (${match.reason})`);
      parts.push(`Steps:`);
      for (const step of match.procedure.steps) {
        const optLabel = step.optional ? ' [optional]' : '';
        parts.push(`  ${step.order}. \`${step.tool}\`${optLabel}`);
      }
      parts.push('');
    }

    parts.push('> You may adapt these procedures to the current context.');
    return parts.join('\n');
  }

  // ─── REFINEMENT ───

  /**
   * After re-executing a procedure, update its success rate.
   */
  async recordExecution(procedureName: string, success: boolean): Promise<void> {
    await this.cikStore.recordCapabilityUsage(procedureName, success);
  }

  // ─── HELPERS ───

  private async findSimilarProcedure(trajectory: Trajectory): Promise<ProcedureMatch | null> {
    const matches = await this.recallProcedures(trajectory.taskDescription, 1);
    if (matches.length > 0 && matches[0].similarity > 0.7) {
      return matches[0];
    }

    // Also check tool sequence match
    const toolSeq = trajectory.calls.filter(c => c.success).map(c => c.tool).join(',');
    const capabilities = await this.cikStore.getCapabilities();
    for (const cap of capabilities.filter(c => c.type === 'procedure')) {
      const params = cap.parameters as Record<string, unknown> | undefined;
      const steps = (params?.steps as ProcedureStep[]) ?? [];
      const capSeq = steps.map(s => s.tool).join(',');
      if (capSeq === toolSeq) {
        return {
          procedure: this.capabilityToProcedure(cap),
          similarity: 0.9,
          reason: 'Exact tool sequence match',
        };
      }
    }

    return null;
  }

  private async reinforceProcedure(procedure: Procedure, trajectory: Trajectory): Promise<void> {
    // Update execution count and average duration via CIK
    await this.cikStore.recordCapabilityUsage(procedure.name, trajectory.success);
  }

  /**
   * Abstract specific arg values into template placeholders.
   * e.g., { path: "/home/user/file.txt" } → { path: "{file_path}" }
   */
  private abstractArgs(args: Record<string, unknown>): Record<string, unknown> {
    const template: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(args)) {
      if (typeof value === 'string') {
        // Keep short values, abstract long ones
        if (value.length > 50) {
          template[key] = `{${key}}`;
        } else {
          template[key] = value;
        }
      } else {
        template[key] = value;
      }
    }
    return template;
  }

  /**
   * Identify steps that might be optional by checking if they failed
   * in trajectories that still succeeded overall.
   */
  private identifyOptionalSteps(trajectory: Trajectory): number[] {
    const optional: number[] = [];
    for (let i = 0; i < trajectory.calls.length; i++) {
      if (!trajectory.calls[i].success && trajectory.success) {
        optional.push(i);
      }
    }
    return optional;
  }

  /**
   * Extract a trigger pattern from a task description.
   * Simple keyword extraction — will be improved with LLM in Phase 3.
   */
  private extractTriggerPattern(description: string): string {
    const keywords = description.toLowerCase()
      .split(/\s+/)
      .filter(w => w.length > 4)
      .filter(w => !COMMON_WORDS.has(w))
      .slice(0, 5);
    return keywords.join('|');
  }

  private capabilityToProcedure(cap: CapabilityEntry): Procedure {
    const params = cap.parameters as Record<string, unknown> | undefined;
    return {
      id: cap.id,
      name: cap.name,
      description: cap.description,
      steps: (params?.steps as ProcedureStep[]) ?? [],
      triggerPattern: (params?.triggerPattern as string) ?? '',
      successRate: cap.successRate,
      executionCount: cap.usageCount,
      avgDurationMs: (params?.avgDurationMs as number) ?? 0,
      learnedFromTrajectories: (params?.learnedFrom as string[]) ?? [],
      createdAt: cap.createdAt,
      updatedAt: cap.updatedAt,
    };
  }

  // Stats
  getActiveTrajectories(): number { return this.activeTrajectories.size; }
  getCompletedTrajectories(): number { return this.completedTrajectories.length; }
}

const COMMON_WORDS = new Set([
  'about', 'after', 'again', 'being', 'below', 'could', 'doing',
  'every', 'first', 'going', 'having', 'might', 'never', 'other',
  'shall', 'since', 'still', 'their', 'there', 'these', 'thing',
  'think', 'those', 'today', 'under', 'until', 'using', 'which',
  'while', 'would', 'should', 'please', 'really', 'before',
]);
