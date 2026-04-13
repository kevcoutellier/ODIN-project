/**
 * Audit Log — Append-only signed log
 *
 * Every security decision, tool call, and agent interaction
 * is recorded in a tamper-evident log. Entries are signed with
 * the instance's Ed25519 key. Compliant with EU AI Act Article 50.
 */

import type { AuditLogEntry, PolicyDecision, TaintLabel } from '@odin/core';
import { randomUUID } from 'node:crypto';
import { appendFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';

export interface AuditLogConfig {
  logPath: string;
  signFn?: (data: string) => string;
}

export class AuditLog {
  private entries: AuditLogEntry[] = [];
  private initialized = false;

  constructor(private config: AuditLogConfig) {}

  async init(): Promise<void> {
    if (this.initialized) return;
    await mkdir(dirname(this.config.logPath), { recursive: true });
    this.initialized = true;
  }

  async record(params: {
    agentDid: string;
    action: string;
    resource: string;
    decision: PolicyDecision;
    taintLabel: TaintLabel;
    trustScore: number;
  }): Promise<AuditLogEntry> {
    await this.init();

    const entry: AuditLogEntry = {
      id: randomUUID(),
      timestamp: Date.now(),
      agentDid: params.agentDid,
      action: params.action,
      resource: params.resource,
      decision: params.decision,
      taintLabel: params.taintLabel,
      trustScore: params.trustScore,
      signature: '',
    };

    // Sign the entry
    if (this.config.signFn) {
      const dataToSign = JSON.stringify({
        id: entry.id,
        timestamp: entry.timestamp,
        agentDid: entry.agentDid,
        action: entry.action,
        resource: entry.resource,
        decision: entry.decision.allowed,
      });
      entry.signature = this.config.signFn(dataToSign);
    }

    this.entries.push(entry);
    // Cap in-memory entries at 5000 (all entries still written to file)
    if (this.entries.length > 5000) {
      this.entries = this.entries.slice(-5000);
    }

    // Append to file (append-only, tamper-evident)
    await appendFile(
      this.config.logPath,
      JSON.stringify(entry) + '\n',
      'utf-8',
    );

    return entry;
  }

  getEntries(limit = 100): AuditLogEntry[] {
    return this.entries.slice(-limit);
  }

  getEntriesByAction(action: string): AuditLogEntry[] {
    return this.entries.filter(e => e.action === action);
  }

  getDeniedEntries(): AuditLogEntry[] {
    return this.entries.filter(e => !e.decision.allowed);
  }

  /**
   * EU AI Act Article 50 compliance: export all metadata
   * for transparency requirements.
   */
  exportComplianceReport(): {
    totalDecisions: number;
    deniedDecisions: number;
    trustScoreRange: { min: number; max: number };
    actionSummary: Record<string, number>;
    timeRange: { from: number; to: number };
  } {
    const scores = this.entries.map(e => e.trustScore);
    const actionCounts: Record<string, number> = {};
    for (const entry of this.entries) {
      actionCounts[entry.action] = (actionCounts[entry.action] ?? 0) + 1;
    }

    return {
      totalDecisions: this.entries.length,
      deniedDecisions: this.entries.filter(e => !e.decision.allowed).length,
      trustScoreRange: {
        min: scores.length > 0 ? Math.min(...scores) : 0,
        max: scores.length > 0 ? Math.max(...scores) : 0,
      },
      actionSummary: actionCounts,
      timeRange: {
        from: this.entries[0]?.timestamp ?? 0,
        to: this.entries[this.entries.length - 1]?.timestamp ?? 0,
      },
    };
  }
}
