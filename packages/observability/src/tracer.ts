/**
 * Decision Tracer — OpenTelemetry-compatible tracing
 *
 * Every security decision generates a span:
 * - IFC taint checks
 * - Policy evaluations
 * - Trust score updates
 * - Circuit breaker transitions
 * - Tool executions
 */

import type { DecisionTrace } from '@odin/core';
import { randomUUID } from 'node:crypto';

export interface Span {
  spanId: string;
  parentSpanId?: string;
  name: string;
  startTime: number;
  endTime?: number;
  attributes: Record<string, unknown>;
  status: 'ok' | 'error' | 'unset';
}

export class DecisionTracer {
  private traces: Map<string, Span[]> = new Map();
  private activeTraceId: string | null = null;
  private spanStack: string[] = [];

  /**
   * Start a new trace (e.g., for a user request).
   */
  startTrace(name: string): string {
    const traceId = randomUUID();
    // Cap at 100 traces, delete oldest when exceeded
    if (this.traces.size >= 100) {
      const oldest = this.traces.keys().next().value;
      if (oldest) this.traces.delete(oldest);
    }
    this.traces.set(traceId, []);
    this.activeTraceId = traceId;

    this.startSpan(name, { traceStart: true });
    return traceId;
  }

  /**
   * Start a span within the current trace.
   */
  startSpan(name: string, attributes: Record<string, unknown> = {}): string {
    if (!this.activeTraceId) {
      this.startTrace('auto');
    }

    const spanId = randomUUID();
    const parentSpanId = this.spanStack.length > 0
      ? this.spanStack[this.spanStack.length - 1]
      : undefined;

    const span: Span = {
      spanId,
      parentSpanId,
      name,
      startTime: performance.now(),
      attributes,
      status: 'unset',
    };

    this.traces.get(this.activeTraceId!)!.push(span);
    this.spanStack.push(spanId);
    return spanId;
  }

  /**
   * End the current span.
   */
  endSpan(status: 'ok' | 'error' = 'ok', attributes?: Record<string, unknown>): void {
    const spanId = this.spanStack.pop();
    if (!spanId || !this.activeTraceId) return;

    const spans = this.traces.get(this.activeTraceId);
    if (!spans) return;

    const span = spans.find(s => s.spanId === spanId);
    if (span) {
      span.endTime = performance.now();
      span.status = status;
      if (attributes) {
        Object.assign(span.attributes, attributes);
      }
    }
  }

  /**
   * End the current trace and return the complete decision trace.
   */
  endTrace(): DecisionTrace | null {
    if (!this.activeTraceId) return null;

    const spans = this.traces.get(this.activeTraceId) ?? [];

    // End all open spans
    while (this.spanStack.length > 0) {
      this.endSpan('ok');
    }

    const trace: DecisionTrace = {
      traceId: this.activeTraceId,
      spans: spans.map(s => ({
        spanId: s.spanId,
        parentSpanId: s.parentSpanId,
        name: s.name,
        startTime: s.startTime,
        endTime: s.endTime ?? performance.now(),
        attributes: { ...s.attributes, status: s.status },
      })),
    };

    this.activeTraceId = null;
    return trace;
  }

  /**
   * Record a security decision as a span.
   */
  recordDecision(
    name: string,
    decision: { allowed: boolean; reason: string },
    durationMs: number,
  ): void {
    const spanId = this.startSpan(`decision:${name}`, {
      'security.decision': decision.allowed ? 'allow' : 'deny',
      'security.reason': decision.reason,
    });
    this.endSpan(decision.allowed ? 'ok' : 'error', {
      'duration_ms': durationMs,
    });
  }

  getTrace(traceId: string): DecisionTrace | null {
    const spans = this.traces.get(traceId);
    if (!spans) return null;

    return {
      traceId,
      spans: spans.map(s => ({
        spanId: s.spanId,
        parentSpanId: s.parentSpanId,
        name: s.name,
        startTime: s.startTime,
        endTime: s.endTime ?? 0,
        attributes: s.attributes,
      })),
    };
  }
}
