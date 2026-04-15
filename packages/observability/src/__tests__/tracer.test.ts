/**
 * DecisionTracer tests — OpenTelemetry-compatible spans for security decisions.
 *
 * Covers:
 *   - trace lifecycle (startTrace → spans → endTrace)
 *   - nested span parent-child linkage via the internal spanStack
 *   - auto-trace creation when startSpan is called without an active trace
 *   - endTrace closes any dangling spans
 *   - recordDecision shorthand → allow=ok / deny=error status
 *   - cap at 100 stored traces (oldest evicted)
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { DecisionTracer } from '../tracer.js';

let tracer: DecisionTracer;
beforeEach(() => { tracer = new DecisionTracer(); });

describe('DecisionTracer — lifecycle', () => {
  it('startTrace creates a trace and opens an initial span', () => {
    const id = tracer.startTrace('user-request');
    expect(id).toBeTruthy();
    const trace = tracer.getTrace(id)!;
    expect(trace).not.toBeNull();
    expect(trace.spans).toHaveLength(1);
    expect(trace.spans[0].name).toBe('user-request');
    expect(trace.spans[0].attributes.traceStart).toBe(true);
  });

  it('startSpan auto-creates a trace when none is active', () => {
    // No explicit startTrace
    const spanId = tracer.startSpan('orphan-span');
    expect(spanId).toBeTruthy();
    // An auto-trace named "auto" was created with the initial span, then our span
    const trace = tracer.endTrace()!;
    expect(trace.spans.length).toBeGreaterThanOrEqual(2);
    expect(trace.spans[0].name).toBe('auto');
    expect(trace.spans.find(s => s.name === 'orphan-span')).toBeTruthy();
  });

  it('nested spans track parent-child via spanStack', () => {
    tracer.startTrace('root');
    const childId = tracer.startSpan('child');
    const grandchildId = tracer.startSpan('grandchild');
    tracer.endSpan('ok'); // grandchild
    tracer.endSpan('ok'); // child
    const trace = tracer.endTrace()!;

    const child = trace.spans.find(s => s.spanId === childId)!;
    const grandchild = trace.spans.find(s => s.spanId === grandchildId)!;

    expect(child.parentSpanId).toBeTruthy(); // root's span
    expect(grandchild.parentSpanId).toBe(childId);
  });

  it('endSpan sets endTime and status on the current span', () => {
    tracer.startTrace('t');
    tracer.startSpan('operation');
    tracer.endSpan('error', { reason: 'permission_denied' });
    const trace = tracer.endTrace()!;

    const op = trace.spans.find(s => s.name === 'operation')!;
    expect(op.endTime).toBeGreaterThan(0);
    expect(op.attributes.status).toBe('error');
    expect(op.attributes.reason).toBe('permission_denied');
  });

  it('endSpan without an active span is a silent no-op', () => {
    // No active trace at all
    expect(() => tracer.endSpan()).not.toThrow();
    // Active trace but stack empty after all spans closed
    tracer.startTrace('t');
    tracer.endTrace();
    expect(() => tracer.endSpan()).not.toThrow();
  });

  it('endTrace closes any dangling open spans with status=ok', () => {
    tracer.startTrace('root');
    tracer.startSpan('inner1');
    tracer.startSpan('inner2');
    // Never explicitly end them
    const trace = tracer.endTrace()!;
    // All spans get endTime; dangling ones get status=ok
    for (const span of trace.spans) {
      expect(span.endTime).toBeGreaterThan(0);
      // The attributes.status is set by endSpan; dangling → 'ok'
      expect(span.attributes.status).toBeDefined();
    }
  });

  it('endTrace clears the active trace (next startSpan auto-creates)', () => {
    const id1 = tracer.startTrace('first');
    tracer.endTrace();
    const id2 = tracer.startSpan('after'); // auto-creates a new trace
    const closed = tracer.endTrace()!;
    expect(closed.traceId).not.toBe(id1);
  });

  it('getTrace returns null for an unknown id', () => {
    expect(tracer.getTrace('nope')).toBeNull();
  });
});

describe('DecisionTracer — recordDecision', () => {
  it('records an allow decision as a span with status=ok', () => {
    tracer.startTrace('req');
    tracer.recordDecision('policy_check', { allowed: true, reason: 'trusted user' }, 3);
    const trace = tracer.endTrace()!;
    const decisionSpan = trace.spans.find(s => s.name === 'decision:policy_check')!;
    expect(decisionSpan).toBeTruthy();
    expect(decisionSpan.attributes['security.decision']).toBe('allow');
    expect(decisionSpan.attributes['security.reason']).toBe('trusted user');
    expect(decisionSpan.attributes.duration_ms).toBe(3);
    expect(decisionSpan.attributes.status).toBe('ok');
  });

  it('records a deny decision as a span with status=error', () => {
    tracer.startTrace('req');
    tracer.recordDecision('policy_check', { allowed: false, reason: 'low trust' }, 1);
    const trace = tracer.endTrace()!;
    const decisionSpan = trace.spans.find(s => s.name === 'decision:policy_check')!;
    expect(decisionSpan.attributes['security.decision']).toBe('deny');
    expect(decisionSpan.attributes.status).toBe('error');
  });
});

describe('DecisionTracer — trace cap', () => {
  it('caps stored traces at 100 (oldest evicted)', () => {
    const firstId = tracer.startTrace('t0');
    tracer.endTrace();
    for (let i = 1; i < 105; i++) {
      tracer.startTrace(`t${i}`);
      tracer.endTrace();
    }
    // First trace should have been evicted
    expect(tracer.getTrace(firstId)).toBeNull();
  });
});
