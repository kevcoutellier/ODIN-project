/**
 * Circuit breaker adversarial tests.
 *
 * Complements circuit-breaker.test.ts (basic state transitions) with:
 *   - concurrent flood under CLOSED → DEGRADED transition
 *   - HALF_OPEN thundering herd (halfOpenMaxAttempts enforcement)
 *   - OPEN state recovery timing (fast fail, then cooldown to HALF_OPEN)
 *   - semantic failure double-counting (2 failures per 1 semantic failure)
 *   - state-change listener notification correctness
 *   - CLOSED → DEGRADED → CLOSED recovery path
 *   - HALF_OPEN fail-back to OPEN on single failure
 *   - forceState bypass + listener still fires
 *   - metrics immutability from the caller
 */

import { describe, it, expect, vi } from 'vitest';
import {
  CircuitBreaker,
  CircuitBreakerOpenError,
  SemanticFailureError,
} from '../circuit-breaker.js';

const tight = { failureThreshold: 4, degradedThreshold: 2, recoveryTimeout: 50, halfOpenMaxAttempts: 2 };

const fail = async () => { throw new Error('svc error'); };
const success = async () => 'ok';

describe('CircuitBreaker — concurrent flood', () => {
  it('20 concurrent failures end in OPEN state (all invocations complete — state flips as failures land)', async () => {
    const cb = new CircuitBreaker('svc', tight);
    const results = await Promise.allSettled(
      Array.from({ length: 20 }, () => cb.call(fail)),
    );
    // All rejected (every call fails)
    expect(results.every(r => r.status === 'rejected')).toBe(true);

    // The key assertion: final state is OPEN once the failure threshold is crossed.
    // Note: in a pure-parallel flood, canExecute() sees CLOSED/DEGRADED for ALL
    // calls before any failure has been recorded, so none are fast-rejected.
    // The protection is in the state transition itself — subsequent batches
    // will be fast-rejected.
    expect(cb.getState()).toBe('OPEN');

    // Second wave: ALL fast-rejected as CircuitBreakerOpenError
    const wave2 = await Promise.allSettled(
      Array.from({ length: 5 }, () => cb.call(fail)),
    );
    const fastRejected = wave2.filter(
      r => r.status === 'rejected' &&
        (r as PromiseRejectedResult).reason instanceof CircuitBreakerOpenError,
    );
    expect(fastRejected.length).toBe(5);
  });

  it('concurrent successes under DEGRADED promote back to CLOSED', async () => {
    const cb = new CircuitBreaker('svc', tight);
    // Force DEGRADED
    for (let i = 0; i < 2; i++) { try { await cb.call(fail); } catch {} }
    expect(cb.getState()).toBe('DEGRADED');

    // Parallel successes
    await Promise.all(Array.from({ length: tight.degradedThreshold }, () => cb.call(success)));
    expect(cb.getState()).toBe('CLOSED');
  });
});

describe('CircuitBreaker — OPEN → HALF_OPEN cooldown', () => {
  it('fast-fails while OPEN without hitting backend', async () => {
    const cb = new CircuitBreaker('svc', tight);
    cb.forceState('OPEN');
    cb.getMetrics(); // ensure method shape
    // lastFailureTime is 0 → elapsed >= recoveryTimeout → transition
    // To simulate a fresh OPEN, set lastFailureTime via a failure beforehand.
    // Force a lastFailureTime just now by recording a single failure from CLOSED:
    const cb2 = new CircuitBreaker('svc', tight);
    for (let i = 0; i < 6; i++) { try { await cb2.call(fail); } catch {} }
    expect(cb2.getState()).toBe('OPEN');

    // Immediately after: calling should fast-fail
    let hits = 0;
    await expect(cb2.call(async () => { hits++; return 'should-not-run'; }))
      .rejects.toThrow(CircuitBreakerOpenError);
    expect(hits).toBe(0);
  });

  it('after recoveryTimeout, transitions OPEN → HALF_OPEN on the next call', async () => {
    const cb = new CircuitBreaker('svc', tight);
    for (let i = 0; i < 6; i++) { try { await cb.call(fail); } catch {} }
    expect(cb.getState()).toBe('OPEN');

    // Wait past recoveryTimeout
    await new Promise(r => setTimeout(r, tight.recoveryTimeout + 10));

    // A success call now enters HALF_OPEN → executes → records success
    const result = await cb.call(success);
    expect(result).toBe('ok');
    // HALF_OPEN needs 2 consecutive successes to close; we've done 1
    expect(cb.getState()).toBe('HALF_OPEN');
  });
});

describe('CircuitBreaker — HALF_OPEN semantics', () => {
  it('halfOpenMaxAttempts is enforced against thundering herd', async () => {
    const cb = new CircuitBreaker('svc', tight);
    cb.forceState('HALF_OPEN');

    // Slow tasks so they concurrently occupy the half-open budget
    const slow = () => new Promise<string>(r => setTimeout(() => r('ok'), 80));
    const attempts = Array.from({ length: 6 }, () => cb.call(slow));
    const settled = await Promise.allSettled(attempts);

    const successes = settled.filter(r => r.status === 'fulfilled');
    const rejections = settled.filter(
      r => r.status === 'rejected' &&
        (r as PromiseRejectedResult).reason instanceof CircuitBreakerOpenError,
    );
    // Budget bound the concurrent successes
    expect(successes.length + rejections.length).toBe(6);
    expect(rejections.length).toBeGreaterThanOrEqual(1);
  });

  it('single failure in HALF_OPEN sends us straight back to OPEN', async () => {
    const cb = new CircuitBreaker('svc', tight);
    cb.forceState('HALF_OPEN');
    try { await cb.call(fail); } catch {}
    expect(cb.getState()).toBe('OPEN');
  });

  it('2 consecutive successes in HALF_OPEN close the circuit', async () => {
    const cb = new CircuitBreaker('svc', tight);
    cb.forceState('HALF_OPEN');
    await cb.call(success);
    await cb.call(success);
    expect(cb.getState()).toBe('CLOSED');
  });
});

describe('CircuitBreaker — semantic failures', () => {
  const validator = (result: string) => result !== 'hallucination';

  it('semantic failure throws SemanticFailureError and counts DOUBLE', async () => {
    const cb = new CircuitBreaker('svc', {
      failureThreshold: 4, degradedThreshold: 2, recoveryTimeout: 50, halfOpenMaxAttempts: 2,
    });

    // One semantic failure = 2 regular failures → 2 ≥ degradedThreshold → DEGRADED
    await expect(
      cb.call(async () => 'hallucination', validator),
    ).rejects.toThrow(SemanticFailureError);

    expect(cb.getState()).toBe('DEGRADED');
    const metrics = cb.getMetrics();
    expect(metrics.semanticFailures).toBe(1);
    // Internal failure counter was bumped twice
    expect(metrics.failures).toBe(2);
  });

  it('two semantic failures take the breaker straight to OPEN', async () => {
    const cb = new CircuitBreaker('svc', tight);
    for (let i = 0; i < 2; i++) {
      await expect(
        cb.call(async () => 'hallucination', validator),
      ).rejects.toThrow(SemanticFailureError);
    }
    // 2 semantic × 2 counts = 4 failures ≥ failureThreshold
    expect(cb.getState()).toBe('OPEN');
  });
});

describe('CircuitBreaker — listeners & metrics', () => {
  it('listener fires for each distinct transition (no duplicate for same-state)', () => {
    const cb = new CircuitBreaker('svc', tight);
    const events: Array<[string, string]> = [];
    cb.onStateChange((from, to) => events.push([from, to]));

    cb.forceState('OPEN');
    cb.forceState('OPEN');              // same state → no event
    cb.forceState('HALF_OPEN');
    cb.forceState('CLOSED');

    expect(events).toEqual([
      ['CLOSED', 'OPEN'],
      ['OPEN', 'HALF_OPEN'],
      ['HALF_OPEN', 'CLOSED'],
    ]);
  });

  it('multiple listeners all receive transitions', () => {
    const cb = new CircuitBreaker('svc', tight);
    const a = vi.fn(), b = vi.fn();
    cb.onStateChange(a);
    cb.onStateChange(b);
    cb.forceState('OPEN');
    expect(a).toHaveBeenCalledWith('CLOSED', 'OPEN');
    expect(b).toHaveBeenCalledWith('CLOSED', 'OPEN');
  });

  it('getMetrics returns a snapshot (mutations do not persist)', async () => {
    const cb = new CircuitBreaker('svc', tight);
    await cb.call(success);
    const snapshot = cb.getMetrics();
    snapshot.successes = 999;
    snapshot.failures = 999;
    const after = cb.getMetrics();
    expect(after.successes).toBe(1);
    expect(after.failures).toBe(0);
  });

  it('targetId is accessible', () => {
    const cb = new CircuitBreaker('my-service', tight);
    expect(cb.getTargetId()).toBe('my-service');
  });
});

describe('CircuitBreaker — state-machine sanity', () => {
  it('CLOSED is the starting state regardless of config', () => {
    expect(new CircuitBreaker('s').getState()).toBe('CLOSED');
    expect(new CircuitBreaker('s', tight).getState()).toBe('CLOSED');
  });

  it('consecutive counter resets on state flip (failure-then-success sequence)', async () => {
    const cb = new CircuitBreaker('svc', tight);
    try { await cb.call(fail); } catch {}
    expect(cb.getMetrics().consecutiveFailures).toBe(1);
    await cb.call(success);
    expect(cb.getMetrics().consecutiveFailures).toBe(0);
    expect(cb.getMetrics().consecutiveSuccesses).toBe(1);
  });

  it('metrics totalCalls includes both successes and failures', async () => {
    const cb = new CircuitBreaker('svc', tight);
    await cb.call(success);
    try { await cb.call(fail); } catch {}
    await cb.call(success);
    expect(cb.getMetrics().totalCalls).toBe(3);
    expect(cb.getMetrics().successes).toBe(2);
    expect(cb.getMetrics().failures).toBe(1);
  });
});
