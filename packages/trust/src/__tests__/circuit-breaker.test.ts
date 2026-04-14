import { describe, it, expect } from 'vitest';
import { CircuitBreaker } from '../circuit-breaker.js';

describe('CircuitBreaker', () => {
  it('starts in CLOSED state', () => {
    const cb = new CircuitBreaker('test-service');
    expect(cb.getState()).toBe('CLOSED');
  });

  it('stays CLOSED on success', async () => {
    const cb = new CircuitBreaker('test', { failureThreshold: 3, degradedThreshold: 2, recoveryTimeout: 1000, halfOpenMaxAttempts: 3 });
    await cb.call(async () => 'ok');
    await cb.call(async () => 'ok');
    expect(cb.getState()).toBe('CLOSED');
  });

  it('transitions to DEGRADED on threshold', async () => {
    const cb = new CircuitBreaker('test', { degradedThreshold: 2, failureThreshold: 5, recoveryTimeout: 1000, halfOpenMaxAttempts: 3 });
    try { await cb.call(async () => { throw new Error('fail'); }); } catch {}
    try { await cb.call(async () => { throw new Error('fail'); }); } catch {}
    expect(cb.getState()).toBe('DEGRADED');
  });

  it('transitions to OPEN on failure threshold', async () => {
    const cb = new CircuitBreaker('test', { failureThreshold: 3, degradedThreshold: 2, recoveryTimeout: 1000, halfOpenMaxAttempts: 3 });
    try { await cb.call(async () => { throw new Error('fail'); }); } catch {}
    try { await cb.call(async () => { throw new Error('fail'); }); } catch {}
    try { await cb.call(async () => { throw new Error('fail'); }); } catch {}
    expect(cb.getState()).toBe('OPEN');
  });

  it('detects semantic failures', async () => {
    const cb = new CircuitBreaker('test', { failureThreshold: 10, degradedThreshold: 5, recoveryTimeout: 1000, halfOpenMaxAttempts: 3 });
    try {
      await cb.call(async () => 'hallucinated', (result) => false);
    } catch {}
    const metrics = cb.getMetrics();
    expect(metrics.semanticFailures).toBe(1);
  });

  it('notifies state change listeners', async () => {
    const cb = new CircuitBreaker('test', { failureThreshold: 2, degradedThreshold: 1, recoveryTimeout: 1000, halfOpenMaxAttempts: 3 });
    const states: string[] = [];
    cb.onStateChange((_from, to) => { states.push(to); });
    try { await cb.call(async () => { throw new Error('fail'); }); } catch {}
    expect(states).toContain('DEGRADED');
    try { await cb.call(async () => { throw new Error('fail'); }); } catch {}
    expect(states).toContain('OPEN');
  });

  it('provides accurate metrics', async () => {
    const cb = new CircuitBreaker('test', { failureThreshold: 5, degradedThreshold: 3, recoveryTimeout: 1000, halfOpenMaxAttempts: 3 });
    await cb.call(async () => 'ok');
    await cb.call(async () => 'ok');
    try { await cb.call(async () => { throw new Error('fail'); }); } catch {}
    const m = cb.getMetrics();
    expect(m.totalCalls).toBe(3);
    expect(m.successes).toBe(2);
    expect(m.failures).toBe(1);
  });

  it('allows calls in CLOSED and DEGRADED', async () => {
    const cb = new CircuitBreaker('test', { degradedThreshold: 2, failureThreshold: 5, recoveryTimeout: 1000, halfOpenMaxAttempts: 3 });
    // CLOSED — call should work
    const r1 = await cb.call(async () => 'ok');
    expect(r1).toBe('ok');
    // Push to DEGRADED
    try { await cb.call(async () => { throw new Error('fail'); }); } catch {}
    try { await cb.call(async () => { throw new Error('fail'); }); } catch {}
    expect(cb.getState()).toBe('DEGRADED');
    // DEGRADED — call should still work
    const r2 = await cb.call(async () => 'still ok');
    expect(r2).toBe('still ok');
  });

  it('blocks calls in OPEN state', async () => {
    const cb = new CircuitBreaker('test', { failureThreshold: 2, degradedThreshold: 1, recoveryTimeout: 60000, halfOpenMaxAttempts: 3 });
    try { await cb.call(async () => { throw new Error('fail'); }); } catch {}
    try { await cb.call(async () => { throw new Error('fail'); }); } catch {}
    expect(cb.getState()).toBe('OPEN');
    // OPEN — call should throw CircuitBreakerOpenError
    await expect(cb.call(async () => 'blocked')).rejects.toThrow('Circuit breaker');
  });
});
