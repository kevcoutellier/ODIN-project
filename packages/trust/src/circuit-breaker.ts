/**
 * Circuit Breaker — 5-state protection for agent interactions
 *
 * Innovation over classic 3-state circuit breakers:
 * CLOSED → DEGRADED → OPEN → HALF_OPEN → CLOSED
 *
 * The DEGRADED state (Odin innovation) allows partial functionality
 * instead of the binary CLOSED/OPEN of traditional patterns.
 * Also detects semantic failures (hallucinations with 200 status).
 */

import type { CircuitBreakerState, CircuitBreakerConfig } from '@odin/core';

export interface CircuitBreakerMetrics {
  totalCalls: number;
  failures: number;
  successes: number;
  semanticFailures: number;
  lastFailureTime: number;
  lastSuccessTime: number;
  consecutiveFailures: number;
  consecutiveSuccesses: number;
}

export class CircuitBreaker {
  private state: CircuitBreakerState = 'CLOSED';
  private metrics: CircuitBreakerMetrics = {
    totalCalls: 0,
    failures: 0,
    successes: 0,
    semanticFailures: 0,
    lastFailureTime: 0,
    lastSuccessTime: 0,
    consecutiveFailures: 0,
    consecutiveSuccesses: 0,
  };
  private halfOpenAttempts = 0;
  private stateChangeListeners: Array<(from: CircuitBreakerState, to: CircuitBreakerState) => void> = [];

  constructor(
    private targetId: string,
    private config: CircuitBreakerConfig = {
      failureThreshold: 5,
      degradedThreshold: 3,
      recoveryTimeout: 30000,
      halfOpenMaxAttempts: 3,
    },
  ) {}

  /**
   * Execute a call through the circuit breaker.
   */
  async call<T>(fn: () => Promise<T>, semanticValidator?: (result: T) => boolean): Promise<T> {
    if (!this.canExecute()) {
      throw new CircuitBreakerOpenError(this.targetId, this.state);
    }

    this.metrics.totalCalls++;

    try {
      const result = await fn();

      // Check for semantic failures (e.g., hallucination with 200 status)
      if (semanticValidator && !semanticValidator(result)) {
        this.recordSemanticFailure();
        throw new SemanticFailureError(this.targetId, 'Semantic validation failed');
      }

      this.recordSuccess();
      return result;
    } catch (error) {
      if (error instanceof SemanticFailureError) throw error;
      this.recordFailure();
      throw error;
    }
  }

  getState(): CircuitBreakerState {
    return this.state;
  }

  getMetrics(): CircuitBreakerMetrics {
    return { ...this.metrics };
  }

  getTargetId(): string {
    return this.targetId;
  }

  onStateChange(listener: (from: CircuitBreakerState, to: CircuitBreakerState) => void): void {
    this.stateChangeListeners.push(listener);
  }

  /**
   * Force a state transition (for testing or manual intervention).
   */
  forceState(newState: CircuitBreakerState): void {
    this.transition(newState);
  }

  private canExecute(): boolean {
    switch (this.state) {
      case 'CLOSED':
      case 'DEGRADED':
        return true;
      case 'HALF_OPEN':
        return this.halfOpenAttempts < this.config.halfOpenMaxAttempts;
      case 'OPEN': {
        const elapsed = Date.now() - this.metrics.lastFailureTime;
        if (elapsed >= this.config.recoveryTimeout) {
          this.transition('HALF_OPEN');
          this.halfOpenAttempts = 0;
          return true;
        }
        return false;
      }
    }
  }

  private recordSuccess(): void {
    this.metrics.successes++;
    this.metrics.consecutiveSuccesses++;
    this.metrics.consecutiveFailures = 0;
    this.metrics.lastSuccessTime = Date.now();

    switch (this.state) {
      case 'HALF_OPEN':
        if (this.metrics.consecutiveSuccesses >= 2) {
          this.transition('CLOSED');
        }
        break;
      case 'DEGRADED':
        if (this.metrics.consecutiveSuccesses >= this.config.degradedThreshold) {
          this.transition('CLOSED');
        }
        break;
    }
  }

  private recordFailure(): void {
    this.metrics.failures++;
    this.metrics.consecutiveFailures++;
    this.metrics.consecutiveSuccesses = 0;
    this.metrics.lastFailureTime = Date.now();

    switch (this.state) {
      case 'CLOSED':
        if (this.metrics.consecutiveFailures >= this.config.degradedThreshold) {
          this.transition('DEGRADED');
        }
        break;
      case 'DEGRADED':
        if (this.metrics.consecutiveFailures >= this.config.failureThreshold) {
          this.transition('OPEN');
        }
        break;
      case 'HALF_OPEN':
        this.transition('OPEN');
        break;
    }
  }

  private recordSemanticFailure(): void {
    this.metrics.semanticFailures++;
    // Semantic failures count double — they're harder to detect
    this.recordFailure();
    this.recordFailure();
  }

  private transition(newState: CircuitBreakerState): void {
    const oldState = this.state;
    if (oldState === newState) return;
    this.state = newState;
    if (newState === 'HALF_OPEN') this.halfOpenAttempts = 0;
    for (const listener of this.stateChangeListeners) {
      listener(oldState, newState);
    }
  }
}

export class CircuitBreakerOpenError extends Error {
  constructor(targetId: string, state: CircuitBreakerState) {
    super(`Circuit breaker for "${targetId}" is ${state}`);
    this.name = 'CircuitBreakerOpenError';
  }
}

export class SemanticFailureError extends Error {
  constructor(targetId: string, reason: string) {
    super(`Semantic failure for "${targetId}": ${reason}`);
    this.name = 'SemanticFailureError';
  }
}
