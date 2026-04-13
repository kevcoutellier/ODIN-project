/**
 * Policy Engine — Cedar-inspired deterministic policy evaluation
 *
 * In production, this integrates with AWS Cedar (Rust bindings).
 * For the PoC, we implement a compatible subset in TypeScript
 * that evaluates policies with the same semantics:
 * - permit/forbid rules
 * - principal/action/resource matching
 * - condition evaluation (when/unless)
 * - <0.1ms p99 evaluation time target
 */

import type { PolicyDecision, PolicyContext, SandboxRing } from '@odin/core';

export interface Policy {
  id: string;
  effect: 'permit' | 'forbid';
  principal?: string | RegExp;
  action: string | RegExp;
  resource: string | RegExp;
  conditions?: PolicyCondition[];
  description?: string;
}

export interface PolicyCondition {
  field: keyof PolicyContext;
  operator: 'eq' | 'neq' | 'gte' | 'lte' | 'gt' | 'lt' | 'in' | 'contains';
  value: unknown;
}

export class PolicyEngine {
  private policies: Policy[] = [];

  /**
   * Load default Zero Trust policies for Odin.
   */
  loadDefaults(): void {
    this.policies = [
      // Allow tool invocation if trust score is sufficient
      {
        id: 'default-tool-permit',
        effect: 'permit',
        action: /^tool\.invoke$/,
        resource: /.*/,
        conditions: [
          { field: 'trustScore', operator: 'gte', value: 50 },
          { field: 'sessionTtl', operator: 'gt', value: 0 },
        ],
        description: 'Allow tool invocation with minimum trust score',
      },

      // Forbid shell execution without human approval
      {
        id: 'forbid-shell-without-approval',
        effect: 'forbid',
        action: /^tool\.invoke$/,
        resource: /^(shell_exec|code_exec|system)$/,
        conditions: [
          { field: 'humanApproval', operator: 'eq', value: false },
        ],
        description: 'Block shell execution without human approval',
      },

      // Forbid actions when in DEGRADED mode (trust < 50)
      {
        id: 'forbid-degraded-mode',
        effect: 'forbid',
        action: /.*/,
        resource: /.*/,
        conditions: [
          { field: 'trustScore', operator: 'lt', value: 50 },
        ],
        description: 'Block all actions in DEGRADED trust mode',
      },

      // Rate limiting
      {
        id: 'rate-limit',
        effect: 'forbid',
        action: /^tool\.invoke$/,
        resource: /.*/,
        conditions: [
          { field: 'dailyCalls', operator: 'gte', value: 1000 },
        ],
        description: 'Rate limit: max 1000 tool calls per day',
      },

      // Ring 0 skills can only read
      {
        id: 'ring0-readonly',
        effect: 'forbid',
        action: /^tool\.invoke$/,
        resource: /^(write|delete|exec|send)/,
        conditions: [
          { field: 'ring', operator: 'eq', value: 0 },
        ],
        description: 'Ring 0 skills are read-only',
      },
    ];
  }

  addPolicy(policy: Policy): void {
    this.policies.push(policy);
  }

  removePolicy(policyId: string): void {
    this.policies = this.policies.filter(p => p.id !== policyId);
  }

  /**
   * Evaluate all policies against a context.
   * Forbid takes precedence over permit (deny-by-default).
   */
  evaluate(context: PolicyContext): PolicyDecision {
    const startTime = performance.now();

    // Collect matching policies
    const matchingForbids: Policy[] = [];
    const matchingPermits: Policy[] = [];

    for (const policy of this.policies) {
      if (!this.matchesAction(policy, context.action)) continue;
      if (!this.matchesResource(policy, context.resource)) continue;
      if (policy.principal && !this.matchesPrincipal(policy, context.agentDid)) continue;
      if (!this.evaluateConditions(policy.conditions ?? [], context)) continue;

      if (policy.effect === 'forbid') {
        matchingForbids.push(policy);
      } else {
        matchingPermits.push(policy);
      }
    }

    const evaluationTimeMs = performance.now() - startTime;

    // Forbid takes precedence
    if (matchingForbids.length > 0) {
      return {
        allowed: false,
        reason: matchingForbids[0].description ?? `Denied by policy ${matchingForbids[0].id}`,
        policy: matchingForbids[0].id,
        evaluationTimeMs,
        conditions: this.extractContextSnapshot(context),
      };
    }

    // At least one permit must match (deny-by-default)
    if (matchingPermits.length > 0) {
      return {
        allowed: true,
        reason: matchingPermits[0].description ?? `Allowed by policy ${matchingPermits[0].id}`,
        policy: matchingPermits[0].id,
        evaluationTimeMs,
        conditions: this.extractContextSnapshot(context),
      };
    }

    // Default deny
    return {
      allowed: false,
      reason: 'No matching permit policy (deny-by-default)',
      policy: 'default-deny',
      evaluationTimeMs,
      conditions: this.extractContextSnapshot(context),
    };
  }

  getPolicies(): Policy[] {
    return [...this.policies];
  }

  private matchesAction(policy: Policy, action: string): boolean {
    if (policy.action instanceof RegExp) return policy.action.test(action);
    return policy.action === action;
  }

  private matchesResource(policy: Policy, resource: string): boolean {
    if (policy.resource instanceof RegExp) return policy.resource.test(resource);
    return policy.resource === resource;
  }

  private matchesPrincipal(policy: Policy, principal: string): boolean {
    if (!policy.principal) return true;
    if (policy.principal instanceof RegExp) return policy.principal.test(principal);
    return policy.principal === principal;
  }

  private evaluateConditions(conditions: PolicyCondition[], context: PolicyContext): boolean {
    return conditions.every(cond => this.evaluateCondition(cond, context));
  }

  private evaluateCondition(cond: PolicyCondition, context: PolicyContext): boolean {
    const actual = context[cond.field];

    switch (cond.operator) {
      case 'eq': return actual === cond.value;
      case 'neq': return actual !== cond.value;
      case 'gte': return (actual as number) >= (cond.value as number);
      case 'lte': return (actual as number) <= (cond.value as number);
      case 'gt': return (actual as number) > (cond.value as number);
      case 'lt': return (actual as number) < (cond.value as number);
      case 'in': return (cond.value as unknown[]).includes(actual);
      case 'contains': return String(actual).includes(String(cond.value));
      default: return false;
    }
  }

  private extractContextSnapshot(context: PolicyContext): Record<string, unknown> {
    return {
      agentDid: context.agentDid,
      trustScore: context.trustScore,
      ring: context.ring,
      humanApproval: context.humanApproval,
    };
  }
}
