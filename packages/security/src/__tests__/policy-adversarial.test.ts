/**
 * Policy Engine adversarial tests — conflict resolution, regex boundaries,
 * condition operator edge cases.
 *
 * Complements policy.test.ts. Focuses on:
 *   - forbid-beats-permit at arbitrary ordering
 *   - custom policy cannot override a built-in forbid
 *   - regex unachored boundaries (the Ring 0 read-only rule)
 *   - condition operators under type coercion and missing fields
 *   - default-deny semantics when all policies removed
 *   - `in` / `contains` corner cases
 */

import { describe, it, expect } from 'vitest';
import { PolicyEngine, type Policy } from '../policy/engine.js';
import { IntegrityLevel, ConfidentialityLevel, type PolicyContext } from '@odin/core';

// ─── Fixture ─────────────────────────────────────────────────────────

const ctx = (overrides: Partial<PolicyContext> = {}): PolicyContext => ({
  agentDid: 'did:odin:test',
  action: 'tool.invoke',
  resource: 'memory_search',
  trustScore: 80,
  sessionTtl: 3600,
  dailyCalls: 0,
  humanApproval: false,
  ring: 1,
  taintLabel: {
    integrity: IntegrityLevel.TRUSTED,
    confidentiality: ConfidentialityLevel.PUBLIC,
    source: 'user',
    timestamp: Date.now(),
  },
  ...overrides,
});

// ─── Conflict resolution ─────────────────────────────────────────────

describe('PolicyEngine — conflict resolution', () => {
  it('forbid beats permit even when permit is added later', () => {
    const engine = new PolicyEngine();
    // Permit first, then forbid
    engine.addPolicy({
      id: 'permit-all', effect: 'permit',
      action: /.*/, resource: /.*/,
    });
    engine.addPolicy({
      id: 'forbid-delete', effect: 'forbid',
      action: /.*/, resource: /^file_delete$/,
    });
    const result = engine.evaluate(ctx({ resource: 'file_delete' }));
    expect(result.allowed).toBe(false);
    expect(result.policy).toBe('forbid-delete');
  });

  it('forbid beats permit when forbid was added FIRST', () => {
    // Order independence — the engine must not depend on insertion order
    const engine = new PolicyEngine();
    engine.addPolicy({
      id: 'forbid-delete', effect: 'forbid',
      action: /.*/, resource: /^file_delete$/,
    });
    engine.addPolicy({
      id: 'permit-all', effect: 'permit',
      action: /.*/, resource: /.*/,
    });
    const result = engine.evaluate(ctx({ resource: 'file_delete' }));
    expect(result.allowed).toBe(false);
    expect(result.policy).toBe('forbid-delete');
  });

  it('custom operator policy cannot override a built-in default forbid', () => {
    // Scenario: an attacker slipping an extra "permit-everything" rule
    // cannot unlock shell_exec without human approval, because the
    // forbid-shell-without-approval rule still matches and wins.
    const engine = new PolicyEngine();
    engine.loadDefaults();
    engine.addPolicy({
      id: 'attacker-permit-all', effect: 'permit',
      action: /.*/, resource: /.*/,
    });
    const result = engine.evaluate(
      ctx({ resource: 'shell_exec', humanApproval: false, trustScore: 90 })
    );
    expect(result.allowed).toBe(false);
    expect(result.policy).toBe('forbid-shell-without-approval');
  });

  it('DEGRADED-mode forbid blocks even when trust-high permit exists', () => {
    const engine = new PolicyEngine();
    engine.loadDefaults();
    const result = engine.evaluate(ctx({ trustScore: 30, resource: 'memory_search' }));
    expect(result.allowed).toBe(false);
    expect(result.policy).toBe('forbid-degraded-mode');
  });

  it('default-deny when all policies removed', () => {
    const engine = new PolicyEngine();
    engine.loadDefaults();
    for (const p of engine.getPolicies()) engine.removePolicy(p.id);
    const result = engine.evaluate(ctx());
    expect(result.allowed).toBe(false);
    expect(result.policy).toBe('default-deny');
  });

  it('removePolicy on unknown id is a silent no-op', () => {
    const engine = new PolicyEngine();
    engine.loadDefaults();
    const before = engine.getPolicies().length;
    expect(() => engine.removePolicy('nonexistent')).not.toThrow();
    expect(engine.getPolicies().length).toBe(before);
  });
});

// ─── Regex boundaries ───────────────────────────────────────────────

describe('PolicyEngine — Ring 0 read-only regex boundaries', () => {
  // The built-in rule is: resource: /^(write|delete|exec|send)/
  // Note the prefix anchor but NO suffix anchor — intentional or not?
  it('blocks "write_file" (prefix match intended)', () => {
    const engine = new PolicyEngine();
    engine.loadDefaults();
    const result = engine.evaluate(ctx({ ring: 0, resource: 'write_file' }));
    expect(result.allowed).toBe(false);
    expect(result.policy).toBe('ring0-readonly');
  });

  it('blocks "delete_all" (prefix match intended)', () => {
    const engine = new PolicyEngine();
    engine.loadDefaults();
    const result = engine.evaluate(ctx({ ring: 0, resource: 'delete_all' }));
    expect(result.allowed).toBe(false);
  });

  it('unanchored suffix: "writer_helper" is unexpectedly blocked (document the over-match)', () => {
    // The regex /^(write|...)/ has no trailing anchor → any resource
    // starting with "write" gets blocked, including "writer_helper".
    // This is overly restrictive — a read-only writer-statistics tool
    // would be denied. Flag as a hardening opportunity.
    const engine = new PolicyEngine();
    engine.loadDefaults();
    const result = engine.evaluate(ctx({ ring: 0, resource: 'writer_helper' }));
    expect(result.allowed).toBe(false);
    expect(result.policy).toBe('ring0-readonly');
  });

  it('"read_file" is NOT caught by the read-only block (ring 0 reads allowed)', () => {
    const engine = new PolicyEngine();
    engine.loadDefaults();
    const result = engine.evaluate(ctx({ ring: 0, resource: 'read_file', trustScore: 80 }));
    // Not blocked by ring0-readonly (no prefix match), permitted by default-tool-permit
    expect(result.allowed).toBe(true);
  });

  it('case sensitivity: "WRITE_FILE" not caught (case-sensitive regex)', () => {
    // Current regex is not case-insensitive → a skill using a capitalised
    // resource name could sneak past. Document the behaviour.
    const engine = new PolicyEngine();
    engine.loadDefaults();
    const result = engine.evaluate(ctx({ ring: 0, resource: 'WRITE_FILE', trustScore: 80 }));
    // ring0-readonly doesn't match → permitted by default-tool-permit
    expect(result.allowed).toBe(true);
  });
});

// ─── Condition operators ────────────────────────────────────────────

describe('PolicyEngine — condition operators', () => {
  it('eq matches exact primitive values', () => {
    const engine = new PolicyEngine();
    engine.addPolicy({
      id: 'permit-ring-2', effect: 'permit',
      action: /.*/, resource: /.*/,
      conditions: [{ field: 'ring', operator: 'eq', value: 2 }],
    });
    expect(engine.evaluate(ctx({ ring: 2 })).allowed).toBe(true);
    expect(engine.evaluate(ctx({ ring: 1 })).allowed).toBe(false);
  });

  it('neq is the inverse of eq', () => {
    const engine = new PolicyEngine();
    engine.addPolicy({
      id: 'permit-not-ring-0', effect: 'permit',
      action: /.*/, resource: /.*/,
      conditions: [{ field: 'ring', operator: 'neq', value: 0 }],
    });
    expect(engine.evaluate(ctx({ ring: 0 })).allowed).toBe(false);
    expect(engine.evaluate(ctx({ ring: 2 })).allowed).toBe(true);
  });

  it('gte matches boundary exactly (trustScore = threshold is allowed)', () => {
    const engine = new PolicyEngine();
    engine.addPolicy({
      id: 'permit-50-plus', effect: 'permit',
      action: /.*/, resource: /.*/,
      conditions: [{ field: 'trustScore', operator: 'gte', value: 50 }],
    });
    expect(engine.evaluate(ctx({ trustScore: 50 })).allowed).toBe(true);
    expect(engine.evaluate(ctx({ trustScore: 49 })).allowed).toBe(false);
  });

  it('gt is strict (threshold exactly is blocked)', () => {
    const engine = new PolicyEngine();
    engine.addPolicy({
      id: 'permit-gt-50', effect: 'permit',
      action: /.*/, resource: /.*/,
      conditions: [{ field: 'trustScore', operator: 'gt', value: 50 }],
    });
    expect(engine.evaluate(ctx({ trustScore: 50 })).allowed).toBe(false);
    expect(engine.evaluate(ctx({ trustScore: 51 })).allowed).toBe(true);
  });

  it('in matches membership in a list', () => {
    const engine = new PolicyEngine();
    engine.addPolicy({
      id: 'permit-known-dids', effect: 'permit',
      action: /.*/, resource: /.*/,
      conditions: [{
        field: 'agentDid', operator: 'in',
        value: ['did:odin:a', 'did:odin:b', 'did:odin:c'],
      }],
    });
    expect(engine.evaluate(ctx({ agentDid: 'did:odin:b' })).allowed).toBe(true);
    expect(engine.evaluate(ctx({ agentDid: 'did:odin:unknown' })).allowed).toBe(false);
  });

  it('contains does substring matching with String() coercion', () => {
    const engine = new PolicyEngine();
    engine.addPolicy({
      id: 'permit-odin-dids', effect: 'permit',
      action: /.*/, resource: /.*/,
      conditions: [{ field: 'agentDid', operator: 'contains', value: 'odin' }],
    });
    expect(engine.evaluate(ctx({ agentDid: 'did:odin:test' })).allowed).toBe(true);
    expect(engine.evaluate(ctx({ agentDid: 'did:alien:test' })).allowed).toBe(false);
  });

  it('unknown operator yields false (safe default — policy does not apply)', () => {
    const engine = new PolicyEngine();
    engine.addPolicy({
      id: 'bad-op', effect: 'permit',
      action: /.*/, resource: /.*/,
      conditions: [{ field: 'trustScore', operator: 'bogus' as any, value: 50 }],
    });
    // Condition never passes → policy never matches → default deny
    const result = engine.evaluate(ctx());
    expect(result.allowed).toBe(false);
    expect(result.policy).toBe('default-deny');
  });

  it('AND semantics: all conditions must pass', () => {
    const engine = new PolicyEngine();
    engine.addPolicy({
      id: 'multi-cond', effect: 'permit',
      action: /.*/, resource: /.*/,
      conditions: [
        { field: 'trustScore', operator: 'gte', value: 50 },
        { field: 'ring', operator: 'lte', value: 1 },
        { field: 'humanApproval', operator: 'eq', value: true },
      ],
    });
    // All three satisfied
    expect(engine.evaluate(ctx({ trustScore: 80, ring: 1, humanApproval: true })).allowed).toBe(true);
    // One false
    expect(engine.evaluate(ctx({ trustScore: 80, ring: 2, humanApproval: true })).allowed).toBe(false);
    // Another false
    expect(engine.evaluate(ctx({ trustScore: 30, ring: 1, humanApproval: true })).allowed).toBe(false);
  });

  it('empty conditions array → policy always matches (no gating)', () => {
    const engine = new PolicyEngine();
    engine.addPolicy({
      id: 'always-permit', effect: 'permit',
      action: /.*/, resource: /.*/,
      conditions: [],
    });
    expect(engine.evaluate(ctx()).allowed).toBe(true);
  });
});

// ─── Principal matching ─────────────────────────────────────────────

describe('PolicyEngine — principal scoping', () => {
  it('policy without principal applies to all DIDs', () => {
    const engine = new PolicyEngine();
    engine.addPolicy({
      id: 'permit-all-principals', effect: 'permit',
      action: /.*/, resource: /.*/,
    });
    expect(engine.evaluate(ctx({ agentDid: 'did:anything' })).allowed).toBe(true);
  });

  it('policy with string principal matches exactly', () => {
    const engine = new PolicyEngine();
    engine.addPolicy({
      id: 'permit-alice', effect: 'permit',
      principal: 'did:odin:alice',
      action: /.*/, resource: /.*/,
    });
    expect(engine.evaluate(ctx({ agentDid: 'did:odin:alice' })).allowed).toBe(true);
    expect(engine.evaluate(ctx({ agentDid: 'did:odin:bob' })).allowed).toBe(false);
  });

  it('policy with regex principal matches a family of DIDs', () => {
    const engine = new PolicyEngine();
    engine.addPolicy({
      id: 'permit-odin-family', effect: 'permit',
      principal: /^did:odin:/,
      action: /.*/, resource: /.*/,
    });
    expect(engine.evaluate(ctx({ agentDid: 'did:odin:alice' })).allowed).toBe(true);
    expect(engine.evaluate(ctx({ agentDid: 'did:ethr:alice' })).allowed).toBe(false);
  });
});

// ─── Decision metadata ──────────────────────────────────────────────

describe('PolicyEngine — decision metadata', () => {
  it('evaluationTimeMs is populated and non-negative', () => {
    const engine = new PolicyEngine();
    engine.loadDefaults();
    const result = engine.evaluate(ctx());
    expect(result.evaluationTimeMs).toBeGreaterThanOrEqual(0);
    expect(result.evaluationTimeMs).toBeLessThan(50); // generous upper bound
  });

  it('context snapshot contains the observable fields', () => {
    const engine = new PolicyEngine();
    engine.loadDefaults();
    const result = engine.evaluate(ctx({ agentDid: 'did:odin:test-id', ring: 2 }));
    expect(result.conditions).toMatchObject({
      agentDid: 'did:odin:test-id',
      ring: 2,
      humanApproval: false,
    });
  });
});
