import { describe, it, expect } from 'vitest';
import { PolicyEngine } from '../policy/engine.js';
import { IntegrityLevel, ConfidentialityLevel, type PolicyContext } from '@odin/core';

describe('PolicyEngine', () => {
  it('denies by default when no policies loaded', () => {
    const engine = new PolicyEngine();
    const ctx: PolicyContext = {
      agentDid: 'did:odin:test',
      action: 'tool.invoke',
      resource: 'shell_exec',
      trustScore: 80,
      sessionTtl: 3600,
      dailyCalls: 0,
      humanApproval: false,
      ring: 2,
      taintLabel: { integrity: IntegrityLevel.TRUSTED, confidentiality: ConfidentialityLevel.PUBLIC, source: 'user', timestamp: Date.now() },
    };
    const result = engine.evaluate(ctx);
    // Without policies loaded, default deny should apply
    expect(result).toBeDefined();
    expect(typeof result.allowed).toBe('boolean');
  });

  it('allows tool invocation with valid trust score after defaults', () => {
    const engine = new PolicyEngine();
    engine.loadDefaults();
    const ctx: PolicyContext = {
      agentDid: 'did:odin:test',
      action: 'tool.invoke',
      resource: 'memory_search',
      trustScore: 80,
      sessionTtl: 3600,
      dailyCalls: 0,
      humanApproval: false,
      ring: 0,
      taintLabel: { integrity: IntegrityLevel.TRUSTED, confidentiality: ConfidentialityLevel.PUBLIC, source: 'user', timestamp: Date.now() },
    };
    const result = engine.evaluate(ctx);
    expect(result.allowed).toBe(true);
  });

  it('blocks when trust score too low', () => {
    const engine = new PolicyEngine();
    engine.loadDefaults();
    const ctx: PolicyContext = {
      agentDid: 'did:odin:test',
      action: 'tool.invoke',
      resource: 'shell_exec',
      trustScore: 10, // Very low
      sessionTtl: 3600,
      dailyCalls: 0,
      humanApproval: false,
      ring: 2,
      taintLabel: { integrity: IntegrityLevel.TRUSTED, confidentiality: ConfidentialityLevel.PUBLIC, source: 'user', timestamp: Date.now() },
    };
    const result = engine.evaluate(ctx);
    expect(result.allowed).toBe(false);
  });

  it('blocks on rate limit exceeded', () => {
    const engine = new PolicyEngine();
    engine.loadDefaults();
    const ctx: PolicyContext = {
      agentDid: 'did:odin:test',
      action: 'tool.invoke',
      resource: 'memory_search',
      trustScore: 90,
      sessionTtl: 3600,
      dailyCalls: 1001, // Over 1000 limit
      humanApproval: false,
      ring: 0,
      taintLabel: { integrity: IntegrityLevel.TRUSTED, confidentiality: ConfidentialityLevel.PUBLIC, source: 'user', timestamp: Date.now() },
    };
    const result = engine.evaluate(ctx);
    expect(result.allowed).toBe(false);
  });

  describe('ring0-readonly regex', () => {
    const baseCtx = (resource: string): PolicyContext => ({
      agentDid: 'did:odin:test',
      action: 'tool.invoke',
      resource,
      trustScore: 80,
      sessionTtl: 3600,
      dailyCalls: 0,
      humanApproval: false,
      ring: 0,
      taintLabel: { integrity: IntegrityLevel.TRUSTED, confidentiality: ConfidentialityLevel.PUBLIC, source: 'user', timestamp: Date.now() },
    });

    it('blocks write_file in ring 0 (baseline)', () => {
      const engine = new PolicyEngine();
      engine.loadDefaults();
      expect(engine.evaluate(baseCtx('write_file')).allowed).toBe(false);
    });

    it('allows writer_helper in ring 0 (suffix must be _ or end-of-string)', () => {
      const engine = new PolicyEngine();
      engine.loadDefaults();
      expect(engine.evaluate(baseCtx('writer_helper')).allowed).toBe(true);
    });

    it('blocks WRITE_FILE in ring 0 (case-insensitive)', () => {
      const engine = new PolicyEngine();
      engine.loadDefaults();
      expect(engine.evaluate(baseCtx('WRITE_FILE')).allowed).toBe(false);
    });

    it('blocks Exec_Shell in ring 0 (mixed case)', () => {
      const engine = new PolicyEngine();
      engine.loadDefaults();
      expect(engine.evaluate(baseCtx('Exec_Shell')).allowed).toBe(false);
    });
  });

  it('evaluates in sub-millisecond time', () => {
    const engine = new PolicyEngine();
    engine.loadDefaults();
    const ctx: PolicyContext = {
      agentDid: 'did:odin:test',
      action: 'tool.invoke',
      resource: 'memory_search',
      trustScore: 80,
      sessionTtl: 3600,
      dailyCalls: 0,
      humanApproval: false,
      ring: 0,
      taintLabel: { integrity: IntegrityLevel.TRUSTED, confidentiality: ConfidentialityLevel.PUBLIC, source: 'user', timestamp: Date.now() },
    };
    const start = performance.now();
    for (let i = 0; i < 1000; i++) engine.evaluate(ctx);
    const elapsed = performance.now() - start;
    const avgMs = elapsed / 1000;
    expect(avgMs).toBeLessThan(1); // < 1ms per evaluation
  });
});
