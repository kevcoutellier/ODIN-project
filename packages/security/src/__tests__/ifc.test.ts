import { describe, it, expect } from 'vitest';
import { IFCEngine } from '../ifc/engine.js';
import { IntegrityLevel, ConfidentialityLevel } from '@odin/core';

describe('IFCEngine', () => {
  it('creates trusted labels', () => {
    const engine = new IFCEngine();
    const label = engine.createTrustedLabel('user:direct');
    expect(label.integrity).toBe('TRUSTED');
    expect(label.confidentiality).toBe('PUBLIC');
    expect(label.source).toBe('user:direct');
  });

  it('creates untrusted labels', () => {
    const engine = new IFCEngine();
    const label = engine.createUntrustedLabel('external:api');
    expect(label.integrity).toBe('UNTRUSTED');
  });

  it('propagates taint — output inherits lowest integrity', () => {
    const engine = new IFCEngine();
    const trusted = engine.createTrustedLabel('user');
    const untrusted = engine.createUntrustedLabel('web');
    const combined = engine.propagate([trusted, untrusted], 'combined');
    expect(combined.integrity).toBe('UNTRUSTED');
  });

  it('propagates taint — output inherits highest confidentiality', () => {
    const engine = new IFCEngine();
    const pub = engine.createTrustedLabel('user');
    const secret = { ...pub, confidentiality: ConfidentialityLevel.SECRET };
    const combined = engine.propagate([pub, secret], 'combined');
    expect(combined.confidentiality).toBe('SECRET');
  });

  it('validates tool calls — trusted input passes', () => {
    const engine = new IFCEngine();
    const trusted = engine.createTrustedLabel('user');
    const result = engine.validateToolCall(trusted, IntegrityLevel.TRUSTED, 'shell_exec');
    expect(result.allowed).toBe(true);
  });

  it('validates tool calls — untrusted blocked for TRUSTED requirement', () => {
    const engine = new IFCEngine();
    const untrusted = engine.createUntrustedLabel('external');
    const result = engine.validateToolCall(untrusted, IntegrityLevel.TRUSTED, 'shell_exec');
    expect(result.allowed).toBe(false);
  });

  it('records violations', () => {
    const engine = new IFCEngine();
    const untrusted = engine.createUntrustedLabel('external');
    engine.validateToolCall(untrusted, IntegrityLevel.TRUSTED, 'dangerous_tool');
    const violations = engine.getViolations();
    expect(violations.length).toBeGreaterThanOrEqual(1);
  });

  it('caps violations at 1000', () => {
    const engine = new IFCEngine();
    const untrusted = engine.createUntrustedLabel('x');
    for (let i = 0; i < 1100; i++) {
      engine.validateToolCall(untrusted, IntegrityLevel.TRUSTED, `tool_${i}`);
    }
    expect(engine.getViolations().length).toBeLessThanOrEqual(1000);
  });
});
