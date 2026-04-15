import { describe, it, expect } from 'vitest';
import type { SkillManifest } from '@odin/core';
import { SkillGate } from '../skill-gate.js';
import { AgentLayersClient } from '../agentlayers-client.js';

// Local-only client: no API key → isAvailable() returns false, scanSkill() returns null
const localOnlyClient = new AgentLayersClient({ baseUrl: 'https://example.invalid' });

function makeManifest(overrides: Partial<SkillManifest> = {}): SkillManifest {
  return {
    name: 'test-skill',
    version: '0.1.0',
    description: 'A test skill',
    author: 'test',
    tools: [],
    trustTier: 0,
    ...overrides,
  };
}

describe('SkillGate — local-only mode (no AgentLayers)', () => {
  it('installs unsigned skills at Tier 0 / Ring 0', async () => {
    const gate = new SkillGate(localOnlyClient);
    const decision = await gate.verify(makeManifest());

    expect(decision.allowed).toBe(true);
    expect(decision.trustTier).toBe(0);
    expect(decision.ring).toBe(0);
    expect(decision.agentLayersScan).toBeNull();
  });

  it('installs signed skills at Tier 1 / Ring 1', async () => {
    const gate = new SkillGate(localOnlyClient);
    const decision = await gate.verify(makeManifest({ signature: 'ed25519:abc123' }));

    expect(decision.allowed).toBe(true);
    expect(decision.trustTier).toBe(1);
    expect(decision.ring).toBe(1);
  });

  it('treats signature-present as informational (passed=true when unsigned)', async () => {
    const gate = new SkillGate(localOnlyClient);
    const decision = await gate.verify(makeManifest());
    const sigCheck = decision.localChecks.find(c => c.check === 'signature-present');

    expect(sigCheck).toBeDefined();
    expect(sigCheck!.passed).toBe(true);
    expect(sigCheck!.details).toMatch(/Tier 0/);
  });

  it('blocks skills with invalid manifest (CRITICAL check)', async () => {
    const gate = new SkillGate(localOnlyClient);
    const decision = await gate.verify(makeManifest({ name: '' }));

    expect(decision.allowed).toBe(false);
    expect(decision.reason).toMatch(/Blocked by local checks/);
  });

  it('blocks skills with dangerous permissions', async () => {
    const gate = new SkillGate(localOnlyClient);
    const decision = await gate.verify(
      makeManifest({
        tools: [
          {
            name: 'danger',
            description: 'dangerous tool',
            parameters: {},
            ring: 0,
            requiredPermissions: ['shell'],
          },
        ],
      }),
    );

    expect(decision.allowed).toBe(false);
  });

  it('blocks source code with injection patterns (CRITICAL check)', async () => {
    const gate = new SkillGate(localOnlyClient);
    const decision = await gate.verify(makeManifest(), 'const x = eval("1+1");');

    expect(decision.allowed).toBe(false);
    expect(decision.reason).toMatch(/Blocked by local checks/);
  });

  it('allows safe source code for unsigned skills (still Tier 0)', async () => {
    const gate = new SkillGate(localOnlyClient);
    const decision = await gate.verify(makeManifest(), 'export function hello() { return 1; }');

    expect(decision.allowed).toBe(true);
    expect(decision.trustTier).toBe(0);
  });
});
