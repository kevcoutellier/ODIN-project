/**
 * OdinAgent smoke tests.
 *
 * The agent is a heavy orchestrator (DID, memory, IFC, policy, sandbox,
 * trust, observability, dashboard, cognition, A2A, gateway). Full
 * behavioural coverage is handled by each subsystem's own tests.
 * Here we verify:
 *   - the constructor wires config-only accessors correctly
 *   - a full init/close lifecycle doesn't throw or leak handles
 *   - chat() through the NullAdapter returns the configure-me notice
 *   - post-init accessors (DID, trust mode, audit report) are populated
 *
 * Ports are picked from a high range to minimise collision risk when
 * test files run in parallel. Each test uses a unique base port.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { OdinAgent } from '../agent.js';
import type { OdinConfig } from '@odin/core';

// Each test file gets its own port range to avoid cross-file collisions.
// The cli/a2a/server test family uses 0 (OS-assigned); we use 24000+ here.
let portCounter = 24000 + Math.floor(Math.random() * 1000);
const nextPort = () => {
  const p = portCounter;
  portCounter += 2; // reserve p and p+1 (A2A uses dashboardPort + 1)
  return p;
};

const makeConfig = (tmpDir: string, port: number): OdinConfig => ({
  agent: { name: 'OdinTest', description: 'test agent' },
  llm: {
    privileged: { provider: 'none', model: 'none', maxTokens: 1024, temperature: 0.7 },
    quarantined: { provider: 'none', model: 'none', maxTokens: 1024, temperature: 0.3 },
  },
  memory: { dbPath: join(tmpDir, 'memory.db'), maxEntries: 100 },
  security: {
    defaultRing: 0,
    requireHumanApproval: [],
    maxDailyCalls: 1000,
    sessionTtlSeconds: 3600,
  },
  trust: {
    agentLayersBaseUrl: 'https://api.agent-layers.com',
    selfAuditIntervalSeconds: 600,
    trustDecayHalfLifeDays: 7,
  },
  gateway: { type: 'cli' },
  terminal: { backend: 'local' },
  cron: { jobs: [] },
  observability: {
    auditLogPath: join(tmpDir, 'audit.log'),
    dashboardPort: port,
  },
  heartbeat: { enabled: false, intervalMs: 3600000 },
});

// Silence noisy console output from agent internals.
let savedLog: typeof console.log;
let savedWarn: typeof console.warn;
beforeEach(() => {
  savedLog = console.log; console.log = () => {};
  savedWarn = console.warn; console.warn = () => {};
});
afterEach(() => { console.log = savedLog; console.warn = savedWarn; });

describe('OdinAgent — config-only accessors (no init)', () => {
  it('isLLMConfigured returns false when provider=none', () => {
    const tmp = mkdtempSync(join(tmpdir(), 'odin-agent-'));
    try {
      const agent = new OdinAgent(makeConfig(tmp, nextPort()));
      expect(agent.isLLMConfigured()).toBe(false);
      expect(agent.getLLMStatus()).toMatch(/Not configured/i);
      expect(agent.getDashboardPort()).toBeGreaterThan(0);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('isLLMConfigured returns true when a provider is configured', () => {
    const tmp = mkdtempSync(join(tmpdir(), 'odin-agent-'));
    try {
      const cfg = makeConfig(tmp, nextPort());
      cfg.llm.privileged = { provider: 'ollama', model: 'gemma3', baseUrl: 'http://localhost:11434' };
      cfg.llm.quarantined = { provider: 'ollama', model: 'gemma3', baseUrl: 'http://localhost:11434' };
      const agent = new OdinAgent(cfg);
      expect(agent.isLLMConfigured()).toBe(true);
      expect(agent.getLLMStatus()).toMatch(/gemma3/);
      expect(agent.getLLMStatus()).toMatch(/ollama/);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });
});

describe('OdinAgent — full lifecycle (init → chat → close)', () => {
  let tmp: string;
  let agent: OdinAgent;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'odin-agent-'));
  });

  afterEach(async () => {
    try { await agent?.close(); } catch {}
    try { rmSync(tmp, { recursive: true, force: true }); } catch {}
  });

  it('init brings every subsystem up without throwing', async () => {
    agent = new OdinAgent(makeConfig(tmp, nextPort()));
    await agent.init();

    // DID is materialised
    const did = agent.getDID();
    expect(did.id).toMatch(/^did:odin:/);

    // Trust scoring is initialised with a local baseline (mode SAFE because fresh)
    const mode = agent.getTrustMode();
    expect(['SAFE', 'CAUTION', 'DEGRADED']).toContain(mode);

    // Audit report exists, even if empty
    const report = agent.getAuditReport();
    expect(report).toHaveProperty('totalDecisions');

    // Session id is populated
    expect(agent.getSessionId()).toBeTruthy();
  });

  it('chat() returns the NullAdapter configure-me notice when no LLM is set', async () => {
    agent = new OdinAgent(makeConfig(tmp, nextPort()));
    await agent.init();

    const reply = await agent.chat('hello');
    // NullAdapter yields: "[No LLM configured] Configure a model..."
    // Agent may wrap this; the core phrase must come through.
    expect(typeof reply).toBe('string');
    expect(reply.length).toBeGreaterThan(0);
    expect(reply.toLowerCase()).toContain('no llm configured');
  });

  it('close() is idempotent (safe to call even if subsystems are half-initialised)', async () => {
    agent = new OdinAgent(makeConfig(tmp, nextPort()));
    // Calling close before init shouldn't throw
    await expect(agent.close()).resolves.toBeUndefined();
    // Then init normally
    await agent.init();
    // Then close again
    await expect(agent.close()).resolves.toBeUndefined();
  });
});
