/**
 * AgentLayers client tests — fetch wiring & graceful degradation.
 *
 * Key invariants:
 *   - Without an apiKey, every call is a no-op returning null/false
 *     (free tier: the agent is fully functional without AgentLayers).
 *   - With an apiKey, requests go to the configured base URL with the
 *     Bearer token, JSON content type, and X-Agent-SDK header.
 *   - Network failures and non-2xx responses degrade to null/false,
 *     never throw (the caller must not crash on an unreachable API).
 *
 * Plus TrustScoreManager: mode transitions, mode-change listeners,
 * and local baseline fallback when AgentLayers is unreachable.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  AgentLayersClient,
  TrustScoreManager,
  type SkillScanResult,
  type MCPScanResult,
  type A2AScanResult,
} from '../agentlayers-client.js';
import type { SkillManifest, AgentCard, TrustScore } from '@odin/core';

// ─── Fixtures ──────────────────────────────────────────────────────────

const SKILL_SCAN: SkillScanResult = {
  score: 85,
  decision: 'INSTALL',
  dimensions: {
    permissions: 90, injection: 85, transparency: 80,
    scopeCreep: 85, supplyChain: 80, community: 85,
  },
  warnings: [],
};

const MCP_SCAN: MCPScanResult = {
  score: 80,
  decision: 'SAFE',
  dimensions: {
    endpointSecurity: 85, permissionScope: 80, dataExfiltration: 80,
    authStrength: 75, configTransparency: 80,
  },
  warnings: [],
};

const A2A_SCAN: A2AScanResult = {
  score: 90,
  decision: 'ALLOW',
  dimensions: {
    authProtocol: 95, messageSigning: 90, delegationDepth: 85,
    scopeContainment: 90, identityVerification: 90,
  },
  warnings: [],
};

const TRUST_SCORE_80: TrustScore = {
  overall: 80,
  dimensions: {
    performance: 85, transparency: 80, security: 85,
    compliance: 75, reputation: 75, reliability: 80,
  },
  timestamp: Date.now(),
  certifiedBy: 'agentlayers',
};

const manifest = (): SkillManifest => ({
  name: 'test-skill', version: '1.0.0', description: 'test',
  author: 'tester', tools: [], trustTier: 0,
});

const agentCard = (): AgentCard => ({
  name: 'Peer', did: 'did:odin:peer', description: 'peer agent',
  capabilities: ['chat'],
  endpoints: { a2a: 'https://peer.example/a2a', health: 'https://peer.example/health' },
});

/** Build a minimal Response-like object for mocking fetch. */
function mockOk<T>(body: T): Response {
  return {
    ok: true,
    status: 200,
    statusText: 'OK',
    json: async () => body,
  } as unknown as Response;
}

function mockFail(status: number, statusText = 'Error'): Response {
  return {
    ok: false,
    status,
    statusText,
    json: async () => ({}),
  } as unknown as Response;
}

// ─── Tests ─────────────────────────────────────────────────────────────

describe('AgentLayersClient — free tier (no API key)', () => {
  it('isAvailable() is false without an API key', () => {
    const client = new AgentLayersClient({ baseUrl: 'https://api.agent-layers.com' });
    expect(client.isAvailable()).toBe(false);
  });

  it('every method returns null/false without an API key', async () => {
    const client = new AgentLayersClient({ baseUrl: 'https://api.agent-layers.com' });
    expect(await client.getTrustScore('did:odin:x')).toBeNull();
    expect(await client.scanSkill(manifest())).toBeNull();
    expect(await client.scanMCPServer({ url: 'u', name: 'n', tools: [] })).toBeNull();
    expect(await client.scanAgentCard(agentCard())).toBeNull();
    expect(await client.reportIncident({
      agentDid: 'did:odin:x',
      type: 'test',
      severity: 'low',
      description: 'test',
    })).toBe(false);
  });

  it('does not call fetch without an API key', async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);
    const client = new AgentLayersClient({ baseUrl: 'https://api.agent-layers.com' });
    await client.getTrustScore('did:odin:x');
    await client.scanSkill(manifest());
    expect(fetchSpy).not.toHaveBeenCalled();
    vi.unstubAllGlobals();
  });
});

describe('AgentLayersClient — paid tier (with API key)', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  const makeClient = () => new AgentLayersClient({
    apiKey: 'sk-test-123',
    baseUrl: 'https://api.agent-layers.com',
  });

  it('getTrustScore hits /api/v1/trust-score with auth headers', async () => {
    const fetchSpy = vi.fn().mockResolvedValue(mockOk(TRUST_SCORE_80));
    vi.stubGlobal('fetch', fetchSpy);

    const client = makeClient();
    const score = await client.getTrustScore('did:odin:test');

    expect(score).toEqual(TRUST_SCORE_80);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const [url, init] = fetchSpy.mock.calls[0];
    expect(url).toBe('https://api.agent-layers.com/api/v1/trust-score');
    expect(init.method).toBe('POST');
    expect(init.headers['Authorization']).toBe('Bearer sk-test-123');
    expect(init.headers['Content-Type']).toBe('application/json');
    expect(init.headers['X-Agent-SDK']).toMatch(/^odin\//);
    expect(JSON.parse(init.body)).toEqual({ agentDid: 'did:odin:test' });
  });

  it('scanSkill hits /api/v1/skill-scanner with manifest body', async () => {
    const fetchSpy = vi.fn().mockResolvedValue(mockOk(SKILL_SCAN));
    vi.stubGlobal('fetch', fetchSpy);

    const client = makeClient();
    const result = await client.scanSkill(manifest());

    expect(result).toEqual(SKILL_SCAN);
    const [url, init] = fetchSpy.mock.calls[0];
    expect(url).toBe('https://api.agent-layers.com/api/v1/skill-scanner');
    expect(JSON.parse(init.body).manifest.name).toBe('test-skill');
  });

  it('scanMCPServer hits /api/v1/mcp-scanner', async () => {
    const fetchSpy = vi.fn().mockResolvedValue(mockOk(MCP_SCAN));
    vi.stubGlobal('fetch', fetchSpy);

    const client = makeClient();
    const result = await client.scanMCPServer({
      url: 'https://mcp.example',
      name: 'test',
      tools: ['tool_a'],
    });

    expect(result).toEqual(MCP_SCAN);
    const [url] = fetchSpy.mock.calls[0];
    expect(url).toBe('https://api.agent-layers.com/api/v1/mcp-scanner');
  });

  it('scanAgentCard hits /api/v1/a2a-scanner with agentCard body', async () => {
    const fetchSpy = vi.fn().mockResolvedValue(mockOk(A2A_SCAN));
    vi.stubGlobal('fetch', fetchSpy);

    const client = makeClient();
    const result = await client.scanAgentCard(agentCard());

    expect(result).toEqual(A2A_SCAN);
    const [, init] = fetchSpy.mock.calls[0];
    expect(JSON.parse(init.body).agentCard.did).toBe('did:odin:peer');
  });

  it('reportIncident returns true on 2xx', async () => {
    const fetchSpy = vi.fn().mockResolvedValue(mockOk({}));
    vi.stubGlobal('fetch', fetchSpy);

    const client = makeClient();
    const result = await client.reportIncident({
      agentDid: 'did:odin:self',
      type: 'indirect_injection',
      severity: 'high',
      description: 'detected',
    });

    expect(result).toBe(true);
    const [url] = fetchSpy.mock.calls[0];
    expect(url).toBe('https://api.agent-layers.com/api/v1/incidents');
  });
});

describe('AgentLayersClient — graceful degradation', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  const makeClient = () => new AgentLayersClient({
    apiKey: 'sk-test',
    baseUrl: 'https://api.agent-layers.com',
  });

  it('fetch rejection (network error) → null, no throw', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('ENOTFOUND')));
    const client = makeClient();
    expect(await client.getTrustScore('did:odin:x')).toBeNull();
    expect(await client.scanSkill(manifest())).toBeNull();
    expect(await client.scanMCPServer({ url: 'u', name: 'n', tools: [] })).toBeNull();
    expect(await client.scanAgentCard(agentCard())).toBeNull();
  });

  it('reportIncident returns false when fetch rejects', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('timeout')));
    const client = makeClient();
    const result = await client.reportIncident({
      agentDid: 'did:odin:x', type: 't', severity: 'low', description: 'd',
    });
    expect(result).toBe(false);
  });

  it('non-2xx response (401/500) → null, no throw', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(mockFail(500, 'Internal')));
    const client = makeClient();
    expect(await client.getTrustScore('did:odin:x')).toBeNull();
    expect(await client.scanSkill(manifest())).toBeNull();
  });
});

describe('TrustScoreManager', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('selfAudit records score and keeps current when AgentLayers is unavailable', async () => {
    const client = new AgentLayersClient({ baseUrl: 'https://api.agent-layers.com' }); // no apiKey
    const mgr = new TrustScoreManager(client, 'did:odin:self');
    const result = await mgr.selfAudit();
    expect(result).toBeNull();
    expect(mgr.getCurrentScore()).toBeNull();
    expect(mgr.getHistory()).toHaveLength(0);
  });

  it('selfAudit updates current, history, and mode', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(mockOk(TRUST_SCORE_80)));
    const client = new AgentLayersClient({ apiKey: 'sk', baseUrl: 'https://x' });
    const mgr = new TrustScoreManager(client, 'did:odin:self');

    const score = await mgr.selfAudit();
    expect(score?.overall).toBe(80);
    expect(mgr.getMode()).toBe('SAFE'); // 80 >= 75
    expect(mgr.getCurrentScore()).toEqual(TRUST_SCORE_80);
    expect(mgr.getHistory()).toHaveLength(1);
  });

  it('fires onModeChange when mode transitions', async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);

    const client = new AgentLayersClient({ apiKey: 'sk', baseUrl: 'https://x' });
    const mgr = new TrustScoreManager(client, 'did:odin:self');

    const transitions: Array<{ mode: string; score: number }> = [];
    mgr.onModeChange((mode, score) => {
      transitions.push({ mode, score: score.overall });
    });

    // Initial mode is SAFE. 80 → still SAFE → no fire.
    fetchSpy.mockResolvedValueOnce(mockOk({ ...TRUST_SCORE_80, overall: 80 }));
    await mgr.selfAudit();

    // SAFE → CAUTION (60) → fires
    fetchSpy.mockResolvedValueOnce(mockOk({ ...TRUST_SCORE_80, overall: 60 }));
    await mgr.selfAudit();

    // CAUTION → DEGRADED (30) → fires
    fetchSpy.mockResolvedValueOnce(mockOk({ ...TRUST_SCORE_80, overall: 30 }));
    await mgr.selfAudit();

    // DEGRADED → SAFE (90) → fires (recovery)
    fetchSpy.mockResolvedValueOnce(mockOk({ ...TRUST_SCORE_80, overall: 90 }));
    await mgr.selfAudit();

    expect(transitions).toHaveLength(3);
    expect(transitions.map(t => t.mode)).toEqual(['CAUTION', 'DEGRADED', 'SAFE']);
  });

  it('does NOT fire onModeChange when mode stays the same', async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);

    const client = new AgentLayersClient({ apiKey: 'sk', baseUrl: 'https://x' });
    const mgr = new TrustScoreManager(client, 'did:odin:self');

    const listener = vi.fn();
    mgr.onModeChange(listener);

    fetchSpy.mockResolvedValue(mockOk({ ...TRUST_SCORE_80, overall: 80 }));
    await mgr.selfAudit(); // transitions from SAFE (initial) to SAFE → NO fire
    await mgr.selfAudit(); // still SAFE → NO fire

    expect(listener).not.toHaveBeenCalled();
  });

  it('caps history at 1000 entries', async () => {
    const fetchSpy = vi.fn().mockResolvedValue(mockOk(TRUST_SCORE_80));
    vi.stubGlobal('fetch', fetchSpy);

    const client = new AgentLayersClient({ apiKey: 'sk', baseUrl: 'https://x' });
    const mgr = new TrustScoreManager(client, 'did:odin:self');

    for (let i = 0; i < 1005; i++) {
      await mgr.selfAudit();
    }
    expect(mgr.getHistory().length).toBe(1000);
  });

  it('computeLocalBaseline produces a deterministic local score', () => {
    const client = new AgentLayersClient({ baseUrl: 'https://x' });
    const mgr = new TrustScoreManager(client, 'did:odin:self');

    const score = mgr.computeLocalBaseline({
      uptime: 100, successRate: 1.0, violationCount: 0,
    });
    expect(score.certifiedBy).toMatch(/self:local-baseline/);
    expect(score.overall).toBeGreaterThan(0);
    expect(score.overall).toBeLessThanOrEqual(100);
    expect(mgr.getCurrentScore()).toEqual(score);
    expect(mgr.getMode()).toBe('SAFE'); // 100 uptime + 1.0 success + 0 violations should SAFE
  });

  it('computeLocalBaseline penalises violations', () => {
    const client = new AgentLayersClient({ baseUrl: 'https://x' });
    const mgr = new TrustScoreManager(client, 'did:odin:self');

    const clean = mgr.computeLocalBaseline({ uptime: 100, successRate: 1.0, violationCount: 0 });
    const dirty = mgr.computeLocalBaseline({ uptime: 100, successRate: 1.0, violationCount: 5 });
    expect(dirty.overall).toBeLessThan(clean.overall);
    expect(dirty.dimensions.security).toBeLessThan(clean.dimensions.security);
  });

  it('trustModeFromScore thresholds: SAFE ≥75, CAUTION ≥50, DEGRADED <50', async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);
    const client = new AgentLayersClient({ apiKey: 'sk', baseUrl: 'https://x' });
    const mgr = new TrustScoreManager(client, 'did:odin:self');

    fetchSpy.mockResolvedValueOnce(mockOk({ ...TRUST_SCORE_80, overall: 75 }));
    await mgr.selfAudit();
    expect(mgr.getMode()).toBe('SAFE');

    fetchSpy.mockResolvedValueOnce(mockOk({ ...TRUST_SCORE_80, overall: 74 }));
    await mgr.selfAudit();
    expect(mgr.getMode()).toBe('CAUTION');

    fetchSpy.mockResolvedValueOnce(mockOk({ ...TRUST_SCORE_80, overall: 49 }));
    await mgr.selfAudit();
    expect(mgr.getMode()).toBe('DEGRADED');
  });
});
