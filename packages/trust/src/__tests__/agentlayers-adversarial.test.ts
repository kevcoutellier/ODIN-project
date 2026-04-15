/**
 * AgentLayers client adversarial tests — behaviour under a hostile server.
 *
 * agentlayers-client.test.ts covers the happy path + basic graceful
 * degradation (network error / non-2xx). This file pushes what happens
 * when the upstream API misbehaves:
 *
 *   - malformed JSON body (res.json() throws)
 *   - response is JSON but wrong shape (missing fields, null)
 *   - response returns a primitive (not an object)
 *   - oversized response (no stream limits — just shouldn't crash)
 *   - slow response that never settles (caller should still honour
 *     upstream timeouts/AbortControllers — NOT tested here because
 *     the client doesn't set one yet — documented as a gap)
 *   - the client never sends an Authorization header when API key absent
 *     (so a later attacker middleware can't assume trust)
 *   - TrustScoreManager doesn't reach stale state if selfAudit returns null
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  AgentLayersClient,
  TrustScoreManager,
} from '../agentlayers-client.js';
import type { SkillManifest, TrustScore } from '@odin/core';

const manifest = (): SkillManifest => ({
  name: 's', version: '1.0.0', description: 'd', author: 'a',
  tools: [], trustTier: 0,
});

function mockResponse(overrides: Partial<Response>): Response {
  return {
    ok: true, status: 200, statusText: 'OK',
    headers: new Headers(),
    json: async () => ({}),
    text: async () => '',
    ...overrides,
  } as unknown as Response;
}

beforeEach(() => { vi.restoreAllMocks(); });
afterEach(() => { vi.unstubAllGlobals(); });

describe('AgentLayersClient — hostile server responses', () => {
  const client = () => new AgentLayersClient({
    apiKey: 'sk-test', baseUrl: 'https://api.agent-layers.com',
  });

  it('malformed JSON body → null (client catches and degrades)', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(mockResponse({
      json: async () => { throw new SyntaxError('Unexpected token'); },
    })));
    const c = client();
    expect(await c.getTrustScore('did:odin:x')).toBeNull();
    expect(await c.scanSkill(manifest())).toBeNull();
  });

  it('response that is JSON but null → null (not a crash)', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(mockResponse({
      json: async () => null,
    })));
    const c = client();
    // Current impl does NOT re-validate shape; `null` flows back as-is.
    // Assert the observable: no crash, safe fallback.
    const result = await c.scanSkill(manifest());
    expect(result).toBeNull();
  });

  it('response is a JSON primitive (string) → returned as-is (documented)', async () => {
    // The client blindly casts the response — downstream callers must
    // be defensive. This test documents the current behaviour.
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(mockResponse({
      json: async () => 'not-a-trust-score',
    })));
    const result = await client().getTrustScore('did:odin:x');
    expect(result).toBe('not-a-trust-score' as unknown as TrustScore);
  });

  it('response missing expected fields → returned as-is (caller must validate)', async () => {
    // Document: client does no schema validation. Flag as a hardening opportunity.
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(mockResponse({
      json: async () => ({ /* no 'overall', no 'dimensions' */ }),
    })));
    const score = await client().getTrustScore('did:odin:x');
    expect(score).toEqual({});
  });

  it('oversized response (1 MB) completes without timeout', async () => {
    const huge = { overall: 50, dimensions: {}, junk: 'x'.repeat(1_000_000) };
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(mockResponse({
      json: async () => huge,
    })));
    const start = Date.now();
    const result = await client().getTrustScore('did:odin:x');
    expect(result).toBeTruthy();
    expect(Date.now() - start).toBeLessThan(500);
  });

  it('does not include Authorization header when no API key set', async () => {
    const fetchSpy = vi.fn().mockResolvedValue(mockResponse({ json: async () => null }));
    vi.stubGlobal('fetch', fetchSpy);
    // No apiKey → isAvailable=false → request is NEVER sent
    const c = new AgentLayersClient({ baseUrl: 'https://api.agent-layers.com' });
    await c.getTrustScore('did:odin:x');
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('reportIncident handles a 500 gracefully and returns false', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(mockResponse({
      ok: false, status: 500, statusText: 'Internal Server Error',
    })));
    const ok = await client().reportIncident({
      agentDid: 'did:odin:x', type: 't', severity: 'high', description: 'd',
    });
    expect(ok).toBe(false);
  });

  it('scanSkill with server returning unexpected HTTP 204 (no body) degrades to null', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(mockResponse({
      status: 204, statusText: 'No Content',
      json: async () => { throw new SyntaxError('Unexpected end of input'); },
    })));
    const result = await client().scanSkill(manifest());
    expect(result).toBeNull();
  });
});

describe('TrustScoreManager — robustness against API hiccups', () => {
  it('selfAudit returning null keeps the manager in its prior mode', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(mockResponse({
      ok: false, status: 503, statusText: 'Service Unavailable',
    })));
    const c = new AgentLayersClient({ apiKey: 'sk', baseUrl: 'https://x' });
    const mgr = new TrustScoreManager(c, 'did:odin:self');
    // Initial mode is SAFE
    expect(mgr.getMode()).toBe('SAFE');
    const result = await mgr.selfAudit();
    expect(result).toBeNull();
    expect(mgr.getMode()).toBe('SAFE'); // unchanged despite API failure
  });

  it('computeLocalBaseline with adversarial inputs stays within [0, 100]', () => {
    const c = new AgentLayersClient({ baseUrl: 'https://x' });
    const mgr = new TrustScoreManager(c, 'did:odin:self');

    const extremeHigh = mgr.computeLocalBaseline({
      uptime: 1_000_000,      // absurd
      successRate: 2.0,       // > 1.0 (can't happen but try it)
      violationCount: -10,    // negative
    });
    expect(extremeHigh.overall).toBeGreaterThanOrEqual(0);
    expect(extremeHigh.overall).toBeLessThanOrEqual(100);

    const extremeLow = mgr.computeLocalBaseline({
      uptime: -1000,
      successRate: -0.5,
      violationCount: 100_000,
    });
    expect(extremeLow.overall).toBeGreaterThanOrEqual(0);
    expect(extremeLow.overall).toBeLessThanOrEqual(100);
  });

  it('rapidly alternating mode changes do not lose listener notifications', async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);
    const c = new AgentLayersClient({ apiKey: 'sk', baseUrl: 'https://x' });
    const mgr = new TrustScoreManager(c, 'did:odin:self');

    const modes: string[] = [];
    mgr.onModeChange((mode) => modes.push(mode));

    // Oscillate: SAFE → DEGRADED → SAFE → DEGRADED ...
    const scores = [30, 85, 30, 85, 30, 85];
    for (const overall of scores) {
      fetchSpy.mockResolvedValueOnce(mockResponse({
        json: async () => ({
          overall,
          dimensions: { performance: 80, transparency: 80, security: 80, compliance: 80, reputation: 80, reliability: 80 },
          timestamp: Date.now(), certifiedBy: 'agentlayers',
        }),
      }));
      await mgr.selfAudit();
    }

    // Expect all 6 mode changes to be captured (SAFE→DEGRADED, DEGRADED→SAFE, ...)
    expect(modes).toEqual(['DEGRADED', 'SAFE', 'DEGRADED', 'SAFE', 'DEGRADED', 'SAFE']);
  });
});
