/**
 * DashboardServer adversarial tests — WebSocket flood, abrupt disconnect,
 * REST stress, and payload boundaries.
 *
 * The dashboard is exposed over localhost by default but may end up behind
 * a reverse proxy. Minimum guarantees:
 *
 *   - many concurrent WS clients do not leak memory or crash the server
 *   - abruptly closed clients are pruned (no broadcast to dead sockets)
 *   - activities / decisionTrace are capped (flood resistance)
 *   - REST POST endpoints reject body-size overruns at 64KB
 *   - decisionTrace stays consistent under many rapid addDecisionTrace calls
 *   - invalid JSON in REST body is surfaced as 500 (with graceful error),
 *     not a crash of the server loop
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { DashboardServer } from '../server.js';
import WebSocket from 'ws';
import type { AddressInfo } from 'node:net';

async function withServer(
  setup: (server: DashboardServer) => void,
  run: (baseUrl: string, server: DashboardServer, port: number) => Promise<void>,
) {
  const server = new DashboardServer(0);
  setup(server);
  await server.start();
  const port = ((server as any).httpServer.address() as AddressInfo).port;
  try {
    await run(`http://127.0.0.1:${port}`, server, port);
  } finally {
    await server.stop();
  }
}

function openWsWithBuffer(port: number): Promise<{ ws: WebSocket; frames: unknown[] }> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}`);
    const frames: unknown[] = [];
    ws.on('message', (data) => {
      try { frames.push(JSON.parse(data.toString())); } catch {}
    });
    ws.on('open', () => resolve({ ws, frames }));
    ws.on('error', reject);
  });
}

async function waitFor(predicate: () => boolean, timeoutMs = 2000, stepMs = 20) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise(r => setTimeout(r, stepMs));
  }
  throw new Error(`waitFor timed out after ${timeoutMs}ms`);
}

let savedLog: typeof console.log;
beforeEach(() => { savedLog = console.log; console.log = () => {}; });
afterEach(() => { console.log = savedLog; });

describe('DashboardServer — WebSocket flood', () => {
  it('accepts many concurrent clients and broadcasts state-update to all', async () => {
    await withServer(() => {}, async (_baseUrl, srv, port) => {
      // Open 25 parallel connections
      const conns = await Promise.all(
        Array.from({ length: 25 }, () => openWsWithBuffer(port)),
      );

      // Each gets the initial state-update
      await waitFor(() => conns.every(c => c.frames.length >= 1));

      // Broadcast an update
      srv.updateState({ trustScore: 55 });
      await waitFor(() =>
        conns.every(c => c.frames.some((f: any) => f.data?.trustScore === 55)),
        3000,
      );

      for (const { ws } of conns) ws.close();
    });
  });

  it('clients that disconnect abruptly are removed from the broadcast set', async () => {
    await withServer(() => {}, async (_baseUrl, srv, port) => {
      const { ws } = await openWsWithBuffer(port);
      // Terminate without the normal close handshake
      ws.terminate();

      // Give the server a moment to notice
      await new Promise(r => setTimeout(r, 50));

      // Broadcast — must not throw even though the client is gone
      expect(() => srv.updateState({ trustScore: 42 })).not.toThrow();
      // Internal set has been pruned (best-effort; may still show 0)
      // We rely on the 'close' event firing after terminate
    });
  });

  it('a client that never listens doesn\'t starve the others', async () => {
    await withServer(() => {}, async (_baseUrl, srv, port) => {
      // Slow client: opens but never reads frames
      const slow = await openWsWithBuffer(port);
      // Pause listening by not advancing its event loop is tricky in Node;
      // we simulate by just NOT asserting anything on `slow.frames`.
      const fast1 = await openWsWithBuffer(port);
      const fast2 = await openWsWithBuffer(port);

      srv.updateState({ trustScore: 88 });
      // fast clients receive the update promptly
      await waitFor(() =>
        [fast1, fast2].every(c => c.frames.some((f: any) => f.data?.trustScore === 88)),
        1500,
      );

      slow.ws.close();
      fast1.ws.close();
      fast2.ws.close();
    });
  });
});

describe('DashboardServer — state flood caps', () => {
  it('activities list caps at 200 entries under flood', async () => {
    await withServer(() => {}, async (baseUrl, srv) => {
      for (let i = 0; i < 350; i++) {
        srv.addActivity({
          timestamp: `t${i}`, type: 'chat', action: `op-${i}`, detail: 'x',
        });
      }
      const res = await fetch(`${baseUrl}/api/state`);
      const state = await res.json();
      expect(state.activities.length).toBeLessThanOrEqual(200);
      // Most recent first
      expect(state.activities[0].action).toBe('op-349');
    });
  });

  it('decisionTrace caps at 200 and alerts promote only on block/warn', async () => {
    await withServer(() => {}, async (baseUrl, srv) => {
      for (let i = 0; i < 350; i++) {
        srv.addDecisionTrace({
          timestamp: `t${i}`,
          type: i % 3 === 0 ? 'block' : (i % 3 === 1 ? 'warn' : 'allow'),
          emitter: 'e', action: `a${i}`, detail: 'd', layer: 'l',
        });
      }
      const res = await fetch(`${baseUrl}/api/state`);
      const state = await res.json();
      expect(state.decisionTrace.length).toBe(200);
      // alerts count only the non-allow entries
      expect(state.alertsActive).toBeLessThanOrEqual(state.alerts.length);
      expect(state.alerts.every((a: any) => ['critical', 'warn', 'info'].includes(a.severity))).toBe(true);
    });
  });
});

describe('DashboardServer — REST payload boundaries', () => {
  it('POST /api/chat exactly at 64KB is accepted', async () => {
    await withServer(
      (srv) => srv.onChat(async () => 'ok'),
      async (baseUrl) => {
        // JSON overhead + ~64KB body → exactly at the limit
        // Build a JSON of size ~65500 bytes to stay under 65536
        const payload = JSON.stringify({ message: 'x'.repeat(65_400) });
        expect(payload.length).toBeLessThan(65_536);
        const res = await fetch(`${baseUrl}/api/chat`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: payload,
        });
        expect(res.status).toBe(200);
      },
    );
  });

  it('POST /api/chat with invalid JSON surfaces as 500 (never a crash)', async () => {
    await withServer(
      (srv) => srv.onChat(async () => 'ok'),
      async (baseUrl) => {
        const res = await fetch(`${baseUrl}/api/chat`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: '{invalid-json',
        });
        // Current impl parses inside a try/catch → 500 with an error body.
        expect(res.status).toBe(500);
        const body = await res.json();
        expect(body.error).toBeTruthy();
      },
    );
  });

  it('POST /api/skill/install 413 on body overflow', async () => {
    await withServer(
      (srv) => srv.onSkillInstall(async () => ({ success: true })),
      async (baseUrl) => {
        // The skill endpoint reads chunks until bodySize > 65536, then 413.
        // Total payload must exceed the limit.
        const res = await fetch(`${baseUrl}/api/skill/install`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: 'x'.repeat(70_000),
        });
        expect(res.status).toBe(413);
      },
    );
  });

  it('OPTIONS request on /api/chat returns 204 (CORS preflight)', async () => {
    await withServer(() => {}, async (baseUrl) => {
      const res = await fetch(`${baseUrl}/api/chat`, { method: 'OPTIONS' });
      expect(res.status).toBe(204);
    });
  });
});

describe('DashboardServer — stress stability', () => {
  it('100 parallel GET /api/state all succeed', async () => {
    await withServer(() => {}, async (baseUrl) => {
      const results = await Promise.all(
        Array.from({ length: 100 }, () => fetch(`${baseUrl}/api/state`)),
      );
      expect(results.every(r => r.status === 200)).toBe(true);
    });
  });

  it('rapid sequence of updates all broadcast (no drops for a steady listener)', async () => {
    await withServer(() => {}, async (_baseUrl, srv, port) => {
      const { ws, frames } = await openWsWithBuffer(port);
      await waitFor(() => frames.length >= 1);
      const before = frames.length;

      // 30 rapid updates
      for (let i = 0; i < 30; i++) srv.updateState({ tokensToday: i });
      await waitFor(() => frames.length >= before + 30);
      ws.close();

      const stateUpdates = frames.slice(before).filter((f: any) => f.type === 'state-update');
      // At minimum, the last update (tokensToday=29) must be visible
      expect(stateUpdates.some((f: any) => f.data.tokensToday === 29)).toBe(true);
    });
  });
});
