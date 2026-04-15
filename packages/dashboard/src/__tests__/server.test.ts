/**
 * DashboardServer tests — REST API surface + WebSocket broadcasts.
 *
 * Uses port 0 (OS-assigned) to avoid clashes. Exercises:
 *   - GET /api/state
 *   - POST /api/chat (with/without handler, body overflow)
 *   - POST /api/skill/install, /api/mcp/connect, /api/config/update,
 *     /api/settings/:section (all follow the same handler pattern)
 *   - updateState broadcasts state-update frames over the WS
 *   - addDecisionTrace pushes to decisionTrace and creates alerts for block/warn
 *   - addActivity broadcasts an 'activity' frame
 *   - CORS preflight + 404 for unknown routes
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
  const baseUrl = `http://127.0.0.1:${port}`;
  try {
    await run(baseUrl, server, port);
  } finally {
    await server.stop();
  }
}

/**
 * Open a WebSocket and buffer incoming frames. We attach the message listener
 * BEFORE the connection opens to avoid missing the server's initial
 * state-update frame (which is sent synchronously on 'connection').
 */
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

/** Wait until predicate is true, or throw. */
async function waitFor(predicate: () => boolean, timeoutMs = 1500, stepMs = 20) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise(r => setTimeout(r, stepMs));
  }
  throw new Error(`waitFor timed out after ${timeoutMs}ms`);
}

// Silence noisy logs if any
let savedLog: typeof console.log;
beforeEach(() => { savedLog = console.log; console.log = () => {}; });
afterEach(() => { console.log = savedLog; });

describe('DashboardServer — REST', () => {
  it('GET /api/state returns the default state', async () => {
    await withServer(() => {}, async (baseUrl) => {
      const res = await fetch(`${baseUrl}/api/state`);
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.agentName).toBeTruthy();
      expect(body.circuitBreakerState).toBe('CLOSED');
      expect(Array.isArray(body.activities)).toBe(true);
    });
  });

  it('GET / returns HTML', async () => {
    await withServer(() => {}, async (baseUrl) => {
      const res = await fetch(`${baseUrl}/`);
      expect(res.status).toBe(200);
      expect(res.headers.get('content-type')).toMatch(/html/);
      const body = await res.text();
      expect(body.length).toBeGreaterThan(0);
    });
  });

  it('OPTIONS request returns 204 with CORS headers', async () => {
    await withServer(() => {}, async (baseUrl) => {
      const res = await fetch(`${baseUrl}/api/state`, { method: 'OPTIONS' });
      expect(res.status).toBe(204);
      expect(res.headers.get('access-control-allow-origin')).toBe('*');
    });
  });

  it('unknown route returns 404', async () => {
    await withServer(() => {}, async (baseUrl) => {
      const res = await fetch(`${baseUrl}/not-a-real-path`);
      expect(res.status).toBe(404);
    });
  });
});

describe('DashboardServer — /api/chat', () => {
  it('400 when no handler registered', async () => {
    await withServer(() => {}, async (baseUrl) => {
      const res = await fetch(`${baseUrl}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: 'hi' }),
      });
      // chatHandler absent → 400 per current impl
      expect(res.status).toBe(400);
    });
  });

  it('routes to the registered chat handler and returns its reply', async () => {
    await withServer(
      (srv) => srv.onChat(async (msg) => `echo:${msg}`),
      async (baseUrl) => {
        const res = await fetch(`${baseUrl}/api/chat`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ message: 'bonjour' }),
        });
        expect(res.status).toBe(200);
        const body = await res.json();
        expect(body.reply).toBe('echo:bonjour');
      },
    );
  });

  it('413 when the body exceeds 64KB', async () => {
    await withServer(
      (srv) => srv.onChat(async () => 'ok'),
      async (baseUrl) => {
        const big = 'a'.repeat(70_000);
        const res = await fetch(`${baseUrl}/api/chat`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ message: big }),
        });
        expect(res.status).toBe(413);
      },
    );
  });

  it('500 when the handler throws', async () => {
    await withServer(
      (srv) => srv.onChat(async () => { throw new Error('handler failure'); }),
      async (baseUrl) => {
        const res = await fetch(`${baseUrl}/api/chat`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ message: 'x' }),
        });
        expect(res.status).toBe(500);
        const body = await res.json();
        expect(body.error).toBe('handler failure');
      },
    );
  });
});

describe('DashboardServer — action handlers (skill/mcp/config/settings)', () => {
  it('503 when skillInstallHandler is not registered', async () => {
    await withServer(() => {}, async (baseUrl) => {
      const res = await fetch(`${baseUrl}/api/skill/install`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'x' }),
      });
      expect(res.status).toBe(503);
      const body = await res.json();
      expect(body.success).toBe(false);
    });
  });

  it('skill install handler is invoked with the parsed body', async () => {
    let captured: unknown = null;
    await withServer(
      (srv) => srv.onSkillInstall(async (data) => {
        captured = data;
        return { success: true, message: 'installed' };
      }),
      async (baseUrl) => {
        const payload = { name: 'translator', version: '1.0.0' };
        const res = await fetch(`${baseUrl}/api/skill/install`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        expect(res.status).toBe(200);
        const body = await res.json();
        expect(body).toEqual({ success: true, message: 'installed' });
        expect(captured).toEqual(payload);
      },
    );
  });

  it('settings route extracts the section from the URL', async () => {
    let capturedSection = '';
    let capturedData: unknown = null;
    await withServer(
      (srv) => srv.onSettingsUpdate(async (section, data) => {
        capturedSection = section; capturedData = data;
        return { success: true };
      }),
      async (baseUrl) => {
        const res = await fetch(`${baseUrl}/api/settings/security`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ defaultRing: 1 }),
        });
        expect(res.status).toBe(200);
        expect(capturedSection).toBe('security');
        expect(capturedData).toEqual({ defaultRing: 1 });
      },
    );
  });

  it('MCP connect handler wired correctly', async () => {
    await withServer(
      (srv) => srv.onMCPConnect(async () => ({ success: true, score: 80 })),
      async (baseUrl) => {
        const res = await fetch(`${baseUrl}/api/mcp/connect`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: 'https://mcp.example' }),
        });
        expect(res.status).toBe(200);
        const body = await res.json();
        expect(body.success).toBe(true);
      },
    );
  });

  it('config update handler wired correctly', async () => {
    await withServer(
      (srv) => srv.onConfigUpdate(async () => ({ success: true })),
      async (baseUrl) => {
        const res = await fetch(`${baseUrl}/api/config/update`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ provider: 'ollama' }),
        });
        expect(res.status).toBe(200);
      },
    );
  });
});

describe('DashboardServer — WebSocket broadcasts', () => {
  it('sends an initial state-update on connect', async () => {
    await withServer(() => {}, async (_baseUrl, _srv, port) => {
      const { ws, frames } = await openWsWithBuffer(port);
      await waitFor(() => frames.length >= 1);
      ws.close();
      expect((frames[0] as any).type).toBe('state-update');
    });
  });

  it('updateState broadcasts a state-update frame with merged data', async () => {
    await withServer(() => {}, async (_baseUrl, srv, port) => {
      const { ws, frames } = await openWsWithBuffer(port);
      await waitFor(() => frames.length >= 1); // initial frame received
      const initialCount = frames.length;

      srv.updateState({ trustScore: 77 });
      await waitFor(() => frames.length > initialCount);
      ws.close();

      const stateFrames = frames.filter((f: any) => f.type === 'state-update');
      // Find the frame with trustScore=77 (there may be multiple state-updates)
      const match = stateFrames.find((f: any) => f.data.trustScore === 77);
      expect(match).toBeTruthy();
    });
  });

  it('addActivity broadcasts an "activity" frame', async () => {
    await withServer(() => {}, async (_baseUrl, srv, port) => {
      const { ws, frames } = await openWsWithBuffer(port);
      await waitFor(() => frames.length >= 1); // initial frame

      srv.addActivity({
        timestamp: '2026-01-01 00:00',
        type: 'chat',
        action: 'user message',
        detail: 'hi',
      });
      await waitFor(() => frames.some((f: any) => f.type === 'activity'));
      ws.close();

      const actFrames = frames.filter((f: any) => f.type === 'activity');
      expect(actFrames.length).toBeGreaterThanOrEqual(1);
      expect((actFrames[0] as any).data.action).toBe('user message');
    });
  });
});

describe('DashboardServer — addDecisionTrace', () => {
  it('stores a trace and promotes block entries to critical alerts', async () => {
    await withServer(() => {}, async (baseUrl, srv) => {
      srv.addDecisionTrace({
        timestamp: '2026-01-01 00:00',
        type: 'block',
        emitter: 'policy',
        action: 'shell_exec',
        detail: 'denied: low trust',
        layer: 'policy',
      });
      const res = await fetch(`${baseUrl}/api/state`);
      const state = await res.json();
      expect(state.decisionTrace.length).toBe(1);
      expect(state.alerts.length).toBe(1);
      expect(state.alerts[0].severity).toBe('critical');
      expect(state.alertsCritical).toBe(1);
      expect(state.alertsActive).toBe(1);
    });
  });

  it('allow entries do not create alerts', async () => {
    await withServer(() => {}, async (baseUrl, srv) => {
      srv.addDecisionTrace({
        timestamp: '2026-01-01 00:00',
        type: 'allow',
        emitter: 'policy',
        action: 'read',
        detail: 'ok',
        layer: 'policy',
      });
      const res = await fetch(`${baseUrl}/api/state`);
      const state = await res.json();
      expect(state.alerts.length).toBe(0);
      expect(state.decisionTrace.length).toBe(1);
    });
  });

  it('caps decisionTrace at 200 entries', async () => {
    await withServer(() => {}, async (baseUrl, srv) => {
      for (let i = 0; i < 210; i++) {
        srv.addDecisionTrace({
          timestamp: String(i), type: 'allow', emitter: 'e', action: 'a', detail: 'd', layer: 'l',
        });
      }
      const res = await fetch(`${baseUrl}/api/state`);
      const state = await res.json();
      expect(state.decisionTrace.length).toBe(200);
    });
  });
});
