/**
 * A2A server tests — real HTTP server on an ephemeral port.
 *
 * These tests boot a real A2AServer, make real HTTP requests (via fetch),
 * and verify the routing + signature verification + task handler wiring.
 * An OS-assigned port (port 0 → server.address().port) avoids clashes.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { A2AServer, type TaskHandler, type SignatureVerifier } from '../server.js';
import type { A2AEnvelope, TaskSendPayload } from '../protocol.js';
import type { AgentCard } from '@odin/core';
import type { AddressInfo } from 'node:net';

const agentCard: AgentCard = {
  name: 'Odin Test',
  did: 'did:odin:test-server',
  description: 'A2A test server',
  capabilities: ['chat', 'search'],
  endpoints: {
    a2a: 'http://localhost',
    health: 'http://localhost/health',
  },
};

const buildEnvelope = (overrides: Partial<A2AEnvelope> = {}): A2AEnvelope => ({
  version: '1.0',
  type: 'task/send',
  id: 'msg-1',
  from: 'did:odin:peer',
  to: 'did:odin:test-server',
  timestamp: new Date().toISOString(),
  signature: 'ed25519:mock',
  payload: {
    taskId: 'task:abc',
    instruction: 'say hello',
    requiredCapabilities: [],
  } as TaskSendPayload,
  ...overrides,
});

async function withServer(
  setup: (server: A2AServer) => void,
  run: (baseUrl: string, server: A2AServer) => Promise<void>,
) {
  const server = new A2AServer({ port: 0, host: '127.0.0.1', minTrustScore: 50 });
  setup(server);
  await server.start();
  const addr = (server as any).server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${addr.port}`;
  try {
    await run(baseUrl, server);
  } finally {
    await server.stop();
  }
}

/** Wait until predicate is true, or throw. */
async function waitUntil(predicate: () => boolean, timeoutMs = 2000, stepMs = 20) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise(r => setTimeout(r, stepMs));
  }
  throw new Error(`waitUntil timed out after ${timeoutMs}ms`);
}

// Quiet the "[A2A] Server listening" log during tests.
let originalLog: typeof console.log;
beforeEach(() => { originalLog = console.log; console.log = () => {}; });
afterEach(() => { console.log = originalLog; });

describe('A2AServer — discovery & health', () => {
  it('GET /.well-known/agent.json returns the configured card', async () => {
    await withServer(
      (srv) => srv.setAgentCard(agentCard),
      async (baseUrl) => {
        const res = await fetch(`${baseUrl}/.well-known/agent.json`);
        expect(res.status).toBe(200);
        const body = await res.json();
        expect(body).toEqual(agentCard);
      },
    );
  });

  it('GET /.well-known/agent.json returns 503 when card not configured', async () => {
    await withServer(
      () => {},
      async (baseUrl) => {
        const res = await fetch(`${baseUrl}/.well-known/agent.json`);
        expect(res.status).toBe(503);
      },
    );
  });

  it('GET /health reports active and total task counts', async () => {
    await withServer(
      () => {},
      async (baseUrl) => {
        const res = await fetch(`${baseUrl}/health`);
        expect(res.status).toBe(200);
        const body = await res.json();
        expect(body.status).toBe('ok');
        expect(body.activeTasks).toBe(0);
        expect(body.totalTasks).toBe(0);
      },
    );
  });

  it('OPTIONS requests return 204 with CORS headers', async () => {
    await withServer(
      () => {},
      async (baseUrl) => {
        const res = await fetch(`${baseUrl}/.well-known/agent.json`, { method: 'OPTIONS' });
        expect(res.status).toBe(204);
        expect(res.headers.get('access-control-allow-origin')).toBe('*');
      },
    );
  });

  it('returns 404 for unknown routes', async () => {
    await withServer(
      () => {},
      async (baseUrl) => {
        const res = await fetch(`${baseUrl}/does-not-exist`);
        expect(res.status).toBe(404);
      },
    );
  });
});

describe('A2AServer — signature verification', () => {
  it('rejects a message with an invalid signature (403)', async () => {
    const verifier: SignatureVerifier = async () => false;
    await withServer(
      (srv) => { srv.setAgentCard(agentCard); srv.onVerify(verifier); },
      async (baseUrl) => {
        const res = await fetch(`${baseUrl}/a2a/message`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(buildEnvelope()),
        });
        expect(res.status).toBe(403);
        const body = await res.json();
        expect(body.error).toMatch(/signature/i);
      },
    );
  });

  it('calls the verifier with the payload JSON and the sender DID', async () => {
    let capturedData = '';
    let capturedSig = '';
    let capturedSender = '';
    const verifier: SignatureVerifier = async (data, sig, sender) => {
      capturedData = data; capturedSig = sig; capturedSender = sender;
      return true;
    };

    await withServer(
      (srv) => { srv.setAgentCard(agentCard); srv.onVerify(verifier); srv.onTask(async () => ({ taskId: 'task:abc', status: 'completed' })); },
      async (baseUrl) => {
        const env = buildEnvelope();
        const res = await fetch(`${baseUrl}/a2a/message`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(env),
        });
        expect(res.status).toBe(202);
        expect(capturedData).toBe(JSON.stringify(env.payload));
        expect(capturedSig).toBe(env.signature);
        expect(capturedSender).toBe(env.from);
      },
    );
  });

  it('accepts messages with no verifier configured (dev mode)', async () => {
    await withServer(
      (srv) => { srv.setAgentCard(agentCard); srv.onTask(async () => ({ taskId: 'task:abc', status: 'completed' })); },
      async (baseUrl) => {
        const res = await fetch(`${baseUrl}/a2a/message`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(buildEnvelope()),
        });
        expect(res.status).toBe(202);
      },
    );
  });
});

describe('A2AServer — envelope validation', () => {
  it('rejects malformed JSON (400)', async () => {
    await withServer(
      () => {},
      async (baseUrl) => {
        const res = await fetch(`${baseUrl}/a2a/message`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: '{invalid',
        });
        expect(res.status).toBe(400);
      },
    );
  });

  it('rejects envelopes missing required fields (400)', async () => {
    await withServer(
      () => {},
      async (baseUrl) => {
        const res = await fetch(`${baseUrl}/a2a/message`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ version: '1.0', type: 'task/send' }),
        });
        expect(res.status).toBe(400);
      },
    );
  });

  it('rejects unknown message types (400)', async () => {
    await withServer(
      () => {},
      async (baseUrl) => {
        const env = buildEnvelope({ type: 'task/garbage' as any });
        const res = await fetch(`${baseUrl}/a2a/message`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(env),
        });
        expect(res.status).toBe(400);
      },
    );
  });
});

describe('A2AServer — task lifecycle', () => {
  it('task/send without handler returns 503 and marks task rejected', async () => {
    await withServer(
      () => {},
      async (baseUrl, srv) => {
        const res = await fetch(`${baseUrl}/a2a/message`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(buildEnvelope()),
        });
        expect(res.status).toBe(503);
        const task = srv.getTask('task:abc');
        expect(task?.status).toBe('rejected');
      },
    );
  });

  it('task/send: 202 ack + handler runs async + task reaches completed', async () => {
    const handler: TaskHandler = async (payload) => ({
      taskId: payload.taskId,
      status: 'completed',
      result: `processed: ${payload.instruction}`,
    });

    await withServer(
      (srv) => srv.onTask(handler),
      async (baseUrl, srv) => {
        const res = await fetch(`${baseUrl}/a2a/message`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(buildEnvelope()),
        });
        expect(res.status).toBe(202);
        const ack = await res.json();
        expect(ack.status).toBe('queued');

        await waitUntil(() => srv.getTask('task:abc')?.status === 'completed');
        const task = srv.getTask('task:abc')!;
        expect(task.result).toBe('processed: say hello');
        expect(task.executionTimeMs).toBeGreaterThanOrEqual(0);
      },
    );
  });

  it('handler throwing marks task failed with error message', async () => {
    const handler: TaskHandler = async () => { throw new Error('boom'); };

    await withServer(
      (srv) => srv.onTask(handler),
      async (baseUrl, srv) => {
        await fetch(`${baseUrl}/a2a/message`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(buildEnvelope()),
        });
        await waitUntil(() => srv.getTask('task:abc')?.status === 'failed');
        const task = srv.getTask('task:abc')!;
        expect(task.error).toBe('boom');
      },
    );
  });

  it('GET /a2a/tasks/:id returns the task state; 404 when unknown', async () => {
    const handler: TaskHandler = async () => ({
      taskId: 'task:abc', status: 'completed', result: 'done',
    });

    await withServer(
      (srv) => srv.onTask(handler),
      async (baseUrl, srv) => {
        // Unknown first
        const missing = await fetch(`${baseUrl}/a2a/tasks/unknown`);
        expect(missing.status).toBe(404);

        // Send a task, wait for completion, then query
        await fetch(`${baseUrl}/a2a/message`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(buildEnvelope()),
        });
        await waitUntil(() => srv.getTask('task:abc')?.status === 'completed');

        const res = await fetch(`${baseUrl}/a2a/tasks/task:abc`);
        expect(res.status).toBe(200);
        const body = await res.json();
        expect(body.status).toBe('completed');
        expect(body.result).toBe('done');
      },
    );
  });

  it('task/cancel marks a running task cancelled', async () => {
    // Handler that blocks until released
    let release: () => void = () => {};
    const handler: TaskHandler = async (p) => {
      await new Promise<void>(r => { release = r; });
      return { taskId: p.taskId, status: 'completed' };
    };

    await withServer(
      (srv) => srv.onTask(handler),
      async (baseUrl, srv) => {
        // Queue task
        await fetch(`${baseUrl}/a2a/message`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(buildEnvelope()),
        });
        // Wait for running
        await waitUntil(() => srv.getTask('task:abc')?.status === 'running');

        // Send cancel
        const cancelRes = await fetch(`${baseUrl}/a2a/message`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(buildEnvelope({
            type: 'task/cancel',
            payload: { taskId: 'task:abc', reason: 'user-requested' } as any,
          })),
        });
        expect(cancelRes.status).toBe(200);
        expect(srv.getTask('task:abc')?.status).toBe('cancelled');

        // Release the handler so the server can clean up
        release();
      },
    );
  });
});

describe('A2AServer — peer/discover & peer/heartbeat', () => {
  it('peer/discover returns our agent card', async () => {
    await withServer(
      (srv) => srv.setAgentCard(agentCard),
      async (baseUrl) => {
        const res = await fetch(`${baseUrl}/a2a/message`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(buildEnvelope({
            type: 'peer/discover',
            payload: { card: agentCard } as any,
          })),
        });
        expect(res.status).toBe(200);
        const body = await res.json();
        expect(body.card).toEqual(agentCard);
      },
    );
  });

  it('peer/heartbeat returns ack', async () => {
    await withServer(
      () => {},
      async (baseUrl) => {
        const res = await fetch(`${baseUrl}/a2a/message`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(buildEnvelope({
            type: 'peer/heartbeat',
            payload: { trustScore: 85, activeTasks: 0, uptimeSeconds: 120 } as any,
          })),
        });
        expect(res.status).toBe(200);
        const body = await res.json();
        expect(body.ack).toBe(true);
      },
    );
  });
});

describe('A2AServer — tasks accessors', () => {
  it('getTasks returns tracked tasks', async () => {
    const handler: TaskHandler = async (p) => ({ taskId: p.taskId, status: 'completed' });
    await withServer(
      (srv) => srv.onTask(handler),
      async (baseUrl, srv) => {
        await fetch(`${baseUrl}/a2a/message`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(buildEnvelope()),
        });
        await waitUntil(() => srv.getTasks().length === 1);
        const tasks = srv.getTasks();
        expect(tasks[0].id).toBe('task:abc');
      },
    );
  });
});
