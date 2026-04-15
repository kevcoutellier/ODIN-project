/**
 * A2A client tests — signed envelope construction, discovery, task lifecycle.
 *
 * The client is responsible for:
 *   - Fetching and caching peer AgentCards (discovery).
 *   - Constructing signed envelopes (signFn is called on payload JSON).
 *   - Refusing to send to unknown peers.
 *
 * fetch is mocked; no real network I/O.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { A2AClient } from '../client.js';
import type { AgentCard } from '@odin/core';

const peerCard: AgentCard = {
  name: 'Peer Agent',
  did: 'did:odin:peer-abc',
  description: 'A peer',
  capabilities: ['chat', 'search'],
  endpoints: {
    a2a: 'https://peer.example',
    health: 'https://peer.example/health',
  },
};

const ourCard: AgentCard = {
  name: 'Odin',
  did: 'did:odin:self-xyz',
  description: 'Zero Trust agent',
  capabilities: ['chat'],
  endpoints: {
    a2a: 'https://self.example',
    health: 'https://self.example/health',
  },
};

function mockOk<T>(body: T): Response {
  return {
    ok: true, status: 200, statusText: 'OK',
    json: async () => body,
    text: async () => JSON.stringify(body),
  } as unknown as Response;
}

function mockFail(status: number, body: unknown = 'error'): Response {
  return {
    ok: false, status, statusText: 'Error',
    json: async () => body,
    text: async () => (typeof body === 'string' ? body : JSON.stringify(body)),
  } as unknown as Response;
}

const signed: string[] = [];
const signFn = (data: string) => {
  signed.push(data);
  return `ed25519:${data.length}`;
};

beforeEach(() => {
  signed.length = 0;
  vi.restoreAllMocks();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('A2AClient — discovery', () => {
  it('discover() fetches /.well-known/agent.json and caches the peer', async () => {
    const fetchSpy = vi.fn().mockResolvedValue(mockOk(peerCard));
    vi.stubGlobal('fetch', fetchSpy);

    const client = new A2AClient({ agentDid: 'did:odin:self', signFn });
    const card = await client.discover('https://peer.example');

    expect(card).toEqual(peerCard);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const [url] = fetchSpy.mock.calls[0];
    expect(url).toBe('https://peer.example/.well-known/agent.json');

    // Cached
    expect(client.getPeer(peerCard.did)).toEqual(peerCard);
    expect(client.getAllPeers()).toHaveLength(1);
  });

  it('discover() strips trailing slash from baseUrl', async () => {
    const fetchSpy = vi.fn().mockResolvedValue(mockOk(peerCard));
    vi.stubGlobal('fetch', fetchSpy);
    const client = new A2AClient({ agentDid: 'did:odin:self', signFn });
    await client.discover('https://peer.example/');
    const [url] = fetchSpy.mock.calls[0];
    expect(url).toBe('https://peer.example/.well-known/agent.json');
  });

  it('discover() throws on non-2xx response', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(mockFail(404)));
    const client = new A2AClient({ agentDid: 'did:odin:self', signFn });
    await expect(client.discover('https://peer.example')).rejects.toThrow(/Discovery failed/);
  });

  it('registerPeer() adds a peer without HTTP call', () => {
    const client = new A2AClient({ agentDid: 'did:odin:self', signFn });
    client.registerPeer(peerCard);
    expect(client.getPeer(peerCard.did)).toEqual(peerCard);
  });

  it('announce() sends peer/discover and caches the returned card', async () => {
    const fetchSpy = vi.fn().mockResolvedValue(mockOk({ card: peerCard }));
    vi.stubGlobal('fetch', fetchSpy);
    const client = new A2AClient({ agentDid: 'did:odin:self', signFn });
    const returned = await client.announce('https://peer.example', ourCard);
    expect(returned).toEqual(peerCard);
    expect(client.getPeer(peerCard.did)).toEqual(peerCard);
    const [url] = fetchSpy.mock.calls[0];
    expect(url).toBe('https://peer.example/a2a/message');
  });

  it('announce() returns null if response has no card', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(mockOk({})));
    const client = new A2AClient({ agentDid: 'did:odin:self', signFn });
    const returned = await client.announce('https://peer.example', ourCard);
    expect(returned).toBeNull();
  });
});

describe('A2AClient — signed envelope construction', () => {
  it('sendTask signs the payload and POSTs an envelope with all required fields', async () => {
    const fetchSpy = vi.fn().mockResolvedValue(mockOk({ taskId: 't1', status: 'queued' }));
    vi.stubGlobal('fetch', fetchSpy);

    const client = new A2AClient({ agentDid: 'did:odin:self', signFn });
    client.registerPeer(peerCard);

    const result = await client.sendTask(peerCard.did, 'summarize the news', {
      requiredCapabilities: ['web.fetch'],
      input: { url: 'https://example.com' },
    });

    expect(result.status).toBe('queued');
    expect(fetchSpy).toHaveBeenCalledTimes(1);

    const [url, init] = fetchSpy.mock.calls[0];
    expect(url).toBe('https://peer.example/a2a/message');
    expect(init.method).toBe('POST');
    expect(init.headers['Content-Type']).toBe('application/json');

    const envelope = JSON.parse(init.body);
    expect(envelope.version).toBe('1.0');
    expect(envelope.type).toBe('task/send');
    expect(envelope.from).toBe('did:odin:self');
    expect(envelope.to).toBe(peerCard.did);
    expect(envelope.id).toBeTruthy();
    expect(envelope.timestamp).toBeTruthy();
    expect(envelope.signature).toMatch(/^ed25519:/);

    // Signed data is the JSON-serialised payload (stable ordering)
    expect(signed).toHaveLength(1);
    const reconstructed = JSON.stringify(envelope.payload);
    expect(signed[0]).toBe(reconstructed);

    expect(envelope.payload.instruction).toBe('summarize the news');
    expect(envelope.payload.requiredCapabilities).toEqual(['web.fetch']);
    expect(envelope.payload.input).toEqual({ url: 'https://example.com' });
    expect(envelope.payload.taskId).toMatch(/^task:/);
  });

  it('sendTask throws for unknown peer', async () => {
    const client = new A2AClient({ agentDid: 'did:odin:self', signFn });
    await expect(client.sendTask('did:odin:unknown', 'hi')).rejects.toThrow(/Unknown peer/);
  });

  it('throws when the peer rejects the message (non-2xx)', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(mockFail(403, 'Invalid signature')));
    const client = new A2AClient({ agentDid: 'did:odin:self', signFn });
    client.registerPeer(peerCard);
    await expect(client.sendTask(peerCard.did, 'hi')).rejects.toThrow(/A2A request failed \(403\)/);
  });
});

describe('A2AClient — heartbeat', () => {
  it('heartbeat() returns false for unknown peer without calling fetch', async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);
    const client = new A2AClient({ agentDid: 'did:odin:self', signFn });
    const ok = await client.heartbeat('did:odin:unknown', 80, 0, 123);
    expect(ok).toBe(false);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('heartbeat() returns true on success', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(mockOk({ ack: true })));
    const client = new A2AClient({ agentDid: 'did:odin:self', signFn });
    client.registerPeer(peerCard);
    expect(await client.heartbeat(peerCard.did, 85, 2, 1000)).toBe(true);
  });

  it('heartbeat() returns false when the peer errors out', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('ECONNREFUSED')));
    const client = new A2AClient({ agentDid: 'did:odin:self', signFn });
    client.registerPeer(peerCard);
    expect(await client.heartbeat(peerCard.did, 85, 2, 1000)).toBe(false);
  });
});

describe('A2AClient — waitForTask', () => {
  it('returns result on completion', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(mockOk({
      status: 'completed', result: 'done', executionTimeMs: 42,
    })));
    const client = new A2AClient({ agentDid: 'did:odin:self', signFn });
    client.registerPeer(peerCard);
    const outcome = await client.waitForTask(peerCard.did, 'task:1', 10, 1000);
    expect(outcome.status).toBe('completed');
    expect(outcome.result).toBe('done');
    expect(outcome.executionTimeMs).toBe(42);
  });

  it('returns timeout status when maxWaitMs elapses without completion', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(mockOk({
      status: 'running',
    })));
    const client = new A2AClient({ agentDid: 'did:odin:self', signFn });
    client.registerPeer(peerCard);
    const outcome = await client.waitForTask(peerCard.did, 'task:1', 30, 100);
    expect(outcome.status).toBe('timeout');
    expect(outcome.error).toMatch(/did not complete/);
  });

  it('throws for unknown peer', async () => {
    const client = new A2AClient({ agentDid: 'did:odin:self', signFn });
    await expect(client.waitForTask('did:odin:unknown', 'task:1')).rejects.toThrow(/Unknown peer/);
  });
});
