/**
 * A2A Client — Send messages to peer agents
 *
 * Handles:
 * - Agent discovery via /.well-known/agent.json
 * - Signed message sending
 * - Task lifecycle management
 * - Automatic retry with circuit breaker integration
 */

import type { AgentCard } from '@odin/core';
import type {
  A2AEnvelope, A2AMessageType, A2APayload,
  TaskSendPayload, TaskResultPayload, PeerDiscoverPayload,
} from './protocol.js';
import { randomUUID } from 'node:crypto';

export interface A2AClientConfig {
  /** Our DID for signing */
  agentDid: string;
  /** Signing function (Ed25519) */
  signFn: (data: string) => string;
  /** Default timeout for requests */
  timeoutMs?: number;
}

export class A2AClient {
  /** Cache of discovered agent cards */
  private knownPeers: Map<string, AgentCard> = new Map();
  private readonly timeout: number;

  constructor(private readonly config: A2AClientConfig) {
    this.timeout = config.timeoutMs ?? 30000;
  }

  // ─── Discovery ───

  /**
   * Discover a peer agent by fetching its AgentCard.
   * The card is cached for subsequent interactions.
   */
  async discover(baseUrl: string): Promise<AgentCard> {
    const url = `${baseUrl.replace(/\/$/, '')}/.well-known/agent.json`;
    const res = await fetch(url, {
      signal: AbortSignal.timeout(this.timeout),
    });

    if (!res.ok) {
      throw new Error(`Discovery failed for ${baseUrl}: ${res.status}`);
    }

    const card = await res.json() as AgentCard;
    this.knownPeers.set(card.did, card);
    return card;
  }

  /**
   * Announce ourselves to a peer agent (mutual discovery).
   */
  async announce(peerUrl: string, ourCard: AgentCard): Promise<AgentCard | null> {
    const payload: PeerDiscoverPayload = {
      card: ourCard,
    };

    const response = await this.sendRaw(peerUrl, 'peer/discover', ourCard.did, payload) as Record<string, unknown> | null;
    if (response?.card) {
      const peerCard = response.card as AgentCard;
      this.knownPeers.set(peerCard.did, peerCard);
      return peerCard;
    }
    return null;
  }

  /**
   * Get a cached peer card by DID.
   */
  getPeer(did: string): AgentCard | undefined {
    return this.knownPeers.get(did);
  }

  /**
   * Get all known peers.
   */
  getAllPeers(): AgentCard[] {
    return [...this.knownPeers.values()];
  }

  /** Register a peer directly (e.g., from config or registry). */
  registerPeer(card: AgentCard): void {
    this.knownPeers.set(card.did, card);
  }

  // ─── Task Operations ───

  /**
   * Send a task to a peer agent.
   * Returns the task acknowledgment or throws on failure.
   */
  async sendTask(
    peerDid: string,
    instruction: string,
    options?: {
      requiredCapabilities?: string[];
      input?: Record<string, unknown>;
      timeoutMs?: number;
      credential?: TaskSendPayload['credential'];
    },
  ): Promise<{ taskId: string; status: string }> {
    const peer = this.knownPeers.get(peerDid);
    if (!peer) {
      throw new Error(`Unknown peer: ${peerDid}. Discover it first.`);
    }

    const taskId = `task:${randomUUID()}`;
    const payload: TaskSendPayload = {
      taskId,
      instruction,
      requiredCapabilities: options?.requiredCapabilities ?? [],
      input: options?.input,
      timeoutMs: options?.timeoutMs,
      credential: options?.credential,
    };

    const response = await this.send(peer, 'task/send', payload);
    return response as { taskId: string; status: string };
  }

  /**
   * Poll a task's status until completion.
   */
  async waitForTask(
    peerDid: string,
    taskId: string,
    pollIntervalMs = 2000,
    maxWaitMs = 60000,
  ): Promise<TaskResultPayload> {
    const peer = this.knownPeers.get(peerDid);
    if (!peer) throw new Error(`Unknown peer: ${peerDid}`);

    const deadline = Date.now() + maxWaitMs;
    while (Date.now() < deadline) {
      const url = `${peer.endpoints.a2a}/a2a/tasks/${taskId}`;
      const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
      if (res.ok) {
        const task = await res.json() as { status: string; result?: string; error?: string; executionTimeMs?: number };
        if (task.status === 'completed' || task.status === 'failed' || task.status === 'cancelled') {
          return {
            taskId,
            status: task.status as TaskResultPayload['status'],
            result: task.result,
            error: task.error,
            executionTimeMs: task.executionTimeMs,
          };
        }
      }
      await new Promise(r => setTimeout(r, pollIntervalMs));
    }

    return { taskId, status: 'timeout', error: `Task did not complete within ${maxWaitMs}ms` };
  }

  /**
   * Send a heartbeat to a peer.
   */
  async heartbeat(peerDid: string, trustScore: number, activeTasks: number, uptimeSeconds: number): Promise<boolean> {
    const peer = this.knownPeers.get(peerDid);
    if (!peer) return false;

    try {
      await this.send(peer, 'peer/heartbeat', { trustScore, activeTasks, uptimeSeconds });
      return true;
    } catch {
      return false;
    }
  }

  // ─── Internal ───

  private async send(peer: AgentCard, type: A2AMessageType, payload: A2APayload): Promise<unknown> {
    return this.sendRaw(peer.endpoints.a2a, type, peer.did, payload);
  }

  private async sendRaw(baseUrl: string, type: A2AMessageType, toDid: string, payload: A2APayload): Promise<unknown> {
    const payloadStr = JSON.stringify(payload);
    const signature = this.config.signFn(payloadStr);

    const envelope: A2AEnvelope = {
      version: '1.0',
      type,
      id: randomUUID(),
      from: this.config.agentDid,
      to: toDid,
      timestamp: new Date().toISOString(),
      signature,
      payload,
    };

    const url = `${baseUrl.replace(/\/$/, '')}/a2a/message`;
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(envelope),
      signal: AbortSignal.timeout(this.timeout),
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`A2A request failed (${res.status}): ${text}`);
    }

    return res.json();
  }
}
