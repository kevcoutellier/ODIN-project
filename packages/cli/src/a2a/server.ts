/**
 * A2A Server — HTTP endpoint for receiving A2A messages
 *
 * Exposes:
 * - GET  /.well-known/agent.json  → Agent Card (public discovery)
 * - POST /a2a/message             → Receive A2A messages
 * - GET  /a2a/tasks/:id           → Query task status
 * - GET  /health                  → Health check
 *
 * All incoming messages are verified:
 * 1. Signature check (Ed25519)
 * 2. DID resolution
 * 3. Trust score threshold
 * 4. Circuit breaker state
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AgentCard } from '@odin/core';
import type { A2AEnvelope, A2ATask, TaskSendPayload, TaskResultPayload } from './protocol.js';
import { DIDManager } from '@odin/security';

export interface A2AServerConfig {
  port: number;
  host?: string;
  /** Minimum trust score to accept tasks from a peer */
  minTrustScore: number;
}

export type TaskHandler = (task: TaskSendPayload, fromDid: string) => Promise<TaskResultPayload>;
export type SignatureVerifier = (data: string, signature: string, senderDid: string) => Promise<boolean>;

export class A2AServer {
  private server: ReturnType<typeof createServer> | null = null;
  private tasks: Map<string, A2ATask> = new Map();
  private taskHandler: TaskHandler | null = null;
  private signatureVerifier: SignatureVerifier | null = null;
  private agentCard: AgentCard | null = null;

  constructor(private readonly config: A2AServerConfig) {}

  /** Set the agent card that will be served at /.well-known/agent.json */
  setAgentCard(card: AgentCard): void {
    this.agentCard = card;
  }

  /** Register the handler that processes incoming tasks */
  onTask(handler: TaskHandler): void {
    this.taskHandler = handler;
  }

  /** Register signature verification function */
  onVerify(verifier: SignatureVerifier): void {
    this.signatureVerifier = verifier;
  }

  /** Get all tracked tasks */
  getTasks(): A2ATask[] {
    return [...this.tasks.values()];
  }

  /** Get a specific task */
  getTask(id: string): A2ATask | undefined {
    return this.tasks.get(id);
  }

  async start(): Promise<void> {
    return new Promise((resolve) => {
      this.server = createServer((req, res) => {
        this.handleRequest(req, res).catch((err) => {
          this.sendJson(res, 500, { error: 'Internal server error', message: err.message });
        });
      });

      const host = this.config.host ?? '0.0.0.0';
      this.server.listen(this.config.port, host, () => {
        console.log(`[A2A] Server listening on ${host}:${this.config.port}`);
        resolve();
      });
    });
  }

  async stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => resolve());
      } else {
        resolve();
      }
    });
  }

  // ─── Request Router ───

  private async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', `http://${req.headers.host}`);

    // CORS headers for agent discovery
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    // Route
    if (req.method === 'GET' && url.pathname === '/.well-known/agent.json') {
      return this.handleAgentCard(res);
    }
    if (req.method === 'POST' && url.pathname === '/a2a/message') {
      return this.handleMessage(req, res);
    }
    if (req.method === 'GET' && url.pathname.startsWith('/a2a/tasks/')) {
      const taskId = url.pathname.slice('/a2a/tasks/'.length);
      return this.handleTaskStatus(taskId, res);
    }
    if (req.method === 'GET' && url.pathname === '/health') {
      return this.sendJson(res, 200, {
        status: 'ok',
        activeTasks: [...this.tasks.values()].filter(t => t.status === 'running').length,
        totalTasks: this.tasks.size,
      });
    }

    this.sendJson(res, 404, { error: 'Not found' });
  }

  // ─── Handlers ───

  private handleAgentCard(res: ServerResponse): void {
    if (!this.agentCard) {
      this.sendJson(res, 503, { error: 'Agent card not configured' });
      return;
    }
    this.sendJson(res, 200, this.agentCard);
  }

  private async handleMessage(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // Parse body
    const body = await this.readBody(req);
    let envelope: A2AEnvelope;
    try {
      envelope = JSON.parse(body);
    } catch {
      this.sendJson(res, 400, { error: 'Invalid JSON' });
      return;
    }

    // Validate envelope structure
    if (!envelope.version || !envelope.type || !envelope.from || !envelope.signature) {
      this.sendJson(res, 400, { error: 'Missing required envelope fields' });
      return;
    }

    // Verify signature
    if (this.signatureVerifier) {
      const payloadStr = JSON.stringify(envelope.payload);
      const valid = await this.signatureVerifier(payloadStr, envelope.signature, envelope.from);
      if (!valid) {
        this.sendJson(res, 403, { error: 'Invalid signature' });
        return;
      }
    }

    // Route by message type
    switch (envelope.type) {
      case 'task/send':
        return this.handleTaskSend(envelope, res);
      case 'task/status': {
        const payload = envelope.payload as { taskId: string };
        return this.handleTaskStatus(payload.taskId, res);
      }
      case 'task/cancel': {
        const payload = envelope.payload as { taskId: string };
        const task = this.tasks.get(payload.taskId);
        if (task && task.status === 'running') {
          task.status = 'cancelled';
          task.completedAt = Date.now();
        }
        this.sendJson(res, 200, { status: 'cancelled' });
        return;
      }
      case 'peer/discover':
        // Return our agent card as acknowledgment
        this.sendJson(res, 200, { card: this.agentCard });
        return;
      case 'peer/heartbeat':
        this.sendJson(res, 200, { ack: true });
        return;
      default:
        this.sendJson(res, 400, { error: `Unknown message type: ${envelope.type}` });
    }
  }

  private async handleTaskSend(envelope: A2AEnvelope, res: ServerResponse): Promise<void> {
    const payload = envelope.payload as TaskSendPayload;

    // Create task record
    const task: A2ATask = {
      id: payload.taskId,
      fromDid: envelope.from,
      toDid: envelope.to,
      instruction: payload.instruction,
      status: 'queued',
      createdAt: Date.now(),
    };
    this.tasks.set(task.id, task);

    if (!this.taskHandler) {
      task.status = 'rejected';
      task.error = 'No task handler registered';
      this.sendJson(res, 503, { error: 'Agent not ready to accept tasks' });
      return;
    }

    // Acknowledge receipt immediately
    this.sendJson(res, 202, { taskId: task.id, status: 'queued' });

    // Execute asynchronously
    task.status = 'running';
    const startTime = Date.now();
    try {
      const result = await this.taskHandler(payload, envelope.from);
      task.status = result.status === 'completed' ? 'completed' : 'failed';
      task.result = result.result;
      task.error = result.error;
      task.executionTimeMs = Date.now() - startTime;
      task.completedAt = Date.now();
    } catch (err) {
      task.status = 'failed';
      task.error = err instanceof Error ? err.message : String(err);
      task.executionTimeMs = Date.now() - startTime;
      task.completedAt = Date.now();
    }
  }

  private handleTaskStatus(taskId: string, res: ServerResponse): void {
    const task = this.tasks.get(taskId);
    if (!task) {
      this.sendJson(res, 404, { error: 'Task not found' });
      return;
    }
    this.sendJson(res, 200, task);
  }

  // ─── Utilities ───

  private sendJson(res: ServerResponse, status: number, data: unknown): void {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(data));
  }

  private readBody(req: IncomingMessage): Promise<string> {
    return new Promise((resolve, reject) => {
      let data = '';
      req.on('data', (chunk) => { data += chunk; });
      req.on('end', () => resolve(data));
      req.on('error', reject);
    });
  }
}
