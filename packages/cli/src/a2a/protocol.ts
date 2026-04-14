/**
 * A2A Protocol — Agent-to-Agent Communication Protocol
 *
 * Implements Google's A2A specification adapted for Zero Trust:
 * - Every message is signed with the sender's DID
 * - Every peer is verified via AgentLayers Trust Mesh
 * - Circuit breakers protect against unreliable peers
 * - All interactions are audited and traced
 *
 * Message flow:
 * 1. Agent A discovers Agent B via registry or direct URL
 * 2. Agent A fetches B's AgentCard (/.well-known/agent.json)
 * 3. Agent A verifies B's DID signature + trust score
 * 4. Agent A sends a Task to B (signed)
 * 5. Agent B verifies A's signature, executes, returns result
 */

import type { AgentCard } from '@odin/core';

// ─── A2A Message Types ───

export type A2AMessageType =
  | 'task/send'       // Send a task to a peer
  | 'task/result'     // Return task result
  | 'task/status'     // Query task status
  | 'task/cancel'     // Cancel a running task
  | 'peer/discover'   // Discovery handshake
  | 'peer/heartbeat'  // Keep-alive
  | 'trust/query'     // Query peer's trust score
  | 'trust/report';   // Report trust incident

export interface A2AEnvelope {
  /** Protocol version */
  version: '1.0';
  /** Message type */
  type: A2AMessageType;
  /** Unique message ID */
  id: string;
  /** Sender DID */
  from: string;
  /** Recipient DID */
  to: string;
  /** ISO timestamp */
  timestamp: string;
  /** Ed25519 signature of the payload */
  signature: string;
  /** The actual payload */
  payload: A2APayload;
}

export type A2APayload =
  | TaskSendPayload
  | TaskResultPayload
  | TaskStatusPayload
  | TaskCancelPayload
  | PeerDiscoverPayload
  | PeerHeartbeatPayload
  | TrustQueryPayload
  | TrustReportPayload;

// ─── Task Payloads ───

export interface TaskSendPayload {
  /** Unique task ID */
  taskId: string;
  /** What the agent should do */
  instruction: string;
  /** Required capabilities for this task */
  requiredCapabilities: string[];
  /** Input data (taint-labeled) */
  input?: Record<string, unknown>;
  /** Maximum execution time in ms */
  timeoutMs?: number;
  /** Ephemeral credential for this task */
  credential?: {
    id: string;
    scope: string[];
    expiresAt: number;
    signature: string;
  };
}

export interface TaskResultPayload {
  /** Reference to the original task */
  taskId: string;
  /** Execution status */
  status: 'completed' | 'failed' | 'rejected' | 'timeout';
  /** Result content */
  result?: string;
  /** Error message if failed */
  error?: string;
  /** Execution time in ms */
  executionTimeMs?: number;
  /** Output taint label */
  outputIntegrity?: string;
}

export interface TaskStatusPayload {
  taskId: string;
  status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
  progress?: number; // 0-100
}

export interface TaskCancelPayload {
  taskId: string;
  reason: string;
}

// ─── Peer Payloads ───

export interface PeerDiscoverPayload {
  /** The discoverer's agent card */
  card: AgentCard;
  /** Capabilities being sought */
  seeking?: string[];
}

export interface PeerHeartbeatPayload {
  /** Agent's current trust score */
  trustScore: number;
  /** Number of active tasks */
  activeTasks: number;
  /** Uptime in seconds */
  uptimeSeconds: number;
}

// ─── Trust Payloads ───

export interface TrustQueryPayload {
  /** DID of the agent being queried about */
  targetDid: string;
}

export interface TrustReportPayload {
  /** DID of the reported agent */
  targetDid: string;
  /** Type of incident */
  incidentType: 'timeout' | 'invalid_response' | 'trust_violation' | 'signature_mismatch';
  /** Severity */
  severity: 'low' | 'medium' | 'high' | 'critical';
  /** Description */
  description: string;
}

// ─── A2A Task Tracking ───

export interface A2ATask {
  id: string;
  fromDid: string;
  toDid: string;
  instruction: string;
  status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled' | 'rejected';
  createdAt: number;
  completedAt?: number;
  result?: string;
  error?: string;
  executionTimeMs?: number;
}
