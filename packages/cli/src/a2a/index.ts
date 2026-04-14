/**
 * A2A Protocol — Agent-to-Agent Communication
 */

export {
  type A2AEnvelope, type A2AMessageType, type A2APayload,
  type TaskSendPayload, type TaskResultPayload, type TaskStatusPayload, type TaskCancelPayload,
  type PeerDiscoverPayload, type PeerHeartbeatPayload,
  type TrustQueryPayload, type TrustReportPayload,
  type A2ATask,
} from './protocol.js';

export { A2AServer, type A2AServerConfig, type TaskHandler, type SignatureVerifier } from './server.js';
export { A2AClient, type A2AClientConfig } from './client.js';
