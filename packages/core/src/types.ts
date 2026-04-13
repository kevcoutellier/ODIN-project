/**
 * Odin Core Types
 * Zero Trust AI Agent — Type definitions for the entire system
 */

// ─── Integrity & Confidentiality Labels (IFC) ───

export enum IntegrityLevel {
  TRUSTED = 'TRUSTED',
  DERIVED = 'DERIVED',
  UNTRUSTED = 'UNTRUSTED',
}

export enum ConfidentialityLevel {
  PUBLIC = 'PUBLIC',
  SENSITIVE = 'SENSITIVE',
  SECRET = 'SECRET',
}

export interface TaintLabel {
  integrity: IntegrityLevel;
  confidentiality: ConfidentialityLevel;
  source: string;
  timestamp: number;
}

export interface TaintedData<T = unknown> {
  value: T;
  label: TaintLabel;
}

// ─── LLM Router ───

export type LLMProvider = 'anthropic' | 'openai' | 'ollama';

export interface LLMConfig {
  provider: LLMProvider;
  model: string;
  apiKey?: string;
  baseUrl?: string;
  maxTokens?: number;
  temperature?: number;
}

export interface DualLLMConfig {
  privileged: LLMConfig;
  quarantined: LLMConfig;
}

export interface LLMMessage {
  role: 'system' | 'user' | 'assistant' | 'tool';
  content: string;
  name?: string;
  toolCallId?: string;
}

export interface LLMResponse {
  content: string;
  toolCalls?: ToolCall[];
  usage?: { inputTokens: number; outputTokens: number };
  model: string;
  label: TaintLabel;
}

export interface ToolCall {
  id: string;
  name: string;
  arguments: Record<string, unknown>;
}

// ─── Tools & Skills ───

export type SandboxRing = 0 | 1 | 2;

export interface ToolDefinition {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
  ring: SandboxRing;
  requiredPermissions: string[];
}

export interface ToolResult {
  toolCallId: string;
  content: string;
  label: TaintLabel;
  success: boolean;
  executionTimeMs: number;
}

export type SkillTrustTier = 0 | 1 | 2;

export interface SkillManifest {
  name: string;
  version: string;
  description: string;
  author: string;
  tools: ToolDefinition[];
  trustTier: SkillTrustTier;
  signature?: string;
  agentLayersScore?: number;
}

// ─── Memory ───

export interface MemoryEntry {
  id: string;
  sessionId: string;
  type: 'note' | 'session' | 'procedure';
  content: string;
  label: TaintLabel;
  merkleHash: string;
  createdAt: number;
  updatedAt: number;
}

export interface MerkleProof {
  root: string;
  path: Array<{ hash: string; position: 'left' | 'right' }>;
  leaf: string;
}

// ─── DID (Decentralized Identity) ───

export interface OdinDID {
  id: string; // did:odin:<fingerprint>
  publicKey: string; // base64 Ed25519 public key
  created: number;
  capabilities: string[];
  trustScore?: number;
}

export interface DIDDocument {
  '@context': string[];
  id: string;
  verificationMethod: Array<{
    id: string;
    type: string;
    controller: string;
    publicKeyBase64: string;
  }>;
  authentication: string[];
  capabilities: string[];
  trustScore?: number;
  trustScoreHistory?: Array<{ score: number; timestamp: number }>;
}

// ─── Policy Engine ───

export interface PolicyDecision {
  allowed: boolean;
  reason: string;
  policy: string;
  evaluationTimeMs: number;
  conditions: Record<string, unknown>;
}

export interface PolicyContext {
  agentDid: string;
  action: string;
  resource: string;
  trustScore: number;
  sessionTtl: number;
  dailyCalls: number;
  humanApproval: boolean;
  ring: SandboxRing;
  taintLabel: TaintLabel;
}

// ─── Trust Score (AgentLayers) ───

export interface TrustScore {
  overall: number;
  dimensions: {
    performance: number;
    transparency: number;
    security: number;
    compliance: number;
    reputation: number;
    reliability: number;
  };
  timestamp: number;
  certifiedBy: string;
}

export type TrustMode = 'SAFE' | 'CAUTION' | 'DEGRADED';

export function trustModeFromScore(score: number): TrustMode {
  if (score >= 75) return 'SAFE';
  if (score >= 50) return 'CAUTION';
  return 'DEGRADED';
}

// ─── Circuit Breaker ───

export type CircuitBreakerState = 'CLOSED' | 'DEGRADED' | 'OPEN' | 'HALF_OPEN';

export interface CircuitBreakerConfig {
  failureThreshold: number;
  degradedThreshold: number;
  recoveryTimeout: number;
  halfOpenMaxAttempts: number;
}

// ─── Agent Card (A2A Protocol) ───

export interface AgentCard {
  name: string;
  did: string;
  description: string;
  capabilities: string[];
  endpoints: {
    a2a: string;
    health: string;
  };
  trustScore?: number;
  signature?: string;
}

// ─── Observability ───

export interface AuditLogEntry {
  id: string;
  timestamp: number;
  agentDid: string;
  action: string;
  resource: string;
  decision: PolicyDecision;
  taintLabel: TaintLabel;
  trustScore: number;
  signature: string;
}

export interface DecisionTrace {
  traceId: string;
  spans: Array<{
    spanId: string;
    parentSpanId?: string;
    name: string;
    startTime: number;
    endTime: number;
    attributes: Record<string, unknown>;
  }>;
}

// ─── Configuration ───

// ─── Thinking / Reasoning Levels ───

export type ThinkingLevel = 'off' | 'minimal' | 'low' | 'medium' | 'high' | 'xhigh' | 'adaptive';

// ─── Tool Profile ───

export type ToolProfile = 'minimal' | 'safe' | 'coding' | 'full' | 'all';

// ─── Configuration ───

export interface OdinConfig {
  agent: {
    name: string;
    description: string;
    personality?: string;
    maxTurns?: number;
    reasoningEffort?: ThinkingLevel;
    workspaceFiles?: { // Context files like SOUL.md, AGENTS.md, USER.md
      agentsMd?: string;
      userMd?: string;
      toolsMd?: string;
      bootMd?: string;
    };
  };
  llm: DualLLMConfig & {
    fallbacks?: LLMConfig[]; // Fallback models tried in order
    smartRouting?: { // Route simple messages to cheaper model
      enabled: boolean;
      maxSimpleChars: number;
      maxSimpleWords: number;
      cheapModel: LLMConfig;
    };
    thinking?: ThinkingLevel;
  };
  memory: {
    dbPath: string;
    maxEntries: number;
    nudgeInterval?: number;
  };
  security: {
    defaultRing: SandboxRing;
    requireHumanApproval: string[];
    maxDailyCalls: number;
    sessionTtlSeconds: number;
    approvalMode?: 'manual' | 'smart' | 'off';
    approvalPersistence?: 'once' | 'session' | 'always'; // Remember approvals
    redactSecrets?: boolean;
    websiteBlocklist?: string[];
    loopDetection?: {
      enabled: boolean;
      historySize: number;
      warningThreshold: number;
      criticalThreshold: number;
    };
  };
  tools?: {
    profile?: ToolProfile;
    allow?: string[];
    deny?: string[];
  };
  trust: {
    agentLayersApiKey?: string;
    agentLayersBaseUrl: string;
    selfAuditIntervalSeconds: number;
    trustDecayHalfLifeDays: number;
  };
  gateway: {
    type: 'cli' | 'telegram' | 'discord' | 'slack' | 'whatsapp';
    telegramToken?: string;
    discordToken?: string;
    slackToken?: string;
    whatsappEnabled?: boolean;
    allowedUsers?: string[];
    requireMention?: boolean;
    streaming?: boolean;
    humanDelay?: { mode: 'off' | 'natural' | 'custom'; minMs?: number; maxMs?: number };
    sessionReset?: { mode: 'none' | 'idle' | 'daily' | 'both'; idleMinutes?: number; atHour?: number };
  };
  terminal: {
    backend?: 'local' | 'docker' | 'ssh';
    timeout?: number;
    dockerImage?: string;
    sshHost?: string;
    sshUser?: string;
    sshPort?: number;
  };
  compression?: {
    enabled: boolean;
    threshold: number; // Trigger at this % of context limit (0.0-1.0)
    targetRatio: number; // Keep this fraction as recent (0.0-1.0)
    protectLastN: number; // Always keep last N messages
  };
  delegation?: {
    enabled: boolean;
    maxConcurrent: number;
    maxDepth: number;
    defaultToolsets?: string[];
  };
  heartbeat?: {
    enabled: boolean;
    intervalMs: number;
    prompt?: string;
  };
  cron: {
    jobs?: Array<{
      name: string;
      schedule: string;
      prompt: string;
      enabled: boolean;
    }>;
  };
  observability: {
    otelEndpoint?: string;
    auditLogPath: string;
    dashboardPort: number;
  };
}
