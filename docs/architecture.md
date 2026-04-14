# Odin by AgentLayers — System Architecture

**Zero Trust AI Agent, Secured by Design, Trusted by Network**

## 1. Overview

Odin is an open-source Zero Trust AI agent framework built as a TypeScript monorepo. Unlike traditional AI agents that assume tool outputs and peer interactions are trustworthy, Odin treats **every data flow, tool invocation, and agent interaction as potentially compromised**. This "never trust, always verify" paradigm is enforced at every layer through four integrated subsystems.

### Design Principles

1. **Identity-First**: Every Odin instance has a unique DID (Decentralized Identifier) based on Ed25519 cryptographic keys. All actions are signed.
2. **Least Privilege**: Tools execute in sandboxed rings (0-2) with taint-tracked inputs/outputs. No tool gets more access than needed.
3. **Continuous Verification**: Trust scores are computed from real-time metrics, not static config. The system degrades gracefully as trust decreases.
4. **Defense in Depth**: Four independent subsystems (Security, Trust, Cognition, Observability) provide overlapping protection layers.

## 2. Monorepo Structure

```
packages/
  core/           Types, DualLLMRouter, MemoryStore, features
  security/       DIDManager, IFCEngine, PolicyEngine, SandboxManager
  trust/          AgentLayersClient, TrustScoreManager, CircuitBreaker
  cognition/      EpisodicStore, CIK, MCTS, Causal, Evolution, Self-Improvement
  cli/            OdinAgent orchestrator, gateways, A2A protocol
  dashboard/      Real-time WebSocket dashboard
  observability/  AuditLog, DecisionTracer, ComplianceReporter
```

## 3. The Four Subsystems

### 3.1 Security Perimeter

The Security subsystem implements the **CaMeL (CApabilities for Machine Learning) model** — a dual-LLM architecture where security controls cannot be bypassed by prompt injection.

| Component | Purpose | Innovation |
|-----------|---------|------------|
| **DIDManager** | Decentralized identity with Ed25519 keypair | `did:odin:<fingerprint>` with ephemeral task-scoped credentials |
| **IFCEngine** | Information Flow Control with taint tracking | Lattice-based integrity propagation (TRUSTED > DERIVED > UNTRUSTED) |
| **PolicyEngine** | Cedar-inspired policy evaluation | Sub-millisecond evaluation with runtime policy loading |
| **SandboxManager** | 3-ring execution isolation | Ring 0 (read-only, no network) to Ring 2 (full access with approval) |

**Data Flow Security**: Every piece of data carries a `TaintLabel` with integrity level, confidentiality level, source, and timestamp. When data from multiple sources is combined, the output inherits the **lowest integrity** and **highest confidentiality** — ensuring tainted data cannot escalate privileges.

### 3.2 Trust Mesh

The Trust subsystem implements a distributed trust network where agents verify each other through the AgentLayers protocol.

| Component | Purpose | Innovation |
|-----------|---------|------------|
| **AgentLayersClient** | API client for the AgentLayers trust network | Skill scanning, MCP server scanning, A2A agent verification |
| **TrustScoreManager** | Real-time trust score computation | 6-dimensional scoring: performance, transparency, security, compliance, reputation, reliability |
| **CircuitBreaker** | 5-state protection for peer interactions | CLOSED → DEGRADED → OPEN → HALF_OPEN (the DEGRADED state is an Odin innovation) |

**Trust Modes**: The agent operates in one of three modes computed from live metrics:
- **SAFE** (score >= 75): Full autonomous operation
- **CAUTION** (score >= 50): Elevated logging, restricted tool access
- **DEGRADED** (score < 50): Blocks execution, requires intervention

### 3.3 Cognitive Architecture (3 Phases)

The Cognition subsystem gives Odin reasoning, memory, and self-improvement capabilities.

**Phase 1 — Foundation**:
- **EpisodicStore**: Graph-based episodic memory with entities, edges, BFS neighborhood, temporal decay
- **CIK Taxonomy**: Capabilities, Identity, Knowledge — the three pillars of agent self-awareness
- **ModelFirstReasoner**: Maintains a world model, generates predictions, tracks counterfactuals

**Phase 2 — Autonomy**:
- **SleepAgent**: Offline memory consolidation (entity merging, weak memory pruning, pattern extraction)
- **EvolutionSandbox**: Sandboxed self-modification with rollback (T1→T2→T3→T4 tier progression, safety gate)
- **A-MEM Controller**: Trajectory-based procedural memory (records tool call sequences, compresses into reusable procedures)

**Phase 3 — Advanced Reasoning**:
- **MCTS Planner**: Monte Carlo Tree Search with UCB1 selection for hierarchical goal planning
- **CausalEngine**: Full Structural Causal Model (SCM) with L1 Association, L2 Intervention (do-calculus), L3 Counterfactual (Pearl's 3-step)
- **CIK Invariant Verifier**: TLA+-inspired formal invariants for runtime safety verification
- **Self-Improvement Loop**: Closed-loop failure analysis → causal diagnosis → counterfactual improvement

### 3.4 Observability

| Component | Purpose |
|-----------|---------|
| **AuditLog** | Append-only log of all security decisions and tool executions |
| **DecisionTracer** | Span-based tracing for the entire decision pipeline |
| **ComplianceReporter** | EU AI Act, OWASP ASI, Singapore MGF, SLSA compliance tracking |

## 4. Message Processing Pipeline

When a user sends a message, it flows through this pipeline:

```
User Message
    │
    ├─1─ IFC Label (TRUSTED source tagging)
    ├─2─ Trust Mode Recomputation (live metrics)
    ├─3─ Session Management (idle/daily reset)
    ├─4─ Context Compression (optional, at 75% limit)
    ├─5─ Privileged LLM Planning (tool call generation)
    │
    ├─6─ Tool Execution Pipeline (for each tool call):
    │     ├── Tool Profile Check (allow/deny list)
    │     ├── Loop Detection (histogram-based)
    │     ├── Approval Persistence (once/session/always)
    │     ├── IFC Taint Validation
    │     ├── Cedar Policy Evaluation
    │     ├── Audit Log Recording
    │     └── Sandbox Execution (Ring 0/1/2)
    │
    ├─7─ Cognition Integration:
    │     ├── A-MEM trajectory compression
    │     ├── Auto-evolution (every 10 chats)
    │     ├── Self-improvement cycle (every 15 chats)
    │     └── Invariant verification (every 25 chats)
    │
    └─8─ Response + Dashboard Sync
```

## 5. Gateway Architecture

Odin supports multiple message delivery platforms through a pluggable gateway system:

| Gateway | Protocol | Features |
|---------|----------|----------|
| **CLI** | WebSocket (Dashboard) | Default, real-time dashboard UI |
| **Telegram** | Bot API (long polling) | Groups with @mention, /commands, Markdown |
| **Discord** | Gateway API v10 (WebSocket) | Guilds, DMs, typing indicators, reconnection |
| **Slack** | Planned | — |
| **WhatsApp** | Planned | — |

All gateways implement the `BaseGateway` abstract class:
- User allowlist filtering
- @mention requirement for group chats
- Automatic routing to `agent.chat()`
- Long message splitting per platform limits

## 6. A2A Protocol

The Agent-to-Agent protocol enables inter-agent communication with Zero Trust guarantees:

### Discovery
```
GET /.well-known/agent.json → AgentCard {name, did, capabilities, endpoints, trustScore, signature}
```

### Message Types
| Type | Direction | Purpose |
|------|-----------|---------|
| `task/send` | → Peer | Delegate a task with scoped credentials |
| `task/result` | ← Peer | Return execution result |
| `task/status` | → Peer | Query task progress |
| `task/cancel` | → Peer | Cancel running task |
| `peer/discover` | ↔ | Mutual agent discovery |
| `peer/heartbeat` | → Peer | Keep-alive with trust score |
| `trust/query` | → Peer | Query peer's trust reputation |
| `trust/report` | → Network | Report trust incident |

### Security Properties
1. Every message is signed with the sender's Ed25519 key
2. Peer AgentCards are verified via AgentLayers Trust Mesh
3. Circuit breakers protect against unreliable peers
4. Ephemeral credentials are task-scoped and time-limited
5. All A2A interactions are audited

## 7. Dashboard

The real-time dashboard provides a 3-column UI with 5 sections:

| Section | Content |
|---------|---------|
| **Identity** | Agent name, DID, trust mode, gateway status, uptime, LLM model |
| **KPIs** | Trust score, skills installed, agents connected, alerts, tokens today |
| **AEGIS Security** | IFC Engine, Supply Chain Scanner, Policy Engine, Trust Mesh — each with real-time metrics |
| **Activity Log** | Timestamped log of tool calls, chats, A2A interactions, security decisions |
| **Decision Trace** | Allow/Warn/Block decisions with emitter, action, detail, and layer |

All dashboard data is computed from real agent state — **zero mocked values**.

## 8. Deployment

### Docker
```bash
docker compose up -d          # Start Odin
docker compose logs -f odin   # Follow logs
```

### CI/CD (GitHub Actions)
- **Build & Test**: Node.js 20 + 22 matrix
- **Security Audit**: `pnpm audit`
- **Docker Build**: Multi-stage with BuildX + GHA cache
- **Release**: Automatic GHCR push + GitHub Release on `release:` commits
