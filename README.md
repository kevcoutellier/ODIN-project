# Odin

**Zero Trust AI Agent — Secured by Design, Trusted by Network.**

Odin is an open-source autonomous AI agent built on Zero Trust principles. Every action is verified, every data flow is tracked, and nothing is trusted by default. Built by [AgentLayers](https://agent-layers.com).

> **M2 Research Project** — Odin is the reference implementation accompanying the master's thesis *"Zero Trust Security Architecture for Autonomous LLM Agents"*. See [`docs/thesis_odin_zero_trust_agent.docx`](docs/thesis_odin_zero_trust_agent.docx) and the scientific review in [`docs/annexe-revue-scientifique.md`](docs/annexe-revue-scientifique.md).

---

## Table of Contents

- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [LLM Configuration](#llm-configuration)
- [Dashboard](#dashboard)
- [A2A Protocol & Gateways](#a2a-protocol--gateways)
- [Design Principles](#design-principles)
- [Tech Stack](#tech-stack)
- [Development](#development)
- [Security](#security)
- [Documentation](#documentation)
- [License](#license)

---

## Architecture

Odin is organized as a TypeScript monorepo of **7 packages** built around 4 subsystems.

### 1. Core Runtime — `@odin/core`

The execution backbone of the agent.

- **LLM Router** — Dual-LLM CaMeL pattern with a *privileged* model (planning, tool calls) and a *quarantined* model (untrusted output processing)
- **Provider Adapters** — `AnthropicAdapter`, `OpenAIAdapter`, `OllamaAdapter`, and `NullAdapter` (boot with no LLM, plug one in at runtime)
- **Memory Store** — SQLite + FTS5 full-text search with Merkle tree integrity verification
- **Skill Loader** — Dynamic capability loading with security scanning

### 2. Security Perimeter — `@odin/security`

Local, free, always-on security layer.

- **IFC Engine** — FIDES-inspired Information Flow Control with dual-lattice taint tracking (integrity × confidentiality)
- **Sandbox Manager** — Docker / gVisor execution isolation with Ring 0 / 1 / 2 privilege levels
- **Policy Engine** — Cedar-inspired declarative access policies, sub-millisecond evaluation
- **DID Manager** — Ed25519 decentralized identity, signed messages, ephemeral task-scoped credentials

### 3. Trust Mesh — `@odin/trust`

Network-level trust verification via the AgentLayers API (optional paid tier — the agent is fully functional without it).

- **Trust Score** — 6-dimensional live evaluation (performance, transparency, security, compliance, reputation, reliability)
- **Circuit Breaker** — 5-state protection: `CLOSED → DEGRADED → OPEN → HALF_OPEN` (DEGRADED is an Odin innovation)
- **Skill / MCP / A2A Scanners** — Static and dynamic supply-chain analysis
- **EU AI Act Compliance** — Regulatory-aware decision logging

### 4. Cognition — `@odin/cognition` *(new)*

Reasoning, memory and self-improvement, organised in three progressive phases.

| Phase | Components |
|-------|------------|
| **Phase 1 — Foundation** | `EpisodicStore` (Graphiti-style graph memory), `CIK` taxonomy (Capabilities / Identity / Knowledge), `ModelFirstReasoner` (world model + counterfactuals) |
| **Phase 2 — Autonomy** | `SleepAgent` (offline consolidation), `EvolutionSandbox` (T1→T4 tier progression with rollback), `AMEMController` (trajectory-compressed procedural memory) |
| **Phase 3 — Advanced Reasoning** | `MCTSPlanner` + `HierarchicalPlanner`, `CausalEngine` (Pearl's 3-level SCM with do-calculus), `CIKInvariantVerifier` (TLA+-inspired formal invariants), `SelfImprovementLoop` (closed-loop failure analysis) |

### 5. Observability — `@odin/observability` + `@odin/dashboard`

Full visibility into agent behaviour.

- **OpenTelemetry** — Distributed tracing for every decision and action
- **DecisionTracer** — Step-by-step reasoning audit trail
- **AuditLog** — Append-only, tamper-evident log
- **ComplianceReporter** — EU AI Act, OWASP ASI, Singapore MGF, SLSA tracking
- **Dashboard** — Real-time WebSocket UI with live KPIs, AEGIS panel, hover tooltips on every setting

---

## Project Structure

```
odin/
├── packages/
│   ├── cli/               # CLI entry point, OdinAgent orchestrator
│   │   ├── src/
│   │   │   ├── a2a/       # Agent-to-Agent protocol (client, server, discovery)
│   │   │   └── gateways/  # Telegram, Discord, base gateway
│   ├── core/              # LLM router, memory, provider adapters
│   ├── security/          # IFC, sandbox, policies, DID
│   ├── trust/             # Trust scoring, circuit breaker, scanners
│   ├── cognition/         # Episodic, CIK, MCTS, causal, evolution
│   ├── observability/     # Tracing, audit logs, compliance
│   └── dashboard/         # Real-time monitoring UI
├── docs/
│   ├── architecture.md
│   ├── security-model.md
│   ├── cognitive-architecture.md
│   ├── annexe-revue-scientifique.md    # Scientific review (annex)
│   ├── thesis_odin_zero_trust_agent.docx
│   └── generate-thesis.cjs
├── .github/workflows/ci.yml            # GitHub Actions CI
├── Dockerfile
├── docker-compose.yml
├── odin.yaml                           # Agent configuration
├── vitest.config.ts
├── pnpm-workspace.yaml
└── package.json
```

---

## Getting Started

### Prerequisites

- Node.js ≥ 20
- pnpm ≥ 8
- *(Optional)* [Ollama](https://ollama.ai), an Anthropic API key, or an OpenAI API key

> **You do NOT need an LLM to boot.** Odin launches in "no LLM" mode and you can plug one in later from the dashboard, the `/llm` CLI command, or environment variables.

### Installation

```bash
git clone https://github.com/kevcoutellier/ODIN-project.git
cd ODIN-project
pnpm install
pnpm build
```

### Running

```bash
# Start the agent in interactive CLI mode
pnpm start

# Development mode with hot reload
pnpm dev

# Show security status and exit
pnpm start -- --status

# Use a custom config file
pnpm start -- --config ./my-odin.yaml
```

### Running with Docker

```bash
docker compose up -d          # Start Odin
docker compose logs -f odin   # Follow logs
```

---

## LLM Configuration

Odin supports **four providers** selected at runtime. API keys are read from the environment; the provider is auto-detected if any of them is set.

| Provider | Environment variable | Auto-selected model (privileged / quarantined) |
|----------|----------------------|-------------------------------------------------|
| Anthropic | `ANTHROPIC_API_KEY` | `claude-sonnet-4` / `claude-haiku-4-5` |
| OpenAI    | `OPENAI_API_KEY`    | `gpt-4o` / `gpt-4o-mini` |
| Ollama    | `OLLAMA_BASE_URL` or `OLLAMA_HOST` | `gemma3` / `gemma3` |
| None      | *(nothing set)*     | `NullAdapter` — agent boots, dashboard works, chat returns a configure-me notice |

You can also force a provider with `ODIN_LLM_PROVIDER=anthropic|openai|ollama|none`.

### Hot-swapping the LLM at runtime

```bash
# From the CLI
/llm anthropic claude-sonnet-4
/llm ollama gemma3 http://localhost:11434
/llm none                      # detach — agent stays alive

# Or via the Dashboard → LLM settings panel
# (Provider dropdown, Model, API Key, Max Tokens, Temperature)
```

### Built-in CLI commands

```
/status              Show trust score, mode, and decision counters
/memory <query>      Search episodic memory
/llm <provider> …    Switch the LLM at runtime
/quit                Graceful shutdown
```

---

## Dashboard

The dashboard is served at `http://localhost:3333` (port configurable via `odin.yaml`). It renders live agent state over WebSocket — **no mocked values**.

- **Identity & KPIs** — DID, trust mode, uptime, tokens used, installed skills, connected agents
- **AEGIS panel** — IFC Engine, Supply Chain Scanner, Policy Engine, Trust Mesh with real-time metrics
- **Activity log & Decision trace** — timestamped tool calls, chats, A2A interactions, Allow / Warn / Block decisions
- **Settings** — LLM, Skills, MCP, Memory, Gateway, Security, Terminal, Cron — every form field has a hover tooltip describing what it does
- **Compliance card** — EU AI Act, OWASP ASI, Singapore MGF coverage

---

## A2A Protocol & Gateways

### Agent-to-Agent protocol

Odin agents discover and talk to each other over a signed A2A protocol:

```
GET /.well-known/agent.json  → AgentCard {did, capabilities, endpoints, trustScore, signature}
```

Message types include `task/send`, `task/result`, `task/status`, `task/cancel`, `peer/discover`, `peer/heartbeat`, `trust/query`, `trust/report`. Every message is Ed25519-signed; peer AgentCards are verified via the AgentLayers Trust Mesh; circuit breakers protect against flaky peers.

### Messaging gateways

| Gateway | Protocol | Status |
|---------|----------|--------|
| CLI / Dashboard | WebSocket | ✅ Default |
| Telegram | Bot API (long polling) | ✅ Shipped |
| Discord  | Gateway API v10 (WebSocket) | ✅ Shipped |
| Slack / WhatsApp | — | 🚧 Planned |

All gateways share the `BaseGateway` abstract class: user allow-list, `@mention` requirement for group chats, automatic routing to `agent.chat()`, long-message splitting.

---

## Design Principles

| Principle | Implementation |
|-----------|---------------|
| **Zero Trust** | Every input, tool output, and peer message is verified — nothing is implicitly trusted |
| **Security is architectural** | Enforced through IFC taint tracking, sandboxing, and CaMeL — not statistical guardrails |
| **Free security, paid trust** | Local security features are free & open source; network trust verification is via AgentLayers |
| **Defense in depth** | Ring sandboxing + Cedar policies + IFC + DID signing = layered protection |
| **Optional by design** | No LLM, no AgentLayers account, no Docker required — the agent still boots and runs locally |

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Runtime | Node.js / TypeScript (ES2022) |
| LLMs | Anthropic, OpenAI, Ollama, or none (NullAdapter) |
| Database | SQLite + FTS5 + Merkle trees |
| Security | IFC taint tracking, Cedar-style policies, Ed25519 (TweetNaCl) |
| Sandbox | Docker / gVisor, Ring 0–2 |
| Cognition | Graph episodic memory, MCTS + UCB1, Pearl SCM, TLA+-inspired invariants |
| Observability | OpenTelemetry, WebSocket dashboard |
| Monorepo | pnpm workspaces |
| Testing | Vitest (150+ tests across core / security / trust / cognition) |
| CI / Packaging | GitHub Actions, Dockerfile, docker-compose |

---

## Development

```bash
pnpm build          # Build all 7 packages
pnpm test           # Run the full Vitest suite
pnpm lint           # Lint
pnpm dev            # Hot-reload dev mode
```

### Running a single package test

```bash
pnpm --filter @odin/cognition test
pnpm --filter @odin/security test
```

---

## Security

Odin addresses the [OWASP Agentic Security Initiative (ASI) 2026](https://owasp.org/) top-10 risks for autonomous AI agents. See [`docs/security-model.md`](docs/security-model.md) for the full threat model and mitigations.

If you discover a vulnerability, please report it responsibly to **security@agent-layers.com** rather than opening a public issue.

---

## Documentation

| Document | Contents |
|----------|----------|
| [`docs/architecture.md`](docs/architecture.md) | System architecture, message pipeline, subsystem interactions |
| [`docs/security-model.md`](docs/security-model.md) | Threat model, CaMeL, IFC lattices, sandbox rings |
| [`docs/cognitive-architecture.md`](docs/cognitive-architecture.md) | Three-phase cognitive design, CIK, MCTS, causal engine |
| [`docs/annexe-revue-scientifique.md`](docs/annexe-revue-scientifique.md) | **Annex — Scientific review (French)** accompanying the M2 thesis |
| [`docs/thesis_odin_zero_trust_agent.docx`](docs/thesis_odin_zero_trust_agent.docx) | M2 thesis manuscript |

---

## License

[MIT](LICENSE)
