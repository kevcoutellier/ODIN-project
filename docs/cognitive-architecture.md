# Odin Cognitive Architecture — Three-Phase Agent Intelligence

## Overview

Odin's cognitive architecture is built in three progressive phases, each adding deeper reasoning and autonomy. Unlike monolithic agent systems, each phase is independently testable and contributes to the agent's overall intelligence through clearly defined interfaces.

## Phase 1: Foundation — Memory & Reasoning

### 1.1 Episodic Memory (Graph-Based)

Odin maintains a graph-based episodic memory store backed by SQLite, combining entity tracking with relationship inference.

**Data Model**:
```
Entities ──[edges]──→ Entities
   │                      │
   └── Episodes ──────────┘
```

- **Entities**: Named concepts with types, observation counts, and temporal decay
- **Edges**: Typed relationships between entities (e.g., `"used_by"`, `"depends_on"`) with weights
- **Episodes**: Contextual groupings of related entities (conversation turns, task sessions)
- **BFS Neighborhood**: Retrieves the local graph around a concept, enabling associative recall

**Key Innovation**: Temporal decay with configurable half-life. Entities not reinforced by new observations fade over time, preventing memory bloat while preserving frequently-accessed knowledge.

### 1.2 CIK Taxonomy (Capabilities, Identity, Knowledge)

The CIK Taxonomy is Odin's self-awareness model — it defines what the agent **can do** (Capabilities), **who it is** (Identity), and **what it knows** (Knowledge).

**Capabilities**:
```typescript
{
  name: "web_search",
  trustTier: "T2",          // Requires T2 trust level
  constraints: ["rate_limited", "public_data_only"],
  lastVerified: 1713052800000
}
```

**Identity**:
```typescript
{
  did: "did:odin:a1b2c3d4...",
  trustTier: "T1",           // Current tier (T1 → T4 progression)
  immutableSince: 1713052800000,
  signatureValid: true
}
```

**Knowledge**:
```typescript
{
  fact: "Tool X returns JSON with field Y",
  confidence: 0.87,
  source: "observation:tool_call:42",
  tier: "T2",
  contradictions: 0,
  lastVerified: 1713052800000
}
```

**Policies**: CIK policies define rules like "Knowledge with confidence < 0.3 must be flagged" or "Capabilities above T3 require human verification". These are evaluated before tool execution.

### 1.3 Model-First Reasoning

The ModelFirstReasoner maintains an internal **world model** — a set of beliefs about the current state of the environment, updated with each observation.

**Reasoning Pipeline**:
```
Observe → Update World Model → Generate Predictions → Plan → Verify → Act
```

- **Observations**: Each tool result updates the world model with structured state changes
- **Predictions**: Before acting, the reasoner predicts outcomes. Post-action, predictions are compared to reality — discrepancies trigger learning.
- **Counterfactuals**: "What would have happened if I had chosen action B instead of A?" — used for offline improvement

## Phase 2: Autonomy — Evolution & Memory Consolidation

### 2.1 Sleep Agent

Inspired by biological memory consolidation, the SleepAgent runs during idle periods to:

1. **Entity Merging**: Identifies and merges duplicate or near-duplicate entities in episodic memory
2. **Weak Memory Pruning**: Removes entities with decay below threshold
3. **Pattern Extraction**: Identifies recurring tool call patterns and converts them to procedural memory
4. **Contradiction Resolution**: Resolves conflicting knowledge entries in CIK

### 2.2 Evolution Sandbox

Odin can **modify its own behavior** through a controlled evolution mechanism:

**Trust Tier Progression**:
```
T1 (Default)
  └─── Evidence + Safety Gate ───→ T2 (Verified)
                                      └─── Evidence + Safety Gate ───→ T3 (Trusted)
                                                                          └─── Evidence + Safety Gate ───→ T4 (Autonomous)
```

**Safety Gate**: Every evolution proposal must pass through the SafetyGate before application:
- **No tier skipping**: T1 → T3 is blocked (must go T1 → T2 → T3)
- **Evidence required**: Each tier upgrade requires documented evidence
- **Rollback**: Failed evolutions are automatically reverted

**Evolution Proposals**:
```typescript
{
  type: 'capability_upgrade' | 'knowledge_update' | 'behavior_change',
  description: "Enable web_search at T2",
  evidence: ["10 successful searches", "0 violations in last 50 calls"],
  requiredTier: 'T2',
  rollbackPlan: "Revert capability to T1, disable web_search"
}
```

### 2.3 A-MEM Controller (Procedural Memory)

The Augmented Memory (A-MEM) Controller converts raw experience into reusable procedures:

**Trajectory Recording**:
```
Start Trajectory → [Tool Call 1] → [Tool Call 2] → ... → End Trajectory
```

Each trajectory captures:
- User instruction (input)
- Sequence of tool calls with arguments and results
- Success/failure outcome
- Total execution time

**Compression**: Long trajectories are compressed into procedural summaries — e.g., "To deploy code: 1) run tests, 2) build, 3) push, 4) deploy". These are stored as retrievable procedures for future similar tasks.

## Phase 3: Advanced Reasoning — Planning, Causality, and Self-Improvement

### 3.1 MCTS Hierarchical Planner

Odin uses **Monte Carlo Tree Search (MCTS)** for complex multi-step planning:

**Algorithm**:
```
for each iteration:
  1. SELECT:   Traverse tree using UCB1 (balance exploration/exploitation)
  2. EXPAND:   Generate possible next actions
  3. SIMULATE: Rollout to estimate future reward
  4. BACKPROP: Update node statistics along the path
```

**Configuration**:
```typescript
{
  maxIterations: 100,     // MCTS iterations per planning step
  maxDepth: 8,            // Maximum plan depth
  maxBranching: 5,        // Actions per expansion
  explorationConstant: √2 // UCB1 exploration parameter
}
```

**Hierarchical Goals**: High-level goals decompose into sub-goals, each with its own MCTS tree. Sub-goal completion propagates upward automatically.

### 3.2 Causal Reasoning Engine (Pearl's Ladder)

Odin implements Judea Pearl's three-level causal hierarchy using **Structural Causal Models (SCM)**:

**Level 1 — Association (Seeing)**:
```
P(Y | X) — "What is Y when I observe X?"
```
Uses topological sort to propagate observations through the causal graph. Pure correlation, no intervention.

**Level 2 — Intervention (Doing)**:
```
P(Y | do(X)) — "What happens to Y if I force X?"
```
Implements do-calculus via **graph mutilation**: removes all incoming edges to the intervened variable, then propagates. This separates causal effect from mere correlation.

**Level 3 — Counterfactual (Imagining)**:
```
P(Y_x | X', Y') — "Would Y have been different if X had been different, given what actually happened?"
```
Implements Pearl's 3-step algorithm:
1. **Abduction**: Infer unobserved variables from actual observations
2. **Action**: Apply the counterfactual intervention (graph mutilation)
3. **Prediction**: Propagate through the modified model

**Application**: After a tool failure, the CausalEngine builds a failure model:
```
tool_input → tool_config → tool_execution → tool_output → task_outcome
```
Then runs counterfactual queries: "Would the task have succeeded if the tool config had been different?" — generating actionable improvement insights.

### 3.3 TLA+ Formal Invariants

Six runtime invariants verify CIK safety properties continuously:

| Invariant | Severity | Check |
|-----------|----------|-------|
| `KNOWLEDGE_CONSISTENCY` | Warning | All knowledge entries have confidence in [0, 1] |
| `CONFIDENCE_BOUNDS` | Error | No confidence values outside valid range |
| `TIER_CONFIDENCE_ALIGNMENT` | Warning | Higher tiers require higher minimum confidence |
| `TEMPORAL_ORDERING` | Error | lastVerified timestamps are not in the future |
| `IDENTITY_IMMUTABILITY` | Critical | DID has not changed since initialization |
| `KNOWLEDGE_CONTRADICTION_RATIO` | Warning | Contradictions are below 10% of total knowledge |

**Health Status**: Based on invariant results:
- `HEALTHY`: All invariants pass
- `DEGRADED`: Only warnings
- `CRITICAL`: Any error-level violation
- `UNSAFE`: Any critical-level violation

### 3.4 Counterfactual Self-Improvement Loop

The closed-loop improvement system continuously learns from failures:

```
┌──────────────────────────────────────────────────┐
│                                                  │
│  Record Failure ──→ Causal Analysis              │
│        │              │                          │
│        │          Build SCM from failure context  │
│        │              │                          │
│        │         Run Counterfactual Queries       │
│        │              │                          │
│        │         Generate Improvement Insights    │
│        │              │                          │
│        │         Apply to:                        │
│        │           ├── CIK Knowledge Store        │
│        │           ├── World Model                │
│        │           └── Evolution Sandbox          │
│        │                                          │
│        └──────────── Next Cycle ─────────────────┘
│                                                  │
└──────────────────────────────────────────────────┘
```

**Failure Sources**:
- `tool_failure`: Tool execution returned an error
- `prediction_error`: World model prediction was wrong
- `evolution_rejected`: Evolution proposal was rejected by safety gate
- `plan_failure`: MCTS plan did not achieve its goal
- `invariant_violation`: A formal invariant was violated

**Cycle Frequency**: Self-improvement runs every 15 chat interactions, with invariant verification every 25 interactions.

## Integration with Security

The cognitive architecture is not isolated — it is integrated with the security subsystem at every level:

1. **CIK policies are evaluated before tool execution** (not just security policies)
2. **Evolution proposals must pass the SafetyGate** (no uncontrolled self-modification)
3. **Invariant violations trigger trust score degradation** (cognitive failures affect trust)
4. **Causal analysis uses taint labels** (understanding data provenance in failure diagnosis)
5. **MCTS plans respect sandbox ring constraints** (plans cannot propose Ring 2 actions without approval)

This integration ensures that intelligence gains never come at the cost of security — the two systems reinforce each other.
