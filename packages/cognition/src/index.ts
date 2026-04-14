// Episodic Memory (Graphiti-inspired graph store)
export {
  EpisodicStore, type Entity, type Edge, type Episode,
  type EpisodicQuery, type EpisodicSearchResult,
} from './episodic/index.js';

// CIK Stores (Capability / Identity / Knowledge)
export {
  CIKStore, CIKPolicyEngine,
  type CapabilityEntry, type IdentityEntry, type KnowledgeEntry,
  type CIKPolicy, type TrustTier, TRUST_TIER_CONFIDENCE,
} from './cik/index.js';

// Model-First Reasoning
export {
  ModelFirstReasoner,
  type WorldState, type ReasoningStep, type Plan, type PlanStep, type Counterfactual,
} from './reasoning/index.js';

// Sleep Agent (Phase 2 — Episodic→Semantic Consolidation)
export {
  SleepAgent,
  type SleepCycleResult, type SleepAgentConfig,
} from './sleep/index.js';

// Evolution Sandbox (Phase 2 — Transactional Knowledge Evolution)
export {
  SafetyGate, EvolutionSandbox,
  type SafetyGateResult, type SafetyCheck, type EvolutionProposal,
} from './evolution/index.js';

// A-MEM Procedural Memory (Phase 2 — Trajectory Compression)
export {
  AMEMController,
  type ToolCallRecord, type Trajectory, type Procedure,
  type ProcedureStep, type ProcedureMatch,
} from './amem/index.js';

// MCTS Hierarchical Planner (Phase 3 — World Model & Planning)
export {
  MCTSPlanner, HierarchicalPlanner,
  type MCTSConfig, type MCTSState, type MCTSAction, type MCTSNode,
  type MCTSPlan, type HierarchicalGoal,
  type ActionGenerator, type RewardEstimator, type StateTransition,
} from './planning/index.js';

// Causal Reasoning (Phase 3 — SCM + do-queries + counterfactuals)
export {
  CausalEngine,
  type CausalVariable, type CausalEdge, type StructuralEquation,
  type CausalModel, type CausalQuery, type CausalResult,
  type CounterfactualQuestion,
} from './causal/index.js';

// TLA+ Formal Invariants (Phase 3 — CIK safety properties)
export {
  CIKInvariantVerifier,
  type InvariantCheck, type InvariantResult, type InvariantViolation,
  type InvariantReport,
} from './invariants/index.js';

// Counterfactual Self-Improvement (Phase 3 — closed-loop learning)
export {
  SelfImprovementLoop,
  type FailureRecord, type ImprovementInsight, type SelfImprovementReport,
} from './selfimprove/index.js';
