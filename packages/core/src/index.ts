// Types
export * from './types.js';

// LLM Router
export { DualLLMRouter, type DualLLMRouterEvents } from './llm-router/index.js';
export { createAdapter, type LLMProviderAdapter } from './llm-router/index.js';

// Memory
export { MemoryStore, type MemoryStoreOptions } from './memory/index.js';
export { MerkleTree, sha256 } from './memory/index.js';

// Advanced Features
export {
  ModelFallbackChain, shouldUseSmartRouting, ContextCompressor,
  getThinkingDirective, getToolsForProfile, isToolAllowed,
  LoopDetector, DelegationManager, SessionManager,
  ApprovalStore, HeartbeatManager, applyHumanDelay,
  type DelegatedTask,
} from './features.js';
