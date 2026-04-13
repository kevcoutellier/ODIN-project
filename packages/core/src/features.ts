/**
 * Odin Advanced Features
 *
 * Implements features found in OpenClaw and Hermes Agent:
 * - Model fallbacks + smart routing
 * - Context compression
 * - Thinking levels
 * - Tool profiles (allow/deny)
 * - Loop detection
 * - Subagent delegation
 * - Session reset
 * - Heartbeat
 * - Approval persistence
 * - Human delay
 */

import type { LLMConfig, LLMMessage, ThinkingLevel, ToolProfile, OdinConfig } from './types.js';

// ─── MODEL FALLBACKS ───

export class ModelFallbackChain {
  private currentIndex = 0;
  private failedModels: Set<string> = new Set();

  constructor(
    private primary: LLMConfig,
    private fallbacks: LLMConfig[] = [],
  ) {}

  getCurrent(): LLMConfig {
    if (this.currentIndex === 0) return this.primary;
    return this.fallbacks[this.currentIndex - 1] ?? this.primary;
  }

  markFailed(model: string): LLMConfig | null {
    this.failedModels.add(model);
    this.currentIndex++;
    if (this.currentIndex > this.fallbacks.length) {
      this.currentIndex = 0; // Loop back to primary
      return null; // All exhausted
    }
    return this.getCurrent();
  }

  reset(): void {
    this.currentIndex = 0;
    this.failedModels.clear();
  }

  getFailedModels(): string[] {
    return [...this.failedModels];
  }
}

// ─── SMART ROUTING ───

export function shouldUseSmartRouting(
  message: string,
  config: OdinConfig['llm']['smartRouting'],
): boolean {
  if (!config?.enabled) return false;
  return message.length <= config.maxSimpleChars && message.split(/\s+/).length <= config.maxSimpleWords;
}

// ─── CONTEXT COMPRESSION ───

export class ContextCompressor {
  constructor(
    private threshold: number = 0.5,
    private targetRatio: number = 0.2,
    private protectLastN: number = 20,
  ) {}

  shouldCompress(messages: LLMMessage[], maxTokens: number): boolean {
    // Rough estimate: 4 chars per token
    const estimatedTokens = messages.reduce((sum, m) => sum + m.content.length / 4, 0);
    return estimatedTokens / maxTokens >= this.threshold;
  }

  compress(messages: LLMMessage[]): { compressed: LLMMessage[]; summary: string } {
    if (messages.length <= this.protectLastN) {
      return { compressed: messages, summary: '' };
    }

    const protectedTail = messages.slice(-this.protectLastN);
    const toCompress = messages.slice(0, -this.protectLastN);

    // Build a summary of the compressed messages
    const summaryParts: string[] = [];
    for (const msg of toCompress) {
      const preview = msg.content.slice(0, 100);
      summaryParts.push(`[${msg.role}] ${preview}${msg.content.length > 100 ? '...' : ''}`);
    }

    const summary = `[Context compressed: ${toCompress.length} messages summarized]\n${summaryParts.slice(0, 10).join('\n')}${toCompress.length > 10 ? `\n... and ${toCompress.length - 10} more` : ''}`;

    const compressed: LLMMessage[] = [
      { role: 'system', content: summary },
      ...protectedTail,
    ];

    return { compressed, summary };
  }
}

// ─── THINKING LEVELS ───

const THINKING_DIRECTIVES: Record<ThinkingLevel, string> = {
  off: '',
  minimal: 'Think briefly before responding.',
  low: 'Think step by step.',
  medium: 'Think carefully and methodically about this problem.',
  high: 'Think very deeply. Consider multiple approaches, edge cases, and implications before responding.',
  xhigh: 'This requires your absolute deepest reasoning. Explore every angle, challenge your own assumptions, consider failure modes, and provide the most thorough analysis possible.',
  adaptive: '', // Let the model decide
};

export function getThinkingDirective(level: ThinkingLevel): string {
  return THINKING_DIRECTIVES[level] ?? '';
}

// ─── TOOL PROFILES ───

const TOOL_PROFILES: Record<ToolProfile, string[]> = {
  minimal: ['memory_search', 'memory_note', 'security_status', 'get_datetime'],
  safe: ['memory_search', 'memory_note', 'security_status', 'get_datetime', 'web_search', 'file_read', 'file_list', 'code_exec'],
  coding: ['memory_search', 'memory_note', 'security_status', 'get_datetime', 'web_search', 'file_read', 'file_write', 'file_list', 'code_exec', 'shell_exec', 'http_request'],
  full: ['*'], // All tools
  all: ['*'],
};

export function getToolsForProfile(profile: ToolProfile): string[] {
  return TOOL_PROFILES[profile] ?? ['*'];
}

export function isToolAllowed(
  toolName: string,
  config?: OdinConfig['tools'],
): boolean {
  if (!config) return true;

  // Profile check
  if (config.profile && config.profile !== 'full' && config.profile !== 'all') {
    const allowed = TOOL_PROFILES[config.profile];
    if (allowed && !allowed.includes('*') && !allowed.includes(toolName)) {
      return false;
    }
  }

  // Deny list takes precedence
  if (config.deny?.includes(toolName)) return false;

  // If allow list exists, tool must be in it
  if (config.allow && config.allow.length > 0) {
    return config.allow.includes(toolName);
  }

  return true;
}

// ─── LOOP DETECTION ───

export class LoopDetector {
  private history: Array<{ tool: string; args: string; timestamp: number }> = [];

  constructor(
    private historySize: number = 20,
    private warningThreshold: number = 3,
    private criticalThreshold: number = 5,
  ) {}

  record(toolName: string, args: Record<string, unknown>): {
    status: 'ok' | 'warning' | 'critical';
    repeats: number;
    message: string;
  } {
    const key = `${toolName}:${JSON.stringify(args)}`;
    this.history.push({ tool: key, args: JSON.stringify(args), timestamp: Date.now() });

    if (this.history.length > this.historySize) {
      this.history = this.history.slice(-this.historySize);
    }

    // Count consecutive identical calls
    let repeats = 0;
    for (let i = this.history.length - 1; i >= 0; i--) {
      if (this.history[i].tool === key) repeats++;
      else break;
    }

    if (repeats >= this.criticalThreshold) {
      return {
        status: 'critical',
        repeats,
        message: `Loop detected: ${toolName} called ${repeats} times consecutively. Breaking loop.`,
      };
    }

    if (repeats >= this.warningThreshold) {
      return {
        status: 'warning',
        repeats,
        message: `Possible loop: ${toolName} called ${repeats} times consecutively.`,
      };
    }

    return { status: 'ok', repeats, message: '' };
  }

  reset(): void {
    this.history = [];
  }
}

// ─── SUBAGENT DELEGATION ───

export interface DelegatedTask {
  id: string;
  goal: string;
  context: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  result?: string;
  startedAt: number;
  completedAt?: number;
  toolsets?: string[];
}

export class DelegationManager {
  private tasks: Map<string, DelegatedTask> = new Map();
  private running = 0;

  constructor(
    private maxConcurrent: number = 3,
    private maxDepth: number = 2,
  ) {}

  canDelegate(): boolean {
    return this.running < this.maxConcurrent;
  }

  createTask(goal: string, context: string, toolsets?: string[]): DelegatedTask | null {
    if (!this.canDelegate()) return null;

    const task: DelegatedTask = {
      id: `task-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      goal,
      context,
      status: 'pending',
      startedAt: Date.now(),
      toolsets,
    };

    this.tasks.set(task.id, task);
    return task;
  }

  markRunning(taskId: string): void {
    const task = this.tasks.get(taskId);
    if (task) { task.status = 'running'; this.running++; }
  }

  markCompleted(taskId: string, result: string): void {
    const task = this.tasks.get(taskId);
    if (task) {
      task.status = 'completed';
      task.result = result;
      task.completedAt = Date.now();
      this.running = Math.max(0, this.running - 1);
    }
  }

  markFailed(taskId: string, error: string): void {
    const task = this.tasks.get(taskId);
    if (task) {
      task.status = 'failed';
      task.result = error;
      task.completedAt = Date.now();
      this.running = Math.max(0, this.running - 1);
    }
  }

  getTask(taskId: string): DelegatedTask | undefined {
    return this.tasks.get(taskId);
  }

  getRunningTasks(): DelegatedTask[] {
    return [...this.tasks.values()].filter(t => t.status === 'running');
  }

  getAllTasks(): DelegatedTask[] {
    return [...this.tasks.values()];
  }
}

// ─── SESSION RESET ───

export class SessionManager {
  private lastActivity = Date.now();
  private listeners: Array<() => void> = [];

  constructor(
    private mode: 'none' | 'idle' | 'daily' | 'both' = 'none',
    private idleMinutes: number = 1440,
    private atHour: number = 4,
  ) {}

  recordActivity(): void {
    this.lastActivity = Date.now();
  }

  shouldReset(): boolean {
    if (this.mode === 'none') return false;

    if (this.mode === 'idle' || this.mode === 'both') {
      const idleMs = Date.now() - this.lastActivity;
      if (idleMs > this.idleMinutes * 60 * 1000) return true;
    }

    if (this.mode === 'daily' || this.mode === 'both') {
      const now = new Date();
      if (now.getHours() === this.atHour && now.getMinutes() === 0) return true;
    }

    return false;
  }

  onReset(listener: () => void): void {
    this.listeners.push(listener);
  }

  triggerReset(): void {
    for (const listener of this.listeners) listener();
  }
}

// ─── APPROVAL PERSISTENCE ───

export class ApprovalStore {
  private approvedOnce: Set<string> = new Set();
  private approvedSession: Set<string> = new Set();
  private approvedAlways: Set<string> = new Set();

  isApproved(toolName: string, persistence: 'once' | 'session' | 'always'): boolean {
    if (this.approvedAlways.has(toolName)) return true;
    if (persistence !== 'once' && this.approvedSession.has(toolName)) return true;
    if (this.approvedOnce.has(toolName)) {
      this.approvedOnce.delete(toolName); // Once = consumed after check
      return true;
    }
    return false;
  }

  approve(toolName: string, persistence: 'once' | 'session' | 'always'): void {
    switch (persistence) {
      case 'once': this.approvedOnce.add(toolName); break;
      case 'session': this.approvedSession.add(toolName); break;
      case 'always': this.approvedAlways.add(toolName); break;
    }
  }

  resetSession(): void {
    this.approvedOnce.clear();
    this.approvedSession.clear();
  }

  getApproved(): { once: string[]; session: string[]; always: string[] } {
    return {
      once: [...this.approvedOnce],
      session: [...this.approvedSession],
      always: [...this.approvedAlways],
    };
  }
}

// ─── HEARTBEAT ───

export class HeartbeatManager {
  private timer: ReturnType<typeof setInterval> | null = null;
  private handler: (() => Promise<void>) | null = null;

  constructor(
    private enabled: boolean = false,
    private intervalMs: number = 300000,
  ) {}

  onBeat(handler: () => Promise<void>): void {
    this.handler = handler;
  }

  start(): void {
    if (!this.enabled || this.timer) return;
    this.timer = setInterval(async () => {
      try { await this.handler?.(); } catch { /* heartbeat failures are silent */ }
    }, this.intervalMs);
  }

  stop(): void {
    if (this.timer) { clearInterval(this.timer); this.timer = null; }
  }
}

// ─── HUMAN DELAY ───

export async function applyHumanDelay(
  mode: 'off' | 'natural' | 'custom',
  minMs: number = 800,
  maxMs: number = 2500,
): Promise<void> {
  if (mode === 'off') return;

  let delay: number;
  if (mode === 'natural') {
    // Natural typing simulation: 800-2500ms with gaussian-like distribution
    delay = 800 + Math.random() * 1700;
  } else {
    delay = minMs + Math.random() * (maxMs - minMs);
  }

  await new Promise(resolve => setTimeout(resolve, delay));
}
