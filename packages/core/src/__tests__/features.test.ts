import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  ModelFallbackChain,
  shouldUseSmartRouting,
  ContextCompressor,
  getThinkingDirective,
  getToolsForProfile,
  isToolAllowed,
  LoopDetector,
  DelegationManager,
  SessionManager,
  ApprovalStore,
  HeartbeatManager,
  applyHumanDelay,
} from '../features.js';
import type { LLMConfig, LLMMessage } from '../types.js';

// ─── ModelFallbackChain ───

describe('ModelFallbackChain', () => {
  const primary: LLMConfig = { provider: 'ollama', model: 'gemma4', baseUrl: '' };
  const fb1: LLMConfig = { provider: 'openai', model: 'gpt-4', baseUrl: '' };
  const fb2: LLMConfig = { provider: 'anthropic', model: 'claude-3', baseUrl: '' };

  it('returns primary by default', () => {
    const chain = new ModelFallbackChain(primary, [fb1, fb2]);
    expect(chain.getCurrent().model).toBe('gemma4');
  });

  it('falls through to fallbacks on failure', () => {
    const chain = new ModelFallbackChain(primary, [fb1, fb2]);
    chain.markFailed('gemma4');
    expect(chain.getCurrent().model).toBe('gpt-4');
    chain.markFailed('gpt-4');
    expect(chain.getCurrent().model).toBe('claude-3');
  });

  it('returns null when all exhausted', () => {
    const chain = new ModelFallbackChain(primary, [fb1]);
    chain.markFailed('gemma4');
    const result = chain.markFailed('gpt-4');
    expect(result).toBeNull();
  });

  it('resets correctly', () => {
    const chain = new ModelFallbackChain(primary, [fb1]);
    chain.markFailed('gemma4');
    chain.reset();
    expect(chain.getCurrent().model).toBe('gemma4');
    expect(chain.getFailedModels()).toHaveLength(0);
  });
});

// ─── Smart Routing ───

describe('shouldUseSmartRouting', () => {
  it('returns false when disabled', () => {
    expect(shouldUseSmartRouting('hello', { enabled: false, maxSimpleChars: 100, maxSimpleWords: 10, cheapModel: { provider: 'ollama', model: 'gemma4', baseUrl: '', maxTokens: 1024, temperature: 0.3 } })).toBe(false);
  });

  it('returns true for short messages', () => {
    expect(shouldUseSmartRouting('hello world', { enabled: true, maxSimpleChars: 100, maxSimpleWords: 10, cheapModel: { provider: 'ollama', model: 'gemma4', baseUrl: '', maxTokens: 1024, temperature: 0.3 } })).toBe(true);
  });

  it('returns false for long messages', () => {
    const long = 'a '.repeat(50);
    expect(shouldUseSmartRouting(long, { enabled: true, maxSimpleChars: 20, maxSimpleWords: 5, cheapModel: { provider: 'ollama', model: 'gemma4', baseUrl: '', maxTokens: 1024, temperature: 0.3 } })).toBe(false);
  });
});

// ─── ContextCompressor ───

describe('ContextCompressor', () => {
  const compressor = new ContextCompressor(0.5, 0.2, 5);

  it('detects when compression is needed', () => {
    const msgs: LLMMessage[] = Array.from({ length: 100 }, (_, i) => ({
      role: 'user' as const,
      content: 'x'.repeat(1000),
    }));
    expect(compressor.shouldCompress(msgs, 50000)).toBe(true);
  });

  it('does not compress below threshold', () => {
    const msgs: LLMMessage[] = [{ role: 'user', content: 'short' }];
    expect(compressor.shouldCompress(msgs, 100000)).toBe(false);
  });

  it('protects last N messages', () => {
    const msgs: LLMMessage[] = Array.from({ length: 20 }, (_, i) => ({
      role: 'user' as const,
      content: `Message ${i}`,
    }));
    const { compressed } = compressor.compress(msgs);
    // Protected last 5 + 1 summary = 6
    expect(compressed.length).toBe(6);
    expect(compressed[compressed.length - 1].content).toBe('Message 19');
  });

  it('returns original when under protectLastN', () => {
    const msgs: LLMMessage[] = [
      { role: 'user', content: 'A' },
      { role: 'assistant', content: 'B' },
    ];
    const { compressed } = compressor.compress(msgs);
    expect(compressed).toEqual(msgs);
  });
});

// ─── Thinking Levels ───

describe('getThinkingDirective', () => {
  it('returns empty for off', () => {
    expect(getThinkingDirective('off')).toBe('');
  });

  it('returns content for high', () => {
    expect(getThinkingDirective('high')).toContain('deeply');
  });

  it('returns content for medium', () => {
    expect(getThinkingDirective('medium')).toContain('carefully');
  });
});

// ─── Tool Profiles ───

describe('isToolAllowed', () => {
  it('allows all when no config', () => {
    expect(isToolAllowed('shell_exec')).toBe(true);
  });

  it('blocks tools outside profile', () => {
    expect(isToolAllowed('shell_exec', { profile: 'minimal' })).toBe(false);
  });

  it('allows tools in profile', () => {
    expect(isToolAllowed('memory_search', { profile: 'minimal' })).toBe(true);
  });

  it('deny list overrides everything', () => {
    expect(isToolAllowed('memory_search', { profile: 'full', deny: ['memory_search'] })).toBe(false);
  });

  it('allow list restricts when set', () => {
    expect(isToolAllowed('shell_exec', { allow: ['memory_search'] })).toBe(false);
    expect(isToolAllowed('memory_search', { allow: ['memory_search'] })).toBe(true);
  });
});

// ─── Loop Detection ───

describe('LoopDetector', () => {
  it('returns ok for normal usage', () => {
    const detector = new LoopDetector(10, 3, 5);
    expect(detector.record('tool_a', { x: 1 }).status).toBe('ok');
    expect(detector.record('tool_b', { x: 2 }).status).toBe('ok');
  });

  it('warns on repeated calls', () => {
    const detector = new LoopDetector(10, 3, 5);
    detector.record('tool_a', { x: 1 });
    detector.record('tool_a', { x: 1 });
    const result = detector.record('tool_a', { x: 1 });
    expect(result.status).toBe('warning');
    expect(result.repeats).toBe(3);
  });

  it('goes critical on excessive repeats', () => {
    const detector = new LoopDetector(10, 3, 5);
    for (let i = 0; i < 4; i++) detector.record('tool_a', { x: 1 });
    const result = detector.record('tool_a', { x: 1 });
    expect(result.status).toBe('critical');
    expect(result.repeats).toBe(5);
  });

  it('resets breaks the loop', () => {
    const detector = new LoopDetector(10, 3, 5);
    for (let i = 0; i < 4; i++) detector.record('tool_a', { x: 1 });
    detector.reset();
    expect(detector.record('tool_a', { x: 1 }).status).toBe('ok');
  });

  it('different args do not count as loop', () => {
    const detector = new LoopDetector(10, 3, 5);
    detector.record('tool_a', { x: 1 });
    detector.record('tool_a', { x: 2 });
    detector.record('tool_a', { x: 3 });
    expect(detector.record('tool_a', { x: 4 }).status).toBe('ok');
  });
});

// ─── Delegation ───

describe('DelegationManager', () => {
  it('creates tasks up to max concurrent', () => {
    const mgr = new DelegationManager(2, 2);
    const t1 = mgr.createTask('goal1', 'ctx1');
    const t2 = mgr.createTask('goal2', 'ctx2');
    expect(t1).not.toBeNull();
    expect(t2).not.toBeNull();
  });

  it('tracks running/completed state', () => {
    const mgr = new DelegationManager(2, 2);
    const task = mgr.createTask('g', 'c')!;
    mgr.markRunning(task.id);
    expect(mgr.getRunningTasks()).toHaveLength(1);
    mgr.markCompleted(task.id, 'done');
    expect(mgr.getRunningTasks()).toHaveLength(0);
  });
});

// ─── Approval Store ───

describe('ApprovalStore', () => {
  it('once approval is consumed after check', () => {
    const store = new ApprovalStore();
    store.approve('shell_exec', 'once');
    expect(store.isApproved('shell_exec', 'once')).toBe(true);
    expect(store.isApproved('shell_exec', 'once')).toBe(false); // Consumed
  });

  it('session approval persists', () => {
    const store = new ApprovalStore();
    store.approve('shell_exec', 'session');
    expect(store.isApproved('shell_exec', 'session')).toBe(true);
    expect(store.isApproved('shell_exec', 'session')).toBe(true); // Still there
  });

  it('always approval survives session reset', () => {
    const store = new ApprovalStore();
    store.approve('shell_exec', 'always');
    store.resetSession();
    expect(store.isApproved('shell_exec', 'always')).toBe(true);
  });

  it('session approval cleared on reset', () => {
    const store = new ApprovalStore();
    store.approve('shell_exec', 'session');
    store.resetSession();
    expect(store.isApproved('shell_exec', 'session')).toBe(false);
  });
});

// ─── Session Manager ───

describe('SessionManager', () => {
  it('never resets when mode is none', () => {
    const mgr = new SessionManager('none');
    expect(mgr.shouldReset()).toBe(false);
  });

  it('resets on idle timeout', async () => {
    const mgr = new SessionManager('idle', 0); // 0 minutes idle threshold
    // Need a tiny delay so Date.now() - lastActivity > 0
    await new Promise(r => setTimeout(r, 5));
    expect(mgr.shouldReset()).toBe(true);
  });

  it('fires listeners on trigger', () => {
    const mgr = new SessionManager('none');
    const fn = vi.fn();
    mgr.onReset(fn);
    mgr.triggerReset();
    expect(fn).toHaveBeenCalledOnce();
  });
});

// ─── Human Delay ───

describe('applyHumanDelay', () => {
  it('returns immediately when off', async () => {
    const start = Date.now();
    await applyHumanDelay('off');
    expect(Date.now() - start).toBeLessThan(50);
  });
});
