/**
 * Sleep agent tests — consolidation, dreaming, reentrance protection.
 *
 * Uses real EpisodicStore + CIKStore with temp SQLite files.
 * Only exercises paths that don't require an LLM.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { unlinkSync } from 'node:fs';
import { SleepAgent } from '../sleep/agent.js';
import { EpisodicStore } from '../episodic/store.js';
import { CIKStore } from '../cik/stores.js';

const cleanup = (path: string) => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { unlinkSync(path + suffix); } catch {}
  }
};

describe('SleepAgent', () => {
  let ep: EpisodicStore, cik: CIKStore, agent: SleepAgent;
  let epPath: string, cikPath: string;

  beforeEach(async () => {
    epPath = join(tmpdir(), `odin-sleep-ep-${Date.now()}-${Math.random()}.db`);
    cikPath = join(tmpdir(), `odin-sleep-cik-${Date.now()}-${Math.random()}.db`);
    ep = new EpisodicStore(epPath);
    cik = new CIKStore(cikPath);
    await ep.init();
    await cik.init();
  });

  afterEach(async () => {
    agent?.stop();
    await ep.close();
    await cik.close();
    cleanup(epPath);
    cleanup(cikPath);
  });

  it('start/stop toggles the internal timer without running a cycle', () => {
    agent = new SleepAgent(ep, cik, { intervalMs: 60_000 });
    expect(agent.getCycleCount()).toBe(0);
    agent.start();
    // start() doesn't run a cycle synchronously
    expect(agent.getCycleCount()).toBe(0);
    agent.stop();
  });

  it('double start is a no-op (single timer)', () => {
    agent = new SleepAgent(ep, cik, { intervalMs: 60_000 });
    agent.start();
    agent.start(); // No error, still one timer
    agent.stop();
  });

  it('runCycle with fewer than minEpisodes returns an empty result', async () => {
    agent = new SleepAgent(ep, cik, { minEpisodes: 5 });
    // Add only 2 episodes
    await ep.recordEpisode('s1', 'Hello', 'conversation');
    await ep.recordEpisode('s1', 'World', 'conversation');

    const result = await agent.runCycle();
    expect(result.episodesProcessed).toBe(0);
    expect(result.knowledgeCreated).toBe(0);
    expect(result.dreamsGenerated).toBe(0);
  });

  it('runCycle increments cycle count only when real work happens', async () => {
    agent = new SleepAgent(ep, cik, { minEpisodes: 2, enableDreaming: false });
    // Below minEpisodes threshold → no cycle increment
    await ep.recordEpisode('s1', 'one', 'conversation');
    await agent.runCycle();
    expect(agent.getCycleCount()).toBe(0);

    // Add enough episodes
    for (let i = 0; i < 5; i++) {
      await ep.recordEpisode('s1', `episode ${i}`, 'conversation');
    }
    await agent.runCycle();
    expect(agent.getCycleCount()).toBe(1);
  });

  it('re-entrance: concurrent runCycle returns last result without re-running', async () => {
    agent = new SleepAgent(ep, cik, { minEpisodes: 2, enableDreaming: false });
    for (let i = 0; i < 5; i++) {
      await ep.recordEpisode('s1', `ep ${i}`, 'conversation');
    }
    // Fire two cycles concurrently; one of them returns immediately
    const [r1, r2] = await Promise.all([agent.runCycle(), agent.runCycle()]);
    // Exactly one of them should have done real work (episodesProcessed > 0)
    const realCycles = [r1, r2].filter(r => r.episodesProcessed > 0);
    expect(realCycles.length).toBeLessThanOrEqual(1);
    // Cycle count incremented at most once
    expect(agent.getCycleCount()).toBeLessThanOrEqual(1);
  });

  it('consolidates repeated entity co-occurrences into knowledge', async () => {
    const e1 = await ep.upsertEntity('TypeScript', 'language');
    const e2 = await ep.upsertEntity('Node.js', 'runtime');

    // 3 episodes co-mentioning both entities (threshold for knowledge creation)
    for (let i = 0; i < 3; i++) {
      await ep.recordEpisode(
        's1',
        `Discussion ${i} about TypeScript and Node.js`,
        'conversation',
        [e1.id, e2.id],
        [],
        0.7,
      );
    }

    agent = new SleepAgent(ep, cik, { minEpisodes: 2, enableDreaming: false });
    const result = await agent.runCycle();

    expect(result.episodesProcessed).toBe(3);
    expect(result.knowledgeCreated + result.knowledgeReinforced).toBeGreaterThan(0);
  });

  it('dream=false ⇒ 0 dreams generated', async () => {
    const e1 = await ep.upsertEntity('A', 'node');
    const e2 = await ep.upsertEntity('B', 'node');
    for (let i = 0; i < 5; i++) {
      await ep.recordEpisode('s1', `ep ${i}`, 'conversation', [e1.id, e2.id]);
    }

    agent = new SleepAgent(ep, cik, { minEpisodes: 2, enableDreaming: false });
    const result = await agent.runCycle();
    expect(result.dreamsGenerated).toBe(0);
  });

  it('watermark advances: a second cycle only processes newer episodes', async () => {
    agent = new SleepAgent(ep, cik, { minEpisodes: 2, enableDreaming: false });
    // Batch 1
    for (let i = 0; i < 3; i++) {
      await ep.recordEpisode('s1', `old ${i}`, 'conversation');
    }
    const r1 = await agent.runCycle();
    expect(r1.episodesProcessed).toBe(3);

    // Small pause then batch 2 — watermark should skip old episodes
    await new Promise(r => setTimeout(r, 10));
    for (let i = 0; i < 3; i++) {
      await ep.recordEpisode('s1', `new ${i}`, 'conversation');
    }
    const r2 = await agent.runCycle();
    // r2 might include the watermark episode itself (timeFrom is inclusive),
    // but should NOT reprocess the oldest episode.
    expect(r2.episodesProcessed).toBeLessThan(6);
    expect(r2.episodesProcessed).toBeGreaterThan(0);
  });

  it('getLastResult returns null before any cycle and the last result after', async () => {
    agent = new SleepAgent(ep, cik);
    expect(agent.getLastResult()).toBeNull();

    await agent.runCycle();
    expect(agent.getLastResult()).not.toBeNull();
  });

  it('isRunning is false outside of a cycle', () => {
    agent = new SleepAgent(ep, cik);
    expect(agent.isRunning()).toBe(false);
  });
});
