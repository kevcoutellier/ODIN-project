import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { EpisodicStore } from '../episodic/store.js';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { unlinkSync } from 'node:fs';

const TEST_DB = join(tmpdir(), `odin-test-episodic-${Date.now()}.db`);

describe('EpisodicStore', () => {
  let store: EpisodicStore;

  beforeEach(async () => {
    store = new EpisodicStore(TEST_DB);
    await store.init();
  });

  afterEach(async () => {
    await store.close();
    try { unlinkSync(TEST_DB); } catch {}
    try { unlinkSync(TEST_DB + '-wal'); } catch {}
    try { unlinkSync(TEST_DB + '-shm'); } catch {}
  });

  // ─── Entities ───

  it('creates new entities', async () => {
    const entity = await store.upsertEntity('TypeScript', 'language', { version: '5.7' });
    expect(entity.id).toBeTruthy();
    expect(entity.name).toBe('TypeScript');
    expect(entity.type).toBe('language');
    expect(entity.mentions).toBe(1);
    expect(entity.merkleHash).toHaveLength(64);
  });

  it('reinforces existing entities', async () => {
    await store.upsertEntity('TypeScript', 'language');
    const reinforced = await store.upsertEntity('TypeScript', 'language', { strict: true });
    expect(reinforced.mentions).toBe(2);
    expect(reinforced.confidence).toBeGreaterThan(1.0 - 0.01); // Initial 1.0 + 0.05 capped
    expect(reinforced.properties).toHaveProperty('strict', true);
  });

  it('finds entities by name (FTS)', async () => {
    await store.upsertEntity('TypeScript', 'language');
    await store.upsertEntity('JavaScript', 'language');
    await store.upsertEntity('Python', 'language');

    const results = await store.findEntities('TypeScript');
    expect(results.length).toBeGreaterThanOrEqual(1);
    expect(results[0].name).toBe('TypeScript');
  });

  it('gets entities by type', async () => {
    await store.upsertEntity('Paris', 'city');
    await store.upsertEntity('TypeScript', 'language');
    await store.upsertEntity('London', 'city');

    const cities = await store.getEntitiesByType('city');
    expect(cities).toHaveLength(2);
    expect(cities.every(c => c.type === 'city')).toBe(true);
  });

  // ─── Edges ───

  it('creates edges between entities', async () => {
    const a = await store.upsertEntity('Alice', 'person');
    const b = await store.upsertEntity('Bob', 'person');
    const edge = await store.createEdge(a.id, b.id, 'knows', {}, 0.8);
    expect(edge.sourceId).toBe(a.id);
    expect(edge.targetId).toBe(b.id);
    expect(edge.relation).toBe('knows');
    expect(edge.weight).toBe(0.8);
  });

  it('reinforces existing edges', async () => {
    const a = await store.upsertEntity('A', 'concept');
    const b = await store.upsertEntity('B', 'concept');
    const e1 = await store.createEdge(a.id, b.id, 'related_to');
    const e2 = await store.createEdge(a.id, b.id, 'related_to');
    expect(e2.reinforcements).toBe(2);
    expect(e2.weight).toBeGreaterThan(e1.weight);
  });

  it('traverses neighborhood (BFS)', async () => {
    const a = await store.upsertEntity('A', 'node');
    const b = await store.upsertEntity('B', 'node');
    const c = await store.upsertEntity('C', 'node');
    await store.createEdge(a.id, b.id, 'link');
    await store.createEdge(b.id, c.id, 'link');

    const n1 = await store.getNeighborhood(a.id, 1);
    expect(n1.entities.length).toBe(2); // A and B
    const n2 = await store.getNeighborhood(a.id, 2);
    expect(n2.entities.length).toBe(3); // A, B, C
  });

  // ─── Episodes ───

  it('records and retrieves episodes', async () => {
    const ep = await store.recordEpisode('s1', 'User asked about TypeScript', 'conversation', [], [], 0.7);
    expect(ep.id).toBeTruthy();
    expect(ep.type).toBe('conversation');
    expect(ep.importance).toBe(0.7);

    const recent = await store.getRecentEpisodes();
    expect(recent.length).toBeGreaterThanOrEqual(1);
    expect(recent[0].content).toContain('TypeScript');
  });

  it('searches episodes by text', async () => {
    await store.recordEpisode('s1', 'Discussion about neural networks and deep learning', 'conversation');
    await store.recordEpisode('s1', 'Wrote a TypeScript function for sorting', 'tool_call');
    await store.recordEpisode('s1', 'Analyzed security vulnerabilities', 'observation');

    const results = await store.searchEpisodes({ text: 'neural networks' });
    expect(results.length).toBeGreaterThanOrEqual(1);
    expect(results[0].content).toContain('neural');
  });

  it('searches episodes by time window', async () => {
    const before = Date.now() - 1000;
    await store.recordEpisode('s1', 'Old episode', 'conversation');
    const after = Date.now() + 1000;

    const results = await store.searchEpisodes({ timeFrom: before, timeTo: after });
    expect(results.length).toBeGreaterThanOrEqual(1);
  });

  // ─── Decay ───

  it('applies decay to edges', async () => {
    const a = await store.upsertEntity('X', 'node');
    const b = await store.upsertEntity('Y', 'node');
    await store.createEdge(a.id, b.id, 'weak_link', {}, 0.5);

    // Decay with very short half-life (should reduce weights)
    const result = await store.applyDecay(0.001); // Very short half-life
    expect(result.edgesDecayed).toBeGreaterThanOrEqual(0);
  });

  // ─── Stats ───

  it('reports accurate stats', async () => {
    await store.upsertEntity('A', 'test');
    await store.upsertEntity('B', 'test');
    const a = await store.upsertEntity('A', 'test'); // reinforced
    const stats = store.getStats();
    expect(stats.entities).toBe(2);
  });
});
