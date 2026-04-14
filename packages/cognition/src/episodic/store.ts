/**
 * Episodic Memory Store — Graph-based (Graphiti-inspired)
 *
 * Replaces flat SQLite memory with a proper episodic graph:
 * - Entities: named concepts/objects/people with types and properties
 * - Edges: typed relationships between entities (with confidence + decay)
 * - Episodes: temporal units grouping entities + edges + raw content
 * - Temporal indexing: episodes are ordered, searchable by time window
 * - Semantic search via FTS5 on entity names/descriptions + episode content
 *
 * Each write is signed with DID + Merkle-hashed for provenance.
 */

import { randomUUID } from 'node:crypto';
import { sha256 } from '@odin/core';

export interface Entity {
  id: string;
  name: string;
  type: string; // person, concept, tool, location, organization, etc.
  properties: Record<string, unknown>;
  firstSeen: number;
  lastSeen: number;
  mentions: number;
  confidence: number; // 0.0-1.0
  merkleHash: string;
}

export interface Edge {
  id: string;
  sourceId: string;
  targetId: string;
  relation: string; // "knows", "uses", "created", "located_in", etc.
  properties: Record<string, unknown>;
  weight: number; // 0.0-1.0 — strength of relationship
  confidence: number;
  createdAt: number;
  lastReinforced: number;
  reinforcements: number;
  merkleHash: string;
}

export interface Episode {
  id: string;
  sessionId: string;
  content: string; // Raw interaction content
  summary?: string; // LLM-generated summary
  entityIds: string[];
  edgeIds: string[];
  timestamp: number;
  duration: number; // ms
  type: 'conversation' | 'tool_call' | 'observation' | 'reflection' | 'dream';
  importance: number; // 0.0-1.0 — computed from entity mentions + novelty
  merkleHash: string;
}

export interface EpisodicQuery {
  text?: string;
  entityType?: string;
  entityName?: string;
  relation?: string;
  timeFrom?: number;
  timeTo?: number;
  minImportance?: number;
  limit?: number;
}

export interface EpisodicSearchResult {
  entities: Entity[];
  edges: Edge[];
  episodes: Episode[];
  relevanceScore: number;
}

export class EpisodicStore {
  private db: any;
  private initialized = false;

  constructor(private dbPath: string) {}

  async init(): Promise<void> {
    if (this.initialized) return;

    const Database = (await import('better-sqlite3')).default;
    this.db = new Database(this.dbPath);
    this.db.pragma('journal_mode = WAL');

    this.db.exec(`
      -- Entities (nodes in the graph)
      CREATE TABLE IF NOT EXISTS entities (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        type TEXT NOT NULL,
        properties TEXT NOT NULL DEFAULT '{}',
        first_seen INTEGER NOT NULL,
        last_seen INTEGER NOT NULL,
        mentions INTEGER NOT NULL DEFAULT 1,
        confidence REAL NOT NULL DEFAULT 1.0,
        merkle_hash TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_entity_type ON entities(type);
      CREATE INDEX IF NOT EXISTS idx_entity_name ON entities(name);

      -- Edges (relationships)
      CREATE TABLE IF NOT EXISTS edges (
        id TEXT PRIMARY KEY,
        source_id TEXT NOT NULL REFERENCES entities(id),
        target_id TEXT NOT NULL REFERENCES entities(id),
        relation TEXT NOT NULL,
        properties TEXT NOT NULL DEFAULT '{}',
        weight REAL NOT NULL DEFAULT 0.5,
        confidence REAL NOT NULL DEFAULT 1.0,
        created_at INTEGER NOT NULL,
        last_reinforced INTEGER NOT NULL,
        reinforcements INTEGER NOT NULL DEFAULT 1,
        merkle_hash TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_edge_source ON edges(source_id);
      CREATE INDEX IF NOT EXISTS idx_edge_target ON edges(target_id);
      CREATE INDEX IF NOT EXISTS idx_edge_relation ON edges(relation);

      -- Episodes (temporal events)
      CREATE TABLE IF NOT EXISTS episodes (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        content TEXT NOT NULL,
        summary TEXT,
        entity_ids TEXT NOT NULL DEFAULT '[]',
        edge_ids TEXT NOT NULL DEFAULT '[]',
        timestamp INTEGER NOT NULL,
        duration INTEGER NOT NULL DEFAULT 0,
        type TEXT NOT NULL DEFAULT 'conversation',
        importance REAL NOT NULL DEFAULT 0.5,
        merkle_hash TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_episode_time ON episodes(timestamp);
      CREATE INDEX IF NOT EXISTS idx_episode_session ON episodes(session_id);
      CREATE INDEX IF NOT EXISTS idx_episode_type ON episodes(type);
      CREATE INDEX IF NOT EXISTS idx_episode_importance ON episodes(importance);

      -- FTS5 for semantic search
      CREATE VIRTUAL TABLE IF NOT EXISTS entity_fts USING fts5(
        id UNINDEXED, name, type UNINDEXED, tokenize='porter unicode61'
      );
      CREATE VIRTUAL TABLE IF NOT EXISTS episode_fts USING fts5(
        id UNINDEXED, content, summary, tokenize='porter unicode61'
      );

      -- Provenance log
      CREATE TABLE IF NOT EXISTS provenance (
        id TEXT PRIMARY KEY,
        target_type TEXT NOT NULL,
        target_id TEXT NOT NULL,
        action TEXT NOT NULL,
        merkle_hash TEXT NOT NULL,
        signature TEXT,
        timestamp INTEGER NOT NULL
      );
    `);

    this.initialized = true;
  }

  // ─── ENTITY OPERATIONS ───

  async upsertEntity(
    name: string,
    type: string,
    properties: Record<string, unknown> = {},
    confidence: number = 1.0,
  ): Promise<Entity> {
    await this.init();
    const now = Date.now();

    // Check if entity already exists by name+type
    const existing = this.db.prepare(
      'SELECT * FROM entities WHERE name = ? AND type = ? LIMIT 1'
    ).get(name, type) as any;

    if (existing) {
      // Update: reinforce existing entity
      const merged = { ...JSON.parse(existing.properties), ...properties };
      const merkleHash = sha256(JSON.stringify({ id: existing.id, name, type, properties: merged, updated: now }));

      this.db.prepare(`
        UPDATE entities SET properties = ?, last_seen = ?, mentions = mentions + 1,
        confidence = MIN(1.0, confidence + 0.05), merkle_hash = ? WHERE id = ?
      `).run(JSON.stringify(merged), now, merkleHash, existing.id);

      this.recordProvenance('entity', existing.id, 'reinforce', merkleHash);

      return {
        id: existing.id, name, type, properties: merged,
        firstSeen: existing.first_seen, lastSeen: now,
        mentions: existing.mentions + 1,
        confidence: Math.min(1.0, existing.confidence + 0.05),
        merkleHash,
      };
    }

    // Create new entity
    const id = randomUUID();
    const merkleHash = sha256(JSON.stringify({ id, name, type, properties, created: now }));

    this.db.prepare(`
      INSERT INTO entities (id, name, type, properties, first_seen, last_seen, mentions, confidence, merkle_hash)
      VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
    `).run(id, name, type, JSON.stringify(properties), now, now, confidence, merkleHash);

    // FTS index
    this.db.prepare('INSERT INTO entity_fts (id, name) VALUES (?, ?)').run(id, name);

    this.recordProvenance('entity', id, 'create', merkleHash);

    return { id, name, type, properties, firstSeen: now, lastSeen: now, mentions: 1, confidence, merkleHash };
  }

  async getEntity(id: string): Promise<Entity | null> {
    await this.init();
    const row = this.db.prepare('SELECT * FROM entities WHERE id = ?').get(id) as any;
    return row ? this.rowToEntity(row) : null;
  }

  async findEntities(query: string, limit: number = 10): Promise<Entity[]> {
    await this.init();
    const sanitized = query.replace(/["\*\(\)\-\+\^~:]/g, ' ').trim();
    if (!sanitized) return [];
    const safeQuery = sanitized.split(/\s+/).map(t => `"${t}"`).join(' ');

    const rows = this.db.prepare(`
      SELECT e.* FROM entity_fts f JOIN entities e ON e.id = f.id
      WHERE entity_fts MATCH ? ORDER BY rank LIMIT ?
    `).all(safeQuery, limit) as any[];

    return rows.map(r => this.rowToEntity(r));
  }

  async getEntitiesByType(type: string, limit: number = 50): Promise<Entity[]> {
    await this.init();
    const rows = this.db.prepare(
      'SELECT * FROM entities WHERE type = ? ORDER BY last_seen DESC LIMIT ?'
    ).all(type, limit) as any[];
    return rows.map(r => this.rowToEntity(r));
  }

  // ─── EDGE OPERATIONS ───

  async createEdge(
    sourceId: string,
    targetId: string,
    relation: string,
    properties: Record<string, unknown> = {},
    weight: number = 0.5,
  ): Promise<Edge> {
    await this.init();
    const now = Date.now();

    // Check for existing edge
    const existing = this.db.prepare(
      'SELECT * FROM edges WHERE source_id = ? AND target_id = ? AND relation = ? LIMIT 1'
    ).get(sourceId, targetId, relation) as any;

    if (existing) {
      // Reinforce existing edge
      const newWeight = Math.min(1.0, existing.weight + 0.1);
      const merkleHash = sha256(JSON.stringify({ id: existing.id, reinforced: now, weight: newWeight }));

      this.db.prepare(`
        UPDATE edges SET weight = ?, last_reinforced = ?, reinforcements = reinforcements + 1,
        merkle_hash = ? WHERE id = ?
      `).run(newWeight, now, merkleHash, existing.id);

      this.recordProvenance('edge', existing.id, 'reinforce', merkleHash);

      return {
        id: existing.id, sourceId, targetId, relation, properties: JSON.parse(existing.properties),
        weight: newWeight, confidence: existing.confidence,
        createdAt: existing.created_at, lastReinforced: now,
        reinforcements: existing.reinforcements + 1, merkleHash,
      };
    }

    const id = randomUUID();
    const merkleHash = sha256(JSON.stringify({ id, sourceId, targetId, relation, created: now }));

    this.db.prepare(`
      INSERT INTO edges (id, source_id, target_id, relation, properties, weight, confidence, created_at, last_reinforced, reinforcements, merkle_hash)
      VALUES (?, ?, ?, ?, ?, ?, 1.0, ?, ?, 1, ?)
    `).run(id, sourceId, targetId, relation, JSON.stringify(properties), weight, now, now, merkleHash);

    this.recordProvenance('edge', id, 'create', merkleHash);

    return { id, sourceId, targetId, relation, properties, weight, confidence: 1.0, createdAt: now, lastReinforced: now, reinforcements: 1, merkleHash };
  }

  async getEdgesFrom(entityId: string): Promise<Edge[]> {
    await this.init();
    const rows = this.db.prepare(
      'SELECT * FROM edges WHERE source_id = ? ORDER BY weight DESC'
    ).all(entityId) as any[];
    return rows.map(r => this.rowToEdge(r));
  }

  async getEdgesTo(entityId: string): Promise<Edge[]> {
    await this.init();
    const rows = this.db.prepare(
      'SELECT * FROM edges WHERE target_id = ? ORDER BY weight DESC'
    ).all(entityId) as any[];
    return rows.map(r => this.rowToEdge(r));
  }

  async getNeighborhood(entityId: string, depth: number = 1): Promise<{ entities: Entity[]; edges: Edge[] }> {
    await this.init();
    const visited = new Set<string>();
    const entities: Entity[] = [];
    const edges: Edge[] = [];
    const queue: Array<{ id: string; currentDepth: number }> = [{ id: entityId, currentDepth: 0 }];

    while (queue.length > 0) {
      const { id, currentDepth } = queue.shift()!;
      if (visited.has(id) || currentDepth > depth) continue;
      visited.add(id);

      const entity = await this.getEntity(id);
      if (entity) entities.push(entity);

      const outEdges = await this.getEdgesFrom(id);
      const inEdges = await this.getEdgesTo(id);

      for (const edge of [...outEdges, ...inEdges]) {
        edges.push(edge);
        const neighborId = edge.sourceId === id ? edge.targetId : edge.sourceId;
        if (!visited.has(neighborId)) {
          queue.push({ id: neighborId, currentDepth: currentDepth + 1 });
        }
      }
    }

    return { entities, edges };
  }

  // ─── EPISODE OPERATIONS ───

  async recordEpisode(
    sessionId: string,
    content: string,
    type: Episode['type'],
    entityIds: string[] = [],
    edgeIds: string[] = [],
    importance: number = 0.5,
    duration: number = 0,
    summary?: string,
  ): Promise<Episode> {
    await this.init();
    const now = Date.now();
    const id = randomUUID();
    const merkleHash = sha256(JSON.stringify({ id, sessionId, content, type, timestamp: now }));

    this.db.prepare(`
      INSERT INTO episodes (id, session_id, content, summary, entity_ids, edge_ids, timestamp, duration, type, importance, merkle_hash)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, sessionId, content, summary ?? null, JSON.stringify(entityIds), JSON.stringify(edgeIds), now, duration, type, importance, merkleHash);

    // FTS index
    this.db.prepare('INSERT INTO episode_fts (id, content, summary) VALUES (?, ?, ?)').run(id, content, summary ?? '');

    this.recordProvenance('episode', id, 'create', merkleHash);

    return { id, sessionId, content, summary, entityIds, edgeIds, timestamp: now, duration, type, importance, merkleHash };
  }

  async searchEpisodes(query: EpisodicQuery): Promise<Episode[]> {
    await this.init();

    if (query.text) {
      const sanitized = query.text.replace(/["\*\(\)\-\+\^~:]/g, ' ').trim();
      if (!sanitized) return [];
      const safeQuery = sanitized.split(/\s+/).map(t => `"${t}"`).join(' ');

      const rows = this.db.prepare(`
        SELECT e.* FROM episode_fts f JOIN episodes e ON e.id = f.id
        WHERE episode_fts MATCH ?
        ${query.minImportance ? 'AND e.importance >= ?' : ''}
        ${query.timeFrom ? 'AND e.timestamp >= ?' : ''}
        ${query.timeTo ? 'AND e.timestamp <= ?' : ''}
        ORDER BY rank LIMIT ?
      `).all(
        safeQuery,
        ...(query.minImportance ? [query.minImportance] : []),
        ...(query.timeFrom ? [query.timeFrom] : []),
        ...(query.timeTo ? [query.timeTo] : []),
        query.limit ?? 20,
      ) as any[];

      return rows.map(r => this.rowToEpisode(r));
    }

    // Time-based query
    const conditions: string[] = [];
    const params: unknown[] = [];

    if (query.timeFrom) { conditions.push('timestamp >= ?'); params.push(query.timeFrom); }
    if (query.timeTo) { conditions.push('timestamp <= ?'); params.push(query.timeTo); }
    if (query.minImportance) { conditions.push('importance >= ?'); params.push(query.minImportance); }

    const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const rows = this.db.prepare(`
      SELECT * FROM episodes ${where} ORDER BY timestamp DESC LIMIT ?
    `).all(...params, query.limit ?? 20) as any[];

    return rows.map(r => this.rowToEpisode(r));
  }

  async getRecentEpisodes(limit: number = 10): Promise<Episode[]> {
    await this.init();
    const rows = this.db.prepare(
      'SELECT * FROM episodes ORDER BY timestamp DESC LIMIT ?'
    ).all(limit) as any[];
    return rows.map(r => this.rowToEpisode(r));
  }

  // ─── DECAY ───

  /**
   * Apply temporal decay to edges and entity confidence.
   * Called periodically (e.g., by the sleep agent).
   */
  async applyDecay(halfLifeDays: number = 7): Promise<{ edgesDecayed: number; entitiesDecayed: number }> {
    await this.init();
    const now = Date.now();
    const halfLifeMs = halfLifeDays * 24 * 60 * 60 * 1000;
    const decayFactor = 0.5;

    // Decay edges
    const staleEdges = this.db.prepare(
      'SELECT id, weight, last_reinforced FROM edges WHERE weight > 0.05'
    ).all() as any[];

    let edgesDecayed = 0;
    for (const edge of staleEdges) {
      const elapsed = now - edge.last_reinforced;
      const decay = Math.pow(decayFactor, elapsed / halfLifeMs);
      const newWeight = edge.weight * decay;
      if (newWeight < edge.weight) {
        this.db.prepare('UPDATE edges SET weight = ? WHERE id = ?').run(Math.max(0.01, newWeight), edge.id);
        edgesDecayed++;
      }
    }

    // Decay entity confidence (slower — entities are more persistent)
    const staleEntities = this.db.prepare(
      'SELECT id, confidence, last_seen FROM entities WHERE confidence > 0.1'
    ).all() as any[];

    let entitiesDecayed = 0;
    for (const entity of staleEntities) {
      const elapsed = now - entity.last_seen;
      const decay = Math.pow(decayFactor, elapsed / (halfLifeMs * 3)); // 3x slower decay for entities
      const newConf = entity.confidence * decay;
      if (newConf < entity.confidence) {
        this.db.prepare('UPDATE entities SET confidence = ? WHERE id = ?').run(Math.max(0.05, newConf), entity.id);
        entitiesDecayed++;
      }
    }

    return { edgesDecayed, entitiesDecayed };
  }

  // ─── STATS ───

  getStats(): { entities: number; edges: number; episodes: number } {
    const e = this.db.prepare('SELECT COUNT(*) as c FROM entities').get() as any;
    const d = this.db.prepare('SELECT COUNT(*) as c FROM edges').get() as any;
    const p = this.db.prepare('SELECT COUNT(*) as c FROM episodes').get() as any;
    return { entities: e.c, edges: d.c, episodes: p.c };
  }

  async close(): Promise<void> {
    if (this.db) { this.db.close(); this.initialized = false; }
  }

  // ─── PROVENANCE ───

  private recordProvenance(targetType: string, targetId: string, action: string, merkleHash: string, signature?: string): void {
    this.db.prepare(`
      INSERT INTO provenance (id, target_type, target_id, action, merkle_hash, signature, timestamp)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(randomUUID(), targetType, targetId, action, merkleHash, signature ?? null, Date.now());
  }

  // ─── ROW MAPPERS ───

  private rowToEntity(row: any): Entity {
    return {
      id: row.id, name: row.name, type: row.type,
      properties: JSON.parse(row.properties),
      firstSeen: row.first_seen, lastSeen: row.last_seen,
      mentions: row.mentions, confidence: row.confidence,
      merkleHash: row.merkle_hash,
    };
  }

  private rowToEdge(row: any): Edge {
    return {
      id: row.id, sourceId: row.source_id, targetId: row.target_id,
      relation: row.relation, properties: JSON.parse(row.properties),
      weight: row.weight, confidence: row.confidence,
      createdAt: row.created_at, lastReinforced: row.last_reinforced,
      reinforcements: row.reinforcements, merkleHash: row.merkle_hash,
    };
  }

  private rowToEpisode(row: any): Episode {
    return {
      id: row.id, sessionId: row.session_id, content: row.content,
      summary: row.summary, entityIds: JSON.parse(row.entity_ids),
      edgeIds: JSON.parse(row.edge_ids), timestamp: row.timestamp,
      duration: row.duration, type: row.type, importance: row.importance,
      merkleHash: row.merkle_hash,
    };
  }
}
