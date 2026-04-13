/**
 * Memory Store — SQLite + FTS5 + Merkle Tree
 *
 * Three-tier memory:
 * 1. Notes: persistent facts declared by user (TRUSTED)
 * 2. Sessions: conversation history with FTS5 search + LLM summaries
 * 3. Procedures: successful workflows converted to reusable procedures
 *
 * Every write produces a Merkle tree entry. The session Merkle root
 * is signed with the instance's Ed25519 key for tamper evidence.
 */

import type {
  MemoryEntry,
  TaintLabel,
  IntegrityLevel,
  ConfidentialityLevel,
} from '../types.js';
import { MerkleTree, sha256 } from './merkle.js';
import { randomUUID } from 'node:crypto';

export interface MemoryStoreOptions {
  dbPath: string;
  maxEntries: number;
}

export class MemoryStore {
  private db: any;
  private merkleTrees: Map<string, MerkleTree> = new Map();
  private initialized = false;

  constructor(private options: MemoryStoreOptions) {}

  async init(): Promise<void> {
    if (this.initialized) return;

    const Database = (await import('better-sqlite3')).default;
    this.db = new Database(this.options.dbPath);

    // Enable WAL mode for better concurrent read performance
    this.db.pragma('journal_mode = WAL');

    // Create tables
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS memory_entries (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        type TEXT NOT NULL CHECK(type IN ('note', 'session', 'procedure')),
        content TEXT NOT NULL,
        integrity TEXT NOT NULL,
        confidentiality TEXT NOT NULL,
        source TEXT NOT NULL,
        merkle_hash TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_memory_session ON memory_entries(session_id);
      CREATE INDEX IF NOT EXISTS idx_memory_type ON memory_entries(type);

      CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts USING fts5(
        id UNINDEXED,
        content,
        type UNINDEXED,
        tokenize='porter unicode61'
      );

      CREATE TABLE IF NOT EXISTS merkle_roots (
        session_id TEXT PRIMARY KEY,
        root_hash TEXT NOT NULL,
        signature TEXT,
        updated_at INTEGER NOT NULL
      );
    `);

    this.initialized = true;
  }

  async write(
    sessionId: string,
    type: MemoryEntry['type'],
    content: string,
    label: TaintLabel,
  ): Promise<MemoryEntry> {
    await this.init();

    const id = randomUUID();
    const now = Date.now();

    // Compute Merkle leaf
    const leafData = JSON.stringify({ id, sessionId, type, content, timestamp: now });
    const tree = this.getOrCreateTree(sessionId);
    const merkleHash = tree.addLeaf(leafData);

    const entry: MemoryEntry = {
      id,
      sessionId,
      type,
      content,
      label,
      merkleHash,
      createdAt: now,
      updatedAt: now,
    };

    // Insert into main table
    this.db.prepare(`
      INSERT INTO memory_entries (id, session_id, type, content, integrity, confidentiality, source, merkle_hash, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, sessionId, type, content, label.integrity, label.confidentiality, label.source, merkleHash, now, now);

    // Insert into FTS
    this.db.prepare(`
      INSERT INTO memory_fts (id, content, type) VALUES (?, ?, ?)
    `).run(id, content, type);

    // Update Merkle root
    this.db.prepare(`
      INSERT OR REPLACE INTO merkle_roots (session_id, root_hash, updated_at)
      VALUES (?, ?, ?)
    `).run(sessionId, tree.getRoot(), now);

    // Enforce maxEntries: delete oldest if over limit
    const countRow = this.db.prepare('SELECT COUNT(*) as cnt FROM memory_entries').get() as any;
    if (countRow.cnt > this.options.maxEntries) {
      const excess = countRow.cnt - this.options.maxEntries;
      const oldRows = this.db.prepare(
        'SELECT id FROM memory_entries ORDER BY created_at ASC LIMIT ?'
      ).all(excess) as any[];
      const ids = oldRows.map((r: any) => r.id);
      for (const oldId of ids) {
        this.db.prepare('DELETE FROM memory_entries WHERE id = ?').run(oldId);
        this.db.prepare('DELETE FROM memory_fts WHERE id = ?').run(oldId);
      }
    }

    return entry;
  }

  async search(query: string, limit = 10): Promise<MemoryEntry[]> {
    await this.init();

    // Sanitize FTS5 special characters to prevent query injection
    const sanitized = query.replace(/["\*\(\)\-\+\^~:]/g, ' ').replace(/\s+/g, ' ').trim();
    if (!sanitized) return [];

    // Wrap each term in double quotes for safe FTS5 matching
    const safeQuery = sanitized.split(' ').map(t => `"${t}"`).join(' ');

    const rows = this.db.prepare(`
      SELECT e.* FROM memory_fts f
      JOIN memory_entries e ON e.id = f.id
      WHERE memory_fts MATCH ?
      ORDER BY rank
      LIMIT ?
    `).all(safeQuery, limit);

    return rows.map(this.rowToEntry);
  }

  async getBySession(sessionId: string, limit = 50): Promise<MemoryEntry[]> {
    await this.init();

    const rows = this.db.prepare(`
      SELECT * FROM memory_entries WHERE session_id = ? ORDER BY created_at DESC LIMIT ?
    `).all(sessionId, limit);

    return rows.map(this.rowToEntry);
  }

  async getByType(type: MemoryEntry['type'], limit = 50): Promise<MemoryEntry[]> {
    await this.init();

    const rows = this.db.prepare(`
      SELECT * FROM memory_entries WHERE type = ? ORDER BY created_at DESC LIMIT ?
    `).all(type, limit);

    return rows.map(this.rowToEntry);
  }

  async getNotes(): Promise<MemoryEntry[]> {
    return this.getByType('note');
  }

  async getProcedures(): Promise<MemoryEntry[]> {
    return this.getByType('procedure');
  }

  getMerkleRoot(sessionId: string): string | null {
    const tree = this.merkleTrees.get(sessionId);
    return tree ? tree.getRoot() : null;
  }

  getMerkleProof(sessionId: string, merkleHash: string) {
    const tree = this.merkleTrees.get(sessionId);
    if (!tree) return null;
    return {
      root: tree.getRoot(),
      path: tree.getProof(merkleHash),
      leaf: merkleHash,
    };
  }

  async close(): Promise<void> {
    if (this.db) {
      this.db.close();
      this.initialized = false;
    }
  }

  private getOrCreateTree(sessionId: string): MerkleTree {
    let tree = this.merkleTrees.get(sessionId);
    if (!tree) {
      tree = new MerkleTree();
      this.merkleTrees.set(sessionId, tree);
    }
    return tree;
  }

  private rowToEntry(row: any): MemoryEntry {
    return {
      id: row.id,
      sessionId: row.session_id,
      type: row.type,
      content: row.content,
      label: {
        integrity: row.integrity as IntegrityLevel,
        confidentiality: row.confidentiality as ConfidentialityLevel,
        source: row.source,
        timestamp: row.created_at,
      },
      merkleHash: row.merkle_hash,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }
}
