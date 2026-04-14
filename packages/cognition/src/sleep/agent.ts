/**
 * Sleep Agent — Background Episodic→Semantic Consolidation
 *
 * Inspired by biological memory consolidation during sleep:
 * 1. REPLAY: Re-scan recent episodes, extract patterns
 * 2. CONSOLIDATE: Merge entities/edges into CIK knowledge store
 * 3. PRUNE: Decay low-importance episodes, remove redundant edges
 * 4. DREAM: Generate "dream" episodes — hypothetical connections
 *
 * Runs as a background timer (default: every 30 min when idle, or on demand).
 * The agent is NOT powered by LLM calls — it operates purely on graph/DB operations
 * for efficiency (LLM-assisted consolidation can be added in Phase 3).
 */

import { sha256 } from '@odin/core';
import type { EpisodicStore, Entity, Edge, Episode } from '../episodic/index.js';
import type { CIKStore, TrustTier, KnowledgeEntry } from '../cik/index.js';

export interface SleepCycleResult {
  startedAt: number;
  finishedAt: number;
  episodesProcessed: number;
  knowledgeCreated: number;
  knowledgeReinforced: number;
  entitiesDecayed: number;
  edgesDecayed: number;
  edgesPruned: number;
  dreamsGenerated: number;
}

export interface SleepAgentConfig {
  /** How often to run consolidation (ms). Default: 30 min */
  intervalMs: number;
  /** Minimum episodes to trigger consolidation. Default: 5 */
  minEpisodes: number;
  /** How many recent episodes to process per cycle. Default: 50 */
  batchSize: number;
  /** Decay half-life in days. Default: 7 */
  decayHalfLifeDays: number;
  /** Prune edges below this weight. Default: 0.05 */
  pruneThreshold: number;
  /** Generate dream episodes? Default: true */
  enableDreaming: boolean;
  /** Max dream episodes per cycle. Default: 3 */
  maxDreams: number;
}

const DEFAULT_CONFIG: SleepAgentConfig = {
  intervalMs: 30 * 60 * 1000,
  minEpisodes: 5,
  batchSize: 50,
  decayHalfLifeDays: 7,
  pruneThreshold: 0.05,
  enableDreaming: true,
  maxDreams: 3,
};

export class SleepAgent {
  private timer: ReturnType<typeof setInterval> | null = null;
  private running = false;
  private lastCycleResult: SleepCycleResult | null = null;
  private lastProcessedTimestamp = 0;
  private cycleCount = 0;
  private config: SleepAgentConfig;

  constructor(
    private episodicStore: EpisodicStore,
    private cikStore: CIKStore,
    config: Partial<SleepAgentConfig> = {},
  ) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  // ─── LIFECYCLE ───

  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => void this.runCycle(), this.config.intervalMs);
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  isRunning(): boolean { return this.running; }
  getLastResult(): SleepCycleResult | null { return this.lastCycleResult; }
  getCycleCount(): number { return this.cycleCount; }

  /**
   * Run a single consolidation cycle (can be called manually or by timer).
   */
  async runCycle(): Promise<SleepCycleResult> {
    if (this.running) return this.lastCycleResult ?? this.emptyResult();
    this.running = true;
    const startedAt = Date.now();

    let knowledgeCreated = 0;
    let knowledgeReinforced = 0;
    let edgesPruned = 0;
    let dreamsGenerated = 0;

    try {
      // 1. REPLAY: Fetch recent unprocessed episodes
      const episodes = await this.episodicStore.searchEpisodes({
        timeFrom: this.lastProcessedTimestamp > 0 ? this.lastProcessedTimestamp : undefined,
        limit: this.config.batchSize,
      });

      if (episodes.length < this.config.minEpisodes) {
        const result = this.emptyResult(startedAt);
        result.episodesProcessed = 0;
        this.lastCycleResult = result;
        return result;
      }

      // 2. CONSOLIDATE: Extract entity co-occurrence patterns → knowledge
      const consolidation = await this.consolidateEpisodes(episodes);
      knowledgeCreated = consolidation.created;
      knowledgeReinforced = consolidation.reinforced;

      // 3. DECAY + PRUNE
      const decay = await this.episodicStore.applyDecay(this.config.decayHalfLifeDays);
      edgesPruned = await this.pruneWeakEdges();

      // 4. DREAM: Generate hypothetical connections
      if (this.config.enableDreaming) {
        dreamsGenerated = await this.dream(episodes);
      }

      // Update watermark
      const maxTimestamp = episodes.reduce((max, ep) => Math.max(max, ep.timestamp), 0);
      if (maxTimestamp > this.lastProcessedTimestamp) {
        this.lastProcessedTimestamp = maxTimestamp;
      }

      this.cycleCount++;

      const result: SleepCycleResult = {
        startedAt,
        finishedAt: Date.now(),
        episodesProcessed: episodes.length,
        knowledgeCreated,
        knowledgeReinforced,
        entitiesDecayed: decay.entitiesDecayed,
        edgesDecayed: decay.edgesDecayed,
        edgesPruned,
        dreamsGenerated,
      };

      this.lastCycleResult = result;
      return result;
    } finally {
      this.running = false;
    }
  }

  // ─── CONSOLIDATION (Episodic → Semantic) ───

  /**
   * Analyze episodes for recurring patterns and create CIK knowledge:
   * - Entity co-occurrence → relationship knowledge
   * - Repeated tool usage → capability reinforcement
   * - Conversation themes → topical knowledge
   */
  private async consolidateEpisodes(episodes: Episode[]): Promise<{ created: number; reinforced: number }> {
    let created = 0;
    let reinforced = 0;

    // 1. Extract entity co-occurrences across episodes
    const coOccurrences = new Map<string, { count: number; entityIds: Set<string>; contexts: string[] }>();

    for (const episode of episodes) {
      if (episode.entityIds.length < 2) continue;

      // For each pair of entities in the episode
      for (let i = 0; i < episode.entityIds.length; i++) {
        for (let j = i + 1; j < episode.entityIds.length; j++) {
          const key = [episode.entityIds[i], episode.entityIds[j]].sort().join('::');
          const existing = coOccurrences.get(key);
          if (existing) {
            existing.count++;
            existing.contexts.push(episode.content.slice(0, 200));
          } else {
            coOccurrences.set(key, {
              count: 1,
              entityIds: new Set([episode.entityIds[i], episode.entityIds[j]]),
              contexts: [episode.content.slice(0, 200)],
            });
          }
        }
      }
    }

    // 2. Co-occurrences that appear 3+ times → knowledge triples
    for (const [key, data] of coOccurrences) {
      if (data.count < 3) continue;

      const [entityAId, entityBId] = key.split('::');
      const entityA = await this.episodicStore.getEntity(entityAId);
      const entityB = await this.episodicStore.getEntity(entityBId);
      if (!entityA || !entityB) continue;

      const result = await this.cikStore.addKnowledge(
        entityA.name,
        'co-occurs_with',
        entityB.name,
        `sleep:consolidation:cycle-${this.cycleCount}`,
        'T3', // LLM-derived tier (agent-inferred, not verified)
        `Observed ${data.count} co-occurrences across episodes`,
      );

      if ('error' in result) continue;
      if (result.verifications > 0) reinforced++;
      else created++;
    }

    // 3. Extract tool usage patterns → capability reinforcement
    const toolEpisodes = episodes.filter(ep => ep.type === 'tool_call');
    const toolUsage = new Map<string, { success: number; fail: number }>();

    for (const ep of toolEpisodes) {
      // Parse tool name from episode content (format: "tool:name result:...")
      const toolMatch = ep.content.match(/^tool:(\w+)/);
      if (!toolMatch) continue;

      const toolName = toolMatch[1];
      const entry = toolUsage.get(toolName) ?? { success: 0, fail: 0 };
      if (ep.importance > 0.5) entry.success++;
      else entry.fail++;
      toolUsage.set(toolName, entry);
    }

    for (const [toolName, usage] of toolUsage) {
      const success = usage.success > 0;
      await this.cikStore.recordCapabilityUsage(toolName, success);
    }

    // 4. Extract conversation themes → knowledge
    const wordFreq = new Map<string, number>();
    for (const ep of episodes.filter(e => e.type === 'conversation')) {
      const words = ep.content.toLowerCase()
        .split(/\s+/)
        .filter(w => w.length > 4) // Skip short words
        .filter(w => !STOP_WORDS.has(w));
      for (const word of words) {
        wordFreq.set(word, (wordFreq.get(word) ?? 0) + 1);
      }
    }

    // Top themes (appear 5+ times) → knowledge
    const themes = [...wordFreq.entries()]
      .filter(([, count]) => count >= 5)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10);

    for (const [theme, freq] of themes) {
      const result = await this.cikStore.addKnowledge(
        'conversation',
        'frequent_topic',
        theme,
        `sleep:consolidation:cycle-${this.cycleCount}`,
        'T4', // External-unverified, statistical
        `Appeared ${freq} times in ${episodes.length} episodes`,
      );

      if ('error' in result) continue;
      if (result.verifications > 0) reinforced++;
      else created++;
    }

    return { created, reinforced };
  }

  // ─── PRUNING ───

  /**
   * Remove edges below the weight threshold — they represent
   * connections the agent has "forgotten."
   */
  private async pruneWeakEdges(): Promise<number> {
    // We need direct DB access — EpisodicStore doesn't expose bulk edge pruning
    // For now, we rely on the decay mechanism reducing weights
    // Actual pruning would need a new method on EpisodicStore
    // This is a safe placeholder — decay is already handling weight reduction
    return 0;
  }

  // ─── DREAMING ───

  /**
   * Generate "dream" episodes — hypothetical connections between
   * entities that haven't been directly linked but share common neighbors.
   * This is transitive inference: if A→B and B→C, dream A→C.
   */
  private async dream(episodes: Episode[]): Promise<number> {
    let dreamsGenerated = 0;

    // Collect all entity IDs from recent episodes
    const entityIds = new Set<string>();
    for (const ep of episodes) {
      for (const id of ep.entityIds) entityIds.add(id);
    }

    // For each entity, look at its neighborhood and find transitive connections
    const entityList = [...entityIds];
    for (let i = 0; i < Math.min(entityList.length, 10); i++) {
      const entityId = entityList[i];
      const neighborhood = await this.episodicStore.getNeighborhood(entityId, 2);

      // Find pairs of entities at depth=2 that aren't directly connected
      const directNeighborIds = new Set(
        neighborhood.edges
          .filter(e => e.sourceId === entityId || e.targetId === entityId)
          .map(e => e.sourceId === entityId ? e.targetId : e.sourceId)
      );

      const depth2Entities = neighborhood.entities.filter(
        e => e.id !== entityId && !directNeighborIds.has(e.id)
      );

      for (const distant of depth2Entities.slice(0, 2)) {
        if (dreamsGenerated >= this.config.maxDreams) break;

        const sourceEntity = await this.episodicStore.getEntity(entityId);
        if (!sourceEntity) continue;

        // Record as a "dream" episode
        await this.episodicStore.recordEpisode(
          `sleep-cycle-${this.cycleCount}`,
          `Dream: ${sourceEntity.name} may be related to ${distant.name} through shared connections`,
          'dream',
          [entityId, distant.id],
          [],
          0.3, // Low importance — dreams are speculative
          0,
          `Transitive connection: ${sourceEntity.name} → [...] → ${distant.name}`,
        );

        dreamsGenerated++;
      }

      if (dreamsGenerated >= this.config.maxDreams) break;
    }

    return dreamsGenerated;
  }

  // ─── HELPERS ───

  private emptyResult(startedAt: number = Date.now()): SleepCycleResult {
    return {
      startedAt,
      finishedAt: Date.now(),
      episodesProcessed: 0,
      knowledgeCreated: 0,
      knowledgeReinforced: 0,
      entitiesDecayed: 0,
      edgesDecayed: 0,
      edgesPruned: 0,
      dreamsGenerated: 0,
    };
  }
}

// Common English stop words to filter out from theme extraction
const STOP_WORDS = new Set([
  'about', 'after', 'again', 'being', 'below', 'between', 'could',
  'doing', 'during', 'every', 'first', 'found', 'going', 'having',
  'himself', 'itself', 'might', 'never', 'other', 'ought', 'right',
  'shall', 'since', 'still', 'their', 'there', 'these', 'thing',
  'think', 'those', 'three', 'today', 'under', 'until', 'using',
  'value', 'wants', 'which', 'while', 'would', 'yours', 'should',
  'would', 'could', 'really', 'nothing', 'another', 'because',
  'before', 'either', 'enough', 'itself', 'myself', 'please',
  'return', 'second', 'always', 'around', 'though', 'within',
]);
