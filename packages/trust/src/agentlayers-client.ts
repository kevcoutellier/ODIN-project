/**
 * AgentLayers API Client
 *
 * Integrates with the AgentLayers platform for:
 * - Trust Score (6 dimensions, continuous self-audit)
 * - Skill Scanner (pre-installation security audit)
 * - MCP Scanner (server security assessment)
 * - A2A Scanner (agent card evaluation)
 *
 * When no API key is configured, Odin falls back to local-only
 * security (free tier). All AgentLayers features degrade gracefully.
 */

import type { TrustScore, SkillManifest, AgentCard, TrustMode } from '@odin/core';
import { trustModeFromScore } from '@odin/core';

export interface AgentLayersConfig {
  apiKey?: string;
  baseUrl: string;
}

export interface SkillScanResult {
  score: number;
  decision: 'INSTALL' | 'ASK' | 'BLOCK';
  dimensions: {
    permissions: number;
    injection: number;
    transparency: number;
    scopeCreep: number;
    supplyChain: number;
    community: number;
  };
  warnings: string[];
}

export interface MCPScanResult {
  score: number;
  decision: 'SAFE' | 'CAUTION' | 'DANGEROUS';
  dimensions: {
    endpointSecurity: number;
    permissionScope: number;
    dataExfiltration: number;
    authStrength: number;
    configTransparency: number;
  };
  warnings: string[];
}

export interface A2AScanResult {
  score: number;
  decision: 'ALLOW' | 'RESTRICT' | 'DENY';
  dimensions: {
    authProtocol: number;
    messageSigning: number;
    delegationDepth: number;
    scopeContainment: number;
    identityVerification: number;
  };
  warnings: string[];
}

export class AgentLayersClient {
  private config: AgentLayersConfig;
  private available: boolean;

  constructor(config: AgentLayersConfig) {
    this.config = config;
    this.available = !!config.apiKey;
  }

  isAvailable(): boolean {
    return this.available;
  }

  /**
   * Self-audit: get the current trust score for this agent instance.
   */
  async getTrustScore(agentDid: string): Promise<TrustScore | null> {
    if (!this.available) return null;

    try {
      const response = await this.request('/api/v1/trust-score', {
        method: 'POST',
        body: JSON.stringify({ agentDid }),
      });

      return response as TrustScore;
    } catch {
      // Graceful degradation: if AgentLayers is unreachable, return null
      return null;
    }
  }

  /**
   * Scan a skill before installation.
   */
  async scanSkill(manifest: SkillManifest): Promise<SkillScanResult | null> {
    if (!this.available) return null;

    try {
      const response = await this.request('/api/v1/skill-scanner', {
        method: 'POST',
        body: JSON.stringify({ manifest }),
      });

      return response as SkillScanResult;
    } catch {
      return null;
    }
  }

  /**
   * Scan an MCP server configuration.
   */
  async scanMCPServer(serverConfig: {
    url: string;
    name: string;
    tools: string[];
  }): Promise<MCPScanResult | null> {
    if (!this.available) return null;

    try {
      const response = await this.request('/api/v1/mcp-scanner', {
        method: 'POST',
        body: JSON.stringify(serverConfig),
      });

      return response as MCPScanResult;
    } catch {
      return null;
    }
  }

  /**
   * Scan an agent card before A2A communication.
   */
  async scanAgentCard(card: AgentCard): Promise<A2AScanResult | null> {
    if (!this.available) return null;

    try {
      const response = await this.request('/api/v1/a2a-scanner', {
        method: 'POST',
        body: JSON.stringify({ agentCard: card }),
      });

      return response as A2AScanResult;
    } catch {
      return null;
    }
  }

  /**
   * Report a security incident to the AgentLayers network.
   */
  async reportIncident(incident: {
    agentDid: string;
    type: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    evidence?: Record<string, unknown>;
  }): Promise<boolean> {
    if (!this.available) return false;

    try {
      await this.request('/api/v1/incidents', {
        method: 'POST',
        body: JSON.stringify(incident),
      });
      return true;
    } catch {
      return false;
    }
  }

  private async request(path: string, init: RequestInit): Promise<unknown> {
    const url = `${this.config.baseUrl}${path}`;

    const response = await fetch(url, {
      ...init,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.config.apiKey}`,
        'X-Agent-SDK': 'odin/0.1.0',
        ...init.headers,
      },
    });

    if (!response.ok) {
      throw new Error(`AgentLayers API error: ${response.status} ${response.statusText}`);
    }

    return response.json();
  }
}

/**
 * Local trust metrics — the inputs to `computeLocalBaseline`.
 *
 * The three original fields (uptime / successRate / violationCount) feed
 * the performance, security, and reliability dimensions. The remaining
 * three dimensions (transparency, compliance, reputation) used to be
 * hardcoded constants; they now consume real evidence from the audit log,
 * the policy engine, and the A2A peer history. When a given piece of
 * evidence is missing, we keep the dimension but surface that explicitly
 * via `LocalTrustExplanation.dimensionEvidence` so callers can tell
 * "computed from N data points" apart from "unknown, neutral baseline".
 */
export interface LocalTrustMetrics {
  /** Percentage 0–100 (effective uptime over the rolling window). */
  uptime: number;
  /** Fraction 0–1 of successful tool / action invocations. */
  successRate: number;
  /** Number of IFC / policy violations observed. */
  violationCount: number;

  // --- transparency evidence (all optional) ---
  auditEntriesTotal?: number;
  auditEntriesSigned?: number;
  auditEntriesWithReason?: number;

  // --- compliance evidence ---
  policyEvaluationsTotal?: number;
  policyEvaluationsDenied?: number;
  humanApprovalRequiredCount?: number;
  humanApprovalGrantedCount?: number;

  // --- reputation evidence ---
  peerInteractionsCount?: number;
  peerSuccessfulVerifications?: number;
  operationalDays?: number;
}

export interface LocalTrustExplanation {
  dimensionEvidence: Record<
    'performance' | 'transparency' | 'security' | 'compliance' | 'reputation' | 'reliability',
    'computed' | 'neutral-baseline'
  >;
}

function clamp01to100(n: number): number {
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(100, n));
}

/**
 * Compute transparency from signed / reasoned audit entries.
 * Returns `null` if there are no entries to evaluate.
 */
function transparencyFromEvidence(m: LocalTrustMetrics): number | null {
  const total = m.auditEntriesTotal ?? 0;
  if (total <= 0) return null;
  const signed = (m.auditEntriesSigned ?? 0) / total;
  const reasoned = (m.auditEntriesWithReason ?? 0) / total;
  // Weighted: reasons matter slightly more than signatures for transparency;
  // an entry without a reason tells an auditor nothing even if signed.
  return clamp01to100((signed * 0.4 + reasoned * 0.6) * 100);
}

/**
 * Compute compliance from active enforcement: did the policy engine actually
 * run, did it deny anything, and when human approval was required was it
 * obtained. With no evaluations on record we return null.
 */
function complianceFromEvidence(m: LocalTrustMetrics): number | null {
  const total = m.policyEvaluationsTotal ?? 0;
  if (total <= 0) return null;
  const denialRate = (m.policyEvaluationsDenied ?? 0) / total;
  // Presence of enforcement is evidence — 40 pts just for running the engine;
  // denials above 0 show the engine isn't a rubber stamp (+ up to 40 pts);
  // human oversight compliance tops it off (+ up to 20 pts).
  const required = m.humanApprovalRequiredCount ?? 0;
  const granted = m.humanApprovalGrantedCount ?? 0;
  const oversightFrac = required > 0 ? granted / required : 1;
  const enforcementBonus = Math.min(40, denialRate * 200); // 20% denials → full
  return clamp01to100(40 + enforcementBonus + oversightFrac * 20);
}

/**
 * Compute reputation from peer interaction history + operational maturity.
 * With no peer data at all we return null rather than invent a number.
 */
function reputationFromEvidence(m: LocalTrustMetrics): number | null {
  const peers = m.peerInteractionsCount ?? 0;
  const days = m.operationalDays ?? 0;
  if (peers <= 0 && days <= 0) return null;
  const peerFrac = peers > 0 ? (m.peerSuccessfulVerifications ?? 0) / peers : 0;
  const maturityFrac = Math.min(1, days / 90); // 90 days → full maturity credit
  return clamp01to100((peerFrac * 0.6 + maturityFrac * 0.4) * 100);
}

/**
 * Trust Score Manager — handles self-audit cycle and mode transitions.
 */
export class TrustScoreManager {
  private currentScore: TrustScore | null = null;
  private mode: TrustMode = 'SAFE';
  private history: TrustScore[] = [];
  private listeners: Array<(mode: TrustMode, score: TrustScore) => void> = [];
  private lastExplanation: LocalTrustExplanation | null = null;

  constructor(
    private client: AgentLayersClient,
    private agentDid: string,
  ) {}

  async selfAudit(): Promise<TrustScore | null> {
    const score = await this.client.getTrustScore(this.agentDid);
    if (!score) return this.currentScore;

    this.currentScore = score;
    this.history.push(score);
    if (this.history.length > 1000) {
      this.history = this.history.slice(-1000);
    }

    const newMode = trustModeFromScore(score.overall);
    if (newMode !== this.mode) {
      this.mode = newMode;
      for (const listener of this.listeners) {
        listener(newMode, score);
      }
    }

    return score;
  }

  /**
   * When AgentLayers is not available, compute a local baseline score from
   * real runtime evidence. Each of the 6 dimensions is either:
   *   - "computed"          — derived from local data (marked in `dimensionEvidence`)
   *   - "neutral-baseline"  — no evidence available, use a conservative default
   * The distinction is retained on `getLastExplanation()` so the dashboard
   * can show "computed from N audit entries" vs "baseline only".
   */
  computeLocalBaseline(metrics: LocalTrustMetrics): TrustScore {
    const performance = clamp01to100(metrics.uptime);
    const security = clamp01to100(100 - metrics.violationCount * 10);
    const reliability = clamp01to100(metrics.successRate * 100);

    const NEUTRAL_TRANSPARENCY = 70;
    const NEUTRAL_COMPLIANCE = 50;
    const NEUTRAL_REPUTATION = 50;

    const transparencyComputed = transparencyFromEvidence(metrics);
    const complianceComputed = complianceFromEvidence(metrics);
    const reputationComputed = reputationFromEvidence(metrics);

    const transparency = transparencyComputed ?? NEUTRAL_TRANSPARENCY;
    const compliance = complianceComputed ?? NEUTRAL_COMPLIANCE;
    const reputation = reputationComputed ?? NEUTRAL_REPUTATION;

    this.lastExplanation = {
      dimensionEvidence: {
        performance: 'computed',
        transparency: transparencyComputed === null ? 'neutral-baseline' : 'computed',
        security: 'computed',
        compliance: complianceComputed === null ? 'neutral-baseline' : 'computed',
        reputation: reputationComputed === null ? 'neutral-baseline' : 'computed',
        reliability: 'computed',
      },
    };

    // Overall = weighted mean of the six dimensions. Weights mirror the
    // original emphasis (security+reliability heaviest) while giving the
    // three newly-computed dimensions real voice.
    const overall = clamp01to100(
      performance * 0.15 +
      transparency * 0.15 +
      security * 0.25 +
      compliance * 0.15 +
      reputation * 0.10 +
      reliability * 0.20,
    );

    const score: TrustScore = {
      overall,
      dimensions: {
        performance,
        transparency,
        security,
        compliance,
        reputation,
        reliability,
      },
      timestamp: Date.now(),
      certifiedBy: 'self:local-baseline',
    };

    this.currentScore = score;
    this.mode = trustModeFromScore(score.overall);
    return score;
  }

  getLastExplanation(): LocalTrustExplanation | null {
    return this.lastExplanation;
  }

  getMode(): TrustMode {
    return this.mode;
  }

  getCurrentScore(): TrustScore | null {
    return this.currentScore;
  }

  getHistory(): TrustScore[] {
    return [...this.history];
  }

  onModeChange(listener: (mode: TrustMode, score: TrustScore) => void): void {
    this.listeners.push(listener);
  }
}
