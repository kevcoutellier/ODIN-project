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
 * Trust Score Manager — handles self-audit cycle and mode transitions.
 */
export class TrustScoreManager {
  private currentScore: TrustScore | null = null;
  private mode: TrustMode = 'SAFE';
  private history: TrustScore[] = [];
  private listeners: Array<(mode: TrustMode, score: TrustScore) => void> = [];

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
   * When AgentLayers is not available, compute a local baseline score.
   */
  computeLocalBaseline(metrics: {
    uptime: number;
    successRate: number;
    violationCount: number;
  }): TrustScore {
    const score: TrustScore = {
      overall: Math.max(0, Math.min(100,
        (metrics.uptime * 0.2 +
         metrics.successRate * 100 * 0.3 +
         Math.max(0, 100 - metrics.violationCount * 10) * 0.5)
      )),
      dimensions: {
        performance: metrics.uptime,
        transparency: 80, // baseline for open source
        security: Math.max(0, 100 - metrics.violationCount * 10),
        compliance: 50, // unknown without AgentLayers
        reputation: 50, // unknown without network data
        reliability: metrics.successRate * 100,
      },
      timestamp: Date.now(),
      certifiedBy: 'self:local-baseline',
    };

    this.currentScore = score;
    this.mode = trustModeFromScore(score.overall);
    return score;
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
