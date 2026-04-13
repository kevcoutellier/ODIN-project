/**
 * Configuration loader — YAML config with sensible defaults
 */

import type { OdinConfig } from '@odin/core';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join } from 'node:path';

const DEFAULT_CONFIG: OdinConfig = {
  agent: {
    name: 'Odin',
    description: 'Zero Trust AI Agent — Secured by design, trusted by network.',
  },
  llm: {
    privileged: {
      provider: 'ollama',
      model: 'gemma4',
      baseUrl: 'http://localhost:11434',
      maxTokens: 4096,
      temperature: 0.7,
    },
    quarantined: {
      provider: 'ollama',
      model: 'gemma4',
      baseUrl: 'http://localhost:11434',
      maxTokens: 2048,
      temperature: 0.3,
    },
  },
  memory: {
    dbPath: './odin-memory.db',
    maxEntries: 10000,
  },
  security: {
    defaultRing: 0,
    requireHumanApproval: ['shell_exec', 'code_exec', 'file_delete'],
    maxDailyCalls: 1000,
    sessionTtlSeconds: 3600,
    approvalMode: 'manual',
    approvalPersistence: 'session',
    redactSecrets: true,
    websiteBlocklist: [],
    loopDetection: { enabled: true, historySize: 20, warningThreshold: 3, criticalThreshold: 5 },
  },
  tools: {
    profile: 'full',
    allow: [],
    deny: [],
  },
  trust: {
    agentLayersBaseUrl: 'https://api.agent-layers.com',
    selfAuditIntervalSeconds: 300,
    trustDecayHalfLifeDays: 7,
  },
  gateway: {
    type: 'cli',
    humanDelay: { mode: 'off' },
    sessionReset: { mode: 'none' },
  },
  terminal: {
    backend: 'local',
    timeout: 180,
  },
  compression: {
    enabled: true,
    threshold: 0.5,
    targetRatio: 0.2,
    protectLastN: 20,
  },
  delegation: {
    enabled: true,
    maxConcurrent: 3,
    maxDepth: 2,
  },
  heartbeat: {
    enabled: true,
    intervalMs: 300000,
  },
  cron: {
    jobs: [],
  },
  observability: {
    auditLogPath: './odin-audit.log',
    dashboardPort: 3333,
  },
};

export async function loadConfig(configPath?: string): Promise<OdinConfig> {
  const config = structuredClone(DEFAULT_CONFIG);

  // Try loading from file
  const paths = configPath
    ? [configPath]
    : ['./odin.yaml', './odin.yml', './odin.json'];

  for (const p of paths) {
    if (existsSync(p)) {
      try {
        const raw = await readFile(p, 'utf-8');
        const yaml = await import('yaml');
        const fileConfig = yaml.parse(raw);
        deepMerge(config, fileConfig);
        break;
      } catch {
        // Skip invalid config files
      }
    }
  }

  // Environment variable overrides
  if (process.env.ANTHROPIC_API_KEY) {
    config.llm.privileged.apiKey = process.env.ANTHROPIC_API_KEY;
    config.llm.quarantined.apiKey = process.env.ANTHROPIC_API_KEY;
  }
  if (process.env.OPENAI_API_KEY && config.llm.privileged.provider === 'openai') {
    config.llm.privileged.apiKey = process.env.OPENAI_API_KEY;
  }
  if (process.env.AGENTLAYERS_API_KEY) {
    config.trust.agentLayersApiKey = process.env.AGENTLAYERS_API_KEY;
  }
  if (process.env.ODIN_LLM_PROVIDER) {
    const allowed = ['anthropic', 'openai', 'ollama'] as const;
    const provider = process.env.ODIN_LLM_PROVIDER;
    if (!allowed.includes(provider as any)) {
      throw new Error(`Invalid ODIN_LLM_PROVIDER "${provider}". Allowed values: ${allowed.join(', ')}`);
    }
    config.llm.privileged.provider = provider as (typeof allowed)[number];
    config.llm.quarantined.provider = provider as (typeof allowed)[number];
  }

  return config;
}

function deepMerge(target: any, source: any): void {
  for (const key of Object.keys(source)) {
    if (
      source[key] &&
      typeof source[key] === 'object' &&
      !Array.isArray(source[key]) &&
      target[key] &&
      typeof target[key] === 'object'
    ) {
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
}
