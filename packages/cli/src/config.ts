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
      provider: 'none',
      model: 'none',
      baseUrl: '',
      maxTokens: 4096,
      temperature: 0.7,
    },
    quarantined: {
      provider: 'none',
      model: 'none',
      baseUrl: '',
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
  if (process.env.AGENTLAYERS_API_KEY) {
    config.trust.agentLayersApiKey = process.env.AGENTLAYERS_API_KEY;
  }

  // Explicit provider override
  if (process.env.ODIN_LLM_PROVIDER) {
    const allowed = ['anthropic', 'openai', 'ollama', 'none'] as const;
    const provider = process.env.ODIN_LLM_PROVIDER;
    if (!allowed.includes(provider as any)) {
      throw new Error(`Invalid ODIN_LLM_PROVIDER "${provider}". Allowed values: ${allowed.join(', ')}`);
    }
    config.llm.privileged.provider = provider as (typeof allowed)[number];
    config.llm.quarantined.provider = provider as (typeof allowed)[number];
  }

  // Auto-detect LLM from API keys (only if still 'none' after config file + env override)
  if (config.llm.privileged.provider === 'none') {
    if (process.env.ANTHROPIC_API_KEY) {
      config.llm.privileged = { provider: 'anthropic', model: 'claude-sonnet-4-20250514', apiKey: process.env.ANTHROPIC_API_KEY, maxTokens: 4096, temperature: 0.7 };
      config.llm.quarantined = { provider: 'anthropic', model: 'claude-haiku-4-5-20251001', apiKey: process.env.ANTHROPIC_API_KEY, maxTokens: 2048, temperature: 0.3 };
    } else if (process.env.OPENAI_API_KEY) {
      config.llm.privileged = { provider: 'openai', model: 'gpt-4o', apiKey: process.env.OPENAI_API_KEY, maxTokens: 4096, temperature: 0.7 };
      config.llm.quarantined = { provider: 'openai', model: 'gpt-4o-mini', apiKey: process.env.OPENAI_API_KEY, maxTokens: 2048, temperature: 0.3 };
    } else if (process.env.OLLAMA_BASE_URL || process.env.OLLAMA_HOST) {
      const baseUrl = process.env.OLLAMA_BASE_URL ?? process.env.OLLAMA_HOST ?? 'http://localhost:11434';
      config.llm.privileged = { provider: 'ollama', model: 'gemma3', baseUrl, maxTokens: 4096, temperature: 0.7 };
      config.llm.quarantined = { provider: 'ollama', model: 'gemma3', baseUrl, maxTokens: 2048, temperature: 0.3 };
    }
    // Otherwise stays 'none' — agent boots without LLM
  } else {
    // Apply API keys to configured provider
    if (process.env.ANTHROPIC_API_KEY && config.llm.privileged.provider === 'anthropic') {
      config.llm.privileged.apiKey = process.env.ANTHROPIC_API_KEY;
      config.llm.quarantined.apiKey = process.env.ANTHROPIC_API_KEY;
    }
    if (process.env.OPENAI_API_KEY && config.llm.privileged.provider === 'openai') {
      config.llm.privileged.apiKey = process.env.OPENAI_API_KEY;
      config.llm.quarantined.apiKey = process.env.OPENAI_API_KEY;
    }
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
