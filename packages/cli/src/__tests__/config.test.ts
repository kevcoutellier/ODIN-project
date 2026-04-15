/**
 * Config loader tests — YAML merge, env var overrides, provider auto-detect.
 *
 * Every test writes a temporary YAML (or relies on env-only path), loads it,
 * and asserts the resolved OdinConfig. We always chdir into a fresh temp dir
 * so `loadConfig()` doesn't pick up the real repo's odin.yaml.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadConfig } from '../config.js';

/** Keys this test ever touches. Snapshot → restore in afterEach. */
const TOUCHED_ENV = [
  'AGENTLAYERS_API_KEY', 'ODIN_LLM_PROVIDER',
  'ANTHROPIC_API_KEY', 'OPENAI_API_KEY',
  'OLLAMA_BASE_URL', 'OLLAMA_HOST',
];

describe('loadConfig', () => {
  let savedEnv: Record<string, string | undefined>;
  let savedCwd: string;
  let tempDir: string;

  beforeEach(() => {
    savedEnv = {};
    for (const k of TOUCHED_ENV) {
      savedEnv[k] = process.env[k];
      delete process.env[k];
    }
    savedCwd = process.cwd();
    tempDir = mkdtempSync(join(tmpdir(), 'odin-config-'));
    process.chdir(tempDir);
  });

  afterEach(() => {
    process.chdir(savedCwd);
    try { rmSync(tempDir, { recursive: true, force: true }); } catch {}
    for (const k of TOUCHED_ENV) {
      if (savedEnv[k] === undefined) delete process.env[k];
      else process.env[k] = savedEnv[k];
    }
  });

  // ─── Defaults ────────────────────────────────────────────────────

  it('returns defaults when no file and no env', async () => {
    const cfg = await loadConfig();
    expect(cfg.agent.name).toBe('Odin');
    expect(cfg.llm.privileged.provider).toBe('none');
    expect(cfg.llm.quarantined.provider).toBe('none');
    expect(cfg.memory.dbPath).toBe('./odin-memory.db');
    expect(cfg.observability.dashboardPort).toBe(3333);
    expect(cfg.trust.agentLayersBaseUrl).toBe('https://api.agent-layers.com');
    expect(cfg.trust.agentLayersApiKey).toBeUndefined();
  });

  // ─── YAML merging ────────────────────────────────────────────────

  it('deep-merges values from odin.yaml in the cwd', async () => {
    writeFileSync(join(tempDir, 'odin.yaml'), `
agent:
  name: "Freyja"
memory:
  maxEntries: 500
observability:
  dashboardPort: 9999
`);
    const cfg = await loadConfig();
    expect(cfg.agent.name).toBe('Freyja');
    expect(cfg.memory.maxEntries).toBe(500);
    expect(cfg.observability.dashboardPort).toBe(9999);
    // Untouched defaults preserved
    expect(cfg.memory.dbPath).toBe('./odin-memory.db');
    expect(cfg.security.defaultRing).toBe(0);
  });

  it('uses an explicit config path over the default discovery', async () => {
    const custom = join(tempDir, 'custom.yaml');
    writeFileSync(custom, 'agent:\n  name: "Custom"\n');
    writeFileSync(join(tempDir, 'odin.yaml'), 'agent:\n  name: "Default"\n');
    const cfg = await loadConfig(custom);
    expect(cfg.agent.name).toBe('Custom');
  });

  it('silently falls back to defaults when the YAML file is invalid', async () => {
    writeFileSync(join(tempDir, 'odin.yaml'), ':::not valid yaml:::\n  bad[indent');
    const cfg = await loadConfig();
    expect(cfg.agent.name).toBe('Odin');
  });

  it('honours the .yml and .json fallback extensions', async () => {
    writeFileSync(join(tempDir, 'odin.yml'), 'agent:\n  name: "FromYml"\n');
    const cfg = await loadConfig();
    expect(cfg.agent.name).toBe('FromYml');
  });

  // ─── AgentLayers API key ─────────────────────────────────────────

  it('picks up AGENTLAYERS_API_KEY from environment', async () => {
    process.env.AGENTLAYERS_API_KEY = 'sk-agl-test';
    const cfg = await loadConfig();
    expect(cfg.trust.agentLayersApiKey).toBe('sk-agl-test');
  });

  // ─── ODIN_LLM_PROVIDER ───────────────────────────────────────────

  it('ODIN_LLM_PROVIDER overrides both privileged and quarantined providers', async () => {
    process.env.ODIN_LLM_PROVIDER = 'ollama';
    process.env.OLLAMA_BASE_URL = 'http://ollama.local:11434';
    const cfg = await loadConfig();
    expect(cfg.llm.privileged.provider).toBe('ollama');
    expect(cfg.llm.quarantined.provider).toBe('ollama');
  });

  it('throws on an invalid ODIN_LLM_PROVIDER value', async () => {
    process.env.ODIN_LLM_PROVIDER = 'gpt5';
    await expect(loadConfig()).rejects.toThrow(/Invalid ODIN_LLM_PROVIDER/);
  });

  // ─── Auto-detection ──────────────────────────────────────────────

  it('auto-detects Anthropic from ANTHROPIC_API_KEY when provider is none', async () => {
    process.env.ANTHROPIC_API_KEY = 'sk-ant-test';
    const cfg = await loadConfig();
    expect(cfg.llm.privileged.provider).toBe('anthropic');
    expect(cfg.llm.privileged.apiKey).toBe('sk-ant-test');
    expect(cfg.llm.quarantined.provider).toBe('anthropic');
    expect(cfg.llm.quarantined.apiKey).toBe('sk-ant-test');
    // Privileged/quarantined models differ (Sonnet / Haiku split)
    expect(cfg.llm.privileged.model).not.toBe(cfg.llm.quarantined.model);
  });

  it('auto-detects OpenAI from OPENAI_API_KEY', async () => {
    process.env.OPENAI_API_KEY = 'sk-openai-test';
    const cfg = await loadConfig();
    expect(cfg.llm.privileged.provider).toBe('openai');
    expect(cfg.llm.privileged.apiKey).toBe('sk-openai-test');
    expect(cfg.llm.privileged.model).toBe('gpt-4o');
    expect(cfg.llm.quarantined.model).toBe('gpt-4o-mini');
  });

  it('auto-detects Ollama from OLLAMA_BASE_URL', async () => {
    process.env.OLLAMA_BASE_URL = 'http://ollama.test:11434';
    const cfg = await loadConfig();
    expect(cfg.llm.privileged.provider).toBe('ollama');
    expect(cfg.llm.privileged.baseUrl).toBe('http://ollama.test:11434');
    expect(cfg.llm.quarantined.baseUrl).toBe('http://ollama.test:11434');
  });

  it('auto-detects Ollama from OLLAMA_HOST when OLLAMA_BASE_URL absent', async () => {
    process.env.OLLAMA_HOST = 'http://ollama.host:11434';
    const cfg = await loadConfig();
    expect(cfg.llm.privileged.provider).toBe('ollama');
    expect(cfg.llm.privileged.baseUrl).toBe('http://ollama.host:11434');
  });

  it('Anthropic takes precedence over OpenAI when both keys are set', async () => {
    process.env.ANTHROPIC_API_KEY = 'sk-ant';
    process.env.OPENAI_API_KEY = 'sk-openai';
    const cfg = await loadConfig();
    expect(cfg.llm.privileged.provider).toBe('anthropic');
  });

  // ─── YAML + env interplay ───────────────────────────────────────

  it('YAML-specified provider is NOT overridden by auto-detect', async () => {
    // YAML sets provider explicitly; auto-detect should NOT replace it
    writeFileSync(join(tempDir, 'odin.yaml'), `
llm:
  privileged:
    provider: openai
    model: gpt-4o
  quarantined:
    provider: openai
    model: gpt-4o-mini
`);
    // But an Anthropic key is set in env
    process.env.ANTHROPIC_API_KEY = 'sk-ant';
    process.env.OPENAI_API_KEY = 'sk-openai';
    const cfg = await loadConfig();
    expect(cfg.llm.privileged.provider).toBe('openai');
    // OpenAI key is applied to the configured provider
    expect(cfg.llm.privileged.apiKey).toBe('sk-openai');
    expect(cfg.llm.quarantined.apiKey).toBe('sk-openai');
  });
});
