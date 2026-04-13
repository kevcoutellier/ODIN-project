/**
 * LLM Provider abstraction
 * Supports Anthropic, OpenAI, and Ollama
 */

import type { LLMConfig, LLMMessage, LLMResponse, TaintLabel, IntegrityLevel, ConfidentialityLevel, ToolDefinition } from '../types.js';

export interface LLMProviderAdapter {
  chat(messages: LLMMessage[], tools?: ToolDefinition[]): Promise<LLMResponse>;
  readonly provider: string;
  readonly model: string;
}

export class AnthropicAdapter implements LLMProviderAdapter {
  private client: any;
  readonly provider = 'anthropic';
  readonly model: string;

  constructor(private config: LLMConfig) {
    this.model = config.model;
  }

  async init(): Promise<void> {
    const { default: Anthropic } = await import('@anthropic-ai/sdk');
    this.client = new Anthropic({ apiKey: this.config.apiKey });
  }

  async chat(messages: LLMMessage[], tools?: ToolDefinition[]): Promise<LLMResponse> {
    if (!this.client) await this.init();

    const systemMsg = messages.find(m => m.role === 'system');
    const nonSystemMsgs = messages.filter(m => m.role !== 'system');

    const anthropicTools = tools?.map(t => ({
      name: t.name,
      description: t.description,
      input_schema: t.parameters,
    }));

    const response = await this.client.messages.create({
      model: this.config.model,
      max_tokens: this.config.maxTokens ?? 4096,
      temperature: this.config.temperature ?? 0.7,
      system: systemMsg?.content,
      messages: nonSystemMsgs.map(m => ({
        role: m.role === 'tool' ? 'user' : m.role as 'user' | 'assistant',
        content: m.role === 'tool'
          ? [{ type: 'tool_result' as const, tool_use_id: m.toolCallId!, content: m.content }]
          : m.content,
      })),
      ...(anthropicTools?.length ? { tools: anthropicTools } : {}),
    });

    const textBlock = response.content.find((b: any) => b.type === 'text');
    const toolUseBlocks = response.content.filter((b: any) => b.type === 'tool_use');

    return {
      content: textBlock?.text ?? '',
      toolCalls: toolUseBlocks.map((b: any) => ({
        id: b.id,
        name: b.name,
        arguments: b.input,
      })),
      usage: {
        inputTokens: response.usage?.input_tokens ?? 0,
        outputTokens: response.usage?.output_tokens ?? 0,
      },
      model: this.config.model,
      label: {
        integrity: 'DERIVED' as IntegrityLevel,
        confidentiality: 'PUBLIC' as ConfidentialityLevel,
        source: `llm:${this.config.provider}:${this.config.model}`,
        timestamp: Date.now(),
      },
    };
  }
}

export class OpenAIAdapter implements LLMProviderAdapter {
  private client: any;
  readonly provider = 'openai';
  readonly model: string;

  constructor(private config: LLMConfig) {
    this.model = config.model;
  }

  async init(): Promise<void> {
    const { default: OpenAI } = await import('openai');
    this.client = new OpenAI({
      apiKey: this.config.apiKey,
      ...(this.config.baseUrl ? { baseURL: this.config.baseUrl } : {}),
    });
  }

  async chat(messages: LLMMessage[], tools?: ToolDefinition[]): Promise<LLMResponse> {
    if (!this.client) await this.init();

    const openaiTools = tools?.map(t => ({
      type: 'function' as const,
      function: {
        name: t.name,
        description: t.description,
        parameters: t.parameters,
      },
    }));

    const response = await this.client.chat.completions.create({
      model: this.config.model,
      max_tokens: this.config.maxTokens ?? 4096,
      temperature: this.config.temperature ?? 0.7,
      messages: messages.map(m => ({
        role: m.role,
        content: m.content,
        ...(m.name ? { name: m.name } : {}),
        ...(m.toolCallId ? { tool_call_id: m.toolCallId } : {}),
      })),
      ...(openaiTools?.length ? { tools: openaiTools } : {}),
    });

    const choice = response.choices[0];
    const toolCalls = choice.message.tool_calls ?? [];

    return {
      content: choice.message.content ?? '',
      toolCalls: toolCalls.map((tc: any) => ({
        id: tc.id,
        name: tc.function.name,
        arguments: JSON.parse(tc.function.arguments),
      })),
      usage: {
        inputTokens: response.usage?.prompt_tokens ?? 0,
        outputTokens: response.usage?.completion_tokens ?? 0,
      },
      model: this.config.model,
      label: {
        integrity: 'DERIVED' as IntegrityLevel,
        confidentiality: 'PUBLIC' as ConfidentialityLevel,
        source: `llm:${this.config.provider}:${this.config.model}`,
        timestamp: Date.now(),
      },
    };
  }
}

export class OllamaAdapter implements LLMProviderAdapter {
  readonly provider = 'ollama';
  readonly model: string;
  private baseUrl: string;

  constructor(private config: LLMConfig) {
    this.model = config.model;
    this.baseUrl = config.baseUrl ?? 'http://localhost:11434';
  }

  async chat(messages: LLMMessage[], tools?: ToolDefinition[]): Promise<LLMResponse> {
    // Convert tools to Ollama format (OpenAI-compatible)
    const ollamaTools = tools?.map(t => ({
      type: 'function' as const,
      function: {
        name: t.name,
        description: t.description,
        parameters: t.parameters,
      },
    }));

    let response: Response;
    try {
      response = await fetch(`${this.baseUrl}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: this.config.model,
          messages: messages.map(m => ({
            role: m.role,
            content: m.content,
            ...(m.toolCallId ? { tool_call_id: m.toolCallId } : {}),
          })),
          stream: false,
          ...(ollamaTools?.length ? { tools: ollamaTools } : {}),
        }),
      });
    } catch (err) {
      throw new Error(`Failed to connect to Ollama at ${this.baseUrl}. Is Ollama running? (ollama serve) — ${err instanceof Error ? err.message : String(err)}`);
    }

    if (!response.ok) {
      throw new Error(`Ollama error: ${response.status} ${response.statusText}`);
    }

    const data = await response.json() as any;

    // Parse tool calls from Ollama response
    const toolCalls = (data.message?.tool_calls ?? []).map((tc: any) => ({
      id: tc.function?.name ?? `call_${Date.now()}`,
      name: tc.function?.name,
      arguments: tc.function?.arguments ?? {},
    }));

    return {
      content: data.message?.content ?? '',
      toolCalls,
      usage: {
        inputTokens: data.prompt_eval_count ?? 0,
        outputTokens: data.eval_count ?? 0,
      },
      model: this.config.model,
      label: {
        integrity: 'DERIVED' as IntegrityLevel,
        confidentiality: 'PUBLIC' as ConfidentialityLevel,
        source: `llm:ollama:${this.config.model}`,
        timestamp: Date.now(),
      },
    };
  }
}

export function createAdapter(config: LLMConfig): LLMProviderAdapter {
  switch (config.provider) {
    case 'anthropic': return new AnthropicAdapter(config);
    case 'openai': return new OpenAIAdapter(config);
    case 'ollama': return new OllamaAdapter(config);
    default: throw new Error(`Unknown LLM provider: ${config.provider}`);
  }
}
