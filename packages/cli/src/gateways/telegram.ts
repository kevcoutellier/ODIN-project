/**
 * Telegram Gateway — Connects Odin to Telegram via Bot API
 *
 * Uses long polling (no webhook server needed).
 * Supports: text messages, /commands, group chats with @mention,
 * Markdown formatting, message splitting for long responses.
 *
 * Security: allowedUsers filter, requireMention for groups.
 */

import { BaseGateway, type GatewayConfig, type GatewayMessage, type GatewayResponse } from './base.js';

const TELEGRAM_API = 'https://api.telegram.org/bot';
const MAX_MESSAGE_LENGTH = 4096;
const POLL_TIMEOUT = 30; // seconds

interface TelegramUpdate {
  update_id: number;
  message?: {
    message_id: number;
    from: { id: number; username?: string; first_name: string };
    chat: { id: number; type: 'private' | 'group' | 'supergroup' | 'channel' };
    text?: string;
    entities?: Array<{ type: string; offset: number; length: number }>;
  };
}

interface TelegramResponse {
  ok: boolean;
  result: unknown;
  description?: string;
}

export class TelegramGateway extends BaseGateway {
  private offset = 0;
  private abortController: AbortController | null = null;
  private botUsername = '';

  constructor(
    private readonly token: string,
    config: GatewayConfig,
  ) {
    super('telegram', config);
  }

  async start(): Promise<void> {
    if (this.running) return;

    // Verify token and get bot info
    const me = await this.apiCall<{ id: number; username: string }>('getMe');
    this.botUsername = me.username;
    console.log(`[Telegram] Bot @${this.botUsername} connected`);

    this.running = true;
    this.pollLoop();
  }

  async stop(): Promise<void> {
    this.running = false;
    this.abortController?.abort();
    console.log('[Telegram] Gateway stopped');
  }

  async send(channelId: string, response: GatewayResponse): Promise<void> {
    const chunks = this.splitMessage(response.text);
    for (const chunk of chunks) {
      await this.apiCall('sendMessage', {
        chat_id: channelId,
        text: chunk,
        parse_mode: response.parseMode === 'html' ? 'HTML' : 'Markdown',
        ...(response.replyToId ? { reply_to_message_id: Number(response.replyToId) } : {}),
      });
    }
  }

  // ─── Internal ───

  private async pollLoop(): Promise<void> {
    while (this.running) {
      try {
        this.abortController = new AbortController();
        const updates = await this.apiCall<TelegramUpdate[]>('getUpdates', {
          offset: this.offset,
          timeout: POLL_TIMEOUT,
          allowed_updates: ['message'],
        }, this.abortController.signal);

        for (const update of updates) {
          this.offset = update.update_id + 1;
          if (update.message?.text) {
            await this.handleUpdate(update);
          }
        }
      } catch (err) {
        if (err instanceof Error && err.name === 'AbortError') break;
        console.error('[Telegram] Poll error:', err);
        // Back off on errors
        await new Promise(r => setTimeout(r, 5000));
      }
    }
  }

  private async handleUpdate(update: TelegramUpdate): Promise<void> {
    const msg = update.message!;
    const isPrivate = msg.chat.type === 'private';
    const isMention = this.checkMention(msg.text ?? '', msg.entities);

    // Strip bot mention from text
    let text = msg.text ?? '';
    if (isMention) {
      text = text.replace(new RegExp(`@${this.botUsername}\\s*`, 'gi'), '').trim();
    }

    // Handle /start command
    if (text === '/start') {
      await this.send(String(msg.chat.id), {
        text: `I am *Odin*, a Zero Trust AI agent by AgentLayers.\nSecured by design. Trusted by network.\n\nSend me a message to begin.`,
        parseMode: 'markdown',
      });
      return;
    }

    const gatewayMsg: GatewayMessage = {
      id: String(msg.message_id),
      userId: String(msg.from.id),
      username: msg.from.username ?? msg.from.first_name,
      channelId: String(msg.chat.id),
      text,
      isDirect: isPrivate,
      isMention,
      raw: update,
    };

    // Send typing indicator
    this.apiCall('sendChatAction', { chat_id: msg.chat.id, action: 'typing' }).catch(() => {});

    const reply = await this.processMessage(gatewayMsg);
    if (reply) {
      await this.send(String(msg.chat.id), {
        text: reply,
        replyToId: isPrivate ? undefined : String(msg.message_id),
        parseMode: 'markdown',
      });
    }
  }

  private checkMention(text: string, entities?: Array<{ type: string; offset: number; length: number }>): boolean {
    if (!entities) return false;
    return entities.some(e =>
      e.type === 'mention' && text.substring(e.offset, e.offset + e.length).toLowerCase() === `@${this.botUsername.toLowerCase()}`,
    );
  }

  private splitMessage(text: string): string[] {
    if (text.length <= MAX_MESSAGE_LENGTH) return [text];
    const chunks: string[] = [];
    let remaining = text;
    while (remaining.length > 0) {
      if (remaining.length <= MAX_MESSAGE_LENGTH) {
        chunks.push(remaining);
        break;
      }
      // Try to split at a newline
      let splitAt = remaining.lastIndexOf('\n', MAX_MESSAGE_LENGTH);
      if (splitAt < MAX_MESSAGE_LENGTH / 2) splitAt = MAX_MESSAGE_LENGTH;
      chunks.push(remaining.slice(0, splitAt));
      remaining = remaining.slice(splitAt);
    }
    return chunks;
  }

  private async apiCall<T>(method: string, params?: Record<string, unknown>, signal?: AbortSignal): Promise<T> {
    const url = `${TELEGRAM_API}${this.token}/${method}`;
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: params ? JSON.stringify(params) : undefined,
      signal,
    });
    const data = await res.json() as TelegramResponse;
    if (!data.ok) {
      throw new Error(`Telegram API error: ${data.description ?? 'Unknown error'}`);
    }
    return data.result as T;
  }
}
