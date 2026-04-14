/**
 * Discord Gateway — Connects Odin to Discord via Gateway API
 *
 * Uses WebSocket gateway (no external library dependency).
 * Supports: text messages, slash commands, DM and guild channels,
 * @mention detection, Markdown formatting, message splitting.
 *
 * Implements Discord Gateway v10 with heartbeat, identify, and resume.
 */

import { BaseGateway, type GatewayConfig, type GatewayMessage, type GatewayResponse } from './base.js';
import { WebSocket } from 'ws';

const DISCORD_API = 'https://discord.com/api/v10';
const DISCORD_GATEWAY = 'wss://gateway.discord.gg/?v=10&encoding=json';
const MAX_MESSAGE_LENGTH = 2000;

// Gateway opcodes
const enum GatewayOp {
  Dispatch = 0,
  Heartbeat = 1,
  Identify = 2,
  Resume = 6,
  Hello = 10,
  HeartbeatAck = 11,
}

// Gateway intents
const INTENTS = {
  GUILDS: 1 << 0,
  GUILD_MESSAGES: 1 << 9,
  GUILD_MESSAGE_CONTENT: 1 << 15, // Privileged intent — must enable in Discord dev portal
  DIRECT_MESSAGES: 1 << 12,
  MESSAGE_CONTENT: 1 << 15,
};

interface DiscordMessage {
  id: string;
  channel_id: string;
  author: { id: string; username: string; bot?: boolean };
  content: string;
  guild_id?: string;
  mentions: Array<{ id: string }>;
}

export class DiscordGateway extends BaseGateway {
  private ws: WebSocket | null = null;
  private heartbeatInterval: ReturnType<typeof setInterval> | null = null;
  private sequence: number | null = null;
  private sessionId = '';
  private resumeUrl = '';
  private botUserId = '';

  constructor(
    private readonly token: string,
    config: GatewayConfig,
  ) {
    super('discord', config);
  }

  async start(): Promise<void> {
    if (this.running) return;

    // Get bot user info
    const me = await this.apiCall<{ id: string; username: string }>('/users/@me');
    this.botUserId = me.id;
    console.log(`[Discord] Bot ${me.username} connecting...`);

    this.running = true;
    this.connect(DISCORD_GATEWAY);
  }

  async stop(): Promise<void> {
    this.running = false;
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }
    if (this.ws) {
      this.ws.close(1000, 'Shutting down');
      this.ws = null;
    }
    console.log('[Discord] Gateway stopped');
  }

  async send(channelId: string, response: GatewayResponse): Promise<void> {
    const chunks = this.splitMessage(response.text);
    for (const chunk of chunks) {
      await this.apiCall(`/channels/${channelId}/messages`, {
        method: 'POST',
        body: {
          content: chunk,
          ...(response.replyToId ? { message_reference: { message_id: response.replyToId } } : {}),
        },
      });
    }
  }

  // ─── WebSocket Gateway ───

  private connect(url: string): void {
    this.ws = new WebSocket(url);

    this.ws.on('message', (data: Buffer) => {
      const payload = JSON.parse(data.toString());
      this.handlePayload(payload);
    });

    this.ws.on('close', (code: number) => {
      if (this.heartbeatInterval) {
        clearInterval(this.heartbeatInterval);
        this.heartbeatInterval = null;
      }
      if (this.running && code !== 1000) {
        console.log(`[Discord] Disconnected (code ${code}), reconnecting...`);
        setTimeout(() => {
          if (this.sessionId && this.resumeUrl) {
            this.connect(this.resumeUrl);
          } else {
            this.connect(DISCORD_GATEWAY);
          }
        }, 5000);
      }
    });

    this.ws.on('error', (err: Error) => {
      console.error('[Discord] WebSocket error:', err.message);
    });
  }

  private handlePayload(payload: { op: number; d: unknown; s: number | null; t: string | null }): void {
    if (payload.s !== null) this.sequence = payload.s;

    switch (payload.op) {
      case GatewayOp.Hello: {
        const { heartbeat_interval } = payload.d as { heartbeat_interval: number };
        this.startHeartbeat(heartbeat_interval);
        // Send Identify or Resume
        if (this.sessionId) {
          this.sendPayload(GatewayOp.Resume, {
            token: this.token,
            session_id: this.sessionId,
            seq: this.sequence,
          });
        } else {
          this.sendPayload(GatewayOp.Identify, {
            token: this.token,
            intents: INTENTS.GUILDS | INTENTS.GUILD_MESSAGES | INTENTS.GUILD_MESSAGE_CONTENT | INTENTS.DIRECT_MESSAGES,
            properties: {
              os: 'linux',
              browser: 'odin',
              device: 'odin',
            },
          });
        }
        break;
      }

      case GatewayOp.HeartbeatAck:
        // Connection is healthy
        break;

      case GatewayOp.Dispatch:
        this.handleDispatch(payload.t!, payload.d);
        break;
    }
  }

  private handleDispatch(event: string, data: unknown): void {
    switch (event) {
      case 'READY': {
        const ready = data as { session_id: string; resume_gateway_url: string; user: { username: string } };
        this.sessionId = ready.session_id;
        this.resumeUrl = ready.resume_gateway_url;
        console.log(`[Discord] Connected as ${ready.user.username}`);
        break;
      }

      case 'MESSAGE_CREATE': {
        const msg = data as DiscordMessage;
        // Ignore our own messages
        if (msg.author.bot || msg.author.id === this.botUserId) return;
        this.handleMessage(msg).catch(err => {
          console.error('[Discord] Message handling error:', err);
        });
        break;
      }
    }
  }

  private async handleMessage(msg: DiscordMessage): Promise<void> {
    const isDirect = !msg.guild_id;
    const isMention = msg.mentions.some(m => m.id === this.botUserId);

    // Strip mention from text
    let text = msg.content;
    if (isMention) {
      text = text.replace(new RegExp(`<@!?${this.botUserId}>\\s*`, 'g'), '').trim();
    }

    const gatewayMsg: GatewayMessage = {
      id: msg.id,
      userId: msg.author.id,
      username: msg.author.username,
      channelId: msg.channel_id,
      text,
      isDirect,
      isMention,
      raw: msg,
    };

    // Show typing indicator
    this.apiCall(`/channels/${msg.channel_id}/typing`, { method: 'POST' }).catch(() => {});

    const reply = await this.processMessage(gatewayMsg);
    if (reply) {
      await this.send(msg.channel_id, {
        text: reply,
        replyToId: isDirect ? undefined : msg.id,
      });
    }
  }

  private startHeartbeat(intervalMs: number): void {
    if (this.heartbeatInterval) clearInterval(this.heartbeatInterval);
    this.heartbeatInterval = setInterval(() => {
      this.sendPayload(GatewayOp.Heartbeat, this.sequence);
    }, intervalMs);
  }

  private sendPayload(op: number, d: unknown): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({ op, d }));
    }
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
      let splitAt = remaining.lastIndexOf('\n', MAX_MESSAGE_LENGTH);
      if (splitAt < MAX_MESSAGE_LENGTH / 2) splitAt = MAX_MESSAGE_LENGTH;
      chunks.push(remaining.slice(0, splitAt));
      remaining = remaining.slice(splitAt);
    }
    return chunks;
  }

  private async apiCall<T>(path: string, options?: { method?: string; body?: unknown }): Promise<T> {
    const res = await fetch(`${DISCORD_API}${path}`, {
      method: options?.method ?? 'GET',
      headers: {
        Authorization: `Bot ${this.token}`,
        'Content-Type': 'application/json',
      },
      body: options?.body ? JSON.stringify(options.body) : undefined,
    });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Discord API error ${res.status}: ${text}`);
    }
    // Some endpoints return 204 No Content
    if (res.status === 204) return undefined as T;
    return await res.json() as T;
  }
}
