/**
 * BaseGateway tests — allowlist, mention requirement, message routing.
 *
 * BaseGateway is abstract. We use a test double (TestGateway) that
 * exposes the protected methods so we can exercise the shared pipeline
 * that all real gateways (Telegram, Discord, CLI) inherit.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  BaseGateway,
  type GatewayConfig,
  type GatewayMessage,
  type GatewayResponse,
  type ChatHandler,
} from '../base.js';

/** Testable subclass — exposes the protected helpers. */
class TestGateway extends BaseGateway {
  public sent: Array<{ channelId: string; response: GatewayResponse }> = [];

  async start(): Promise<void> { this.running = true; }
  async stop(): Promise<void> { this.running = false; }
  async send(channelId: string, response: GatewayResponse): Promise<void> {
    this.sent.push({ channelId, response });
  }

  // Expose protected methods
  public checkUser(userId: string) { return this.isUserAllowed(userId); }
  public checkRespond(msg: GatewayMessage) { return this.shouldRespond(msg); }
  public route(msg: GatewayMessage) { return this.processMessage(msg); }
}

const msg = (overrides: Partial<GatewayMessage> = {}): GatewayMessage => ({
  id: 'm1',
  userId: 'user1',
  username: 'alice',
  channelId: 'c1',
  text: 'hello agent',
  isDirect: true,
  isMention: false,
  ...overrides,
});

let gw: TestGateway;
const defaultConfig = (overrides: Partial<GatewayConfig> = {}): GatewayConfig => ({
  allowedUsers: [],
  requireMention: false,
  streaming: false,
  ...overrides,
});

describe('BaseGateway — accessors', () => {
  beforeEach(() => { gw = new TestGateway('test', defaultConfig()); });

  it('getName returns the configured name', () => {
    expect(gw.getName()).toBe('test');
  });

  it('isRunning is false initially, true after start, false after stop', async () => {
    expect(gw.isRunning()).toBe(false);
    await gw.start();
    expect(gw.isRunning()).toBe(true);
    await gw.stop();
    expect(gw.isRunning()).toBe(false);
  });

  it('onChat registers a handler', async () => {
    const handler: ChatHandler = async () => 'reply';
    gw.onChat(handler);
    const response = await gw.route(msg());
    expect(response).toBe('reply');
  });
});

describe('BaseGateway — allowlist', () => {
  it('empty allowlist allows any user', () => {
    gw = new TestGateway('t', defaultConfig({ allowedUsers: [] }));
    expect(gw.checkUser('anyone')).toBe(true);
  });

  it('non-empty allowlist admits listed users', () => {
    gw = new TestGateway('t', defaultConfig({ allowedUsers: ['alice', 'bob'] }));
    expect(gw.checkUser('alice')).toBe(true);
    expect(gw.checkUser('bob')).toBe(true);
  });

  it('non-empty allowlist rejects unlisted users', () => {
    gw = new TestGateway('t', defaultConfig({ allowedUsers: ['alice'] }));
    expect(gw.checkUser('mallory')).toBe(false);
  });
});

describe('BaseGateway — shouldRespond', () => {
  it('always responds to direct messages', () => {
    gw = new TestGateway('t', defaultConfig({ requireMention: true }));
    expect(gw.checkRespond(msg({ isDirect: true, isMention: false }))).toBe(true);
  });

  it('ignores group messages without mention when requireMention=true', () => {
    gw = new TestGateway('t', defaultConfig({ requireMention: true }));
    expect(gw.checkRespond(msg({ isDirect: false, isMention: false }))).toBe(false);
  });

  it('responds to group messages with mention when requireMention=true', () => {
    gw = new TestGateway('t', defaultConfig({ requireMention: true }));
    expect(gw.checkRespond(msg({ isDirect: false, isMention: true }))).toBe(true);
  });

  it('responds to any group message when requireMention=false', () => {
    gw = new TestGateway('t', defaultConfig({ requireMention: false }));
    expect(gw.checkRespond(msg({ isDirect: false, isMention: false }))).toBe(true);
  });
});

describe('BaseGateway — processMessage pipeline', () => {
  it('returns null for unauthorized users (silent drop)', async () => {
    gw = new TestGateway('t', defaultConfig({ allowedUsers: ['alice'] }));
    gw.onChat(async () => 'reply');
    const result = await gw.route(msg({ userId: 'mallory' }));
    expect(result).toBeNull();
  });

  it('returns null for group messages without mention when requireMention=true', async () => {
    gw = new TestGateway('t', defaultConfig({ requireMention: true }));
    gw.onChat(async () => 'reply');
    const result = await gw.route(msg({ isDirect: false, isMention: false }));
    expect(result).toBeNull();
  });

  it('returns null for empty / whitespace-only text', async () => {
    gw = new TestGateway('t', defaultConfig());
    gw.onChat(async () => 'reply');
    expect(await gw.route(msg({ text: '' }))).toBeNull();
    expect(await gw.route(msg({ text: '   \n\t ' }))).toBeNull();
  });

  it('returns an informative fallback when no handler is registered', async () => {
    gw = new TestGateway('t', defaultConfig());
    const result = await gw.route(msg());
    expect(result).toBe('Gateway not connected to agent.');
  });

  it('routes valid messages through the registered chat handler', async () => {
    gw = new TestGateway('t', defaultConfig());
    let captured: { text: string; userId: string; channelId: string } | null = null;
    gw.onChat(async (text, meta) => {
      captured = { text, userId: meta.userId, channelId: meta.channelId };
      return 'handled';
    });
    const result = await gw.route(msg({ text: 'what is up', userId: 'u42', channelId: 'c99' }));
    expect(result).toBe('handled');
    expect(captured).toEqual({ text: 'what is up', userId: 'u42', channelId: 'c99' });
  });

  it('send() stores the outgoing response (subclass contract)', async () => {
    gw = new TestGateway('t', defaultConfig());
    await gw.send('c1', { text: 'hello' });
    expect(gw.sent).toHaveLength(1);
    expect(gw.sent[0]).toEqual({ channelId: 'c1', response: { text: 'hello' } });
  });
});
