/**
 * Gateway Base — Abstract interface for all message gateways
 *
 * Every gateway (CLI, Telegram, Discord, Slack, WhatsApp) implements
 * this interface. The agent doesn't care which platform delivers
 * the message — it only cares about the GatewayMessage contract.
 */

export interface GatewayMessage {
  /** Unique message ID from the platform */
  id: string;
  /** Platform user ID */
  userId: string;
  /** Display name of the sender */
  username: string;
  /** Channel/chat/group ID */
  channelId: string;
  /** The actual text content */
  text: string;
  /** Whether this is a direct message (not group) */
  isDirect: boolean;
  /** Whether the bot was mentioned (for group chats) */
  isMention: boolean;
  /** Original platform-specific message object */
  raw?: unknown;
}

export interface GatewayResponse {
  /** Text to send back */
  text: string;
  /** Optional: reply to a specific message */
  replyToId?: string;
  /** Optional: parse mode for rich text */
  parseMode?: 'text' | 'markdown' | 'html';
}

export interface GatewayConfig {
  /** List of allowed user IDs (empty = allow all) */
  allowedUsers: string[];
  /** Whether to require @mention in group chats */
  requireMention: boolean;
  /** Whether to stream responses */
  streaming: boolean;
}

export type ChatHandler = (message: string, meta: { userId: string; channelId: string }) => Promise<string>;

export abstract class BaseGateway {
  protected chatHandler: ChatHandler | null = null;
  protected running = false;

  constructor(
    protected readonly name: string,
    protected readonly gatewayConfig: GatewayConfig,
  ) {}

  /** Register the handler that processes messages (agent.chat) */
  onChat(handler: ChatHandler): void {
    this.chatHandler = handler;
  }

  /** Start listening for messages */
  abstract start(): Promise<void>;

  /** Stop the gateway gracefully */
  abstract stop(): Promise<void>;

  /** Send a proactive message (not in response to a user message) */
  abstract send(channelId: string, response: GatewayResponse): Promise<void>;

  /** Check if the gateway is currently running */
  isRunning(): boolean {
    return this.running;
  }

  /** Get gateway name for logging */
  getName(): string {
    return this.name;
  }

  /** Check if a user is allowed to interact */
  protected isUserAllowed(userId: string): boolean {
    if (this.gatewayConfig.allowedUsers.length === 0) return true;
    return this.gatewayConfig.allowedUsers.includes(userId);
  }

  /** Should the bot respond to this message? */
  protected shouldRespond(msg: GatewayMessage): boolean {
    // Always respond to direct messages
    if (msg.isDirect) return true;
    // In groups, check if mention is required
    if (this.gatewayConfig.requireMention && !msg.isMention) return false;
    return true;
  }

  /** Process an incoming message through the security pipeline */
  protected async processMessage(msg: GatewayMessage): Promise<string | null> {
    // Check user allowlist
    if (!this.isUserAllowed(msg.userId)) {
      return null; // Silently ignore unauthorized users
    }

    // Check if we should respond (mention requirement)
    if (!this.shouldRespond(msg)) {
      return null;
    }

    // Skip empty messages
    if (!msg.text.trim()) return null;

    // Route to agent
    if (!this.chatHandler) {
      return 'Gateway not connected to agent.';
    }

    return this.chatHandler(msg.text, {
      userId: msg.userId,
      channelId: msg.channelId,
    });
  }
}
