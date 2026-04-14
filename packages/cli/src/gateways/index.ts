/**
 * Gateway Factory — Creates the right gateway based on config
 */

export { BaseGateway, type GatewayMessage, type GatewayResponse, type GatewayConfig, type ChatHandler } from './base.js';
export { TelegramGateway } from './telegram.js';
export { DiscordGateway } from './discord.js';

import type { GatewayConfig } from './base.js';
import { BaseGateway } from './base.js';
import { TelegramGateway } from './telegram.js';
import { DiscordGateway } from './discord.js';

export interface GatewayOptions {
  type: 'cli' | 'telegram' | 'discord' | 'slack' | 'whatsapp';
  telegramToken?: string;
  discordToken?: string;
  slackToken?: string;
  allowedUsers?: string[];
  requireMention?: boolean;
  streaming?: boolean;
}

/**
 * Create a gateway instance based on configuration.
 * Returns null for 'cli' type (handled by dashboard WebSocket).
 */
export function createGateway(options: GatewayOptions): BaseGateway | null {
  const config: GatewayConfig = {
    allowedUsers: options.allowedUsers ?? [],
    requireMention: options.requireMention ?? true,
    streaming: options.streaming ?? false,
  };

  switch (options.type) {
    case 'telegram': {
      if (!options.telegramToken) {
        throw new Error('Telegram gateway requires telegramToken in config or TELEGRAM_BOT_TOKEN env var');
      }
      return new TelegramGateway(options.telegramToken, config);
    }

    case 'discord': {
      if (!options.discordToken) {
        throw new Error('Discord gateway requires discordToken in config or DISCORD_BOT_TOKEN env var');
      }
      return new DiscordGateway(options.discordToken, config);
    }

    case 'slack':
    case 'whatsapp':
      console.warn(`[Gateway] ${options.type} gateway is not yet implemented, falling back to CLI mode`);
      return null;

    case 'cli':
    default:
      return null; // CLI mode uses dashboard WebSocket
  }
}
