#!/usr/bin/env node

/**
 * Odin CLI — Interactive Zero Trust AI Agent
 *
 * Usage:
 *   odin              Start interactive chat
 *   odin --config     Specify config file path
 *   odin --status     Show security status
 */

import { createInterface } from 'node:readline';
import { OdinAgent } from './agent.js';
import { loadConfig } from './config.js';

const BANNER = `
╔══════════════════════════════════════════════════╗
║                                                  ║
║     ⚡ ODIN by AgentLayers                       ║
║                                                  ║
║     Zero Trust AI Agent                          ║
║     Secured by design. Trusted by network.       ║
║                                                  ║
╚══════════════════════════════════════════════════╝
`;

const COLORS = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  dim: '\x1b[2m',
  cyan: '\x1b[36m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
};

function colorize(text: string, color: keyof typeof COLORS): string {
  return `${COLORS[color]}${text}${COLORS.reset}`;
}

async function main() {
  const args = process.argv.slice(2);
  const configPath = args.find((_, i) => args[i - 1] === '--config');

  console.log(colorize(BANNER, 'cyan'));

  // Load config
  console.log(colorize('Loading configuration...', 'dim'));
  const config = await loadConfig(configPath);

  // Initialize agent
  console.log(colorize('Initializing Odin agent...', 'dim'));
  const agent = new OdinAgent(config, {
    onSecurityDecision: (action, allowed, reason) => {
      const icon = allowed ? colorize('[ALLOW]', 'green') : colorize('[DENY]', 'red');
      console.log(colorize(`  ${icon} ${action}: ${reason}`, 'dim'));
    },
    onToolCall: (name, args) => {
      console.log(colorize(`  [TOOL] ${name}(${JSON.stringify(args)})`, 'blue'));
    },
    onTrustModeChange: (mode) => {
      const color = mode === 'SAFE' ? 'green' : mode === 'CAUTION' ? 'yellow' : 'red';
      console.log(colorize(`\n  [TRUST] Mode changed to: ${mode}\n`, color));
    },
    onError: (error) => {
      console.error(colorize(`  [ERROR] ${error.message}`, 'red'));
    },
  });

  try {
    await agent.init();
  } catch (error: any) {
    console.error(colorize(`\nFailed to initialize: ${error.message}`, 'red'));
    console.error(colorize('Make sure Ollama is running (ollama serve) with Gemma 4 (ollama pull gemma4)', 'yellow'));
    process.exit(1);
  }

  const did = agent.getDID();
  const trustMode = agent.getTrustMode();
  const dashboardPort = config.observability.dashboardPort;

  console.log(colorize(`\n  DID: ${did.id}`, 'dim'));
  console.log(colorize(`  Trust Mode: ${trustMode}`, trustMode === 'SAFE' ? 'green' : 'yellow'));
  console.log(colorize(`  Session: ${agent.getSessionId()}`, 'dim'));
  console.log(colorize(`  LLM: Gemma 4 via Ollama (local, private)`, 'dim'));
  console.log(colorize(`  AgentLayers: ${agent.getTrustScore()?.certifiedBy?.includes('agent-layers') ? 'Connected' : 'Local only (free tier)'}`, 'dim'));
  console.log(colorize(`\n  Dashboard: http://localhost:${dashboardPort}`, 'cyan'));
  console.log();

  // Handle --status flag
  if (args.includes('--status')) {
    const score = agent.getTrustScore();
    console.log(colorize('Security Status:', 'bright'));
    console.log(JSON.stringify(score, null, 2));
    process.exit(0);
  }

  // Interactive REPL
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: colorize('you > ', 'cyan'),
  });

  console.log(colorize('Type your message. Commands: /status, /memory <query>, /quit\n', 'dim'));
  rl.prompt();

  rl.on('line', async (line) => {
    const input = line.trim();
    if (!input) {
      rl.prompt();
      return;
    }

    // Commands
    if (input === '/quit' || input === '/exit') {
      console.log(colorize('\nGoodbye. Stay secure.', 'cyan'));
      await agent.close();
      process.exit(0);
    }

    if (input === '/status') {
      const score = agent.getTrustScore();
      const report = agent.getAuditReport();
      console.log(colorize('\n--- Security Status ---', 'bright'));
      console.log(`  Trust Mode: ${agent.getTrustMode()}`);
      console.log(`  Trust Score: ${score?.overall ?? 'N/A'}/100`);
      console.log(`  Total Decisions: ${report.totalDecisions}`);
      console.log(`  Denied: ${report.deniedDecisions}`);
      console.log(colorize('--- End Status ---\n', 'bright'));
      rl.prompt();
      return;
    }

    if (input.startsWith('/memory ')) {
      const query = input.slice(8);
      try {
        const response = await agent.chat(`Search my memory for: ${query}`);
        console.log(colorize(`\nodin > ${response}\n`, 'green'));
      } catch (error: any) {
        console.error(colorize(`Error: ${error.message}`, 'red'));
      }
      rl.prompt();
      return;
    }

    // Regular chat
    try {
      console.log(); // spacing
      const response = await agent.chat(input);
      console.log(colorize(`odin > ${response}\n`, 'green'));
    } catch (error: any) {
      console.error(colorize(`\nError: ${error.message}\n`, 'red'));
    }

    rl.prompt();
  });

  rl.on('close', async () => {
    console.log(colorize('\nGoodbye. Stay secure.', 'cyan'));
    await agent.close();
    process.exit(0);
  });
}

main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
