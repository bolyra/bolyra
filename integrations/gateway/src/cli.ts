#!/usr/bin/env node
/**
 * @bolyra/gateway — CLI entry point.
 *
 * Uses Node.js built-in parseArgs (Node 18+). No external CLI framework.
 *
 * Usage:
 *   npx @bolyra/gateway --target http://localhost:3000/mcp
 *   bolyra-gateway --target http://localhost:3000/mcp --dev --port 4100
 */

import { parseArgs } from 'node:util';
import { loadConfig } from './config';
import { createGatewayProxy } from './proxy';
import { createReceiptWriter } from './receipts';
import { RedisNonceStore } from './redis-nonce-store';
import { MemoryNonceStore } from '@bolyra/mcp';
import type { NonceStore } from '@bolyra/mcp';
import type { CliFlags } from './config';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const VERSION: string = (require('../package.json') as { version: string }).version;

const HELP = `
@bolyra/gateway v${VERSION}
Bolyra MCP Auth Gateway — reverse proxy with ZKP agent authentication.

Usage:
  bolyra-gateway [options]
  npx @bolyra/gateway [options]

Options:
  --target <url>       Upstream MCP server URL (required unless in config)
  --port <number>      Gateway listen port (default: 4100)
  --config <path>      Path to gateway config file (default: ./gateway.yaml)
  --dev                Enable dev mode (mock verification, no real ZKP)
  --receipt-dir <path> Directory for receipt JSON files (default: ./receipts/)
  --receipt-stdout     Write receipts to stdout (NDJSON)
  --no-receipts        Disable receipt generation
  --network <name>     Bolyra network (default: base-sepolia)
  --help               Show this help
  --version            Show version

Examples:
  # Minimal: proxy with dev mode
  bolyra-gateway --target http://localhost:3000/mcp --dev

  # Production with config file
  bolyra-gateway --config ./gateway.yaml

  # Override config with CLI flags
  bolyra-gateway --config ./gateway.yaml --port 8080 --receipt-stdout
`.trim();

/** Parse CLI arguments and start the gateway. */
export function main(argv: string[] = process.argv.slice(2)): void {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      options: {
        target: { type: 'string' },
        port: { type: 'string' }, // parse as string, convert to number
        config: { type: 'string' },
        dev: { type: 'boolean', default: false },
        'receipt-dir': { type: 'string' },
        'receipt-stdout': { type: 'boolean', default: false },
        'no-receipts': { type: 'boolean', default: false },
        network: { type: 'string' },
        help: { type: 'boolean', default: false },
        version: { type: 'boolean', default: false },
      },
      strict: true,
    });
  } catch (err) {
    console.error(`Error: ${(err as Error).message}`);
    console.error('Run with --help for usage.');
    process.exit(1);
  }

  const { values } = parsed;

  if (values.help) {
    console.log(HELP);
    process.exit(0);
  }

  if (values.version) {
    console.log(VERSION);
    process.exit(0);
  }

  // Build CLI flags
  const flags: CliFlags = {
    target: values.target as string | undefined,
    port: values.port ? parseInt(values.port as string, 10) : undefined,
    config: values.config as string | undefined,
    dev: values.dev as boolean | undefined,
    receiptDir: values['receipt-dir'] as string | undefined,
    receiptStdout: values['receipt-stdout'] as boolean | undefined,
    noReceipts: values['no-receipts'] as boolean | undefined,
    network: values.network as string | undefined,
  };

  // Load and validate config
  let config;
  try {
    config = loadConfig(flags);
  } catch (err) {
    console.error(`Configuration error: ${(err as Error).message}`);
    process.exit(1);
  }

  // Warn if HMAC is not configured in production mode
  if (!config.devMode && !config.hmac) {
    console.warn('[gateway] WARNING: HMAC signing not configured. X-Bolyra-* headers sent to upstream will be unsigned. Set hmac.secret in your config for production deployments.');
  }

  // Create receipt writer
  const receiptWriter = createReceiptWriter(config.receipts);

  // Create nonce store based on config
  const nonceStore: NonceStore = config.nonce.store === 'redis'
    ? new RedisNonceStore({
        url: config.nonce.redis!.url,
        keyPrefix: config.nonce.redis?.keyPrefix,
        connectTimeout: config.nonce.redis?.connectTimeout,
      })
    : new MemoryNonceStore();

  // Create and start the proxy
  const server = createGatewayProxy({
    config,
    receiptWriter,
    nonceStore,
  });

  server.listen(config.port, () => {
    printBanner(config);
  });

  // Graceful shutdown
  const shutdown = async () => {
    console.log('\n[gateway] Shutting down...');
    if (nonceStore instanceof RedisNonceStore) {
      await nonceStore.close();
    }
    server.close(() => {
      process.exit(0);
    });
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

/** Print the startup banner. */
function printBanner(config: { target: string; port: number; devMode: boolean; nonce: { store: string; redis?: { url: string } }; receipts: { enabled: boolean; output: string; dir?: string }; network: string }): void {
  const receiptInfo = !config.receipts.enabled
    ? 'disabled'
    : config.receipts.output === 'stdout'
      ? 'stdout (NDJSON)'
      : config.receipts.output === 'webhook'
        ? 'webhook'
        : `${config.receipts.dir ?? './receipts/'} (file)`;

  const nonceInfo = config.nonce.store === 'redis'
    ? `redis (${config.nonce.redis?.url ?? 'unknown'})`
    : 'memory';

  console.log(`
@bolyra/gateway v${VERSION}
  Mode:     ${config.devMode ? 'dev' : 'production'}
  Target:   ${config.target}
  Port:     ${config.port}
  Nonce:    ${nonceInfo}
  Receipts: ${receiptInfo}
  Network:  ${config.network}
`);
}

// Run if executed directly (not imported)
if (require.main === module) {
  main();
}
