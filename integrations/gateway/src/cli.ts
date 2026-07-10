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

import * as fs from 'node:fs';
import * as path from 'node:path';
import { parseArgs } from 'node:util';
import { loadConfig } from './config';
import { hasStaticCredentials } from './credential-binding';
import { createGatewayProxy } from './proxy';
import { createReceiptWriter } from './receipts';
import { createGatewayReceiptSigner } from './receipt-signer';
import type { GatewayReceiptSigner } from './receipt-signer';
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
  --dev                Bolyra Core mode: classical checks, no ZK circuits.
                       With registered credentials (credentials section or
                       --credentials) permission claims are enforced against
                       the registry; without them, claims are self-asserted.
  --credentials <path> Credentials file (YAML/JSON map: commitment ->
                       { permissionBitmask, expiryTimestamp? }); overrides
                       the config's credentials section
  --receipt-dir <path> Directory for receipt JSON files (default: ./receipts/)
  --receipt-stdout     Write receipts to stdout (NDJSON)
  --no-receipts        Disable receipt generation
  --network <name>     Bolyra network (default: base-sepolia)
  --help               Show this help
  --version            Show version

Examples:
  # Minimal: proxy in Core mode (tutorial-friendly, claims self-asserted)
  bolyra-gateway --target http://localhost:3000/mcp --dev

  # Core mode with enforced credential binding
  bolyra-gateway --target http://localhost:3000/mcp --dev --credentials ./credentials.yaml

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
        credentials: { type: 'string' },
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
    credentials: values.credentials as string | undefined,
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

  // Credential binding visibility (v0.4.0). Unconfigured dev stays
  // frictionless for tutorials, but the tradeoff must be loud.
  const credentialsConfigured = hasStaticCredentials(config.credentials);
  if (config.devMode && !credentialsConfigured) {
    console.warn('[gateway] WARNING: Core mode without registered credentials — permission claims are self-asserted and NOT verified. Add a credentials section to gateway.yaml (or pass --credentials <path>) to enforce credential binding.');
  }
  if (!config.devMode && !credentialsConfigured) {
    console.warn('[gateway] WARNING: production mode without credentials — every tools/call will be denied (verification requires a credential resolver). Add a static credentials section or embed the middleware with resolveCredential.');
  }

  // Warn if HMAC is not configured in production mode
  if (!config.devMode && !config.hmac) {
    console.warn('[gateway] WARNING: HMAC signing not configured. X-Bolyra-* headers sent to upstream will be unsigned. Set hmac.secret in your config for production deployments.');
  }

  // Warn if Redis is using unencrypted connection in production
  if (!config.devMode && config.nonce.store === 'redis' && config.nonce.redis?.url?.startsWith('redis://')) {
    console.warn('[gateway] WARNING: Redis URL uses unencrypted redis:// -- consider rediss:// for production');
  }

  // Create receipt writer + resolve the receipt signer.
  // Every allow/deny decision gets an ES256K-signed receipt. Without a
  // configured receipts.privateKey the key is ephemeral: receipts stay
  // independently verifiable (the signer address is recoverable from each
  // signature and printed below / persisted to signer.json), but the address
  // rotates on restart.
  const receiptWriter = createReceiptWriter(config.receipts);
  let receiptSigner: GatewayReceiptSigner | undefined;
  if (config.receipts.enabled) {
    try {
      receiptSigner = createGatewayReceiptSigner(config);
    } catch (err) {
      console.error(`Receipt signer error: ${(err as Error).message}`);
      console.error('Check receipts.privateKey in your config (32-byte hex secp256k1 key).');
      process.exit(1);
    }

    if (receiptSigner.ephemeral && !config.devMode) {
      console.warn('[gateway] WARNING: no receipts.privateKey configured — using an ephemeral signing key. Receipts remain verifiable, but the signer address rotates on restart. Set receipts.privateKey for a pinnable trust anchor.');
    }

    // Persist the signer identity next to file-mode receipts so auditors can
    // pin the trust anchor (same pattern as the verified-actions demo).
    if (config.receipts.output === 'file') {
      try {
        const dir = config.receipts.dir ?? './receipts/';
        fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(
          path.join(dir, 'signer.json'),
          JSON.stringify(
            {
              issuer: receiptSigner.issuer,
              keyId: receiptSigner.keyId,
              alg: receiptSigner.alg,
              signer: receiptSigner.signer,
              ephemeral: receiptSigner.ephemeral,
            },
            null,
            2,
          ) + '\n',
        );
      } catch (err) {
        console.warn(`[gateway] WARNING: could not write signer.json: ${(err as Error).message}`);
      }
    }
  }

  // Create nonce store based on config
  let nonceStore: NonceStore;
  if (config.nonce.store === 'redis') {
    const redisUrl = config.nonce.redis?.url;
    if (!redisUrl) throw new Error('Redis URL is required when nonce.store is redis');
    nonceStore = new RedisNonceStore({
      url: redisUrl,
      keyPrefix: config.nonce.redis?.keyPrefix,
      connectTimeout: config.nonce.redis?.connectTimeout,
    });
  } else {
    nonceStore = new MemoryNonceStore();
  }

  // Create and start the proxy. Passing the resolved signer keeps the
  // proxy's signing key identical to the one printed in the banner and
  // persisted to signer.json.
  const server = createGatewayProxy({
    config,
    receiptWriter,
    nonceStore,
    gatewayReceiptSigner: receiptSigner,
  });

  server.listen(config.port, () => {
    printBanner(config, receiptSigner);
  });

  // Graceful shutdown
  const shutdown = async () => {
    console.log('\n[gateway] Shutting down...');
    if (nonceStore instanceof RedisNonceStore) {
      try { await nonceStore.close(); } catch { /* already disconnected */ }
    }
    server.close(() => {
      process.exit(0);
    });
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

/** Redact credentials from a URL for safe logging. */
function redactUrl(url: string): string {
  try {
    const parsed = new URL(url);
    if (parsed.password) parsed.password = '***';
    if (parsed.username) parsed.username = '***';
    return parsed.toString();
  } catch { return '(invalid url)'; }
}

/** Print the startup banner. */
function printBanner(
  config: import('./types').GatewayConfig,
  receiptSigner?: GatewayReceiptSigner,
): void {
  const receiptInfo = !config.receipts.enabled
    ? 'disabled'
    : config.receipts.output === 'stdout'
      ? 'stdout (NDJSON)'
      : config.receipts.output === 'webhook'
        ? 'webhook'
        : `${config.receipts.dir ?? './receipts/'} (file)`;

  const nonceInfo = config.nonce.store === 'redis'
    ? `redis (${redactUrl(config.nonce.redis?.url ?? 'unknown')})`
    : 'memory';

  const signerInfo = receiptSigner
    ? `${receiptSigner.signer} (ES256K${receiptSigner.ephemeral ? ', ephemeral — set receipts.privateKey to persist' : ''})`
    : 'n/a';

  const registeredCount = hasStaticCredentials(config.credentials)
    ? Object.keys(config.credentials.map).length
    : 0;
  const bindingInfo = config.devMode
    ? registeredCount > 0
      ? `enforcing (${registeredCount} registered credential${registeredCount === 1 ? '' : 's'})`
      : 'NONE — permission claims self-asserted (add credentials to enforce)'
    : registeredCount > 0
      ? `scopeCommitment (static registry, ${registeredCount} credential${registeredCount === 1 ? '' : 's'})`
      : 'scopeCommitment (resolver required — none configured)';

  console.log(`
@bolyra/gateway v${VERSION}
  Mode:     ${config.devMode ? 'dev' : 'production'}
  Target:   ${config.target}
  Port:     ${config.port}
  Binding:  ${bindingInfo}
  Nonce:    ${nonceInfo}
  Receipts: ${receiptInfo}
  Signer:   ${signerInfo}
  Network:  ${config.network}
`);
}

// Run if executed directly (not imported)
if (require.main === module) {
  main();
}
