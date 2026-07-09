#!/usr/bin/env node
import { parseArgs } from 'node:util';
import * as path from 'path';
import { loadShieldConfig } from './config';
import { learn } from './learn';
import { createShield } from './shield';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const VERSION: string = (require('../package.json') as { version: string }).version;

const HELP = `
@bolyra/shield v${VERSION}
Stdio MCP auth proxy — wrap any MCP server with per-tool permission enforcement.

Usage:
  bolyra-shield --server "<command>" [options]
  npx @bolyra/shield --server "<command>" [options]

Options:
  --server <cmd>     Command to spawn the MCP server (required)
  --config <path>    Path to shield config file (default: ./shield.yaml)
  --learn            Discover the server's tools and generate a default-deny
                     shield.yaml (all tools at READ_DATA) instead of proxying
  --dev              Enable dev mode (mock verification)
  --help             Show this help
  --version          Show version

Examples:
  # Wrap the filesystem MCP server
  bolyra-shield --server "npx @modelcontextprotocol/server-filesystem /tmp" --dev

  # With config file
  bolyra-shield --server "node my-server.js" --config ./shield.yaml

  # Generate a starting policy from the server's own tool list
  bolyra-shield --learn --server "node my-server.js"
`.trim();

function main(argv: string[] = process.argv.slice(2)): void {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      options: {
        server: { type: 'string' },
        config: { type: 'string', default: './shield.yaml' },
        learn: { type: 'boolean', default: false },
        dev: { type: 'boolean', default: false },
        help: { type: 'boolean', default: false },
        version: { type: 'boolean', default: false },
      },
      strict: true,
    });
  } catch (err) {
    console.error(`Error: ${(err as Error).message}`);
    process.exit(1);
  }

  const { values } = parsed;

  if (values.help) { console.log(HELP); process.exit(0); }
  if (values.version) { console.log(VERSION); process.exit(0); }

  if (values.learn) {
    if (!values.server) {
      console.error('Error: --learn requires --server (command to spawn the MCP server)');
      process.exit(1);
    }
    const outPath = path.resolve(values.config as string);
    learn({ server: values.server as string, outPath })
      .then(({ tools }) => {
        process.stderr.write(`@bolyra/shield v${VERSION} — learn\n`);
        process.stderr.write(`  Discovered ${tools.length} tool${tools.length === 1 ? '' : 's'}:\n`);
        for (const t of tools) {
          process.stderr.write(`    ${t.name}  → requireBitmask: 1 (READ_DATA)\n`);
        }
        process.stderr.write(`\n  Wrote ${outPath} (defaultDeny: true).\n`);
        process.stderr.write(`  Review each tool and raise its requireBitmask before production use.\n`);
        process.exit(0);
      })
      .catch((err: Error) => {
        console.error(`Error: ${err.message}`);
        process.exit(1);
      });
    return;
  }

  const config = loadShieldConfig(
    values.config as string,
    values.server as string | undefined,
  );

  if (values.dev) config.devMode = true;

  process.stderr.write(`@bolyra/shield v${VERSION}\n`);
  process.stderr.write(`  Server:   ${config.server}\n`);
  process.stderr.write(`  Mode:     ${config.devMode ? 'dev' : 'production'}\n`);
  process.stderr.write(`  Tools:    ${Object.keys(config.tools).length} policies\n`);
  if (config.defaultDeny) {
    process.stderr.write(`  Policy:   default-deny (unknown tools rejected)\n`);
  }
  process.stderr.write(`  Receipts: stderr\n\n`);

  createShield(config);
}

main();
