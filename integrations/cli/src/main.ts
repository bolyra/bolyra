#!/usr/bin/env node

/**
 * Bolyra CLI — unified credential lifecycle management.
 *
 * Usage:
 *   bolyra cred create|inspect|revoke|list
 *   bolyra key generate|show
 *   bolyra receipt verify
 *   bolyra dev
 *   bolyra --help
 *   bolyra --version
 */

import { parseArgs } from 'node:util';

// Lazy-import command handlers to avoid loading SDK until needed
async function runCredCreate(args: string[]): Promise<void> {
  const { run } = await import('./commands/cred-create');
  await run(args);
}
async function runCredInspect(args: string[]): Promise<void> {
  const { run } = await import('./commands/cred-inspect');
  await run(args);
}
async function runCredRevoke(args: string[]): Promise<void> {
  const { run } = await import('./commands/cred-revoke');
  await run(args);
}
async function runCredList(args: string[]): Promise<void> {
  const { run } = await import('./commands/cred-list');
  await run(args);
}
async function runKeyGenerate(args: string[]): Promise<void> {
  const { run } = await import('./commands/key-generate');
  await run(args);
}
async function runKeyShow(args: string[]): Promise<void> {
  const { run } = await import('./commands/key-show');
  await run(args);
}
async function runReceiptVerify(args: string[]): Promise<void> {
  const { run } = await import('./commands/receipt-verify');
  await run(args);
}
async function runDev(args: string[]): Promise<void> {
  const { run } = await import('./commands/dev');
  await run(args);
}
async function runRun(args: string[]): Promise<void> {
  const { run } = await import('./commands/run');
  await run(args);
}

const HELP = `Bolyra CLI — credential lifecycle management

Usage:
  bolyra <command> [options]

Commands:
  cred create       Create a new agent credential
  cred inspect      Inspect a credential from file or store
  cred revoke       Revoke a credential in the local store
  cred list         List credentials in the local store

  key generate      Generate an Ed25519 operator keypair
  key show          Show public key info from a private key file

  receipt verify    Verify a signed audit receipt

  run               Run any MCP server with auth + HTTP exposure
  dev               Generate dev identities for testing

Options:
  --help, -h        Show this help message
  --version, -v     Show version

Store location: ~/.bolyra/credentials/
`;

function printVersion(): void {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const pkg = require('../package.json');
  console.log(`@bolyra/cli ${pkg.version}`);
}

/** Route argv to the correct command handler */
export async function main(argv: string[]): Promise<void> {
  // Strip node + script from argv if present
  const args = argv.length > 2 && argv[0]?.includes('node') ? argv.slice(2) : argv;

  if (args.length === 0 || args[0] === '--help' || args[0] === '-h') {
    console.log(HELP);
    return;
  }

  if (args[0] === '--version' || args[0] === '-v') {
    printVersion();
    return;
  }

  const group = args[0];
  const action = args[1];
  const rest = args.slice(2);

  switch (group) {
    case 'cred':
      switch (action) {
        case 'create':
          return runCredCreate(rest);
        case 'inspect':
          return runCredInspect(rest);
        case 'revoke':
          return runCredRevoke(rest);
        case 'list':
          return runCredList(rest);
        default:
          console.error(`Unknown cred command: ${action ?? '(none)'}`);
          console.error('Available: create, inspect, revoke, list');
          process.exitCode = 2;
          return;
      }
    case 'key':
      switch (action) {
        case 'generate':
          return runKeyGenerate(rest);
        case 'show':
          return runKeyShow(rest);
        default:
          console.error(`Unknown key command: ${action ?? '(none)'}`);
          console.error('Available: generate, show');
          process.exitCode = 2;
          return;
      }
    case 'receipt':
      if (action === 'verify') {
        return runReceiptVerify(rest);
      }
      console.error(`Unknown receipt command: ${action ?? '(none)'}`);
      console.error('Available: verify');
      process.exitCode = 2;
      return;
    case 'run':
      // Pass everything after 'run' including '--' separator
      return runRun(args.slice(1));
    case 'dev':
      return runDev(args.slice(1));
    default:
      console.error(`Unknown command: ${group}`);
      console.log(HELP);
      process.exitCode = 2;
      return;
  }
}

// Run if invoked directly
if (require.main === module) {
  main(process.argv).catch((err) => {
    console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 1;
  });
}
