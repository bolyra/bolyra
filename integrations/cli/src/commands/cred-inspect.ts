/**
 * bolyra cred inspect <file|commitment> — Inspect a credential.
 */

import { parseArgs } from 'node:util';
import * as fs from 'node:fs';
import { formatCredentialInspect } from '../format';
import { loadCredential, loadCredentialFromFile } from '../store';
import type { StoredCredential } from '../format';

const HELP = `bolyra cred inspect <file|commitment> — Inspect a credential

Arguments:
  <file|commitment>   Path to credential JSON file, or commitment value

Flags:
  --json              Output raw JSON instead of human-readable table
  --help              Show this help
`;

export async function run(args: string[]): Promise<void> {
  const { values, positionals } = parseArgs({
    args,
    options: {
      json: { type: 'boolean', default: false },
      help: { type: 'boolean', default: false },
    },
    allowPositionals: true,
    strict: true,
  });

  if (values.help) {
    console.log(HELP);
    return;
  }

  if (positionals.length === 0) {
    console.error('Error: provide a credential file path or commitment value');
    process.exitCode = 2;
    return;
  }

  const target = positionals[0];
  let cred: StoredCredential | null = null;

  // Resolution order:
  // 1. If target is a file path that exists: read from file
  // 2. If target matches a commitment in store: read from store
  if (fs.existsSync(target)) {
    try {
      cred = loadCredentialFromFile(target);
    } catch (err) {
      console.error(`Error reading credential file: ${err instanceof Error ? err.message : String(err)}`);
      process.exitCode = 1;
      return;
    }
  } else {
    // Try as commitment
    cred = loadCredential(target);
  }

  if (!cred) {
    console.error(`Credential not found: "${target}"`);
    console.error('Provide a valid file path or a commitment stored in ~/.bolyra/credentials/');
    process.exitCode = 1;
    return;
  }

  if (values.json) {
    console.log(JSON.stringify(cred, null, 2));
  } else {
    console.log(formatCredentialInspect(cred));
  }
}
