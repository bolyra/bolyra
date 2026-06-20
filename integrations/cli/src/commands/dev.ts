/**
 * bolyra dev — Generate dev identities for testing.
 */

import { parseArgs } from 'node:util';
import * as fs from 'node:fs';
import { createDevIdentities } from '@bolyra/sdk';
import { serializeBigInt } from '../parse';

const HELP = `bolyra dev — Generate dev identities for testing

Flags:
  --permissions <bitmask>   Permission bitmask, hex or decimal (default: 0xFF)
  --expiry <timestamp>      Expiry timestamp in Unix seconds (default: 2099-12-31)
  --out <path>              Output file for identities JSON (default: stdout)
  --help                    Show this help

WARNING: Dev identities use fixed seeds. Never use in production.
`;

export async function run(args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: {
      permissions: { type: 'string' },
      expiry: { type: 'string' },
      out: { type: 'string' },
      help: { type: 'boolean', default: false },
    },
    strict: true,
  });

  if (values.help) {
    console.log(HELP);
    return;
  }

  console.error('[bolyra] WARNING: Dev identities use fixed seeds. Never use in production.');

  // Parse options
  let permissionBitmask: bigint | undefined;
  if (values.permissions) {
    const permStr = values.permissions;
    if (permStr.startsWith('0x') || permStr.startsWith('0X')) {
      permissionBitmask = BigInt(permStr);
    } else {
      permissionBitmask = BigInt(permStr);
    }
  }

  let expiryTimestamp: bigint | undefined;
  if (values.expiry) {
    expiryTimestamp = BigInt(values.expiry);
  }

  const identities = await createDevIdentities({
    permissionBitmask,
    expiryTimestamp,
  });

  const serialized = serializeBigInt(identities) as Record<string, unknown>;
  const output = { ...serialized, _dev: true };
  const jsonOutput = JSON.stringify(output, null, 2);

  if (values.out) {
    fs.writeFileSync(values.out, jsonOutput + '\n', 'utf-8');
    console.error(`Dev identities written to: ${values.out}`);
  } else {
    console.log(jsonOutput);
  }
}
