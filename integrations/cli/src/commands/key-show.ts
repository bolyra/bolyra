/**
 * bolyra key show <file> — Show public key info from a private key file.
 */

import { parseArgs } from 'node:util';
import * as fs from 'node:fs';
import { parseKeyFile, truncateHex } from '../parse';

const HELP = `bolyra key show <file> — Show public key info from a private key file

Arguments:
  <file>              Path to private key file

Flags:
  --help              Show this help
`;

export async function run(args: string[]): Promise<void> {
  const { values, positionals } = parseArgs({
    args,
    options: {
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
    console.error('Error: provide a private key file path');
    process.exitCode = 2;
    return;
  }

  const keyPath = positionals[0];
  if (!fs.existsSync(keyPath)) {
    console.error(`Error: file not found: ${keyPath}`);
    process.exitCode = 1;
    return;
  }

  const keyContent = fs.readFileSync(keyPath);
  const privateKey = parseKeyFile(keyContent);

  // Derive public key using circomlibjs (same as SDK internals)
  const circomlibjs = await import('circomlibjs');
  const eddsa = await circomlibjs.buildEddsa();
  const poseidon = await circomlibjs.buildPoseidon();
  const F = poseidon.F;

  const pubKey = eddsa.prv2pub(privateKey);
  const x = F.toObject(pubKey[0]) as bigint;
  const y = F.toObject(pubKey[1]) as bigint;

  console.log('Public Key:');
  console.log(`  x: 0x${x.toString(16)}`);
  console.log(`  y: 0x${y.toString(16)}`);
  console.log(`  DID: did:bolyra:operator:${truncateHex(x)}`);
}
