/**
 * bolyra key generate — Generate an Ed25519 operator keypair.
 */

import { parseArgs } from 'node:util';
import * as fs from 'node:fs';
import * as crypto from 'node:crypto';
import * as path from 'node:path';

const HELP = `bolyra key generate — Generate an Ed25519 operator keypair

Flags:
  --out <path>        Output path for private key (default: ./operator.key)
  --format <fmt>      Output format: raw or hex (default: raw)
  --help              Show this help

The private key is written with mode 0o600. The public key is derived
and saved to <out>.pub.
`;

export async function run(args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: {
      out: { type: 'string', default: './operator.key' },
      format: { type: 'string', default: 'raw' },
      help: { type: 'boolean', default: false },
    },
    strict: true,
  });

  if (values.help) {
    console.log(HELP);
    return;
  }

  const format = values.format ?? 'raw';
  if (format !== 'raw' && format !== 'hex') {
    console.error(`Invalid format: "${format}". Use: raw, hex`);
    process.exitCode = 2;
    return;
  }

  const outPath = values.out ?? './operator.key';

  // Generate 32 cryptographically random bytes
  const privateKeyBytes = crypto.randomBytes(32);

  // Write private key
  if (format === 'raw') {
    fs.writeFileSync(outPath, privateKeyBytes, { mode: 0o600 });
  } else {
    fs.writeFileSync(outPath, privateKeyBytes.toString('hex') + '\n', {
      mode: 0o600,
      encoding: 'utf-8',
    });
  }

  // Derive public key via circomlibjs (same approach as SDK internals)
  const circomlibjs = await import('circomlibjs');
  const eddsa = await circomlibjs.buildEddsa();
  const poseidon = await circomlibjs.buildPoseidon();
  const F = poseidon.F;

  const pubKey = eddsa.prv2pub(privateKeyBytes);
  const x = F.toObject(pubKey[0]) as bigint;
  const y = F.toObject(pubKey[1]) as bigint;

  // Write public key info to .pub file
  const pubContent = JSON.stringify(
    { x: x.toString(), y: y.toString() },
    null,
    2,
  );
  fs.writeFileSync(outPath + '.pub', pubContent + '\n', { encoding: 'utf-8', mode: 0o644 });

  console.log('Keypair generated:');
  console.log(`  Private key: ${outPath} (mode 0600)`);
  console.log(`  Public key:  ${outPath}.pub`);
  console.log(`  x: 0x${x.toString(16)}`);
  console.log(`  y: 0x${y.toString(16)}`);
}
