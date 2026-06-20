/**
 * bolyra cred revoke <commitment> — Revoke a credential in the local store.
 */

import { parseArgs } from 'node:util';
import { revokeCredential } from '../store';
import { truncateHex } from '../parse';

const HELP = `bolyra cred revoke <commitment> — Revoke a credential

Arguments:
  <commitment>        Commitment value of the credential to revoke

Flags:
  --reason <text>     Optional reason for revocation
  --help              Show this help

Note: This is local-only revocation. It does not propagate to any
registry or on-chain state.
`;

export async function run(args: string[]): Promise<void> {
  const { values, positionals } = parseArgs({
    args,
    options: {
      reason: { type: 'string' },
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
    console.error('Error: provide a commitment value to revoke');
    process.exitCode = 2;
    return;
  }

  const commitment = positionals[0];

  try {
    const cred = revokeCredential(commitment, values.reason);
    console.log(`Credential ${truncateHex(BigInt(cred.commitment))} revoked.`);
    if (values.reason) {
      console.log(`Reason: ${values.reason}`);
    }
    console.error('Note: This is local-only revocation. It does not propagate to any registry or on-chain state.');
  } catch (err) {
    console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 1;
  }
}
