/**
 * bolyra cred list — List credentials in the local store.
 */

import { parseArgs } from 'node:util';
import { listCredentials } from '../store';
import { formatCredentialTable, credentialStatus } from '../format';
import type { StoredCredential } from '../format';

const HELP = `bolyra cred list — List credentials in the local store

Flags:
  --json                Output as JSON array
  --filter <status>     Filter by: active, expired, revoked (default: all)
  --help                Show this help
`;

export async function run(args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: {
      json: { type: 'boolean', default: false },
      filter: { type: 'string' },
      help: { type: 'boolean', default: false },
    },
    strict: true,
  });

  if (values.help) {
    console.log(HELP);
    return;
  }

  let creds = listCredentials();

  // Apply filter
  if (values.filter) {
    const filterStatus = values.filter.toLowerCase();
    if (!['active', 'expired', 'revoked'].includes(filterStatus)) {
      console.error(`Invalid filter: "${values.filter}". Use: active, expired, revoked`);
      process.exitCode = 2;
      return;
    }
    creds = creds.filter((c) => {
      const status = credentialStatus(BigInt(c.expiryTimestamp), c.revoked);
      return status === filterStatus;
    });
  }

  if (values.json) {
    console.log(JSON.stringify(creds, null, 2));
  } else {
    console.log(formatCredentialTable(creds));
  }
}
