/**
 * bolyra cred create — Create a new agent credential.
 */

import { parseArgs } from 'node:util';
import * as fs from 'node:fs';
import * as crypto from 'node:crypto';
import { createAgentCredential, permissionsToBitmask } from '@bolyra/sdk';
import { parseExpiry, parsePermissions, parseKeyFile, serializeBigInt } from '../parse';
import { saveCredential, ensureStoreDir } from '../store';
import type { StoredCredential } from '../format';

const HELP = `bolyra cred create — Create a new agent credential

Flags:
  --operator-key <path>   Path to Ed25519 private key file (required)
  --model <name>          Model identifier string (required)
  --permissions <list>    Comma-separated permission names (required)
                          Valid: read,write,financial_small,financial_medium,
                                 financial_unlimited,sign,delegate,pii
  --expiry <duration>     Duration (30d, 1y, 8h) or Unix timestamp (required)
  --out <path>            Output file path (default: stdout)
  --store                 Also save to ~/.bolyra/credentials/
  --help                  Show this help
`;

export async function run(args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: {
      'operator-key': { type: 'string' },
      model: { type: 'string' },
      permissions: { type: 'string' },
      expiry: { type: 'string' },
      out: { type: 'string' },
      store: { type: 'boolean', default: false },
      help: { type: 'boolean', default: false },
    },
    strict: true,
  });

  if (values.help) {
    console.log(HELP);
    return;
  }

  if (!values['operator-key']) {
    console.error('Error: --operator-key is required');
    process.exitCode = 2;
    return;
  }
  if (!values.model) {
    console.error('Error: --model is required');
    process.exitCode = 2;
    return;
  }
  if (!values.permissions) {
    console.error('Error: --permissions is required');
    process.exitCode = 2;
    return;
  }
  if (!values.expiry) {
    console.error('Error: --expiry is required');
    process.exitCode = 2;
    return;
  }

  // Read operator key
  const keyContent = fs.readFileSync(values['operator-key']);
  const operatorKey = parseKeyFile(keyContent);

  // Hash model name: SHA-256 truncated to BN254 field
  const modelHashBytes = crypto.createHash('sha256').update(values.model).digest();
  const modelHashFull = BigInt('0x' + modelHashBytes.toString('hex'));
  // Truncate to BN254 scalar field (modular reduction)
  const BN254_FIELD_ORDER = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
  const modelHash = modelHashFull % BN254_FIELD_ORDER;

  // Parse permissions
  const permissions = parsePermissions(values.permissions);

  // Parse expiry
  const expiryTimestamp = parseExpiry(values.expiry);

  // Create credential
  const credential = await createAgentCredential(
    modelHash,
    operatorKey,
    permissions,
    expiryTimestamp,
  );

  // Serialize for output
  const serialized = serializeBigInt(credential) as Record<string, unknown>;

  // Add metadata
  const stored: StoredCredential = {
    commitment: credential.commitment.toString(),
    modelHash: credential.modelHash.toString(),
    modelName: values.model,
    operatorPublicKey: {
      x: credential.operatorPublicKey.x.toString(),
      y: credential.operatorPublicKey.y.toString(),
    },
    permissionBitmask: credential.permissionBitmask.toString(),
    expiryTimestamp: credential.expiryTimestamp.toString(),
    signature: {
      R8: {
        x: credential.signature.R8.x.toString(),
        y: credential.signature.R8.y.toString(),
      },
      S: credential.signature.S.toString(),
    },
    createdAt: new Date().toISOString(),
    revoked: false,
    revokedAt: null,
    revokedReason: null,
  };

  const jsonOutput = JSON.stringify(stored, null, 2);

  // Output
  if (values.out) {
    fs.writeFileSync(values.out, jsonOutput + '\n', 'utf-8');
    console.error(`Credential written to: ${values.out}`);
  } else {
    console.error('WARNING: Full credential printed to stdout. Use --out <file> or --store to save securely.');
    console.log(jsonOutput);
  }

  // Store
  if (values.store) {
    const storePath = saveCredential(stored);
    console.error(`Stored at: ${storePath}`);
  }

  // Print commitment to stderr for easy capture
  console.error(`Commitment: ${credential.commitment.toString()}`);
}
