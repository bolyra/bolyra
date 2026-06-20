/**
 * Local credential store at ~/.bolyra/credentials/.
 *
 * Each credential is a JSON file named by the first 16 hex chars of
 * its commitment. All BigInt values are stored as decimal strings.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import type { StoredCredential } from './format';

/** Default store directory */
function defaultStoreDir(): string {
  return path.join(os.homedir(), '.bolyra', 'credentials');
}

/** Filename for a credential commitment (first 16 hex chars) */
function commitmentFilename(commitment: string): string {
  try {
    const hex = BigInt(commitment).toString(16);
    return `${hex.slice(0, 16)}.json`;
  } catch {
    // If commitment is not a valid bigint, use it as-is (truncated)
    const safe = commitment.replace(/[^a-zA-Z0-9]/g, '').slice(0, 16);
    return `${safe}.json`;
  }
}

/** Ensure the store directory exists */
export function ensureStoreDir(storeDir?: string): string {
  const dir = storeDir ?? defaultStoreDir();
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

/** Save a credential to the store */
export function saveCredential(
  cred: StoredCredential,
  storeDir?: string
): string {
  const dir = ensureStoreDir(storeDir);
  const filename = commitmentFilename(cred.commitment);
  const filePath = path.join(dir, filename);
  fs.writeFileSync(filePath, JSON.stringify(cred, null, 2) + '\n', 'utf-8');
  return filePath;
}

/** Load a credential by commitment from the store */
export function loadCredential(
  commitment: string,
  storeDir?: string
): StoredCredential | null {
  const dir = storeDir ?? defaultStoreDir();
  const filename = commitmentFilename(commitment);
  const filePath = path.join(dir, filename);
  if (!fs.existsSync(filePath)) return null;
  const data = fs.readFileSync(filePath, 'utf-8');
  return JSON.parse(data) as StoredCredential;
}

/** Load a credential from a file path */
export function loadCredentialFromFile(filePath: string): StoredCredential {
  const data = fs.readFileSync(filePath, 'utf-8');
  return JSON.parse(data) as StoredCredential;
}

/** List all credentials in the store */
export function listCredentials(storeDir?: string): StoredCredential[] {
  const dir = storeDir ?? defaultStoreDir();
  if (!fs.existsSync(dir)) return [];

  const files = fs.readdirSync(dir).filter((f) => f.endsWith('.json'));
  const creds: StoredCredential[] = [];

  for (const file of files) {
    try {
      const data = fs.readFileSync(path.join(dir, file), 'utf-8');
      creds.push(JSON.parse(data) as StoredCredential);
    } catch {
      // Skip corrupted files
    }
  }

  return creds;
}

/** Mark a credential as revoked in the store */
export function revokeCredential(
  commitment: string,
  reason?: string,
  storeDir?: string
): StoredCredential {
  const dir = storeDir ?? defaultStoreDir();
  const cred = loadCredential(commitment, dir);
  if (!cred) {
    throw new Error(
      `Credential not found in store for commitment: ${commitment}. ` +
        `Store directory: ${dir}`
    );
  }

  cred.revoked = true;
  cred.revokedAt = new Date().toISOString();
  cred.revokedReason = reason ?? null;

  saveCredential(cred, dir);
  return cred;
}

/** Delete a credential from the store (for testing) */
export function deleteCredential(
  commitment: string,
  storeDir?: string
): boolean {
  const dir = storeDir ?? defaultStoreDir();
  const filename = commitmentFilename(commitment);
  const filePath = path.join(dir, filename);
  if (!fs.existsSync(filePath)) return false;
  fs.unlinkSync(filePath);
  return true;
}
