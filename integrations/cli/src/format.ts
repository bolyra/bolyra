/**
 * Output formatting utilities for the Bolyra CLI.
 *
 * - Human-readable table output
 * - Permission abbreviation display
 * - Credential status computation
 */

import { Permission, permissionsToBitmask } from '@bolyra/sdk';
import { truncateHex, serializeBigInt } from './parse';

/** Permission abbreviation map for compact display */
const PERM_ABBREV: Record<number, string> = {
  [Permission.READ_DATA]: 'R',
  [Permission.WRITE_DATA]: 'W',
  [Permission.FINANCIAL_SMALL]: '$',
  [Permission.FINANCIAL_MEDIUM]: '$$',
  [Permission.FINANCIAL_UNLIMITED]: '$$$',
  [Permission.SIGN_ON_BEHALF]: 'S',
  [Permission.SUB_DELEGATE]: 'D',
  [Permission.ACCESS_PII]: 'P',
};

/** Permission full name map */
const PERM_NAMES: Record<number, string> = {
  [Permission.READ_DATA]: 'READ_DATA',
  [Permission.WRITE_DATA]: 'WRITE_DATA',
  [Permission.FINANCIAL_SMALL]: 'FINANCIAL_SMALL',
  [Permission.FINANCIAL_MEDIUM]: 'FINANCIAL_MEDIUM',
  [Permission.FINANCIAL_UNLIMITED]: 'FINANCIAL_UNLIMITED',
  [Permission.SIGN_ON_BEHALF]: 'SIGN_ON_BEHALF',
  [Permission.SUB_DELEGATE]: 'SUB_DELEGATE',
  [Permission.ACCESS_PII]: 'ACCESS_PII',
};

/** Convert a bitmask to abbreviated permission string (e.g., "RW$") */
export function permissionsAbbrev(bitmask: bigint): string {
  let result = '';
  for (let i = 0; i < 8; i++) {
    if ((bitmask >> BigInt(i)) & 1n) {
      result += PERM_ABBREV[i] ?? `?${i}`;
    }
  }
  return result;
}

/** Convert a bitmask to full permission names (e.g., "READ_DATA, WRITE_DATA") */
export function permissionsFullNames(bitmask: bigint): string {
  const names: string[] = [];
  for (let i = 0; i < 8; i++) {
    if ((bitmask >> BigInt(i)) & 1n) {
      names.push(PERM_NAMES[i] ?? `BIT_${i}`);
    }
  }
  return names.join(', ');
}

/** Bitmask as binary string (e.g., "0b00000111") */
export function bitmaskBinary(bitmask: bigint): string {
  return '0b' + bitmask.toString(2).padStart(8, '0');
}

/** Credential status based on expiry and revocation */
export function credentialStatus(
  expiryTimestamp: bigint,
  revoked: boolean
): 'active' | 'expired' | 'revoked' {
  if (revoked) return 'revoked';
  const nowSeconds = BigInt(Math.floor(Date.now() / 1000));
  if (expiryTimestamp <= nowSeconds) return 'expired';
  return 'active';
}

/** Format remaining time until expiry as human-readable string */
export function timeRemaining(expiryTimestamp: bigint): string {
  const nowSeconds = BigInt(Math.floor(Date.now() / 1000));
  if (expiryTimestamp <= nowSeconds) return 'expired';
  const diff = Number(expiryTimestamp - nowSeconds);
  const days = Math.floor(diff / 86400);
  if (days > 365) return `${Math.floor(days / 365)}y ${days % 365}d remaining`;
  if (days > 0) return `${days}d remaining`;
  const hours = Math.floor(diff / 3600);
  if (hours > 0) return `${hours}h remaining`;
  const minutes = Math.floor(diff / 60);
  return `${minutes}m remaining`;
}

/** Format a Unix timestamp as ISO-8601 */
export function formatTimestamp(ts: bigint): string {
  return new Date(Number(ts) * 1000).toISOString();
}

/** Stored credential shape (superset of AgentCredential) */
export interface StoredCredential {
  commitment: string;
  modelHash: string;
  modelName?: string;
  operatorPublicKey: { x: string; y: string };
  permissionBitmask: string;
  expiryTimestamp: string;
  signature: { R8: { x: string; y: string }; S: string };
  createdAt: string;
  revoked: boolean;
  revokedAt: string | null;
  revokedReason: string | null;
}

/** Format a credential for human-readable inspect output */
export function formatCredentialInspect(cred: StoredCredential): string {
  const commitment = BigInt(cred.commitment);
  const modelHash = BigInt(cred.modelHash);
  const bitmask = BigInt(cred.permissionBitmask);
  const expiry = BigInt(cred.expiryTimestamp);
  const status = credentialStatus(expiry, cred.revoked);

  const lines = [
    `Credential: ${truncateHex(commitment)}`,
    `  Model hash:    ${truncateHex(modelHash)}`,
  ];

  if (cred.modelName) {
    lines.push(`  Model name:    ${cred.modelName}`);
  }

  lines.push(
    `  Operator key:  (Ax, Ay) = (0x${BigInt(cred.operatorPublicKey.x).toString(16).slice(0, 12)}..., 0x${BigInt(cred.operatorPublicKey.y).toString(16).slice(0, 12)}...)`,
    `  Permissions:   ${permissionsFullNames(bitmask)} (bitmask: ${bitmaskBinary(bitmask)})`,
    `  Expiry:        ${formatTimestamp(expiry)} (${timeRemaining(expiry)})`,
    `  DID:           did:bolyra:agent:${truncateHex(commitment)}`,
    `  Status:        ${status}`,
  );

  if (cred.revoked && cred.revokedAt) {
    lines.push(`  Revoked at:    ${cred.revokedAt}`);
    if (cred.revokedReason) {
      lines.push(`  Reason:        ${cred.revokedReason}`);
    }
  }

  return lines.join('\n');
}

/** Format a list of credentials as a table */
export function formatCredentialTable(creds: StoredCredential[]): string {
  if (creds.length === 0) return 'No credentials found.';

  const header = ' COMMITMENT         MODEL       PERMISSIONS  EXPIRY              STATUS';
  const rows = creds.map((c) => {
    const commitment = truncateHex(BigInt(c.commitment), 6, 4);
    const model = (c.modelName ?? truncateHex(BigInt(c.modelHash), 4, 0)).padEnd(11);
    const perms = permissionsAbbrev(BigInt(c.permissionBitmask)).padEnd(12);
    const expiry = BigInt(c.expiryTimestamp);
    const status = credentialStatus(expiry, c.revoked);
    const expiryStr = status === 'revoked'
      ? `revoked ${c.revokedAt?.slice(0, 10) ?? ''}`.padEnd(20)
      : formatTimestamp(expiry).slice(0, 10).padEnd(20);
    return ` ${commitment.padEnd(19)} ${model} ${perms} ${expiryStr} ${status}`;
  });

  return [header, ...rows].join('\n');
}
