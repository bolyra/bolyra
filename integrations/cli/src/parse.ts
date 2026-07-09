/**
 * Shared parsing utilities for the Bolyra CLI.
 *
 * - Duration string parsing (30d, 1y, 24h)
 * - Permission name parsing and validation
 * - BigInt serialization helpers
 */

import * as crypto from 'node:crypto';
import { Permission, validateCumulativeBitEncoding, permissionsToBitmask } from '@bolyra/sdk';

/**
 * BN254 scalar field order. Model hashes are reduced modulo this value so they
 * fit the circuit's scalar field.
 */
const BN254_FIELD_ORDER =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/**
 * Hash a model identifier into a BN254 scalar field element.
 *
 * Computes `sha256(utf8(model))`, interprets the 32-byte digest as a big-endian
 * BigInt, then reduces it modulo the BN254 scalar field order. The result is
 * always in the range `[0, BN254_FIELD_ORDER)`.
 *
 * This is the canonical model-binding rule shared by `cred create` (credential
 * issuance) and the external verifier (model-binding check) so both derive an
 * identical `modelHash` for the same input.
 */
export function hashModel(model: string): bigint {
  const digest = crypto.createHash('sha256').update(model).digest();
  const full = BigInt('0x' + digest.toString('hex'));
  return full % BN254_FIELD_ORDER;
}

/** Duration unit multipliers in seconds */
const DURATION_UNITS: Record<string, number> = {
  s: 1,
  m: 60,
  h: 3600,
  d: 86400,
  w: 604800,
  y: 31536000,
};

/**
 * Parse a duration string (e.g., "30d", "1y", "24h", "8h") into seconds.
 * Returns null if the string is not a valid duration.
 */
export function parseDuration(input: string): number | null {
  const match = input.match(/^(\d+)([smhdwy])$/);
  if (!match) return null;
  const value = parseInt(match[1], 10);
  if (value === 0) {
    throw new Error('Duration must be positive');
  }
  const unit = match[2];
  return value * DURATION_UNITS[unit];
}

/**
 * Parse an expiry value — either a duration string (relative to now)
 * or a Unix timestamp (number). Returns a BigInt Unix timestamp.
 */
export function parseExpiry(input: string): bigint {
  const durationSeconds = parseDuration(input);
  if (durationSeconds !== null) {
    const nowSeconds = Math.floor(Date.now() / 1000);
    return BigInt(nowSeconds + durationSeconds);
  }

  // Try as Unix timestamp
  const ts = parseInt(input, 10);
  if (!isNaN(ts) && ts > 0) {
    const nowSeconds = Math.floor(Date.now() / 1000);
    if (ts < nowSeconds) {
      throw new Error('Expiry must be in the future');
    }
    return BigInt(ts);
  }

  throw new Error(
    `Invalid expiry: "${input}". Use a duration (e.g., 30d, 1y, 8h) or a Unix timestamp.`
  );
}

/** Map of permission name (case-insensitive) to Permission enum */
const PERMISSION_MAP: Record<string, Permission> = {
  read: Permission.READ_DATA,
  read_data: Permission.READ_DATA,
  write: Permission.WRITE_DATA,
  write_data: Permission.WRITE_DATA,
  financial_small: Permission.FINANCIAL_SMALL,
  financial_medium: Permission.FINANCIAL_MEDIUM,
  financial_unlimited: Permission.FINANCIAL_UNLIMITED,
  sign: Permission.SIGN_ON_BEHALF,
  sign_on_behalf: Permission.SIGN_ON_BEHALF,
  delegate: Permission.SUB_DELEGATE,
  sub_delegate: Permission.SUB_DELEGATE,
  pii: Permission.ACCESS_PII,
  access_pii: Permission.ACCESS_PII,
};

/** All valid permission names for help text */
export const VALID_PERMISSION_NAMES = Object.keys(PERMISSION_MAP);

/**
 * Parse a comma-separated permission string into Permission[] array.
 * Validates cumulative bit encoding.
 */
export function parsePermissions(input: string): Permission[] {
  const names = input.split(',').map((s) => s.trim().toLowerCase());
  const permissions: Permission[] = [];

  for (const name of names) {
    if (name === '') continue;
    const perm = PERMISSION_MAP[name];
    if (perm === undefined) {
      throw new Error(
        `Unknown permission: "${name}". Valid names: ${Object.keys(PERMISSION_MAP).join(', ')}`
      );
    }
    if (!permissions.includes(perm)) {
      permissions.push(perm);
    }
  }

  if (permissions.length === 0) {
    throw new Error('At least one permission is required.');
  }

  // Validate cumulative encoding
  const bitmask = permissionsToBitmask(permissions);
  validateCumulativeBitEncoding(bitmask);

  return permissions;
}

/**
 * Serialize a value containing BigInts to JSON, converting BigInts to decimal strings.
 */
export function serializeBigInt(value: unknown): unknown {
  if (typeof value === 'bigint') {
    return value.toString();
  }
  if (value === null || value === undefined) {
    return value;
  }
  if (Buffer.isBuffer(value)) {
    return value.toString('hex');
  }
  if (Array.isArray(value)) {
    return value.map(serializeBigInt);
  }
  if (typeof value === 'object') {
    const result: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      result[k] = serializeBigInt(v);
    }
    return result;
  }
  return value;
}

/**
 * Format a BigInt as a truncated hex string (e.g., "0x1a2b...ef34").
 */
export function truncateHex(value: bigint, prefixLen = 6, suffixLen = 4): string {
  const hex = value.toString(16);
  if (hex.length <= prefixLen + suffixLen) {
    return `0x${hex}`;
  }
  return `0x${hex.slice(0, prefixLen)}...${hex.slice(-suffixLen)}`;
}

/**
 * Read a private key from a file. Returns a Buffer (32 bytes).
 * Supports raw binary (32 bytes) or hex-encoded (64 chars).
 */
export function parseKeyFile(content: Buffer): Buffer {
  // If exactly 32 bytes, treat as raw
  if (content.length === 32) {
    return content;
  }

  // Try hex-encoded (with or without 0x prefix, with optional whitespace)
  const hexStr = content.toString('utf-8').trim().replace(/^0x/, '');
  if (/^[0-9a-fA-F]{64}$/.test(hexStr)) {
    return Buffer.from(hexStr, 'hex');
  }

  throw new Error(
    'Invalid key file: expected 32 raw bytes or 64 hex characters.'
  );
}
