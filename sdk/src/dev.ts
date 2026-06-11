/**
 * Dev-mode identity fixtures for Bolyra SDK.
 *
 * Creates fixed-seed human + agent identities without requiring circuit
 * artifacts. Useful for local development, demos, and permission-denial tests.
 *
 * WARNING: These identities use fixed public seeds. NEVER use them in
 * production or with real funds.
 */

import { HumanIdentity, AgentCredential, Permission } from './types';
import { createHumanIdentity, createAgentCredential } from './identity';

// Fixed dev seeds — public, reproducible, never use in production
const DEV_SECRET = BigInt('0xDEADBEEFCAFEBABE0000000000000001');
const DEV_MODEL_HASH = BigInt('0xB017A00DEF0000000000000000000001');

// 32-byte operator key with recognizable byte pattern (0xDE, 0xAD, ...)
const DEV_OPERATOR_KEY: Buffer = Buffer.from([
  0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
  0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
]);

// Default expiry: 2099-12-31 00:00:00 UTC (stable dev fixture)
const DEV_DEFAULT_EXPIRY = 4102358400n;

// All eight permission bits set: 0b11111111
const DEV_ALL_PERMISSIONS: Permission[] = [
  Permission.READ_DATA,
  Permission.WRITE_DATA,
  Permission.FINANCIAL_SMALL,
  Permission.FINANCIAL_MEDIUM,
  Permission.FINANCIAL_UNLIMITED,
  Permission.SIGN_ON_BEHALF,
  Permission.SUB_DELEGATE,
  Permission.ACCESS_PII,
];

let _warned = false;

/** Convert a permission bitmask back to an array of Permission flags */
function bitmaskToPermissions(bitmask: bigint): Permission[] {
  const all = DEV_ALL_PERMISSIONS;
  const result: Permission[] = [];
  for (const p of all) {
    if ((bitmask >> BigInt(p)) & 1n) {
      result.push(p);
    }
  }
  return result;
}

/** Options accepted by {@link createDevIdentities} */
export interface DevIdentityOptions {
  /** Override permission bitmask (default: 0b11111111 — all permissions). */
  permissionBitmask?: bigint;
  /** Override expiry timestamp in Unix seconds (default: 2099-12-31). */
  expiryTimestamp?: bigint;
}

/** Return type of {@link createDevIdentities} */
export interface DevIdentities {
  human: HumanIdentity;
  agent: AgentCredential;
  /** Fixed 32-byte operator private key (Buffer). NEVER use in production. */
  operatorKey: Buffer;
}

/**
 * Create fixed-seed dev identities for local development and demos.
 *
 * No circuit artifacts are required. All values are deterministic.
 *
 * @example
 * ```ts
 * const { human, agent, operatorKey } = await createDevIdentities();
 * // Use for handshake testing without running a real proof
 * ```
 */
export async function createDevIdentities(
  options: DevIdentityOptions = {},
): Promise<DevIdentities> {
  if (!_warned) {
    _warned = true;
    console.warn(
      '[bolyra] createDevIdentities(): using fixed-seed identities — ' +
        'NEVER use these in production.',
    );
  }

  const permissionBitmask = options.permissionBitmask ?? 0b11111111n;
  const expiryTimestamp = options.expiryTimestamp ?? DEV_DEFAULT_EXPIRY;

  const permissions = bitmaskToPermissions(permissionBitmask);

  const human = await createHumanIdentity(DEV_SECRET);
  const agent = await createAgentCredential(
    DEV_MODEL_HASH,
    DEV_OPERATOR_KEY,
    permissions,
    expiryTimestamp,
  );

  return { human, agent, operatorKey: DEV_OPERATOR_KEY };
}
