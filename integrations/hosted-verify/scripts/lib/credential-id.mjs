/**
 * The managed-credential id, derived under plain Node with node:crypto only.
 *
 *   credential_id = lowercase_hex( SHA-256( DST || 0x00 || LP(K) || LP(B) ) )
 *   DST   = UTF8("bolyra:managed-credential-id:v1")
 *   LP(x) = uint32_be(byte_length(x)) || x
 *   K     = UTF8("x:y"), decimal coordinates without leading zeros
 *   B     = the binding digest as 32 bytes big-endian, in [0, 2^256)
 *
 * The layout exists in THREE copies, byte-for-byte equal:
 *   1. src/credential-id.ts — the Worker's, authoritative (parameterised on CREDENTIAL_ID_VERSION)
 *   2. this file — used by scripts/verify-deploy.mjs and test/fixtures/generate-registrations.cjs
 *   3. examples/managed-revocation/src/credential-id.ts (repo root) — the example's mirror
 * Copies 2 and 3 hardcode v1. Bumping CREDENTIAL_ID_VERSION in the Worker changes the DST and
 * therefore every id: bump the DST here and in copy 3 in the same change, then regenerate
 * test/fixtures/registrations.json. test-node/credential-id.test.mjs pins this copy to the
 * committed fixtures; the example's test pins copy 3 to the same fixtures.
 */
import { createHash } from 'node:crypto';

export const CREDENTIAL_ID_DST = 'bolyra:managed-credential-id:v1';

const DST_BYTES = Buffer.concat([Buffer.from(CREDENTIAL_ID_DST, 'utf8'), Buffer.from([0])]);

function lengthPrefixed(bytes) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(bytes.length, 0);
  return Buffer.concat([len, bytes]);
}

function bytes32(value) {
  if (typeof value !== 'bigint' || value < 0n || value >= 1n << 256n) throw new RangeError('value must be a bigint in [0, 2^256)');
  return Buffer.from(value.toString(16).padStart(64, '0'), 'hex');
}

/**
 * @param {{ x: bigint, y: bigint }} operator the operator public key
 * @param {bigint} bindingDigest `bindingDigest(binding)` (already reduced mod the BN254 order)
 * @returns {string} 64 lowercase hex characters
 */
export function credentialId(operator, bindingDigest) {
  for (const c of [operator?.x, operator?.y]) {
    if (typeof c !== 'bigint') throw new TypeError('operator coordinates must be bigints');
    if (c < 0n || c >= 1n << 256n) throw new RangeError('operator coordinates must be in [0, 2^256)');
  }
  const k = Buffer.from(`${operator.x.toString()}:${operator.y.toString()}`, 'utf8');
  return createHash('sha256')
    .update(Buffer.concat([DST_BYTES, lengthPrefixed(k), lengthPrefixed(bytes32(bindingDigest))]))
    .digest('hex');
}
