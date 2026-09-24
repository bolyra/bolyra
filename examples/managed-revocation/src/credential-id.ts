/**
 * The managed-credential id, derived locally. This MIRRORS
 * integrations/hosted-verify/src/credential-id.ts (the authoritative derivation) with
 * node:crypto only, so the example needs nothing from the Worker's install:
 *
 *   credential_id = lowercase_hex( SHA-256( DST || 0x00 || LP(K) || LP(B) ) )
 *   DST   = UTF8("bolyra:managed-credential-id:v1")
 *   LP(x) = uint32_be(byte_length(x)) || x
 *   K     = UTF8("x:y"), decimal coordinates without leading zeros
 *   B     = the binding digest as 32 bytes big-endian
 *
 * The layout exists in THREE copies: this file, integrations/hosted-verify/src/credential-id.ts,
 * and integrations/hosted-verify/test/fixtures/generate-registrations.cjs. The Worker
 * parameterises the DST on CREDENTIAL_ID_VERSION; this mirror (like the generator)
 * hardcodes v1, so a version bump must touch this file and the generator too. What catches
 * a miss: the runtime check in run.ts (the id the Worker returns on registration must equal
 * the one computed here, `same id`) and test/credential-id.test.ts, which pins this copy to
 * the Worker's committed fixtures.
 */
import { createHash } from 'node:crypto';

const DST = Buffer.concat([Buffer.from('bolyra:managed-credential-id:v1', 'utf8'), Buffer.from([0])]);

function lengthPrefixed(bytes: Buffer): Buffer {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(bytes.length, 0);
  return Buffer.concat([len, bytes]);
}

function bytes32(value: bigint): Buffer {
  if (value < 0n || value >= 1n << 256n) throw new RangeError('value must be in [0, 2^256)');
  return Buffer.from(value.toString(16).padStart(64, '0'), 'hex');
}

export function credentialId(operator: { x: bigint; y: bigint }, bindingDigest: bigint): string {
  const k = Buffer.from(`${operator.x.toString()}:${operator.y.toString()}`, 'utf8');
  return createHash('sha256')
    .update(Buffer.concat([DST, lengthPrefixed(k), lengthPrefixed(bytes32(bindingDigest))]))
    .digest('hex');
}
