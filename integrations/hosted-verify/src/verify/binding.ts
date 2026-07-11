/**
 * Binding-signature digest + request/model binding checks (spec §4).
 *
 * Ported from `integrations/cli/src/verify/binding.ts` for the Workers runtime:
 *   - SHA-256 via `@noble/hashes` (pure JS, no `node:crypto`)
 *   - BabyJubjub EdDSA-Poseidon verification via `@zk-kit/eddsa-poseidon`
 *     (pure JS — validated against the SDK's circomlibjs implementation on the
 *     repo conformance fixtures; workerd cannot run circomlibjs' runtime WASM)
 *   - canonical JSON via `@bolyra/receipts` `canonicalize` (the spec §4.1
 *     normative serializer)
 */

import { sha256 } from '@noble/hashes/sha256';
import { verifySignature } from '@zk-kit/eddsa-poseidon';
import { canonicalize } from '@bolyra/receipts';
import { BN254_FIELD_ORDER } from '@bolyra/sdk/dist/identity.js';
import type { Binding } from './bundle';
import { VerifyDenial } from './verdict';

/** Domain-separation tag for the binding signature digest (spec §4.2). */
const BINDING_DST = 'bolyra.external-verifier.binding.v1';

const encoder = new TextEncoder();

function bytesToBigInt(bytes: Uint8Array): bigint {
  let hex = '';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return BigInt('0x' + hex);
}

/**
 * `digest = sha256( DST || 0x00 || canonicalize(binding) ) mod BN254_FIELD_ORDER`
 * (spec §4.2–§4.3). Byte-identical to the CLI reference implementation.
 */
export function bindingDigest(binding: Binding): bigint {
  const dst = encoder.encode(BINDING_DST);
  const body = encoder.encode(canonicalize(binding));
  const payload = new Uint8Array(dst.length + 1 + body.length);
  payload.set(dst, 0);
  payload[dst.length] = 0x00;
  payload.set(body, dst.length + 1);
  return bytesToBigInt(sha256(payload)) % BN254_FIELD_ORDER;
}

/**
 * Verify the operator's EdDSA-Poseidon signature over the binding digest
 * against the operator public key revealed by the credential (spec §4.4).
 * Throws `VerifyDenial invalid_signature` when it does not verify.
 */
export function verifyBindingSig(
  binding: Binding,
  sig: { R8: { x: bigint; y: bigint }; S: bigint },
  operatorPubkey: { x: bigint; y: bigint },
): void {
  let ok = false;
  try {
    ok = verifySignature(
      bindingDigest(binding),
      { R8: [sig.R8.x, sig.R8.y], S: sig.S },
      [operatorPubkey.x, operatorPubkey.y],
    );
  } catch {
    // Malformed points / out-of-range values are a failed signature, not an
    // internal error — fail closed with the signature denial.
    ok = false;
  }
  if (!ok) {
    throw new VerifyDenial(
      'invalid_signature',
      'binding signature does not verify against the operator key',
    );
  }
}

/**
 * Byte-for-byte request↔binding match (spec §2.1): `agent_name`,
 * `project_key` (literal — NO path canonicalization), `program`, `model`, and
 * `granted_capabilities ⊆ binding.capabilities`.
 */
export function checkRequestBinding(
  request: {
    agent_name: string;
    project_key: string;
    program: string;
    model: string;
    granted_capabilities: string[];
  },
  binding: Binding,
): void {
  const fields = ['agent_name', 'project_key', 'program', 'model'] as const;
  for (const field of fields) {
    if (request[field] !== binding[field]) {
      throw new VerifyDenial(
        'request_mismatch',
        `request ${field} does not match the signed binding`,
        { field, request: request[field], binding: binding[field] },
      );
    }
  }

  const allowed = new Set(binding.capabilities);
  for (const cap of request.granted_capabilities) {
    if (!allowed.has(cap)) {
      throw new VerifyDenial(
        'request_mismatch',
        `granted capability "${cap}" is not covered by the signed binding`,
        { field: 'granted_capabilities', capability: cap },
      );
    }
  }
}

/** `sha256(model) mod BN254_FIELD_ORDER` — the SDK's model-hash convention. */
export function hashModel(model: string): bigint {
  return bytesToBigInt(sha256(encoder.encode(model))) % BN254_FIELD_ORDER;
}

/** The proven `modelHash` MUST equal the hash of the requested model string. */
export function checkModelBinding(modelHash: bigint, requestModel: string): void {
  if (modelHash !== hashModel(requestModel)) {
    throw new VerifyDenial(
      'model_mismatch',
      'proven model hash does not match the requested model',
      { requestModel },
    );
  }
}
