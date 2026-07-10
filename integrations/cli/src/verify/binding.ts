/**
 * Request-authorizing signature digest + request/model binding checks for the
 * `bolyra verify` external verifier (spec §4.3, §5.9 / §5.9b, F1).
 *
 * A `BindingClaim` is the operator's signed statement of WHICH agent, project,
 * program, model, and capability set a credential authorizes. Three checks
 * enforce it end to end:
 *
 *   1. {@link verifyBindingSig} — the operator's EdDSA signature over the
 *      binding digest MUST verify against the *proven* operator public key
 *      (the key the ZK proof attests to). This is the F1 request-authorizing
 *      signature: it binds the human-readable request context to the proof.
 *   2. {@link checkRequestBinding} — the caller-supplied request MUST match the
 *      signed binding byte-for-byte (agent/project/program/model) and its
 *      granted capabilities MUST be a subset of the signed capability set.
 *   3. {@link checkModelBinding} — the model committed inside the proof
 *      (`modelHash`) MUST equal the hash of the requested model string.
 *
 * The digest uses an explicit domain-separation tag so a binding signature can
 * never be confused with any other Bolyra signature over canonical JSON.
 */

import * as crypto from 'node:crypto';
import { canonicalize } from '@bolyra/receipts';
import { eddsaVerify, BN254_FIELD_ORDER } from '@bolyra/sdk';
import { hashModel } from '../parse';
import { VerifyDenial } from './verdict';

/**
 * The operator's signed authorization claim: the exact agent, project, program,
 * model, and capability set a credential is bound to.
 */
export interface BindingClaim {
  agent_name: string;
  project_key: string;
  program: string;
  model: string;
  capabilities: string[];
}

/** Domain-separation tag for the binding signature digest (spec §5.9). */
const BINDING_DST = 'bolyra.external-verifier.binding.v1';

/**
 * Compute the field element that the operator signs to authorize a binding.
 *
 * `digest = sha256( DST || 0x00 || canonicalize(binding) )`, interpreted as a
 * big-endian BigInt and reduced modulo the BN254 scalar field order so it is a
 * valid EdDSA-Poseidon message. The single `0x00` byte separates the ASCII
 * domain tag from the canonical binding bytes so no binding payload can be
 * crafted to collide with a differently-tagged message.
 */
export async function bindingDigest(binding: BindingClaim): Promise<bigint> {
  const payload = Buffer.concat([
    Buffer.from(BINDING_DST, 'utf8'),
    Buffer.from([0x00]),
    Buffer.from(canonicalize(binding), 'utf8'),
  ]);
  const digest = crypto.createHash('sha256').update(payload).digest();
  return BigInt('0x' + digest.toString('hex')) % BN254_FIELD_ORDER;
}

/**
 * Verify the operator's EdDSA signature over the binding digest against the
 * PROVEN operator public key. Throws {@link VerifyDenial} `invalid_signature`
 * if it does not verify (F1).
 */
export async function verifyBindingSig(
  binding: BindingClaim,
  sig: { R8: { x: bigint; y: bigint }; S: bigint },
  operatorPubkey: { x: bigint; y: bigint },
): Promise<void> {
  const ok = await eddsaVerify(operatorPubkey, await bindingDigest(binding), sig);
  if (!ok) {
    throw new VerifyDenial(
      'invalid_signature',
      'binding signature does not verify against the proven operator key',
    );
  }
}

/**
 * Check the caller-supplied request against the signed binding (spec §4.3).
 *
 * `agent_name`, `project_key`, `program`, and `model` MUST be byte-equal to the
 * binding. `project_key` is compared LITERALLY — no `path.resolve`/normalization
 * — so `a/../b` and `b` are treated as distinct keys. The request's
 * `granted_capabilities` MUST be a subset of the binding's `capabilities`.
 * Any violation throws {@link VerifyDenial} `request_mismatch` with the
 * offending field in `detail`.
 */
export function checkRequestBinding(
  request: {
    agent_name: string;
    project_key: string;
    program: string;
    model: string;
    granted_capabilities: string[];
  },
  binding: BindingClaim,
): void {
  const fields: Array<keyof BindingClaim & keyof typeof request> = [
    'agent_name',
    'project_key',
    'program',
    'model',
  ];
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

/**
 * Check that the model committed inside the proof (`modelHash`) matches the
 * requested model string (spec §5.9b). Throws {@link VerifyDenial}
 * `model_mismatch` on divergence.
 */
export function checkModelBinding(modelHash: bigint, requestModel: string): void {
  if (modelHash !== hashModel(requestModel)) {
    throw new VerifyDenial(
      'model_mismatch',
      'proven model hash does not match the requested model',
      { requestModel },
    );
  }
}
