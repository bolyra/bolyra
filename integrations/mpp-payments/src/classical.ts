/**
 * In-process classical (Bolyra Core) verification — the gate's default.
 *
 * This is the External Verifier Contract v1 classical pipeline (the same
 * algorithm as the Bolyra hosted-verify preview, itself the classical subset
 * of `bolyra verify`), run in-process with no subprocess and NO ZK
 * dependency: nothing on this path loads snarkjs.
 *
 * CLASSICAL TRUST MODEL (read before trusting a verdict). Without a Groth16
 * proof, every public signal and credential field in the bundle is
 * self-asserted. The ONE cryptographically load-bearing fact is the
 * operator's EdDSA-Poseidon signature over the request binding (spec §4). An
 * `allow` therefore means, and only means: **a configured trusted operator
 * signed a binding authorizing this exact {agent_name, project_key, program,
 * model, capabilities, expiry}, the request matches that signed binding, and
 * the granted capabilities are a subset of it.** The trust anchor is
 * `trustedOperators`, not the proof's Merkle root.
 *
 * BINDING v2 — EXPIRY IS SIGNATURE-BOUND. The signed binding now includes
 * `expiry` (unix seconds), pinned equal to the revealed credential expiry
 * (check 4b). A presenter can no longer re-anchor a later expiry on an issued
 * mandate: rewriting `binding.expiry` breaks the signature, and rewriting only
 * `credential.expiry` fails the binding↔credential expiry equality. The
 * obsolete five-field v1 binding (expiry NOT signed) is rejected
 * `unsupported_version`.
 *
 * Checks, in order (mirrors integrations/cli/src/verify/core.ts and
 * integrations/hosted-verify/src/verify/core.ts — field orders are
 * CODE-VERIFIED there against AgentPolicy.circom and sdk/src/identity.ts):
 *   1. bundle structure (bvp/1, agent slot, envelope shape)
 *   2. zk-only slot gate (human/delegation bundles are denied, not half-verified)
 *   3. trusted-operator gate (fail-closed when the set is empty)
 *   4. EdDSA-Poseidon binding signature over the binding digest
 *   5. byte-literal request↔binding match + granted ⊆ signed capabilities
 *   6. model binding: sha256(model) mod p == revealed modelHash
 *   7. scope anchoring (consistency): poseidon recompute of scopeCommitment
 *   8. capability → permission bits + cumulative-scope subset (consistency)
 *   9. strict expiry against the caller-supplied now_unix (now == expiry is expired)
 *
 * NOT checked (documented, honest scope): Groth16 proof math, Merkle-root
 * inclusion, human uniqueness, delegation chains, replay. A spend mandate is
 * a STANDING authorization — reusable within tier and expiry by design — so
 * this classical path does not consume nonces; per-payment idempotency is
 * MPP's challenge binding, not this gate's job.
 */

import * as crypto from 'node:crypto';
import {
  eddsaVerify,
  poseidon3,
  poseidon5,
  validateCumulativeBitEncoding,
  BN254_FIELD_ORDER,
} from '@bolyra/sdk';
import { canonicalize } from '@bolyra/receipts';
import { parseBundle, type BindingClaim, type ParsedBundle } from './bundle';
import { requiredPermissionBits } from './tiers';
import {
  allow,
  deny,
  isVerifyDenial,
  VerifyDenial,
  type OperatorKey,
  type Verdict,
  type VerifierRequest,
} from './types';

/** Domain-separation tag for the binding-signature digest (spec §4.2, v2). */
const BINDING_DST = 'bolyra.external-verifier.binding.v2';

/**
 * The field element the operator signs to authorize a binding:
 * `sha256( DST || 0x00 || canonicalize(binding) )` reduced mod the BN254
 * scalar field order. Binding v2 canonicalizes the six-field binding (including
 * `expiry`) under the v2 DST. Byte-compatible with `bolyra verify` — the same
 * bundle verifies under either verifier.
 */
export function bindingDigest(binding: BindingClaim): bigint {
  const payload = Buffer.concat([
    Buffer.from(BINDING_DST, 'utf8'),
    Buffer.from([0x00]),
    Buffer.from(canonicalize(binding), 'utf8'),
  ]);
  const digest = crypto.createHash('sha256').update(payload).digest();
  return BigInt('0x' + digest.toString('hex')) % BN254_FIELD_ORDER;
}

/** `sha256(model) mod p` — the model-hash convention of `bolyra verify`. */
export function hashModel(model: string): bigint {
  const digest = crypto.createHash('sha256').update(model).digest();
  return BigInt('0x' + digest.toString('hex')) % BN254_FIELD_ORDER;
}

/** Canonical `x:y` id for an operator key. */
function operatorKeyId(x: bigint, y: bigint): string {
  return `${x.toString()}:${y.toString()}`;
}

/**
 * Parse the configured trusted-operator set. Decimal-string coordinates only;
 * an EMPTY or malformed set fails closed (`internal_error`) — never
 * "all operators trusted".
 */
function loadTrustedOperators(operators: OperatorKey[]): Set<string> {
  if (!Array.isArray(operators) || operators.length === 0) {
    throw new VerifyDenial('internal_error', 'no trusted operator configured');
  }
  const set = new Set<string>();
  for (const entry of operators) {
    if (!/^[0-9]+$/.test(entry?.x ?? '') || !/^[0-9]+$/.test(entry?.y ?? '')) {
      throw new VerifyDenial(
        'internal_error',
        'trustedOperators entries must be decimal-string {x, y} coordinate pairs',
      );
    }
    set.add(operatorKeyId(BigInt(entry.x), BigInt(entry.y)));
  }
  return set;
}

/** BigInt a decimal string field, failing closed as `invalid_bundle`. */
function fieldElement(value: string, label: string): bigint {
  try {
    return BigInt(value);
  } catch {
    throw new VerifyDenial('invalid_bundle', `${label} is not a decimal field element`);
  }
}

/**
 * Run the classical pipeline. Never throws: every failure resolves to a
 * `deny` verdict (spec §7 — decision-level outcomes are verdicts).
 */
export async function verifyClassical(
  request: VerifierRequest,
  trustedOperators: OperatorKey[],
): Promise<Verdict> {
  try {
    // 1–2. Structure + zk-only slot gate.
    const bundle: ParsedBundle = parseBundle(request.bundle);
    if (bundle.zkOnlySlots.length > 0) {
      throw new VerifyDenial(
        'invalid_proof',
        `bundle carries zk-only slots (${bundle.zkOnlySlots.join(', ')}) that classical ` +
          'verification cannot check — configure a zk-class external verifier (`bolyra verify`)',
        { slots: bundle.zkOnlySlots },
      );
    }

    const cred = bundle.agent.credential;
    const operatorPubkey = {
      x: fieldElement(cred.operator_pubkey.x, 'operator_pubkey.x'),
      y: fieldElement(cred.operator_pubkey.y, 'operator_pubkey.y'),
    };

    // 3. TRUST ANCHOR: operator key must be a configured trusted issuer.
    const operators = loadTrustedOperators(trustedOperators);
    if (!operators.has(operatorKeyId(operatorPubkey.x, operatorPubkey.y))) {
      throw new VerifyDenial('untrusted_root', 'operator key is not a configured trusted issuer', {
        operator_key: operatorKeyId(operatorPubkey.x, operatorPubkey.y),
      });
    }

    // 4. Binding signature: EdDSA-Poseidon over the binding digest, against
    //    the trusted operator key. The classical authorization.
    const sig = {
      R8: {
        x: fieldElement(bundle.sig.R8.x, 'sig.R8.x'),
        y: fieldElement(bundle.sig.R8.y, 'sig.R8.y'),
      },
      S: fieldElement(bundle.sig.S, 'sig.S'),
    };
    const sigOk = await eddsaVerify(operatorPubkey, bindingDigest(bundle.binding), sig);
    if (!sigOk) {
      throw new VerifyDenial(
        'invalid_signature',
        'binding signature does not verify against the operator key',
      );
    }

    // 4b. Bind the signed expiry to the revealed credential expiry (binding v2).
    //     The signature now covers binding.expiry; requiring it to equal the
    //     credential expiry the scope math + strict-expiry check consume means a
    //     re-anchored expiry either breaks the signature (if binding.expiry is
    //     rewritten) or is caught here (if only credential.expiry is rewritten).
    if (bundle.binding.expiry !== bundle.agent.credential.expiry) {
      throw new VerifyDenial(
        'invalid_bundle',
        'binding expiry does not match the credential expiry',
        { binding_expiry: bundle.binding.expiry, credential_expiry: bundle.agent.credential.expiry },
      );
    }

    // 5. Request ↔ binding: byte-literal field match (spec §4.3 — project_key
    //    is compared LITERALLY, no path normalization) + capability subset.
    for (const field of ['agent_name', 'project_key', 'program', 'model'] as const) {
      if (request.request[field] !== bundle.binding[field]) {
        throw new VerifyDenial(
          'request_mismatch',
          `request ${field} does not match the signed binding`,
          { field, request: request.request[field], binding: bundle.binding[field] },
        );
      }
    }
    const signedCapabilities = new Set(bundle.binding.capabilities);
    for (const capability of request.request.granted_capabilities) {
      if (!signedCapabilities.has(capability)) {
        throw new VerifyDenial(
          'request_mismatch',
          `granted capability "${capability}" is not covered by the signed binding`,
          { field: 'granted_capabilities', capability },
        );
      }
    }

    // 6. Model binding: the revealed modelHash must equal sha256(model) mod p.
    const modelHash = fieldElement(cred.model_hash, 'model_hash');
    if (modelHash !== hashModel(request.request.model)) {
      throw new VerifyDenial('model_mismatch', 'model hash does not match the requested model', {
        requestModel: request.request.model,
      });
    }

    // 7. Scope anchoring (consistency): recompute scopeCommitment from the
    //    revealed preimage and compare to publicSignals[2]. Field order is
    //    code-verified against AgentPolicy.circom:
    //      credentialCommitment = poseidon5(modelHash, opX, opY, bitmask, expiry)
    //      scopeCommitment      = poseidon3(bitmask, credentialCommitment, expiry)
    const bitmask = fieldElement(cred.permission_bitmask, 'permission_bitmask');
    const expiry = BigInt(cred.expiry);
    const credentialCommitment = await poseidon5(
      modelHash,
      operatorPubkey.x,
      operatorPubkey.y,
      bitmask,
      expiry,
    );
    const scopeCommitment = await poseidon3(bitmask, credentialCommitment, expiry);
    const scopeSignal = fieldElement(
      bundle.agent.envelope.publicSignals[2] ?? '0',
      'publicSignals[2]',
    );
    if (scopeCommitment !== scopeSignal) {
      throw new VerifyDenial(
        'invalid_proof',
        'credential preimage does not match proof scopeCommitment',
      );
    }

    // 8. Capability → permission bits + cumulative subset over the revealed
    //    bitmask (consistency; sound enforcement needs the zk-class verifier).
    const required = requiredPermissionBits(request.request.granted_capabilities);
    try {
      validateCumulativeBitEncoding(bitmask);
      validateCumulativeBitEncoding(required);
    } catch (err) {
      throw new VerifyDenial(
        'invalid_bundle',
        'permission bitmask is not a valid cumulative encoding',
        { reason: err instanceof Error ? err.message : String(err) },
      );
    }
    if ((required & ~bitmask) !== 0n) {
      throw new VerifyDenial('scope_exceeded', 'required scope exceeds the credential scope', {
        required_scope: required.toString(),
        effective_scope: bitmask.toString(),
      });
    }

    // 9. STRICT expiry against the caller's clock: now == expiry is EXPIRED
    //    (matches the circuit's LessThan(currentTimestamp, expiryTimestamp)).
    if (!(BigInt(request.now_unix) < expiry)) {
      throw new VerifyDenial('expired', 'credential is expired at the current timestamp', {
        now_unix: String(request.now_unix),
        expiry: expiry.toString(),
      });
    }

    return { ...allow(), kind: 'classical' };
  } catch (err) {
    if (isVerifyDenial(err)) {
      return { ...err.toVerdict(), kind: 'classical' };
    }
    return { ...deny('internal_error', 'internal verification error'), kind: 'classical' };
  }
}
