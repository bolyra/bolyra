/**
 * Classical (Bolyra Core) verification pipeline for the hosted verify preview.
 *
 * This is the External Verifier Contract v1 algorithm from
 * `integrations/cli/src/verify/core.ts`, restricted to the checks that are
 * sound WITHOUT zero-knowledge circuit verification. The verdict is therefore
 * `kind: "classical"` (spec §3.5) — it attests to classical crypto + policy
 * checks, NOT to Groth16 proof validity.
 *
 * CLASSICAL TRUST MODEL (read this before trusting a verdict). Without a
 * Groth16 proof, EVERY public signal and credential field in the bundle is
 * self-asserted — an attacker can put any value there. The ONE
 * cryptographically load-bearing fact is the operator's EdDSA-Poseidon
 * signature over the request binding (spec §4). So an `allow` means, and ONLY
 * means: **a configured trusted operator signed a binding authorizing this
 * exact {agent_name, project_key, program, model, capabilities, expiry}, the
 * request matches that signed binding, and the granted capabilities are a
 * subset of it.** The trust anchor is the tenant's operator key set
 * (`trusted_operators` in the `TENANTS` secret), NOT the proof's Merkle root (which is unverified here
 * and carries no weight).
 *
 * BINDING v2 — EXPIRY IS SIGNATURE-BOUND. The signed binding includes `expiry`
 * (unix seconds), pinned equal to the revealed credential expiry, so a presenter
 * cannot re-anchor a later expiry on an issued mandate. The obsolete five-field
 * v1 binding is rejected `unsupported_version`.
 *
 * AUTHENTICATED-BY-SIGNATURE checks (sound):
 *   trusted-operator gate, EdDSA-Poseidon binding signature, byte-literal
 *   request↔binding match, granted ⊆ signed capabilities.
 *
 * CONSISTENCY checks on the revealed (NOT operator-signed) credential — they
 * catch honest misconfiguration and are needed for internal coherence, but a
 * holder of a trusted operator key could self-assert any value here, so they
 * are NOT a defense against a malicious trusted operator; sound enforcement of
 * scope/expiry requires the zk-class verifier:
 *   Poseidon scope anchoring, model-hash binding, capability→scope subset,
 *   strict expiry.
 *
 * CHECKS NOT PERFORMED (zk-class only; see CHECKS_NOT_PERFORMED):
 *   Groth16 proof verification + vkey pinning, Merkle-root inclusion,
 *   human-uniqueness proofs, delegation-chain proofs (bundles carrying those
 *   slots are DENIED, not silently half-verified), local replay state (replay
 *   protection is host nonce mode: the caller MUST reserve-before-act every
 *   `consume_nonces` entry per spec §7.3).
 */

import { parseBundle, type Binding } from './bundle';
import { assertTrustedOperator } from './operators';
import { assertScopeAnchored, assertSubset, assertNotExpired } from './scope';
import { verifyBindingSig, checkRequestBinding, checkModelBinding } from './binding';
import { requiredBits, type CapabilityMap } from './capabilities';
import {
  allow,
  deny,
  isVerifyDenial,
  VerifyDenial,
  type AllowVerdict,
  type DenyVerdict,
  type ConsumeNonce,
} from './verdict';

export interface VerifierRequestContext {
  agent_name: string;
  project_key: string;
  program: string;
  model: string;
  granted_capabilities: string[];
}

export interface VerifierRequest {
  version: number;
  bundle: string;
  request: VerifierRequestContext;
  now_unix: number;
  /**
   * OPTIONAL preview extension (spec §2.2 allows additional request
   * properties): the proof-system class the caller wants. This endpoint only
   * implements `classical`; an explicit `zk` (or any other value) is denied.
   */
  kind?: string;
}

/**
 * The facts a classical `allow` rests on: the operator-signed binding (spec §4)
 * and the trusted operator key the signature verified against. Populated ONLY
 * on the allow path — every denial returns a verdict alone — so a caller that
 * derives identity from these values is using signature-covered data, not the
 * self-asserted credential fields.
 */
export interface VerifiedClassical {
  readonly binding: Readonly<Binding>;
  readonly operator: { readonly x: bigint; readonly y: bigint };
}

/** `verified` is present exactly when the verdict is an allow; the type carries the rule. */
export type ClassicalResult =
  | { verdict: AllowVerdict; verified: VerifiedClassical }
  | { verdict: DenyVerdict; verified?: undefined };

/**
 * The classical authorization surface (sound: every item is either a
 * signed-by-the-operator fact or a fail-closed gate). Surfaced on /health.
 */
export const CHECKS_AUTHENTICATED = [
  "trusted-operator gate: credential operator key ∈ the tenant's configured trusted operators (fail-closed if none)",
  'BabyJubjub EdDSA-Poseidon binding signature over the request binding, against that operator key (spec §4, binding v2)',
  'byte-literal request↔binding match (agent_name/project_key/program/model)',
  'granted_capabilities ⊆ operator-signed capabilities',
  'signed binding.expiry == revealed credential.expiry (binding v2 — expiry is signature-bound)',
  "registry membership: the verified signed binding is ACTIVE in the calling tenant's managed credential registry (checked last; a registry failure fails closed)",
] as const;

/**
 * Consistency checks on the revealed credential. These are NOT operator-signed
 * in bvp/1, so they catch honest misconfiguration but do not defend against a
 * malicious holder of a trusted operator key — sound scope/expiry enforcement
 * needs the zk-class verifier. Surfaced on /health, explicitly labeled.
 */
export const CHECKS_CONSISTENCY = [
  'request schema + version (spec §2) and bvp/1 structure + proof-envelope shape',
  'Poseidon scope anchoring: revealed preimage recomputes the self-asserted scopeCommitment signal',
  'model-hash binding: sha256(model) mod p equals the revealed modelHash',
  'capability → permission-bit mapping + cumulative-scope subset (over the revealed bitmask)',
  'strict expiry against caller-supplied now_unix (now == expiry is expired; over the signature-bound expiry, binding v2)',
  'nullifier presence + consume_nonces emission (host nonce mode, spec §8)',
] as const;

export const CHECKS_NOT_PERFORMED = [
  'Groth16 proof verification + vkey pinning (zk-class only — use `bolyra verify`)',
  'Merkle-root inclusion (the proof root is unverified here and carries no trust weight)',
  'human-uniqueness proofs (human-backed bundles are denied)',
  'delegation-chain proofs (delegation-bearing bundles are denied)',
  'local replay state (host nonce mode only: reserve-before-act every consume_nonces entry)',
] as const;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** §2 structural validation — BEFORE any bundle decode or crypto. */
function validateRequest(request: unknown): asserts request is VerifierRequest {
  if (!isPlainObject(request)) {
    throw new VerifyDenial('malformed_input', 'request must be a JSON object');
  }
  if (typeof request.version !== 'number' || !Number.isInteger(request.version)) {
    throw new VerifyDenial('malformed_input', 'request.version must be an integer');
  }
  if (typeof request.bundle !== 'string' || request.bundle.length === 0) {
    throw new VerifyDenial('malformed_input', 'request.bundle must be a non-empty string');
  }
  const inner = request.request;
  if (!isPlainObject(inner)) {
    throw new VerifyDenial('malformed_input', 'request.request must be an object');
  }
  for (const field of ['agent_name', 'project_key', 'program', 'model'] as const) {
    if (typeof inner[field] !== 'string') {
      throw new VerifyDenial('malformed_input', `request.request.${field} must be a string`);
    }
  }
  if (
    !Array.isArray(inner.granted_capabilities) ||
    !inner.granted_capabilities.every((c): c is string => typeof c === 'string')
  ) {
    throw new VerifyDenial(
      'malformed_input',
      'request.request.granted_capabilities must be an array of strings',
    );
  }
  if (
    typeof request.now_unix !== 'number' ||
    !Number.isInteger(request.now_unix) ||
    request.now_unix <= 0
  ) {
    throw new VerifyDenial('malformed_input', 'request.now_unix must be a positive integer');
  }

  if (request.version !== 1) {
    throw new VerifyDenial('unsupported_version', `unsupported request version ${request.version}`, {
      expected: 1,
      got: request.version,
    });
  }
}

/**
 * Run the classical verification pipeline. Never throws: every failure path
 * resolves to a `deny` verdict (spec §7 — decision-level outcomes are
 * verdicts, not errors). Configuration is the CALLER's problem: it hands in
 * the tenant's canonical trusted-operator set and the effective capability
 * map, both already validated (a defect there is the caller's 500). Returns the
 * verdict and, on allow, what was verified.
 */
export function verifyClassical(
  body: unknown,
  trustedOperators: ReadonlySet<string>,
  capabilityMap: CapabilityMap,
): ClassicalResult {
  try {
    // 1. Request shape + version (cheapest, no crypto).
    validateRequest(body);
    const request = body;

    // 2. Preview scope gate: this endpoint is classical-only. An explicit
    //    request for zk-class verification is denied with a clear reason.
    if (request.kind !== undefined && request.kind !== 'classical') {
      throw new VerifyDenial(
        'invalid_proof',
        `this preview verifies classically only (requested kind "${String(request.kind)}"); ` +
          'zk verification is not available — use the `bolyra verify` CLI',
        { preview: 'classical-only' },
      );
    }

    // 3. Decode + structurally validate the presentation bundle.
    const bundle = parseBundle(request.bundle);

    // 4. Classical-only gate: human/delegation slots are backed exclusively by
    //    ZK proofs this preview cannot verify — deny rather than half-verify.
    if (bundle.human !== undefined || bundle.delegation !== undefined) {
      const slots = [
        ...(bundle.human !== undefined ? ['human'] : []),
        ...(bundle.delegation !== undefined ? ['delegation'] : []),
      ];
      throw new VerifyDenial(
        'invalid_proof',
        `bundle carries zk-only slots (${slots.join(', ')}) that this classical preview ` +
          'cannot verify — use the `bolyra verify` CLI',
        { preview: 'classical-only', slots },
      );
    }

    // (Groth16 verification + vkey pinning would run here in the zk-class
    // reference verifier. NOT performed — see CHECKS_NOT_PERFORMED. Because the
    // proof is unverified, NONE of the public signals are trusted below.)

    const agentSignals = bundle.agent.envelope.publicSignals;
    const cred = bundle.agent.credential;
    const operatorPubkey = {
      x: BigInt(cred.operator_pubkey.x),
      y: BigInt(cred.operator_pubkey.y),
    };

    // 5. TRUST ANCHOR: the operator key MUST be a configured trusted issuer,
    //    and the binding signature MUST verify against it. Together these are
    //    the classical authorization — an attacker cannot sign a binding for a
    //    trusted key they do not hold. Fail closed when the tenant has no
    //    issuer (enforced at load).
    assertTrustedOperator(trustedOperators, operatorPubkey.x, operatorPubkey.y);
    verifyBindingSig(
      bundle.binding,
      { R8: { x: BigInt(bundle.sig.R8.x), y: BigInt(bundle.sig.R8.y) }, S: BigInt(bundle.sig.S) },
      operatorPubkey,
    );

    // 5b. Binding v2: the SIGNED binding expiry MUST equal the revealed
    //     credential expiry that the strict-expiry check consumes. This closes
    //     the classical re-anchoring gap: rewriting binding.expiry breaks the
    //     signature, rewriting only credential.expiry is caught here.
    if (bundle.binding.expiry !== cred.expiry) {
      throw new VerifyDenial('invalid_bundle', 'binding expiry does not match the credential expiry', {
        binding_expiry: bundle.binding.expiry,
        credential_expiry: cred.expiry,
      });
    }

    // 6. Request binding + model binding — the request must match what the
    //    operator signed (sound: binding fields are covered by the signature).
    checkRequestBinding(request.request, bundle.binding);
    checkModelBinding(BigInt(cred.model_hash), request.request.model);

    // 7. Consistency: recompute the self-asserted scopeCommitment from the
    //    revealed preimage. NOT a trust check (the signal is unverified) — it
    //    catches an internally-incoherent credential.
    assertScopeAnchored(
      {
        modelHash: BigInt(cred.model_hash),
        opX: operatorPubkey.x,
        opY: operatorPubkey.y,
        bitmask: BigInt(cred.permission_bitmask),
        expiry: BigInt(cred.expiry),
      },
      BigInt(agentSignals[2] ?? '0'),
    );

    // 8. Capability → scope subset over the revealed bitmask (consistency).
    const required = requiredBits(capabilityMap, request.request.granted_capabilities);
    const effectiveScope = BigInt(cred.permission_bitmask);
    const effectiveExpiry = BigInt(cred.expiry);
    assertSubset(required, effectiveScope);

    // 9. Strict expiry against the caller's clock over the revealed expiry
    //    (spec §2.1: the host owns the time source).
    assertNotExpired(BigInt(request.now_unix), effectiveExpiry);

    // 10. Replay protection — host nonce mode ONLY (the Worker is stateless):
    //     emit the one-time nullifier for the caller to reserve-before-act.
    const nullifier = agentSignals[1];
    if (nullifier === undefined || nullifier === '0') {
      throw new VerifyDenial('nonce_missing', 'proof lacks a usable nullifier');
    }
    const consumeNonces: ConsumeNonce[] = [
      {
        issuer_key: `${cred.operator_pubkey.x}:${cred.operator_pubkey.y}`,
        nonce: nullifier,
        retain_until: Number(effectiveExpiry),
      },
    ];
    return {
      verdict: allow(consumeNonces),
      verified: { binding: bundle.binding, operator: operatorPubkey },
    };
  } catch (e) {
    if (isVerifyDenial(e)) return { verdict: e.toVerdict() };
    // Unexpected fault: never echo raw internals on the wire (spec §3.3 —
    // messages must not leak secrets/paths). Log server-side only.
    console.error('hosted-verify internal error:', e instanceof Error ? e.stack : String(e));
    return { verdict: deny('internal_error', 'internal verification error') };
  }
}
