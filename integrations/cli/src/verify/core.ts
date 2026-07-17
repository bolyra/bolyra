/**
 * Core verification orchestrator for the `bolyra verify` external verifier
 * (spec §5). This is the single place the individual verify/* modules are
 * sequenced into the full verification algorithm.
 *
 * CONTRACT:
 *   - Every verify/* module throws {@link VerifyDenial} on a policy/crypto
 *     failure. This core CATCHES it and returns its `.toVerdict()`.
 *   - Any OTHER (unexpected) throw is mapped to `deny('internal_error', ...)`.
 *   - `verify` is a PURE function of `(request, flags)` → `Verdict`: it reads no
 *     stdin and writes no stdout. The CLI shell (Task 14) owns I/O and exit
 *     codes; this module owns the algorithm.
 *
 * The §5 step order is load-bearing (fail-fast, cheapest/soundest checks first)
 * and MUST NOT be reordered — see the numbered comments below.
 */

import type { BolyraConfig } from '@bolyra/sdk';
import type { NonceStore } from '@bolyra/mcp';

import {
  allow,
  deny,
  isVerifyDenial,
  VerifyDenial,
  type Verdict,
} from './verdict';
import { parseBundle } from './bundle';
import {
  verifyAgentProof,
  verifyHumanProofIfPresent,
  requireNullifier,
} from './proofs';
import { loadRootSource, assertTrusted } from './roots';
import {
  assertScopeAnchored,
  assertSubset,
  assertNotExpired,
  type CredentialPreimage,
} from './scope';
import {
  verifyBindingSig,
  checkRequestBinding,
  checkModelBinding,
} from './binding';
import {
  verifyDelegationChain,
  type DelegationHop,
  type DelegationChainContext,
} from './delegation';
import { loadCapabilityMap, requiredBits } from './capabilities';
import { FileNonceStore, buildConsumeNonce } from './nonce-store';

/** Replay-mode: burn the agent nullifier locally, or delegate to the host. */
export type NonceMode = 'local' | 'host';

/**
 * The request-context block a caller asserts about the operation being
 * authorized. Every field is matched byte-for-byte against the signed binding
 * (except `granted_capabilities`, which must be a subset of it).
 */
export interface VerifierRequestContext {
  agent_name: string;
  project_key: string;
  program: string;
  model: string;
  /** Host capability tokens the caller wants to exercise (spec §6). */
  granted_capabilities: string[];
}

/**
 * The untrusted verification request (spec §4.1). `bundle` is the transport
 * encoding of a `bvp/1` presentation; `request` is the caller's asserted
 * context; `now_unix` is the verifier's clock.
 */
export interface VerifierRequest {
  /** Request envelope version. Only `1` is supported in v1. */
  version: number;
  /** Raw JSON object text, or base64url-encoded JSON, of the `bvp/1` bundle. */
  bundle: string;
  /** The caller's asserted request context. */
  request: VerifierRequestContext;
  /** The verifier's current time, Unix seconds. */
  now_unix: number;
}

/** Operator-supplied verification flags (resolved from CLI flags / env). */
export interface VerifyFlags {
  /** `--circuits-dir`: explicit circuit vkey/artifact directory. */
  circuitsDir?: string;
  /** `--roots-file`: path to the trusted-roots JSON. */
  rootsFile?: string;
  /** Repeated `--root`: inline trusted roots (trusted for any tree). */
  rootPins?: string[];
  /** `--capability-map`: path to a capability→permission JSON override. */
  capabilityMapFile?: string;
  /** `--nonce-mode`: `local` (default, burn locally) or `host` (emit instruction). */
  nonceMode?: NonceMode;
  /** Injectable nonce store (defaults to a durable {@link FileNonceStore}). */
  nonceStore?: NonceStore;
  /** SDK config forwarded to the delegation verifier (e.g. circuit dir). */
  config?: BolyraConfig;
  /**
   * `--verbose`: when set, an unexpected (non-{@link VerifyDenial}) failure
   * writes its raw detail (message/stack, which may include filesystem paths) to
   * STDERR. The wire `internal_error` verdict on stdout stays generic regardless.
   */
  verbose?: boolean;
}

/** Max retention for a burned nonce: 30 days (spec §5.2). */
const MAX_NONCE_TTL = 30 * 86400;

/**
 * Retention TTL (seconds) for a burned nonce: the time until the credential
 * expires, capped at {@link MAX_NONCE_TTL} and floored at 1 so the store never
 * receives a non-positive TTL (an already-expired credential is rejected by the
 * separate strict expiry check).
 */
function nonceTtl(expiry: bigint, nowUnix: number): number {
  const span = Number(expiry) - nowUnix;
  return Math.max(1, Math.min(span, MAX_NONCE_TTL));
}

/** Narrow an unknown value to a non-null, non-array plain object. */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * §5.1 — structurally validate the untrusted request BEFORE any bundle decode
 * or proof work. Ill-formed shape → `malformed_input`; a well-formed request
 * whose `version` is not `1` → `unsupported_version`. Both are thrown as
 * {@link VerifyDenial} so the single catch below maps them to a wire verdict.
 */
function validateRequest(request: VerifierRequest): void {
  const r = request as unknown;
  if (!isPlainObject(r)) {
    throw new VerifyDenial('malformed_input', 'request must be an object');
  }
  if (typeof r.version !== 'number' || !Number.isInteger(r.version)) {
    throw new VerifyDenial('malformed_input', 'request.version must be an integer');
  }
  if (typeof r.bundle !== 'string' || r.bundle.length === 0) {
    throw new VerifyDenial('malformed_input', 'request.bundle must be a non-empty string');
  }
  const inner = r.request;
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
  if (typeof r.now_unix !== 'number' || !Number.isInteger(r.now_unix) || r.now_unix <= 0) {
    throw new VerifyDenial('malformed_input', 'request.now_unix must be a positive integer');
  }

  // Well-formed but unsupported version.
  if (r.version !== 1) {
    throw new VerifyDenial('unsupported_version', `unsupported request version ${r.version}`, {
      expected: 1,
      got: r.version,
    });
  }
}

/**
 * Execute the full external-verifier algorithm (spec §5) and return a machine
 * verdict. Never throws: every failure path resolves to a `deny` verdict.
 *
 * @param request untrusted request (bundle + asserted context + clock).
 * @param flags operator-supplied resolution options (dirs, roots, nonce mode).
 */
export async function verify(request: VerifierRequest, flags: VerifyFlags): Promise<Verdict> {
  try {
    // 1. Validate the request shape + version (cheapest, no crypto).
    validateRequest(request);

    // 2. Decode + structurally validate the presentation bundle.
    const bundle = parseBundle(request.bundle);

    // 3. Groth16 + mandatory vkeyHash pinning (agent, then human if present).
    await verifyAgentProof(bundle, { circuitsDir: flags.circuitsDir });
    await verifyHumanProofIfPresent(bundle, { circuitsDir: flags.circuitsDir });

    const agentSignals = bundle.agent.envelope.publicSignals;
    const cred = bundle.agent.credential;
    const operatorPubkey = {
      x: BigInt(cred.operator_pubkey.x),
      y: BigInt(cred.operator_pubkey.y),
    };

    // 4. Trusted-root gate for the agent tree (and the human tree if present).
    const rootSource = loadRootSource({
      rootsFile: flags.rootsFile,
      rootPins: flags.rootPins,
      env: process.env,
    });
    assertTrusted(rootSource, agentSignals[0], 'agent');
    if (bundle.human !== undefined) {
      const humanSignals = bundle.human.envelope.publicSignals;
      assertTrusted(rootSource, humanSignals[0], 'human');

      // 4b. Bind the human proof to THIS session. HumanUniqueness public signals
      //     are [0]humanMerkleRoot [1]nullifierHash [2]nonceBinding [3]scope
      //     [4]sessionNonce; the agent proof's sessionNonce is agentSignals[5].
      //     Without this bind, a valid human proof captured from ANOTHER
      //     handshake could be stapled onto an unrelated agent proof to forge a
      //     "human-backed" verdict (forgeable-when-present replay).
      if (BigInt(humanSignals[4]) !== BigInt(agentSignals[5])) {
        throw new VerifyDenial('invalid_proof', 'human proof not bound to session');
      }
      // v1 handshakes fix the human scope at 1; anything else is not a v1 proof.
      if (BigInt(humanSignals[3]) !== 1n) {
        throw new VerifyDenial('invalid_proof', 'human proof wrong scope');
      }
    }

    // 5. Scope anchor (F1/F2): recompute scopeCommitment from the revealed
    //    credential preimage and bind it to publicSignals[2].
    const preimage: CredentialPreimage = {
      modelHash: BigInt(cred.model_hash),
      opX: operatorPubkey.x,
      opY: operatorPubkey.y,
      bitmask: BigInt(cred.permission_bitmask),
      expiry: BigInt(cred.expiry),
    };
    await assertScopeAnchored(preimage, BigInt(agentSignals[2]));

    // 6. Binding signature (F1): the operator's EdDSA signature over the signed
    //    binding must verify against the PROVEN operator public key.
    await verifyBindingSig(
      bundle.binding,
      { R8: { x: BigInt(bundle.sig.R8.x), y: BigInt(bundle.sig.R8.y) }, S: BigInt(bundle.sig.S) },
      operatorPubkey,
    );

    // 6b. Binding v2: the SIGNED binding expiry must equal the credential
    //     expiry the proof commits to. Together with the in-circuit expiry
    //     binding this closes the classical re-anchoring gap for a bundle
    //     verified by a zk-class verifier that also honors the binding.
    if (bundle.binding.expiry !== cred.expiry) {
      throw new VerifyDenial('invalid_bundle', 'binding expiry does not match the credential expiry', {
        binding_expiry: bundle.binding.expiry,
        credential_expiry: cred.expiry,
      });
    }

    // Shared nonce store: delegation per-hop replay (step 7) AND the top-level
    // agent nonce (step 11) burn into the SAME store instance.
    const nonceStore = flags.nonceStore ?? new FileNonceStore();
    const nonceMode: NonceMode = flags.nonceMode ?? 'local';

    // 7. Delegation chain (if any) → effective scope + expiry. Otherwise the
    //    effective authority is the credential's own bitmask + expiry.
    let effectiveScope: bigint;
    let effectiveExpiry: bigint;
    if (bundle.delegation && bundle.delegation.length > 0) {
      // In host nonce mode the verifier holds NO local state: per-hop delegation
      // nullifiers are session-bound (pinned to the agent's sessionNonce), so the
      // host reserving the agent nullifier already covers delegation replay. We
      // therefore skip the local per-hop burn under host mode (and emit no extra
      // host entry for delegation).
      const delegationConfig: BolyraConfig | undefined =
        flags.config ??
        (flags.circuitsDir !== undefined ? { circuitDir: flags.circuitsDir } : undefined);

      const ctx: DelegationChainContext = {
        agentScopeCommitment: BigInt(agentSignals[2]),
        sessionNonce: BigInt(agentSignals[5]),
        currentTimestamp: BigInt(agentSignals[4]),
        agentExpiry: BigInt(cred.expiry),
        rootSource,
        nonceStore,
        nonceTtlSeconds: nonceTtl(BigInt(cred.expiry), request.now_unix),
        skipNonceConsumption: nonceMode === 'host',
        ...(delegationConfig !== undefined ? { config: delegationConfig } : {}),
      };
      const effective = await verifyDelegationChain(
        bundle.delegation as unknown as DelegationHop[],
        ctx,
      );
      effectiveScope = effective.effectiveScope;
      effectiveExpiry = effective.effectiveExpiry;
    } else {
      effectiveScope = BigInt(cred.permission_bitmask);
      effectiveExpiry = BigInt(cred.expiry);
    }

    // 8. Request binding: the caller's asserted context must match the signed
    //    binding, and the requested model must equal the proven model hash.
    checkRequestBinding(request.request, bundle.binding);
    checkModelBinding(BigInt(cred.model_hash), request.request.model);

    // 9. Capability → scope: map host capabilities to required bits and assert
    //    they are a subset of the effective scope.
    const capabilityMap = loadCapabilityMap({ file: flags.capabilityMapFile });
    const required = requiredBits(capabilityMap, request.request.granted_capabilities);
    assertSubset(required, effectiveScope);

    // 10. Strict expiry against the effective expiry (now == expiry is EXPIRED).
    assertNotExpired(BigInt(request.now_unix), effectiveExpiry);

    // 11. Nonce / replay protection on the agent nullifier — plus, when the
    //     bundle is human-backed, the human-uniqueness nullifier under its own
    //     `human:` namespace (distinct from the agent key so the two never
    //     collide in the same local store).
    const nullifier = requireNullifier(agentSignals);
    const humanNonceKey =
      bundle.human !== undefined
        ? `human:${bundle.human.envelope.publicSignals[1]}`
        : undefined;

    if (nonceMode === 'host') {
      // Host mode: burn NOTHING locally; instruct the host to reserve each
      // one-time nullifier (scoped to the issuer key) until the effective
      // expiry, reserve-before-act (spec §7.3). Human-backed bundles carry a
      // second entry for the human nullifier.
      const issuerKey = `${cred.operator_pubkey.x}:${cred.operator_pubkey.y}`;
      const retainUntil = Number(effectiveExpiry);
      const consumeNonces = [buildConsumeNonce(nullifier, issuerKey, retainUntil)];
      if (humanNonceKey !== undefined) {
        consumeNonces.push(buildConsumeNonce(humanNonceKey, issuerKey, retainUntil));
      }
      return allow(consumeNonces);
    }

    // Local mode (default): burn the agent nullifier now; a replay denies.
    const ttl = nonceTtl(effectiveExpiry, request.now_unix);
    const fresh = await nonceStore.markIfFresh(nullifier, ttl);
    if (!fresh) {
      throw new VerifyDenial('nonce_replayed', 'agent nullifier replayed');
    }
    // Human-backed: also burn the human-uniqueness nullifier so the same human
    // proof cannot be re-presented within its retention window.
    if (humanNonceKey !== undefined) {
      const humanFresh = await nonceStore.markIfFresh(humanNonceKey, ttl);
      if (!humanFresh) {
        throw new VerifyDenial('nonce_replayed', 'human nullifier replayed');
      }
    }

    return allow();
  } catch (e) {
    if (isVerifyDenial(e)) return e.toVerdict();
    // An unexpected fault. NEVER echo the raw exception text on the wire verdict
    // — it can leak filesystem paths or other internal detail. Emit a generic
    // message; surface the real detail on STDERR only under --verbose.
    if (flags.verbose) {
      const detail = e instanceof Error ? (e.stack ?? e.message) : String(e);
      process.stderr.write(`bolyra verify: internal error: ${detail}\n`);
    }
    return deny('internal_error', 'internal verification error');
  }
}
