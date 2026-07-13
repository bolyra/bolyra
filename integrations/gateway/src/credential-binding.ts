/**
 * @bolyra/gateway — credential binding for packaged Core mode (--dev).
 *
 * Dev mode mocks proof verification, so the permission mask inside a bundle
 * is self-asserted. When the gateway config carries a static `credentials`
 * section, every claim is checked against the registered credential — the
 * packaged version of examples/verified-actions-demo's HostOptions.credentials
 * registry (added there after a Codex P1 about self-asserted masks), and the
 * dev-mode stand-in for production's resolveCredential + Poseidon3
 * scopeCommitment binding, where a forged mask cannot produce a valid proof.
 *
 * In production mode the same config section is compiled into a
 * resolveCredential implementation, so the cryptographic binding inside
 * @bolyra/mcp's verifyBundle (recompute Poseidon3(mask, commitment, expiry)
 * and compare to the proof's scopeCommitment output) engages with no
 * embedding code required.
 */

import { validateCumulativeBitEncoding } from '@bolyra/sdk';
import type { AgentCredential } from '@bolyra/sdk';
import type { BolyraProofBundle, BolyraAuthContext } from '@bolyra/mcp';
import type { CredentialSource, GatewayConfig } from './types';

/** A registered credential, parsed into bigints once at startup. */
export interface RegisteredCredential {
  permissionBitmask: bigint;
  expiryTimestamp?: bigint;
}

/** Result of a dev-mode credential binding check. */
export type CredentialBindingResult =
  | { ok: true }
  | { ok: false; reasonCode: string };

/** True when the config carries a usable static credential map. */
export function hasStaticCredentials(
  credentials: CredentialSource | undefined,
): credentials is Extract<CredentialSource, { type: 'static' }> {
  return (
    credentials !== undefined &&
    credentials.type === 'static' &&
    Object.keys(credentials.map ?? {}).length > 0
  );
}

/**
 * Compile the validated static credentials section into a lookup registry.
 * Returns undefined when no static credentials are configured (permissive
 * dev behavior is preserved — the caller is responsible for making that
 * tradeoff visible). Assumes validateConfig already ran; parse failures here
 * throw at startup, never mid-request.
 */
export function buildCredentialRegistry(
  credentials: CredentialSource | undefined,
): Map<string, RegisteredCredential> | undefined {
  if (!hasStaticCredentials(credentials)) return undefined;
  const registry = new Map<string, RegisteredCredential>();
  for (const [commitment, entry] of Object.entries(credentials.map)) {
    registry.set(BigInt(commitment).toString(), {
      permissionBitmask: BigInt(entry.permissionBitmask),
      expiryTimestamp:
        entry.expiryTimestamp !== undefined ? BigInt(entry.expiryTimestamp) : undefined,
    });
  }
  return registry;
}

/** Render a bitmask as binary with a "b" suffix (demo's fmtMask). */
function fmtMask(mask: bigint): string {
  return mask.toString(2) + 'b';
}

/** Circuits are 64-bit: masks, expiries, and scopes must fit uint64. */
export const UINT64_MAX = (1n << 64n) - 1n;

/**
 * Strict decimal-string -> bigint, same wire format as production's toBigInt
 * (integrations/mcp/src/verify.ts). Loose BigInt() would accept hex forms
 * production rejects. Returns null instead of throwing.
 */
function parseDecimal(value: unknown): bigint | null {
  if (typeof value !== 'string' || !/^\d+$/.test(value)) return null;
  return BigInt(value);
}

/**
 * Cumulative-bit encoding check — bit 4 (FINANCIAL_UNLIMITED) implies bits
 * 3+2, bit 3 (FINANCIAL_MEDIUM) implies bit 2. Delegates to the SDK's
 * validateCumulativeBitEncoding (the canonical mirror of the
 * AgentPolicy/Delegation circuits), adapted to the gateway's
 * error-description-or-null shape. The sdk floor is ^0.6.1, whose entry
 * loads snarkjs lazily, so this runtime import keeps the Core path
 * snarkjs-free (proven by test/sdk-canonical-validator.test.ts).
 * Returns an error description, or null when the mask is valid.
 */
export function cumulativeMaskError(mask: bigint): string | null {
  try {
    validateCumulativeBitEncoding(mask);
    return null;
  } catch (err) {
    return err instanceof Error ? err.message : String(err);
  }
}

/**
 * Dev-mode credential binding check — the demo host's check 3, packaged.
 *
 * The claimed identity/permissions MUST match the registered credential:
 *   - the bundle's credentialCommitment must be registered
 *     (`credential_unknown`),
 *   - the root permission mask the bundle asserts (agent public signal [3])
 *     must EQUAL the registered grant (`credential_mismatch` — forged claim),
 *   - a delegation chain may only narrow: the effective mask must be a
 *     subset of the registered grant (`credential_mismatch` — expansion),
 *   - a registered expiry, when present, must not have passed
 *     (`credential_expired`).
 *
 * No new crypto is invented here: dev proofs are mocked, so the registry is
 * the source of truth — exactly the verification depth of the demo's
 * registered-credential map.
 */
export function checkCredentialBinding(
  bundle: BolyraProofBundle,
  authCtx: BolyraAuthContext,
  registry: Map<string, RegisteredCredential>,
  nowSeconds: bigint = BigInt(Math.floor(Date.now() / 1000)),
): CredentialBindingResult {
  let commitmentKey: string;
  try {
    commitmentKey = BigInt(bundle.credentialCommitment).toString();
  } catch {
    return {
      ok: false,
      reasonCode: 'credential_unknown: commitment is not a decimal string',
    };
  }

  const registered = registry.get(commitmentKey);
  if (registered === undefined) {
    return {
      ok: false,
      reasonCode: 'credential_unknown: commitment not registered with this gateway',
    };
  }

  if (registered.expiryTimestamp !== undefined && registered.expiryTimestamp <= nowSeconds) {
    return {
      ok: false,
      reasonCode: `credential_expired: registered credential expired at ${registered.expiryTimestamp} (current: ${nowSeconds})`,
    };
  }

  // Root claim: agent public signal [3] is the requiredScopeMask the bundle
  // asserts for the credential itself. verifyBundle already parsed it (a
  // non-numeric value fails verification before this check runs).
  const claimedRoot = bundle.agentProof.publicSignals[3]
    ? BigInt(bundle.agentProof.publicSignals[3])
    : 0n;
  if (claimedRoot !== registered.permissionBitmask) {
    return {
      ok: false,
      reasonCode:
        `credential_mismatch: bundle claims permissions ${fmtMask(claimedRoot)} ` +
        `but the registered credential grants ${fmtMask(registered.permissionBitmask)} (forged bundle)`,
    };
  }

  // Delegation may only narrow — at EVERY hop, not just leaf-vs-root. A
  // chain 7 -> 1 -> 3 keeps its leaf under the root grant but the second hop
  // widened 1 -> 3; production's Delegation circuit rejects that, so dev
  // binding must too. Per hop, mirror the circuit/verifier semantics:
  //   - strict decimal wire format for scope/commitment/expiry (production's
  //     toBigInt path rejects hex forms),
  //   - uint64 range + cumulative-bit encoding on the scope,
  //   - scope must narrow relative to the previous hop,
  //   - expiry must not outlive the previous hop / registered credential
  //     (Delegation.circom enforces delegateeExpiry <= delegatorExpiry),
  //   - expired hops rejected against the GATEWAY clock (the bundle's own
  //     currentTimestamp is caller-supplied — never trust it for expiry).
  let previousScope = registered.permissionBitmask;
  let previousExpiry = registered.expiryTimestamp; // undefined = unbounded
  for (let i = 0; i < (bundle.delegationChain?.length ?? 0); i++) {
    const link = bundle.delegationChain![i];
    const hopScope = parseDecimal(link.delegateeScope);
    const hopExpiry = parseDecimal(link.delegateeExpiry);
    const hopCommitment = parseDecimal(link.delegateeCommitment);
    if (hopScope === null || hopExpiry === null || hopCommitment === null) {
      return {
        ok: false,
        reasonCode: `credential_mismatch: delegationChain[${i}] scope/commitment/expiry is not a decimal string`,
      };
    }
    if (hopScope > UINT64_MAX || hopExpiry > UINT64_MAX) {
      return {
        ok: false,
        reasonCode: `credential_mismatch: delegationChain[${i}] scope/expiry exceeds uint64 (circuit range)`,
      };
    }
    const maskError = cumulativeMaskError(hopScope);
    if (maskError) {
      return {
        ok: false,
        reasonCode: `credential_mismatch: delegationChain[${i}] scope violates cumulative-bit encoding — ${maskError}`,
      };
    }
    if (hopExpiry <= nowSeconds) {
      return {
        ok: false,
        reasonCode: `credential_expired: delegationChain[${i}] expired at ${hopExpiry} (current: ${nowSeconds})`,
      };
    }
    if (previousExpiry !== undefined && hopExpiry > previousExpiry) {
      return {
        ok: false,
        reasonCode:
          `credential_mismatch: delegationChain[${i}] extends expiry to ${hopExpiry} beyond ` +
          `its delegator's ${previousExpiry} (delegateeExpiry <= delegatorExpiry)`,
      };
    }
    if ((hopScope & ~previousScope) !== 0n) {
      return {
        ok: false,
        reasonCode:
          `credential_mismatch: delegationChain[${i}] expands permissions from ${fmtMask(previousScope)} ` +
          `to ${fmtMask(hopScope)} (scope narrowing is one-way)`,
      };
    }
    previousScope = hopScope;
    previousExpiry = hopExpiry;
  }

  // Defense in depth: whatever mask verification produced as effective must
  // itself sit inside the registered grant.
  const effective = authCtx.permissionBitmask;
  if ((effective & ~registered.permissionBitmask) !== 0n) {
    return {
      ok: false,
      reasonCode:
        `credential_mismatch: effective permissions ${fmtMask(effective)} exceed ` +
        `the registered grant ${fmtMask(registered.permissionBitmask)} (scope narrowing is one-way)`,
    };
  }

  return { ok: true };
}

/**
 * Compile the static credentials section into a resolveCredential
 * implementation for production mode. Returns undefined when no static
 * credentials are configured.
 *
 * The resolved object carries exactly the fields @bolyra/mcp's verifyBundle
 * consumes for scopeCommitment binding — permissionBitmask, commitment,
 * expiryTimestamp (Poseidon3 over those three MUST equal the proof's public
 * scopeCommitment output). The remaining AgentCredential fields (operator
 * key, EdDSA signature, modelHash) are proving-side material a verifier
 * never holds, so they are not representable in a verifier-side registry.
 */
export function createStaticCredentialResolver(
  credentials: CredentialSource | undefined,
): ((commitment: string) => Promise<AgentCredential | null>) | undefined {
  const registry = buildCredentialRegistry(credentials);
  if (!registry) return undefined;
  return async (commitment: string): Promise<AgentCredential | null> => {
    let key: string;
    try {
      key = BigInt(commitment).toString();
    } catch {
      return null;
    }
    const entry = registry.get(key);
    if (!entry || entry.expiryTimestamp === undefined) return null;
    // Expired registrations must not resolve. verifyBundle only docks score
    // for an expired credential (an otherwise-perfect proof would still pass
    // at 80 >= minScore 70), so the resolver fails closed instead.
    if (entry.expiryTimestamp <= BigInt(Math.floor(Date.now() / 1000))) return null;
    const credential: Pick<
      AgentCredential,
      'permissionBitmask' | 'expiryTimestamp' | 'commitment'
    > = {
      permissionBitmask: entry.permissionBitmask,
      expiryTimestamp: entry.expiryTimestamp,
      commitment: BigInt(key),
    };
    // Cast: verifyBundle only reads the three fields above (see
    // integrations/mcp/src/verify.ts). Proving-side fields are absent by
    // construction on the verifier side.
    return credential as AgentCredential;
  };
}
