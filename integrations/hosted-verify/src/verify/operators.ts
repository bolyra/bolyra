/**
 * Trusted-issuer gate for the CLASSICAL preview.
 *
 * WHY THIS AND NOT A MERKLE ROOT: the zk-class reference verifier
 * (`bolyra verify`) verifies a Groth16 proof that binds the credential to an
 * agent Merkle root, THEN checks that root against a trusted set. This preview
 * does not verify the proof, so the proof's public signals — including the
 * Merkle root — are attacker-controlled and carry no weight (an attacker just
 * copies a trusted root string into publicSignals[0]).
 *
 * The only cryptographically load-bearing fact in a bvp/1 bundle WITHOUT a
 * proof is the operator's EdDSA-Poseidon signature over the request binding
 * (spec §4). So the classical trust anchor is the set of trusted OPERATOR
 * PUBLIC KEYS: an `allow` requires the credential's operator key to be a
 * configured issuer AND the binding signature to verify against it. An
 * attacker cannot forge a binding signature for a key they do not hold.
 *
 * `TRUSTED_OPERATORS` is a comma-separated list of `x:y` decimal public-key
 * coordinate pairs. NO configured issuer is fail-closed (`internal_error`) —
 * never "all operators trusted".
 */

import { VerifyDenial } from './verdict';

/** Canonical `x:y` form of a public-key coordinate pair. */
export function operatorKeyId(x: bigint, y: bigint): string {
  return `${x.toString()}:${y.toString()}`;
}

/** Parse `TRUSTED_OPERATORS` into a set of canonical `x:y` decimal pairs. */
export function loadTrustedOperators(envValue: string | undefined): Set<string> {
  const entries = (envValue ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);

  if (entries.length === 0) {
    throw new VerifyDenial('internal_error', 'no trusted operator source configured');
  }

  const operators = new Set<string>();
  for (const entry of entries) {
    const parts = entry.split(':');
    if (parts.length !== 2 || !/^[0-9]+$/.test(parts[0]!) || !/^[0-9]+$/.test(parts[1]!)) {
      throw new VerifyDenial(
        'internal_error',
        'TRUSTED_OPERATORS entry must be an "x:y" decimal coordinate pair',
      );
    }
    operators.add(operatorKeyId(BigInt(parts[0]!), BigInt(parts[1]!)));
  }
  return operators;
}

/**
 * Assert the credential's operator key is a configured trusted issuer. Uses
 * `untrusted_root` — the spec §9 trust-anchor-rejected code, which the
 * registry documents as proof-system-agnostic (a classical verifier reuses the
 * same vocabulary).
 */
export function assertTrustedOperator(
  operators: Set<string>,
  opX: bigint,
  opY: bigint,
): void {
  const id = operatorKeyId(opX, opY);
  if (!operators.has(id)) {
    throw new VerifyDenial('untrusted_root', 'operator key is not a configured trusted issuer', {
      operator_key: id,
    });
  }
}
