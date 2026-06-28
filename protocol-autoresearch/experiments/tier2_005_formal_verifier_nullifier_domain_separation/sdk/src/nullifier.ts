/**
 * Nullifier construction helpers for the Bolyra identity protocol.
 *
 * Domain Separation Tags (v2.0.0):
 *   All nullifier derivations prepend a circuit-specific domain tag as the
 *   first Poseidon input, preventing cross-circuit nullifier collisions.
 *
 *   | Tag | Circuit          | Nullifier Formula                                       |
 *   |-----|------------------|---------------------------------------------------------|
 *   | 1   | HumanUniqueness  | Poseidon₃(1, scope, secret)                              |
 *   | 2   | AgentPolicy      | Poseidon₃(2, agentSecret, policyScope)                   |
 *   | 3   | Delegation       | Poseidon₄(3, delegatorSecret, delegateeCredComm, scope)  |
 *
 *   These tags are frozen constants — see circuits/FORMAL-PROPERTIES.md §P-DS-1.
 *   IETF RFC 9380 (hash-to-curve) domain separation conventions apply.
 *
 * @module nullifier
 */

import { poseidon3, poseidon4 } from "poseidon-lite";

// ── Domain tag constants ─────────────────────────────────────────────────
// These MUST match the circuit definitions in circuits/src/*.circom.
// They are frozen and MUST NOT be changed after deployment.

/** Domain tag for HumanUniqueness circuit nullifiers. */
export const HUMAN_NULLIFIER_DOMAIN = 1n;

/** Domain tag for AgentPolicy circuit nullifiers. */
export const AGENT_NULLIFIER_DOMAIN = 2n;

/** Domain tag for Delegation circuit nullifiers. */
export const DELEGATION_NULLIFIER_DOMAIN = 3n;

/**
 * Compute the domain-separated nullifier for a HumanUniqueness proof.
 *
 * @param scope - Application scope identifier
 * @param secret - Human prover's secret key
 * @returns The nullifier hash as a bigint
 */
export function computeHumanNullifier(scope: bigint, secret: bigint): bigint {
  return poseidon3([HUMAN_NULLIFIER_DOMAIN, scope, secret]);
}

/**
 * Compute the domain-separated nullifier for an AgentPolicy proof.
 *
 * @param agentSecret - Agent's secret key
 * @param policyScope - Policy scope identifier
 * @returns The nullifier hash as a bigint
 */
export function computeAgentNullifier(
  agentSecret: bigint,
  policyScope: bigint
): bigint {
  return poseidon3([AGENT_NULLIFIER_DOMAIN, agentSecret, policyScope]);
}

/**
 * Compute the domain-separated nullifier for a Delegation proof.
 *
 * @param delegatorSecret - Delegator's secret key
 * @param delegateeCredCommitment - Delegatee's credential commitment
 * @param scope - Delegation scope identifier
 * @returns The nullifier hash as a bigint
 */
export function computeDelegationNullifier(
  delegatorSecret: bigint,
  delegateeCredCommitment: bigint,
  scope: bigint
): bigint {
  return poseidon4([
    DELEGATION_NULLIFIER_DOMAIN,
    delegatorSecret,
    delegateeCredCommitment,
    scope,
  ]);
}
