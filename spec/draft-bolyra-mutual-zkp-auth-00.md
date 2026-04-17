---
title: "Mutual Zero-Knowledge Proof Authentication for Human and AI Agent Identities"
abbrev: "Bolyra Mutual ZKP Auth"
docname: draft-bolyra-mutual-zkp-auth-00
category: std
ipr: trust200902

author:
  - name: Viswanadha Pratap Kondoju
    organization: Bolyra
    email: viswa@bolyra.ai

normative:
  RFC2119:
  RFC8174:

informative:
  SEMAPHORE:
    title: "Semaphore: Zero-Knowledge Signaling on Ethereum"
    target: https://semaphore.pse.dev

--- abstract

This document specifies a protocol for privacy-preserving mutual authentication
between human users and artificial intelligence agents using zero-knowledge proofs
(ZKPs). The protocol enables a human and an AI agent to independently prove claims
about their identities -- group membership for humans and credential validity for
agents -- without either party learning anything about the counterparty beyond
policy satisfaction. The protocol further supports privacy-preserving composable
delegation of scoped permissions through chains of agents, where each delegation
hop narrows permissions without revealing the actual permission structure.

--- middle

# Introduction

The proliferation of autonomous AI agents acting on behalf of human users has
created an urgent need for identity and authorization infrastructure that spans
both human and AI populations. Existing approaches require either specialized
hardware (World/Worldcoin), government-issued identification (Didit), or expose
social graph patterns (BrightID). None provide privacy-preserving mutual
authentication across heterogeneous entity types.

This specification defines the Bolyra protocol, which addresses this gap through
three primitives:

1. A mutual handshake protocol where a human and an AI agent independently
   generate zero-knowledge proofs verified in a single on-chain transaction.

2. A composable delegation mechanism where scoped permissions are narrowed
   through multi-hop agent chains using identity-bound scope commitments.

3. A cumulative bit encoding scheme for hierarchical permissions that ensures
   delegation narrowing via bitwise AND correctly expresses tier downgrades.

## Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 {{RFC2119}} {{RFC8174}}
when, and only when, they appear in all capitals, as shown here.

# Terminology

Identity Commitment:
: A Poseidon hash of an EdDSA public key on the Baby Jubjub elliptic curve,
  used as the leaf value in a human identity Merkle tree. Computed as
  Poseidon2(Ax, Ay) where (Ax, Ay) is the public key point derived from
  the secret scalar via BabyPbk().

Credential Commitment:
: A Poseidon hash of an AI agent's credential fields, used as the leaf value
  in an agent credential Merkle tree. Computed as Poseidon5(modelHash,
  operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp).

Scope Commitment:
: An identity-bound hash of a permission bitmask and the entity's credential
  commitment. Computed as Poseidon2(permissionBitmask, credentialCommitment).
  Published as a public output of proofs to enable chain linking without
  revealing the actual permission bits.

Session Nonce:
: A fresh random value that binds both handshake proofs to the same session.
  MUST be unique per handshake. MUST be checked for freshness against an
  on-chain used-nonce mapping.

Nullifier:
: A deterministic value derived from the prover's secret and a scope identifier.
  Used to detect double-signaling within the same scope. MUST be computed as
  Poseidon2(scope, secret) for humans or Poseidon2(credentialCommitment,
  sessionNonce) for agents.

Nonce Binding:
: A derived value that cryptographically ties a human's proof to a specific
  session. Computed as Poseidon2(nullifierHash, sessionNonce). Enables the
  on-chain verifier to confirm that the human's proof was generated for
  this particular session.

Delegation Hop:
: A single step in a delegation chain where a delegator grants a subset of
  their permissions to a delegatee. Each hop produces a zero-knowledge proof,
  a new scope commitment for the next hop, and a delegatee Merkle root for
  enrollment verification.

Delegation Token:
: The message signed by a delegator to authorize a specific delegation.
  Computed as Poseidon4(previousScopeCommitment, delegateeCredCommitment,
  delegateeScope, delegateeExpiry).

Root History Buffer:
: A circular buffer of the last 30 Merkle roots maintained on-chain for
  both the human and agent trees. Prevents valid proofs from failing due
  to tree updates during proof generation.

# Protocol Overview

## System Architecture

The Bolyra protocol comprises three principal components:

1. A Human Identity Subsystem maintaining EdDSA-based identity commitments
   in a Lean Incremental Merkle Tree.

2. An AI Agent Credential Subsystem maintaining operator-signed credential
   commitments in a separate Lean Incremental Merkle Tree.

3. An On-Chain Registry Contract that stores both Merkle trees, verifies
   proofs, manages nonce freshness, tracks delegation chain state, and
   enforces revocation. The registry maintains a 30-entry circular root
   history buffer for each tree and stores delegation chain state indexed
   by session nonce.

## Cryptographic Primitives

Implementations MUST use the following cryptographic primitives:

- Hash Function: Poseidon algebraic hash over the BN128 scalar field
- Signature Scheme: EdDSA on the Baby Jubjub twisted Edwards curve
  (a = 168700, d = 168696) embedded in the BN128 scalar field
- Elliptic Curve Pairing: BN128 (alt_bn128) for Groth16 verification
  (EIP-196, EIP-197)
- Merkle Tree: Lean Incremental Merkle Tree with Poseidon2 as the
  node hash function, maximum depth of 20

Implementations MAY substitute alternative algebraic hash functions
(e.g., Rescue-Prime, Griffin) provided they operate over the same
prime field and maintain equivalent collision resistance.

## Proving Systems

The protocol uses a mixed proving system architecture:

- Human Identity Circuit (HumanUniqueness): Groth16. This enables reuse
  of the Semaphore v4 Powers of Tau Phase 1 ceremony, requiring only a
  circuit-specific Phase 2.

- Agent Credential Circuit (AgentPolicy): PLONK with universal setup.
  No circuit-specific ceremony is required.

- Delegation Circuit (Delegation): PLONK with universal setup. No
  circuit-specific ceremony is required.

The on-chain registry MUST support distinct verifier contract interfaces
for Groth16 and PLONK proof types.

# Mutual Handshake Protocol

## Overview

The mutual handshake enables a human and an AI agent to authenticate
each other without learning any identity information beyond the fact
that each party satisfies the required policy. Both proofs are bound
to the same session nonce and verified atomically in a single on-chain
transaction.

## Protocol Flow

1. The verifier (relayer or dApp) generates a fresh session nonce.
   The nonce MUST be cryptographically random and at least 128 bits.

2. The human generates a Groth16 zero-knowledge proof proving:
   - Their identity commitment is a leaf in the human Merkle tree
   - A scope-bound nullifier for Sybil detection
   - A nonce binding tying the proof to the session

3. The AI agent concurrently generates a PLONK zero-knowledge proof proving:
   - Their credential commitment is a leaf in the agent Merkle tree
   - An operator EdDSA signature over the credential commitment
   - Permission bitmask satisfies the required scope policy
   - Credential has not expired
   - An identity-bound scope commitment for delegation chain entry

4. Both proofs are submitted to the on-chain registry in a single
   transaction along with the session nonce as a transaction argument.

5. The registry MUST verify all of the following, in order:

   a. Session nonce freshness (not previously used). The nonce MUST be
      marked as used atomically with the rest of verification.
   b. Session nonce equality: the sessionNonce public signal from the
      human proof (humanPubSignals[4]) MUST equal the transaction
      argument, AND the sessionNonce public signal from the agent proof
      (agentPubSignals[5]) MUST equal the transaction argument.
   c. Human nullifier not in the revocation mapping.
   d. Human Merkle root validity (against the human root history buffer).
   e. Agent Merkle root validity (against the agent root history buffer).
   f. Groth16 proof validity (human) via the deployed Groth16 verifier.
   g. PLONK proof validity (agent) via the deployed PLONK verifier.

6. On success, the registry MUST:
   a. Record the nonce as used
   b. Store the agent's scope commitment (agentPubSignals[2]) as the
      delegation chain seed in the lastScopeCommitment mapping, indexed
      by session nonce
   c. Emit a HandshakeVerified event containing the human nullifier,
      agent nullifier, and session nonce

## Human Proof Specification

### Circuit: HumanUniqueness

The human circuit MUST accept the following signals:

Private inputs:

- `secret`: EdDSA secret scalar (Baby Jubjub subgroup order). MUST be
  range-checked to [0, 2^251) via Num2Bits(251) decomposition. The bound
  2^251 is strictly less than the Baby Jubjub subgroup order l, ensuring
  all valid secrets pass while rejecting field elements outside the range.
- `merkleProofLength`: Actual depth of the Merkle proof
- `merkleProofIndex`: Leaf index in the tree
- `merkleProofSiblings[MAX_DEPTH]`: Sibling hashes (padded to MAX_DEPTH)

Public inputs:

- `scope`: Context identifier for nullifier derivation
- `sessionNonce`: Session binding value

Public outputs:

- `humanMerkleRoot`: Computed Merkle root
- `nullifierHash`: Poseidon2(scope, secret)
- `nonceBinding`: Poseidon2(nullifierHash, sessionNonce)

The circuit MUST enforce the following constraints:

1. Secret range: secret MUST be decomposable into 251 bits (Num2Bits(251)),
   ensuring it lies in [0, 2^251).
2. Public key derivation: (Ax, Ay) = BabyPbk(secret), the Baby Jubjub
   scalar multiplication of the base point by the secret.
3. Identity commitment: identityCommitment = Poseidon2(Ax, Ay).
4. Merkle membership: BinaryMerkleRoot(MAX_DEPTH) with the identity
   commitment as the leaf MUST produce humanMerkleRoot.
5. Nullifier determinism: nullifierHash = Poseidon2(scope, secret).
   This value is deterministic per identity per scope.
6. Nonce binding: nonceBinding = Poseidon2(nullifierHash, sessionNonce).

### Human Public Signal Layout

The Groth16 verifier MUST receive exactly 5 public signals in this order:

| Index | Signal | Description |
|-------|--------|-------------|
| 0 | humanMerkleRoot | Computed Merkle root |
| 1 | nullifierHash | Sybil-detection nullifier |
| 2 | nonceBinding | Session binding hash |
| 3 | scope | Context identifier (public input) |
| 4 | sessionNonce | Session nonce (public input) |

## Agent Proof Specification

### Circuit: AgentPolicy

The agent circuit MUST accept the following signals:

Private inputs:

- `modelHash`: Hash of model identifier
- `operatorPubkeyAx`, `operatorPubkeyAy`: Operator EdDSA public key
  (Baby Jubjub point coordinates)
- `permissionBitmask`: 64-bit permission bitfield
- `expiryTimestamp`: Credential expiration (Unix timestamp)
- `sigR8x`, `sigR8y`, `sigS`: Operator EdDSA signature components
- `merkleProofLength`, `merkleProofIndex`,
  `merkleProofSiblings[MAX_DEPTH]`: Merkle inclusion proof

Public inputs:

- `requiredScopeMask`: Policy requiring specific permission bits
- `currentTimestamp`: Current time (from verifier)
- `sessionNonce`: Session binding value

Public outputs:

- `agentMerkleRoot`: Computed Merkle root
- `nullifierHash`: Poseidon2(credentialCommitment, sessionNonce)
- `scopeCommitment`: Poseidon2(permissionBitmask, credentialCommitment)

The circuit MUST enforce the following constraints:

1. Range checks: Num2Bits(64) on permissionBitmask, expiryTimestamp,
   and currentTimestamp. This prevents field overflow attacks where values
   greater than 2^64 pass the circuit but overflow in Solidity uint64.
2. Credential commitment: credentialCommitment = Poseidon5(modelHash,
   operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp).
3. EdDSA signature: EdDSAPoseidonVerifier over credentialCommitment using
   the operator's public key (Ax, Ay) and signature (R8x, R8y, S).
4. Merkle membership: BinaryMerkleRoot(MAX_DEPTH) with credentialCommitment
   as the leaf MUST produce agentMerkleRoot.
5. Scope satisfaction: for each bit i in [0, 64), the constraint
   requiredBits[i] * (1 - permBits[i]) === 0 MUST hold. This ensures
   every bit set in requiredScopeMask is also set in permissionBitmask.
6. Cumulative bit encoding: the following constraints MUST hold:
   - bitmaskBits[4] * (1 - bitmaskBits[3]) === 0
   - bitmaskBits[4] * (1 - bitmaskBits[2]) === 0
   - bitmaskBits[3] * (1 - bitmaskBits[2]) === 0
7. Expiry: currentTimestamp < expiryTimestamp, enforced via LessThan(64).

### Agent Public Signal Layout

The PLONK verifier MUST receive exactly 6 public signals in this order:

| Index | Signal | Description |
|-------|--------|-------------|
| 0 | agentMerkleRoot | Computed Merkle root |
| 1 | nullifierHash | Session-specific nullifier |
| 2 | scopeCommitment | Identity-bound scope hash |
| 3 | requiredScopeMask | Required permission bits (public input) |
| 4 | currentTimestamp | Current time (public input) |
| 5 | sessionNonce | Session nonce (public input) |

# Composable Delegation

## Overview

The delegation mechanism enables scoped permission narrowing through
multi-hop agent chains. Each hop proves in zero knowledge that the
delegatee's permissions are a subset of the delegator's permissions,
that the delegatee's expiry does not exceed the delegator's, and that
the delegatee is an enrolled agent in the agent Merkle tree.

## Identity-Bound Scope Commitment Chain

Delegation chain integrity is maintained through identity-bound scope
commitments. Each scope commitment is computed as:

    scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)

By including the credential commitment, the scope commitment is bound
to a specific enrolled entity. An actor with the same permission bits
but a different credential MUST NOT be able to produce a matching
scope commitment.

The chain operates as follows:

1. The mutual handshake stores the agent's scopeCommitment as the
   chain seed in the on-chain lastScopeCommitment mapping.

2. Each delegation hop reads the current lastScopeCommitment from
   on-chain state and proves that the delegator's scope and credential
   hash to this value.

3. Each hop outputs a new scopeCommitment binding the delegatee's
   scope and credential, which the registry writes back to the
   lastScopeCommitment mapping.

## Delegation Circuit Specification

The delegation circuit MUST accept the following signals:

Private inputs:

- `delegatorScope`: 64-bit permission bitmask of delegator
- `delegateeScope`: 64-bit permission bitmask of delegatee
- `delegateeExpiry`: Delegatee expiry timestamp
- `delegatorExpiry`: Delegator expiry timestamp
- `delegatorPubkeyAx`, `delegatorPubkeyAy`: Delegator EdDSA public key
- `sigR8x`, `sigR8y`, `sigS`: Delegator EdDSA signature over delegation token
- `delegatorCredCommitment`: Delegator's credential commitment
- `delegateeCredCommitment`: Delegatee's credential commitment
- `delegateeMerkleProofLength`, `delegateeMerkleProofIndex`,
  `delegateeMerkleProofSiblings[MAX_DEPTH]`: Delegatee Merkle proof

Public inputs:

- `previousScopeCommitment`: Chain-linking value from prior hop
- `sessionNonce`: Session binding value

Public outputs:

- `newScopeCommitment`: Poseidon2(delegateeScope, delegateeCredCommitment)
- `delegationNullifier`: Poseidon2(delegationTokenHash, sessionNonce)
- `delegateeMerkleRoot`: Computed Merkle root for delegatee enrollment

The circuit MUST enforce the following constraints:

1. Range checks: Num2Bits(64) on delegatorScope, delegateeScope,
   delegateeExpiry, and delegatorExpiry.
2. Chain linking: Poseidon2(delegatorScope, delegatorCredCommitment)
   MUST equal previousScopeCommitment. This is the critical identity-bound
   chain-linking constraint.
3. Scope subset: for each bit i in [0, 64), the constraint
   delegateeBits[i] * (1 - delegatorBits[i]) === 0 MUST hold.
4. Cumulative bit encoding on delegatee scope:
   - delegateeBits[4] * (1 - delegateeBits[3]) === 0
   - delegateeBits[4] * (1 - delegateeBits[2]) === 0
   - delegateeBits[3] * (1 - delegateeBits[2]) === 0
5. Expiry narrowing: delegateeExpiry <= delegatorExpiry, enforced
   via LessEqThan(64).
6. Delegation token: delegationToken = Poseidon4(previousScopeCommitment,
   delegateeCredCommitment, delegateeScope, delegateeExpiry).
7. EdDSA signature: EdDSAPoseidonVerifier over delegationToken using
   the delegator's public key.
8. Delegatee enrollment: BinaryMerkleRoot(MAX_DEPTH) with
   delegateeCredCommitment as the leaf MUST produce delegateeMerkleRoot.
   This prevents phantom delegatee attacks where permissions are delegated
   to non-enrolled entities.

### Delegation Public Signal Layout

The delegation PLONK verifier MUST receive exactly 5 public signals:

| Index | Signal | Description |
|-------|--------|-------------|
| 0 | previousScopeCommitment | Chain-linking input |
| 1 | sessionNonce | Session binding (public input) |
| 2 | newScopeCommitment | New chain-linking output |
| 3 | delegationNullifier | Replay-prevention nullifier |
| 4 | delegateeMerkleRoot | Delegatee enrollment proof |

## On-Chain Delegation Verification

The registry MUST verify each delegation hop by performing the following
steps in order:

1. Confirming that the session nonce was consumed by a prior handshake
   (usedNonces[sessionNonce] MUST be true). If not, the registry MUST
   revert with DelegationRequiresHandshake.

2. Reading the lastScopeCommitment for the session nonce from on-chain
   state. This value was either seeded by verifyHandshake or advanced
   by a prior verifyDelegation call.

3. Comparing the proof's previousScopeCommitment (pubSignals[0]) to
   the on-chain lastScopeCommitment. If they do not match, the registry
   MUST revert with ScopeChainMismatch.

4. Verifying the sessionNonce in the proof (pubSignals[1]) matches
   the transaction argument.

5. Verifying the delegation nullifier (pubSignals[3]) has not been
   previously used. If it has, the registry MUST revert with
   DelegationNullifierReused. The nullifier MUST be marked as used.

6. Incrementing the per-session hop counter and checking it does not
   exceed MAX_DELEGATION_HOPS. If it exceeds the limit, the registry
   MUST revert with MaxDelegationHopsExceeded.

7. Verifying the delegatee Merkle root (pubSignals[4]) exists in
   the agent root history buffer. If not, the registry MUST revert
   with StaleAgentRoot.

8. Verifying the PLONK proof via the deployed delegation verifier.

9. Writing the new scope commitment (pubSignals[2]) to the
   lastScopeCommitment mapping, advancing the chain state.

10. Emitting a DelegationVerified event containing the delegation
    nullifier, new scope commitment, and session nonce.

The maximum delegation chain depth MUST be enforced as an on-chain constant.
The default value is 3 hops.

# Permission Encoding

## Bitmask Structure

Permissions are encoded as a 64-bit unsigned integer bitmask:

| Bit | Permission | Implies |
|-----|-----------|---------|
| 0 | read_data | -- |
| 1 | write_data | -- |
| 2 | financial_transaction (tier 1) | -- |
| 3 | financial_transaction (tier 2) | bit 2 |
| 4 | financial_transaction (tier 3) | bits 2, 3 |
| 5 | sign_on_behalf | -- |
| 6 | sub_delegate | -- |
| 7 | access_pii | -- |
| 8-63 | application-specific | -- |

## Cumulative Encoding Invariant

Implementations MUST enforce the cumulative bit encoding invariant:

- If bit 4 is set, bits 3 and 2 MUST also be set
- If bit 3 is set, bit 2 MUST also be set

This invariant MUST be enforced in both the AgentPolicy circuit (at
credential proof time) and the Delegation circuit (at delegation time).
The invariant ensures that delegation narrowing via bitwise AND correctly
expresses tier downgrades. Without it, an agent could be enrolled with
bit 4 set but bits 2-3 unset, creating an inconsistent permission state
where the agent has unlimited financial authority without basic financial
permissions.

The constraint form is: higherBit * (1 - lowerBit) === 0, which
evaluates to zero when either the higher bit is unset or the lower bit
is set.

# On-Chain State Model

## Registry State

The on-chain IdentityRegistry contract MUST maintain the following state:

- `humanTree`: Lean Incremental Merkle Tree for human identity commitments
- `agentTree`: Lean Incremental Merkle Tree for agent credential commitments
- `humanRootHistory[30]`: Circular buffer of the last 30 human tree roots
- `agentRootHistory[30]`: Circular buffer of the last 30 agent tree roots
- `humanRootExists`: Mapping from root to boolean for O(1) root validity checks
- `agentRootExists`: Mapping from root to boolean for O(1) root validity checks
- `humanRevocations`: Mapping from nullifier hash to boolean for human revocation
- `usedNonces`: Mapping from session nonce to boolean for replay protection
- `usedDelegationNullifiers`: Mapping from delegation nullifier to boolean
- `delegationHopCount`: Mapping from session nonce to hop count
- `lastScopeCommitment`: Mapping from session nonce to the current chain
  scope commitment

## Enrollment

Human enrollment MUST insert an identity commitment (Poseidon2(Ax, Ay))
into the human tree and record the new root in the human root history buffer.

Agent enrollment MUST insert a credential commitment (Poseidon5(modelHash,
operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp))
into the agent tree and record the new root in the agent root history buffer.

Batch enrollment SHOULD be supported for both human and agent populations.

# Security Considerations

## Replay Protection

Session nonces MUST be unique and MUST be checked against the on-chain
usedNonces mapping before acceptance. Nonces MUST be marked as used
atomically with proof verification -- specifically, the nonce MUST be
marked used at the beginning of the verifyHandshake function, before
proof verification, to prevent reentrancy attacks.

Delegation nullifiers MUST be checked against the usedDelegationNullifiers
mapping and marked as used atomically with delegation verification.

## Nonce Equality Enforcement

The on-chain registry MUST explicitly check that the session nonce embedded
in each proof's public signals matches the session nonce provided as a
transaction argument. This prevents an attacker from submitting proofs
generated for different sessions in the same transaction. Specifically:

- humanPubSignals[4] MUST equal the transaction's sessionNonce
- agentPubSignals[5] MUST equal the transaction's sessionNonce

## Revocation

Human identities MAY be revoked by recording their nullifier hash in the
humanRevocations mapping. Because the human nullifier is deterministic per
identity per scope (Poseidon2(scope, secret)), revocation is stable across
sessions when the scope is constant.

Agent credentials SHOULD be revoked at the Merkle tree level by updating
the credential's leaf to zero using the Lean Incremental Merkle Tree's
update operation. This invalidates all subsequent Merkle proofs referencing
the original credential commitment. The new root is recorded in the root
history buffer, so in-flight proofs against pre-revocation roots remain
valid for the grace window (up to 30 tree operations).

Agent nullifiers are NOT suitable for revocation because they are
session-specific (Poseidon2(credentialCommitment, sessionNonce)) and change
with every session.

## Scope Commitment Privacy

The scope commitment Poseidon2(permissionBitmask, credentialCommitment) is
privacy-hiding within the ZKP protocol: an on-chain observer sees only the
hash, not the permission bits. However, the 64-bit permission bitmask domain
is susceptible to offline enumeration given a known credential commitment --
an attacker who knows an agent's credential commitment can hash all 2^64
possible bitmask values to find a match.

Implementations requiring stronger privacy SHOULD use a blinding salt:
Poseidon3(permissionBitmask, credentialCommitment, blindingSalt). When using
a blinding salt, the delegation circuit MUST be modified to include the salt
as a private input and incorporate it into both the chain-linking check and
the new scope commitment computation.

## Delegation Chain Integrity

Delegation chain state MUST be maintained on-chain, not supplied by callers.
The lastScopeCommitment mapping MUST be written only by:

- The verifyHandshake function (to seed the chain with the agent's
  scope commitment), and
- The verifyDelegation function (to advance the chain with the new
  scope commitment)

No caller-supplied parameter MUST participate in chain-state determination.
This design prevents an attacker from providing a fabricated
previousScopeCommitment that bypasses chain-linking verification.

Additionally, delegation MUST require that a handshake was previously
verified for the given session nonce. This binds the delegation chain to
a specific authenticated human-agent session, preventing delegation chains
that operate independently of any authenticated context.

## Phantom Delegatee Prevention

Each delegation hop MUST prove that the delegatee's credential commitment
is a leaf in the agent Merkle tree. The circuit computes the delegatee's
Merkle root as a public output, and the on-chain verifier checks this root
against the agent root history buffer. Without this check, an attacker
could delegate permissions to a non-enrolled phantom entity.

## Field Overflow Prevention

All circuit inputs representing bounded integer values (permission bitmasks,
timestamps) MUST be range-checked via Num2Bits decomposition to prevent
field overflow attacks. A value that is valid in the BN128 scalar field
(~254 bits) but exceeds the Solidity uint64 range would bypass on-chain
overflow checks while satisfying circuit constraints.

# IANA Considerations

This document has no IANA actions.

--- back

# Acknowledgments

The Bolyra protocol builds on the Semaphore Protocol {{SEMAPHORE}} for human
anonymous group membership proofs, and on the circomlib library for circuit
primitives (Poseidon hash, EdDSA verification, Merkle tree inclusion). The
Lean Incremental Merkle Tree implementation is from the @zk-kit library.
The BinaryMerkleRoot circuit is from @zk-kit/binary-merkle-root.circom.

# Circuit Constraint Budgets

The following are estimated constraint counts for each circuit at MAX_DEPTH=20:

- HumanUniqueness: ~15,000 constraints
  - BabyPbk scalar multiplication: ~5,000
  - Poseidon hashes (3x Poseidon2): ~1,200
  - BinaryMerkleRoot (depth 20): ~10,000
  - Num2Bits(251) range check: ~251

- AgentPolicy: ~50,000 constraints
  - EdDSA verify (EdDSAPoseidonVerifier): ~30,000
  - BinaryMerkleRoot (depth 20): ~10,000
  - Poseidon hashes (Poseidon5 + 2x Poseidon2): ~2,800
  - Range checks (3x Num2Bits(64) + Num2Bits(64)): ~256
  - Scope satisfaction (64 constraints): ~64
  - Cumulative bit encoding: ~3
  - LessThan(64): ~64

- Delegation: ~55,000 constraints
  - EdDSA verify: ~30,000
  - BinaryMerkleRoot (depth 20, delegatee): ~10,000
  - Poseidon hashes (Poseidon4 + 3x Poseidon2): ~3,200
  - Range checks (4x Num2Bits(64)): ~256
  - Scope subset (64 constraints): ~64
  - Cumulative bit encoding: ~3
  - LessEqThan(64): ~64
