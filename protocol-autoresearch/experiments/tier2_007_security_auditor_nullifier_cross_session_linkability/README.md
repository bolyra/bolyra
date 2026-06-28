# Experiment: HumanUniqueness Nullifier Cross-Session Linkability Fix

**ID:** `security_auditor_nullifier_cross_session_linkability`
**Priority:** High
**Persona:** Security Auditor
**Dimension:** Correctness

## Problem

The HumanUniqueness nullifier (`Poseidon₃(DOMAIN_HUMAN, scope, secret)`) is constant across all sessions for the same human identity. Colluding verifiers can link all handshakes by comparing nullifier values, breaking the privacy guarantees of the ZKP protocol.

## Solution: Two-Nullifier Architecture

Replace the single static nullifier with two outputs:

1. **Session nullifier** (public, per-session):
   ```
   nullifierHash = Poseidon₄(DOMAIN_HUMAN, scope, secret, sessionNonce)
   ```
   Unique per handshake. Used for replay prevention.

2. **External nullifier commitment** (public, stable):
   ```
   externalNullifierCommitment = Poseidon₁(Poseidon₃(DOMAIN_HUMAN, scope, secret))
   ```
   Same across sessions. Used on-chain for sybil gating and revocation.

## Artifacts

| File | Type | Description |
|------|------|-------------|
| `circuits/src/HumanUniqueness.circom` | Circuit | Updated with sessionNonce input and two-nullifier outputs |
| `circuits/src/HumanUniquenessRevocation.circom` | Circuit | Auxiliary circuit for revocation proofs |
| `contracts/src/HumanRegistry.sol` | Contract | Updated for session nullifier replay guard + commitment sybil guard |
| `contracts/src/IHumanVerifier.sol` | Contract | Updated interface with 4 public signals |
| `sdk/src/human.ts` | SDK | Updated witness builder and verification helpers |
| `sdk/src/types.ts` | SDK | `HumanProof` type with `externalNullifierCommitment` |
| `spec/draft-bolyra-mutual-zkp-auth-01.md` | Spec | Two-nullifier architecture + privacy threat model |
| `circuits/test/HumanUniqueness.test.js` | Test | Unlinkability, commitment stability, regression tests |
| `contracts/test/HumanRegistry.test.js` | Test | Registry integration tests with two-nullifier flow |
| `docs/privacy-nullifier-design.md` | Docs | Design doc with before/after diagrams |

## Usage

### Compile the circuit

```bash
npm run compile:circuits
```

### Run circuit tests (fast, witness-only)

```bash
npm run test:circuits:fast
```

### Run contract tests

```bash
npm run test:contracts
```

### SDK usage

```typescript
import {
  createHumanIdentity,
  generateSessionNonce,
  buildHumanWitness,
  computeSessionNullifier,
  computeExternalNullifierCommitment,
} from "@bolyra/sdk";

// Create identity
const identity = createHumanIdentity(secret);

// Generate a fresh session nonce per handshake
const sessionNonce = generateSessionNonce();

// Build witness for the circuit
const witness = buildHumanWitness(
  identity,
  scope,
  sessionNonce,
  merkleProof,
  identityTreeRoot
);

// The witness contains:
// - nullifierHash: unique per session (unlinkable)
// - externalNullifierCommitment: stable per identity (sybil gating)
```

## Migration from v2.0.0

1. **Trusted setup must be regenerated** — the public signal count changed from 3 to 4.
2. **Semaphore v4 ceremony no longer reusable** — different constraint shape.
3. **SDK `HumanProof` type** — gains `externalNullifierCommitment` and `sessionNonce` fields.
4. **`nullifierHash` semantics changed** — now per-session, not per-identity.
5. **On-chain registry** — must track both `sessionNullifiers` (replay) and `registeredCommitments` (sybil).

## Security Properties

| Property | Mechanism | Status |
|----------|-----------|--------|
| Cross-session unlinkability | sessionNonce in nullifier | ✓ Fixed |
| Replay prevention | sessionNullifiers mapping | ✓ Preserved |
| Sybil resistance | externalNullifierCommitment | ✓ Preserved |
| Revocation | revokedCommitments mapping | ✓ New |
| Domain separation | DOMAIN_HUMAN = 1 tag | ✓ Preserved |
