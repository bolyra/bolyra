# Adversarial Review — Round 3 (Opus, post M1+M2)
Reviewed: 2026-04-16
Source: Claude Opus subagent
Verdict: **NOT READY TO FILE**

## The big finding: M2 was a self-inflicted wound

M2 broadened Claim 1(d)(iii) from "stores as storage variable" to a genus
covering storage/event/commitment-to-root. The intent was to close a
design-around. The actual effect: the claim now reads on Tornado Cash,
Aztec Connect, and Semaphore v4's event-based commitment storage.

- **112(a) hole**: The spec only describes the storage variable
  embodiment. Claiming event log + Merkle-of-records embodiments
  without any written description is a textbook LizardTech failure.
  Examiner will reject Claim 1 outright.
- **102/103 hole**: Tornado Cash literally emits `Deposit` events with
  commitments to a Merkle root. Aztec Connect does the same with
  rollup state. Pre-M2, the narrow "storage variable" language forced
  prior art through a narrow window. Post-M2, the door is open.
- **101 hole**: Genericizing the mechanism moves further from concrete
  technology. Alice Step 2 gets HARDER to survive.
- **112(b) hole**: "commitment to a root of a data structure containing
  such records" is unintelligible as drafted. Indefinite.

## Must-fix before filing (5 items)

### MF1. Revert or anchor M2
**Two options:**
- **Option A (safe):** Revert Claim 1(d)(iii) back to "stores... as a
  storage variable indexed by the session nonce." Accept the
  event-emission design-around risk — it's less severe than losing the
  claim to 112(a) and 102/103.
- **Option B (ambitious):** Keep the genus but add ~500 words of spec
  describing concrete algorithms for event-log retrieval and
  Merkle-of-records verification. Significant drafting work.

### MF2. Rewrite "commitment to a root of a data structure containing such records"
Currently unintelligible. If keeping the genus, use clear language like
"a root of a Merkle tree containing handshake-session records, the root
being stored on-chain and the record retrievable via Merkle proof."

### MF3. Add priority anchors for CIP candidates
Recursive SNARK folding, platform-signed attestations, off-chain
verification — all contemplated as CIPs but NOT disclosed anywhere. A
CIP filed later gets no priority to today. Add 1-2 paragraphs on each
as "alternative embodiments" to anchor priority.

### MF4. sessionNonce generation mechanism (1 paragraph)
"Verifier-generated" is repeated but never defined. Add:
"The session nonce may be generated via commit-reveal between parties,
derived from a blockchain randomness beacon (e.g., VRF output),
obtained from a recent block hash with commit-reveal hardening, or
selected randomly by the verifier subject to freshness enforcement
against the used-nonce mapping."

### MF5. Scope commitment brute-force mitigation (1 paragraph)
Current privacy argument is weak. The scope is 64 bits; a brute-force
Poseidon preimage attack is feasible for a determined adversary
(~2^64 hashes ≈ seconds on GPU). This undercuts the privacy claims of
Claims 1, 5, 9. Add discussion of:
- Entropy injection: concatenate a random salt with the scope bitmask
- Scope blinding: commit to Poseidon(scope, credCmt, blinding) where
  blinding is a random field element
- Acknowledged limitation: scope commitments are privacy-hiding in the
  ZK protocol but not against exhaustive offline search given a known
  credCmt. This is acceptable because delegatee credentials are
  Merkle-included in the on-chain tree and thus discoverable regardless.

## 101 outlook by claim

| Claim | Survival odds | Why |
|-------|--------------|-----|
| Claim 1 | 75% | Saved by specific circuit constraints in (c). M2 hurt it. |
| Claim 9 | 60% | Abstract "escrow/clerk on a computer" characterization likely |
| Claim 15 | 40-50% | Highest risk. Electric Power Group / Two-Way Media apply |
| Claim 16 (system) | 70% | Standard system-claim eligibility |

## Design-arounds that still escape (even after M1)

### DA1. Three-function state machine (~10 lines of Solidity)
Add a third write path (e.g., `refreshChainState()`). Now the contract
isn't "exclusively" writing from two functions. Claim 15(b) doesn't read.

### DA2. Mediator contract pattern
Handshake contract emits event. Separate oracle contract writes chain
state. Not "written by the handshake verification function."

### DA3. Recursive SNARK (Nova/SuperNova)
Aggregate all delegation proofs into one off-chain proof. Claims 1, 9,
15 all require on-chain verification — this escapes them entirely.
(The inventor flagged this as a future CIP, confirming the provisional
doesn't cover it.)

### DA4. Hash substitution
Claim 15(a) requires Poseidon. Competitor uses Keccak or Rescue —
no literal infringement.

### DA5. ECDSA instead of EdDSA
Claim 15(c)(iv) requires EdDSA. Competitor uses secp256k1-ECDSA-in-SNARK
(Aztec-style) — non-infringement.

### DA6. Two-address workaround
Split handshake and delegation across separate contracts. Argue
chain-state record is "maintained by a separate contract" — not
"the verifier contract" per Claim 15(d).

## Prior-art combinations that still threaten obviousness

**Claim 1 killer:**
Semaphore v4 + Indicio ProvenAI + zkLogin/Mysten Labs (dual-proof
verification in one tx) + Tornado Cash root-history pattern. Motivation:
PSE roadmap explicitly discusses this convergence.

**Claim 9 killer:**
UCAN v0.10 / Biscuit (capability attenuation) + zkCreds / Cinderella
(ZK subset proofs) + Semaphore (nullifier pattern) + standard state
machine. Scope-commitment chain linking via Poseidon is the obvious
application.

**Claim 15 killer:**
Combo 1 + Combo 2 + trivial observation to seed the delegation chain
from handshake output.

## Strategic claim recommendations

### Replace negative limitations with positive structural ones
Instead of "written exclusively by X and Y," use:
"wherein the verifier contract's external and public functions that
modify the chain-state record consist of the handshake verification
function and the delegation verification function."

This reduces Festo prosecution-history-estoppel exposure and is easier
to prove in litigation.

### Drop "exactly two conditions" from Claim 9(a)
It's in a parenthetical (likely non-limiting under Smart Enterprises)
and it excludes future legitimate extensions (emergency admin reset,
batch delegation).

### Add backup Claim 15' anchoring on specific crypto stack
Current Claim 15 survives Alice on the specific Poseidon/EdDSA/BabyJub/
LeanIMT combination AND the cumulative bit invariant. Make this explicit:

"Claim 15'. The method of claim 15, wherein:
- the first zero-knowledge proof uses Groth16 over BN128
- the second zero-knowledge proof uses PLONK over BN128
- all commitments use Poseidon hashes
- signatures use EdDSA over Baby Jubjub
- Merkle trees use LeanIMT with Poseidon
- permissions use cumulative bit encoding enforced at both enrollment
  and delegation."

This backup survives Alice cleanly.

## Decision matrix

| Action | Cost | Impact |
|--------|------|--------|
| Revert M2 (MF1 Option A) | 5 minutes | Fixes 112(a), 102/103, 101 simultaneously |
| Keep genus + add 500 words (MF1 Option B) | 2-3 hours | Broader coverage, but adds 112 risk |
| Add priority anchors (MF3) | 30 min | Protects future CIP priority |
| Add nonce mechanism (MF4) | 10 min | Closes MSP4 enablement gap |
| Add brute-force mitigation (MF5) | 15 min | Saves Claim 5 privacy argument |
| Rewrite negative limitations as positive | 30 min | Reduces Festo exposure |
| Add backup Claim 15' | 20 min | 101 safety net |

Total must-fix work: ~2 hours for safe path (Option A on MF1).
