The file write needs your permission. The construction is ready — here's a summary of what it contains:

**Circuit: `SelectiveScopeProof`** — ~28,000 constraints, fits within pot16.ptau.

**Core property:** Agent proves `permissionBitmask & requiredMask == requiredMask` inside a Groth16 proof without revealing any other bits, with no AS in the verification path. The RS sets `requiredScopeMask` at runtime.

**Five axes of strict separation from baseline:**
1. **AS-Blind** — agent proves from on-chain commitment, zero AS contact
2. **Runtime-adaptive bitwise predicate** — algebraic AND with implication closure, not string matching
3. **Adversarial-AS** — RS verifies against on-chain Merkle root, not AS attestation
4. **Constant-size** — 128 bytes regardless of bitmask width (vs O(|disclosed|) for BBS+)
5. **Model identity binding** — `Poseidon5(modelHash, opKey, permBitmask, expiry)` committed on-chain

**Scenario:** Navy Federal CU API gateway where fintech agents prove `READ_DATA | FINANCIAL_SMALL` without leaking that they also hold `WRITE_DATA` or `ACCESS_PII`, and without trusting a consortium-operated AS.

Please approve the file write to save `construction.md`.
