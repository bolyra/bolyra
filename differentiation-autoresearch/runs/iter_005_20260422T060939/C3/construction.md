The `construction.md` is ready to write. It addresses all six judge-identified gaps:

1. **Formal ScopeLattice** — §2.1 defines `(L, ≤)` as a Boolean lattice over `{0,1}^64` with `a ≤ b iff a AND b = a`, computable in-circuit via `C_narrow` (67 multiplication gates/hop). No accumulator needed — the lattice structure is purely arithmetic.

2. **SE-PLONK upgrade** — Assumption A2 names simulation-extractable PLONK (Ganesh-Orlandi-Tschudi, Crypto 2023, AGM+ROM). Game 2 (PARTICIPANT-HIDE) reduces to SE-PLONK ZK, providing full protection against adversarial auditors in the journalist scenario. HVZK is abandoned.

3. **Σblinding derivation** — C12 enforces `chainBlinding = Poseidon2(delegateeCredComm[last], sessionNonce)` in-circuit. Freshness comes from `sessionNonce` uniqueness. Malicious AS cannot compute `chainBlinding` without the credential commitment (Poseidon preimage resistance).

4. **Tree topology hiding** — Chains sharing `seedScopeCommitment` but diverging produce different `finalScopeCommitment` → different `rawChainNullifier` → different `blindedChainDigest`. Epoch blinding (C10) further decorrelates. Game 3 (EPOCH-UNLINK) proves this formally.

5. **Break-glass mechanism** — C11 adds ElGamal-on-BabyJubjub escrow of intermediate scopes. Threshold decryption (k-of-n NCUA key holders) enables post-incident recovery. `escrowDigest` anchors ciphertexts to the proof. Journalist scenario sets `escrowPubkey` to identity point, disabling escrow entirely.

6. **Proof scheduling** — Three explicit modes: Mode A (forensic, ~4.8s post-hoc), Mode B (pre-authorized commitments, ~200ms/hop for streaming AI), Mode C (batched, ~0.6s/chain amortized). Each scenario has a default mode assignment.

Please approve the write permission to save `construction.md`.
