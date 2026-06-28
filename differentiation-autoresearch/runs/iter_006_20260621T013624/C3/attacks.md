# Tier 3 Adversarial — C3 Delegation audit without exposure

## Persona: auth0_pm

---

### Attack 1: The Blinding Salt Is a New Category of Enterprise Secret You Have No Infrastructure For

- **Attack**: The construction requires every delegator to retain their `blindingSalt` across hops (§2, upstream circuit changes, "each delegator retains their blindingSalt to pass it as a private input when the next hop's delegation proof reconstructs their scope commitment for chain linking"). This is a new class of ephemeral-but-must-survive secret that sits outside every existing enterprise secret management pattern. It's not a long-lived credential (rotate on schedule), not a session token (expires with the session), and not a nonce (never reused). It must survive long enough for the next-hop prover to reconstruct the chain, and must be deleted afterward to prevent scope recovery. In an AI agent pipeline with 4 hops, this means 4 separate agents — potentially running in different orgs, clouds, or k8s namespaces — must coordinate salt handoffs in a way that is durable, confidential, and auditable. What happens when Hop 1's agent crashes mid-pipeline and its salt is lost? Is the chain permanently unauditable? Must the entire session be replayed? The construction states the change is "backward-compatible" (§2, upstream circuit changes) but says nothing about the operational lifecycle of these salts. WorkOS issues a JWT. The JWT contains the scope. The auditor reads the scope. There is no distributed secret coordination problem.

- **Why it works / why it fails against the construction**: The construction addresses the cryptographic need for salts in detail (§2 Constraint 3, §4 Reduction sketch) but does not address the key management lifecycle at all. The scenario in §7 says "each delegator retains their blinding salt" but does not say *where*, *how*, or *what failure modes exist*. This is a deployment gap, not a theoretical one.

- **In-threat-model?** No — the threat model (§3) defines adversary capabilities around Poseidon collision resistance and PLONK soundness. Salt loss, salt exfiltration by a compromised agent process, and recovery from failed delegation pipelines are outside the formal model. The construction must address this.

---

### Attack 2: Your "No Trusted Third Party" Claim Is Cryptographically True and Operationally False

- **Attack**: §8 prominently claims "PLONK proof is self-verifiable. The nullifier-scope binding ensures the proof's scopes match on-chain reality without querying any authority." But the audit workflow in §7 requires the auditor to "cross-reference each pair against on-chain `DelegationVerified` events." That on-chain query goes through an EVM RPC endpoint. In production, that endpoint is Alchemy, Infura, QuickNode, or a self-hosted Base node. The auditor now trusts: (a) the Circom compiler ZKProva Inc. used, (b) the `pot16.ptau` powers-of-tau ceremony provenance, (c) the deployed Solidity verifier contract on Base (who deployed it? who controls the upgrade key?), and (d) the RPC provider's view of on-chain state. The construction eliminates the *OAuth Authorization Server* as a trusted party and replaces it with the *Base L2 blockchain + a solo-founder's circuit artifacts*. For Navy Federal Credit Union's NCUA examiner (§7), this is not an improvement in the trust model — it is a lateral shift to infrastructure the credit union has never evaluated, never audited, and has no regulatory precedent for using in examination workflows. Auth0's trust chain for NFCU is: Auth0 (SOC 2 Type II) → JWT → auditor. Bolyra's trust chain is: ZKProva Inc. (unknown compliance posture) → Circom circuits → pot16.ptau → Base L2 → Alchemy RPC → auditor.

- **Why it works / why it fails against the construction**: The construction's §8 baseline comparison is technically accurate regarding the *cryptographic* trust model. It does not address *operational* trust: who audits the circuit code, who controls the verifier contract, who provides the RPC endpoint, and what the NCUA thinks about on-chain anchoring. The formal threat model in §3 explicitly excludes "the BN128 pairing (trusted setup for PLONK is universal)" from adversary control but does not address contract upgrade keys or RPC provider manipulation.

- **In-threat-model?** No — the formal model assumes correct circuit deployment and honest on-chain state. Contract upgrade key compromise and RPC-level equivocation are outside scope. For enterprise procurement, this is a blocker, not a footnote.

---

### Attack 3: You Are Solving the Wrong Problem for the Stated Buyer

- **Attack**: The entire construction is premised on a scenario where an NCUA examiner wants to verify monotonic narrowing *without learning intermediate scopes* (§7: "Examiner does NOT learn: who the intermediate agents are, what specific permissions each had, or the pipeline architecture"). But NCUA examiners under SR 11-7 and the FFIEC AI guidance want *maximum transparency*, not minimum disclosure. The stated buyer (Navy Federal Credit Union) has a regulatory incentive to show the examiner *everything* — because hiding the pipeline architecture from your regulator during an examination is a red flag, not a feature. The "journalist/source variant" (§7) is the use case where privacy from the auditor matters, and that is genuinely novel — but it is not a credit union use case, and it is not an enterprise MCP auth use case. By anchoring the flagship scenario (§7) to NFCU + NCUA, the construction claims enterprise-grade relevance for a construction whose privacy property is irrelevant or counterproductive to that buyer. WorkOS sells to enterprises who want their IAM team, their auditors, and their security team to see exactly who has what permissions. The construction's strongest feature (scope hiding from the auditor) is misaligned with the buyer it named.

- **Why it works / why it fails against the construction**: The construction's §7 scenario says "without Bolyra, NFCU must reveal TransUnion's involvement as competitive intelligence." But NFCU's NCUA examination is not adversarial — NFCU *wants* to show the examiner the pipeline is sound. The competitive intelligence concern is with third parties seeing the chain, not with the examiner. RFC 8693 tokens shown only to the examiner under NDA already solve the competitive intelligence concern without ZK proofs, at a procurement cost of $0.

- **In-threat-model?** No — the construction's gap list (candidate `gap_to_close`) mentions "too narrow, must broaden" use cases. The formal model is internally consistent. But the stated deployment scenario mismatches the privacy property, and a procurement team will catch this immediately.

---

### Attack 4: The Latency Tax Compounds Across the Entire Pipeline, Not Just the Audit

- **Attack**: The construction headlines the audit circuit at "< 2 seconds" (§6). But the upstream circuit changes (§2, §6) mean every delegation in the hot path now computes `Poseidon3` instead of `Poseidon2` — adding ~100 constraints per `AgentPolicy` invocation and ~200 constraints per `Delegation` invocation. In the §7 4-hop pipeline, that is 1 `AgentPolicy` proof + 4 `Delegation` proofs, each on circuits already at 18K–22K constraints, each now with additional Poseidon3 calls and two extra private inputs per hop. The construction's §6 cost estimate accounts only for the new `DelegationChainAudit` circuit and explicitly notes the upstream delta as "+~100 constraints" and "+~200 constraints" without estimating the per-hop proving time impact on the existing circuits. If the Delegation circuit's ~22K constraints already takes T seconds, the 1% constraint increase is not the issue — the issue is that every tool-call hop in a production pipeline now requires a ZK proof before proceeding. The construction's claim (§6) of "< 2 seconds" for the audit proof ignores that the 4 prior delegation proofs must also complete before the audit proof can be generated. WorkOS issues the entire 4-hop delegation chain as JWT exchanges in under 400ms total across the pipeline. The construction's pipeline latency is N × (Delegation proving time) + audit proving time, not just 2 seconds.

- **Why it works / why it fails against the construction**: The construction notes in §6 that proving times for the existing circuits (`AgentPolicy` ~18K, `Delegation` ~22K) are not the subject of the estimate. This is technically scoped correctly but operationally misleading when presented to an operator deciding whether to adopt the protocol. The comparison table (§8) cites WorkOS's <100ms without addressing the cumulative pipeline latency, only the audit proof latency.

- **In-threat-model?** No — the formal threat model is a soundness game, not a performance model. But the candidate's own `attack_prompts` explicitly call out "circuits take ~15s to prove, WorkOS issues tokens in <100ms" as a known attack surface. The construction provides a 2-second estimate for one new circuit while leaving the cumulative pipeline latency unaddressed. An operator evaluating adoption needs the end-to-end number.


## Persona: cryptographer

Applied cryptographer (IACR publications, reviews for CRYPTO/EUROCRYPT/S&P). Unless I see a threat model, a game definition, and a reduction sketch, it's marketing. You've provided more formalism than most — let me find the cracks.

---

### Attack 1: Cross-Session Chain Splice — The `chainAnchor` Does Not Prove Chain Coherence

**Attack:**

The adversary gathers `DelegationVerified` events from *two unrelated sessions* `S₁` and `S₂` whose scope bitmasks happen to be monotonically ordered. Concretely: let `(nullifier_A, scopeCommit_A)` come from session `S₁` with scope `0x87`, and `(nullifier_B, scopeCommit_B)` come from session `S₂` with scope `0x01`. The adversary constructs a `DelegationChainAudit` proof where hop 0 uses the `S₁` event and hop 1 uses the `S₂` event. The private witness satisfies every circuit constraint:

- Constraint 3 holds: the prover supplies the correct `(scope, credCommitment, blindingSalt)` tuples for each event (they know them, they generated both sessions)
- Constraint 5 holds: `0x01 ⊆ 0x87`
- Constraint 8 holds: each `hopDigest[i] = Poseidon2(nullifier_i, scopeCommit_i)` reconstructs correctly
- Constraint 9 holds: `chainAnchor = PoseidonN(hopDigest[0], hopDigest[1], 0, ..., 0)`
- The auditor cross-references both `(nullifier, scopeCommit)` pairs against on-chain events — both exist and match

Yet there is no actual delegation relationship between hop 0 and hop 1. Hop 0's agent never delegated to hop 1's agent. The adversary has fabricated a synthetic delegation chain from independent events.

**Why it works / why it fails:**

This works because **constraint 4 is vacuous as written**. The stated constraint is:

```
select(hopActive[i], scopeCommit[i-1], scopeCommit[i-1]) ===
select(hopActive[i], previousExpected, previousExpected)
```

Both sides of this equality reduce to `scopeCommit[i-1]` regardless of `hopActive[i]`, because `select(b, x, x) = x`. The term `previousExpected` is undefined in the circuit — it is a pseudocode artifact, not a witness signal. **The chain-linking constraint is never actually instantiated.** The circuit has no signal corresponding to "the `previousScopeCommitment` input fed into the `Delegation` circuit at hop `i`."

The `chainAnchor` cross-reference proves that each `(nullifier_i, scopeCommit_i)` pair exists on-chain in *some* `DelegationVerified` event. It does NOT prove that `scopeCommit[i]` was the `previousScopeCommitment` field supplied to the delegation proof that emitted `nullifier[i+1]`. These are distinct outputs and inputs of distinct on-chain transactions. Nothing in the circuit or the auditor's verification procedure checks that the events form a sequential delegation chain rather than a handpicked set of events with convenient bitmask ordering.

**In-threat-model?** No — construction must address this. The `NarrowingAuditSoundness` game condition (c) says "each hopDigest[i] matches a `DelegationVerified` event" — it does not require the events to form a chain. The adversary satisfies condition (c) while violating the intended semantics. The reduction sketch (steps 5–7) claims that matching `hopDigest[i]` to on-chain events forces the extracted scope to equal the actual on-chain scope, which is true — but "actual on-chain scope from hop `i`'s event" is not the same as "scope from the event that was the input to hop `i+1`'s delegation." The reduction conflates these. Fix: emit a `chainId` or `nextNullifierPreimage` commitment inside each `DelegationVerified` event and constrain it in-circuit.

---

### Attack 2: Universal SRS Subversion — The "No Per-Circuit Ceremony" Claim Is Misleading

**Attack:**

The construction justifies using PLONK on the grounds that "auditors can verify without trusting a circuit-specific ceremony." This is true — PLONK avoids a *per-circuit* trusted setup — but PLONK over KZG requires a *universal* structured reference string (SRS) that itself requires a trusted setup ceremony. If the party who ran the KZG setup retained the toxic waste `τ` (the secret evaluation point), they can compute a fake proof $\pi^*$ for any false statement, including:

$$\text{Verify}(\text{vk}, (\text{rootScopeCommitment, chainLength=4, ...}), \pi^*) = 1$$

with `narrowingValid = 1`, `policyOk = 1`, and a fabricated `chainAnchor` — even when the actual delegation violated monotonicity at every hop.

The adversary in `NarrowingAuditSoundness` need not find any witness at all. With the SRS trapdoor, they evaluate the quotient polynomial at `τ` directly and produce a valid KZG opening. PLONK knowledge soundness holds *only* in the algebraic group model (AGM) or generic group model conditioned on an honest SRS. Under subverted setup, all security properties (soundness and zero-knowledge) collapse simultaneously.

**Why it works / why it fails:**

Section 3 ("Adversary model") states the adversary does NOT control "the BN254 pairing (trusted setup for PLONK is universal)." This is stated as a non-capability, which is fair as a threat model choice. But Section 8 ("Why the baseline cannot match") claims "PLONK proof is self-verifiable … the BN254 pairing check and Poseidon preimage binding are the only trust assumptions." This is a lie by omission. The auditor must also trust:

1. That the KZG SRS `{τ^i G₁}` was generated honestly and τ discarded
2. That the circuit's constraint system was compiled correctly and the compiled `vkey` matches the intended circuit

Neither of these is self-verifiable by the auditor at proof-verification time. The claim in Section 7 that "no trust in NFCU's systems required" is false — the NCUA examiner must trust the SRS used by NFCU's PLONK prover. If NFCU ran the KZG ceremony themselves (or used one controlled by a single party), the examiner has no narrowing guarantee.

**In-threat-model?** Partially. The threat model excludes SRS subversion, which is a legitimate scope choice, but the construction's marketing language ("self-verifiable," "no trust in any authority") overstates the guarantee. In the NCUA scenario specifically — where the examining body is adversarial to NFCU and the SRS may have been generated by NFCU — this is not a fringe concern. The construction must either (a) explicitly state that SRS integrity is a trust assumption excluded from the game, or (b) specify a multi-party ceremony requirement, or (c) reference a transparent PCS (e.g., FRI-based STARK, which removes the SRS assumption entirely). The current Section 4 assumptions list does not include SRS honesty, making the reduction sketch formally incomplete.

---

### Attack 3: `sessionNonce`–Nullifier Binding Is Not Enforced In-Circuit

**Attack:**

The `sessionNonce` is listed as a public input. The construction states that `delegationNullifier[i] = Poseidon2(delegationTokenHash, sessionNonce)`. If this equality were enforced in-circuit with `sessionNonce` as a public input and `delegationTokenHash[i]` as a private input, then all nullifiers would be bound to the same session.

But examining constraints 1–10: **no constraint ties `delegationNullifier[i]` to `sessionNonce`**. The `delegationNullifier[i]` is a private input. The circuit checks (constraint 8) that `hopDigest[i] = Poseidon2(delegationNullifier[i], scopeCommit[i])` and (constraint 9) that `chainAnchor = PoseidonN(hopDigest[0..7])`. It does not check that `delegationNullifier[i]` was derived from `sessionNonce`.

The adversary constructs a proof with `sessionNonce = N₁` (matching a real handshake), but sources `delegationNullifier[1]` from a different session `N₂`. Since `delegationNullifier[1]` is a private input and is only constrained to match an on-chain `DelegationVerified` event (via `chainAnchor`), the adversary can mix nullifiers from sessions `N₁` and `N₂` freely, as long as the selected on-chain events have monotonically narrowing scopes.

**Why it works / why it fails:**

The construction in §5 maps `sessionNonce` binding to the "Handshake session nonce" in the spec, and §2 says `sessionNonce` "binds to the originating handshake session." This is an assertion about *intent*, not a circuit constraint. The binding only exists if the circuit contains:

```
for each i: delegationNullifier[i] === Poseidon2(delegationTokenHash[i], sessionNonce)
```

with `delegationTokenHash[i]` as an additional private signal. This constraint is missing. Without it, `sessionNonce` as a public input does nothing — it's a decorative field that the verifier checks is *present* but whose relationship to the private witnesses is unconstrained.

This compounds Attack 1: the adversary can not only mix events across sessions but can also include the "right" `sessionNonce` for the root handshake while sourcing intermediate delegation nullifiers from entirely different sessions, passing the auditor's check that `rootScopeCommitment` matches the handshake event for `sessionNonce` while the rest of the chain is fabricated.

**In-threat-model?** No — construction must address this. Add `delegationTokenHash[i]` as a private signal and enforce `delegationNullifier[i] = Poseidon2(delegationTokenHash[i], sessionNonce)` in-circuit for each active hop. This closes both this attack and partially mitigates Attack 1 (cross-session splicing becomes harder, though the chain-coherence gap in constraint 4 remains).

---

### Attack 4: Scope Recovery via Corrupted-Neighbor Disambiguation at Tight Chains

**Attack:**

The `ScopeRecovery` game allows the adversary to corrupt up to `n-1` hops in a chain of length `n`. Consider the journalist scenario: the journalist (hop 0) and the editor (auditor) are honest. The two relay agents (hops 1 and 2) and the source agent (hop 3) form the remaining hops. The adversary corrupts hops 1 and 2 (the relay agents), learning `scope[1]` and `scope[2]` and their blinding salts.

From the construction's own acknowledgment (Section 3, Collusion resilience): "If A corrupts hops j-1 and j+1, A learns `scope[j-1]` and `scope[j+1]`, and can verify narrowing relationships `scope[j+1] ⊆ scope[j] ⊆ scope[j-1]`." The adversary now knows the feasible set $F = \{s : \text{scope}[2] \subseteq s \subseteq \text{scope}[1]\}$.

For a bit-structured permission space where the journalist grants `{READ, WRITE, FINANCIAL_SMALL}` (hop 1 scope = `0x07`) and the relay narrows to `{READ}` (hop 2 scope = `0x01`), the feasible set for hop 1.5 (an intermediate hop the adversary doesn't control) is all `s` with `0x01 ⊆ s ⊆0x07`, giving exactly `{0x01, 0x03, 0x05, 0x07}` — 4 candidates. The blinding salt prevents confirming which one appears on-chain. But if the business context makes `0x01` or `0x07` the only operationally sensible choices (e.g., "this relay either read-only proxies or passes through full write capability"), the adversary's information-theoretic uncertainty is 1 bit, not 254 bits.

More formally: the security claim `Pr[ScopeRecovery] ≤ 256/|F_p| ≈ 2^{-246}` assumes `scope[j]` is drawn uniformly at random from `{0,...,255}`. This is not a realistic distribution for a business delegation chain. In practice, `scope[j]` is drawn from the feasible set $F$ determined by neighboring corrupted hops, and the adversary's advantage is `|F|` times larger than claimed. For tight chains, $|F| = 1$ and the adversary wins with probability 1 — exactly the degenerate case the construction acknowledges but dismisses as "inherent to the delegation semantics."

**Why it works / why it fails:**

The construction's response is: "the adversary learns the scope from the narrowing structure alone — but this is inherent to the delegation semantics, not a failure of the commitment scheme." This is technically correct but strategically evasive. The `ScopeRecovery` game as stated claims `Pr[A wins] ≤ 1/|F_p| + negl(λ)` — this is *false* when the adversary controls both neighbors of the target hop. The correct bound is:

$$\Pr[A \text{ wins}] \leq \frac{|F|}{|F_p|} + \text{negl}(\lambda)$$

where $|F|$ is the number of feasible scopes consistent with the corrupted neighbors' values. For well-structured permission lattices with few tiers, $|F|$ is a small constant (often 2–4), and the blinding gives no marginal benefit beyond what the monotonicity constraints already reveal.

The reduction sketch for `ScopeRecovery` (B sets `scopeCommit[j] = y` and runs A) is also incomplete: B must embed the challenge value into a *real on-chain event*, which requires writing to the blockchain. This non-standard reduction capability means B is not a polynomial-time Turing machine with standard black-box access — it controls the on-chain state, which is a stronger assumption than preimage resistance of Poseidon alone.

**In-threat-model?** Yes and no. The blinding genuinely prevents brute-force recovery of an independently-chosen scope (the attack that Section 3 formalizes against). But the stated probability bound `1/|F_p|` is wrong whenever the adversary corrupts neighboring hops — it should be `|F|/|F_p|`, and in realistic deployments with structured permission spaces, `|F|` is not negligibly small. The construction should (a) correct the bound in the `ScopeRecovery` game to condition on the corrupted neighbor set, (b) acknowledge this as an inherent information-theoretic leakage rather than claiming negligible advantage in all corrupted-neighbor scenarios, and (c) separate "hiding against a non-colluding auditor" (which the blinding achieves) from "hiding against an adversary who corrupts both neighbors" (which is impossible without additional indirection).


## Persona: cu_ciso

---

### Attack 1: The Incident Response Trap

- **Attack**: NCUA examination follows a member data breach traced to the AI loan-origination pipeline. The regulator opens an enforcement action under NCUA Part 748 §748.1(c), which requires the CU to "respond to and recover from" security incidents. The examiner invokes subpoena authority and demands the full delegation chain — who accessed what data, when, with what permissions. The CU runs the `DelegationChainAudit` circuit and produces `narrowingValid=1, policyOk=1`. The examiner rejects it: "I need to know which agent accessed the member's SSN, not a proof that someone somewhere was bounded to READ_DATA. Your narrowing proof is a wall, not an audit trail."

- **Why it works / why it fails**: The construction explicitly guarantees the auditor "does NOT learn: who the intermediate agents are, what specific permissions each had." This is the privacy property. But NCUA Part 748 and GLBA Safeguards (16 CFR §314.4(a)(2)) require the CU to demonstrate *actual* oversight of member data — not a proof of structural bounds. In litigation or enforcement, a CU that can prove narrowing held but cannot name the third-party agent at hop 2 has arguably destroyed audit evidence. The construction has no mechanism for *tiered disclosure* — a mode where the CU can produce the full plaintext chain to a regulator under seal while producing the blinded proof for routine audits. The examiner doesn't want the ZK proof; they want the underlying facts, and the construction has made those facts cryptographically unrecoverable from any party who doesn't hold all the private inputs.

- **In-threat-model?** **No** — the construction must address the regulatory disclosure scenario where privacy yields to legal compulsion. A tiered mode (the CU retains plaintext records; the ZK proof is for *routine* attestation only) is architecturally absent and is the gap.

---

### Attack 2: Blinding Salt Custody is Unauditable Key Management

- **Attack**: The construction requires each delegator to "retain their `blindingSalt` to pass it as a private input when the next hop's delegation proof reconstructs their scope commitment for chain linking." Under GLBA Safeguards Rule §314.4(c)(2) and FFIEC IT Handbook (Information Security), a regulated entity must maintain documented key management procedures including generation, storage, rotation, destruction, and recovery. The CISO asks the vendor: "Where does the blinding salt live? Show me the HSM policy." The construction says "retained locally by the delegator" — for hop 2, that's TransUnion. The CU has no contractual or technical control over whether TransUnion retains the salt in a browser ephemeral, a secrets manager with no MFA, or a developer's laptop. If TransUnion's salt is lost, the CU cannot generate a valid chain-linking proof and cannot produce the audit artifact at all. The gap is worse: the salt is not a cryptographic key in any standard sense, so it falls outside most CUs' key management policy scope entirely.

- **Why it works / why it fails**: The construction documents the salt as "a new private input (field element, ≥ 128 bits of entropy)" but provides zero operational guidance on its lifecycle. Section 2 describes the change as "minimal" and "backward-compatible" but that framing is cryptographic, not operational. For a CU managing third-party AI vendors, the blinding salt is an undocumented, unrecoverable secret held by a vendor over which the CU has no custody. Loss at any hop silently breaks the audit capability — and because the salt is private, the CU cannot even detect that it's missing until proof generation fails. Under NCUA's vendor management expectations (Letter 07-CU-13), the CU is responsible for ensuring third parties can support the CU's regulatory obligations. A salt that lives at TransUnion with no retention or rotation policy fails that bar.

- **In-threat-model?** **No** — the construction treats salt custody as a solved problem ("retained locally by the delegator") without specifying retention policy, recovery procedures, or how the CU exercises oversight of salt custody at third-party hops. This must be addressed.

---

### Attack 3: The Third-Party Vendor You Cannot Document

- **Attack**: NCUA Third-Party Relationships guidance (NCUA Letter 21-CU-02, aligned with FFIEC IT Handbook Outsourcing Technology Services) requires the CU to maintain a vendor inventory, conduct due diligence, and demonstrate ongoing oversight of each third party processing member data. In the NFCU deployment scenario (Section 7), hop 2 is a TransUnion credit scoring agent. The construction's privacy guarantee is that "the examiner cannot brute-force scope values" and "does NOT learn who the intermediate agents are." The examiner pivots: "Show me your vendor management file for the agent at hop 2." The CU produces it. Now the examiner asks: "How do I verify the agent in your vendor file is the same agent that participated in this delegation chain?" The `credCommitment[2]` is private. The on-chain `DelegationVerified` event emits `(delegationNullifier[2], scopeCommit[2])` — both opaque. Nothing in the construction allows the CU to bind a legal vendor identity (TransUnion's DUNS number, EIN, signed contract) to the cryptographic participant identity at hop 2 without revealing the hop's `credCommitment`. The construction has decoupled cryptographic identity from legal identity with no bridge.

- **Why it works / why it fails**: Section 7 frames this as a feature: the examiner learns the chain has 4 hops without learning who they are. But NCUA's third-party risk framework requires the CU to prove it *knows* who they are and has appropriate agreements in place. The `auditPolicyMask` check proves the terminal agent satisfied a policy; it does not prove the CU had a signed BAA, a vendor risk assessment, or NCUA-required due diligence file for the intermediate agents. A CU that can prove monotonic narrowing but cannot map the hop identities to its vendor management system will fail the third-party risk section of the NCUA examination regardless of the proof's cryptographic soundness. The construction needs a mechanism — likely out-of-band, but specified — for the CU to bind legal vendor identity to `credCommitment` in a way that is auditable to the examiner without full chain disclosure.

- **In-threat-model?** **No** — the construction addresses the *cryptographic* audit but not the *regulatory* audit, which requires identity-to-legal-entity binding at each hop. This is structurally absent.

---

### Attack 4: chainLength + auditPolicyMask as Pipeline Fingerprint

- **Attack**: `chainLength` and `auditPolicyMask` are public inputs. In a financial institution's AI pipeline, the number of hops and the policy the terminal agent must satisfy are not arbitrary — they're determined by the pipeline architecture. A sophisticated adversary (competitor, rogue examiner, nation-state) who observes multiple `DelegationVerified` events and multiple audit proofs over time can build a statistical fingerprint: "Navy Federal's loan origination pipeline always produces `chainLength=4`, `auditPolicyMask=0x01`." Combined with the timing of on-chain events (four `DelegationVerified` emissions in quick succession) and the `sessionNonce` structure, the pipeline architecture becomes identifiable even without recovering any scope value. The construction's own security analysis (Section 3, ScopeRecovery) acknowledges that "collusion resilience" fails when "narrowing constraints uniquely determine `scope[j]`" — in a 4-hop chain where the examiner knows root scope (from public `rootScopeCommitment`) and terminal policy (from `auditPolicyMask`), the intermediate scopes are constrained to the interval `[auditPolicyMask, rootScopeCommitment]`. For the NFCU scenario with `rootScopeCommitment` reflecting `0x87` and `auditPolicyMask=0x01`, the intermediate scopes are constrained but non-unique. However, if the pipeline is always run with the same 4 agents in the same roles, correlation of `credCommitment` values across the Merkle tree against on-chain nullifier patterns allows participant inference even without direct scope recovery — the CISO's Tier 1 ops team, or an NCUA examiner with a subpoena to the chain indexer, can run this analysis without breaking any cryptographic primitive.

- **Why it works / why it fails**: The construction prevents scope recovery via Poseidon3 preimage resistance (formally sound). It does not prevent *structural* fingerprinting from public metadata. The `chainAnchor` is a deterministic function of the hop nullifiers and blinded scope commitments; for a fixed pipeline run with the same participants, the same `chainAnchor` is produced each time (nullifiers bind to `sessionNonce`, so they differ per session, which mitigates exact replay — but the structural metadata does not). The construction does not analyze traffic analysis resistance or metadata leakage via `chainLength`, timing correlation, or `auditPolicyMask` semantics. For a mid-size CU with a small number of pipeline configurations, this is a realistic inference channel that falls outside the formal threat model.

- **In-threat-model?** **No** — the formal threat model addresses scope recovery and narrowing soundness but explicitly excludes traffic analysis and structural metadata inference. The construction must bound what an observer learns from `(chainLength, auditPolicyMask, sessionNonce, on-chain event timing)` jointly, or acknowledge this as an accepted residual risk with mitigation guidance (e.g., padding `chainLength` to a fixed value, abstracting `auditPolicyMask` to coarser policy identifiers).


## Persona: rfc7662_advocate

---

### Attack 1: AS-Issued Narrowing Attestation Renders the ZK Layer Redundant in the Primary Scenario

**Attack**: A well-configured AS implementing draft-ietf-oauth-jwt-introspection-response can issue a signed JWT that asserts, per-session, exactly what `DelegationChainAudit` outputs: `narrowingValid=true`, `policyOk=true` over a named `auditPolicyMask`, `chainLength`, and a session binding — without disclosing intermediate scope values or participant identities to the relying auditor. The AS computes the monotonic subset check server-side (it possesses all scope values at issuance time via RFC 8693 token exchange), then signs a narrowing-attestation JWT scoped to the specific examiner via audience binding (RFC 8707). The signed JWT is offline-verifiable; the auditor never queries the AS live.

The construction's §8 ("No trusted third party") asserts the PLONK proof is "self-verifiable" where the RFC 8693 chain "requires the Authorization Server." But the construction's primary scenario (§7, NCUA examination) posits an examiner who already **trusts NFCU's systems enough to accept loan origination outcomes**. An NCUA examiner operates within a supervisory regime — they trust the AS (or NFCU's audit log) as a regulated entity subject to examination. The threat model in §3 defines the adversary as one who "may collude with participants," not one who colludes with the AS. The AS-signed narrowing attestation produces identical public claims (`narrowingValid`, `policyOk`) with offline verifiability via standard JWS signature verification.

The construction's actual differentiator is: **scope hiding from the AS itself**. But in §7's NFCU scenario, NFCU operates the AS — it already knows all scope values. The ZK machinery protects against the examiner learning scopes, not against the AS.

**Why it fails / survives**: The construction survives only if you posit an adversarial AS that might lie about whether narrowing held. That threat is real for cross-org pipelines (§7 cross-org scenario) where no single AS sees all hops. For single-org regulatory audit (the §7 primary scenario), the AS-signed attestation covers the auditor's stated need. The construction overclaims scope in §8 by treating the regulatory scenario and the cross-org scenario identically.

**In-threat-model?** Partially. For cross-org and journalist scenarios: **yes, construction survives** — no single AS exists. For the NFCU regulatory scenario as described: **construction must address** why the examiner distrusts NFCU's own AS.

---

### Attack 2: The Blinding Salt Cooperation Paradox — Scope Hiding Defeats Audit Liveness

**Attack**: The construction introduces a new coordination requirement absent from RFC 8693: every delegator must **retain their `blindingSalt[i]`** and supply it as a private input when the next hop's delegation proof chains to their scope commitment (§2, "Required upstream change"). To generate the `DelegationChainAudit` proof, the proof generator needs `blindingSalt[i]` from every active hop.

Now consider the NFCU scenario: hop 2 is TransUnion, an external third party. The audit proof generator is NFCU's compliance agent. NFCU cannot produce the audit proof without TransUnion's `blindingSalt[2]`. But TransUnion's motivation for participating in the Bolyra construction is **scope hiding** — they don't want the examiner to learn their specific permissions. That same hiding property means TransUnion can credibly refuse to provide their blinding salt to NFCU, since disclosure of the salt to NFCU's proof generator is equivalent to disclosure of their scope (NFCU already knows `credCommitment[2]` from the Merkle tree and can trivially brute-force `scope[2]` given both `credCommitment[2]` and `blindingSalt[2]` over 8-bit values).

In RFC 8693, the AS retains the complete delegation lineage and can reconstruct a full audit trail **unilaterally**, without cooperation from any intermediate party. The RFC 8693 audit requires trusting the AS; it does not require runtime cooperation from every party in the chain.

The construction's §2 says "each delegator retains their `blindingSalt` to pass it as a private input" — but the protocol for HOW the proof generator obtains these salts from third-party delegators is not specified. If a party refuses, is lost, or is offline, the audit cannot proceed. The construction provides no recovery mechanism (salt escrow would defeat hiding; on-chain storage would defeat hiding; AS-mediated recovery reintroduces the AS as trusted third party).

**Why it fails / survives**: The construction does not address this coordination requirement at all. The threat model (§3) models adversaries who collude with participants — but does not model participants who are **honest but uncooperative** (they followed the protocol but won't provide their salt to an auditor they didn't originally consent to).

**In-threat-model?** No. **Construction must address** the blinding salt liveness dependency — either by specifying an out-of-band salt-sharing protocol, accepting reduced auditability when parties withhold salts, or noting that cross-org audit requires contractual salt-retention obligations outside the cryptographic layer.

---

### Attack 3: The On-Chain Registry Is a Trusted Third Party by Another Name

**Attack**: The construction's "No trusted third party" claim in §8 is undermined by its own anchoring mechanism. The `chainAnchor` cross-reference (§2, constraint 9) requires the auditor to verify `hopDigest[i]` against on-chain `DelegationVerified` events. This requires trusting:

1. **The smart contract** — that it correctly stores and emits `DelegationVerified` events, and that its `verifyProof` function correctly enforces the per-hop delegation constraints.
2. **The BN254 pairing implementation** — the PLONK verifier on-chain.
3. **The Ethereum/Base network** — that the events are not reorged, censored, or manipulated.
4. **The PLONK universal SRS** — a trusted setup ceremony. The construction notes "universal setup" but PLONK's SRS is still a multi-party computation that requires at least one honest participant. RFC 8693 with an HSM-backed AS signing key has a comparable single-point-of-trust model.

RFC 9449 DPoP + RFC 8707 audience binding + a threshold-signed AS (HSM cluster, multi-party signing) produces sender-constrained, audience-bound tokens with a comparable trust distribution. The "no trusted third party" framing in §8 implies Byzantine elimination of trust — but the construction merely **redistributes** trust from an AS to a smart contract plus a blockchain network plus a universal SRS ceremony. For enterprise deployments (NFCU), the smart contract operator is as trusted as an AS operator. Blockchain liveness (gas, finality) and reorg risk introduce failure modes absent from a well-operated AS.

**Why it fails / survives**: The construction survives on a more limited claim: the trust assumptions are **different** (math + on-chain state vs. AS query) and more verifiable (anyone can check the on-chain state without querying a private endpoint). The "no trusted third party" framing in §8 is too strong — the construction provides **verifiable trust** rather than **eliminated trust**.

**In-threat-model?** Yes, on the narrow claim. **But §8's framing must be corrected** — the construction should claim "verifiable on-chain trust anchor" rather than "no trusted third party," since the PLONK verifier contract and BN254 SRS are themselves trust assumptions that the RFC 8693 comparison glosses over.

---

### Attack 4: Bitmask Monotonicity Is Not Semantic Scope Narrowing — and the RFC 8693 AS Enforces the Right Predicate

**Attack**: Constraint 5 enforces `scope[i] & ~scope[i-1] == 0` — bitwise subset. This is correct only if **every bit has a fixed, universally agreed semantic meaning** and **operators cannot remap bit assignments across organizational boundaries**. In a cross-org scenario (the construction's stated motivation), hop 0 (journalist's agent, operated by NewsOrg) and hop 2 (relay agent, operated by SourceProtect) may have different operators who independently define their 8-bit permission encodings.

Concretely: if bit 5 means `SIGN_ON_BEHALF` in NewsOrg's operator policy but bit 5 is not defined (reserved) in SourceProtect's operator policy, a delegatee holding `scope[2] = 0b00100000` has passed the circuit's monotonic narrowing check while possessing a capability (`SIGN_ON_BEHALF` under NewsOrg's semantics) that was never explicitly granted by SourceProtect's interpretation.

In RFC 8693, scope values are **strings** (`"read:data"`, `"financial:small"`) and the AS enforces narrowing semantically — it refuses to issue a downstream token with a scope string not present in the upstream token. Semantic scope narrowing is protocol-enforced by the AS; bitwise subset is arithmetic-enforced by the circuit. When semantics are shared (within a single Bolyra deployment with canonical bit definitions), the circuit is correct. Across organizations with potentially different operator policies, the arithmetic predicate doesn't capture the semantic invariant.

The construction's §2 (Permissions Model in CLAUDE.md) defines a global 8-bit canonical encoding, which works within the Bolyra protocol. But §1 claims the construction "applies to AI agent pipelines ... cross-org agent handoff" — cross-org implies potentially heterogeneous operators. The circuit has no mechanism to verify that operator `A` at hop 0 and operator `B` at hop 3 are using the same bit semantics.

**Why it fails / survives**: The construction survives within a single Bolyra deployment where all operators adopt the canonical 8-bit encoding (enforced by the SDK). The cross-org claim is weakened if cross-org also means cross-encoding. The RFC 8693 AS baseline handles heterogeneous scope namespaces natively; the construction silently assumes a shared canonical encoding.

**In-threat-model?** No for single-deployment chains. For the cross-org scenario: **construction must address** how it guarantees that `credCommitment[i]` values at different hops correspond to operators who share the same canonical bit encoding — or restrict the cross-org claim to deployments where all operators register under a shared Bolyra authority that enforces the canonical encoding at enrollment time.


## Persona: spiffe_engineer

---

### Attack 1: Salt Custody Is a New Long-Lived Secret — SPIRE Eliminated This Problem

- **Attack**: The construction requires each delegator to *retain* their `blindingSalt[i]` as a private input so that the *next* hop's delegation proof can reconstruct `scopeCommit[i-1]` for chain-linking (constraint 4, Section 2), and so that an audit proof generated *after* the pipeline runs can supply all 8 salts. In a real AI agent pipeline — serverless functions, ephemeral containers, short-lived OIDC tokens — the hop-0 agent (the member's Claude instance) may not exist six months later when the NCUA examiner arrives. Section 7 says "each delegator retains their `blindingSalt` locally," but the construction is silent on: who stores the salts, for how long, under what key management policy, and what happens when a delegator is gone. SPIRE SVIDs rotate hourly via the Workload API. No workload retains a long-lived secret derived from its identity. Bolyra just introduced one: a per-hop field element that *must* be retained and retrievable for audit proof generation. If the pipeline operator stores the salts centrally to solve the availability problem, you have re-created a single point of trust (the salt registry) that you claimed to eliminate by removing the Authorization Server. If each hop is responsible for its own salt, you have a distributed key management problem that SPIRE solved at the infrastructure layer in 2017.

- **Why it works**: The construction's privacy guarantee (`ScopeRecovery` game, Section 3) depends on `blindingSalt[i]` being unknown to the adversary. But the construction's *liveness guarantee* (being able to generate an audit proof post-hoc) depends on `blindingSalt[i]` being *available* to the proof generator. These are directly in tension. The construction patches the brute-force scope enumeration attack but creates an offline availability requirement it does not formally specify.

- **In-threat-model?** **No** — construction must address. The salt custody lifecycle (generation, storage, access control, rotation, deletion after audit window) is not specified. The `ScopeRecovery` game assumes the adversary cannot obtain honest hop salts, but does not define what storage model guarantees this. The NCUA deployment scenario in Section 7 is incomplete without answering: which party generates the audit proof, and how does that party obtain the blinding salts of the ephemeral agents in the pipeline?

---

### Attack 2: `credCommitment` Is Operator-Asserted, Not Platform-Attested — SPIRE Roots Identity in Hardware

- **Attack**: The construction's agent identity is `credCommitment = EdDSA(modelHash, operatorPrivKey)` — the operator signs a hash of the model binary and calls it an identity. The ZK circuit verifies an EdDSA signature over this commitment (per Section 5, Baby Jubjub). SPIRE provides workload identity rooted in *platform attestation*: TPM2 measured boot, AWS instance identity documents, k8s ServiceAccount token binding, or SGX quote verification. The SPIRE agent attests the *platform running the code*, not a key held by whoever deployed it. The distinction matters in the NFCU scenario: a malicious NFCU operator could issue a `credCommitment` for a model binary they control, sign it with their `operatorPrivKey`, and use it in the delegation chain. The ZK proof verifies the credential structure but cannot verify that the agent presenting the credential is actually running the attested binary rather than something else. SPIRE's node attestation closes this gap at the infrastructure layer. Bolyra's `credCommitment` scheme is a software attestation rooted in key custody — weaker than any TPM-based binding and exactly the attack surface that SPIFFE was designed to eliminate.

- **Why it works**: Section 4 (Security Argument) cites "Discrete logarithm hardness on Baby Jubjub: credential commitments are binding." This only means the *operator* cannot equivocate about two different credentials under the same commitment. It does not mean the *running workload* is the one the commitment describes. An operator who controls `operatorPrivKey` can issue a valid `credCommitment` for any `modelHash` they choose, including a hash of a model they replaced post-issuance. The ZK proof proves credential *structure*, not runtime *identity binding*. This is the fundamental limitation of all certificate-based identity schemes that SPIFFE/SPIRE was designed to overcome.

- **In-threat-model?** **No** — construction must address. The threat model (Section 3) does not include a compromised operator who issues `credCommitment`s for binaries they no longer control. This is not an exotic threat: model updates, rollbacks, and A/B deployments are routine in production AI pipelines. Without hardware-rooted attestation, the `credCommitment` scheme is a softer security property than the protocol claims in regulatory contexts (NCUA, FFIEC SR 11-7).

---

### Attack 3: On-Chain Event Availability Is a Liveness Dependency SPIRE Does Not Have

- **Attack**: The auditor's verification (Section 2, constraint 9; Section 7, step 3) requires cross-referencing `hopDigest[i] = Poseidon2(nullifier_i, scopeCommit_i)` against on-chain `DelegationVerified` events. The verifier must be able to query the EVM chain (Base Sepolia in production, per `CLAUDE.md`) for the indexed events at the time of audit. SPIFFE JWT-SVIDs are self-contained bearer tokens: the JWT body carries the SPIFFE ID, the signature key is in the SPIFFE trust bundle, and verification requires only the trust bundle — no network call, no chain query, no event index. For NCUA examination purposes, the regulatory record retention window is 7 years (12 CFR 749). The construction requires that Base Sepolia (or whatever chain the registry is deployed on) index the `DelegationVerified` events for that duration and that the auditor can reliably query them. If the chain is pruned, archived, or the RPC provider changes, the `chainAnchor` cross-reference breaks. Section 8 claims "Offline verifiability: PLONK proof + on-chain event cross-reference. No real-time API calls to any authority" — but this is false. The cross-reference *requires* reading on-chain state. The construction confuses "no calls to an Authorization Server" with "no external dependency."

- **Why it works**: The `chainAnchor` design (constraint 9) is the binding mechanism that prevents fabricated witnesses, but it introduces exactly the external dependency it claims to eliminate. A SPIFFE engineer would observe: you traded AS liveness dependency for chain liveness dependency. You haven't eliminated the liveness requirement — you've moved it to a system with weaker availability SLAs than a production SPIRE server.

- **In-threat-model?** **No** — construction must address. The construction needs either (a) a mechanism for the proof generator to bundle the relevant event data as an inclusion proof (e.g., a Merkle proof against the block's event trie) so the auditor can verify offline without an RPC call, or (b) an explicit specification of the data retention and archival requirements. Neither is present.

---

### Attack 4: WIMSE Already Scopes This Problem — Why Are You Not Contributing There?

- **Attack**: `draft-ietf-wimse-arch` (currently in IESG review) explicitly addresses workload-to-workload delegation, token binding across workload identity boundaries, and selective disclosure of claims in the workload context. The WIMSE transaction token (`Txn-Token`) carries the full delegation context, and the architecture explicitly contemplates ZK-based attestors as a token type extension point. The construction's contribution — proving monotonic narrowing over hidden bitmasks — is a *ZK attestor plugin for WIMSE*, not a parallel protocol. Contributing this as a WIMSE extension (a ZK-based `att` claim type for delegation narrowing) would: (1) inherit SPIFFE trust domain federation for the cross-org case; (2) reuse SPIRE's node attestation to root `credCommitment` in hardware; (3) leverage the WIMSE transaction token's existing binding to `sessionNonce`-equivalent nonces (`req_cnf`); and (4) avoid the on-chain dependency by anchoring to SPIRE-attested state rather than EVM events. The construction's table in Section 8 dismisses this with "No standard defines how OAuth token exchange interoperates with on-chain ZKP verification" — but that is circular. The reason no standard defines this is that nobody has contributed the ZK primitive to WIMSE. The construction could be that contribution instead of a competing protocol.

- **Why it works / why it partially fails**: The attack correctly identifies that the ZK narrowing primitive does not require a new protocol — it could be a WIMSE attestor extension. Where the attack fails: the blinded Poseidon3 commitment for *on-chain, publicly observable* scope commitments has no analogue in WIMSE, which is an off-chain token architecture. The construction's specific claim that on-chain scope commitments must be computationally hiding (the `ScopeRecovery` game against a blockchain observer) is a real gap that WIMSE Txn-Tokens do not address — they are bearer tokens with encrypted or selectively disclosed claims, but the *on-chain anchoring* requirement (Section 5, on-chain registry requirement) is unique to the construction. However, the construction could be scoped to eliminate the on-chain anchoring requirement and contribute the ZK narrowing proof as a WIMSE extension — at which point it becomes an additive contribution to an existing standard rather than a parallel protocol, which is a significantly stronger position.

- **In-threat-model?** **Partially yes, partially no.** The construction survives the attack for the specific case where on-chain anchoring is a stated requirement (cross-org without shared AS). It does not survive the attack for the off-chain cases (journalist/source chain, intra-org AI pipeline within a single SPIRE trust domain). For those cases, the construction must either (a) justify why a WIMSE ZK attestor extension is insufficient, or (b) reposition as a WIMSE contribution rather than a competing protocol.
