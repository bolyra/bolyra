# Tier 3 Adversarial — C2 Cross-scope unlinkability

## Persona: auth0_pm

---

### Attack 1: The 30-Second Payment Terminal

- **Attack:** Section 7's deployment scenario puts a credit union member agent paying at Amazon checkout. Section 4's side-channel table says RSes batch Merkle root freshness checks on a "fixed schedule (e.g., every 30s)" to decouple authentication timing from on-chain reads. Add 1.5s rapidsnark proof generation plus network round-trip. Worst-case checkout latency: **~32 seconds**. WorkOS and Stytch issue tokens in <100ms. Auth0 MCP auth completes in a single OAuth redirect. No Amazon payment team approves a 32-second p99. The construction introduces the 30s batching window specifically as a privacy property (decoupling AS timing observation), so shortening the window directly degrades the unlinkability guarantee claimed in Section 3. You cannot have both <100ms latency and the timing side-channel mitigation — the construction presents these as compatible without addressing the tradeoff.

- **Why it works / fails:** The construction does not model or bound the latency introduced by batched root reads. Rapidsnark's 1.5s is quoted for the proving step alone (§6). The batching interval is presented as a free parameter, but its minimum value is bounded below by the unlinkability guarantee: a 0ms batch interval collapses to real-time root reads, which reintroduces the timing correlation the construction claims to prevent (§4, timing side channel row). The construction cannot reduce batch interval to <1s without weakening its own security argument.

- **In-threat-model?** No — the construction must bound the latency vs. privacy tradeoff explicitly and show it is acceptable for the named deployment scenarios (payment flows, Section 7).

---

### Attack 2: RS-Local Nullifier Storage Is an Unaudited Distributed Systems Requirement

- **Attack:** Section 2's verification architecture diagram says "RS checks nullifier not reused / store scopedNullifier locally." For Amazon as RS-A, "locally" means Amazon's payment microservice cluster — potentially hundreds of stateful nodes that must share a nullifier set with consistency guarantees. The construction offloads double-spend prevention from the blockchain (where it's free, atomic, and auditable) to the RS operator's internal infrastructure. If Amazon runs two payment service instances that don't share nullifier state within the same 30s proof validity window, replay within that window succeeds. The construction gives no guidance on nullifier storage consistency requirements, SLA, or what happens when the RS's nullifier DB is unavailable (fail open = replay attacks; fail closed = availability collapse). Auth0 and WorkOS manage this infrastructure for customers. Here every RS operator must implement it correctly, independently.

- **Why it works / fails:** Section 2 describes nullifier storage in one sentence: "Each RS maintains its own nullifier set (scoped to its `scopeId`). On-chain nullifier storage is NOT required." This is a correct statement of the design, but it defers a critical correctness burden to the RS operator without specifying what "maintains" requires. The security proof in Section 4 assumes nullifiers are checked but says nothing about what happens under distributed RS deployment — which is the only realistic deployment for any RS large enough to justify ZK auth overhead.

- **In-threat-model?** No — the construction must specify nullifier storage consistency requirements (e.g., linearizable store, proof-of-freshness window, failure mode policy) or the replay-resistance guarantee is unverifiable by a procuring enterprise.

---

### Attack 3: Privacy Guarantee Inverts the Regulatory Requirement

- **Attack:** Section 7 cites FCRA §604 and Reg V as the reason the credit union AS "must not construct a member's merchant graph." This is real. But the same credit union is a federally-insured depository institution subject to BSA/AML: 31 USC §5318(g) requires suspicious activity reporting, and FinCEN expects the institution to be able to reconstruct transaction authorization chains on demand for examination. The construction's privacy property — that the AS "observes no per-agent, per-merchant data. Cannot reconstruct merchant graph" — is precisely the audit trail a BSA examiner will subpoena. The construction solves one regulatory problem by creating a more serious one. A credit union compliance officer reviewing this will reject it not because the cryptography is wrong, but because "our AS cannot see what our agents authorized" fails the next NCUA examination. WorkOS and Auth0 ship SOC 2 Type II audit logs of every token issuance as a feature, not a bug.

- **Why it works / fails:** The construction presents FCRA compliance as a clean win in §7 without addressing the competing BSA/AML audit obligation. There is no mention of how an authorized regulator (not an adversarial AS) would obtain the per-agent transaction record when lawfully required. The threat model in Section 3 defines the AS as adversarial, but the real deployment has the AS as a regulated entity with mandatory logging obligations. These two framings are in direct conflict and the construction does not resolve them.

- **In-threat-model?** No — the construction must propose a lawful audit access mechanism (e.g., agent-held audit log, regulatory disclosure circuit, escrow of `credCommitment` with HSM-protected regulatory key) or the credit union deployment scenario is not viable.

---

### Attack 4: Revocation Latency Is Unbounded Under the Root History Buffer

- **Attack:** Section 5 references a "30-entry circular buffer, read-only by RS" for root freshness. When a credential must be revoked — member reports their agent compromised, fraud detection fires, member closes account — the credit union updates the Merkle tree, changing the root. RSes that have already read and cached a prior root will continue to accept proofs against the old root until their next scheduled read. With 30s batching intervals and a 30-entry buffer, a revoked credential could remain valid at any given RS for up to 30s × 30 = 15 minutes in the worst case if the RS hasn't refreshed. For financial transactions this is a critical gap. OAuth token introspection (RFC 7662) gives near-instantaneous revocation. Short-lived OAuth tokens (60s) cap revocation lag. The construction's revocation path is: update Merkle tree on-chain → wait for RS to read new root → RS starts rejecting proofs against old root. The construction does not bound this lag or provide an emergency revocation path.

- **Why it works / fails:** The buffer size (30 entries) and batch interval are implementation parameters in the construction, so a reader might argue "just use 1-entry buffer + 1s interval." But Section 4 shows this collapses the timing side-channel mitigation. The construction is again trading two security properties against each other without characterizing the tradeoff space. More fundamentally, no revocation mechanism is specified — the construction says nothing about what a credit union does when it needs to immediately invalidate a credential.

- **In-threat-model?** No — the construction must specify a revocation mechanism with a bounded revocation latency SLA, and must show that the chosen latency bound is compatible with the timing side-channel mitigation's required batch interval.


## Persona: cryptographer

Applied cryptographer, IACR reviewer. I've read the construction twice. The game definition is present, which is a good sign — but the reduction sketch collapses under scrutiny, and the threat model contains a structural contradiction that invalidates the central claim. Here are the attacks.

---

### Attack 1: AS Enrollment Oracle — The PRF "Key" Is Not Secret

**Attack:** The reduction sketch (§4, step 1) invokes PRF security with `credCommitment` as the key: "adversary knows `scopeId` (public input) but not `credCommitment` (private)." This is false for the AS.

The AS is defined as the **enrollment authority and Merkle tree operator** (§3). To insert a leaf into the agent Merkle tree, the AS must know or compute the leaf value. The leaf is `credCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)`. Inspect each input:

- `modelHash` — hash of a public model identifier. Known.
- `operatorPubkeyAx`, `operatorPubkeyAy` — EdDSA *public* key. Known by definition.
- `permissionBitmask` — the AS *sets* this at enrollment. Known.
- `expiryTimestamp` — the AS *sets* this at enrollment. Known.

There is no agent-held secret mixed into `credCommitment`. The entire preimage is either public or AS-controlled. The AS can recompute `credCommitment` for every enrolled agent from enrollment records. With `credCommitment` in hand, the AS evaluates `Poseidon2(scopeId_B, credCommitment)` for any target RS-B using a **single forward Poseidon call** — no inversion required.

Section §7.1 explicitly claims: "the credit union cannot compute `scopedNullifier_B` for Costco because it would need `credCommitment` (private)." The credit union computed `credCommitment` when it enrolled the agent. This claim is false.

**Why it works:** The PRF assumption requires the key to be a uniform secret unknown to the adversary. Here the "key" (`credCommitment`) is fully determined by AS-visible data. The reduction to PRF security is vacuous — it's excluding the adversary from the very knowledge that defines its role.

**Compare to Semaphore v4** (which the construction explicitly analogizes in §5): Semaphore identity commitment = `hash(trapdoor, nullifier)` where `trapdoor` and `nullifier` are **user-generated secrets the AS never sees**. The user submits a commitment; the AS inserts the commitment without learning the preimage. Bolyra's `credCommitment` has no analogous agent-side entropy. This is a structural gap, not a parameter choice.

**In-threat-model?** No. The construction must address this. Minimum fix: add an agent-held blinding secret `r` to credCommitment — `Poseidon6(modelHash, Ax, Ay, permBitmask, expiry, r)` — where `r` is generated by the agent and never transmitted to the AS. The agent commits to `r` at enrollment; the AS inserts the commitment blind. Without this, the unlinkability claim fails against the enrollment AS.

---

### Attack 2: Forward Evaluation Disambiguation by Colluding AS+RS

**Attack:** Even granting (incorrectly, per Attack 1) that the AS doesn't know `credCommitment` a priori, the colluding AS+RS attack does not require Poseidon inversion. The construction's §4 step 5 says:

> "To link this to RS-B's `scopedNullifier_B`, the adversary must invert Poseidon to recover `credCommitment` from the known `(scopeId_A, scopedNullifier_A)` pair — which contradicts PRF security."

This conflates one-wayness with the actual attack surface. The adversary's real strategy is **forward enumeration over the known enrollment set**:

1. RS-A (colluding) shares `scopedNullifier_A = Poseidon2(scopeId_A, credCommitment_target)` with the AS.
2. The AS holds enrollment records for all N agents: `{credCommitment_1, ..., credCommitment_N}`.
3. For each `credCommitment_i`, compute `candidate = Poseidon2(scopeId_A, credCommitment_i)`.
4. Match: `candidate == scopedNullifier_A` identifies which enrolled agent presented to RS-A.
5. Now compute `Poseidon2(scopeId_B, credCommitment_target)` for any other scope. Linkage complete.

This is O(N) forward Poseidon evaluations. Poseidon2 is cheap: ~300 constraints / ~0.1ms per evaluation. For N = 1,000 agents, this is 100ms. For N = 1,000,000 it's ~100s — still feasible for offline analysis. The threat model does not specify a minimum anonymity set size, so this attack is in scope for small-to-medium deployments.

**Why it fails only partially:** For the §7.1 scenario with 13M enrolled agents, exhaustive enumeration becomes expensive (~364 CPU-hours per RS correlation query). But: (a) the AS can precompute a lookup table at enrollment time in O(N) offline work; (b) with 13M agents, a lookup table of `(scopedNullifier_i → credCommitment_i)` per RS takes ~400MB RAM — trivially feasible for a federal credit union's infrastructure.

The construction must state an explicit anonymity set lower bound and prove that the attack cost exceeds the adversary's computational budget. Neither appears in the current text.

**In-threat-model?** No. The §3 adversary capability list does not bound N, and the reduction incorrectly characterizes the attack as requiring Poseidon inversion. Construction must add: minimum anonymity set requirement, precomputation model in the game definition, and offline lookup table as an explicit adversary strategy.

---

### Attack 3: IND-UNL-AS Game Definition Does Not Model Enrollment Oracle

**Attack:** The game (§3) is structurally incorrect for an AS-as-enrollment-authority adversary.

The game as written:
1. **Challenger** runs setup and generates the Merkle tree with `credCommitment_0, credCommitment_1`.
2. **Adversary** receives proofs and guesses the challenge bit.

The adversary A is identified as the AS. But the game never gives A the enrollment data — specifically, A never receives `credCommitment_0` or `credCommitment_1`. In a real deployment, the AS **performs enrollment**: it receives the operator pubkey and policy parameters, computes the credCommitment, and inserts the leaf. The game challenger should not be a separate entity from A in this scenario.

A correctly formulated game must either:

**(a) Give A an enrollment oracle** at setup time, which returns `credCommitment_i` for each agent (since the AS computes these), and show A still cannot win; or

**(b) Separate the enrollment authority from the AS** — e.g., a trusted third party inserts blinded commitments that neither A nor the agent can trace — and define the AS as only observing on-chain state post-enrollment.

The current game proves unlinkability against an adversary who *doesn't know* the enrolled credCommitments. This is a weaker adversary than the AS described in the same §3 threat model. The game and the threat model are in direct contradiction.

**Formal statement of the gap:** Let `IND-UNL-AS^{enroll}` be the game where A additionally receives an enrollment oracle `O_enroll(params) → credCommitment`. The construction claims security for an AS with enrollment authority but proves security only for the weaker game without `O_enroll`. The reduction sketch (§4) is a proof of the wrong theorem.

**In-threat-model?** No. The game definition must be corrected to match the threat model. The claim "for all PPT adversaries A, Adv^{IND-UNL-AS}_A(λ) ≤ ..." is proved for the wrong A.

---

### Attack 4: scopeBlinder Malleability — No Freshness Enforcement in Circuit

**Attack:** The `blindedScopeTag` is designed to ensure per-presentation unlinkability to the same RS:

```
blindedScopeTag = Poseidon2(scopeCommitment, scopeBlinder)
```

where `scopeBlinder` is a private circuit input. The construction relies on `scopeBlinder` being fresh random per presentation to achieve this (§2, constraint 9; §4 side-channel table). But the circuit contains **no constraint enforcing that `scopeBlinder` is not a constant**. Any field element satisfies the circuit.

An adversary controlling the agent process (e.g., a compromised agent runtime, a malicious agent library, or an agent running in a coerced environment) can set `scopeBlinder = 0` for all presentations. Then:

```
blindedScopeTag = Poseidon2(scopeCommitment, 0)
```

is deterministic across all sessions to the same RS with the same permissions. The RS-A can now link all proofs from this agent across sessions — the per-presentation unlinkability guarantee collapses to per-session linkability.

More subtly: `scopeCommitment = Poseidon2(permissionBitmask, credCommitment)` (§2, constraint 9). If two agents have the same `permissionBitmask` and an adversarial RS wants to distinguish them, a fixed `scopeBlinder = 0` makes `blindedScopeTag` a deterministic function of `credCommitment` — collapsing to the Attack 1 scenario.

**Comparison to nonce binding in HumanUniqueness:** The `sessionNonce` in `HumanUniqueness` is generated by the RS and bound as a public input, making replay of old proofs impossible. `scopeBlinder` has no analogous external commitment — it is entirely agent-supplied, making freshness unenforceable by the RS verifier.

**Fix:** RS must supply a fresh challenge value (like `sessionNonce`) that is incorporated into `blindedScopeTag` as a public input, e.g.:

```
blindedScopeTag = Poseidon2(scopeCommitment, RS_challenge)
```

where `RS_challenge` is a public input from the RS. This transforms the blinder from agent-chosen to RS-controlled, enforcing freshness. The current design conflates zero-knowledge (the blinder is hidden from AS) with freshness (the blinder is actually random), which are independent properties.

**In-threat-model?** Partially. The construction claims per-presentation unlinkability as a property but doesn't characterize the adversary controlling the agent process. Against an honest-but-curious agent, the attack doesn't arise. Against a malicious agent runtime (which is the relevant threat for enterprise deployments where the agent is third-party software), the circuit provides no protection. The side-channel table (§4) lists nonce freshness as mitigated but the mitigation only covers `sessionNonce` — `scopeBlinder` is not addressed.

---

**Summary table**

| Attack | Severity | In-threat-model? | Root cause |
|---|---|---|---|
| AS Enrollment Oracle | Critical | No | credCommitment has no agent secret |
| Forward Enumeration | High | No | Lookup table ≠ PRF inversion |
| Game Definition Mismatch | High | No | Challenger ≠ AS in current game |
| scopeBlinder Malleability | Medium | Partial | No freshness enforcement in circuit |

The first three attacks share a single root cause: the construction treats `credCommitment` as a secret from the AS, but the AS computes it. Fix that structural gap — add agent-held entropy to the commitment scheme, analogous to Semaphore's trapdoor — and Attacks 1–3 become substantially harder to execute (contingent on the enrollment blind commitment being correctly specified). Attack 4 requires an independent fix regardless.


## Persona: cu\_ciso

### Attack 1: The Distributed Audit-Trail Shredder

- **Attack:** NCUA Part 748, Appendix A requires me to maintain audit logs of access to member financial systems — who accessed what, when, with what authority. Section 4 of this construction explicitly removes the AS from the authentication hot path: "The AS sees only: Merkle root read events — No nullifiers, no scope IDs, no proofs." My examiner will ask for the auth event log. I hand them "batched Merkle root reads, shared across all 13M agents." That's not a log — that's a blank page. The actual audit trail (nullifiers, timestamps, scope IDs) is sharded across Amazon, Costco, and a local pharmacy's nullifier stores in Section 4 ("Each RS maintains its own nullifier set"). I do not control those systems. I cannot subpoena them in 72 hours when NCUA calls an incident. The FFIEC CAT Cybersecurity domain explicitly requires centralized logging for covered financial institutions.

- **Why it works / fails:** The construction achieves its cryptographic privacy claim precisely by destroying centralized observability. That tradeoff is fine for a consumer privacy product. It is fatal for a regulated depository institution. The construction has no answer to this — Section 2's "verification architecture" diagram labels the AS observing "Zero per-agent, per-merchant data" as a feature, without acknowledging it is a NCUA Part 748 examination finding waiting to happen.

- **In-threat-model?** No — the construction must address how a regulated CU operator reconstructs a legally-defensible audit trail without reintroducing the AS correlation vector it just eliminated.

---

### Attack 2: Credential Revocation Window Is a Financial Crime Exposure

- **Attack:** Section 7 describes enrollment ("one-time") but contains zero revocation mechanism. Walk me through this: a member's device is stolen at 2pm. Fraud detection flags it at 2:07pm. I call my ops team to revoke the agent credential. They update the Merkle tree, which changes `agentMerkleRoot`. But Section 4 specifies RSes check against a "30-entry circular buffer" of historical roots, with batched reads "every 30s." If the buffer holds 30 roots at 30-second intervals, a freshly-revoked credential remains cryptographically valid against stale roots in that buffer for up to 15 minutes post-revocation — during which the stolen device can continue authorizing `FINANCIAL_SMALL` transactions at any RS. Under GLBA Safeguards Rule 16 CFR §314.4(h), I must have "a process for implementing timely actions in response to identified events." Fifteen minutes of post-revocation financial access is not timely. My core processor revokes a debit card in under 30 seconds.

- **Why it works / fails:** The construction's performance optimization (batched root reads to prevent timing side-channels, per Section 4's side-channel mitigation table) directly conflicts with revocation latency requirements. There is no mechanism for a CU AS to push an emergency revocation signal to RSes without reintroducing the AS visibility the construction eliminated. The construction does not acknowledge this tension.

- **In-threat-model?** No — the construction must define a revocation path with a maximum propagation SLA that a regulated institution can commit to in its incident response plan. Nullifier-based replay protection is scoped per-RS and does nothing for cross-RS emergency revocation.

---

### Attack 3: RS Nullifier Stores Are Unaudited Fourth Parties

- **Attack:** The construction places replay-protection state at the RS: "Each RS maintains its own nullifier set." In the credit-union deployment scenario, my member's agent interacts with Amazon (RS-A), Costco (RS-B), and a local pharmacy (RS-C). My NCUA Vendor Management Policy requires me to assess, onboard, and periodically audit every entity that processes member authentication tokens. Amazon and Costco are not my vendors — they are counterparties. I have no contract with them covering SOC 2 Type II obligations, data retention of nullifier sets, or breach notification timelines. NCUA examiner questionnaires under the Third-Party Relationships guidance (Letter 01-CU-20, updated in the FFIEC guidance) will ask me to enumerate every entity holding member access artifacts. "RS-local nullifier storage distributed across uncounted third parties" is not an enumerable vendor list. I cannot pass that examination question.

- **Why it works / fails:** The construction offloads a critical security control (replay prevention) to entities outside the CU's contractual reach. The security argument in Section 4 assumes RSes correctly implement nullifier checking — but there is no enforcement mechanism, no audit right, and no breach notification path for the CU if an RS fails to store or check nullifiers correctly. A misconfigured RS nullifier store enables replay attacks against member credentials, and the CU has no visibility into it.

- **In-threat-model?** No — the construction treats RSes as trusted correct implementations. For a regulated CU, correctness of RS nullifier stores is a vendor audit requirement, not an assumption. The construction must specify a minimum RS compliance profile and how the CU enforces it.

---

### Attack 4: Private Input Key Custody Is Completely Unspecified

- **Attack:** I am running Table 2 of the FFIEC CAT against this construction. Under "Cyber Risk Management and Oversight" → "Cybersecurity Controls" → "Access and Data Management," I need to know where the agent's private credential material lives. The `ScopedAgentAuth` circuit takes as private inputs: `modelHash`, `operatorPubkeyAx/Ay`, `operatorPubkeyS` (EdDSA private key), `sigR8x`, `sigR8y`, `sigS`, and 20 Merkle sibling hashes. Section 7 says "Agent generates `ScopedAgentAuth` proof" but says nothing about where these private inputs are stored between proof generations. Is this a browser wallet? A mobile enclave? A custodial key service? The construction handwaves this entirely. If the operator EdDSA private key lives in a browser, I've handed a `FINANCIAL_SMALL` signing capability to every XSS vulnerability on the member's device. If it lives in a custodial service operated by Bolyra, I now have a critical vendor with privileged access to member financial credentials — which requires a full NCUA third-party due diligence cycle, contractual key management obligations, and a right to examine.

- **Why it works / fails:** The cryptographic construction is sound assuming key material is secure. But "assuming key material is secure" is precisely what a security program exists to operationalize. The construction scores a 9 on cryptographic elegance and a 0 on key lifecycle management. GLBA Safeguards 16 CFR §314.4(f) requires me to oversee service provider arrangements involving member data. The private inputs to this circuit are member data.

- **In-threat-model?** No — key custody is explicitly out of scope in the construction ("standard network assumption; composable with TLS + onion routing if needed"). For a CU deploying this in production, key custody is the threat model. The construction must specify a key management architecture with defined custody boundaries, HSM or TEE requirements, and a recoverable-but-non-exportable secret model before a regulated institution can evaluate it.


## Persona: rfc7662_advocate

---

### Attack 1: Preimage Table Inversion — The AS Knows Every Leaf

**Attack:**
The construction's PRF security argument (§4, reduction step 5) claims:
> "Recovering `credCommitment` from `scopedNullifier_A` requires inverting Poseidon — infeasible under PRF assumption."

This is only true if `credCommitment` is **unknown** to the adversary. But the adversarial AS in the threat model (§3) is explicitly the **enrollment authority and Merkle tree operator**. It enrolled every agent. It therefore has a complete roster:

```
{ credCommitment_j } for all j ∈ enrolled agents
```

The `scopeId` values are derived from public RS domains: `Poseidon("amazon.com")` is fully predictable. When the colluding RS-A hands the AS `scopedNullifier_A`, the AS simply runs:

```
for each credCommitment_j in enrollment_roster:
    if Poseidon2(Poseidon("amazon.com"), credCommitment_j) == scopedNullifier_A:
        return j  // agent identified
```

This is a **dictionary lookup against a known-size set**, not a Poseidon inversion. With 13M enrolled agents the AS must evaluate 13M Poseidon calls — roughly 130ms on modern hardware at ~100ns/hash. Cross-scope linkability is then trivial: repeat the lookup for `scopedNullifier_B` at Costco.

**Why it works:** The PRF assumption treats `credCommitment` as an adversarially unknown key. The construction's own threat model violates this assumption — the AS is the keyholder for every enrolled credential.

**In-threat-model?** Yes. The adversary is defined as controlling the enrollment authority. The construction must address this. Candidate mitigations (none of which are currently in the spec): (a) enroll leaf as a *commitment* to a user-chosen secret the AS never sees (Semaphore-style), so the AS knows a commitment but not the preimage; (b) use a blind enrollment protocol. Neither is present in §2.

---

### Attack 2: The IND-UNL-AS Game Is Trivially Breakable by Its Own Adversary Definition

**Attack:**
Game `IND-UNL-AS(λ)` in §3 sets up as follows:

> "Adversary A selects two distinct scopeIds (s₀, s₁)... A receives `{(π, scopedNullifier, blindedScopeTag)}` from one of two worlds (same agent or different agents)."

The game gives A the adversarial AS role. Per the threat model, A controls the Merkle tree and therefore knows `{credCommitment₀, credCommitment₁}`. The distinguishing strategy is trivially:

```
A receives scopedNullifier_s0, scopedNullifier_s1.
Compute: 
  candidate_0_s0 = Poseidon2(s₀, credCommitment₀)
  candidate_1_s0 = Poseidon2(s₀, credCommitment₁)

if scopedNullifier_s0 == candidate_0_s0 and scopedNullifier_s1 == candidate_0_s0:
    # wait, that can't be right — same agent, same scope gives same nullifier
```

More precisely, A evaluates `Poseidon2(s₀, credCommitment₀)` and checks which enrolled agent produced `scopedNullifier_s0`. It then checks `Poseidon2(s₁, credCommitment_??)` and sees whether the same agent produced `scopedNullifier_s1`. The advantage is 1 − negl, not negl.

The security theorem's conclusion (`Adv ≤ Adv^PRF + Adv^KS`) is vacuously stated without accounting for the adversary's a priori knowledge of all PRF keys. The reduction in §4 never constructs a PRF challenger that the AS-adversary can't trivially win because there is no PRF game where the key is unknown — the reduction hands A the key at enrollment time.

**Why it works:** The reduction must embed the PRF challenge *inside* the credential commitment in a way that hides it from the enrollment authority. No such mechanism exists in the current construction.

**In-threat-model?** Yes. This invalidates the formal claim in §3–§4 as stated. The game needs to be redesigned with a blind-enrollment setup step before the PRF reduction is sound.

---

### Attack 3: BBS+ Anonymous Credentials Already Close This Gap Without ZK Circuits

**Attack (from my RFC toolbox):**
Section 8's baseline comparison dismisses anonymous credentials by citing the AS-on-hot-path structural impossibility. But BBS+ signature-based anonymous credentials (already deployed in the W3C VC Data Integrity spec, and the underlying primitive in IETF `draft-irtf-cfrg-bbs-signatures`) provide **unlinkable presentations from a single issuance**:

1. AS issues **one** BBS+ credential to the agent at enrollment time. AS sees this once: `{agent_id, permissions, expiry}`.
2. Agent generates a **derived presentation** (a BBS+ proof-of-knowledge of the signature) for each RS. Each presentation is cryptographically unlinkable to every other — including by the original signer (the AS).
3. Each RS verifies the presentation against the AS's public key. No per-authentication call to the AS.
4. Audience-binding via RFC 8707 + DPoP nonce prevents replay. PPIDs prevent RS-to-RS subject correlation.

The construction's §8 table entry "AS sees token issuance: Yes" for the baseline is accurate only for per-authentication token introspection (RFC 7662 in its original form). BBS+ presentations eliminate this. The AS sees exactly one event per credential lifetime — the initial issuance — which matches what `ScopedAgentAuth` achieves at enrollment.

The remaining claimed advantage of `ScopedAgentAuth` over BBS+:
- *Nullifier sybil detection* — BBS+ has no built-in nullifier; a ZK-based nullifier scheme (Coconut, Zk-creds) must be layered on top. True — but this is a well-studied addition, not an impossibility.
- *Formal IND-UNL-AS game* — but as shown in Attacks 1–2, this game as stated is unsound.
- *AS + RS colluding* — under BBS+, the AS cannot link presentations because the presentation is a zero-knowledge proof-of-knowledge of its own signature. The AS is the PRF key issuer but cannot invert presentations. This is stronger than what `ScopedAgentAuth` achieves given Attack 1.

**Why it (partially) fails against the construction:** BBS+ still requires a signing oracle (AS) to issue credentials; the Bolyra construction moves that to a self-sovereign enrollment Merkle tree. But the construction does NOT prevent the AS from knowing credCommitments (Attack 1), so the structural difference narrows significantly. The construction must demonstrate a property BBS+ cannot achieve.

**In-threat-model?** Partially. The construction does not engage with BBS+ or Coconut in §8. Section 8's "structural impossibility" claim is overstated.

---

### Attack 4: `requiredScopeMask` Public Output Enables Cohort-Narrowing Across RSes

**Attack:**
The circuit's public output includes `requiredScopeMask` (64-bit, §2 public outputs table — note: this is a public *input* to the circuit, but it appears in the proof transcript visible to the RS and, if the RS cooperates, to the colluding AS). Additionally, the `agentMerkleRoot` is a public output present in every proof.

Consider the following: The AS colludes with RS-A (Amazon) and RS-B (Costco). Both RSes receive ZK proofs. Each proof's public signals include:
- `agentMerkleRoot` — identical for all proofs in the same time window (shared across all 13M agents)
- `requiredScopeMask` — specific to the RS's policy: Amazon might require `0b00000100` (FINANCIAL_SMALL); a healthcare portal might require `0b10000000` (ACCESS_PII)
- `currentTimestamp` — RS-supplied but reveals approximate authentication time

If the AS colludes with two RSes, it receives two sets of public signals. While nullifiers are unlinkable (modulo Attack 1), the `requiredScopeMask` values combined with authentication timestamps create a **cohort-narrowing side-channel**: agents with `FINANCIAL_UNLIMITED` (bit 4 set) are a small subset. Agents who authenticated to Amazon at 14:32 with bitmask `0b00010100` AND to a healthcare portal at 14:35 with bitmask `0b10010100` represent a highly distinctive fingerprint.

The construction's §4 side-channel mitigations table covers timing of root queries, proof size, and nonce freshness. It does not address `requiredScopeMask` or `currentTimestamp` as public-output fingerprints available to colluding RSes.

Under RFC 9449 DPoP + PPID, the AS sees these same attributes — no advantage gained. But Bolyra claims the AS does NOT see these values. The problem is that the RS does, and a colluding RS shares them. The anonymity set for `requiredScopeMask=0b00011100` (FINANCIAL_MEDIUM) may be far smaller than the full enrolled population.

**Why it fails as a complete break:** It does not recover `credCommitment` or link nullifiers across scopes without Attack 1. It is a probabilistic narrowing, not a cryptographic break.

**In-threat-model?** Yes — the threat model explicitly includes "a strict subset of RSes" colluding with the AS. The construction must either (a) treat `requiredScopeMask` as a private input and verify it inside the circuit against a commitment, publishing only a boolean "requirements met" output, or (b) explicitly bound the anonymity set size as a function of bitmask rarity and acknowledge it as an accepted residual.


## Persona: spiffe_engineer

---

### Attack 1: The Enrollment Authority Already Holds `credCommitment` — The IND-UNL-AS Game Is Mis-specified

- **Attack:**
  The AS is defined in the threat model (§3) as "the entity controlling the agent Merkle tree." This is the enrollment authority. During enrollment, the AS (or the operator working with the AS) computes `credCommitment = Poseidon5(modelHash, Ax, Ay, permBitmask, expiry)` and inserts it into the tree. The AS retains this value — it computed it. The IND-UNL-AS game (§3) sets up the tree with `(credCommitment₀, credCommitment₁)` but never explicitly withholds these values from adversary A. In the game's challenger/adversary split this ambiguity is hidden; in the actual deployment the split does not exist.

  With `credCommitment_i` known for all `N` enrolled agents, and `scopedNullifier_B = Poseidon2(scopeId_B, credCommitment_?)` obtained from a colluding RS-B, the AS runs:

  ```
  for each enrolled agent i:
      if Poseidon2(scopeId_B, credCommitment_i) == scopedNullifier_B:
          agent i authenticated to RS-B
  ```

  No Poseidon inversion is required. The reduction in §4 ("AS + RS-A collusion requires inverting Poseidon to recover `credCommitment` from `(scopeId_A, nullifier_A)`") is only valid if the AS does not already hold `credCommitment`. The AS does. `credCommitment` is NOT a secret from the AS — it is a public leaf in a Merkle tree the AS controls.

  Compounding this: `scopeId = Poseidon("amazon.com")` is precomputable from the RS's domain name. If the AS maintains a directory of registered RS domains (standard in enterprise federation), it can build a complete oracle `nullifier(agent_i, RS_j) = Poseidon2(Poseidon(RS_j.domain), credCommitment_i)` for every `(i,j)` pair before observing a single proof. Privacy is fully broken at the moment any RS shares a nullifier with the AS.

- **Why it works:** The construction's security argument in §4 (colluding RS resistance) rests on the claim that recovering `credCommitment` from `(scopeId_A, nullifier_A)` requires inverting a PRF. This is true for a third party. It is false for the enrollment authority, which is definitionally the same entity as the AS in the threat model.

- **In-threat-model?** **No — construction must address.** The IND-UNL-AS game must be revised to either (a) treat `credCommitment` as a secret the AS cannot access (which requires a separate key-generation ceremony outside AS control), or (b) add a blinding layer so the AS inserts a commitment `Poseidon(credCommitment, enrollmentSecret)` without learning `credCommitment` itself. Neither is currently specified.

---

### Attack 2: SPIFFE JWT SVIDs Already Achieve Structural AS-Removal — The "Structural Impossibility" Claim Is Scoped Wrong

- **Attack:**
  §8 "Why the baseline cannot match" compares against OAuth 2.0 + RFC 8707 + DPoP + BBS+, correctly noting that OAuth requires the AS on every token issuance path. The comparison table asserts "AS sees token issuance: Yes" for the baseline. This is true for OAuth. It is false for SPIFFE JWT SVIDs.

  In a SPIFFE/SPIRE deployment:
  - The SPIRE agent runs on the workload node and issues JWT SVIDs locally, without contacting the SPIRE server at issuance time.
  - The SPIRE server (the analog of the AS) distributed key material during attestation but is not in the authentication hot path.
  - When workload W presents a JWT SVID to peer service RS-A, the SPIRE server sees nothing. The RS verifies against a cached JWKS URI.
  - The SPIRE server never observes `{workload_id, target=RS-A, scope, timestamp}` — exactly the property the construction claims to achieve.

  The attack prompt "Your 'mutual ZK handshake' is just mTLS with SVIDs. What's new?" lands precisely here. The construction's §8 row "AS sees token issuance: No (ScopedAgentAuth)" is not a differentiation from SPIFFE — it is already SPIFFE's baseline behavior.

  The genuine delta the construction has over SPIFFE JWT SVIDs is narrower: (a) cryptographic anonymity within the enrolled agent set (SPIFFE JWT SVIDs carry a stable SPIFFE ID that identifies the workload across all RSes — exactly the cross-RS linkability the construction eliminates), and (b) ZK enforcement of cumulative-bit permission narrowing without AS involvement. These are real contributions, but the construction oversells "AS removal" as if it is novel over all existing workload identity systems, when it is only novel over OAuth.

- **Why it fails partially:** The construction survives this attack if it re-scopes the comparison: SPIFFE gives AS-removal but NOT agent anonymity — the SPIFFE ID is stable and linkable across RSes. The Bolyra `scopedNullifier` is the first primitive that provides both AS-removal AND cross-RS unlinkability. The construction should say this explicitly rather than comparing only to OAuth.

- **In-threat-model?** **Partially yes, but requires a corrected claim.** The §8 table should add a SPIFFE/JWT SVID row. The construction survives against SPIFFE only on the anonymity dimension; it should not claim AS-removal as its headline novelty.

---

### Attack 3: Root History Buffer as an Epoch Correlation Oracle Under Active AS

- **Attack:**
  The construction mitigates timing side-channels by having the RS batch root-freshness checks "on a fixed schedule (e.g., every 30s)" (§4 side-channel table). The assumption is that many agents share the same root read, so any individual read is unlinkable to a specific authentication event.

  A SPIFFE engineer deploying at Fortune 500 scale recognizes that the AS (Merkle tree operator) controls when the root updates. Consider this active attack:

  1. AS updates the Merkle root at time `T_i`, producing root `R_i`.
  2. AS immediately adds agent `alice` to the tree, producing root `R_{i+1}`.
  3. RS-A reads `R_i` (cached for ≤ 30s) and RS-B reads `R_{i+1}` (after the add).
  4. Any proof submitted to RS-A that is valid under `R_i` but not `R_{i+1}` narrows the set of possible agents to those enrolled before `T_i`. Any proof valid under `R_{i+1}` narrows to the set enrolled by `T_{i+1}`.

  More precisely: the on-chain root history buffer is a 30-entry circular buffer (§5). Each root version corresponds to a known epoch of enrolled agents. If the AS controls both enrollment timing and root rotation, it can shrink the anonymity set to 1 by performing targeted enrollment events timed to isolate specific agents into distinct root epochs. This turns the Merkle root version into a precision de-anonymization handle under an active AS, even without knowing `credCommitment` values.

  The batching mitigation only works if the AS cannot correlate root epoch to agent membership changes — but the AS controls both.

- **Why it works:** The construction's §4 says "Timing of root queries — RS batches root freshness checks on a fixed schedule." This addresses a passive timing observer. It does not address an active AS that orchestrates enrollment events to shrink anonymity sets epoch by epoch. SPIRE's node attestation model has an analogous concern (SVIDs rotate on a fixed schedule regardless of workload activity) and handles it by decoupling certificate rotation from workload activity at the node level. Bolyra's Merkle root update is coupled to enrollment, which the AS controls.

- **In-threat-model?** **No — construction must address.** The threat model (§3) lists "Read access to all on-chain state" and "Timing observations of on-chain root queries" as adversary capabilities. Controlling root update timing is an implicit capability of "controlling the agent Merkle tree." The construction should either (a) require root updates on a fixed clock independent of enrollment events, or (b) formalize the anonymity set size floor (minimum `k` agents per epoch) as a deployment parameter and add it to the security argument.

---

### Attack 4: Wrong Layer — SPIFFE ZK Attestor + WIMSE Token Extension Achieves This Without a New Protocol

- **Attack (architectural):**
  SPIFFE's attestor plugin interface lets operators register custom attestors that produce SVIDs based on arbitrary attestation evidence. WIMSE `draft-ietf-wimse-arch` is standardizing workload-to-workload token exchange with selective disclosure and audience binding. The construction's core contribution — a ZK proof that an agent holds a credential with certain permissions, without revealing which credential — could be delivered as:

  1. A **SPIRE ZK attestor** that attests `modelHash` and `operatorPubkey` using a ZK proof, producing an SVID backed by a Groth16/PLONK proof of enrollment.
  2. A **WIMSE token extension** carrying a `scopedNullifier` claim that replaces the stable SPIFFE ID for cross-RS unlinkability.
  3. Standard SPIRE node attestation (TPM, AWS IMDSv2, k8s pod identity) for binding the ZK credential to actual hardware/infrastructure.

  The construction instead introduces: a new Merkle tree format, a new wire format (`blindedScopeTag`, `scopedNullifier` as Poseidon field elements), new verifier contracts (Solidity), and a new trusted setup (`pot16.ptau`). Every RS must deploy a Groth16/PLONK verifier. Every deployment operator must adopt Bolyra's enrollment flow rather than extending existing SPIRE servers they already run.

  In the cross-credit-union scenario (§7), Amazon and Costco would need to run Bolyra verifier contracts. In a SPIFFE-augmented design, they would run the existing SPIRE agent with a new SVID verifier plugin — fitting into their existing service mesh and mTLS infrastructure without new smart contracts.

- **Why it works:** This is not a cryptographic break but an architectural falsification of the novelty claim. The construction claims a new protocol is necessary. The SPIFFE engineer's position is that the cryptographic primitive (scoped ZK nullifier) is separable from the protocol and could be contributed to WIMSE/SPIFFE rather than deployed as a parallel identity layer. The adoption barrier of requiring Solidity verifier contracts is a real deployment blocker that the construction does not address.

- **In-threat-model?** **No (not a cryptographic attack), but the construction must address the interoperability gap.** The construction should either (a) provide a SPIFFE/WIMSE compatibility layer — e.g., wrapping `scopedNullifier` in a WIMSE token claim and publishing a SPIRE attestor plugin — or (b) explicitly justify why a new root of trust is required rather than a WIMSE extension. The §8 comparison table omits SPIFFE entirely; this is the table entry that matters most to enterprise deployers.
