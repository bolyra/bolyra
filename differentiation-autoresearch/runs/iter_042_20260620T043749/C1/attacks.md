# Tier 3 Adversarial — C1 Selective scope proof

## Persona: auth0_pm

---

### Attack 1: The Latency Gap Kills Every Integration Before It Starts

- **Attack:** Section 6 admits snarkjs in browser/Node takes 3–5s. That's the integration path any operator actually uses before they've shipped native binaries. WorkOS MCP auth issues a signed token in under 100ms — a developer building an agent gateway benchmarks both on day one and the Bolyra path is 30–50× slower on the happy path, not the edge case. The "rapidsnark <500ms" claim requires a pre-compiled C++ native binary deployed alongside every agent runtime. That's not a library you npm-install; that's an ops dependency that needs a sidecar, a build step, and a deploy pipeline. Section 2 says "the agent generates a Groth16 proof using private credential data" as if this is a one-liner. It is not.

- **Why it works:** The construction provides no onboarding path from "developer has credentials" to "agent generates a sub-500ms proof in production." The 192-byte proof size is irrelevant if the time-to-proof makes the agent unusable in latency-sensitive API chains. SLA-sensitive operators (financial services, especially) have p99 budgets. A 500ms proving step in a 5-hop agent chain blows the entire API timeout.

- **In-threat-model?** No. The construction never addresses the deployment model for the prover binary, the cold-start cost of loading proving keys, or how the 3–5s path is acceptable during the early adoption phase before rapidsnark is packaged. **Construction must address: what is the proving latency on the actual integration path (snarkjs + Node), and is it within operator SLA budgets?**

---

### Attack 2: The Adversarial-AS Threat Model Is a Fiction in Every Target Account

- **Attack:** Section 3 defines the adversary as controlling the AS — "A malicious AS cannot forge a credential commitment." Section 7 says NFCU benefits because "if the AS is compromised, it can silently escalate an agent's scope." NFCU *is* the AS. They run their own identity infrastructure or they buy it from us (Auth0) under a BAA. The adversarial-AS threat is not in NFCU's threat model — it's in Bolyra's marketing deck. The security comparison in Section 8 ("RS trusts the AS's signed assertion" vs. "RS trusts math") only matters if the AS and RS have misaligned interests. In every enterprise deployment I have ever seen, the AS and RS are both owned by the same organization. They share a trust boundary by design.

- **Why it works:** The entire Section 8 "core impossibility" argument — that OAuth introspection is an assertion protocol and therefore fundamentally weaker — depends on the AS being adversarial. Remove that assumption (as every real enterprise deployment does) and OAuth introspection with short-lived tokens and DPoP binding is *equally strong* against network attackers, requires zero new infrastructure, and ships today with SOC 2 Type II coverage. The construction's claimed gap collapses to: "what if your AS vendor is evil?" That's a vendor-selection problem, not a cryptographic one.

- **In-threat-model?** No. The construction positions adversarial-AS soundness as the primary differentiator but provides no evidence that any credit union or fintech procurement team has ever cited "our AS might lie about scope" as a threat they are buying against. **Construction must address: for buyers who control their own AS, what is the residual value proposition?**

---

### Attack 3: Onboarding Funnel Collapses at Step One

- **Attack:** Section 7's "Bolyra path" describes the steady-state flow but skips the prerequisite stack: deploy a Solidity registry contract to Base Sepolia (or mainnet — cost?), build and maintain a Merkle tree of enrolled agent credential commitments, generate EdDSA operator keypairs and sign each credential, distribute proving keys (`.zkey` artifacts from a trusted setup ceremony), configure the on-chain root history buffer (30-entry circular per spec §3.1), and get the rapidsnark binary built for your target platform. Auth0 MCP auth is: create an application, paste a client ID, get a token. WorkOS is the same. Cloudflare Access is `wrangler deploy`. The Bolyra integration surface touches four separate infrastructure layers before the first proof is generated.

- **Why it works:** Section 5's "primitive mapping" table is 8 rows of circuit components that all have to work in concert before the construction produces a single verifiable proof. Any one of these failing — wrong `agentMerkleRoot`, stale on-chain root, expired `.zkey`, wrong circuit build — produces an opaque verification failure with no error signal to the operator. The construction has no equivalent of a 401 response with a `WWW-Authenticate` header pointing at what went wrong.

- **In-threat-model?** No — the construction does not model integration failure modes or operator debug paths at all. **Construction must address: what is the minimum surface area for a working integration, and what does a developer do when `Groth16.Verify` returns false?**

---

### Attack 4: The BBS+ Comparison Is Strawmanned and SD-JWT Closes the Gap

- **Attack:** Section 8 claims BBS+ "does not support bitwise AND over a multi-bit field, nor implication closure across hierarchical permission tiers." This is true of a naïve BBS+ implementation where each permission is a separate claim. But the comparison is against a constructed worst-case baseline. The actual alternative is: encode the entire 64-bit bitmask as a single integer claim in an SD-JWT VC (RFC draft-ietf-oauth-sd-jwt-vc), issue it with implication closure enforced *at issuance* by the AS, and let the RS check `(bitmask & requiredMask) == requiredMask` in 10 lines of code. The RS still doesn't learn the full bitmask because SD-JWT selective disclosure can expose only the bits the agent chooses to reveal — specifically, the agent can disclose only `"has_financial_small": true` as a derived claim, without disclosing the raw integer. Cross-RS unlinkability: use short-lived (~60s) tokens per RS. No correlation possible. No on-chain Merkle tree. No Circom.

- **Why it works:** The construction's Section 8 table lists "constant-size proof" as a differentiator because "BBS+ derived proof grows as O(|disclosed claims|)." But with a single integer claim, BBS+ produces a constant-size derived proof too — there is only one claim being disclosed. The "2^64 permission space where AS-side policy tables do not scale" scenario from the candidate's `gap_to_close` is a theoretical strawman; no real system enumerates 18 quintillion permissions. The practical comparison is 64 bits → one integer claim → SD-JWT VC → the proof path that ships in 6 months from any of the named incumbents.

- **In-threat-model?** No. The construction does not engage with SD-JWT VC as a comparator at all — only with RFC 7662 + BBS+ as separate components. **Construction must address: why is a single-integer-claim SD-JWT VC with short-lived per-RS tokens insufficient for the bill-pay RS scenario in Section 7, specifically under the non-adversarial-AS assumption?**


## Persona: cryptographer

Applied cryptographer. My bar: a formal game definition, a named assumption, and a reduction. I have read §§1–8. Here is what breaks.

---

### Attack 1: Trusted-Setup/Adversarial-AS Inconsistency — Subverted CRS Enables Proof Forgery

- **Attack:** The threat model (§3) simultaneously claims the adversary controls the AS and excludes the adversary from controlling the CRS ("trusted setup is assumed honest"). In practice these are not independent. A deployment where the organization that operates the AS also contributed to the Groth16 trusted-setup MPC — even one out of N participants — retains the toxic waste `(α, β, γ, δ)`. The holder can compute `A · (B + α) - α · β` (the forging equations) for any statement, including statements asserting invalid Merkle membership or a false scope predicate. The SSU reduction (§4) assumes A1 (knowledge soundness), but knowledge soundness breaks completely under a subverted CRS — there is no extractor when the CRS is malformed. Every SSU case (a), (b), (c) collapses simultaneously.

- **Why it survives / why it fails:** It fails. The SSU security claim is specifically motivated by the adversarial-AS scenario ("RS trusts math, not the AS"). But the math is only trustworthy if the CRS is independent of the AS operator. The construction states no constraint on who may participate in the trusted-setup ceremony, no requirement for MPC with at least one honest participant outside the AS operator's control, and no fallback to a transparent system. The adversarial-AS claim is vacuous when the AS operator holds even a single MPC contribution.

- **In-threat-model?** No — construction must address. Required fix: (a) mandate a ceremony with participants drawn from a set disjoint from AS operators, documenting the attestation chain; or (b) prove the PLONK alternative (§5: "OPTIONAL") with a universal SRS under a subverted-setup-resistant instantiation (Marlin/PLONK with KZG still has this issue; switch to an IOP-based system like STARKs if adversarial-CRS is a required threat). Alternatively, state explicitly that the adversarial-AS claim is only valid under honest-setup and adjust the claim to match.

---

### Attack 2: Blinded Nullifier Destroys Replay Detection — Missing State Specification

- **Attack:** The construction randomizes the nullifier output: `blindedNullifier = Poseidon2(Poseidon2(cc, sessionNonce), r)` where `r` is a fresh per-presentation `blindingNonce`. Two valid presentations of the same credential against the same RS challenge `sessionNonce` produce cryptographically distinct `blindedNullifier` values (under A5, PRF assumption). The RS's verification procedure (§2, Step 5) lists five checks: root match, nonce match, timestamp tolerance, `scopeSatisfied == 1`. It does not specify: "check `blindedNullifier` not in spent set" nor "mark `sessionNonce` as consumed." The `blindedNullifier` output, as blinded, **cannot function as a replay-prevention token** — the RS cannot build a nullifier set over randomized values and detect replay by a different blinding of the same credential.

- **Consequence:** An agent (or attacker who compromised the agent) can simultaneously generate two valid proofs `(π₁, pubSignals₁)` and `(π₂, pubSignals₂)` for the same `sessionNonce`, using different `blindingNonce` values. Both pass all five RS checks, producing distinct `blindedNullifier` outputs. The RS has no way to detect double-presentation within the same challenge window. This breaks double-spend prevention for any use case where the credential represents a one-time authorization (e.g., a bill-pay transaction in the NFCU scenario, §7).

- **In-threat-model?** No — construction must address. Options: (a) The RS must statelessly enforce that each issued `sessionNonce` is single-use and immediately consumed on first successful verification. This requires stateful RS-side nonce tracking — which must be specified explicitly as a protocol requirement (it is not). (b) Alternatively, output the **raw** (unblinded) nullifier `Poseidon2(cc, sessionNonce)` alongside the blinded form — allowing the RS to maintain a deterministic spent set — but this reintroduces the cross-RS linkability the blinding was designed to prevent. There is a real tension here between replay prevention and unlinkability; the construction has not resolved it.

---

### Attack 3: Delegation Chain Leaks Blinding Randomness to Delegatee — SP Game Breaks in Chained Context

- **Attack:** Section 2 ("Delegation chaining interop") states: *"The `blindingNonce` used in the initial proof is provided as a private input to the delegation circuit for this re-derivation."* This requires the delegatee (the party constructing the downstream `Delegation` circuit proof) to receive `blindingNonce`. With `blindingNonce` and the public `blindedScopeCommitment` in hand, the delegatee can compute the intermediate `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)`. Because `credentialCommitment` is a leaf in the public on-chain Merkle tree, the delegatee knows it. They now hold `scopeCommitment = Poseidon2(b, cc)` for known `cc`, unknown `b`. Over a 64-bit space with structured permission assignments (the cumulative encoding of §2 implies at most a few valid configurations per business role), an offline exhaustive search checking `Poseidon2(b_candidate, cc) == scopeCommitment` over the plausible bitmask set is computationally realistic — not a 2⁶⁴ brute force but a search over structured permission profiles.

- **Why the SP reduction fails here:** The SP security argument (§4, Step 2) relies on `blindedScopeCommitment` being PRF-indistinguishable because `blindingNonce` is uniform and private to the prover. In the delegation scenario, `blindingNonce` is no longer private — it is shared with the delegatee. The assumption "prover-local random field element" (§2) is violated. The PRF security argument (`Poseidon2(·, r)` is indistinguishable from random when `r` is uniform and secret) collapses when `r` is disclosed. The SP game does not model this context; it models single-agent single-proof scenarios. A full SP game for delegation chains would require `blindingNonce` to remain hidden from all downstream parties, which contradicts the stated delegation protocol.

- **In-threat-model?** No — construction must address. Correct fix: the delegation circuit must accept `scopeCommitment` (the unblinded intermediate) as private input, re-blind it with a **fresh** `blindingNonce` chosen by the delegatee, and produce its own `blindedScopeCommitment`. The on-chain registry then stores a chain of blinded commitments, each using independent randomness. The linking proof between the `SelectiveScopeProof`'s blinded output and the delegation circuit's re-blinded input must be done inside the circuit (verifying the unblinded link without revealing `blindingNonce` to any external party). The current spec conflates "chain-linking" with "randomness disclosure," which are separable.

---

### Attack 4: Adaptive Chosen-Mask Refusal Oracle — Full Bitmask Recovery in 64 Queries

- **Attack:** The SP game (§3) fixes a single `requiredScopeMask` and asks whether A can distinguish which of two agents (with different bitmasks `b₀ ≠ b₁`) produced the proof. In deployment, the RS controls `requiredScopeMask` as a free public input. A malicious RS runs the following adaptive strategy: issue 64 sequential challenges with `requiredScopeMask = 2^i` for `i = 0, …, 63` (one bit at a time). For each challenge, if the agent's bitmask has bit `i` set, the agent generates a valid proof (`scopeSatisfied = 1`). If bit `i` is NOT set, the agent **cannot generate a valid proof** — constraint G5 would be unsatisfied, and no valid witness exists. The agent must either (a) decline the request (observable refusal) or (b) abort. In either case, the RS observes a binary signal: *proof produced* vs. *no proof*. After 64 queries, the RS recovers the full bitmask exactly. Proof size being 192 bytes and ZK over the unrevealed bits is irrelevant — the information leaks through the liveness channel, not the proof content.

- **Why it fails against the construction:** The circuit and proof system are not at fault here — this is a protocol-level attack that the SP game does not model. The SP game gives A a single proof transcript, not adaptive oracle access conditioned on the agent's response behavior. The construction has no countermeasure: it does not specify that agents must generate "dummy" proofs for unsatisfied masks (which would be invalid/unsound), mandate constant-time refusal indistinguishable from normal latency, or require the agent to decline all probes with identical error messages regardless of which bit failed.

- **In-threat-model?** No — the threat model (§3) grants A observation of all prior transcripts but does not model the RS adaptively choosing `requiredScopeMask` across sessions. This is an active, adaptive attack that must be included. Required fix: restate the SP game as a **chosen-statement** game where A selects `requiredScopeMask` adaptively, then bound the leakage. The real bound is not `negl(λ)` — it is `min(|bitmask|, number_of_queries)` bits per session, which is information-theoretically unavoidable given the selective-disclosure model. The construction should acknowledge this and scope the privacy claim to single-presentation, single-required-mask contexts, or require the RS to commit to its required mask before the agent responds.


## Persona: cu_ciso

---

### Attack 1: The Audit Trail Paradox — Privacy Feature Is the Forensics Problem

- **Attack:** The construction's core selling point — AS-blind presentation, cross-RS unlinkability via fresh `blindingNonce`, blinded nullifiers that cannot be correlated across sessions — is also the thing that destroys my incident response capability. Suppose an AI agent commits fraud: it drains $47,000 from member accounts on a Tuesday. My NCUA examiner shows up Thursday. I need to answer: which agent, which permissions, which transactions, in what sequence? The `blindedNullifier` is, by design, a pseudorandom value with no stable identifier I can search. Each presentation to each RS produces a different public output. The AS was never contacted — so there's no AS-side log. Section 3 (Threat model) explicitly puts "observation of all prior proof transcripts" in the adversary's hands, but nowhere in the construction is there a mechanism for the CU's audit function to reconstruct the proof-to-transaction chain.

  NCUA Part 748 Appendix A (Guidelines for Safeguarding Member Information) §II.D requires maintaining records sufficient to detect, respond to, and reconstruct security incidents. FFIEC CAT Domain 3 (Cybersecurity Controls) requires audit logging with sufficient detail for forensic reconstruction. The construction satisfies neither.

- **Why it works / why it fails:** The construction doesn't address it at all. Section 7 (deployment scenario) claims a "compliance win" for GLBA data minimization but is silent on Part 748 audit requirements. Unlinkability across RSes means I cannot join proof transcripts to a single agent event sequence. The claim in §3 that the adversary can observe "all prior proof transcripts" is actually describing my auditor's position — and the adversary and auditor have the same information, which is nothing actionable.

- **In-threat-model?** No. The construction must address this. Options include: a per-RS audit log of `(sessionNonce, blindedNullifier, timestamp, requiredScopeMask)` combined with an offline CISO-held lookup table mapping `blindedNullifier → rawNullifier → credentialCommitment` (which re-introduces the AS or a privileged audit oracle); or a separate audit-proof output circuit that re-derives a CISO-scoped identifier without exposing it to the RS. Neither is specified.

---

### Attack 2: The Trusted Setup Is an Orphaned Vendor with No Contract

- **Attack:** Section 4 states "Groth16 CRS (trusted setup is assumed honest." Section 5 maps the proving system to `pot16.ptau` — a universal Powers-of-Tau file. My NCUA third-party risk examiner will ask: who ran that ceremony? Under what controls? Where's the SOC 2 report? What's the remediation plan if the toxic waste was not destroyed? FFIEC CAT Domain 2 (Threat Intelligence) and NCUA Part 748 §748.0(c) both require vendor risk assessments for any third party upon whom security controls depend. The Groth16 CRS is not a vendor I can put through my Vendor Management Policy — it has no legal entity, no SLA, no contact, no insurance, and no breach notification obligation.

  More concretely: if the `pot16.ptau` ceremony was compromised (a participant retained their randomness contribution), any party holding that toxic waste can forge a valid Groth16 proof for ANY statement — including a proof that a credential holds `FINANCIAL_UNLIMITED` (bit 4) when it does not. The construction's entire soundness argument in §4 (A1: Knowledge soundness of Groth16) collapses unconditionally. There is no runtime detection: a forged proof passes `Groth16.Verify` with probability 1.

- **Why it works / why it fails:** Section 2 (CLAUDE.md) notes "pot16.ptau (2^16 constraints) is the universal SRS for the project-specific Groth16 keys." The construction provides no information about the ceremony provenance, the number of participants, the audit record, or who is responsible for detecting a ceremony compromise. In a regulated environment, "assumed honest" is not a risk control — it is an unmitigated risk.

- **In-threat-model?** No. The construction must cite a specific auditable ceremony (e.g., Hermez Phase 1, Zcash Powers of Tau with participant list and attestations), provide a link to the ceremony attestation records, and define the incident response plan if a ceremony compromise is announced. It must also address whether PLONK's universal SRS (which requires only a single honest participant in a KZG ceremony) is the preferred alternative for regulated deployments precisely because it reduces ceremony trust surface.

---

### Attack 3: On-Chain Registry Availability Is Not a Credit Union SLA

- **Attack:** Step 1 of the RS verification protocol (§2) requires the RS to "read `agentMerkleRoot` from on-chain registry (or a cached signed root)." Section 5 maps this to "Agent root history buffer (30-entry circular)." My bill-pay system runs on a core processor with a 99.95% uptime SLA. The on-chain registry runs on Base (mainnet) or Base Sepolia (testnet per CLAUDE.md). Base's historical uptime has included sequencer outages. If the on-chain RPC endpoint is unavailable — sequencer down, RPC provider rate-limited, network congestion during a market event — my RS cannot verify any agent proof. Every bill-pay request fails. The CISO attack prompt is direct: "If your on-chain registry has a 1% outage budget, that's more than my core processor."

  The parenthetical "or a cached signed root" in step 1 is the only availability mitigation mentioned, and it is completely unspecified: who signs the cached root? For how long is it valid? What is the cache invalidation policy when a new agent is enrolled or revoked? A stale cached root means a revoked agent (operator key compromised, credential expired via emergency revocation) continues to pass verification until the cache is refreshed.

- **Why it works / why it fails:** The construction defines the 30-entry circular root history buffer (spec §3.1) as the on-chain source of truth but provides no offline fallback with defined SLA. "Cached signed root" is a one-clause parenthetical with no specification. For a regulated financial institution, business continuity planning (BCP) under GLBA Operational Risk and FFIEC BCP requirements demands a documented RTO/RPO for every critical dependency. An unspecified cache with undefined staleness is not a BCP.

- **In-threat-model?** No. The construction must specify: maximum cache staleness (e.g., 15 minutes), the signing key for offline roots (and its custody model), the enrollment/revocation latency impact during fallback mode, and the procedure for handling a cache-root mismatch. Without this, the deployment scenario in §7 (NFCU bill-pay) cannot meet any standard financial institution availability requirement.

---

### Attack 4: Operator Key Lifecycle Has No Revocation Path Under GLBA Incident Response

- **Attack:** The credential commitment is `Poseidon5(modelHash, Ax, Ay, permissionBitmask, expiryTimestamp)` where `Ax, Ay` is the operator EdDSA public key. Every credential in the agent tree is signed by this operator key (G3: `EdDSAPoseidonVerifier`). If the operator's EdDSA private key is compromised — exfiltrated from the operator's HSM, leaked in a breach — an attacker can forge new credential commitments with arbitrary `permissionBitmask` values, enroll them into the Merkle tree (if they also control the enrollment function), and produce valid proofs.

  My attack is not cryptographic — it is operational. My NCUA examiner will ask: "When you detect the operator key is compromised, what is your revocation procedure and what is the blast radius?" The construction provides no answer. Key compromise means ALL credentials signed by that key are potentially tainted. But the Merkle tree contains the credential commitments — there is no flag for "issued by compromised key." I cannot issue a CRL (there is no CRL mechanism). I cannot immediately invalidate all proofs generated by those credentials — they are self-contained, AS-blind, and the RS has no revocation oracle.

  The `expiryTimestamp` eventually expires them, but the construction does not specify maximum credential lifetime. An operator-issued credential with a 1-year expiry and a compromised signing key means a 1-year window of undetectable forgery — far exceeding GLBA incident response requirements (§501(b): notify customers within a reasonable time frame after detecting an unauthorized disclosure).

- **Why it works / why it fails:** Section 2 (Threat model) explicitly protects "the agent's EdDSA private key" — but this is the AGENT's key. The OPERATOR's EdDSA key (used to sign the credential commitment) is in the adversary's reach if the operator's infrastructure is breached. The construction's threat model does not include operator key compromise, even though G3 makes the operator key the root of trust for every credential's scope claim. The "adversarial AS" model in §3 protects against AS lying — but the AS and the operator are the same entity in the NFCU deployment scenario. An NFCU-operated agent gateway is NFCU's AS. The adversarial-AS soundness claim assumes the on-chain Merkle tree is honest, but enrollment into the tree requires an operator transaction — which requires the operator key.

- **In-threat-model?** No. The construction must address: operator key custody requirements (HSM, key ceremony), maximum credential lifetime (forcing rotation windows), an emergency revocation mechanism (e.g., the on-chain registry contract allows the operator to publish a revocation root that RS must check), and the incident response runbook for key compromise. Without this, the CISO cannot satisfy GLBA §501(b) response obligations or NCUA Part 748 incident response requirements.


## Persona: rfc7662_advocate

*OAuth Working Group veteran. Ten years shipping production introspection. Every ZK claim is suspect until proven not achievable with RFC 7662 and its extensions.*

---

### Attack 1: "Adversarial-AS Soundness" Is Not a New Trust Anchor — the Operator IS the AS

**Attack:**
Section 1 states the construction remains sound when "the AS itself may be adversarial (lying about or withholding the agent's actual permissions)." Section 3 names the adversary as controlling "the Authorization Server." But read §2 carefully: the credential commitment is `Poseidon5(modelHash, Ax, Ay, permissionBitmask, expiry)` and is authenticated by the **operator's EdDSA key**. The on-chain Merkle tree is populated by whoever controls the enrollment flow. In the concrete NFCU deployment scenario (§7), NFCU is simultaneously the operator and — in any realistic deployment — the entity that would also run the AS in the OAuth model.

The RFC 7662 advocate's position: *the adversarial-AS claim is circular.* The entity you are protecting against (a malicious AS) is functionally identical to the entity you trust to correctly construct `permissionBitmask` and sign it into the Merkle tree. A compromised NFCU key pair can enroll a credential with `permissionBitmask = 0xFF` (all bits set), which will produce a valid Groth16 proof for any `requiredScopeMask`. The on-chain contract does not validate that the enrolled bitmask is consistent with any out-of-band authorization policy — it only verifies Merkle membership. The RFC 7662 baseline has exactly the same failure mode (compromised AS), just expressed differently. Neither construction survives a compromised issuance key.

**Why it fails against the construction:**
The construction survives a *lying* AS (one who fabricates introspection responses) but is correctly designed to not survive a *compromised operator key* (this is explicitly out of scope in §3: "adversary does NOT control the agent's EdDSA private key or secret credential fields"). The distinction matters if and only if there is an institutional separation between the credential-issuing operator and the OAuth AS. In multi-operator or decentralized deployments, this separation is real and architecturally meaningful. In the NFCU single-operator scenario, it is not.

**In-threat-model?**
**No** — the construction must clarify which deployments make the operator/AS separation load-bearing. The NFCU example does not. The claim in §1 ("adversarial-AS model") needs a concrete scenario where the AS and operator are distinct parties with distinct key material and misaligned incentives. Without that, §8's "Adversarial-AS soundness" row in the comparison table is vacuous for the stated use case.

---

### Attack 2: Blinded Nullifier Destroys Deterministic Replay Prevention — RFC 7662 `jti` Does Not Have This Problem

**Attack:**
The construction adds a prover-chosen `blindingNonce` to produce `blindedNullifier = Poseidon2(Poseidon2(credentialCommitment, sessionNonce), blindingNonce)`. The motivation (§2, §4 Scope Privacy reduction) is correct: without blinding, `rawNullifier = Poseidon2(credentialCommitment, sessionNonce)` is deterministic and leaks cross-session identity. The blinding is required for SP-game security.

But here is what the construction does not say: **the blinded nullifier cannot be used for replay detection.** The RS cannot maintain a nullifier blacklist because two invocations of the same agent with the same `sessionNonce` produce different `blindedNullifier` values (distinct `blindingNonce` samples). Replay prevention now reduces entirely to the RS enforcing single-use `sessionNonce` values. That is: the RS must maintain a nonce registry and reject any `(sessionNonce, agentMerkleRoot)` pair it has issued before — which is **exactly the state management burden OAuth's `jti` (JWT ID) mechanism imposes**, and which RFC 7662-with-introspection handles at the AS.

The RFC 7662 advocate's attack: *you have not eliminated state — you have moved it.* Standard Semaphore-style nullifiers are deterministic: `nullifier = Poseidon(credentialCommitment, externalNullifier)`. The RS stores seen nullifiers and rejects duplicates without tracking nonces. The construction's blinding breaks this. The construction now requires the RS to track used session nonces — and if the RS fails to do so (an implementation error that is common in practice), there is no cryptographic backstop from the blinded nullifier itself.

**Why it fails against the construction:**
The construction is not cryptographically broken by this — it just shifts the replay-prevention burden from a nullifier set (credential-scoped, compact) to a nonce set (session-scoped, requires RS-side discipline). The trade-off is real but not a soundness failure; it is an engineering cost the construction should acknowledge. A partial mitigation: use a time-bounded `sessionNonce` with expiry so the nonce set is bounded in size.

**In-threat-model?**
**No** — the construction does not acknowledge that blinding the nullifier eliminates its replay-prevention function. §2 lists `blindedNullifier` under "replay prevention" in the verification protocol (step 5), but this is misleading: the RS cannot check `blindedNullifier` against a prior-seen set for replay detection. The construction must either (a) restore a deterministic nullifier alongside the blinded output (accepting the identity-leakage trade-off in contexts where replay prevention matters more than cross-session unlinkability), or (b) explicitly state that replay prevention is delegated entirely to `sessionNonce` freshness and document the implementation requirement.

---

### Attack 3: Signed JWT Introspection Response Achieves Offline RS Verification — the Claimed "Architectural" Gap Is a Deployment-Phase Gap

**Attack:**
Section 8's first comparison row claims: "Agent cannot choose disclosure subset at runtime without AS pre-configuring it." This is true for synchronous RFC 7662 introspection. But `draft-ietf-oauth-jwt-introspection-response` (now RFC 9701) allows the AS to produce a signed JWT containing only the scopes relevant to a specific RS, with an embedded `aud` claim matching that RS (RFC 8707 resource indicators). The RS verifies this JWT offline using the AS's published JWK Set. The AS is not in the hot path at proof time — the agent presents the pre-fetched JWT directly.

The RFC 7662 advocate's claim: *the only remaining AS-mediated property is that the AS must have pre-issued the scope-filtered JWT for each RS.* In the NFCU scenario this means the AS pre-issues: `{scope: "financial_small", aud: "bill-pay-rs", sub: <pairwise-id>, exp: ...}`. No AS roundtrip at the RS at proof time. Offline verification. Per-RS scope filtering. PPID (pairwise subject identifier, RFC 8707 + OIDC Core §8) eliminates cross-RS correlation at the subject level.

The construction's response (§8, "adversarial-AS soundness") is that a malicious AS can issue a JWT claiming `scope: financial_small` for an agent that actually holds no financial permissions. True — but the Bolyra alternative requires trusting the operator to correctly populate `permissionBitmask` before enrolling the credential (Attack 1 above). The distinguishing property reduces to: in the ZK construction, the RS cryptographically verifies the *commitment* to the bitmask; in OAuth, the RS trusts the AS's *assertion* about scope. This is a genuine difference — but only in the adversarial-AS / key-compromise scenario, not in the nominal trust model.

**Why it fails against the construction:**
The construction survives this attack in the adversarial-AS scenario *if* the operator and AS are separate entities. It does not survive it in the NFCU single-operator scenario (same attack as §1 above). The construction should explicitly bound its claims: "the following gap is load-bearing only when operator and AS are institutionally and cryptographically separated."

**In-threat-model?**
**Yes, partially** — the construction survives this attack in its intended adversarial-AS model. But §8's framing implies this gap applies universally. The construction should narrow the claim: the comparison row should read "adversarial-AS model only" and cite a concrete multi-operator scenario (e.g., a credential issued by an employer for an agent that connects to third-party financial RSes outside the employer's trust boundary) rather than NFCU (single operator). As stated, §7's deployment scenario does not support the adversarial-AS row in §8's table.

---

### Attack 4: The 64-Bit Bitmask Scalability Argument Is a Strawman — Cedar/OPA Evaluate Structured Policy, Not Flat Tables

**Attack:**
Section 7 claims: "With 50 internal services and 10,000 enrolled agents, the policy table has 500,000 entries." This is the justification for the "regulated agent with 2^64 permission space where AS-side policy tables do not scale" scenario from the candidate's `scenarios` field.

The RFC 7662 advocate objects: **modern policy engines do not use flat per-(agent, RS) tables.** AWS Cedar (open-sourced 2023), OPA (Rego), or Casbin evaluate structured policy. A Cedar policy for NFCU's bill-pay RS reads:

```cedar
permit(
  principal is Agent,
  action == Action::"BillPay",
  resource
)
when { principal.permissions.contains("FINANCIAL_SMALL") };
```

This is one policy, not 10,000 entries. The AS evaluates it at token issuance time against the agent's stored permission record. The introspection response returns `scope: financial_small` only when the policy passes. Adding a new agent does not add a policy entry — the agent's record is data, not policy. The "500,000 entries" figure assumes a different (and obsolete) policy model.

For the 2^64 permission space argument: a 64-bit bitmask is not 2^64 *distinct scope strings* — it is 64 boolean dimensions. Cedar can represent `principal.permissionBitmask.hasBit(2)` as a policy condition. The AS computes this at issuance, not at every introspection call. The scalability argument does not hold for structured permission models.

**Why it fails against the construction:**
The construction's core ZK properties (AS-blindness, adversarial-AS soundness, bitwise predicate with implication closure, constant-size proof) are not undermined by this attack. The ZK properties stand on their own. But the *scalability motivation* presented in §7 is weak and will be dismissed by an OAuth practitioner who knows Cedar or OPA. Worse, it makes the rest of §8's gap analysis look like a strawman if this is one of the featured deployment arguments.

**In-threat-model?**
**No** — the construction does not need the scalability argument to justify its properties. Remove or significantly qualify the "500,000 policy entries" claim in §7. The load-bearing argument is adversarial-AS soundness and bitwise predicate evaluation over committed private data — not policy table size. Leaning on the scalability argument invites dismissal of the entire §8 comparison by practitioners who will immediately recognize the Cedar/OPA counterexample.


## Persona: spiffe_engineer

---

### Attack 1: "You're building a ZK attestor outside the pluggable attestor socket"

- **Attack:** SPIRE's architecture separates *attestation* (proving who/what the workload is) from *identity issuance* (SVID). The attestor socket is pluggable — TPM 2.0, k8s SAT, AWS IID are all just plugins. I can write a `ZKPermissionAttestor` that runs inside SPIRE, calls your `SelectiveScopeProof` circuit, and records the result as a workload selector. The SVID I issue then carries `zkperm:scope_satisfied:0x04` as a selector claim, verifiable offline by any RS with the SPIFFE bundle. You haven't built a new protocol — you've built an attestor that belongs inside SPIRE, wrapped in a new protocol stack.

- **Why it works / fails:** Partially works as a framing attack — the construction never explains why the ZK prover must live *outside* the trust anchor rather than *inside* it as an attestor. However, the attack fails at the adversarial-AS boundary: a ZK attestor running *inside* SPIRE still requires the SPIRE server to honestly record what the attestor returned. The SPIRE server can silently substitute the attestation result in the SVID it issues. In the adversarial-AS model (§3), that substitution is precisely what the game SSU(λ) is designed to prevent — a malicious AS cannot forge scope membership because the on-chain Merkle root and Groth16 soundness (A1) are the trust anchors, not the AS's signed assertion. The plugin approach collapses this property: the RS trusts SPIRE's claim that the ZK proof verified, not the proof itself.

- **In-threat-model?** YES — construction survives, but only if the adversarial-AS threat model is accepted. The construction should preemptively state: "Layering a ZK attestor inside SPIRE preserves SPIRE as the trust anchor; the adversarial-AS game is precisely the case where that anchor fails."

---

### Attack 2: WIMSE JWT SVIDs are already AS-blind at verification time — your "no roundtrip" claim is not novel

- **Attack:** WIMSE (draft-ietf-wimse-arch §4.2) explicitly separates token issuance from token verification. A JWT SVID is self-verifiable against the cached SPIFFE trust bundle — no SPIRE roundtrip at verification time. The RS imports the bundle once (trust bootstrap), then verifies JWT SVIDs locally forever. You claim in §8 that "AS must issue the token and define the introspection response" as a fixed property of RFC 7662 — but that's RFC 7662, not WIMSE. WIMSE with JWT SVIDs achieves your "no AS roundtrip at proof time" property today, in production, at Fortune 500 scale. Name the gap that remains.

- **Why it works / fails:** This is the sharpest attack because it correctly identifies that AS-blindness at *verification time* is already solved by WIMSE. The construction's Table (§8, row "AS-blind presentation") conflates two distinct properties: (1) the RS does not contact the AS at verification time, and (2) the AS cannot have lied about scope at issuance time. WIMSE achieves (1) but not (2) — the JWT SVID is signed by SPIRE, so SPIRE's honesty is required at issuance. More critically: WIMSE SVIDs expose the full scope claim to the RS. The SP game (§3) immediately breaks against WIMSE — the RS sees `scope: ["financial_small", "access_pii", "sign_on_behalf"]` in the SVID, and both RSes can correlate presentations by scope string equality. The construction's actual differentiating property is **AS-blind PLUS selective disclosure PLUS adversarial-AS soundness simultaneously** — and the comparison table should lead with this conjunction rather than treating AS-blindness as the distinguishing claim.

- **In-threat-model?** NO — the construction must sharpen §8 row 1. "AS-blind presentation" as a standalone label is misleading. WIMSE engineers will correctly call it out. The actual claim is the conjunction. The construction needs a paragraph in §8 that explicitly says: "WIMSE achieves (1) but not (2); the adversarial-AS model and selective disclosure together are what WIMSE cannot express."

---

### Attack 3: `modelHash` is self-attested — your "runtime model binding" claim has no root of trust

- **Attack:** In §2, `modelHash` is a **private input** to the circuit. The RS sees only `blindedNullifier` and `blindedScopeCommitment` — neither reveals `modelHash`. The EdDSA operator signature (G3) proves the operator signed *some* credential containing *some* `modelHash` at issuance time. But there is nothing in the proof that binds the prover to be *currently executing* the model identified by that hash. A compromised or misconfigured agent can hold a valid credential issued for `modelHash = H("gpt-4o")` while actually running a jailbroken model, and generate a valid `SelectiveScopeProof`. The RS is convinced the credential was issued for H("gpt-4o") but has no assurance about what is executing now. In SPIFFE, node attestation via TPM 2.0 PCR measurements or AMD SEV-SNP measurement registers provides hardware-level assurance of *what code is actually running* at proof time. §8's claim "OAuth has no concept of which model is running right now" is correct — but neither does Bolyra's construction, cryptographically.

- **Why it works:** This is a genuine gap. The construction commits to `modelHash` at *issuance time* (when the operator creates the credential), not at *proof time* (when the agent generates the `SelectiveScopeProof`). The circuit cannot distinguish a prover using the correct model from one using a substituted model, because the circuit takes `modelHash` as a witness it never independently verifies. The only defense would be a trusted execution environment attestation (SGX, TDX, SEV-SNP) bound to the proof — which is not in the construction. Against a SPIFFE engineer who runs workload attestation via TPM, this is a meaningful regression.

- **In-threat-model?** NO — The construction must either (a) acknowledge that `modelHash` binding is operator-asserted rather than hardware-attested and scope the claim accordingly, or (b) sketch how a TEE attestation quote could be incorporated as an additional public input (e.g., `teeAttestedModelHash` as a public signal, verified against a registry of known-good measurements). As written, §8's "Runtime model identity binding" column overstates the guarantee.

---

### Attack 4: The delegation chain's `blindingNonce` retention requirement creates stateful identity — SPIFFE SVIDs are stateless

- **Attack:** §2 (Delegation chaining interop) requires the prover to **retain the `blindingNonce`** from the initial `SelectiveScopeProof` and supply it as a private input to the downstream `Delegation` circuit for chain verification. This means the agent must maintain persistent secret state across sessions: at minimum, `(credentialCommitment, blindingNonce, sessionNonce)` from the prior proof. If the agent is stateless (ephemeral container, serverless function, burst-scaled pod) or if that state is lost (restart, crash, eviction), the delegation chain breaks — the on-chain `blindedScopeCommitment` cannot be re-linked without the original `blindingNonce`. SPIFFE SVIDs are stateless: a new SVID is minted on demand from SPIRE via the Workload API, and the X.509 chain-of-trust is verified structurally from the certificate chain without any retained per-presentation secret. Ephemeral workloads rotate SVIDs every few minutes without any cross-session state management burden.

- **Why it works / fails:** This is a concrete operational objection, not a cryptographic break. The construction is sound — if `blindingNonce` is retained, the delegation chain works. But the implicit statefulness requirement is an engineering liability that the construction does not acknowledge. For the NFCU scenario (§7), agents are likely long-lived processes, mitigating the concern. For serverless or burst-scaled agentic runtimes (the primary AI-agent deployment pattern), this is a real constraint. A SPIFFE engineer will correctly note that their deployment model has zero per-presentation retained state.

- **In-threat-model?** YES — the construction is not broken by this attack, but it should acknowledge the statefulness assumption in §7 and recommend that implementations persist `(credentialCommitment, blindingNonce)` in a tamper-evident local store (e.g., sealed to the TEE) for delegation-capable agents. Alternatively, the construction could eliminate the `blindingNonce` retention requirement by using a deterministic derivation: `blindingNonce = PRF(agentSecret, sessionNonce)`, making the blinding nonce re-derivable from the agent's root secret and the RS's nonce — no additional retained state required.
