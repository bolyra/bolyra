# Tier 3 Adversarial — C1 Selective scope proof

## Persona: auth0_pm

---

### Attack 1: The Adversarial-AS Threat Model Matches Zero Enterprise Procurement Requirements

**Attack:**
The construction's central differentiation claim is §3 "adversarial-AS soundness" — that a malicious AS cannot lie about scope membership because the proof anchors to an on-chain Merkle root and Groth16 soundness, not an AS assertion. But in every enterprise deal I run, the buyer chose Auth0, Okta, or WorkOS *because* they trust that vendor. No CISO at NFCU is writing a procurement requirement that says "we need cryptographic protection against our own authorization server lying." Their actual threat model is: compromised agent token exfiltration, over-permissioned service accounts, session replay, and insider threat. RFC 7662 + DPoP + token binding addresses every one of those. The adversarial-AS scenario is a cryptographically elegant property that maps to no line item in any enterprise security questionnaire.

**Why it works / why it fails against the construction:**
The construction doesn't address this at all. §7 (NFCU scenario) pivots to GLBA data minimization and policy table scale — both real concerns — but then §8's "core impossibility" claim rests on "when the AS is the adversary." For NFCU, Okta is not the adversary. This is a gap between what the construction proves and what the buyer is actually afraid of.

**In-threat-model?** No — the construction must either (a) show that "adversarial AS" maps to a real buyer risk that isn't just theoretical, or (b) de-emphasize this as the primary claim and lead instead with the GLBA data minimization / policy table scale argument, which is at least a GTM-credible pain point.

---

### Attack 2: The Onboarding Cliff Makes "Paste an API Key" Win Every Time

**Attack:**
Walk me through actual onboarding. WorkOS: sign up, get `wos_live_...` key, pass it to your MCP client config. Done in 4 minutes. What's Bolyra's day-one flow?

Per §2, the operator must: (1) generate a Baby Jubjub EdDSA keypair using tooling that doesn't ship in any mainstream cloud SDK, (2) construct a `Poseidon5(modelHash, Ax, Ay, bitmask, expiry)` credential commitment, (3) sign it with the EdDSA key, (4) submit an on-chain transaction to enroll the credential commitment in the agent Merkle tree (gas, latency, wallet setup), and (5) configure the RS with the on-chain registry address and the Groth16 verification key. The RS also needs to either run a blockchain node or use a Bolyra relay to read `agentMerkleRoot` — which the construction mentions in §2 (verification step 1) as "or a cached signed root" without specifying who signs it or where it lives.

The construction's §7 NFCU scenario skips entirely from "NFCU deploys an AI agent gateway" to "the agent generates a SelectiveScopeProof" without naming a single tool, SDK method, or ops requirement. That gap is where deals die in procurement.

**Why it works / why it fails against the construction:**
The TS SDK (`createAgentCredential`) abstracts some of this, but CLAUDE.md confirms the Python SDK "only ships pure-Python types/validation" and proving spawns Node via subprocess bridge. A Python-native MCP operator gets a subprocess dependency on Node, snarkjs, and circuit artifacts as prerequisites before issuing a single credential. No section of the construction addresses operator tooling, key custody, or the on-chain enrollment UX. The RS-side `agentMerkleRoot` trust path (§2 step 1: "reads from on-chain registry or cached signed root") is unspecified — if it's a relay, who runs it, and why is that relay more trustworthy than Auth0?

**In-threat-model?** No — the construction is silent on operator UX, key management, and RS-side infrastructure dependencies. This is a distribution gap that compounds with every additional touchpoint.

---

### Attack 3: Proving Latency is Understated and the Comparison is Unfair

**Attack:**
Section §6 claims Groth16 (rapidsnark, native): `<500ms`. That's the best case — native binary, pre-compiled circuit artifacts, warm process, local hardware. Now add the actual round-trip for a financial API call: RS generates `sessionNonce`, sends challenge to agent, agent generates proof, agent sends `(π, pubSignals)` back, RS reads `agentMerkleRoot` from chain or relay, RS verifies. The on-chain read alone adds 200–2000ms depending on RPC latency and caching strategy. The construction's §2 verification step 1 says the RS reads the Merkle root — it doesn't say from a local cache. If the RS caches the root, it must track the 30-entry circular root history buffer (mentioned in §5 mapping) to know which historical root to accept, because the agent proved against the root valid at credential enrollment time, not necessarily the current root.

WorkOS issues tokens in `<100ms` end-to-end. Even optimistic Bolyra at 500ms proving + 300ms round-trip + 200ms chain read = ~1 second per API call. For a member-facing bill-pay flow that chains 3–5 MCP tool calls, that's 3–5 seconds of ZK overhead per request, in addition to normal API latency.

**Why it works / why it fails against the construction:**
The construction acknowledges snarkjs at 3–5s and rapidsnark at `<500ms` but doesn't model the full round-trip including the RS-side chain read and the challenge-response overhead. It also doesn't address cold-start latency for rapidsnark (binary startup, artifact loading), or what happens when the agent is running in a serverless/container environment where the rapidsnark binary and 50+ MB of `.zkey` artifacts must be available. These are real deployment constraints that don't appear anywhere in §7.

**In-threat-model?** No — the construction must provide an end-to-end latency model (not just proving time), address the Merkle root read latency, and show either that 500ms–1s is acceptable for the stated use case or that a root caching/relay architecture is specified and operated.

---

### Attack 4: The GLBA Data Minimization Argument Doesn't Survive Compliance Review

**Attack:**
Section §7 argues that NFCU's bill-pay RS seeing the full scope string violates GLBA §501(b) data minimization, and that Bolyra solves this cryptographically. But GLBA §501(b) data minimization is about what data is transmitted and stored — and RFC 7662 already solves this at the AS layer. The AS can return *only* `"scope": "financial_small"` in the introspection response. The RS never sees `ACCESS_PII` or `SIGN_ON_BEHALF` — those are simply not included in the response. The bill-pay RS logs `financial_small`. The GLBA auditor sees a JWT with exactly the scopes required. Done. The construction's §8 column for "AS-blind presentation" says "Agent cannot choose disclosure subset at runtime without AS pre-configuring it" — but that's the correct enterprise behavior. The AS *should* pre-configure per-RS scope policies. That's what authorization servers do.

The construction's real concern about the AS seems to be the 500K policy-table entry problem (`50 services × 10,000 agents`). That's a real scaling argument but it's an ops complexity argument, not a GLBA argument. Mixing them weakens both. And for 10,000 agents at 50 services, Auth0 Actions or WorkOS role assignments handle this with group-based policies — not 500K individual entries.

**Why it works / why it fails against the construction:**
The GLBA claim in §7 conflates "RS learns the agent's full permission bitmask" with "GLBA is violated." But the RS only learns what the AS includes in the introspection response, and the AS is the entity NFCU controls and configures. The compliance gap doesn't exist in the stated form. The stronger and more defensible version of this argument is the adversarial-AS scenario where a *compromised* AS returns a falsely elevated scope — but that's the §3 threat model the construction already establishes, which circles back to Attack 1: does any NFCU compliance officer write that threat into their risk register?

**In-threat-model?** No — the GLBA data minimization framing as written does not survive a compliance review against existing AS-side scope filtering. The construction should either tighten this to the specific adversarial-AS + audit-trail scenario (where the cryptographic proof is the audit evidence, not the AS assertion) or drop GLBA as the compliance hook and lead with "cryptographic audit trail that doesn't depend on AS logs."


## Persona: cryptographer

I'll work through the construction section by section. The threat model in §3 is more careful than most, but there are at least four spots where the formalism breaks down or the reduction is wrong.

---

### Attack 1: Scope Privacy Game Is Trivially Broken by the `scopeCommitment` Public Output

**Attack:**

In the SP game (§3), the adversary A sees `pubSignals`, which — per §2 — includes `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` as a public output. Since `credentialCommitment = Poseidon5(modelHash, Ax, Ay, permissionBitmask, expiry)` also embeds `permissionBitmask`, the `scopeCommitment` is a deterministic, publicly computable function of `permissionBitmask`. In the SP game, A is given both enrolled agents and therefore knows both `(b₀, CC₀)` and `(b₁, CC₁)`. A precomputes:

```
SC₀ = Poseidon2(b₀, Poseidon5(..., b₀, ...))
SC₁ = Poseidon2(b₁, Poseidon5(..., b₁, ...))
```

A then matches the observed `scopeCommitment` in `pubSignals` against `SC₀` or `SC₁` and wins SP with probability 1, not `1/2 + negl(λ)`.

**Why it works:**

The SP reduction in §4 explicitly states "permissionBitmask does not appear in any public output." This is false on its face — `scopeCommitment` is a public output listed in the circuit's public outputs table (§2), and it is a (computationally injective, by A2) function of `permissionBitmask`. The Poseidon preimage argument in §4 would hold only if `scopeCommitment` were omitted from the public signal set. As written, A needs zero cryptographic capability to win — it's a table lookup against values it can compute at zero cost.

The construction notes in §4 that "`scopeCommitment` can be omitted... when delegation chaining is not needed." But the circuit as specified outputs it unconditionally, and the SP game as stated does not condition on omission. The security claim and the construction are inconsistent.

**In-threat-model?** No — the construction must either (a) remove `scopeCommitment` from public outputs and restrict it to private delegation-path verification, or (b) randomize it with a per-presentation blinding nonce and fix the SP reduction accordingly.

---

### Attack 2: Cross-RS Linkability — §8 Unlinkability Claim Is Unfounded with `scopeCommitment` Present

**Attack:**

Section 8 claims "cross-RS unlinkability" as a Bolyra advantage over BBS+. The argument is that `blindedNullifier = Poseidon2(rawNullifier, blindingNonce)` randomizes per-presentation. This is correct for the nullifier. But `scopeCommitment` is NOT blinded. It is a deterministic function of `(permissionBitmask, credentialCommitment)` and therefore a deterministic function of the agent's credential. Any two RSes that both receive presentations from the same agent observe the same `scopeCommitment`. They can trivially correlate.

This is strictly worse than the OAuth baseline: in the BBS+ case, the AS is the correlating party but RS-to-RS correlation via the derived proof is provably absent (BBS+ presentations are unlinkable). Here, ANY pair of colluding RSes can link all presentations from the same credential, without needing the AS at all.

**Why it works:**

The construction provides no blinding on `scopeCommitment`. The blinded nullifier covers one dimension (nullifier linkage), but the proof transcript's public signals contain a second, unblinded correlator. The SP reduction's failure (Attack 1) and the linkability failure are two faces of the same missing blinding term.

Formally: the cross-RS unlinkability game would require that for any two transcripts `(π₁, pubSignals₁)` and `(π₂, pubSignals₂)` produced from the same credential to different RSes, no PPT adversary can determine they share a credential. But `pubSignals₁.scopeCommitment == pubSignals₂.scopeCommitment` holds with probability 1 (under Poseidon determinism), so the game is broken with probability 1.

**In-threat-model?** No — the §8 claim "Bolyra eliminates AS-layer correlation entirely" is overstated. The construction moves correlation from the AS to any pair of RSes. This does not match the stated adversary model, which allows up to `n-1` colluding agents but says nothing about colluding RSes.

---

### Attack 3: Subverted Groth16 CRS — The AS-Trust Paradox

**Attack:**

The construction's central motivation (§3, §8) is that the AS may be adversarial and RFC 7662 is therefore insufficient because "assertions are worthless" when the trust anchor is compromised. But §3's adversary model explicitly excludes "The Groth16 CRS (trusted setup is assumed honest)." This is a category error: the construction removes trust in the AS (a centralized party) and replaces it with trust in the CRS ceremony (another centralized event). The adversary who can corrupt the AS can plausibly corrupt the ceremony, particularly in an enterprise setting where NFCU would run its own trusted setup.

With a toxic-waste-retaining CRS, knowledge soundness (A1) collapses entirely. The setup creator holds a trapdoor `τ` such that for any `(pubSignals*, π*)`, they can produce an accepting proof without knowledge of any valid witness. In particular, they can forge proofs for agents that are NOT in the Merkle tree, for bitmasks that do NOT satisfy `requiredMask`, and for credentials that are expired. The SSU reduction reduces to A1, and A1 does not hold when the CRS is subverted.

The PLONK fallback in §2.5 mitigates this for PLONK instances (universal trusted setup, powers-of-tau is circuit-agnostic and more auditable). But the spec designates Groth16 as REQUIRED and PLONK as OPTIONAL, and the §4 security argument is stated for Groth16 only. The construction needs either (a) a subverted-setup security model and a corresponding impossibility argument (showing CRS-subversion is at least as hard to mount as AS corruption, which requires evidence), or (b) PLONK as the required primary system and Groth16 as the optional fast path, reversing the current priority.

**Why it works / why it might fail:**

The construction can respond that CRS ceremonies are auditable and multi-party (Zcash-style MPC setup, where one honest participant suffices). This is a legitimate mitigation, but it is unaddressed in §3–4. The NFCU deployment scenario in §7 mentions no ceremony details. Without specifying ceremony requirements, the CRS trust assumption is no better formalized than the AS trust assumption being criticized.

**In-threat-model?** The adversary model explicitly excludes this. But the exclusion is unjustified given the construction's own motivating argument against centralized trust. The construction must address why the CRS trust assumption is weaker (more auditable, threshold) than the AS trust assumption.

---

### Attack 4: The Blinded Nullifier Provides No Useful Replay Prevention — Design Confusion

**Attack:**

Section 2 labels `blindedNullifier` as serving "replay prevention." The raw nullifier `rawNullifier = Poseidon2(credentialCommitment, sessionNonce)` is already unique per `(credential, session)` because `sessionNonce` is a fresh RS-generated challenge. Binding `rawNullifier` to the RS's nonce is sufficient to prevent replay of the same proof transcript. The additional blinding step — `blindedNullifier = Poseidon2(rawNullifier, blindingNonce)` where `blindingNonce` is PRIVATE and random — produces a per-presentation random value that the RS cannot compute, cannot predict, and cannot accumulate for double-spend detection.

Specifically: suppose two sessions from the same credential use `sessionNonce₁` and `sessionNonce₂`. The RS sees `blindedNullifier₁` and `blindedNullifier₂`. Because `blindingNonce` is private and fresh each time, `blindedNullifier₁ ≠ blindedNullifier₂` with probability 1 even if the underlying credential is identical. The RS cannot detect that both proofs come from the same credential, which means it cannot enforce "one use per credential" or any per-credential rate limit.

This is actually desirable for some use cases (the bill-pay scenario wants unlimited reuse), but the construction conflates two distinct goals: (a) **session replay prevention** (handled by sessionNonce binding alone) and (b) **credential single-use or rate limiting** (not achievable with the blinded nullifier design). Calling the blinded nullifier "replay prevention" is misleading. More critically, if any downstream use case requires rate limiting (e.g., the `FINANCIAL_MEDIUM` permission allowing at most N transactions per day), the current nullifier design provides zero enforcement mechanism — the RS cannot detect repeated presentations of the same credential across sessions.

**Why it works:**

The circuit as specified does not constrain `blindingNonce` to any public context (it could be made a deterministic function of `(credentialCommitment, day_bucket)` to enable rate-window linkability without full session unlinkability). As it stands, the blinded nullifier is a fresh random value that provides cross-RS unlinkability at the cost of any stateful replay/rate detection. The construction should state explicitly which of these goals is achieved and which is sacrificed, rather than claiming both under the single label "replay prevention."

**In-threat-model?** Partially — the SSU game (§3) uses a fresh `sessionNonce*` to define the win condition, so pure replay (reusing the same proof transcript) is correctly prevented. But the construction overclaims: "replay prevention" as usually understood in credential protocols means detecting and blocking a credential after it is revoked or after it has been used the maximum permitted number of times. The blinded nullifier prevents neither.


## Persona: cu_ciso

---

### Attack 1: Trusted Setup as Unauditable Single Point of Catastrophic Failure

- **Attack:** §3 explicitly excludes from the threat model: *"The Groth16 CRS (trusted setup is assumed honest)."* A1 (knowledge soundness) holds only if the toxic waste from the Powers of Tau ceremony was destroyed. If a single participant in the `pot16.ptau` ceremony retained their randomness, they can forge a valid Groth16 proof for *any* permission bitmask, including `permissionBitmask = 0xFF` (all 64 bits set), passing every G3–G7 constraint, and the RS cannot detect it — the proof is cryptographically indistinguishable from a legitimate one. There is no revocation for a poisoned CRS; the entire key set must be replaced.

- **Why it works against this construction:** The construction inherits `pot16.ptau` from the Bolyra project-specific ceremony (CLAUDE.md: *"Project-specific keys (Agent/Delegation) use pot16.ptau"*). §5 maps this to spec §2.3. The RS's entire verification path — `Groth16.Verify(vkey, pubSignals, π)` — collapses to meaningless if the CRS is poisoned. The threat model explicitly does not model this adversary, calling it out of scope. But it is not out of scope for my NCUA examiner.

- **Regulatory mapping:** NCUA Part 748 §748.0(b) requires the CU's security program to identify risks in systems it relies on. Under FFIEC CAT, this is a Maturity Level 5 dependency: a single mathematical event (key ceremony) with no compensating control, no audit log proving destruction of toxic waste, and no examiner-readable attestation. My third-party vendor management policy requires a SOC 2 Type II report or equivalent. *Who audited the pot16.ptau ceremony, and where is the MPC transcript I can give my examiner?*

- **In-threat-model?** **No.** The construction must address CRS ceremony auditability, link to a public MPC transcript (e.g., Hermez, Zcash Sapling), or scope-limit the claim to settings where the ceremony is verified. A poisoned CRS is not a negligible attack in a regulated financial context — it is an undetectable, unlimited scope-escalation vulnerability.

---

### Attack 2: The Audit Trail Inversion Problem — blindedNullifier Defeats Incident Reconstruction

- **Attack:** §2 G8 computes `blindedNullifier = Poseidon2(Poseidon2(credentialCommitment, sessionNonce), blindingNonce)` where `blindingNonce` is a private random per-presentation value. §4 SP game explicitly proves this construction makes presentations *unlinkable across RSes*. §8 lists "Cross-RS unlinkability" as a feature. Now I have a security incident at 2am: an agent made 400 unauthorized bill-pay calls in 12 minutes. My SOC team pulls the RS logs. They have 400 distinct `blindedNullifier` values. They cannot link them to a single agent credential (by design — the ZK proof hides it). They cannot call the AS (there is no AS). They cannot trace back to which operator or model hash is responsible without the agent's cooperation. The agent is the adversary.

- **Why it works:** §7 names this as a compliance win — *"The RS does NOT learn bits 0, 1, 3–7. No AS was contacted."* But incident response requires the *opposite*: a chain of custody from observed action back to accountable identity. The construction's privacy guarantee is structurally opposed to forensic traceability. The `rawNullifier = Poseidon2(credentialCommitment, sessionNonce)` is deterministic per (credential, session) but the `blindingNonce` is private and ephemeral. If the agent destroys it, the link is gone.

- **Regulatory mapping:** GLBA Safeguards Rule 16 CFR §314.4(h) requires the CU to maintain procedures to detect and respond to security events, including identifying affected members. NCUA Part 748 Appendix B §III requires incident response plans that include *"identifying and protecting evidence."* A system where the agent unilaterally controls whether its actions are attributable is not a security program — it is a liability program. My board narrative cannot include "the math proves the agent had permission but we cannot identify which agent caused the incident."

- **In-threat-model?** **No.** The SP game models privacy against the RS, but does not model the CU's own need to attribute actions post-incident. The construction needs a dual-mode: ZK privacy for real-time RS verification AND a linkable audit channel (e.g., encrypted to CU's audit key, or rawNullifier logged by a CU-controlled nonce oracle) that satisfies the CU's forensic obligation without leaking to third-party RSes.

---

### Attack 3: On-Chain Registry SLA vs. Core Processor Comparison — The §2 Step 1 Dependency

- **Attack:** §2 verification step 1 states: *"RS reads `agentMerkleRoot` from on-chain registry (or a cached signed root)."* The on-chain registry is on Base Sepolia (CLAUDE.md: *"Deploy target chain: Base Sepolia"*). Spec §5 maps this to *"Agent root history buffer (30-entry circular)"* from spec §3.1. My Fiserv DNA core processor runs at 99.98% uptime per contract (≈105 minutes downtime/year). Base Sepolia is an L2 testnet with no contractual SLA, no FFIEC-regulated uptime commitment, no indemnification clause, and no established NCUA precedent as a system-of-record. When the chain has an outage or L1 reorg affects finality, step 1 either blocks (RS cannot get the root → agents cannot transact) or falls back to the "cached signed root" — which is an offline copy of unknown age with no defined staleness bound in the construction.

- **Why it works:** The 30-entry circular history buffer (§5) means a root is valid for up to 30 Merkle tree updates. If tree updates happen infrequently, a cached root could be hours or days old. An agent revoked at T=0 remains provable against a cached root until the RS refreshes. The construction provides no maximum cache TTL, no alerting mechanism when the RS is operating on a stale root, and no fallback that satisfies both availability and revocation freshness simultaneously.

- **Regulatory mapping:** FFIEC CAT Domain 2 (Threat Intelligence and Collaboration) and Domain 4 (External Dependency Management) require the CU to assess third-party dependencies for availability and recovery. Under NCUA Examination guidance for third-party risk (Letter 07-CU-13), the CU must obtain assurance of service continuity. A blockchain with no SLA, no indemnification, and no contractual relationship is not an auditable external dependency — it is an uncontrolled infrastructure component. My vendor management policy cannot on-board a smart contract.

- **In-threat-model?** **No.** The threat model §3 says the adversary does NOT control the on-chain registry. But this framing assumes the registry is *available*. Network-level unavailability (not adversarial) breaks the verification protocol with no defined fallback. The construction must specify: maximum permitted root cache age, who signs the cached root (and under what key management policy), and what the RS does when it cannot reach the chain.

---

### Attack 4: scopeCommitment Oracle — Deterministic Leakage Enabling Bitmask Enumeration

- **Attack:** §2 public outputs include `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)`. §4's SP game proof-of-privacy acknowledges: *"this output does leak a deterministic function of permissionBitmask."* The `credentialCommitment` is also deterministic: `Poseidon5(modelHash, Ax, Ay, bitmask, expiry)`. Both are Poseidon hashes over a 64-bit integer (`permissionBitmask`) plus known or observable fields. A 64-bit space has 2^64 possible values, but permission bitmasks in practice are highly structured — the construction's own CLAUDE.md documents 8 named bits with implication constraints, giving a realistic permission space of at most a few hundred valid combinations (not 2^64). An RS that collects multiple `scopeCommitment` values from an agent across different `requiredScopeMask` challenges can precompute a rainbow table over the sparse valid bitmask space and invert the commitment — learning the full bitmask, defeating the selective-disclosure claim.

- **Why it works:** The SP game §3 assumes two agents with bitmasks `b₀ ≠ b₁`. But the game does not model an RS with precomputed tables over the realistic permission space. The §4 SP reduction says distinguishing requires "inverting Poseidon (A2)" — but Poseidon inversion is only hard over a *large* pre-image space. When the pre-image space is `{0x01, 0x03, 0x04, 0x07, 0x0C, ...}` (the small set of valid cumulative encodings), the RS can brute-force Poseidon offline in milliseconds. The `credentialCommitment` (which includes `operatorPubkeyAx/Ay`) may also be recoverable if the operator's public key is known (it's public by definition).

- **Regulatory mapping:** GLBA §501(b) data minimization and NCUA member privacy rules require that permission state (which encodes what a member authorized an agent to do) not be inferrable by third parties. If the RS can reconstruct the full bitmask from `scopeCommitment` observations, the CU has disclosed member authorization scope to a third-party RS — a GLBA privacy violation, regardless of whether the ZK proof "technically" hides it. *My examiner will not accept "the pre-image space is theoretically large" when the implementation constrains it to dozens of valid states.*

- **In-threat-model?** **No.** The SP game models information-theoretic hiding over an implicit large input space, but the construction's own permission model (CLAUDE.md: 8 bits, cumulative encoding) collapses this to a small enumerable set. The construction must either (a) omit `scopeCommitment` from public outputs in non-delegation contexts (§4 notes this is optional — make it the default), (b) add a blinding term to `scopeCommitment` analogous to `blindingNonce` in G8, or (c) explicitly bound the claim to settings where the permission space is large enough to defeat enumeration.


## Persona: rfc7662_advocate

---

### Attack 1: Operator Key Is the New Authorization Server — Adversarial-AS Claim Is Circular

**Attack:**
The construction's headline property is "adversarial-AS soundness" — the RS trusts math, not the AS. But read §3 carefully: the adversary does *not* control "the agent's EdDSA private key or secret credential fields." Who holds the EdDSA operator key? The *operator*. Who enrolls credential commitments into the on-chain Merkle tree? The *operator* (or whoever controls the registry contract's write path). In the NFCU scenario (§7), NFCU is simultaneously the AS and the credential operator. The construction has renamed the Authorization Server "operator" and renamed the signed introspection response "a Groth16 proof of EdDSA signature verification."

The trust chain is:
`RS trusts Merkle root → Merkle root updated by operator → operator signed credential → operator chose the permissionBitmask`

This is isomorphic to `RS trusts AS → AS issued JWT → AS chose the scope`. An adversarial operator inflates a credential's bitmask, enrolls it in the registry, and the circuit faithfully proves the inflated scope. The RS has no independent check on whether the claimed bitmask reflects actual granted permissions — it only checks that the bitmask was EdDSA-signed and Merkle-enrolled by the operator.

**Why it fails against the construction:** The construction's §3 threat model explicitly excludes adversarial operators ("adversary does NOT control the agent's EdDSA private key"). This is a valid scope restriction, but:

1. The §8 gap table claims "Adversarial-AS soundness" as an architectural differentiator over RFC 7662. That differentiator disappears unless "operator" and "AS" are *different principals* with separated trust. The construction never states this separation is required or how it is enforced.
2. In every realistic enterprise deployment (NFCU, §7), the same organization plays both roles. The cryptography proves the bitmask was issued correctly by whoever controls the operator key — it does not prove the bitmask is *authorized* by any higher principal the RS independently trusts.

**In-threat-model?** No — the construction must either (a) require operator ≠ AS as an explicit deployment invariant with enforcement mechanism, or (b) narrow the adversarial-AS claim to "AS cannot *retroactively* forge scope for already-enrolled credentials," which is a weaker property the paper should state precisely. As written, the gap table overclaims.

---

### Attack 2: `scopeCommitment` Leaks a Deterministic Bitmask Fingerprint — SP Game Has a Hole

**Attack:**
The public output `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` is deterministic. Since `credentialCommitment` is the Merkle leaf (public by construction — the Merkle tree's leaves must be known to compute membership proofs), any party with the leaf value can enumerate plausible bitmasks and find the one matching `scopeCommitment` by brute force.

Corporate permission schemes are not 64-bit random strings. They are sparse role assignments. NFCU's realistic permission space is O(10) distinct roles: READ_ONLY, BILL_PAY_AGENT, LOAN_OFFICER_AGENT, etc. With 10 plausible bitmask values, an RS (or any observer of proof transcripts) inverts `scopeCommitment` in 10 Poseidon evaluations. The SP game requires distinguishing `b₀` from `b₁` — if the real-world bitmask space is small, the adversary guesses with high probability.

Section 4 acknowledges this partially ("the `scopeCommitment` output does leak a deterministic function of `permissionBitmask`") but deflects to "RS cannot invert Poseidon." Poseidon inversion is not required — only enumeration over a low-entropy input space. The SP reduction in §4 assumes Poseidon collision resistance, but that assumption is about *collision*, not *preimage with a small domain*.

Compare: RFC 7662 + PPID (OIDC pairwise subject identifiers) gives each RS a different sub claim, preventing cross-RS correlation. The `scopeCommitment` is the same value presented to every RS that asks about the same credential — an identifier more stable than a PPID.

**Why it fails against the construction:** Section 4 offers `scopeCommitment` as optional ("can be omitted from the public outputs when delegation chaining is not needed"). If the construction's privacy claim is "omit scopeCommitment for full privacy," then the construction needs to make this the default and acknowledge the delegation trade-off explicitly rather than listing cross-RS unlinkability as an unconditional property in §8's gap table row 6.

**In-threat-model?** Yes — but the SP game proof is incomplete. It argues Poseidon non-invertibility under a uniform-distribution assumption that does not hold for enterprise permission bitmasks. The security argument must either (a) bound adversary advantage in terms of the bitmask entropy or (b) mandate `scopeCommitment` omission when unlinkability is required.

---

### Attack 3: Revocation Is AS-Dependent in Practice — RFC 7662 Wins on Timely Revocation

**Attack:**
The RS reads `agentMerkleRoot` from the on-chain registry "or a cached signed root" (§2, step 1). The 30-entry circular root history buffer (Bolyra spec §3.1, referenced in §5) means the RS can accept proofs against any of the last 30 published roots.

Credential revocation in this construction requires: (1) the operator removes the leaf from the active tree, (2) posts a new root on-chain, (3) the RS abandons all 30 cached roots (or waits for the history buffer to flush). Between revocation event and RS cache expiry, a revoked agent can generate valid proofs against any of the 30 retained roots. On a chain with 12-second block times and a history buffer designed for liveness (e.g., one root per hour), revocation-to-rejection latency can be hours.

RFC 7662 with real-time introspection responds to revocation in the next introspection call — typically <100ms. Even offline JWT introspection with short `exp` (e.g., 5-minute tokens) bounds revocation latency to 5 minutes. The construction's latency is bounded by `30 × root_publication_interval`, which is unspecified and potentially much longer.

The GLBA scenario in §7 makes this concrete: if NFCU discovers a compromised agent at 09:00, revokes the credential at 09:01, but the bill-pay RS has a cached root from 08:30 and the history buffer holds 30 hourly roots — the compromised agent presents valid proofs until 14:30. Under GLBA §501(b), this is a live data-access window for a known-compromised agent.

**Why it fails against the construction:** Section 7 does not address revocation at all. Section 8's gap table has no revocation row. The construction claims superiority for the GLBA compliance scenario, but the adversarial scenario most relevant to compliance — revoke-on-compromise — is unaddressed.

**In-threat-model?** No — construction must define a revocation mechanism with a bounded latency guarantee and include it in the comparison table. "Short-expiry credentials" is the obvious mitigation (also the RFC 7662 mitigation), which narrows the claimed architectural difference.

---

### Attack 4: RFC 8693 Token Exchange + RFC 8707 + DPoP Approximates AS-Blind Scope Minimization for the Non-Adversarial Case — Where Is the Concrete Delta?

**Attack:**
Section 8's "AS-blind presentation" gap row claims agents "cannot choose disclosure subset at runtime without AS pre-configuring it." This understates what RFC 8693 token exchange enables. The flow:

1. Agent holds a broad-scope bearer credential from the AS.
2. At request time, agent calls the AS token exchange endpoint with `requested_token_type=urn:ietf:params:oauth:token-type:access_token`, `audience=https://bill-pay.nfcu.com` (RFC 8707), and `scope=financial_small`.
3. AS issues a narrow-scope, audience-bound, short-lived JWT. Agent presents it to the bill-pay RS with DPoP (RFC 9449).
4. Bill-pay RS verifies the JWT offline (JWT introspection response, signed by AS). RS sees only `scope: financial_small` and the audience-bound sub.

The bill-pay RS never learns about `ACCESS_PII` or `SIGN_ON_BEHALF`. The AS is in the loop at *exchange time* (not at *presentation time*), and that exchange happens before the RS interaction. No RS roundtrip, no real-time introspection.

The construction's counter is adversarial-AS soundness (Attack 1 applies here too) and the 500,000-entry policy table scaling argument. On the latter: RFC 8693 exchange requests are dynamic — the *agent* specifies the target scope in the exchange request. The AS validates that the requested scope is a subset of the agent's granted scope (`financial_small ⊆ agent_granted_scopes`). No per-(agent, RS) policy table needed — the AS enforces subset semantics at exchange time using existing scope grant records. The construction's §7 claim that "the policy table has 500,000 entries" is a strawman of static per-RS AS configuration rather than dynamic token exchange.

The genuine residual gap after applying RFC 8693 + 8707 + 9449 is: (a) adversarial-AS soundness (as argued above, this requires operator ≠ AS), (b) runtime model identity binding (no OAuth concept of `modelHash`), and (c) bitwise implication closure enforced *in the proof* rather than by AS policy. Item (c) is real — BBS+ claims are per-field, not over a committed bitfield. But the construction should name (c) as the primary differentiator rather than building its case on adversarial-AS and constant-size proof, which are either overstated or applicable to a narrower deployment context than claimed.

**In-threat-model?** No — the construction's §8 comparison table treats RFC 8693 token exchange as equivalent to static per-RS policy tables. It should model the strongest baseline: RFC 8693 + RFC 8707 + DPoP + signed JWT introspection with dynamic exchange. Against that baseline, the true differentiators shrink to: (a) adversarial-AS soundness *only when operator ≠ AS* and (b) in-proof bitwise implication closure. The gap table as written overstates the construction's advantage by understating the baseline.


## Persona: spiffe_engineer

### Attack 1: Model Hash is Self-Asserted, Not Attested — The Construction Solves the Wrong Binding Problem

- **Attack:** The `modelHash` is a private input (§2, Private Inputs table). The circuit proves `credentialCommitment = Poseidon5(modelHash, Ax, Ay, bitmask, expiry)` is in the on-chain Merkle tree. But *nothing in the construction verifies that the claimed `modelHash` corresponds to the model actually executing at proof time.* The proof says: "I know some `modelHash` such that this commitment is enrolled." It does not say: "The model currently producing tokens is the one whose hash I'm claiming." An operator with an EdDSA key can issue credentials for model hash `H_safe` and run model hash `H_jailbroken`; the circuit is satisfied either way because the operator signed `H_jailbroken` into a new credential commitment and enrolled it.

  SPIRE's workload attestation does not have this problem. A SPIRE agent running on the same node performs kernel-level attestation: it reads `/proc/<pid>/exe`, checks the binary hash, verifies against the expected selector. The resulting SVID is grounded in the OS's process table and (optionally) a TPM PCR quote. There is no "self-assertion" step. The workload cannot lie about its own binary.

  The construction's §8 claim "No binding to model hash or runtime operator key at inference time" as a gap against OAuth is correct — but the construction doesn't close it either. It moves the binding from OAuth's `client_id` string to a Poseidon hash, but the provenance of that hash remains operator-asserted, not attestation-grounded.

- **Why it works / fails:** The construction survives the cryptographic reduction (a forged proof requires breaking Groth16 soundness or Poseidon), but the *semantic* binding between `modelHash` and the executing model is outside the threat model. The reduction in §4 says the adversary doesn't control the operator's EdDSA private key — but the adversary *is* a compromised operator in realistic deployments. An operator who enrolls a rogue model hash produces a valid proof. The circuit cannot detect this.

- **In-threat-model?** No. The construction must address: how does the RS gain assurance that `modelHash` was measured by a trusted attestor (TEE, SPIRE agent, TPM), not just asserted by the agent itself? Without this, §7's "runtime model identity binding" property (Table §8) is a semantic claim, not a cryptographic one.

---

### Attack 2: Scope Commitment Breaks SP Game Under Implication-Constrained Enumeration

- **Attack:** The public output `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` is present whenever delegation chain tracking is enabled (§2, Public Outputs; §4, Note on scopeCommitment). The `credentialCommitment` is a Merkle leaf — publicly visible on-chain. An observer who reads the registry has `credentialCommitment`. Given `scopeCommitment = Poseidon2(x, credentialCommitment)` with known `credentialCommitment`, recovering `x = permissionBitmask` is a preimage problem over 64-bit space.

  The SP game (§3) claims `|Pr[c' = c] - 1/2| ≤ negl(λ)` because "the adversary cannot invert Poseidon." However, Poseidon's preimage resistance is stated over the full BN254 scalar field (~254 bits). Here the preimage is drawn from a 64-bit space — 18.4 quintillion candidate values. With the cumulative bit encoding constraints (G6) applied:

  - `bit4 → bit3 → bit2` enforces a lattice; not all 2^64 bit patterns are valid.
  - For the 8-bit permission model as described in CLAUDE.md, valid configurations satisfying G6 are fewer than 256 and enumerable in milliseconds.
  - Even for a genuine 64-bit space, the implication closure rules (financial tier hierarchy, etc.) reduce valid combinations to a structured and potentially small set.

  The construction's §4 SP game reduction relies on A4 (ZK simulation) and A2 (Poseidon collision resistance), but it does not account for the low effective entropy of `permissionBitmask` given G6 constraints. A distinguisher doesn't need to break Poseidon — it just needs to compute `Poseidon2(b, credentialCommitment)` for all valid `b` values and compare against the observed `scopeCommitment`. The lattice of valid permissions makes `b` guessable in O(valid configurations) Poseidon evaluations.

- **Why it works / fails:** The formal SP game is stated over arbitrary bitmasks `b₀ ≠ b₁`. But the game setup doesn't constrain `b₀`, `b₁` to be indistinguishable under G6. The proof of SP relies on the simulator (A4) producing indistinguishable `scopeCommitment` — but `scopeCommitment` is a *deterministic* function of `permissionBitmask`, so two agents with different bitmasks always produce different `scopeCommitment` values. The game's privacy guarantee only holds when `scopeCommitment` is omitted (§4, Note); the table in §8 does not distinguish these two modes.

- **In-threat-model?** Partially. The construction acknowledges `scopeCommitment` leaks information but treats it as optional. It must either: (a) remove `scopeCommitment` from the public outputs table unconditionally and note the delegation chain limitation, or (b) restate the SP game with and without `scopeCommitment` and quantify the leakage in bits given G6's reduction of valid configurations. The 8-bit permission model described in CLAUDE.md makes this a practical attack, not a theoretical one.

---

### Attack 3: WIMSE Workload-to-Workload Token Exchange Already Achieves AS-Blind Presentation at the Right Layer

- **Attack:** Section §8's "architectural" gap column claims: "Agent cannot choose disclosure subset at runtime without AS pre-configuring it." This is true of RFC 7662, but `draft-ietf-wimse-arch` §4.2 (Workload-to-Workload authentication) defines a pattern where workloads exchange short-lived JWT SVIDs directly, the receiving workload verifies against a locally cached SPIFFE trust bundle (JWKS), and the issuing AS is not contacted at verification time. Combine this with WIMSE's `transaction-token` (TTv2, draft-ietf-oauth-transaction-tokens) for selective claim propagation in a service mesh, and you have:

  1. **AS-blind verification at the RS**: the RS caches the SPIFFE JWKS bundle (rotated out-of-band via the SPIRE server federation API, not per-request). Verification is local.
  2. **Selective disclosure**: JWT SVIDs carry a `scope` claim. WIMSE transaction tokens can carry a minimal scope set per workload-to-workload hop. The AS pre-configures what each workload can request — yes — but this is no different from the operator enrolling a credential in Bolyra's Merkle tree: *someone* defines the permission set at issuance time in both models.
  3. **Compromised AS**: SPIFFE's node attestation means the trust anchor is the SPIRE server's CA, not the token issuer. If the SPIRE server is compromised, you have the same problem as a compromised on-chain registry operator in Bolyra. The threat models are structurally isomorphic.

  The construction's claim of "adversarial-AS soundness" (§1, §3, §8) requires the AS to be *actively adversarial* — not just unavailable, but lying about scope membership. WIMSE's trust anchor is the SPIRE CA certificate in the trust bundle. To lie about scope membership, a WIMSE adversary must compromise the SPIRE CA — equivalent to Bolyra's requirement to compromise the on-chain registry operator's EdDSA key and forge a Merkle leaf insertion. These are the same attack, rooted in different HSMs.

- **Why it works / fails:** The attack works to the extent that WIMSE + SPIFFE handles the production threat model (AS is unavailable or slow) equally well, without a new trusted setup, without a ZK proving overhead (~500ms rapidsnaark per §6), and within the existing IETF standards track. The construction's genuinely novel property is the *cryptographic bitfield predicate* — the RS verifies a bitwise AND over a committed value. WIMSE cannot do this: JWT scope is a string set, not a committed bitfield, and no composition of WIMSE primitives evaluates `bitmask & requiredMask == requiredMask` over committed private data. But the construction overstates its novelty by framing AS-blindness as its primary differentiator when WIMSE covers that case without ZK.

- **In-threat-model?** Yes, for the genuinely ZK-specific properties. The construction survives this attack on its bitfield predicate claim. But it **must** narrow its uniqueness claim: WIMSE achieves AS-blind workload-to-workload authentication. Bolyra's unique property is *cryptographically committed bitfield evaluation with implication closure in a setting where the operator/AS is adversarial and the RS trusts only the on-chain root.* The current §1 claim leads with "no AS roundtrip" as primary differentiator — WIMSE already gives you that.

---

### Attack 4: The 30-Root History Buffer Creates an Unspecified Revocation Window

- **Attack:** §5 (Bolyra Primitive Mapping) notes the on-chain root anchor uses an "agent root history buffer (30-entry circular)" from spec §3.1. Step 5 of the Verification Protocol (§2) says the RS accepts a proof against `agentMerkleRoot` — but with a 30-entry circular buffer, the RS must accept any of the last 30 Merkle roots as valid. When an agent is revoked (its leaf removed, a new root posted), the revoked agent can continue to generate valid proofs against any of the 29 prior roots that are still within the acceptance window. The RS verifying against a cached older root cannot distinguish a revoked agent from a valid one.

  SPIFFE SVIDs use TTL-based revocation: a short-lived SVID (default 1 hour) expires automatically. SPIRE rotates SVIDs continuously. A revoked workload's next rotation request is denied. The maximum revocation window is bounded by the SVID TTL — a configurable, operationally auditable parameter.

  The Bolyra construction has no equivalent bound. "30 roots" is not a time bound — it is a root-update-count bound. If the agent tree updates once per week (plausible for a large enterprise with infrequent enrollment events), a revoked agent has a **30-week** window to continue presenting valid proofs to an RS with a slightly stale cached root. The NFCU scenario in §7 (50 internal services, 10,000 enrolled agents) would produce infrequent root updates, maximizing this window.

  Furthermore, Step 1 says "RS reads `agentMerkleRoot` from on-chain registry (or a cached signed root)" — the "cached" path is undefined. How stale can a cached root be? The construction doesn't specify a maximum root age.

- **Why it works / fails:** The SSU game (§3) defines the adversary winning if a non-member proof verifies. But the SSU game is defined relative to a fixed `agentMerkleRoot*` — it doesn't model the multi-root acceptance window. A revoked agent with a proof against root `r_{t-15}` is a *member* at `r_{t-15}` and a *non-member* at the current root `r_t`. If the RS accepts `r_{t-15}` as a valid anchor, the SSU game says the adversary has not won (the commitment is a valid leaf at that root), but the revocation has been bypassed. This is outside the formal game but is the operationally relevant attack.

- **In-threat-model?** No. The construction must specify: (a) the maximum root acceptance age in wall-clock time (not root count), (b) the minimum root update frequency required to bound the revocation window, and (c) RS-side staleness rejection policy. Without these, the revocation semantics are undefined and the 30-root buffer is a compliance gap in the GLBA §501(b) scenario described in §7 — a bill-pay RS accepting 30-week-old roots for a revoked agent's credential is not "cryptographic compliance."
