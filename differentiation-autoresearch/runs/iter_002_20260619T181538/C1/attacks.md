# Tier 3 Adversarial — C1 Selective scope proof

## Persona: auth0_pm

---

### Attack 1: The Latency Tax Kills the Integration Story

- **Attack:** Section 6 claims "< 500 ms with rapidsnark" as the proof generation target. But rapidsnark is a native binary (`circuits/build/rapidsnark_prover`) that must be co-located with the agent. In the deployment scenarios that actually exist today — AWS Lambda, Cloudflare Workers, Azure Container Apps, any serverless or ephemeral compute — you cannot ship a native proving binary. You're back to snarkjs, which puts you at 3+ seconds. WorkOS and Auth0 issue tokens in under 100 ms from any runtime environment, including edge. The construction's performance claim is accurate only for a narrow class of always-on, bare-metal agents. For the majority of agentic compute deployed in 2026, the latency tax is 30–50×, not 5×.

- **Why it works / fails:** The construction does not bound which runtimes are valid deployment targets for the prover. It presents the rapidsnark number as the headline without qualifying that it requires native binary co-location. The scenario (Section 7) depicts Columbia CU's agent as if it's a persistent server process, which sidesteps the question entirely. The attack succeeds against any operator using serverless or managed container runtimes — which is most of them.

- **In-threat-model?** No. The construction must address this. Either (a) constrain the deployment model explicitly and accept that you're targeting a narrower set of operators, or (b) provide a proof delegation path (agent delegates witness generation to a trusted prover service) and address the trust model of that delegation. Leaving it implicit invites rejection at the integration design review.

---

### Attack 2: The Adversarial-AS Scenario Is a Strawman in the Target Market

- **Attack:** The entire adversarial-AS soundness argument (Section 3, Section 8 Property 3) assumes that Columbia CU's AS could collude against partner credit unions, or lie about an agent's permissions. In practice, credit unions don't run bespoke authorization servers. They run Okta, Azure AD B2C, Auth0, or a CUSO-shared identity platform (e.g., Symitar's integration layer). These are third-party commercial products with their own SOC 2 attestations, liability insurance, and NCUA examination exposure. The threat model you're defending against — "a fully compromised AS cannot forge a valid proof" — already has a market solution: don't trust a solo-founder AS, trust a commercial one with audit history. You've built an elaborate ZK construction to solve a trust problem that the market solved by buying Okta.

- **Why it works / fails:** This is a genuine threat-model mismatch. The construction is technically sound for an adversarial-AS environment, but the Section 7 deployment scenario explicitly uses a credit union context where the realistic AS is a commercial federated IdP, not a custom adversarial server. The attack lands hardest at the buyer stage — a CISO will ask "who is the AS in this scenario?" and when the answer is "Okta," the adversarial-AS argument collapses. The construction does not distinguish between the theoretical adversary capability (AS fully controlled) and the realistic enterprise environment.

- **In-threat-model?** No. The construction should either (a) explicitly scope the adversarial-AS claim to the class of operators running self-hosted custom ASes (narrowing the TAM but maintaining honesty) or (b) identify the realistic weaker-AS threat (AS is honest-but-curious, AS leaks introspection logs to competitors) that still motivates ZK even in a world with commercial IdPs. The current framing overclaims the threat and undersells the realistic differentiation.

---

### Attack 3: Replacing AS Availability with Chain Availability Is a Lateral Move, Not an Upgrade

- **Attack:** Section 8 Property 1 and Section 7 cite a "CrowdStrike-style outage" as the motivating scenario — Columbia CU's AS goes offline for 14 hours, locking out consortium agents. The construction's fix is to have the RS verify against `onChainAgentRoot` read from the Bolyra on-chain registry. But now the RS has a new availability dependency: the Base L2 RPC endpoint. The construction acknowledges a "30-entry root history buffer" (Section 5 table), meaning the RS caches up to 30 root transitions. If the chain is unavailable or lagged beyond the buffer window — which is unspecified in duration — the RS cannot verify freshness of the root. More critically, the 30-entry buffer creates a revocation lag: a compromised credential cannot be instantly invalidated. The operator must wait for the next Merkle root update to propagate, and RSes caching stale roots will continue accepting proofs against revoked credentials during that window. Auth0's token revocation is synchronous and immediate.

- **Why it works / fails:** The construction trades a well-understood availability problem (managed IdP SLA) for a less-understood one (L2 finality + RPC availability + root buffer expiry). The revocation lag is a real security regression relative to synchronous introspection, not a theoretical concern. A credit union with NCUA oversight cannot have a "revocation propagates eventually" posture for agent credentials with `FINANCIAL_UNLIMITED` permissions. This attack succeeds as a procurement objection and as a genuine security gap.

- **In-threat-model?** No. The construction must specify: (a) the root buffer TTL policy (how long a cached root is valid before the RS must refresh), (b) the revocation latency SLA and whether it meets NCUA third-party risk management requirements, and (c) the fallback behavior when chain RPC is unavailable. Without these, the availability argument inverts — the construction has worse availability guarantees than a managed IdP for the scenarios that matter to regulated operators.

---

### Attack 4: Procurement Kills This Before Cryptography Is Ever Evaluated

- **Attack:** The construction is technically rigorous. The security argument in Section 4 is coherent. None of that matters at the procurement stage. A credit union's vendor risk management process requires: SOC 2 Type II report, penetration test from a named third-party firm, D&O and cyber liability insurance, an SLA with financial penalties, a named security contact for incident response, and — for any protocol touching NCUA-regulated member data — evidence that the vendor has passed NCUA third-party due diligence (NCUA Letter 01-CU-20 and the updated 2023 guidance). A solo founder cannot provide any of these. WorkOS, Auth0, and Stytch all provide these as baseline. The construction can be the most elegant ZK protocol in the field and still lose every enterprise deal to "paste-an-API-key" from a SOC 2-certified vendor, because the buyer's procurement checklist doesn't have a row for "zero-knowledge soundness."

- **Why it works / fails:** This attack is not about the construction's cryptographic properties — it's about the go-to-market reality. The construction's strongest differentiation (AS-blind, adversarial-AS soundness, constant-size proof) is evaluated by cryptographers and protocol engineers, who are rarely the economic buyer at a credit union. The CISO and VP of Operations are the buyers, and their decision criteria are regulatory compliance, vendor financial stability, and support SLAs. The construction addresses none of these in Sections 1–8. The Section 7 regulatory alignment paragraph cites "NCUA Letter 24-CU-03" — but a letter citing a novel ZK protocol from an unaudited vendor will not satisfy an NCUA examiner; it will trigger a finding.

- **In-threat-model?** No, but this is intentional — it's out of scope for the cryptographic construction document. However, the construction's framing (Section 7) presents the credit union scenario as a deployment-ready use case, which makes the procurement gap an active claim the document is making. Either remove the Section 7 enterprise framing and scope the document as a cryptographic specification, or add a Section 9 that addresses the trust-bootstrap problem: how an operator builds sufficient confidence in the Bolyra protocol to adopt it before SOC 2 exists.


## Persona: cryptographer

Applied cryptographer. IACR publications. Reviews for CRYPTO/EUROCRYPT/S&P. My stance: unless I see a tight game definition and a reduction sketch, it is marketing. The construction has both — let me break them.

---

### Attack 1: Chosen-Predicate Bit Extraction

**Attack:**
The ScopeExtraction game (§3) is fatally underspecified. The adversary is given a **single** challenge proof over two bitmasks B0, B1 that both satisfy the same predicate R. The game then asks whether A distinguishes them. This models only one round with one predicate.

But the oracle phase (game step 3) lets A query the **honest agent** for proofs on predicates of A's choice. A now runs the following:

```
For i in {0, 1, ..., 63}:
    query agent with requiredScopeMask = (1 << i)
    if agent returns a valid proof → bit i is set
    if agent refuses / proof fails → bit i is cleared
```

After 64 queries, A has reconstructed the full `permissionBitmask` with probability 1. The privacy game does not restrict this because its winning condition is only stated for the challenge phase. But reconstruction before the challenge trivially breaks the stated privacy guarantee.

**Why it works:** The agent cannot produce a valid G5 witness for a predicate that sets bit i if `permBits[i] = 0` — the constraint `requiredBits[i] * (1 - permBits[i]) === 0` is unsatisfied. An agent unwilling to expose its failure to generate a proof (or one that gracefully returns "cannot prove") leaks a 1-bit oracle per query. A cooperative agent trying to generate a proof for an unsatisfied predicate simply cannot, and either times out or aborts.

**Why the privacy reduction fails:** §4 reduces ScopeExtraction to PLONK ZK, which says the proof transcript `pi` is simulatable. Correct — for a **fixed** public input assignment. But the game allows chosen-predicate oracle queries that act as a membership oracle over the bitmask. PLONK ZK says nothing about what the adversary learns from the **existence or nonexistence** of a valid proof. The simulator only simulates accepting transcripts; it cannot simulate a rejection.

**Required fix:** The privacy game must be upgraded to a **chosen-predicate zero-knowledge** definition, and the agent must be specified to return a constant response (e.g., a simulated proof for a randomly sampled satisfying bitmask) whenever the predicate is not satisfied. Otherwise the "reveals nothing beyond predicate satisfaction" claim in §1 is false.

**In-threat-model?** No. The construction must address this.

---

### Attack 2: Proof Freshness / Timestamp Ambiguity

**Attack:**
G7 checks `currentTimestamp < expiryTimestamp`. `currentTimestamp` is listed as a **public input** — which in PLONK means it is part of the proof's input vector and is committed inside the Groth16 / PLONK computation. Whoever constructs the proof must fix `currentTimestamp` at prove-time.

The verification protocol (§2) says in step 2 that "RS constructs public inputs: `[requiredScopeMask, currentTimestamp, onChainAgentRoot]`." But in step 3, "RS **receives** proof pi and public outputs `[scopePredicateHash, agentNullifier]` from the **agent**."

Here is the ambiguity: **who fixes `currentTimestamp` in the proof?** If the agent generates the proof offline — as explicitly permitted ("agent generates this proof locally") — then the agent, not the RS, chooses `currentTimestamp` at proof-generation time. The RS only sees the proof after the fact and checks the public signal matches "now." But in PLONK, the "public input" is embedded in the proof, and verification merely checks consistency. If the protocol does not specify that the RS asserts `currentTimestamp == now()` independently (with a clock tolerance), then:

1. Agent generates proof with `currentTimestamp = T_issue` days before presentation, with `T_issue < expiryTimestamp`. Valid proof.
2. At access time `T_present >> T_issue`, the agent submits the old proof. The embedded `currentTimestamp = T_issue` still passes G7.
3. If the RS just calls `Verify(vk, pi, signals)` and accepts, the proof is **replayed** without revocation.

The `agentNullifier = Poseidon2(credentialCommitment, requiredScopeMask)` does NOT include `currentTimestamp`, so the nullifier does not distinguish a fresh proof from an old one for the same predicate. Rate-limiting on `agentNullifier` blocks second uses but does not enforce freshness — a nullifier-cleared replay (new RS, same predicate) succeeds indefinitely until expiry.

**Why it works:** The verification protocol does not require the RS to assert `currentTimestamp == now()` before calling `Verify`. `scopePredicateHash = Poseidon3(requiredScopeMask, credentialCommitment, currentTimestamp)` binds to the embedded timestamp, but the RS has no obligation to check this value equals "now." A proof generated months ago with a far-future `expiryTimestamp` can be replayed at any RS.

**Reduction failure:** The SelectiveScopeForgery game (§3) does not model replay. The game's winning condition is "does the agent have the required permissions" — not "was this proof generated freshly." Replay attacks are outside the game's scope by construction, meaning the game is under-modeled.

**Required fix:** The RS must be specified to supply `currentTimestamp` as a challenge nonce *before* proof generation (i.e., challenge-response: RS sends `(requiredScopeMask, nonce_timestamp)`, agent generates proof over these), or the nullifier must include `currentTimestamp`. The verification protocol must mandate `currentTimestamp_in_proof == RS_clock ± delta`. Without this, the construction is not a ZK auth protocol — it is a ZK capability token that never expires before credential expiry.

**In-threat-model?** No. The construction must address this.

---

### Attack 3: Subverted SRS — Forging Under Known Toxic Waste

**Attack:**
The construction uses PLONK with `pot16.ptau` as the universal SRS (§5, §6). KZG-based PLONK requires a powers-of-tau ceremony that produces `([τ^0]₁, [τ^1]₁, ..., [τ^{n-1}]₁, [τ]₂)` where τ is the **toxic waste** that must be destroyed. If τ is known, the adversary can compute:

```
For any circuit relation R and any public input x:
    Construct a fake proof pi* such that Verify(vk, pi*, x) = ACCEPT
    without knowing any witness w satisfying R(x, w).
```

This is not a circuit-specific attack — it applies to any KZG-based polynomial commitment and breaks knowledge soundness entirely.

The construction states in §3 (Adversary model): "The adversary does NOT control: The RS's local copy of the PLONK verification key." But the adversary **does** control the AS. If the AS participated in the `pot16.ptau` ceremony and retained τ (or obtained it from a compromised ceremony participant), then Assumption 1 (knowledge soundness of PLONK) is violated. The adversary forges an accepting proof for `permissionBitmask` satisfying `requiredScopeMask` without possessing any enrolled credential.

**Why it matters:** The construction's claim of "adversarial-AS soundness" (§8, Property 3) explicitly includes the case where "the AS is fully adversarial." But the AS is a plausible contributor to or corruptor of the `pot16.ptau` ceremony, especially in a deployment where Columbia CU (§7) ran or participated in the ceremony. A ceremony with one corrupt participant is a fully compromised SRS in KZG.

**What the construction says:** §4 Assumption 1 states "Knowledge soundness of PLONK (with universal SRS): Any PPT prover that produces an accepting proof knows a valid witness." This assumption is **false** if τ is known to the adversary. The reduction sketch in §4 opens with "By PLONK knowledge soundness... extract witness w" — this step fails unconditionally when the SRS is subverted.

**In-threat-model?** No. The adversarial-AS threat model must either (a) explicitly exclude AS participation in the SRS ceremony, (b) specify that the `pot16.ptau` was generated by a multi-party computation with at least one honest participant outside the AS's control (e.g., the Hermez/Ethereum ceremony), or (c) switch to a transparent proving system (STARKs, Bulletproofs) that has no trusted setup. Using `pot16.ptau` sourced from a ceremony the AS touched directly contradicts the adversarial-AS claim.

---

### Attack 4: Adversarial Operator Collapses the "Adversarial-AS" Claim

**Attack:**
The construction's Property 3 (§8) states: "A malicious AS can lie. BBS+ credentials are still AS-issued; a malicious issuer can issue fraudulent credentials." This is framed as a weakness of the baseline. The construction claims to fix this because "credential commitment is enrolled on-chain... the AS cannot unilaterally alter blockchain consensus."

But in §2, G3 is an **EdDSA signature by the operator**: `EdDSA.Verify((operatorPubkeyAx, operatorPubkeyAy), credentialCommitment, (sigR8x, sigR8y, sigS))`. The `operatorPubkeyAx, operatorPubkeyAy` are **private inputs**. The RS never sees which operator signed the credential. The RS only verifies that some operator signed and that the credential commitment is enrolled on-chain.

Now consider the threat model: the AS is "fully adversarial, colluding, compromised, or offline." The AS controls `permissionBitmask` assignment. In the Columbia CU deployment (§7), who enrolls the credential? Columbia CU's operator enrolls `Poseidon5(modelHash, opAx, opAy, 0b10010111, expiry)`. The operator key belongs to Columbia CU — which IS the AS.

A fully adversarial AS/Columbia CU can:
1. Generate operator keypair `(sk_op, pk_op)`.
2. Compute `credentialCommitment' = Poseidon5(modelHash, pk_op_Ax, pk_op_Ay, 0b11111111, expiry)` (all permissions, including `ACCESS_PII`).
3. Sign with `sk_op`: valid EdDSA signature.
4. Enroll `credentialCommitment'` on-chain alongside the legitimate credential.
5. At partner CU RS, present a `SelectiveScopeProof` using `credentialCommitment'`, proving `ACCESS_PII` satisfaction.

The RS verifies: (a) EdDSA signature is valid ✓, (b) Merkle proof against on-chain root ✓, (c) bitmask satisfies `requiredScopeMask` ✓. The RS accepted a fraudulent elevated-permission credential. The adversarial AS inflated its own permissions, which is **exactly** the attack BBS+ also suffers from an adversarial issuer.

**Why the reduction fails:** The SelectiveScopeForgery game (§3) defines forgery as producing a proof where "the honest agent's permissionBitmask does NOT satisfy `requiredScopeMask*`." But this game only protects the **honest agent's commitment C***. It says nothing about an adversarial operator enrolling a fresh fraudulent commitment with inflated permissions. Case 2b of the reduction sketch explicitly acknowledges: "A is using a different enrolled agent's credential — not a forgery against the honest agent, but a legitimate proof for a different agent." The game lets this through.

**Required fix:** The threat model must specify who controls operator key issuance and enrollment. If the AS controls enrollment, "adversarial-AS soundness" degrades to "the AS cannot modify already-enrolled commitments" — not "the AS cannot grant inflated permissions." The distinction matters enormously. The correct claim is: the construction provides **commitment binding** (once enrolled, the bitmask is fixed) and **AS-blind presentation** (no AS roundtrip), but it does NOT provide protection against a malicious enrollment authority issuing fraudulent elevated-permission credentials. Property 3's comparison to BBS+ is misleading: BBS+ is also commitment-binding post-issuance; the real difference is AS-blind presentation, which must be claimed more precisely.

**In-threat-model?** No. "Adversarial-AS soundness" as stated implies protection against permission inflation, which the construction does not provide when the AS controls the operator key. The threat model must be tightened to scope the AS adversary as "cannot modify on-chain state after enrollment" rather than "fully adversarial."


## Persona: cu_ciso

---

### Attack 1: The Zero-Knowledge Audit Gap

- **Attack:** Section 7 claims "NCUA examiners reviewing consortium data-sharing agreements can verify that only cryptographically proven minimum-necessary permissions were exercised." But when a member calls at 2am claiming an agent pulled their credit file they didn't authorize, my incident responders have a `scopePredicateHash = Poseidon3(requiredScopeMask, credentialCommitment, currentTimestamp)` and an `agentNullifier`. These are opaque field elements. My Tier 1 ops team cannot look up "which agent accessed member #4471's record at 02:17 UTC." The construction explicitly states the RS "learns nothing about the agent's full permission set, model hash, operator key" — that's also true of my SOC and my NCUA examiner. NCUA Part 748 Appendix B requires a documented audit trail mapping access events to identifiable actors. The zero-knowledge property that makes this construction novel is precisely what destroys my examiners' ability to reconstruct a breach timeline. The construction provides a *cryptographic* log, not a *regulatory* one.

- **Why it works:** The construction's threat model (Section 3) never mentions a lawful investigation adversary who needs to pierce the ZK veil with CU cooperation. The `agentNullifier` is designed to be unlinkable to `modelHash` by the RS — but my examiners will demand that linkage under subpoena. The construction has no "break-glass" deanonymization path, no mapping table from nullifier → operator identity, and no described process for correlating `scopePredicateHash` values back to a specific agent instance during forensic review.

- **In-threat-model?** No — construction must address. Required: a documented escrow mechanism (e.g., operator publishes a `(nullifier → agentId)` mapping in a regulator-accessible registry) or an explicit statement that Columbia CU's operator log serves as the audit layer. Without this, NCUA Part 748 §III.C incident response requirements are unmet, and this cannot pass examination.

---

### Attack 2: Operator Key Custody is Hand-Waved

- **Attack:** The construction's entire soundness argument reduces to EdDSA-Poseidon unforgeability on Baby Jubjub (Assumption 4, Section 4). The operator's private key signs every `credentialCommitment`. Section 2 lists `sigR8x, sigR8y, sigS` as private inputs but never asks: where does the operator private key live at signing time? If it's a `.env` file on an EC2 instance running the agent orchestrator, I've lost. If it's a cloud KMS, who has admin access? If the key is rotated, does every extant credential commitment become invalid (requiring re-enrollment on-chain with gas costs)? GLBA Safeguards Rule §314.4(c) requires encrypted storage and documented access controls for credentials used to access member data. My vendor management policy requires documented key lifecycle procedures from all third parties. Section 5's "Bolyra primitive mapping" says nothing about operator key custody.

- **Why it works:** The construction's security game (Section 3) grants the adversary control of the AS but explicitly excludes "the honest agent's private inputs." In production, the operator key IS a private input, and its custody is off-circuit. The threat model assumes away the exact HSM/KMS question my GLBA examiner will ask first.

- **In-threat-model?** No — construction must address. Required: a concrete key management section specifying at minimum: HSM or cloud KMS requirement, key rotation procedure with on-chain re-enrollment mechanics, and access control attestation that satisfies GLBA §314.4(c). Without this, the cryptographic soundness argument is disconnected from the operational reality my examiners evaluate.

---

### Attack 3: Base L2 Sequencer Liveness vs. NCUA Business Continuity Requirements

- **Attack:** Section 5 states the RS reads `onChainAgentRoot` from the `BolyraRegistry` with a "30-entry root history buffer." The construction promotes AS-blind operation as a resilience advantage (Section 7: "During a CrowdStrike-style outage, Columbia CU's AS goes offline for 14 hours"). But the RS now has a hard dependency on Base L2 RPC availability to obtain any valid `onChainAgentRoot`. Base's centralized sequencer has had documented outages. If Base's sequencer goes down for 4 hours and my consortium has 12 RSes all reading chain state, every agent-driven loan pre-qualification stops. The 30-entry root history buffer only protects against stale roots — it does not protect against my local Base node being unavailable. The construction trades AS availability risk for L2 sequencer availability risk, and neither the SLA nor the failure mode is analyzed. My NCUA Business Continuity Plan (NCUA Part 749) requires documented RPO/RTO for all systems touching member data access. An undocumented dependency on a blockchain sequencer does not meet this bar.

- **Why it works:** The construction's Section 7 explicitly claims the Bolyra approach solves the "AS availability" problem but never quantifies the replacement dependency's SLA. Base Sepolia is a testnet (named in `CLAUDE.md`); the production deployment target is unspecified. A CISO asking "what's the SLA?" gets no answer from the construction.

- **In-threat-model?** No — construction must address. Required: (1) documented RPC provider SLA with fallback node configuration, (2) analysis of root history buffer TTL vs. maximum tolerable sequencer downtime, (3) explicit RPO/RTO statement for comparison against NCUA Part 749 continuity requirements.

---

### Attack 4: Cross-CU Nullifier Correlation Violates GLBA Affiliate Sharing Rules

- **Attack:** In the Section 7 consortium scenario, 12 credit unions operate as independent RSes. Each RS stores `agentNullifier = Poseidon2(credentialCommitment, requiredScopeMask)` for rate-limiting (Section 2, G9). Since `credentialCommitment` is deterministic for a given agent credential and `requiredScopeMask` is RS-specified, any two RSes that specify the *same* `requiredScopeMask` will observe the *same* `agentNullifier` for the same agent. If the 12 consortium CUs share nullifier tables (a natural operational choice for consortium-wide rate-limiting), they have a stable pseudonymous identifier that tracks a specific Columbia CU agent across all 12 institutions. Under GLBA §502, sharing a member-affiliated agent's activity record across non-affiliated financial institutions requires opt-out notices or an exception. Even if consortium members are contractually affiliated, state-level privacy laws (e.g., California CCPA for agent operators domiciled there) may treat cross-institutional behavioral tracking as a data sale. The construction's privacy guarantee is framed RS-to-RS (one RS learns nothing), but says nothing about the consortium-level correlation surface it creates.

- **Why it works:** The privacy game in Section 3 (ScopeExtraction) is defined against a single RS. It explicitly asks whether one RS can distinguish two bitmasks — not whether two RSes can correlate the same agent across visits. The nullifier design is identical for identical inputs by construction, enabling exactly this cross-RS linkage. Section 7's deployment scenario creates the consortium structure that makes this attack concrete, without acknowledging it.

- **In-threat-model?** No — construction must address. Required: either (a) make the nullifier RS-specific by including an RS identifier in G9: `Poseidon3(credentialCommitment, requiredScopeMask, rsId)`, eliminating cross-RS correlation at the cost of per-RS rate-limit tables, or (b) explicitly analyze consortium-level privacy and document GLBA compliance posture. As written, the construction enables surveillance of agent behavior across financial institution boundaries, which is the opposite of the privacy guarantee marketed to CISOs.


## Persona: rfc7662_advocate

*Ten years shipping introspection endpoints. I have seen every ZK claim before. Let me read this construction carefully.*

---

### Attack 1: Deterministic Nullifier Enables Cross-RS Linkability

- **Attack:** The construction defines `agentNullifier = Poseidon2(credentialCommitment, requiredScopeMask)` (Section 2, G9). Because `credentialCommitment` is fixed per credential and `requiredScopeMask` is determined by what the RS requires (not by the agent), this nullifier is **identical across every RS that presents the same required mask**. In the consortium scenario (Section 7), if 6 of the 12 partner credit unions all require `requiredScopeMask = 0b00000101`, they each receive the same `agentNullifier`. They can collude — or a passive observer watching all 12 RS logs can determine — that the same agent visited all 6 RSes that week. The construction claims in Section 7 that "the RS learns nothing about... any other permission," but it says nothing about cross-RS session unlinkability.

- **Why it fails against the construction:** The privacy game in Section 3 only asks whether an adversary can distinguish two bitmasks *given a single proof against a single RS*. It does not model a multi-RS adversary who aggregates `agentNullifier` values across RSes. The ScopeExtraction game is strictly single-RS. Cross-RS linkability is not addressed anywhere in the security argument.

- **Contrast with baseline:** OIDC Pairwise Pseudonymous Identifiers (PPID, Section 8.1 of OIDC Core) give each RS a distinct sub value derived per AS-RS pair. RFC 8707 audience binding further partitions tokens. A DPoP-bound token has a distinct `jkt` fingerprint per session. The baseline has a defined mechanism for cross-RS unlinkability; the construction has a deterministic cross-RS correlator baked into its public output.

- **In-threat-model?** No — cross-RS linkability is not in the stated security games. **Construction must address this** or retract the implicit privacy claim in the consortium scenario. Simplest fix: salt the nullifier with a per-session nonce or per-RS identifier. But then rate-limiting semantics change.

---

### Attack 2: "Runtime-Adaptive Predicate" Is an Illusion — AS-Side Policy Subsumes It

- **Attack:** Section 8, Property 2 claims the baseline "cannot evaluate `bitmask & requiredMask == requiredMask`... at verification time" because JWT introspection "returns a fixed scope string." This is a strawman of RFC 7662 as actually deployed. The AS-side introspection policy (RFC 7662 §2.1: "the authorization server MAY decide to tailor the response for the requesting resource server") already filters the response per RS. In FAPI 2.0 deployments, each RS registers its `resource` URI (RFC 8707) and the AS returns only the scopes relevant to that RS. The RS never sees the agent's full permission set. The scope string is not "fixed" — it is dynamically computed per RS at introspection time.

  More fundamentally: the construction's own scenario undermines the "runtime-adaptive" claim. The RS in Section 7 specifies `requiredScopeMask = 0b00000101`. That mask is **static per RS endpoint** — it is the RS's policy, not derived from runtime state. No RS says "I need different bits depending on what you're about to do" after the HTTP request arrives. The predicate is determined before the agent contacts the RS. An AS with per-RS scope policy could return `["read_data","financial_small"]` to the partner CU's RS introspection request — exactly matching the predicate — without revealing that the agent also holds `financial_unlimited` and `access_pii`. This is standard AS-side minimum-disclosure policy.

- **Why it partially fails:** The construction's advantage in Property 2 is real only for the implication-closure enforcement (`bit4 -> bit3 -> bit2`, G6). AS-side policy returns a scope list; verifying that the list satisfies implication rules requires either (a) the AS enforcing it before responding, which it can, or (b) the RS enforcing it locally on the returned scopes, which is trivial. The implication rules are 3 lines of RFC logic, not a ZK primitive.

- **In-threat-model?** Partially. The AS-blind property (no AS contact) is real and not replicated by the baseline. But the "runtime-adaptive predicate" framing inflates this into something that sounds computationally novel when it is merely a workflow difference (predicate given at verification time vs. filtered at issuance time). **Construction should retract the "runtime-adaptive" language** and restate the actual advantage: predicate can be set by the RS at presentation time with zero AS involvement, which is categorically different from AS-filtered introspection even if the predicate values are effectively static per RS.

---

### Attack 3: Adversarial-AS Soundness Collapses to Adversarial-Operator Soundness

- **Attack:** Section 3 places the AS in the adversary's control but excludes "the RS's local copy of the PLONK verification key" and "the honest agent's private inputs." The security argument in Section 4 then reduces forgery to PLONK knowledge soundness + Poseidon collision resistance. This is correct *if the on-chain enrollment is honest*. But who calls the enrollment transaction? The **operator** — the entity holding `operatorPubkeyAx / operatorPubkeyAy` — signs the credential commitment and submits it to the Bolyra registry contract.

  In the consortium threat model, the concern is that Columbia CU's AS is semi-trusted. But Columbia CU's **operator key** performs the enrollment. These are the same trust principal. A rogue Columbia CU operator can:
  1. Create a credential commitment with `permissionBitmask = 0b11111111` (all permissions).
  2. Enroll it on-chain legitimately — the registry contract has no policy about what permissions are acceptable.
  3. The partner RS verifies the on-chain root and concludes the credential is valid.
  4. The partner RS is now cryptographically assured that an agent with all permissions is legitimately enrolled — even if Columbia CU never intended to grant those permissions.

  The construction defends against "AS lies about scope in an introspection response." It does not defend against "operator enrolls an overclaimed credential." These are the same attacker in the consortium scenario. The on-chain registry is a bulletin board, not a policy enforcer.

- **Why it partially fails:** If there is a separate enrollment authority (e.g., a consortium-level multisig or a DAO governance contract) that validates permission claims before enrollment, this attack closes. But no such mechanism is described in Section 2 (verification protocol) or Section 5 (Bolyra primitive mapping). The `BolyraRegistry` contract is described only as an on-chain Merkle tree with a 30-entry root history buffer — not as a permissioned enrollment authority.

- **Contrast with baseline:** RFC 8693 Token Exchange with audience restriction and RFC 9728 Protected Resource Metadata gives the RS a way to demand that the AS prove it is authorized to issue scopes for a given resource — the AS's assertion is then auditable at the protocol level. The baseline's trust model is "the AS said so AND the AS is registered with this RS." The construction's trust model reduces to "the operator enrolled this AND the operator's key is valid." Neither model provides a *policy root* independent of the issuing party. The construction should not claim adversarial-AS soundness extends to adversarial-operator scenarios without adding an enrollment policy layer.

- **In-threat-model?** Partially. The AS-vs-operator conflation is in-scope for the consortium scenario. **Construction must clarify** either (a) the operator and AS are distinct trust principals (with a mechanism to keep them distinct), or (b) adversarial-AS soundness holds only against network-level AS compromise, not against a rogue credential issuer.

---

### Attack 4: "Cryptographic Binding to Runtime Model Identity" Requires a Hardware Root — modelHash Is a Self-Reported Claim

- **Attack:** Section 8, Property 5 states: "Neither RFC 7662, DPoP, nor BBS+ bind the token to a specific model hash + operator key + permission bitmask at call time." The construction's binding is `credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)`. The `modelHash` is described as "Poseidon hash of model identifier" (private input table, Section 2).

  Who computes `modelHash`? The agent process itself, at proving time. Who verifies that `modelHash` corresponds to the actual model weights running in memory? Nobody. There is no TEE attestation, no TPM PCR measurement, no AMD SEV or Intel TDX quote in the construction. The operator signs a commitment over a self-reported hash. This is cryptographically equivalent to a `client_id` registration where the client says "I am GPT-7" and the AS records that without verification.

  A compromised or rogue agent can substitute any `modelHash` value into the private input — the circuit (G3) only verifies that the EdDSA signature over `credentialCommitment` is valid. If the operator's key signs a commitment with `modelHash = H("gpt-4o")`, the circuit accepts it regardless of what model is actually running. Property 5's claim that DPoP cannot "bind the token to a specific model hash" is correct — but neither does this construction, in any meaningful sense. DPoP's `jkt` is at least bound to a key the client demonstrably holds at the moment of use. The `modelHash` claim is weaker: it is bound to whatever the agent claims at proof generation time.

- **Why this is load-bearing:** The differentiation claim in the patent context presumably rests on "we cryptographically know which model is making this call." If `modelHash` is self-reported, the novelty over `client_id` + `client_assertion` (RFC 7523) is questionable. RFC 7523 already binds the token to a private key the client proves possession of. Adding a self-reported hash field to that assertion achieves the same binding as the construction's G3.

- **Path to fixing:** TEE-based model attestation (e.g., NVIDIA H100 Confidential Computing attestation quote over model weights hash, committed to at enrollment time) would make this claim real. Without it, the construction should retract "cryptographic binding to runtime model identity" and restate it as "operator-attested model identity commitment" — weaker but accurate.

- **In-threat-model?** No — the security game (Section 3) does not include an adversary who runs a different model while presenting a proof for an enrolled model hash. **Construction must address this** or qualify Property 5. This is the most significant gap in the current draft: it is the claim most likely to be challenged in a patent prosecution or standards body review.


## Persona: spiffe_engineer

---

### Attack 1: Operator Key Is Just a Renamed AS — Adversarial-AS Claim Is Circular

**Attack:**
Section 8, Property 3 claims "even a fully compromised AS cannot forge a valid proof" because the RS verifies against on-chain state. But look at the actual trust chain:

1. The `credentialCommitment` is enrolled on-chain by **an operator** holding the `operatorPrivKey` (G3: EdDSA signature).
2. Who controls `operatorPrivKey`? The entity running the Bolyra infrastructure — call them Columbia CU's platform team.
3. Who controls `BolyraRegistry` on-chain? Whoever deployed it. If the contract is upgradeable (standard for production deployments), the upgrade key holder can rewrite the Merkle root.

The construction displaces the AS to two new trust anchors — the operator key and the contract admin — without naming them as trusted parties in the threat model (Section 3). The adversary model says "A controls the AS" but explicitly does **not** enumerate `operatorPrivKey` compromise or registry upgrade key as adversary capabilities. This is a gap in the threat model definition, not a property of the construction.

In SPIFFE terms: the SPIRE server issues SVIDs and holds the signing key. You are claiming SPIFFE is broken because its trust root is the SPIRE CA. But your trust root is `operatorPrivKey` + `BolyraRegistry` admin — same structural role, less audited, no HSM mandate, no rotation ceremony specified.

**Why it works against the construction:** Section 3 explicitly puts the AS under adversary control but excludes operator and registry. The security game (SelectiveScopeForgery) defines winning in terms of forging a proof — not in terms of the operator issuing a fraudulent enrollment. An adversarial operator can enroll a credential with `permissionBitmask = 0xFF` for any `modelHash`, and the RS learns nothing about this because the ZK proof only proves predicate satisfaction. The privacy property (Section 3, ScopeExtraction) actively prevents the RS from detecting over-provisioned enrollments.

**In-threat-model?** No — the construction must address: (a) enumerate `operatorPrivKey` and registry upgrade key as new trust anchors, and explicitly compare their attack surface against AS compromise; (b) explain why the adversarial-AS claim is stronger than "adversarial-SPIRE-CA" given identical structural roles.

---

### Attack 2: Permanent Correlation Handle via Static `credentialCommitment`

**Attack:**
`agentNullifier = Poseidon2(credentialCommitment, requiredScopeMask)` is deterministic and static for the lifetime of the credential. Two RSes that share nullifier logs — even informally, through leaked audit data — can:

1. Detect that the same agent (same `credentialCommitment`, same `requiredScopeMask`) accessed both services. Cross-RS identity linkage with zero information beyond the nullifier.
2. If they use different `requiredScopeMask` values but share `scopePredicateHash` outputs, they can triangulate which predicates the agent satisfies and bound the permission set from below.

The `credentialCommitment` itself (`Poseidon5(modelHash, opAx, opAy, permissionBitmask, expiryTimestamp)`) is a fixed handle for the entire credential lifetime. The privacy game (ScopeExtraction) only models a **single RS** — it does not address multi-RS correlation in a federated consortium (the exact deployment scenario described in Section 7).

SPIFFE directly addresses this: SVIDs are **short-lived** (default TTL = 1 hour) with automated rotation via the Workload API. A new SVID has a new key pair and new SPIFFE ID path segment. Cross-RS correlation across a rotation boundary is structurally impossible. The Bolyra construction has no equivalent rotation mechanism. What is the Merkle re-enrollment ceremony, and how does it prevent cross-session linkage?

**Why it works against the construction:** Section 7 (Columbia CU consortium with 12 partner RSes) is precisely the environment where nullifier sharing is incentivized — NCUA examiners would want cross-RS audit logs. The construction's compliance argument (NCUA Letter 24-CU-03) actually *requires* collecting nullifiers for audit. A subpoena to any single consortium RS yields a partial graph of the agent's access pattern across all RSes that share the same `requiredScopeMask`.

**In-threat-model?** No — the construction must define a multi-RS privacy game, add a credential rotation / re-enrollment protocol, or redefine the nullifier to be session-scoped rather than credential-scoped. The current `agentNullifier` design is inconsistent with the consortium deployment scenario's privacy claims.

---

### Attack 3: WIMSE Sender-Constrained Token + Cached Attestation Covers Properties 1–3 for the Common Case

**Attack:**
The WIMSE architecture draft (`draft-ietf-wimse-arch`) defines workload-to-workload authentication where the receiving workload (RS equivalent) holds a pre-fetched trust bundle and the sender presents a sender-constrained token bound to an ephemeral key. Combined with:

- A pre-fetched jwt-introspection-response with `scope` narrowed to `requiredScopeMask` at bundle fetch time
- DPoP binding the token to the calling workload's ephemeral key
- SPIFFE federation (separate SPIRE servers per CU trust domain)

…the RS can verify the agent's scope without a live AS roundtrip (the bundle was fetched earlier), without trusting the calling CU's AS at presentation time (the RS has the bundle locally), and with sender-constraint preventing token theft replay.

Section 8, Property 1 ("AS-blind presentation") claims this is categorically impossible for the baseline. But jwt-introspection-response responses are cached — the AS was contacted at bundle refresh time, not at presentation time. The construction conflates "AS not contacted at this exact moment" with "AS cannot interfere with this presentation." A cached jwt-introspection-response where the scope field is `READ_DATA FINANCIAL_SMALL` achieves the same RS-observable result as the ZK proof for the normal (non-adversarial-AS) case.

The differentiator only appears when the AS is **actively adversarial during the credential's validity period** — not just offline. The construction's claim is really: "if the AS was honest at issuance time but becomes adversarial later, the RS remains protected." For the Columbia CU scenario (Section 7), this threat requires that Columbia CU's platform team is actively attacking partner RSes after issuing credentials — a scenario with legal and business remedies, not purely a cryptographic problem.

**Why it works / fails against the construction:** For the adversarial-AS-during-validity-period scenario, the WIMSE baseline does fail and the construction survives. But Section 8 frames this as a category difference across all five properties simultaneously, when in fact Properties 1, 2, and 4 are achievable (approximately) by WIMSE + BBS+ for any AS that was honest at issuance time. The genuine category difference is narrower: it's specifically the *post-issuance adversarial AS* combined with *operator-key-rooted enrollment* that the construction uniquely handles.

**In-threat-model?** Partially — the construction survives the active adversarial-AS case, but must narrow its baseline comparison claim. Section 8 currently implies WIMSE cannot achieve Properties 1 and 4 under any configuration; that is too strong. The correct claim is "cannot achieve all five simultaneously when the AS becomes adversarial post-issuance while the credential is still valid."

---

### Attack 4: The SPIFFE ZK Attestor Layering Argument — Why a New Protocol Instead of a New Attestor?

**Attack:**
SPIRE has a documented plugin interface for **workload attestors** — the component that decides whether a workload deserves an SVID. Writing a ZK workload attestor that:

1. Receives a PLONK proof + public signals from the workload at SVID-request time
2. Verifies `SelectiveScopeProof` against an on-chain root (same circuit, same gadgets)
3. Issues a JWT SVID with `scope: "READ_DATA FINANCIAL_SMALL"` (and nothing else) if the proof verifies

…achieves all five of the construction's claimed properties **within the SPIFFE trust model**:

- **AS-blind at RS:** The RS holds a cached SPIFFE JWKS bundle. No live AS contact at presentation.
- **Runtime-adaptive predicate:** The workload attestor can be parameterized on `requiredScopeMask` per RS registration.
- **Adversarial-AS soundness:** The SPIRE server's attestor verifies the ZK proof; it cannot issue an SVID without a valid proof, so even a compromised SPIRE admin cannot issue a fraudulent SVID (the ZK proof still needs the on-chain Merkle witness).
- **Constant-size proof:** PLONK proof is still 768 bytes at attestor-time; the resulting JWT SVID is a standard compact JWT.
- **Model identity binding:** The `modelHash` is inside the circuit; SPIRE attestors can extract public signals and embed them in the SVID `spiffe://trust-domain/agent/{modelHash}` path.

The result: all the ZK cryptography is preserved, but the protocol surface is SPIFFE. The 12-CU consortium in Section 7 already has a trust federation answer: SPIFFE trust domain federation, with each CU running its own SPIRE server and federating trust bundles. Bolyra would be an attestor plugin, not a parallel protocol.

The construction provides no analysis of why a ZK SPIRE attestor would be insufficient. This is the central question your Section 8 "category difference" argument must answer, and it doesn't appear anywhere in the construction.

**Why it works / fails against the construction:** The layering argument shows that the ZK **mechanism** (circuit, gadgets, proof) is separable from the **protocol** (Bolyra vs. SPIFFE). The construction conflates these. A SPIFFE ZK attestor preserves the ZK mechanism inside an ecosystem with: existing tooling (SPIRE, SPIFFE ID parsers), standards-track RFC alignment (WIMSE, RFC 9449), HSM-backed SVID issuance, automated rotation, and audited federation protocols. Bolyra forces adopters to deploy a new protocol stack on top of blockchain infrastructure — a significant deployment cost with no cryptographic justification in Section 7 or 8.

**In-threat-model?** No — this is a design-level challenge, not a cryptographic attack. The construction must explain why the ZK construction needs to be a standalone protocol rather than an attestor plugin. The genuine gaps to fill: (a) SPIRE attestors run inside a trusted SPIRE process — if SPIRE is compromised the attestor doesn't help, so there is an adversarial-AS residual even with ZK attestor; (b) SPIFFE SVIDs are short-lived and don't support predicate-at-presentation-time (the RS gets the already-scoped SVID, it can't change `requiredScopeMask` at request time). These are real advantages of the Bolyra design — but they need to be stated explicitly as the *justification for a new protocol*, not buried in a comparison to RFC 7662 alone.
