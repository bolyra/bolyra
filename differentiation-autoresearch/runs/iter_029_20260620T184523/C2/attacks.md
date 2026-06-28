# Tier 3 Adversarial — C2 Cross-scope unlinkability

## Persona: auth0_pm

---

### Attack 1: Trust Boundary Collapse — The CU Is the Cloud Host

**Attack:** The construction's entire IND-UNL-AS security argument rests on a single assumption stated in §3.1: *"The adversary does NOT control: The agent's local execution environment."* In the primary deployment scenario (§7), NFCU is simultaneously the credential operator, the AS, **and** the cloud infrastructure provider where the member agent runs. A production shopping agent for an NFCU member runs in AWS Lambda or a GKE pod — infrastructure that NFCU provisions, configures, and retains root access to. The `scopeBlindingSecret` is stored in *that* execution environment. NFCU can retrieve it from secrets manager, CloudWatch logs, or ephemeral container storage before or after it is generated. No ZK circuit protects local storage.

**Why it works / why it fails:** The construction explicitly acknowledges the boundary: *"If the adversary compromises the agent's local storage, all unlinkability guarantees are void."* It then asserts this "mirrors the standard assumption that a user's secret key is not leaked." But that analogy holds for *human* users who own their own devices. It fails for enterprise agents where the credential issuer IS the infrastructure operator. The IND-UNL-AS game (§3.2) is sound as a cryptographic game — but it models a threat that does not match the stated deployment scenario in §7. The reduction to Poseidon PRF (§4.2) is valid only if the adversary cannot obtain `scopeBlindingSecret` by non-cryptographic means. NFCU doesn't need to break Poseidon. They check their own secrets manager.

**In-threat-model?** **No — construction must address this.** §3.1 needs an explicit trust boundary around *who controls the agent's execution environment*, and §7 needs to specify that the "CU-as-AS" scenario only holds when the agent runs in a non-CU-controlled environment (member device, neutral cloud account). As written, the primary deployment scenario defeats the primary security claim.

---

### Attack 2: Proof Latency × Throughput Economics

**Attack:** The construction targets proving time `< 3s` for PLONK on `~17,124` constraints (§6). WorkOS and Auth0 issue tokens in under 100ms. For the NFCU scenario, a realistic member-agent deployment handles concurrent authorizations across many members simultaneously — not one agent, but tens of thousands during peak shopping hours (Black Friday, holiday season). At 3s per proof with no parallelism budget already spent on member-facing services, the economics of running a proof-generation fleet become punishing. More damaging: every new RS visit by every agent generates a fresh proof (the `sessionNonce` prevents caching — §2.2 public inputs include a per-request nonce). The construction mentions rapidsnark (`< 2s` Groth16) in the CLAUDE.md benchmarks, but §6 gives no cost-per-proof figure, no proof-batching strategy, and no horizontal scaling architecture. The epoch-bucketing (§2.5) addresses double-spend detection, not proof reuse.

**Why it works / why it fails:** The construction's §6 provides constraint counts and target proving times but is silent on: multi-tenant proof orchestration, cost per proof on commodity cloud hardware, tail latency at P99, and what happens when the agent needs to authorize at 10 RSes in a 30-second purchase flow. The `< 3s` target is per-proof, not per-transaction. A checkout flow touching payment gateway + merchant + fraud service + loyalty provider = 4 proofs × 3s = 12s minimum. That is not competitive with any existing auth flow. Auth0's DPoP + PPID response in 100ms × 4 calls = 400ms. The construction does not address this gap — it acknowledges the baseline comparison in §8 but frames it as a trust-model win, not a latency win, with no engineering path to close the gap.

**In-threat-model?** **No — construction must address this.** A buyer-level response requires either (a) a proof aggregation scheme that batches multiple RS authorizations into one proving step, (b) a pre-computation strategy for the epoch window, or (c) an explicit acknowledgment that this construction is wrong for high-throughput synchronous flows and right only for async or low-frequency authorization patterns. None of these are in the current construction.

---

### Attack 3: RS-Side Integration Is Not "Paste an API Key"

**Attack:** The construction's §2.6 verification flow requires every Resource Server to: (1) resolve the on-chain `agentMerkleRoot` via a 30-entry root history buffer lookup in a smart contract, (2) maintain a local nullifier double-spend set indexed by `scopedNullifier`, (3) understand `scopeId` derivation (Poseidon hash of a scope string), (4) integrate a PLONK verifier (either call the deployed Solidity verifier contract or run a local snarkjs verifier), and (5) validate `epochId` against local clock. For a merchant like Amazon or Costco to become an RS, their engineering team must integrate all five. Compare to WorkOS MCP auth: add an SDK, paste an API key, configure scopes in a dashboard — the RS integration is a single HTTPS call to `/introspect`. Auth0 and Stytch offer equivalent one-line RS integration. The construction's onboarding complexity is the RS's problem, not the agent's, which means adoption is gated by the least-motivated party.

**Why it works / why it fails:** §2.6 describes the verification flow accurately but does not provide an RS integration SDK, a turnkey verifier service, or a hosted nullifier registry. The CLAUDE.md references `@bolyra/sdk` but the spec for RS-side integration is a manual Circom/Solidity operation. The construction's claim in §8 that *"the AS is never contacted after enrollment"* is a feature for the agent but a burden for the RS: the RS now owns on-chain state resolution, nullifier storage, and proof verification that the AS previously handled on behalf of all RSes. This is a correct observation about trust model improvement, but it transfers operational complexity downstream. Enterprise procurement at a credit union's merchant partner will not sign off on custom ZK verifier integration without a managed service option.

**In-threat-model?** **No — construction must address this.** The construction needs a hosted RS verifier endpoint (essentially a lightweight AS that is not in the authorization path but IS in the verification path) to make RS adoption tractable. This is architecturally straightforward — a stateless verifier service that checks PLONK proofs and maintains nullifier sets — but its absence is a blocker for every RS in the stated scenarios.

---

### Attack 4: On-Chain `scopeCommitment` Is a Delegation-User Fingerprint

**Attack:** The construction resolves the RS-facing linkability problem by moving `scopeCommitment` to the `DelegationEntry` circuit (§2.3, §3.3). But §3.1 explicitly states the adversary "reads all on-chain state, including `scopeCommitment` values stored in the `lastScopeCommitment` mapping by `DelegationEntry` proofs." The `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` is stable per agent-credential. Every time that agent initiates a new delegation chain — which in the healthcare scenario (§7) happens across multiple provider handoffs — a new `entryNullifier` is posted but the underlying `scopeCommitment` is deterministic. An adversary monitoring the `DelegationEntry` on-chain events sees: (a) `scopeCommitment` (stable per agent), (b) `entryNullifier = Poseidon2(credentialCommitment, sessionNonce)` (varies per session), (c) `agentMerkleRoot` (varies per epoch). With the adversary in possession of `operatorPrivKey` (as granted in §3.2 step 1), they can compute `credentialCommitment` and therefore `scopeCommitment` for any enrolled agent they know about. They can then scan the `lastScopeCommitment` mapping to confirm whether a specific agent has ever initiated a delegation chain and how many times. §3.5 acknowledges this: *"The on-chain visibility is acceptable because... it reveals only that the agent is capable of delegating, not where it authorizes."* But the frequency and timing of `DelegationEntry` submissions is a traffic-analysis vector the construction explicitly excludes from its epoch-bucketing mitigation — §3.5 lists epoch bucketing only for `ScopedAgentAuth` proofs, not for `DelegationEntry` events.

**Why it works / why it fails:** The construction's §4.3 collusion resistance argument correctly shows that an adversary cannot bridge from `scopeCommitment` (on-chain) to `scopedNullifier` (RS-facing) without `scopeBlindingSecret`. This is sound. But the attack does not require bridging — it only requires counting. In the Kaiser/Quest/Cedars-Sinai scenario (§7), Kaiser as adversarial operator can observe: *"This patient agent's `scopeCommitment` appears in `DelegationEntry` events 4 times in the past week."* Combined with appointment scheduling metadata Kaiser already holds legitimately, this narrows the referral network substantially. The IND-UNL-AS game (§3.2) does not model this: it asks whether the adversary can distinguish *which scope* a proof targets, not whether the adversary can *count delegation events* for a known agent. The side-channel table in §3.5 omits `DelegationEntry` timing as a category entirely.

**In-threat-model?** **Yes, partially — construction survives the linkability claim but must acknowledge the gap.** The IND-UNL-AS game as stated is not broken by this attack. However, the construction's §7 healthcare scenario claims *"Kaiser cannot determine whether the patient visited Quest, Cedars-Sinai, or both"* — this is true for RS-facing proofs but false for delegation chain frequency if Kaiser monitors on-chain `DelegationEntry` events. §3.5 needs a row for "On-chain `DelegationEntry` event frequency" with an explicit mitigation (e.g., rate-limit on-chain submissions to one per epoch, or batch multiple delegation initiations into a single transaction).


## Persona: cryptographer

---

### Attack 1: IND-UNL-AS Game Is Trivially Won by Reading `scopeId` from Public Inputs

- **Attack:** In §3.2 step 3, the game states: "A receives the proof and all public signals." The public signals of `ScopedAgentAuth` include the public input `scopeId` (explicitly listed in the §2.2 public inputs table as `Poseidon("CU-A:merchant-read")`). The adversary selects S_a and S_b, receives the challenge proof, reads `scopeId` directly from the transmitted public signals, and identifies which scope was used. Advantage = 1, unconditionally, regardless of PRF security.

- **Why it works / fails:** The circuit design and the game definition are in direct conflict. The game models the adversary trying to distinguish two scopes, but `scopeId` is plaintext in the proof transcript. There is no ZK argument that conceals a public input — that is not what ZK does. ZK hides the witness; it cannot hide public inputs from the verifier (or anyone who receives the proof). In real deployment, the agent sends `(proof, publicSignals)` to the RS over TLS, so the AS (never contacted) does not see it — but the game is not modeling TLS isolation. The game in §3.2 literally gives A the proof and all public signals, so A sees `scopeId` in plaintext.

  Two possible repairs exist, both requiring changes to the construction:
  (a) **Redefine the game to give A only public outputs** `(agentMerkleRoot, scopedNullifier, epochBinding)` — but then the game no longer captures collusion where an RS shares the full proof with the AS, because in that case AS also learns `scopeId`.
  (b) **Move `scopeId` to a private input**, with only a Poseidon commitment `H(scopeId, nonce)` as a public output. The RS verifies the commitment matches its published scope identifier out-of-band. This fixes the game but changes the circuit interface.

- **In-threat-model?** **No — construction must address.** The formal security claim in §4.2 ("Adv^IND-UNL-AS ≤ Adv^PRF_Poseidon + Adv^KS_PLONK + negl(λ)") is vacuous as stated because the game is trivially won before the PRF security of anything is relevant. This is not a gap in the reduction — it is a definitional flaw in the game.

---

### Attack 2: Reduction Silently Assumes the PLONK ZK Simulator Does Not Require the SRS Trapdoor

- **Attack:** The reduction in §4.2 step 2 says: "Simulates a valid PLONK proof using the PLONK simulator (exists by zero-knowledge property)." For universal PLONK over KZG commitments (which is what `pot16.ptau` produces), the honest-verifier ZK simulator generates a valid-looking proof for arbitrary public inputs WITHOUT knowing the witness — but it does so by producing fake polynomial commitments using the SRS toxic waste τ. Without τ, no known polynomial-time simulator exists for KZG-based PLONK. The reduction's soundness therefore rests on an unstated assumption: `B` can simulate PLONK proofs, which requires knowing τ, but the construction's setup story (§2.1: "PLONK avoids per-circuit ceremony") does not describe who holds τ or whether the adversary could have learned it.

- **Why it works / fails:** The adversary model (§3.1) explicitly gives A control over the operator key material and on-chain state, but is silent on the Powers of Tau ceremony. If A participated in the `pot16.ptau` ceremony (or if the ceremony was run by a single party such as the AS-as-operator) and learned τ, then A can simulate PLONK proofs independently — which breaks the ZK property the reduction relies on, but more critically: it means the honest-verifier ZK assumption is violated in exactly the AS=operator deployment scenario (§7) the construction is built for.

  Additionally, the reduction has a role inversion problem: B is supposed to simulate PLONK proofs in the query phase for A. But B does not know the witness (it is trying to use the oracle to avoid knowing `s_b`). B cannot call the real PLONK prover (no witness) and cannot call the simulator without τ. The reduction sketch does not resolve this — it waves at "exists by ZK property" as if the simulator is freely available to B. This must be made explicit as an assumption: "B has access to τ" or "B uses an ideal ZK oracle," and the security claim must be stated under a model that accounts for subverted τ (e.g., a simulation-extractable variant of PLONK, or a NIZK in the random oracle model with an explicit simulator).

- **In-threat-model?** **No — construction must address.** The named assumptions in §4.1 include A-PRF, A-CR, A-KS, and A-DL, but nowhere do they state "the adversary does not know the SRS trapdoor τ" or "the SRS was generated by a trusted multi-party ceremony with at least one honest participant." The A-KS assumption (PLONK knowledge soundness) is compatible with an adversary who knows τ — knowledge soundness holds even if τ is public. But ZK simulation — which the reduction relies on — is a different property that is broken if τ is known to the wrong party. The reduction is incomplete without this assumption.

---

### Attack 3: `scopeId`→`requiredScopeMask` Binding Is Off-Circuit and Off-Chain, Enabling Scope Forgery

- **Attack:** In `ScopedAgentAuth`, `scopeId` and `requiredScopeMask` are independent public inputs (§2.2). The circuit constrains that `permBits ⊇ requiredBits` (constraint 4), but no constraint — in-circuit or on-chain — binds `scopeId` to any particular `requiredScopeMask`. An adversary (malicious agent or man-in-the-middle who intercepts the proof before TLS termination) can substitute `requiredScopeMask` with a weaker value before presenting the proof to an RS.

  More precisely: Agent A holds permissions `0b00000001` (READ_DATA only). RS-B requires `requiredScopeMask = 0b00000011` (READ_DATA + WRITE_DATA). Agent A cannot generate a valid proof for RS-B's actual mask. However, the agent can present a proof with `(scopeId = Poseidon("RS-B:read-write"), requiredScopeMask = 0b00000001)`. The circuit is satisfied (agent's permissions satisfy the presented mask). RS-B must independently verify that `requiredScopeMask = 0b00000011` — this check is not in the circuit and not enforced on-chain. If RS-B is misconfigured, negligent, or subject to a mismatch between its off-chain policy and what it checks in proof verification, the agent obtains unauthorized access.

- **Why it works / fails:** The circuit proves a subset relationship between the agent's private permission bitmask and the public `requiredScopeMask`. It does NOT prove that `requiredScopeMask` is the correct policy for `scopeId`. This creates an input integrity gap: the security of the scope satisfaction proof is only as strong as the RS's off-circuit enforcement of its own policy. In the healthcare scenario (§7), Kaiser publishing `(scopeId_Quest, requiredScopeMask = READ_DATA)` and an agent presenting `(scopeId_Quest, requiredScopeMask = 0x00)` would be accepted by any RS that does not explicitly validate the mask against a canonical registry.

  The fix is either (a) publish `(scopeId, requiredScopeMask)` bindings on-chain in the registry and add a circuit constraint that verifies the presented `requiredScopeMask` against the on-chain value for `scopeId`, or (b) document as an explicit protocol requirement that RSes MUST reject any proof where `requiredScopeMask ≠ the RS's own registered policy`, making this enforcement a verifier-side obligation. Neither option is currently stated in §2.2, §2.6, or §5.

- **In-threat-model?** **No — construction must address.** This attack is in the threat model for any agent who attempts to over-claim access, or any RS-to-RS relay scenario where one RS forwards a proof to another. The construction's "correctness" argument in §8 ("circuit proves `permBits ⊇ requiredBits`") conflates circuit correctness with protocol security: the circuit is correct, but the protocol is insecure if the binding between scope identity and required policy is not enforced.

---

### Attack 4: Colluding RSes Execute an Epoch-Level Intersection Attack That Is Not Bounded by the PRF Reduction

- **Attack:** The `epochId` is a public input (5-minute granularity, §2.5). When m colluding RSes each observe one proof per epoch from an unknown agent, they can perform a timing intersection: "Did RS-A and RS-B both see a new-nullifier proof in epoch E?" If yes, both proofs might originate from the same agent. Over k epochs, the probability that an innocent coincidence explains consistent co-occurrence drops geometrically. For an anonymity set of N agents where M < N agents make any authorization in a given epoch, the adversary narrows the set to M after one epoch and can intersect further over time.

  This attack is entirely outside the IND-UNL-AS game as defined. The game gives A arbitrary proofs for arbitrary scopes in the query phase, then presents a single challenge proof. It does not model the adversary performing statistical intersection over many real authorizations made by the actual agent across multiple epochs. The reduction to Poseidon PRF security says nothing about this — it bounds a distinguishing experiment, not an intersection attack.

- **Why it works / fails:** The construction's epoch bucketing (§2.5, §3.5) converts per-request timing into 5-minute-window timing. This mitigates fine-grained per-request correlation but does not eliminate epoch-level co-occurrence. The `epochBinding` is deterministic per (agent, scope, epoch) — so if RS-A and RS-B both see `epochId = 1234` in their received proofs, the adversary knows both proofs occurred in the same 5-minute window. Combined with network metadata (§3.5 acknowledges IP correlation is out of scope but defers it to transport-layer anonymization), the intersection attack succeeds with probability that scales with traffic sparsity: in the NFCU scenario, if only one member agent makes financial authorizations on a Tuesday morning in a given epoch, the intersection is deterministic.

  The construction's side-channel table (§3.5) lists "Timing of proof submission → Epoch bucketing: all proofs within a 300s window share the same epochId. Agent MAY add random delay within epoch." The word "MAY" is not a cryptographic mitigation — it is a recommendation. And random delay within a 5-minute epoch does not prevent two proofs in the same epoch from being co-located by the colluding RSes: they only need to see `epochId = E` in both, not the sub-epoch timestamp.

- **In-threat-model?** **Partially — the construction acknowledges IP correlation is out of scope, but epoch intersection using only the cryptographic public outputs (`epochId`, new-nullifier flag) is in scope and not bounded by the stated reduction.** The IND-UNL-AS game does not model repeated executions and does not capture intersection distinguishers. The formal claim should either extend the game to a multi-session setting with explicit intersection bounds, or explicitly narrow the scope of the unlinkability claim to exclude adversaries who observe traffic patterns across multiple epochs.


## Persona: cu_ciso

---

### Attack 1: The Construction Destroys Its Own Audit Trail

**Attack:** Section 7 (Scenario: NFCU) explicitly advertises that "NFCU has no visibility into which merchants the agent subsequently contacts, when, or how often. The merchant graph is cryptographically hidden." My NCUA examiner will read this sentence and mark a finding before I finish the page. NCUA Part 748, Appendix B §III.C requires my security program to include "audit controls" that "record and examine activity in systems containing member information." GLBA Safeguards Rule (16 CFR §314.4(h)) requires me to "regularly test or otherwise monitor the effectiveness of the safeguards' key controls." If my AS/operator role is intentionally blinded to what the agent is doing post-enrollment, I cannot satisfy either requirement. Member #4821's agent executes `FINANCIAL_SMALL` at Amazon at 14:02 and Costco at 14:07. The transaction disputes arrive at 15:00. My Tier 1 ops team has no log to pull — the construction's unlinkability guarantee *is* the absence of my audit record. I cannot transfer risk to an insurer without a log. I cannot answer the examiner's questionnaire. I cannot tell the board what happened.

**Why it works against the construction:** The construction addresses this nowhere. Section 3.5 lists six side channels and mitigations. Audit trail absence is not a side channel — it is the core privacy guarantee. The construction's threat model (§3.1) explicitly excludes NFCU-as-operator from the trusted set, which from a regulatory standpoint means the CU has voluntarily blinded itself from its own member activity. The construction has no exception mode, no lawful-access override, no supervised-disclosure path.

**In-threat-model?** No — construction must address. Proposed remedy: define a "CU compliance mode" where the *member* (not the operator) holds a lawful-access key that can be produced under a court order or dispute resolution, without the CU reconstructing the full graph unilaterally. This is architecturally non-trivial and is not scoped in §2 or §7.

---

### Attack 2: `scopeBlindingSecret` Key Custody Has No Regulatory Landing Zone

**Attack:** Section 2.4 says the `scopeBlindingSecret` "is stored alongside the agent's credential material in the agent's local secure storage." Full stop. The construction never defines what "local secure storage" means in a deployed CU context. My FFIEC CAT Domain 3 (Cyber Risk Management and Oversight) requires me to document key management procedures. GLBA §314.4(e) requires me to oversee service provider arrangements — but if the member's agent holds a secret I can never touch, I cannot satisfy vendor key management controls for that secret either. The possibilities are:

- **Browser localStorage**: trivially exfiltrated via XSS, extensions, or OS-level memory dumps. Section 3.1 concedes "If the adversary compromises the agent's local storage, all unlinkability guarantees are void." A browser is not local secure storage by any FFIEC definition.
- **Mobile secure enclave**: reasonable, but requires HSM-grade attestation and a backup/recovery plan. What happens when the member loses their phone? Section 2.4 says "generate a new credential" — there is no member-recoverable procedure here. My member support team at 2am has no recovery path. I have a 1-800 number and a SOC that cannot help.
- **Hardware wallet / dedicated agent device**: operationally implausible for a $3B credit union's member base.

The construction's security proof (§4.2) is clean, but it rests entirely on the invariant that `scopeBlindingSecret` never leaves the agent's local environment. It provides zero specification for how that invariant is enforced, audited, or recovered. My NCUA examiner's third-party questionnaire will ask: "What key management procedures does the vendor provide for member-held secrets?" The answer today is "sample from `/dev/urandom` and store it locally."

**Why it works against the construction:** The reduction in §4.2 is sound given the assumption. The assumption has no implementation. The construction mentions key rotation only as "generate a new credential" with no member UX, no recovery ceremony, no CU-assisted re-enrollment path that doesn't reintroduce correlation. The gap between cryptographic assumption and operational reality is not addressed in any section.

**In-threat-model?** No — construction must address. A FIPS 140-3 Level 2 or higher key storage specification (e.g., WebAuthn PRF extension, platform secure enclave with attestation, or hardware-backed credential store) is required before any CU examiner conversation is possible. The construction should cite a specific secure storage profile and explain the recovery flow.

---

### Attack 3: Non-Standard Primitives Fail the Vendor Management Questionnaire

**Attack:** My Vendor Management Policy requires that cryptographic algorithms used by third-party systems be either NIST-approved or subject to documented risk acceptance at the CISO level with board notification. Section 4.1 names four assumptions: Poseidon PRF security, Poseidon collision resistance, PLONK knowledge soundness, and discrete log on Baby Jubjub. None of these map to:

- FIPS 140-3 approved algorithms (AES, SHA-2/3, RSA, ECDSA on P-256/P-384)
- NIST PQC finalists (ML-KEM, ML-DSA, SLH-DSA)
- Any algorithm that appears in an NCUA examiner's reference guide

Poseidon is a 2019 academic construction optimized for ZK circuits, not for FIPS compliance. PLONK is a 2019 universal SNARK. Baby Jubjub is a 2018 twisted Edwards curve defined over BN254 scalar field — it has no NIST or NSA Suite B status. The construction acknowledges (§5) that "no new primitives are introduced," but that framing only helps if the existing primitives are on an approved list. They are not.

My NCUA examination under Part 748 will include a question about whether cryptographic controls use "industry-standard" algorithms. My answer for this system is: "We use Poseidon and PLONK, which are standard in the ZKP research community." That sentence will generate a finding. The construction provides a tight reduction (§4.2) to Poseidon PRF — which is helpful academically and useless regulatorily.

**Why it works against the construction:** Section 8's comparison table lists "Formal security definition: IND-UNL-AS game with tight reduction" as a differentiator. The NCUA examiner does not evaluate IND-UNL-AS games. The examiner evaluates whether my security program uses "appropriate safeguards" as defined by reference to industry standards — NIST SP 800-series, ISO 27001, SOC 2 Trust Services Criteria. None of these cite Poseidon. The construction has no bridge from its cryptographic claims to regulatory control language.

**In-threat-model?** No — construction must address. Required additions: (1) an explicit regulatory mapping table: "Poseidon PRF → NIST SP 800-108 PRF conceptual equivalent, pending formal standardization — documented risk acceptance required"; (2) a SOC 2 Type II report scope or equivalent third-party attestation for the proving library and on-chain registry; (3) an algorithm agility path for migration if NIST issues guidance on ZK-specific hash functions. Without these, the system cannot survive a vendor management questionnaire.

---

### Attack 4: On-Chain `scopeCommitment` Is a Public Behavioral Record Under GLBA

**Attack:** Section 2.3 states that `DelegationEntry` proofs write `scopeCommitment` to on-chain state, and Section 3.1 acknowledges that "the adversary reads all on-chain state, including `scopeCommitment` values stored in the `lastScopeCommitment` mapping." The construction argues this is acceptable because `scopeCommitment` doesn't reveal *which* RSes the agent contacted. My GLBA and state privacy analysis says that's the wrong question.

The on-chain registry is a public blockchain (Base, per the CLAUDE.md context). Every `DelegationEntry` proof submission is a permanent public record that:
- At timestamp T, an agent with enrollment key `entryNullifier = Poseidon2(credentialCommitment, sessionNonce)` initiated a delegation chain.
- That agent's operator is NFCU (the on-chain registry knows which operator enrolled the credential — the `agentMerkleRoot` is operator-specific).

This means a public blockchain now contains: "An NFCU member agent initiated a delegation chain at 14:05 on June 20." That is member behavioral data on a public ledger. GLBA §314.3 defines "customer information" as "any record containing nonpublic personal information about a customer." The fact that an NFCU member used a delegated agent is nonpublic personal information. The construction has no analysis of whether writing this to a public chain constitutes disclosure, or whether CCPA/state privacy laws require NFCU to disclose to members that their behavioral signals are being published on-chain.

Section 4.3 (Collusion Resistance) argues that the adversary "cannot link a `scopeCommitment` to any RS-facing `scopedNullifier` without breaking Poseidon PRF." That is cryptographically sound. It does not address the metadata published — the *existence* of the delegation event, its timestamp, and its linkage to NFCU's operator key — all of which are visible to any blockchain observer without breaking any cryptographic assumption.

**Why it works against the construction:** The construction's threat model explicitly acknowledges on-chain observability of `scopeCommitment` (§3.1, §4.3) and argues it is acceptable. The GLBA analysis is simply absent. The construction treats "cannot link to RS-facing nullifier" as equivalent to "no regulatory exposure," which is incorrect. Publishing *any* member behavioral signal to a public ledger — even an unlinkable one — requires disclosure analysis that this construction does not contain.

**In-threat-model?** No — construction must address. Required: (1) a GLBA disclosure analysis of what the on-chain `lastScopeCommitment` mapping publishes and whether it constitutes member data publication requiring notice; (2) an opt-in/opt-out mechanism for delegation chain initiation; (3) evaluation of whether a private or permissioned chain mitigates the public disclosure concern without degrading the trust model; (4) explicit treatment in §3.5 (Side-channel threat model) of on-chain metadata leakage as a regulatory surface, not just a cryptographic side channel.


## Persona: rfc7662_advocate

---

### Attack 1: JWT Introspection Response Caching Already Removes the AS from the Hot Path

- **Attack:** Section §2.6 claims "The AS is never contacted" as a structural advantage over OAuth. But RFC 9728 (Protected Resource Metadata) combined with draft-ietf-oauth-jwt-introspection-response already supports this model: the AS pre-signs a JWT introspection response scoped to a specific RS audience (`aud` = RS identifier per RFC 8707). The RS caches this signed response and verifies locally for the token's TTL — no per-request AS contact. After initial token issuance, the AS is architecturally off the critical path exactly as the construction claims. The construction's §8 table row "AS removal from hot path" credits Bolyra with a property that cached JWT introspection already provides.

- **Why it works / why it fails:** This attack lands partially. The AS must still issue the initial scope-specific token and log the (agent, scope, RS-audience) binding before going off-path. Bolyra enrollment creates only a (credential, permissionBitmask) tuple — no scope-specific token is ever issued, so no scope-RS mapping ever enters AS logs. The construction is correct that after enrollment the AS has zero per-RS-visit visibility. The cached JWT approach buys AS off-path for *latency* but not for *surveillance* — the issuance log is immutable. §8 should sharpen this distinction: "AS removed from per-request latency path" vs. "AS removed from per-authorization information set" are different properties; only the latter is novel.

- **In-threat-model?** Yes — the construction survives, but §8 needs to close the rhetorical gap. Claiming AS-removal as a binary property without distinguishing latency removal from information-set removal understates the baseline and overstates the novelty.

---

### Attack 2: Blind BBS+ Issuance Breaks the "Structurally Impossible" Claim in §8

- **Attack:** The construction's §8 states "The structural impossibility" — that no RFC composition can hide scope from the AS. But this ignores blind credential issuance, which is a deployed cryptographic primitive. A BBS+ blind signature flow allows the agent to embed the target scope as a blinded message: the AS signs the credential without learning the scope value. Combined with per-RS PPID (`sub`) values (RFC 8707 audience binding), the RS-facing token reveals neither the agent's stable identity nor the full scope set. The AS's issuance log records only "issued a BBS+ blind credential to agent-key-hash" — not the scope. At the RS, multi-show unlinkability (BBS+ holder-binding) prevents cross-RS correlation by colluding verifiers. This is RFC-adjacent and does not require new ZK infrastructure.

- **Why it works / why it fails:** The attack partially holds. Blind BBS+ issuance does hide scope from the AS at issuance time, which the construction did not address. However, the argument fails at the collusion boundary: if the RS returns any normalized scope claim to the AS (e.g., for audit logging, GDPR subject-access requests, or fraud investigation), the AS recovers the mapping. More importantly, blind issuance requires the agent to know the target scope before contacting the AS — the AS must authorize the blind signature without inspecting the message, meaning the AS cannot enforce permission policy on the blinded scope. The Bolyra construction enforces scope containment inside the circuit (`requiredScopeMask` constraint) against the on-chain Merkle root without requiring the AS to see the scope at all. Blind BBS+ moves the trust to "AS will blindly sign whatever the agent requests," which is a weaker authorization model. But this is an argument the construction must make explicitly — §8 currently ignores blind issuance entirely.

- **In-threat-model?** Yes — but the construction has a documentation gap. §8's "structural impossibility" claim is too strong. A corrected claim: "no composition of OAuth RFCs provides AS-blind scope authorization with circuit-enforced permission containment." Blind BBS+ provides AS-blind issuance but not circuit-enforced containment; Bolyra provides both.

---

### Attack 3: `scopeBlindingSecret` Trust Boundary Collapses in Operator-Hosted Agent Deployments

- **Attack:** §3.1 defines the trust boundary: "The adversary does NOT control the agent's local execution environment." The entire IND-UNL-AS security argument rests on this. But in both concrete deployment scenarios (§7), the agent is an autonomous software process. In the NFCU scenario: NFCU is simultaneously the operator (holds `operatorPrivKey`), the AS, and — in typical enterprise deployments — the cloud provider running the agent workloads. An NFCU-deployed shopping agent runs on NFCU infrastructure. NFCU can instrument the agent process, read `/dev/urandom` outputs, or intercept the `scopeBlindingSecret` at generation time. The IND-UNL-AS game explicitly states the adversary is "The Authorization Server and/or the credential operator" — which is NFCU — but then excludes NFCU's agent runtime from the adversary model. In the credit union scenario the construction is specifically designed for, these roles are not separable in practice.

- **Why it works / why it fails:** This is the sharpest attack. The construction's adversary model is internally inconsistent with its primary deployment scenario: the entity the construction tries to hide traffic from (NFCU-as-AS) is also the most likely operator of the agent execution environment. The threat model in §3.1 should be read as: IND-UNL-AS holds only if the agent runs in a TEE, client-controlled environment (browser, mobile device, user-owned server), or third-party compute that the operator cannot observe. For user-facing agents running locally (browser extension, mobile wallet, self-hosted), the trust boundary is defensible. For SaaS AI agents running on the credential operator's infrastructure, the `scopeBlindingSecret` is accessible to the exact adversary the game models. The construction provides no mechanism for the agent to prove it generated `scopeBlindingSecret` independently (that would require a TEE attestation or remote attestation scheme, not mentioned anywhere).

- **In-threat-model?** **No** — the construction must address this. Either (a) restrict the deployment model to client-controlled execution environments with an explicit prohibition on operator-hosted agents, (b) integrate TEE attestation so the agent can prove `scopeBlindingSecret` was generated in an enclave the operator cannot read, or (c) weaken the IND-UNL-AS claim to hold only against operators who do not control the agent runtime. The current claim "NFCU cannot compute `scopeBlindingSecret`" (§7, point 5) is false for NFCU-hosted agents.

---

### Attack 4: On-Chain `DelegationEntry` Timing Is a Deanonymization Oracle Against the Construction's Primary Threat

- **Attack:** §2.3 states that `DelegationEntry` proofs are submitted on-chain, and the on-chain `scopeCommitment` is stored indexed by `sessionNonce`. The AS/operator (who knows all credential fields and can enumerate which `scopeCommitment` values belong to which enrolled agents) can observe the blockchain for `DelegationEntry` submissions. Each submission timestamp is publicly visible. The AS/operator therefore observes: "Agent credential #4821 initiated a delegation chain at block 1,402,718 (14:01:22 UTC)." This is a precise on-chain timestamp correlated to a known agent identity (because the operator can recompute `credentialCommitment` and look up the matching `scopeCommitment` on-chain). The epoch-bucketing mitigation (§3.5) applies to RS-facing `ScopedAgentAuth` proofs — it does not apply to `DelegationEntry` submissions, which have no epoch-bucketing or delay mechanism specified. An adversarial NFCU can correlate on-chain `DelegationEntry` timestamps with merchant-reported transaction times to reconstruct the partial traffic graph for any agent that uses delegation.

- **Why it works / why it fails:** The attack is valid for agents that use the delegation path. §3.5 addresses timing for `ScopedAgentAuth` but explicitly omits `DelegationEntry` — the side-channel table has no entry for "on-chain delegation entry timing." For non-delegation flows, the construction correctly notes "no `DelegationEntry` proof is ever submitted and no `scopeCommitment` appears on-chain." But the healthcare scenario (§7, second scenario) requires delegation, and Kaiser-as-operator can observe on-chain delegation initiations linked to known `scopeCommitment` values. The IND-UNL-AS game (§3.2) permits the adversary to observe "on-chain state, including `scopeCommitment` values" — the game should also require the adversary to observe timing, which it currently does not model as a distinguishing oracle.

- **In-threat-model?** **No** — the construction must address this for the healthcare delegation scenario. Mitigations: (a) mandate random delay before `DelegationEntry` submission (not specified), (b) batch multiple delegation entries in a single transaction to reduce per-agent timing resolution, (c) require off-chain or privacy-preserving delegation seeding that does not expose per-agent timestamps, or (d) explicitly bound the IND-UNL-AS game to non-delegation flows and provide a separate game (`IND-UNL-AS-DEL`) for the delegation case that models the timing channel. The current formal security definition in §3.2 does not model the adversary's ability to use block timestamps as a distinguisher, which is a gap in the reduction of §4.2.


## Persona: spiffe_engineer

---

### Attack 1: The Blinding Secret Storage Is the Workload API Problem — You Rebuilt It Worse

**Attack:** The entire security argument rests on `scopeBlindingSecret` being agent-local and operator-independent (§2.4, §3.1, §3.4). The construction says it "MUST be generated by the agent's local execution environment" using a CSPRNG and stored in "the agent's local secure storage." This is precisely the problem that SPIFFE's Workload API solves: how do you securely deliver and store a credential secret inside a workload process without the platform operator or the container orchestrator extracting it?

SPIRE's answer is the Workload API — a Unix domain socket where the SPIRE agent streams short-lived X.509 SVIDs into the workload process without ever persisting the private key to disk, and with the SPIRE agent itself attested by a hardware node attestor (TPM, AWS IID, k8s PSAT). The workload never stores the key; it receives it ephemerally.

The construction's `scopeBlindingSecret` must be *persistently stored* (§2.4: "generated once per agent credential and reused across all scopes"). This means: disk storage, process memory, or a secrets manager — all of which expose the secret to the same platform operator that the construction is trying to hide traffic from. If NFCU operates the Kubernetes node running the member agent, NFCU's infrastructure team can extract the `scopeBlindingSecret` from the pod's secret store, recompute every `scopedNullifier`, and reconstruct the full merchant graph. The IND-UNL-AS game explicitly carves out "if the adversary compromises the agent's local storage" as an explicit non-guarantee (§3.1), but this is not a narrow exception — it is the normal operational reality for enterprise workloads.

**Why it fails / why it works:** The construction explicitly documents this as a trust assumption (§3.1: "the agent's local execution environment being outside the adversary's control"). But SPIFFE's contribution is precisely that node attestation creates a *hardware-rooted* trust boundary for exactly this scenario. The construction handwaves the storage problem ("agent's local secure storage") while SPIFFE solves it with a concrete attestation stack. The construction inherits the same threat model SPIFFE was designed to address, then doesn't address it.

**In-threat-model?** No — the construction must address how `scopeBlindingSecret` is protected from the platform operator. The IND-UNL-AS game gives the adversary `operatorPrivKey` but explicitly withholds platform-level access from the adversary definition. In real deployments these are the same entity. Without a hardware attestation story (TPM, secure enclave, or equivalent), the unlinkability guarantee collapses in the primary deployment scenario.

---

### Attack 2: There Is No Revocation — The 30-Entry Buffer Is an Availability Mechanism, Not a Security Mechanism

**Attack:** Section 2.4 states: "If the agent's local environment is compromised, the `scopeBlindingSecret` is assumed leaked. The agent MUST generate a new credential (new enrollment in the Merkle tree) with a fresh `scopeBlindingSecret`). There is no in-place rotation mechanism — the old credential's nullifiers become stale as the old Merkle root ages out of the 30-entry history buffer."

This means revocation requires: (1) the compromise is detected, (2) the agent re-enrolls, (3) the old Merkle root falls out of the 30-entry history buffer. Steps 1–2 assume detection, which is not guaranteed. Step 3 is not time-bounded in the construction — there is no stated bound on how long a root stays in the 30-entry buffer. If the buffer spans 30 days of low-throughput tree updates, a compromised credential may remain valid for 30 days post-detection.

SPIFFE X.509 SVIDs have configurable TTLs (typically 1 hour), automatic rotation via the Workload API, and a SPIRE-controlled CRL path. Compromise-to-revocation latency is bounded by TTL, not by buffer size and enrollment activity. WIMSE's WIT tokens inherit OAuth short-lived token semantics with active revocation endpoints.

**Why it works against the construction:** The IND-UNL-AS game in §3.2 considers a PPT adversary but does not model *credential compromise events*. The security argument holds for an uncompromised blinding secret. But the recovery procedure is unbounded. An adversary who exfiltrates `scopeBlindingSecret` can impersonate the agent at any RS (by generating valid PLONK proofs with the stolen secret) until the old root ages out. The 30-entry buffer was designed to tolerate proof-generation latency (§3.5: "tolerates proof generation latency"), not to bound revocation windows. These are orthogonal requirements the construction conflates.

**In-threat-model?** No — the construction must specify a maximum lifetime for a revoked root in the history buffer, tie the buffer window to a wall-clock bound, and define a process for emergency revocation that is faster than passive buffer expiry. The current description does not provide this.

---

### Attack 3: On-Chain `DelegationEntry` Creates a Timing Side Channel the IND-UNL-AS Game Does Not Model

**Attack:** The adversary in §3.1 controls the AS/operator and can observe all on-chain state including `scopeCommitment` values stored in `lastScopeCommitment[sessionNonce]` by `DelegationEntry` proofs. The AS/operator knows `credentialCommitment` (computable from known credential fields: §3.4). Therefore the AS/operator can identify *which* `DelegationEntry` entries on-chain correspond to agents they credentialed: compute `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` for each credentialed agent and scan the on-chain registry for matches.

This does not break the IND-UNL-AS game as stated (the game asks about *RS-facing scope*, not delegation existence). But it creates an information channel the game ignores: the AS/operator learns the *timestamp* of every delegation chain initiation for every credentialed agent. Combined with the adversary's control of up to $k-1$ RSes (§3.1), and the RS's visibility into `epochBinding` timing, an adversary can build a probabilistic traffic graph:

- On-chain: "Agent X (identified via `scopeCommitment`) initiated a delegation chain at epoch 4521."
- RS-B (controlled by adversary): "An unknown agent with a `scopedNullifier` appeared at epoch 4521."
- Inference: The two events are correlated in time. In a low-traffic deployment (one delegation initiation per hour), this is de-anonymizing.

The construction acknowledges this risk in §3.5 ("the adversary learns the set of agents that have initiated delegation chains, but cannot link a `scopeCommitment` to any RS-facing `scopedNullifier` without breaking Poseidon PRF") but does not account for the timing correlation channel. PRF security is irrelevant when the adversary uses timestamps rather than nullifier inversion.

**Why it works:** The IND-UNL-AS game (§3.2) requires the adversary to distinguish which of two *unused* scopes a proof was generated for — it does not model timing correlation between on-chain delegation events and RS access patterns. The reduction to Poseidon PRF in §4.2 is tight *given the game definition*, but the game definition excludes the timing side channel that on-chain `DelegationEntry` introduces.

**In-threat-model?** No — the construction must extend the IND-UNL-AS game to model an adversary who observes on-chain delegation timestamps and correlates them with RS access timing, or it must add a timing obfuscation requirement for `DelegationEntry` submissions (e.g., mandatory random delay, batched on-chain submission, or using a mixer contract). The current §3.5 side-channel table omits this attack vector.

---

### Attack 4: This Is WIMSE WIT With a ZK Attestor — Why Not Extend the Standard Instead of Replacing It?

**Attack:** The WIMSE architecture (`draft-ietf-wimse-arch`) defines Workload Identity Tokens (WIT) for service-to-service authentication and includes token exchange (`draft-ietf-oauth-transaction-tokens`) for delegation chains. The selective disclosure requirement — hiding access patterns from the issuer — is explicitly in scope for the WIMSE WG as an open work item. The construction's §8 baseline comparison dismisses OAuth/OIDC but does not engage with the WIMSE layering.

Concretely: the construction's `ScopedAgentAuth` circuit is a ZK attestor that proves Merkle membership + permission satisfaction without revealing the credential to the verifier. SPIRE has a first-class plugin model for custom node and workload attestors. A SPIRE workload attestor that (1) issues a short-lived `scopeBlindingSecret` scoped to the workload's SPIFFE ID and (2) enables the workload to generate PLONK proofs of `ScopedAgentAuth` — delivered via the Workload API — would achieve the same RS-facing unlinkability without abandoning the SPIFFE trust model, revocation semantics, or federation capabilities.

The `ScopedAgentAuth` proof would then be carried as a bearer token in the WIMSE WIT's `cnf` claim, analogous to how DPoP proof-of-possession works today. The construction's "AS-free" model could be preserved at the RS layer: the RS verifies the PLONK proof against the on-chain root without contacting the SPIRE server, while the SPIRE server retains enrollment authority, node attestation, and revocation control. This is a contribution to WIMSE, not a replacement of it.

**Why it partially fails:** The construction's primary claim — that the AS must be removed from the authorization hot path to prevent traffic graph reconstruction — is correct and not addressable within the current WIMSE WIT model (which still requires the SPIRE server to issue the WIT). The ZK construction's IND-UNL-AS property genuinely cannot be achieved by layering on an AS-centric architecture. So the attack's conclusion ("contribute to WIMSE instead of building a new protocol") is partially wrong: the AS elimination is a necessary architectural departure, not a layering choice.

However, the attack correctly identifies that *everything except AS elimination* — the Merkle enrollment, the delegation chain, the permission bitmask semantics, the revocation model — could and arguably should be specified as extensions to SPIFFE/WIMSE primitives rather than as a standalone protocol. The construction does not justify why it defines its own SPIFFE ID equivalent (`modelHash` + operator pubkey), its own trust domain model (Merkle tree), and its own workload attestation flow (operator EdDSA signature), rather than mapping onto `spiffe://trust-domain/agent/{modelHash}` with a ZK attestor plugin.

**In-threat-model?** Yes for AS elimination (the construction survives this attack on its core claim). No for the rest of the design surface: the construction must justify why it does not reuse the SPIFFE ID naming convention, SPIRE's trust domain federation model, and WIMSE's WIT token envelope — or explicitly specify how Bolyra credentials map to SPIFFE IDs for interoperability with existing SPIFFE-aware infrastructure. The current §5 (Bolyra primitive mapping) is entirely self-referential and does not include a SPIFFE interoperability row.
