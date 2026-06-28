# Tier 3 Adversarial — C2 Cross-scope unlinkability

## Persona: auth0_pm

> Senior PM, MCP Auth product. We ship to 10,000 enterprises. I have seen every "OAuth is architecturally broken" pitch. Let me show you exactly where this one falls apart before procurement does.

---

### Attack 1: The AS-Not-On-Critical-Path Strawman

- **Attack:** Section 8's comparison table claims "every token request hits the AS with (agent_id, RS, scope, timestamp)" as the baseline. That is not how any of us ship. Auth0, WorkOS, and Stytch all issue *signed JWT access tokens* with embedded `scope` and `aud` claims. The RS validates locally using a cached JWKS endpoint — the AS is not contacted at verification time. RFC 8707 (Resource Indicators) adds per-RS audience binding. DPoP adds sender-binding. The AS is on the critical path only at *issuance* (once, then cached) and *refresh* (configurable, e.g. 15 min). The "structural impossibility" claim in §8 is arguing against a 2010 OAuth deployment, not the 2026 market.

- **Why it works / why it fails:** The construction's IND-UNL-AS advantage analysis is mathematically sound *within the game*, but the game is mis-specified relative to the actual threat. The real threat is: AS sees issuance events. Those can already be decoupled from per-request traffic via long-lived JWTs. The construction eliminates *per-verification* AS visibility, which no one actually needs to solve. The *issuance-time* correlation problem (agent requests a JWT for scope=nfcu AND scope=penfed in the same session) is not addressed by this construction — those two issuance calls still hit the AS unless the agent pre-provisions all tokens out-of-band, which is a protocol design problem the construction does not specify.

- **In-threat-model?** No — the construction must either (a) narrow its comparison to issuance-time correlation only and define a matching threat game, or (b) specify how agents pre-provision credentials for all scopes in a single enrollement event without the AS learning the scope set.

---

### Attack 2: Compliance Auditability Inversion

- **Attack:** The exact sectors named in §7 — credit unions (NCUA Part 748, GLBA §501(b)) and healthcare (HIPAA §164.312(b)) — have **mandatory access audit log requirements**. Every access to member financial data or patient records must produce a tamper-evident audit trail naming the accessor, the resource accessed, and the timestamp. This construction's entire value proposition is *cryptographic unlinkability* — that the operator cannot reconstruct the referral graph or merchant graph. But NCUA examiners and HIPAA auditors will explicitly ask: "Show me every access to member account X in the last 90 days." A system that is cryptographically incapable of producing that log is not a compliance win; it is a compliance *blocker*.

- **Why it works:** The construction explicitly optimizes for the property "NFCU cannot reconstruct which merchants the agent visited" (§7, bullet 4–5). This is the *opposite* of what NFCU's BSA officer needs. The nullifier-per-scope design means NFCU holds `scopeNullifier_A` for its own scope but cannot produce a joined audit log across scopes, which is precisely the regulatory ask. The batch relay (§2, batched submission gadget) further obfuscates timing, compounding the audit gap. The healthcare variant compounds this: HIPAA requires a covered entity to produce an accounting of disclosures within 60 days of a member request (45 CFR §164.528) — a ZK scheme that hides which specialist the agent visited from the PCP breaks this requirement structurally.

- **In-threat-model?** No — the construction must define a **selective disclosure** layer: a mode where the credential holder can produce a linkable audit proof (revealing scope identity to a designated auditor, e.g. a regulator) while maintaining unlinkability to unauthorized parties. Without this, the construction is not deployable in either target vertical.

---

### Attack 3: Agent Key Compromise → Permanent Forgeable Credential

- **Attack:** `operatorSecretKey` is now a **private input held client-side by the agent** (§2, private inputs table). If the agent runtime is compromised — jailbroken, prompt-injected to exfiltrate its key material, or its container image is backdoored — the attacker possesses the secret key and can generate valid `ScopeIsolatedAgentPolicy` proofs for *any* scope indefinitely. The only revocation path is posting a new Merkle root that excludes the compromised credential, which requires (a) detecting the compromise, (b) submitting an on-chain transaction, and (c) waiting for RS operators to sync the new root via the "root history buffer." The construction does not specify how RSes learn a root has been revoked — they check `agentMerkleRoot` against a "root history buffer" (§2, verification step 6) but the latency between compromise detection and RS-side enforcement is undefined.

  Meanwhile, Auth0's Machine-to-Machine tokens expire in 86400s by default and can be revoked in `<1s` via `/oauth/revoke`. WorkOS enterprise credentials can be revoked per-session with immediate AS propagation.

- **Why it works:** The construction trades revocability for unlinkability at the key level. For *human* ZK identity (Semaphore pattern), this tradeoff is acceptable because keys are held in hardware wallets and rotate infrequently. For *AI agent* credentials, the key is held in software, in a runtime that executes arbitrary tool calls from an LLM. The attack surface for key exfiltration is orders of magnitude higher. The construction does not acknowledge this or propose agent-specific key hygiene (HSM-backed keys, key rotation cadence, emergency revocation SLA).

- **In-threat-model?** No — the construction must specify: (a) expected key storage requirements for agent runtimes (is an HSM required?), (b) revocation latency SLA and how RSes are notified synchronously, and (c) whether `operatorSecretKey` is per-agent-instance or per-agent-model (if shared across instances, one compromise affects the entire model deployment).

---

### Attack 4: RS-Side Deployment Requirement Kills the Scenario

- **Attack:** The off-chain verification path (§2, verification protocol, steps 3–6) requires every RS to: (1) implement Poseidon3 hashing to recompute `expectedScopeBinding`, (2) deploy or call a ZK verifier (Groth16 or PLONK, ~230K or ~350K gas equivalent off-chain), (3) maintain a local `scopeNullifier` store for Sybil detection, and (4) integrate with the on-chain root history buffer. The concrete scenario in §7 lists NFCU, PenFed, **and a merchant fintech aggregator** all as RSes that must run this stack.

  Paste-an-API-key onboarding (WorkOS, Auth0, Stytch) has a time-to-first-auth of under 5 minutes. The Bolyra RS integration requires: a Circom-compiled verifier, a Poseidon hash library in whatever language the RS uses (the construction does not specify off-chain library support), nullifier store schema migration, and a read connection to an Ethereum node for root queries. The merchant fintech in the scenario is using Stripe Connect or Plaid — they are not running Circom verifiers.

- **Why it works:** The §8 table frames this as a capability gap ("AS sees token issuance per RS" vs. "No"). But the real comparison for a PM is *integration hours × RS count × RS engineering sophistication*. The construction's strongest argument (§8, "structural impossibility") is technically correct but operationally irrelevant if no RS outside the Bolyra ecosystem ever ships the verifier. The PPID + resource indicators baseline does not require RSes to change anything — they already validate JWTs with standard libraries. Bolyra's construction requires every RS to become a ZK verifier. In the target market (credit unions, regional fintechs), that is a multi-quarter engineering project per RS.

- **In-threat-model?** No — the construction must specify: (a) a drop-in RS verification SDK with Poseidon and Groth16 verify implemented for Node, Python, and Java (the dominant RS languages in fintech), (b) a hosted verification endpoint that RSes can call without running the verifier locally (acknowledging the trust tradeoff this introduces), or (c) a realistic adoption sequencing that does not require simultaneous RS upgrades across an ecosystem.


## Persona: cryptographer

**Stance:** "I read the reduction sketch. It has two load-bearing gaps that are not engineering problems — they are definitional failures. The rest are implementation hazards that collapse the claim in realistic deployments."

---

### Attack 1: `scopeCommitment` is a permanent cross-scope linking tag

**Attack:**

The adversary runs the `Prove(·,·)` oracle (which the game explicitly grants) against each agent at any non-challenge scope:

```
scopeCommitment_0 ← pubSignals(Prove(A₀, sid_test))
scopeCommitment_1 ← pubSignals(Prove(A₁, sid_test))
```

Now the challenge proofs π₀, π₁ are presented. Each one contains `scopeCommitment` as a public output. From §2:

```
scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)
credentialCommitment = Poseidon5(modelHash, Ax, Ay, permBitmask, expiry)
```

Because A₀ and A₁ have distinct Baby Jubjub keypairs `(Ax₀,Ay₀) ≠ (Ax₁,Ay₁)`, their credential commitments are distinct, and therefore their `scopeCommitment` values are distinct. Crucially, **`scopeCommitment` does not depend on `scopeId`**. It is a deterministic, agent-unique, scope-independent fingerprint that appears in the public signals of every proof the agent generates.

The adversary trivially maps `pubSignals(π₀).scopeCommitment ∈ {scopeCommitment_0, scopeCommitment_1}` and outputs b′ = 0 if it matches `scopeCommitment_0`.

**Advantage:** 1 — not negligible.

**Why it works:** §2 lists `scopeCommitment` as a public output and §6 confirms it's one of the on-chain posted values. The IND-UNL-AS game in §3 grants full oracle access with only the challenge `(agent, scope)` pairs excluded. The oracle exclusion does not prevent the adversary from learning which `scopeCommitment` belongs to which agent via non-challenge oracle queries.

**In-threat-model?** **No.** The game as written is broken by a one-round oracle attack. The construction must either (a) remove `scopeCommitment` from the public outputs of `ScopeIsolatedAgentPolicy` and handle delegation chain linking via a separate unlinkable commitment, or (b) rerandomize `scopeCommitment` per-scope with a blinding term that's a function of `scopeId`. As written, §8's claim "colluding AS+RS cannot de-anonymize" is false — the AS needs no RS collusion at all.

---

### Attack 2: The PRF reduction requires simulation-extractable ZK; the construction only provides knowledge-sound ZK

**Attack:**

The reduction in §4 constructs a PRF distinguisher B that:

> "simulates the IND-UNL-AS game... B knows the setup and can generate valid proofs for both agents"

To simulate the challenge proof π₀ while replacing `Poseidon2(scopeId, sk_b)` with the PRF oracle output O(sid₀), B must produce a Groth16 proof whose `scopeNullifier` public output equals O(sid₀) **without knowing sk_b**. This requires B to generate a valid proof for a statement whose witness it does not know.

Generating a valid Groth16 proof without the witness requires either:
- Knowledge of the CRS toxic waste τ (i.e., the setup is subverted), or
- A **zero-knowledge simulator** from the simulation-extractable (SE) Groth16 variant.

The construction cites only **Groth16-KS** (knowledge soundness under q-PKE + q-SDH). Knowledge soundness says: any prover that produces a valid proof must "know" a witness. It does **not** provide B with a simulator. The ZK property (honest-verifier or even malicious-verifier) lets the challenger simulate transcripts for known witnesses — but B does not know sk_b when the PRF oracle is random.

Simulation-extractable Groth16 (SE-Groth16, e.g., Abdolmaleki et al., CCS 2019; or the AGM-based analysis by Fuchsbauer et al.) provides a simulator S that can produce accepting transcripts without the witness, while retaining extractability for new proofs. The construction must claim SE-Groth16, not just KS-Groth16, for the reduction to be valid.

**Why it matters:** The distinction is not academic. SE requires additional assumptions (typically the AGM + ROM together, or stronger structured-reference-string assumptions). If the construction is instantiated with a standard Groth16 without SE analysis, the reduction fails, and the IND-UNL-AS claim is unproven even under Poseidon-PRF.

**In-threat-model?** **No — the security proof is incomplete.** The claim "Under the construction below, the adversary's advantage is negligible... assuming Poseidon is a PRF and Groth16/PLONK achieve knowledge soundness" is an incorrect assumption set for the reduction as sketched. The construction must add SE-Groth16 (or reprove under the AGM) to the named assumptions in §4.

---

### Attack 3: `operatorSecretKey` ambiguity — operator-scoped key collapses both Sybil-resistance and unlinkability

**Attack:**

The existing `AgentPolicy` circuit (CLAUDE.md: `createAgentCredential(modelHash, operatorPrivKey, permissions, expiry)`) encodes ONE `operatorPrivKey` per operator entity. The `ScopeIsolatedAgentPolicy` circuit adds `operatorSecretKey` as a private input to derive:

```
scopeNullifier = Poseidon2(scopeId, operatorSecretKey)
```

If `operatorSecretKey` is the **operator's master signing key** (i.e., the same key used to sign all agent credentials issued by that operator), two catastrophes follow:

**Catastrophe A — Sybil collapse:** All agents issued by the same operator produce **identical** `scopeNullifier` at each scope. The RS cannot distinguish between them; the nullifier-based Sybil detection fails entirely.

**Catastrophe B — AS precomputes entire nullifier space:** The AS, as the credential issuer, knows `operatorSecretKey`. Given a set of known RS scope identifiers (public endpoints), the AS can precompute `Poseidon2(sid_i, operatorSecretKey)` for every `sid_i` in the ecosystem. It then matches on-chain or off-chain nullifiers to individual scopes, reconstructing the full traffic graph without the ZK property providing any protection.

The construction introduces `BabyPbk(operatorSecretKey)` key consistency in §2, which proves the prover knows the secret key corresponding to the public key in the credential. If the intent is one public key per AGENT (not per operator), then `operatorSecretKey` must be an AGENT-SPECIFIC ephemeral secret unknown to the operator. The specification does not state this. The public API `createAgentCredential(modelHash, operatorPrivKey, ...)` in the SDK suggests operator-scoped keys.

**Formal game impact:** The IND-UNL-AS game's §3 adversary capability explicitly excludes `operatorSecretKey` from adversary control. But in a deployment where the AS is the operator (the most natural threat scenario described in §7 — "NFCU acts as the AS"), the AS IS the holder of `operatorSecretKey`. The threat model in §3 and the deployment scenario in §7 are contradictory.

**In-threat-model?** **No — for the primary deployment scenario.** The game says the adversary lacks `operatorSecretKey`; the scenario says the AS is the credential operator who controls `operatorSecretKey`. The construction must either (a) mandate that each agent generates an independent ephemeral Baby Jubjub keypair not known to the operator, and prove the credential binds to that ephemeral key, or (b) acknowledge that operator-level AS adversaries are out of scope and narrow the threat model accordingly. Neither option is exercised in the current document.

---

### Attack 4: Trusted-setup scope — `ScopeIsolatedAgentPolicy` is a new circuit; no ceremony specification exists

**Attack:**

`ScopeIsolatedAgentPolicy` has ~15,500 constraints vs `AgentPolicy`'s ~12,500. These are **different circuits with different R1CS matrices** — same pot16.ptau universal SRS may be reused, but the **circuit-specific Groth16 proving key** (`alpha_1`, `beta_2`, `delta_1`, etc.) must be freshly computed in a new circuit-specific ceremony. The document:

- References `pot16.ptau` as the universal SRS (reusable across circuits ✓)
- Does not specify a new MPC ceremony for `ScopeIsolatedAgentPolicy`
- Does not specify how toxic waste from the new circuit-specific setup is destroyed
- Does not specify whether the new `.zkey` is a contribution chain or a fresh setup

Under a **subverted circuit-specific setup** (adversary knows the toxic waste τ for the new `.zkey`):

- The adversary can forge proofs for arbitrary public signals: any `(agentMerkleRoot, scopeNullifier, scopeCommitment, scopeBinding)` tuple without knowing any private witness.
- More specifically: the adversary can generate proofs where `agentMerkleRoot` is a valid on-chain root but the `scopeNullifier` is chosen to match any target agent — reintroducing linkability by planting colluding nullifiers.
- The adversary can inject a "marker" into `scopeBinding` by choosing a malformed `scopeId` in a forged proof, then query colluding RSes for this marker.
- Knowledge soundness (Groth16-KS) **provides no protection** under subverted setup — KS applies only when the CRS is honestly generated.

The paper does not analyze this attack surface. Notably, §4 names "Groth16-KS" as an assumption but does not condition it on "CRS is honestly generated by a ceremony the adversary did not subvert." Universal composability under setup compromise (Canetti et al., "Universally Composable Security with Global Setup") would require the setup itself to be UC-secure, which is a distinct and stronger requirement.

**PLONK note:** PLONK avoids per-circuit trusted setup by using a universal SRS. If the construction committed to PLONK-only for `ScopeIsolatedAgentPolicy`, this attack surface shrinks to the universal SRS security (which still requires a ceremony, but of smaller scale). The document permits either proving system and does not mandate PLONK.

**In-threat-model?** **No — the threat model in §3 states the adversary cannot break Poseidon preimage resistance or extract witnesses from Groth16/PLONK, but it does not bound the adversary's ability to subvert the trusted setup.** A complete threat model must either (a) add "setup is honestly generated" as an explicit assumption, with a reference to a ceremony specification, or (b) mandate PLONK for this circuit (avoiding the per-circuit ceremony) and prove security under the universal SRS model. The current document does neither.

---

**Bottom line:** Attacks 1 and 2 are formal breaks of the stated IND-UNL-AS game under the construction as written. Attack 3 is a deployment-model contradiction that invalidates the primary scenario in §7. Attack 4 is a missing assumption that silently collapses the entire scheme under realistic adversary control. The construction is not marketing — the intent is correct and the primitive choices are reasonable — but the security statement cannot be signed off as written.


## Persona: cu_ciso

---

### Attack 1: Audit Trail Destruction — the Privacy Property Is a GLBA Violation

- **Attack:** I pull up GLBA Safeguards Rule §314.4(e) and NCUA Part 748 Appendix A §III.C (audit and accountability controls). My examiner will ask: "Produce all resource accesses by member agent X between Jan 1 and Mar 31." Under this construction, the off-chain path is explicitly the **primary path** and the AS "never sees per-RS traffic" (§2, Verification Protocol). The `scopeId` is a **private circuit witness**. My CU, as operator/AS, holds `scopeNullifier_A` (for our own scope) and nothing else. We have no audit record that the agent accessed PenFed or the merchant. We didn't see the proof. We can't reconstruct the traffic. The scope unlinkability that's the entire claim of C2 **is the NCUA exam finding**.

- **Why it works:** The construction successfully eliminates the AS from the per-request critical path (§8). It does not distinguish between a *competitive* AS (NFCU spying on PenFed traffic — the threat model) and a *compliance* AS (NFCU maintaining its own BSA/AML audit log for its own member's agent). These are the same architectural pathway. The batch relay compound this: nullifiers posted there have no scope annotation, no timestamp attributable to a specific member authorization event, no counterpart log entry. Section 7's deployment scenario explicitly celebrates that "NFCU sees only `scopeNullifier_A`" — which means NFCU's audit log is missing two of the three authorization events for its own member's agent.

- **In-threat-model?** **No** — construction must address. The IND-UNL-AS game (§3) treats the AS as a pure adversary. Regulatory deployments require the *issuing* CU to be a *privileged* auditor, not an untrusted party. The construction needs a separate audit path — e.g., an encrypted scope-revelation proof delivered to the issuing AS only, or a selective-disclosure mechanism that lets the member's own CU reconstruct its own agent's scope sequence without leaking it to third-party RSs. This is architecturally distinct from what C2 currently specifies.

---

### Attack 2: Key Custody Non-Answer — `operatorSecretKey` Lives Nowhere Defensible

- **Attack:** I open NCUA Letter 01-CU-20 (Authentication Guidance) and FFIEC Authentication Guidance (2011, updated 2021). The circuit's private input table (§2) lists `operatorSecretKey: F_p — Operator EdDSA secret scalar`. The construction provides **zero specification** of where this value is stored, who generates it, and what key management lifecycle applies. For the cross-CU scenario in §7, the agent is a member-deployed AI (not a CU-operated server). That means `operatorSecretKey` is on the member's device — browser, mobile, edge runtime. There is no HSM. There is no FIPS 140-2 boundary. There is no MFA protecting key extraction. When my Tier 1 ops team gets a call that a member's agent drained their PenFed account and the member claims the key was stolen from their laptop, I have no compensating control to point to. My examiner asks: "What is your key management program for agent signing keys?" My answer is "the member's browser."

- **Why it works:** The security argument (§4) correctly reduces to DL-BabyJubjub — an adversary without `operatorSecretKey` cannot forge scope nullifiers. But DL hardness assumes the key is secret. Nothing in the construction enforces that assumption at rest. The Knowledge Soundness argument proves no one can *extract* the key from a proof — it says nothing about exfiltration from the endpoint holding the key before proof generation. Section 2's private input table is a circuit spec, not a key management spec. GLBA Safeguards §314.4(f) requires "access controls on customer information systems" — a browser-resident EdDSA scalar fails this test trivially.

- **In-threat-model?** **No** — construction must address. Minimum required: specify key storage tiers (HSM-backed operator server vs. user-device key), define which deployment configurations are CU-grade vs. consumer-grade, and provide a key compromise response procedure that doesn't require the agent's secret to revoke cross-scope nullifiers (see Attack 3).

---

### Attack 3: Revocation SLA — Compromised Credential Cannot Be Recalled Across Scopes

- **Attack:** At 2am, our fraud team flags anomalous activity from a member agent. I need to revoke it. Under the construction, revocation means updating the agent Merkle tree to exclude the agent's credential leaf (§2, `agentMerkleRoot` is a public output checked against on-chain root history). But: (a) the on-chain Merkle root update requires a transaction with finality latency (Base Sepolia, §Architecture — 2-second slot, but real finality is longer); (b) the **off-chain path is primary** — RS verification checks `agentMerkleRoot` against the on-chain "root history buffer" (§2), not the latest root. How deep is that buffer? If it's 256 roots, a compromised agent credential may be valid against stale roots for the entire buffer window. (c) Each RS maintains its own local `scopeNullifier` store (§2, step 5), but revocation of a credential does not automatically propagate to each RS's store — the RS won't know to reject the old nullifier until its root history cache expires. The construction has no revocation notification protocol.

- **Why it works:** Section 2's RS verification step 6 says "RS checks `agentMerkleRoot` against the on-chain root history buffer." A root history buffer exists precisely to tolerate Merkle root staleness — which also means a revoked credential's old root may still be in-buffer and accepted. The construction offers no mechanism for the issuing CU to push a revocation notice to RSs that have already verified a scope nullifier. FFIEC CAT Domain 2 (Threat Intelligence) and NCUA third-party risk guidance both require the ability to terminate service and confirm termination within defined SLAs. "Wait for root history buffer to expire" is not a SLA I can present to my board or examiner.

- **In-threat-model?** **No** — construction must address. A credential revocation event (Merkle root update) must propagate to RS nullifier stores within a bounded window, or the construction needs a separate revocation list (CRL equivalent) that RSs must check independently of the root history buffer. The tradeoff between root history depth (availability) and revocation latency (security) must be explicitly specified with CU-grade SLA numbers attached.

---

### Attack 4: Batch Relay Is an Unaudited Concentration Risk

- **Attack:** I pull up NCUA Supervisory Letter 07-01 (Third-Party Due Diligence) and FFIEC IT Examination Handbook (Outsourcing Technology Services). Section 2 introduces a **batch relay contract** to mitigate timing side channels: "Agents MAY batch multiple scope proofs and submit them in a single transaction to a batch relay contract. The batch relay shuffles and posts nullifiers with uniform timing." This relay is an on-chain smart contract. Questions I cannot answer from this document: Who operates it? What is its audit status (SOC 2 Type II? Smart contract audit by whom?)? What is its uptime SLA — and is it better than my core processor's 99.95%? What is the gas cost SLA during network congestion? If the relay is unavailable, does authorization fall back to direct (unshuffled, timing-leaking) submission, or does it fail closed? The construction says "Agents MAY batch" — so the timing protection is **optional**, which means I cannot represent it as a control.

- **Why it works:** The construction defines the batch relay as a mitigating gadget for the timing side channel (noted as an open gap in the candidate's `gap_to_close`). But it specifies the relay only at the functional level. A smart contract on Base Sepolia is a fourth-party dependency — my CU's member agents depend on it, my CU does not operate it, and if it is the construct through which unlinkability is operationally achieved, it is a technology service provider requiring due diligence under NCUA guidance. The "MAY" construction in the spec means the timing side channel mitigation is not a guaranteed property of any deployment — an examiner reading §3's "passive network adversary" capability and §2's batch relay would correctly note that the timing protection is optional and vendor-dependent.

- **In-threat-model?** **Partially** — the timing side channel is acknowledged. But the construction must address: (a) define batch relay as a normative component with specified SLA if timing protection is a security claim; (b) identify who is responsible for operating and auditing it; (c) specify fallback behavior when the relay is unavailable; (d) clarify whether the timing guarantee is a SHOULD or a MUST in the security proof. If it's a SHOULD, §3's adversary capabilities should include "observes unshuffled proof submission timing in non-batched deployments" — which reopens the timing correlation attack the relay was meant to close.


## Persona: rfc7662_advocate

*OAuth Working Group veteran. Ten years shipping production introspection. Every ZK claim is suspect until proven not achievable by the RFC suite. Let's look at what you've actually built.*

---

### Attack 1: `scopeCommitment` is a permanent cross-scope fingerprint — the construction self-deanonymizes

**Attack:** The circuit's public outputs (Section 2) include:

```
scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)
```

where `credentialCommitment = Poseidon5(modelHash, Ax, Ay, permBitmask, expiry)` (§5.2 primitive mapping). Every field in `credentialCommitment` is fixed at enrollment time and never changes across scope invocations. Therefore `scopeCommitment` is a **deterministic, constant fingerprint** for the same agent credential.

Section 2's on-chain path explicitly states: *"Only the `scopeNullifier`, `scopeCommitment`, and `agentMerkleRoot` are posted on-chain."* So `scopeCommitment` appears in every on-chain record, globally visible.

The adversary in the IND-UNL-AS game wins trivially: upon seeing `pubSignals(π₀)` and `pubSignals(π₁)`, they check whether `scopeCommitment₀ == scopeCommitment₁`. For the real-world scenario — same agent, different scopes — this equality holds with probability 1. In the deployment scenario (Section 7), NFCU colluding with the merchant holds on-chain records for scope A and scope C; both carry identical `scopeCommitment` values. The cross-scope fingerprint is worse than any RFC 7662 correlation vector because it is cryptographically stable and doesn't require the AS to be in the loop.

**Why it works against the construction:** The construction deliberately posts `scopeCommitment` on-chain for "delegation chain seeding" (Section 2). This is a legitimate use case, but it directly conflicts with the unlinkability claim. The two requirements — stable delegation anchor vs. unlinkable cross-scope identity — are architecturally contradictory with the current design.

**Structural fix required:** `scopeCommitment` must be scope-dependent, e.g., `Poseidon3(scopeId, permissionBitmask, credentialCommitment)`, making it vary per RS while still being verifiable by the RS (which knows its own `scopeId`). But this breaks cross-scope delegation chain linking, which uses `scopeCommitment` as a stable reference. The construction needs a two-commitment design: one stable root commitment (never published) and one scope-blinded commitment (published per RS). That is a larger architectural change than the construction acknowledges.

**In-threat-model?** **YES — construction does NOT survive in current form.** The scopeCommitment leak is not a side channel; it is a primary public output that directly enables cross-scope correlation by any on-chain observer, AS or otherwise. The IND-UNL-AS reduction sketch in Section 4 does not mention this signal at all.

---

### Attack 2: The IND-UNL-AS game models the wrong threat — it cannot detect same-agent cross-scope linkage

**Attack:** The IND-UNL-AS game as defined (Section 3) enrolls **two distinct agents** A₀ and A₁ and asks the adversary to guess *which* agent visited *which* scope. This models a "which of these two agents?" question. It does **not** model the actual deployment threat, which is:

> *Given π₀ from RS-A and π₁ from RS-B, can the adversary determine whether they originate from the SAME agent?*

The correct game is a **same-or-different** distinguisher:

```
b=0: (π₀, π₁) ← Prove(sk, sid₀), Prove(sk, sid₁)       // same agent, two scopes
b=1: (π₀, π₁) ← Prove(sk₀, sid₀), Prove(sk₁, sid₁)     // two different agents
```

The construction's game never exercises this scenario. In the Section 3 game, the challenge always involves one proof from A₀ and one from A₁ — the adversary is distinguishing permutation, not presence. An adversary that can identify "these two proofs are from the same credential" with non-negligible advantage trivially breaks the real-world property but may be undetectable under the stated game.

**Concrete consequence:** If `agentMerkleRoot` is stable across proof generations by the same agent (it is, between tree updates), and if the tree has low churn, then seeing the same `agentMerkleRoot` across two proofs is already a k-anonymity narrowing signal. In the same-or-different game, this matters: proofs from the same agent at two different RSes share `agentMerkleRoot`, `scopeCommitment` (see Attack 1), and fall in the same batch window (see Attack 4). An adversary playing same-or-different doesn't need to break the PRF — they just correlate correlated public outputs.

The IND-UNL-AS reduction in Section 4 correctly reduces scopeNullifier unlinkability to Poseidon-PRF. But the game formulation provides much weaker guarantees than the deployment claim in Section 1 ("same agent accessing N distinct RSes"). The formal claim and the formal game are not aligned.

**RFC 7662 jab:** RFC 7662 + PPID already achieves the construction's stated IND-UNL-AS game: pairwise subject identifiers produce different `sub` values per RS for the same user, the AS issues the PPID mapping, and a "which agent visited which RS" adversary cannot link pairwise identifiers without AS collusion. The construction's IND-UNL-AS advantage over PPID is not demonstrated by the current game.

**In-threat-model?** **YES — the game definition must be replaced.** The claim in Section 1 is about same-agent cross-scope identity. The game in Section 3 models different-agent scope permutation. The security argument does not cover the stated claim.

---

### Attack 3: JWT introspection response (signed, encrypted per-RS) removes the AS from the per-request hot path — the §8 impossibility argument is overstated

**Attack:** Section 8's "structural impossibility" row states: *"AS sees token issuance per RS → Yes (baseline)"* and claims *"no standards-track mechanism in OAuth/OIDC can retrofit this property."* This is factually overstated for the following deployment:

1. **RFC 8707 Resource Indicators** at token issuance time: the agent requests a separate, audience-bound access token per RS (`resource=https://rs-a.example`). These tokens may all be issued in a single batch request at enrollment time.
2. **Draft JWT introspection response** (draft-ietf-oauth-jwt-introspection-response): AS signs an encrypted JWT introspection response per token, encrypted to the RS's public key. The RS caches this response for the token's lifetime.
3. **RFC 9449 DPoP**: tokens are sender-constrained to the agent's key; replay across RSes is impossible.
4. **Result:** After enrollment-time issuance, the AS is completely off the request hot path. The RS verifies the cached JWT introspection response locally, exactly as the ZK construction's RS verifies a ZK proof locally.

The construction's claim that "AS necessarily observes all issuance events" is true — but so does Bolyra. The Bolyra agent enrolls in the Merkle tree, which requires an enrollment operator (who is logically equivalent to the AS). The enrollment operator knows the full permission set and the agent's model hash. The credential is signed by the operator key. This is isomorphic to an AS issuing a token.

The remaining delta is: in Bolyra, the AS (operator) does not see *which RS* each issued credential targets, because scopeId is a private circuit input. In the JWT introspection deployment, the AS sees `resource=rs-a` at issuance time. **This is the real, narrowly-scoped advantage** — not the sweeping "AS is eliminated from all critical paths" claim.

The honest version of §8's table row should read: *"AS sees target RS at issuance → Yes (baseline), No (Bolyra — scopeId is never revealed to operator even at enrollment)."* The current framing conflates per-request correlation (addressed) with enrollment-time correlation (also present in Bolyra) and overstates the impossibility.

**In-threat-model?** **Partial — the construction survives but §8's impossibility argument must be tightened.** The actual advantage is specifically that `scopeId` is never revealed to the operator/AS at any point, not that the AS is structurally eliminated. This is a meaningful but narrower claim.

---

### Attack 4: The batch relay converts timing side-channel into on-chain clustering — worse than DPoP's AS-side timing

**Attack:** Section 2's batched submission gadget states: agents submit nullifiers in a single transaction to the batch relay contract, which "shuffles and posts nullifiers with uniform timing." The batch window is 1–60 seconds.

This creates a new, worse linkability vector:

- On-chain, a single transaction contains `[nullifier_A, nullifier_B, nullifier_C]` posted by the same agent in the same batch.
- The transaction itself is a cryptographic clustering signal: any on-chain observer, including the AS, sees that these three nullifiers appeared in the same block, same transaction, from the same sender address.
- Even with shuffling within the batch, the batch boundary is observable.
- Compare to the DPoP baseline: DPoP timestamps leak request timing to the AS but each request is independent. There is no single artifact grouping multiple RS accesses into one observable cluster.

The construction attempts to hide which scope each nullifier belongs to (nullifiers are scope-specific via PRF). But the batch transaction reveals the *cardinality* and *co-occurrence* of access events: "this agent accessed exactly 3 RSes within a 10-second window." For the healthcare scenario (Section 7), a cardiology and dermatology referral appearing in the same batch transaction is more revealing than either referral alone.

Additionally, the relay is opt-in ("Agents MAY batch"). If the agent submits nullifiers individually for any reason — latency, relay unavailability, offline RS — the baseline timing correlation returns. The construction provides no timing guarantee for the non-batching path.

**RFC 9449 comparison:** DPoP does leak per-request timestamps to the AS, but those timestamps are private (visible only to the AS receiving the request). The batch relay's timing clusters are public, permanent, on-chain. An adversary monitoring the chain post-hoc can reconstruct co-access patterns from batch membership even if they were not present at request time.

**In-threat-model?** **YES — the batch relay is described as a mitigation but introduces a new public co-occurrence oracle.** The construction must either (a) make batching mandatory and enforce uniform batch sizes (preventing cardinality leakage), (b) use a mixer/tornado-style contract that breaks batch membership linkage, or (c) abandon the on-chain path for nullifier submission and rely entirely on per-RS off-chain storage. The current opt-in, variable-size batch relay may be net negative for the timing side-channel threat model.


## Persona: spiffe\_engineer

---

### Attack 1: Operator-AS Key Conflation — The PRF Key Is Not Secret from the Adversary

**Attack:**

Section 2 derives scope nullifiers as `Poseidon2(scopeId, operatorSecretKey)`. Section 3 lists as a hardened assumption: "Adversary does NOT have the operator's EdDSA secret key (`operatorSecretKey`)." But Section 7's concrete scenario explicitly names NFCU as **both the AS and the operator** who signs the credential with their operator key. NFCU holds `operatorSecretKey` by construction — it is the entity that issues the `sigR8x/sigR8y/sigS` credential signature over the `credentialCommitment`. Any entity that can sign credentials knows the key used for signing, and that same key is the PRF seed for every scope nullifier the agent will ever produce.

A colluding-AS adversary in the IND-UNL-AS game has access to all Merkle roots and public signals **plus** — in the named deployment scenario — the PRF key itself. The adversary does not need to break Poseidon-PRF; it simply evaluates `Poseidon2(sid_penfed, operatorSecretKey)` and `Poseidon2(sid_merchant, operatorSecretKey)` directly. Section 7's prose quietly substitutes the phrase "agentSecret" where the circuit table says `operatorSecretKey` — these are not the same thing. There is no `agentSecret` signal in the private inputs table.

**Why it works:** The IND-UNL-AS adversary capability list (§3) is inconsistent with the deployment scenario (§7). In SPIFFE terms: this is the classic mistake of conflating the **node attestor secret** (operator) with the **workload's own secret** (agent). SPIRE separates these: the agent/node attestor issues the SVID, but the workload presents it without the attestor knowing the per-request audience. Bolyra's `operatorSecretKey` needs to be an **agent-held** secret unknown to the issuer, which requires a second key-generation ceremony at agent enrollment (analogous to SPIRE's workload API ephemeral key pair). The circuit needs a `agentSecretKey ≠ operatorSecretKey` as the PRF seed.

**In-threat-model?** **No — construction must address this.** The threat model's assumption (AS does not hold `operatorSecretKey`) fails in every deployment where AS == operator, which is the only concrete scenario given. This breaks the IND-UNL-AS claim entirely.

---

### Attack 2: SPIFFE JWT SVIDs Already Provide Offline Presentation — Section 8's "Structural Impossibility" Is Wrong

**Attack:**

Section 8 states: "The AS is the root of trust and necessarily observes all issuance events" and "No standards-track mechanism in OAuth/OIDC can retrofit this property because the AS's role as token issuer is load-bearing." This is factually incorrect for SPIFFE JWT SVIDs.

SPIRE issues JWT SVIDs with a `aud` (audience) claim on a **rotation schedule** (default: 1-hour TTL). The workload fetches the SVID from the local Workload API socket — SPIRE never sees which RS the workload presents it to. The SPIRE server observes the rotation event (workload renews its SVID every hour), not the individual RS access. A workload that contacts 100 RS instances within a single SVID lifetime produces zero AS-visible issuance events beyond the initial rotation. The "per-request AS visibility" property claimed in Section 8's baseline comparison does not apply to SPIFFE JWT SVIDs with rotation intervals longer than a typical request burst.

Furthermore, draft-ietf-wimse-arch §4.3 ("Workload Token") defines a workload-signed token for service-to-service authentication that does not require AS participation in the data plane. The construction's §8 table compares against "Baseline (PPID + DPoP + BBS+)" but ignores WIMSE, which is the directly competing IETF work.

**Why it partially fails against the construction:** ZK scope nullifiers do provide **stronger** unlinkability than SPIFFE JWT SVIDs — specifically, even within a single SVID rotation window, a malicious RS that receives a JWT SVID can reconstruct the SPIFFE ID and correlate identity across scopes (since the SVID's `sub` is the same SPIFFE URI every time). ZK nullifiers are per-scope and unlinkable. So the ZK advantage is real but narrower than claimed.

**In-threat-model?** **Partially yes, but construction must address the overclaim.** The "structural impossibility" argument in §8 is wrong. The correct claim is: "SPIFFE JWT SVIDs are unlinkable to the AS per-request but linkable to colluding RS pairs via the `sub` field. ZK scope nullifiers eliminate RS-level linkability. WIMSE does not yet define a scope-isolation primitive." The construction should scope its advantage claim to RS-colluding-with-AS linkability, not AS-sees-all-issuance.

---

### Attack 3: PRF Reduction Simulation Gap — The Reduction Sketch Is Circular

**Attack:**

The reduction sketch in Section 4 claims: "B simulates the IND-UNL-AS game. For the challenge agent (say agent b=0), B uses the PRF/random oracle to compute scopeNullifiers instead of Poseidon2(scopeId, sk₀)."

But B set up the game. B runs `KeyGen(pp)` twice to produce `(sk₀, pk₀, cred₀)` and `(sk₁, pk₁, cred₁)`. B therefore **knows both secret keys**. B can evaluate `Poseidon2(scopeId, sk₀)` directly without querying the PRF oracle. The PRF oracle is never actually needed — B can simulate all public signals for both agents using the known keys. The reduction degenerates: it never actually uses the distinguishing oracle, so it cannot produce a valid reduction from IND-UNL-AS advantage to PRF advantage.

A correct reduction would need to embed the PRF challenge into the game in a way where the simulator does **not** know the secret key for at least one agent. This requires a different setup: e.g., the challenger generates one of the two agents' keys and provides only the public key + enrollment credential to the simulator, forcing the simulator to use the PRF oracle for that agent's nullifiers. The current sketch does not construct this.

Additionally, the `Prove(·,·)` oracle restriction is underspecified: the adversary is blocked from requesting proofs for `(b, sid₀)` and `(1−b, sid₁)` — but it can still request `(b, sid₁)` (challenge agent at non-challenge scope). If the adversary receives `Poseidon2(sid₁, sk_b)` from the oracle and separately receives the challenge signal `Poseidon2(sid₁, sk_{1-b})` in π₁, it can distinguish whether `b=0` or `b=1` by checking nullifier equality — the oracle restriction as written does not block this.

**In-threat-model?** **No — construction must address this.** The reduction does not establish the claimed security. The IND-UNL-AS game oracle needs a cross-scope restriction: the adversary must be blocked from querying *either* challenge agent at *any* scope that would allow cross-scope nullifier comparison. The reduction must be rebuilt with one agent's key hidden from the simulator.

---

### Attack 4: Trust-Domain Federation as a Drop-In — Name the Gap Precisely

**Attack:**

Section 7's healthcare scenario: PCP issues an agent credential; the agent visits two specialists without the PCP learning the referral network topology. In SPIFFE: the PCP's SPIRE server is a trust domain anchor. PenFed's specialist runs a SPIRE federation bundle. The PCP's SPIRE server never observes which federated trust domains the agent's SVID is presented to — the agent presents its X.509 SVID to each federated service via mTLS, and the PCP's SPIRE server has no data-plane visibility into those presentations. SPIFFE federation (draft-ietf-wimse-x509-federation) gives exactly the "issuer does not learn referral topology" property claimed in §7.

The construction's §8 does not identify what gap federation fails to close. The claim that "PPID hides the sub from PenFed/merchant but NFCU sees the full traffic graph" applies to OAuth PPID — it does not apply to SPIFFE federation where the issuing SPIRE server has no data-plane role after SVID issuance.

The construction must articulate a specific property that SPIFFE federation cannot provide. Candidates that might be defensible: (1) RS-colluding-with-issuer linkability via SVID `sub` field — a colluding specialist can share the SPIFFE URI with the PCP to reconstruct referral linkage; ZK scope nullifiers prevent this. (2) Selective disclosure of permission bitmask — SPIFFE SVIDs do not carry ZK-verifiable permission constraints; claims in JWT SVIDs are in the clear. If the construction's advantage claim is precisely (1) and (2), state that. As written, §8 implies a broader impossibility that federation refutes.

**In-threat-model?** **Yes — construction survives if it tightens the claim.** ZK unlinkability against a colluding RS+issuer pair is a genuine gap in SPIFFE federation (SVID `sub` is correlatable). The construction should replace the "structural impossibility" framing with: "SPIFFE federation prevents issuer data-plane visibility but does not prevent RS-colluding-with-issuer `sub` correlation. Scope-isolated ZK nullifiers close this residual linkage. Additionally, ZK circuits enforce permission bitmask constraints verifiably without revealing scope identity in the clear."
