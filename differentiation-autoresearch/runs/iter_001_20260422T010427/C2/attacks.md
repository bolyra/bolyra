# Tier 3 Adversarial — C2 Cross-scope unlinkability

## Persona: auth0_pm

### Attack 1: Proving Latency Makes This Dead on Arrival for Interactive Agents

- **Attack**: The PM points to §6, which claims "< 3 seconds" per `ScopedAccess` proof. An agent accessing 3 RS instances in a single workflow (the construction's own §7 scenario: auto dealer → healthcare → grocery) requires 3 sequential proof generations = **≥9 seconds of auth overhead** before the first business action completes. WorkOS issues tokens in <100ms. Cloudflare Access terminates at edge in <50ms. The PM asks: "Show me a credit union member who will wait 9 seconds for their agent to authenticate before doing anything useful. Show me the UX research."

- **Why it works / fails**: The construction does not address **proof parallelism** (can the agent generate multiple `ScopedAccess` proofs concurrently?), **proof caching** (can a valid proof be reused within its epoch without regeneration?), or **speculative pre-proving** (prove before the user triggers access). The 3-second estimate is for a ~13K constraint PLONK circuit which is plausible, but the construction makes no architectural claim about parallel generation. For sequential multi-RS workflows, the additive latency is a real UX regression vs. <100ms OAuth tokens.

- **In-threat-model?** **No.** The construction has no latency budget or parallelism strategy. It must address: (a) whether proofs for different scopes can be generated in parallel using the same `agentSecret`, (b) whether a proven proof can be cached and resubmitted within the same `epochSalt` window without reproving, and (c) what the UX contract is for the 3-second window (loading state? pre-warming?).

---

### Attack 2: The scopeId Trust Problem — Who Owns the Namespace?

- **Attack**: The construction defines `scopeId = Poseidon hash of RS domain` (§2, §7 step 3), but this is **never enforced inside the circuit**. The `scopeId` is a **public input** — the prover supplies it. The RS accepts any proof with a valid `scopeNullifier` for the `scopeId` the RS expects, but there is no on-chain registry preventing two colluding RS instances from **agreeing to use the same `scopeId`**. If RS-A (auto dealer) and RS-B (healthcare) both announce `scopeId = Poseidon("shared-scope")`, then `scopeNullifier_A = scopeNullifier_B = Poseidon2("shared-scope", agentSecret)` — the nullifiers are **identical**, and the two RS operators can trivially link every access from the same agent. The IND-UNL-AS game in §3 assumes the adversary "cannot" do this, but the assumption is not enforced by the protocol.

- **Why it works**: The construction's unlinkability reduction in §4 rests entirely on `j_0 ≠ j_1` (distinct scopes). The game definition in §3 stipulates "two distinct scopes `j_0, j_1`" — but "distinct" is a semantic property of the RS, not a cryptographic constraint in the circuit. A colluding (AS + RS-A + RS-B) adversary can choose `j_0 = j_1` by agreeing out-of-band on a common scopeId, collapsing the unlinkability entirely. The construction's §8 claims "different scopes → computationally unlinkable nullifiers" but this is only true when scopes *are* different — a condition the construction provides no mechanism to guarantee.

- **In-threat-model?** **No.** The construction must add a scopeId uniqueness enforcement mechanism — e.g., an on-chain scope registry where each RS registers a `scopeId` that is a verifiable hash of their verified domain certificate, or a circuit constraint tying `scopeId` to a trusted registry root. Without this, the IND-UNL-AS game's precondition `j_0 ≠ j_1` is a client-side honor system.

---

### Attack 3: epochSalt Controller Breaks Unlinkability Across Epochs

- **Attack**: §2 states the `epochSalt` is "committed on-chain at epoch start" and the circuit checks `epochCommitment === Poseidon2(epochSalt, scopeId)`. But **the construction never specifies who commits the epochSalt**. In the §7 deployment scenario, SECU operates the AS *and* is the natural operator of the smart contract infrastructure. If SECU (the adversarial AS) controls the epoch commitment contract, it can set `epochSalt_agent_i = Poseidon(agentPublicKey_i, epochNumber)` — an agent-specific salt masked as a global epoch parameter. The circuit verifies `epochCommitment === Poseidon2(epochSalt, scopeId)` but has **no constraint that `epochSalt` is the same for all agents in the same epoch**. An AS-controlled contract can issue per-agent epoch salts, making `epochBinding = Poseidon2(scopeNullifier, epochSalt_agent)` a deterministic function of the agent identity even across epoch boundaries — destroying cross-epoch unlinkability and potentially enabling cross-scope correlation.

- **Why it works**: The reduction sketch in §4 proves security assuming `epochSalt` is uniformly random and independent of the agent's identity. But the circuit's constraint 11 (`epochCommitment === Poseidon2(epochSalt, scopeId)`) only validates consistency between what's in the proof and what's on-chain — it does not prevent the on-chain contract from committing a per-agent salt. The AS can publish `n` different "epoch commitments" for the same epoch, one per enrolled agent, and supply each agent the corresponding `epochSalt` during proof generation. The agent's circuit will verify correctly (it checks against its own `epochCommitment`), but the AS now has agent-tagged epoch data. The §3 adversary capability list includes "Nonce manipulation: Supply adversarially chosen `epochCommitment` values" — this attack is within the stated capabilities.

- **In-threat-model?** **Yes, partially** — the adversary capability includes epochCommitment manipulation, but the construction's defense ("epochSalt is committed on-chain") assumes a neutral or verifiable commitment mechanism that the construction does not specify. This must be addressed: the epochSalt must be derived from a publicly verifiable, AS-independent source (e.g., block hash, VDF output, or a permissionless commit-reveal with multiple independent participants).

---

### Attack 4: Procurement Reality — The Construction Has No Enterprise Validation Path

- **Attack**: The PM goes to the procurement checklist. Auth0 has SOC 2 Type II. WorkOS has HIPAA BAAs and enterprise SLAs. Cloudflare has FedRAMP. Bolyra is a solo-founder protocol with zero production deployments, no credit union design partner LOI, no third-party cryptographic audit of the `ScopedAccess` circuit or the IND-UNL-AS game proof, and no operational runbook for what happens when the epoch commitment contract fails, the Merkle root diverges, or a proving library CVE drops. The PM asks: "When SECU's CISO asks 'who do I call at 2am when this breaks,' what is the answer?" The cryptographic strength rating of 9/10 means nothing to the procurement committee that wants a vendor with a legal entity, cyber liability insurance, and a named account executive.

- **Why it works**: The construction is evaluated on cryptographic correctness (C2 with target strength 10), but the gap between "cryptographically sound" and "enterprise procurable" is not a cryptographic gap — it's a GTM, legal, and operational gap. The construction's §7 deployment scenario names SECU as the AS operator but contains no discussion of: audit trail requirements under NCUA examination, incident response obligations, liability for false proofs accepted due to an undiscovered circuit bug, or upgrade path when the Poseidon-PRF assumption is revisited. Auth0's MCP auth product (auth0.com/ai/docs/mcp/intro/overview) ships today with a documented upgrade path, audit logging, and enterprise support tiers. The construction's formal security argument (§4) is stronger than anything Auth0 offers cryptographically — but procurement doesn't buy Theorem 1.

- **In-threat-model?** **No** — this is outside the cryptographic threat model by definition, but it is the correct framing for the auth0_pm persona. The construction must either (a) explicitly scope itself as a research prototype requiring enterprise wrapping to deploy, or (b) address the operational trust model: who operates the epoch commitment contract, who performs the circuit audit, what is the upgrade governance when a bug is found, and what is the liability model for a false accept.


## Persona: cryptographer

I am an applied cryptographer. My stance: unless I see a threat model, a game definition, and a reduction sketch, it's marketing. The construction provides all three — which means I can now find the gaps in what is written, rather than complaining about what is missing. These attacks are against the formal text.

---

### Attack 1: Missing ZK Term — the Reduction Proves PRF but Not Witness Privacy

**Attack:** The adversary is a colluding set of RS instances that deviate from the prescribed PLONK verifier protocol. In the IND-UNL-AS game (§3), the adversary receives Phase 1 oracle outputs as actual PLONK proof transcripts — not just the public outputs `(agentMerkleRoot, scopeNullifier, epochBinding)`. A malicious verifier that controls the random challenges in the interactive PLONK protocol (or adaptively chooses the hash preimages in the Fiat-Shamir transform via a weak RO implementation) may be able to extract partial information about `agentSecret` from the proof transcript directly, without breaking the PRF.

The reduction sketch in §4 ("Reduction sketch: IND-UNL-AS → Poseidon-PRF") bounds:

```
Adv^{IND-UNL-AS}_A ≤ Adv^{PRF}_{Poseidon} + Adv^{KS}_{PLONK}
```

Knowledge soundness (`Adv^{KS}_{PLONK}`) is a property about the prover: any successful prover must "know" a witness. It says nothing about what the verifier learns from a valid proof. The required property is **zero-knowledge** — specifically, that the proof transcript is simulatable without the witness. Against a malicious verifier (a colluding RS), this requires at minimum honest-verifier ZK composed with Fiat-Shamir (in the ROM), and ideally **simulation-extractability** (Faust et al., ASIACRYPT 2022) to prevent proof malleability across multiple transcripts sharing the same `agentSecret`.

The reduction needs a third term: `Adv^{ZK}_{PLONK}`. The hybrid argument collapses once we replace real `agentSecret`-keyed Poseidon outputs with a random function — but we need PLONK's ZK to ensure the *proof transcripts themselves* reveal nothing about which PRF key was used. Without this term, the bound is incomplete.

**Why it fails against the construction:** No simulator is constructed. The construction states PLONK uses a universal setup and cites §3.3, but provides no ZK simulator for the IND-UNL-AS game. The game description in §3 gives the adversary proofs (oracles), not just public outputs — the proof transcript is richer than `(scopeNullifier, epochBinding)`.

**In-threat-model?** No. The construction must add `Adv^{ZK}_{PLONK}` to the reduction bound and explicitly state whether the ZK property used is HVZK, MVZK, or simulation-extractable. Given the adversary controls the RS (verifier), HVZK is insufficient.

---

### Attack 2: scopeId Collision — AS-Controlled Scope Assignment Trivially Breaks Unlinkability

**Attack:** The IND-UNL-AS threat model (§3) explicitly grants the adversary: *"Supply adversarially chosen `scopeId` values, `epochCommitment` values, and timestamps."* The circuit (§2, Table: Public inputs) takes `scopeId` as a raw public input with no constraint binding it to any canonical RS identifier. The constraint set (§2, Constraints 1-12) contains no check that `scopeId = Poseidon(RS_domain)` for any registered or certified RS domain.

Adversarial strategy: The AS operates two colluding RS instances, RS-A and RS-B. It assigns both the identical `scopeId*` — say, by controlling the scope-minting registry or by simply instructing both RS instances to present `scopeId* = 42` when requesting proofs from agents. Both RS instances receive:

```
scopeNullifier = Poseidon2(scopeId*, agentSecret)
```

This is *identical* across RS-A and RS-B for the same agent. The colluding RS instances trivially link any two accesses from the same agent. The PRF security of Poseidon is irrelevant: the adversary has collapsed two distinct scopes to the same PRF input.

**Why it works:** The construction's security argument (§4) assumes `j_0 ≠ j_1` in the hybrid (Hybrid 1 → Hybrid 3 transition: "since `j_0 ≠ j_1`, the output `RF_0(j_1)` is an independent random value"). If the adversary can force `j_0 = j_1`, the entire hybrid argument collapses. The construction provides no mechanism — cryptographic or organizational — to ensure distinct RS instances hold distinct, non-forgeable `scopeId` values. The phrase "e.g., Poseidon hash of RS domain" in the description is informal and unconstrained by any circuit gate.

**In-threat-model?** No — and the threat model explicitly grants this capability. The construction must either: (a) bind `scopeId` to an on-chain RS registry with a non-equivocation proof, or (b) add a circuit constraint that verifies `scopeId` against a signed RS certificate whose signing key is independent of the AS.

---

### Attack 3: epochSalt Is Private Input But Must Be Public — Epoch Binding Is Vacuous

**Attack:** The circuit private inputs table (§2) lists `epochSalt` as a private input. Constraint 11 requires:

```
epochCommitment === Poseidon2(epochSalt, scopeId)
```

where `epochCommitment` is a public input "committed on-chain at epoch start." For an agent to satisfy this constraint and generate a valid proof, the agent must know the preimage `epochSalt`. Since `epochCommitment` is public and `epochSalt` is its preimage, `epochSalt` must be publicly revealed to all agents before or during the epoch — otherwise no agent can generate a proof. `epochSalt` is therefore public in the deployment model, not private.

Consequence: `epochBinding = Poseidon2(scopeNullifier, epochSalt)` is a deterministic function of two quantities that are both public or semi-public. `scopeNullifier` is already a public output (Table: Public outputs). `epochSalt` is effectively public (revealed for proof generation). Any party who observes `scopeNullifier_A` from RS-A's access log can compute `epochBinding_A` for any future epoch without additional information:

```
epochBinding_A[t] = Poseidon2(scopeNullifier_A, epochSalt[t])
```

The on-chain `epochBinding` record provides no privacy beyond what `scopeNullifier` already leaks. The claim that `epochBinding` provides "replay prevention while the `scopeNullifier` remains constant per (scope, agent)" (§2, Key design choices) is correct, but the claim that it provides *additional privacy* by separating on-chain observable state from scope nullifiers is false: the mapping `epochSalt → epochBinding` is publicly computable from `scopeNullifier`.

Furthermore, the "shuffled batch contract" timing defense (§3, Timing) submits `epochBinding` values on-chain. Since `epochBinding` is computable from the public `scopeNullifier` and the public `epochSalt`, the on-chain record directly encodes the scope nullifier up to a known, invertible transform — breaking the intended temporal decorrelation if RS-A's logs are also available.

**In-threat-model?** No. The construction must clarify whether `epochSalt` is public or private and, if public, remove it from the private inputs table and re-examine the privacy claim for `epochBinding`. If `epochSalt` is intended to be secret, the distribution mechanism must be specified — and that mechanism becomes a new trust assumption.

---

### Attack 4: Nullifier Precomputation Under AS Enrollment Omniscience — agentSecret Key Generation Is Unspecified

**Attack:** The construction's central claim (§4, "Why the AS's enrollment knowledge doesn't help") is:

> "The secret is generated independently by the agent and never transmitted. […] Thus, knowing `credComm_i` gives zero information about the PRF key used in nullifier generation."

This claim is stated informally and is not backed by a formal specification of the `agentSecret` generation protocol. The threat model grants the AS "Enrollment omniscience: Observe all enrollment transactions, including credential commitments, operator public keys, and Merkle tree updates." The AS knows `(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)` for each agent at enrollment time.

Adversarial strategy: If the `agentSecret` is derived — even partially — from operator-visible data, the AS can enumerate. Concrete attack surface: (a) If the agent derives `agentSecret` from a seed provided or observable at enrollment (e.g., a nonce from the AS, a timestamp correlated with enrollment, a hardware attestation value visible to the AS), then the AS holds partial information about the PRF key. (b) The construction deploys agents in TEEs (§4, "stored in a secure enclave or TEE"). TEE attestation reports are observable to the relying party — if the AS is the relying party for TEE attestation, it may receive attestation data that narrows the entropy space of `agentSecret`. (c) If the BabyJubjub public key `(Ax, Ay) = BabyPbk(agentSecret)` is embedded in the `credComm` as the *agent's* key (the construction is ambiguous: §4 refers to it as "the operator public key" in `credComm`, suggesting the agent public key is separate), and the agent public key is transmitted during enrollment, the AS holds `(Ax, Ay)` and can precompute candidate nullifiers for any scope given a dictionary of candidate secrets.

The formal gap: The proof in §4 reduces IND-UNL-AS security to Poseidon-PRF + PLONK-KS, with the PRF key being `agentSecret`. For the reduction to hold, the PRF key must be information-theoretically independent of everything the adversary sees at enrollment. The construction asserts this independence informally but provides no formal specification of the key generation protocol, no adversarial model for TEE attestation leakage, and no specification of which public key (agent vs. operator) appears in `credComm`. Without a formal key generation spec, the reduction's hypothesis ("agentSecret is uniform and independent") cannot be verified.

**In-threat-model?** Partial. The base attack (precomputation from enrollment data) is a known pitfall for nullifier schemes (cf. the persona's attack prompt: "if AS knows the scope_id, can it precompute nullifiers for all enrolled agents?"). The construction does not address this. The construction must formalize the `agentSecret` generation protocol, bound the entropy visible to the AS at enrollment time, and include this as a named assumption (e.g., "Agent Key Indistinguishability: `agentSecret` is computationally indistinguishable from uniform given all enrollment transcripts visible to the AS").

---

### Summary Table

| Attack | Section Implicated | Verdict |
|---|---|---|
| 1: Missing ZK term — PLONK KS ≠ ZK | §4 Reduction sketch | Not in-threat-model — must add ZK/SE term |
| 2: scopeId collision via AS-controlled scope assignment | §2 Public inputs, §3 Adversary capabilities | Not in-threat-model — capability explicitly granted, circuit has no defense |
| 3: epochSalt private/public inconsistency | §2 Private inputs, §3 Timing | Not in-threat-model — `epochBinding` privacy claim is vacuous |
| 4: agentSecret key generation unspecified | §4 "Why AS knowledge doesn't help" | Partially in-threat-model — informal claim, no formal key gen spec |


## Persona: cu_ciso

---

### Attack 1: The Shuffled Batch Contract Destroys My Audit Log

**Attack:** Section 2 ("Epoch salt for replay prevention") and Section 3 ("Timing side-channel resistance") describe a **shuffled batch contract with commit-reveal** that deliberately decorrelates `T_access` from `T_chain`. The construction celebrates this as a timing-privacy win. My NCUA examiner celebrates the opposite: GLBA Safeguards Rule (16 CFR Part 314.4(c)) requires me to monitor and log access to member information systems. NCUA Part 748 Appendix B §II.C requires a documented audit trail that ties access events to time, actor, and affected data. If your mitigation uniformly distributes chain-recording time across a 15-minute epoch and shuffles insertion order, I **cannot** reconstruct a temporally ordered access log from the on-chain record. The privacy property you're selling me is a compliance violation I'm buying.

**Why it works / why it fails:** The construction does not fail cryptographically — it succeeds. But the threat model (§3) is adversarial-AS-as-privacy-threat, not examiner-as-audit-requester. These are in direct tension. Section 7 claims "A regulator can verify that an agent presented a valid ScopedAccess proof to a specific RS at a specific epoch." But "epoch" resolution (15 minutes) is not the granularity NCUA examiners expect. They want timestamps to the second, correlated to the member account, correlated to the transaction. The construction hands them a Poseidon hash and a 15-minute window.

**In-threat-model?** No — construction must address. The construction must define a separate, examiner-readable audit path that does not break the privacy property. One option: the RS logs access with full timestamp locally (not on-chain), the on-chain record is the privacy layer, and the examiner requests RS logs directly under subpoena or exam authority. The construction must explicitly designate who holds the temporally precise log, under what retention policy, and how that maps to NCUA 748.

---

### Attack 2: agentSecret Key Custody — "If It's a Browser, You've Lost Me"

**Attack:** The threat model (§3) states: "The adversary cannot extract the agent's secret scalar (stored in a secure enclave or TEE on the agent's host)." Section 7 says "The agent generates agentSecret locally — SECU never sees it." This is the entire PRF key for every scopeNullifier the agent will ever generate. My attack is operational, not cryptographic: **what is the recovery path when this key is lost or compromised?**

Scenario A — Device destruction: Member's phone is stolen and wiped. `agentSecret` is gone. Every `scopeNullifier` the agent would generate is now unreproducible. The credential can be revoked from the Merkle tree, but the member needs a new enrollment. How does SECU verify it's re-enrolling the same member without breaking the unlinkability property? If SECU keeps a mapping of member → agentSecret for recovery, it has the PRF key, and the AS-blind property collapses retroactively.

Scenario B — TEE attestation failure: If the TEE is an iOS Secure Enclave, an Android StrongBox, or a browser-level HSM (WebAuthn resident key), each has different compromise surfaces. The construction does not name the TEE, its attestation chain, or who audits it. FFIEC CAT Domain 2 (Threat Intelligence) and NCUA 748 Appendix B §III require me to assess the residual risk of each control. "TEE on the agent's host" is not a control I can put in a risk register.

**Why it works / why it fails:** The construction's security proof is clean under the assumption that `agentSecret ∉ adversary's view`. The operational question is: how do I maintain that invariant across a 10-year member relationship, multiple device upgrades, and a Tier 1 ops team that has never heard of Baby Jubjub? The construction offers no key management lifecycle, no recovery ceremony, and no attestation requirement. This is not a cryptographic attack — it is a vendor management gap that NCUA examiners identify under LTCU 01-CU-20 third-party risk guidance.

**In-threat-model?** No — construction must address. The construction needs a §9 covering key lifecycle: generation ceremony, storage medium (named TEE type with attestation), recovery protocol (and its privacy implications), rotation policy, and revocation-without-deanonymization path.

---

### Attack 3: On-Chain Registry SLA vs. Core Processor SLA

**Attack:** The construction's RS authorization path is: agent generates PLONK proof → RS verifies against on-chain Merkle root → RS checks on-chain nullifier accumulator → RS accepts. Every single RS access has a hard dependency on two on-chain reads (Merkle root history buffer, nullifier set) and potentially one on-chain write (epochBinding batch submission). Section 6 targets < 3 second proving time and ~300K gas verification. My core processor (Symitar, XP, Corelation) runs at 99.99% availability — roughly 52 minutes of unplanned downtime per year. My attack is: **what is the availability SLA of the on-chain registry, and who is liable when it misses?**

Ethereum mainnet has experienced multi-hour degradations. L2s (Polygon, Arbitrum) have had sequencer outages measured in hours. A 99% uptime target — 1% outage budget — is 87.6 hours per year, which is 100x worse than my core processor. During that outage, can members access any RS? If the answer is "no," I have an availability control weaker than my 1970s batch-processing mainframe. If the answer is "yes via fallback," then the fallback must be specified and the construction must explain how the fallback does not re-introduce the AS-correlation that the on-chain path was designed to prevent.

**Why it works / why it fails:** The construction entirely omits availability discussion. Section 2 mentions a "root history buffer (30-entry circular)" that allows stale root acceptance, which partially mitigates root freshness. But nullifier accumulator queries and epochBinding submissions still require live chain access. The construction has no degraded-mode path.

**In-threat-model?** No — construction must address. NCUA examiners reviewing the vendor management questionnaire will ask for SLA documentation on every third-party system in the critical path. "The blockchain" is not an entity I can sign a BAA or SLA with. The construction needs an availability model with a named chain, its historical uptime, a fallback mode, and the privacy implications of that fallback.

---

### Attack 4: The IND-UNL-AS Game Is Not a Regulatory Control

**Attack:** Section 4 opens with: "For all PPT adversaries A, Adv^{IND-UNL-AS}_A ≤ Adv^{PRF}_{Poseidon} + Adv^{KS}_{PLONK}." My attack is that this sentence — and the three pages of hybrid argument — map to **zero rows** in my FFIEC CAT maturity model, **zero controls** in NCUA 748 Appendix B, and **zero line items** in my SOC 2 Type II audit scope.

My examiner's questionnaire asks: "Describe your access control framework for member data." I cannot write "we achieve negligible PRF advantage under Poseidon on BN254." I need: access control policy (FFIEC CAT Domain 3, Control 3.1.1), third-party access controls (GLBA 314.4(f)), and logging/monitoring (NCUA 748 Appendix B §II.C). The construction's §5 Bolyra primitive mapping maps circuit gadgets to Bolyra spec sections — but Bolyra is not NIST SP 800-53, not FFIEC, not GLBA.

Furthermore, Section 8 claims: "No formal game exists [for BBS+]. BBS+ unlinkability excludes the issuer as adversary." This is a correct cryptographic critique of BBS+. But my decision framework is not "which construction has a stronger formal game." It is "which construction has a vendor with SOC 2 Type II, an indemnification clause, and an examiner-readable control narrative." The construction wins the cryptographic argument and loses the procurement argument.

**Why it works / why it fails:** The construction cannot fail cryptographically on this attack — it is a category error. The attack works because the target buyer (CU CISO) makes purchase decisions on audit defensibility, not proof strength. A construction that achieves IND-UNL-AS but ships without a control mapping document, a SOC 2 scope definition, and an NCUA 748 narrative will not pass vendor due diligence at any credit union that has been through an NCUA examination.

**In-threat-model?** No — construction must address. The construction needs a §10: Regulatory Control Mapping. Each cryptographic property (unlinkability, replay prevention, scope isolation, audit trail) must be mapped to a named FFIEC CAT control, GLBA section, or NCUA 748 appendix item. The IND-UNL-AS game belongs in an appendix; the control narrative belongs in the executive summary. Without this, the construction is a research paper, not a deployable system.


## Persona: rfc7662_advocate

---

### Attack 1: `agentMerkleRoot` Is a Persistent Cross-Proof Fingerprint

**Attack:** The construction exposes `agentMerkleRoot` as a **public output** of every `ScopedAccess` proof (§2, public outputs table). Colluding RS-A and RS-B simply match on this value. Every proof from an agent enrolled under the same Merkle snapshot produces the identical root. The anonymity set is not "all enrolled agents" — it is all agents enrolled under that **specific historical root version**, bounded by the 30-entry circular buffer (§2, Bolyra mapping row 9). In a small credit union with 200 member agents and infrequent enrollments, consecutive snapshots may differ by one leaf. Two proofs sharing the same root narrow membership to a cohort that existed for the inter-enrollment interval.

**Why it works / why it fails:** The IND-UNL-AS game (§3) treats `(agentMerkleRoot, scopeNullifier, epochBinding)` as the adversary's view, but the reduction in §4 argues only about `scopeNullifier` being PRF-indistinguishable. The game proof never addresses `agentMerkleRoot` as a linking variable. Two challenge proofs `π_A` and `π_B` in the `b=0` case (same agent, two scopes) have **identical** `agentMerkleRoot`, while in the `b=1` case (different agents, two scopes) they *may* also share a root if both were enrolled before the same update. The reduction sketch (§4, Hybrids 0–3) simply does not model this correlation. The adversary's distinguisher does not need to break Poseidon-PRF at all; it reads off matching root values before touching nullifiers.

**In-threat-model?** Yes — the adversary explicitly colludes with RS subsets (§3, adversary capabilities). Construction must address this. Mitigation would require either (a) hiding `agentMerkleRoot` (making it a private input verified against a public set commitment without exposing which exact root), or (b) proving the IND-UNL-AS bound holds even when the adversary observes `agentMerkleRoot`. Neither is present.

---

### Attack 2: RFC 8707 + Offline JWT Already Eliminates the AS from the Hot Path

**Attack:** Section 8 claims: *"AS issues every token. Every RS access requires an AS roundtrip."* This characterization of the baseline is false as of 2023. RFC 8707 (Resource Indicators) allows the agent to request a token pre-scoped to `resource=https://auto-dealer.example.com`. The RS validates the audience claim locally — no introspection call, no AS in the critical path. Pair this with the draft-ietf-oauth-jwt-introspection-response extension (signed JWT introspection response): even the introspection endpoint delivers a signed JWT the RS caches and verifies offline. Add RFC 9449 DPoP with a pre-issued nonce: the agent pre-fetches a DPoP-bound token per RS at session start in a single batched authorization call, then uses it offline. The AS sees one batch request — "agent wants tokens for {auto-dealer, health, grocery}" — but **never sees which token is used, when, or in what order.** Access-time correlation at the AS is impossible because no per-use communication occurs.

**Why it works / why it fails:** The construction's §8 table row 1 ("AS cannot see per-RS access") rests entirely on this false premise. The baseline *can* achieve AS-blind per-RS access via pre-issuance. The real remaining gap is narrower: the AS observes the **set of requested scopes at session start**, not per-access timing. Whether the AS can infer a merchant graph from that single batch request depends on which scopes the agent pre-fetches. If the agent pre-fetches all permissible scopes at enrollment (not at session start), the AS learns only the permission set, not intent. The §8 comparison table needs to be rewritten to argue against *this* configuration, not the naive token-per-request model.

**In-threat-model?** Partially. The construction's claim that AS-blind per-RS access is impossible in the baseline is out of scope — it is achievable today. The construction must reframe its advantage as (a) *formal game-based unlinkability under adversarial AS* (which the baseline truly lacks), not operational AS-blindness, and (b) scope nullifier non-linkability across RSes, which RFC 8707 does not provide. Without this reframing, §8 overstates the gap and an RFC 7662 advocate will correctly reject the premise.

---

### Attack 3: Deterministic `scopeNullifier` + Public Nullifier Accumulator Enables Intersection Attack

**Attack:** The `scopeNullifier = Poseidon2(scopeId, agentSecret)` is **epoch-stable**: it does not change across epochs for the same (agent, scope) pair (§2, constraint 9; §7, step 6). The construction explicitly intends this for sybil detection: *"within a single scope-epoch, the scopeNullifier_A is deterministic."* But the `ScopedAccess` circuit emits `scopeNullifier` as a **public output**, and §7 step 7 describes a regulator viewing on-chain `epochBinding` records. For an on-chain nullifier accumulator to provide epoch replay prevention, either `scopeNullifier` or a deterministic function of it (e.g., `epochBinding`) must be recorded. If RS-A records `scopeNullifier_A` on-chain for sybil detection across a longer window than one epoch, then the full cross-epoch visit history at RS-A is a public dataset keyed by stable pseudonym `scopeNullifier_A`.

A passive observer (including the AS) now runs a nullifier intersection across RS nullifier sets: `{scopeNullifier values at RS-A} ∩ {scopeNullifier values at RS-B}`. If the intersection is empty the sets are disjoint; if non-empty there is a common member. Because `scopeNullifier_A ≠ scopeNullifier_B` by design (different scopeIds), **direct** nullifier matching fails — but cross-scope timing intersection over the public `epochBinding` records at different RSes allows probabilistic de-anonymization. The epoch batching (§3, timing mitigation) provides `epoch_length` seconds of ambiguity per epoch, but behavioral patterns (agent always accesses RS-A before RS-B within the same 15-minute window) re-identify across epochs with sufficient history.

**Why it works / why it fails:** The timing mitigation in §3 addresses single-epoch chain-recording correlation. It does not address multi-epoch behavioral fingerprinting using the stable `scopeNullifier` as a within-RS identity. The IND-UNL-AS game (§3) models a one-shot interaction and does not capture a polynomial-length sequence of access events where the adversary accumulates evidence across epochs. The game should require that A's advantage remain negligible even after observing T sequential epochs of access data, not just one challenge query.

**In-threat-model?** Yes. The adversary explicitly has "adaptive queries" and "log retention" (§3). An AS with full RS collusion accumulating epochBinding logs across T epochs can mount this intersection attack. The construction needs either (a) a per-epoch random rerandomization of `scopeNullifier` (breaking the stable pseudonym while preserving sybil resistance via on-chain commitment) or (b) an extension of the IND-UNL-AS game to the T-epoch sequential model with a corresponding reduction.

---

### Attack 4: `epochSalt` Distribution Creates an Implicit AS Channel

**Attack:** The circuit requires `epochSalt` as a **private input** to the prover, yet `epochCommitment = Poseidon2(epochSalt, scopeId)` is a **public input** described as "committed on-chain at epoch start" (§2, public inputs table). Poseidon2 is one-way: knowing `(epochCommitment, scopeId)` does not reveal `epochSalt`. This creates a logical dependency: the prover must hold `epochSalt` before they can construct a valid proof, but `epochSalt` must also be consistent with the on-chain `epochCommitment`. **Someone must distribute `epochSalt` to enrolled agents.** The construction does not specify who.

If the AS (or any on-chain smart contract the AS controls) publishes `epochSalt` for each (scope, epoch) pair, the AS can embed per-agent structure: issue a different `epochSalt` to each agent under the pretext that "each RS publishes its own epoch salt." A per-agent `epochSalt` immediately breaks scope-nullifier unlinkability: `epochBinding = Poseidon2(Poseidon2(scopeId, agentSecret), epochSalt_agent)` is now agent-tagged through `epochSalt_agent`, and the AS can correlate all proofs from a given agent by recognizing the unique salt it issued. The circuit constraint 11 (`epochCommitment === Poseidon2(epochSalt, scopeId)`) only checks that the prover used the salt corresponding to the published commitment — it does not prevent the AS from publishing distinct commitments per agent.

If `epochSalt` is derived from an on-chain VRF or beacon (e.g., Ethereum RANDAO), this attack is precluded — but the construction neither specifies the salt source nor proves that the epoch commitment contract is AS-independent.

**Why it works / why it fails:** Section 8 table row 5 claims "AS-supplied nonces" independence: *"epochSalt is committed on-chain at epoch start and verified inside the circuit — the AS cannot pattern it per-agent."* This claim holds only if the on-chain commitment contract is not controlled by the AS. In the credit union deployment (§7), SECU operates the AS. If SECU also operates or influences the epoch commitment contract — a plausible assumption for a permissioned deployment — the independence claim collapses. RFC 9449 DPoP nonces are AS-issued and exploitable (as the construction notes), but the construction substitutes an on-chain epoch salt whose governance model is unspecified.

**In-threat-model?** Yes. The adversary "controls the Authorization Server" (§3) and "may supply adversarially chosen epochCommitment values" (§3, adversary capabilities). The construction must (a) specify that `epochSalt` is derived from a public, AS-independent beacon (e.g., RANDAO, drand), (b) prove that the epoch commitment contract is permissionless and the AS cannot submit per-scope-per-agent salts, and (c) include the epoch commitment governance model in the threat model as an explicit trust boundary.


## Persona: spiffe_engineer

I run SPIFFE/SPIRE at scale. My infrastructure handles millions of SVID rotations per day. When I look at this construction I see protocol engineering that belongs at the platform layer, not a novel ZK contribution — and I have specific technical objections.

---

### Attack 1: epochSalt Committer Is Undefined — Adversarial AS Can Pattern Salts

**Attack:**
Section 2 states `epochSalt` is "per-epoch randomness committed on-chain at epoch start" and constraint 11 checks `epochCommitment === Poseidon2(epochSalt, scopeId)`. But the construction never specifies *who submits the epochSalt transaction*. If the adversarial AS is the committer — and it is, since it operates the enrollment infrastructure — it can choose `epochSalt` values with embedded structure. The circuit enforces only that the agent used *the correct committed salt* (constraint 11), not that the salt was chosen without knowledge of which agents will use which scopes in that epoch. A crafted `epochSalt` can break the `epochBinding` collision resistance: choose salts such that `Poseidon2(epochSalt_j, scopeId_j)` for agent-specific (AS-known) epoch windows produces recognizable `epochBinding` patterns.

Concretely: the reduction in §4 assumes `epochSalt` is "uniformly random" (§3 threat model, "per-epoch randomness"), but the adversary's capability list says AS controls *enrollment transactions and Merkle updates* — it does not say AS cannot commit the epoch salt. The shuffle-batch contract in §3 mitigates timing correlation of *submissions*, but if the salt itself is adversarially chosen, the shuffling is irrelevant.

**Why it works / why it fails:**
The construction's security argument (§4, Hybrid 1→3) treats `epochSalt` as a uniformly random input known to the adversary only *after* commitment. If the AS is the committer, this assumption fails. The `Poseidon-PRF` reduction requires the PRF key (`agentSecret`) to be independent of the function input (`scopeId`), but does not cover adversarial input selection for `epochSalt`. The gap is not in the Poseidon PRF itself but in the trust model for the salt oracle.

**In-threat-model?** No — construction must address. The threat model (§3) lists "nonce manipulation: supply adversarially chosen `scopeId` values, `epochCommitment` values, and timestamps" but does not explicitly grant or deny the AS the ability to *commit* the `epochSalt`. If the AS is the epoch registrar, the adversary has a lever that bypasses the formal game. The fix is a distributed random beacon (e.g., RANDAO/EIP-4399) or a commit-reveal scheme where no single party controls the salt — neither of which is specified.

---

### Attack 2: Static `scopeNullifier` Enables Cross-Epoch Within-Scope Linkability — Sybil Prevention Trades Off a Different Privacy Property

**Attack:**
Section 2 defines `scopeNullifier = Poseidon2(scopeId, agentSecret)` as *epoch-invariant* — the same value across all epochs for the (scope, agent) pair. Section 7 correctly notes this prevents an agent from presenting as two distinct identities at RS-A within one epoch. But `scopeNullifier` is a **public output** of every `ScopedAccess` proof (§2, Public outputs table). RS-A in epoch `t` and RS-A in epoch `t+k` will observe the *identical* `scopeNullifier_A`. Any party with access to the RS-A access log across epochs — including the adversarial AS if it colludes with RS-A — can link all of the agent's visits to RS-A across the entire credential lifetime.

The IND-UNL-AS game (§3) is defined as cross-scope unlinkability at a *single point in time*. The challenge asks whether `(π_A, π_B)` reveal if `π_A` and `π_B` share an agent. The game does not model the adversary accumulating `scopeNullifier_A` values over many epochs. A colluding AS+RS-A can build a longitudinal access profile for each scopeNullifier it observes — which is effectively a persistent pseudonym — and then correlate session start times (observable from the on-chain handshake) to merchant patterns over weeks.

**Why it works / why it fails:**
The construction correctly achieves the stated IND-UNL-AS property as defined. The game is satisfied. But the game is insufficient: it doesn't capture longitudinal privacy within a scope. In the §7 deployment scenario, SECU-as-AS colluding with Auto Dealer (RS-A) sees the member's `scopeNullifier_A` across every auto-related transaction for years. That's a durable pseudonym — worse than a PPID if the member's access frequency at that merchant is distinctive.

SPIFFE's SVID rotation by contrast issues short-lived SVIDs (default 1 hour in SPIRE). A fresh X.509 SVID per workload invocation means there is no persistent cross-epoch identifier at the verifier. The construction's design choice — static nullifier for sybil prevention — *reintroduces* the persistent identifier property that ZK is supposed to eliminate, just scoped per-RS instead of globally.

**In-threat-model?** No — construction must address. Either: (a) rotate `agentSecret` per epoch (but then the agent can't prove membership without re-enrollment or a separate secret management scheme); (b) use an epoch-specific nullifier `Poseidon3(scopeId, agentSecret, epoch)` at the cost of losing cross-epoch sybil detection (the agent can present twice across epochs with no linkage); or (c) formally acknowledge the pseudonymity-within-scope property and bound the privacy loss. None of these are currently specified.

---

### Attack 3: SPIFFE ZK Attestor + WIMSE Local Token Exchange Achieves the AS-Blind Property Without a New Protocol

**Attack:**
Section 8's "fundamental architectural gap" claims: "No combination of BBS+, PPID, DPoP, or resource indicators can close this gap because they all require the AS to participate in every authorization event." This claim does not address WIMSE.

WIMSE architecture (draft-ietf-wimse-arch, §4.2, "workload-to-workload authentication") defines *local* token exchange: a workload holds a service token (issued by SPIRE at attestation time) and exchanges it *peer-to-peer* for a resource-specific token bound to the target workload's audience — without an AS roundtrip. The SPIRE workload API already issues per-audience JWT-SVIDs locally: `WorkloadAPI.FetchJWTSVID(audience: "rs-a.example.com")` never contacts the SPIRE server if the workload has a cached SVID. The audience-bound JWT-SVID plays the role of `scopeNullifier` — it is distinct per RS and does not require AS involvement.

The unlinkability property follows from SPIFFE's trust domain isolation: RS-A and RS-B see JWT-SVIDs with distinct audiences. If the SPIFFE ID embeds a per-invocation nonce (achievable via SPIRE's configurable SPIFFE ID template), the verifiers cannot link them to the same workload without colluding with the SPIRE server — which is exactly the threat model Bolyra cites.

To close the "adversarial AS" gap specifically, a SPIRE ZK attestor plugin — a node attestation plugin that produces a PLONK proof of agent enrollment instead of a TPM quote — would give SPIRE the same enrollment-soundness property. The plugin interface is documented and production-hardened.

**Why it works / why it fails:**
This attack fails on one dimension: WIMSE provides *policy-based* unlinkability (the SPIRE server *chooses* not to log per-audience issuance), not *cryptographic* unlinkability. A compromised or adversarial SPIRE server can reconstruct the traffic graph from its issuance logs. The Bolyra construction's IND-UNL-AS game provides cryptographic guarantees where the AS is *computationally* prevented from correlating, not just *policy-prevented*. WIMSE has no game-based security definition for adversarial AS unlinkability.

However, the construction's §8 claim that existing standards *cannot* close the gap is too strong. The accurate claim is: "WIMSE provides weaker (policy-based) unlinkability; this construction provides cryptographic unlinkability reducible to Poseidon-PRF." The construction should acknowledge WIMSE, characterize the trust-level gap precisely, and consider contributing the ZK attestor model to WIMSE rather than defining a parallel trust architecture. The WIMSE WG is explicitly soliciting input on selective disclosure mechanisms (WIMSE ML, 2024-03).

**In-threat-model?** Yes — construction survives on the cryptographic guarantee claim. But the scope of §8's claim needs narrowing; the current framing ("no combination can close this gap") is falsified by WIMSE's partial solution. A reviewer will flag this.

---

### Attack 4: The IND-UNL-AS Game Excludes the Handshake Channel — Session-Correlated De-Anonymization Is Out of Scope

**Attack:**
The game definition in §3 initializes with "Challenger enrolls `q` agents." Phase 1 allows A to query `ScopedAccess` proofs. The challenge and Phase 2 are `ScopedAccess`-only. **The handshake is not modeled as an adversarial input.** Section 7 explicitly states "SECU observes the handshake (it's on-chain) but this is a one-time session event." But the `AgentPolicy` circuit's public outputs are not listed in this construction — they are inherited from the Bolyra spec. If the `AgentPolicy` circuit produces a session commitment or session nonce that is common to all subsequent `ScopedAccess` proofs within a session, the AS can group all RS accesses within a session by matching against the session-scoped Merkle root window.

More precisely: the handshake happens at time `T_h`. The agent then generates `ScopedAccess` proofs at `T_1, T_2, T_3`. The proofs use `agentMerkleRoot` as a public output. If the Merkle tree is append-only and the AS knows the insertion timestamp of each credential, the AS can narrow `agentMerkleRoot` to a specific enrollment time window. Combined with `T_h` (handshake time, on-chain), the AS can identify which Merkle root corresponds to which enrolled agent — and thus attribute all proofs that use that root to the same session, even without seeing `scopeNullifier`.

The batch shuffle in §3 decorrelates `T_chain` from `T_access`, but the handshake `T_h` is *not* batched — it is an on-chain event with a precise timestamp. The IND-UNL-AS game does not give A the handshake transcript, which means the game is easier than the real deployment.

**Why it works / why it fails:**
The construction's handshake is modeled as out-of-scope for the unlinkability game — it's a "one-time session event." But in §7's SECU scenario, each merchant access session starts with a handshake. If members access Auto Dealer once per quarter, the quarterly handshake timestamps are distinctive. A colluding AS+RS-A can look at `T_h` for sessions involving RS-A's scope and narrow to the set of agents whose handshake timestamps match. This is a timing attack on the *game definition*, not the circuit: the game is defined correctly for `ScopedAccess` in isolation, but the deployment composition leaks more than the game models.

**In-threat-model?** No — construction must address. The IND-UNL-AS game should be extended to include the handshake transcript as adversarial input in Phase 1, or the construction should prove that the handshake's public outputs are independent of `agentSecret` and thus cannot be used to narrow the anonymity set for `scopeNullifier` attribution. Currently, the composition of the handshake + `ScopedAccess` proofs is asserted to be privacy-preserving (§7) but not proven.
