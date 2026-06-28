# Tier 3 Adversarial — C2 Cross-scope unlinkability

## Persona: auth0_pm

---

### Attack 1: The Construction's Core "Feature" Is an AML Compliance Violation in the Primary Target Market

- **Attack:** The construction's §7 hero scenario explicitly states that after Bolyra deployment, "NFCU can reconstruct the complete merchant graph" using OAuth, and the design goal is to eliminate that visibility. The author frames "merchant graph hidden from issuer" as the product's crown jewel. I fire up FinCEN's Bank Secrecy Act guidance and point to 31 U.S.C. § 5318(g): credit unions are legally required to monitor member transaction patterns for suspicious activity and file SARs. Anti-money laundering programs under the BSA/NCUA Letter to Credit Unions 01-CU-11 require transaction monitoring across payees. A system architecturally designed to prevent a CU from seeing "member #4821's agent requested financial_small access to Amazon at 14:02, then Costco at 14:07" is a system that breaks the CU's AML compliance program. NCUA examiners will not pass a credit union that cannot reconstruct member transaction graphs.

- **Why it works:** The threat model in §3.1 explicitly models the CU-as-operator as the adversary and optimizes to hide merchant graph from them. The construction cannot both satisfy IND-UNL-AS (adversary = CU) and also enable BSA-compliant transaction monitoring for the same CU. These are structurally incompatible. The NFCU example in §7.1 names the specific threat: "NFCU can reconstruct the complete merchant graph" — that's not a bug, it's a regulatory requirement.

- **In-threat-model?** No. The construction must address how a CU deploys this without becoming BSA non-compliant. One possible escape: a selective-disclosure variant where the CU can audit its own member's graph only under a legal trigger (subpoena, SAR threshold breach) but not in real time. That requires a different circuit design — a compliance-escrow gadget not present in this construction.

---

### Attack 2: Proving Latency Makes the AS-Free Path a Net Regression at the Checkout Layer

- **Attack:** The construction claims <3s PLONK and <2s Groth16 (§6, proving time targets), targeting "commodity hardware." Auth0 machine-to-machine token issuance is <100ms from cache; WorkOS MCP auth issues tokens in the same range via their standard OAuth 2.0 client credentials flow. I walk through the agent's NFCU → Amazon checkout path from §7.1 step 2: the agent must locally generate a PLONK proof *per RS request*, which includes running a full PLONK prover for ~17K constraints. Even if we grant 2s (Groth16 with rapidsnark), this is 20× the OAuth round-trip for an operation that happens at payment authorization time. The "AS-free" framing in §2.6 saves one HTTPS round-trip (~50-200ms) while adding 2,000ms of local compute. The construction explicitly requires a fresh `sessionNonce` per request (§2.2 public inputs), preventing proof caching across requests to the same RS. `epochBinding` is stable within a 300s window but `sessionNonce` is per-request, so the prover must re-run for every authorization. At Amazon's checkout, an agent that takes 2-3 seconds to produce an authorization proof will fail Stripe's payment auth timeout SLA (typically 5s end-to-end).

- **Why it works:** The construction acknowledges the latency in §6 but offers no mitigation for per-request proof generation. Pre-computation is blocked by the freshness requirement: `sessionNonce` is a public input provided by the RS at request time (or derived from the handshake), so the agent cannot pre-prove before receiving it. The 30-entry root history buffer (§2.6 step 4) helps with Merkle staleness but has no bearing on proving time.

- **In-threat-model?** Yes, this is within the construction's scope — but the construction does not address it. A credible response requires either: (a) a proof-of-concept benchmark showing rapidsnark on mobile/edge hardware achieving <500ms for this circuit size, or (b) a nonce-batching design where a single proof covers a time window and the per-request freshness comes from a secondary commitment that does not require re-proving. Neither is present.

---

### Attack 3: "Agent-Local Secure Storage" Is a Fiction for Cloud-Native Agent Deployments

- **Attack:** §2.4 defines the entire security of IND-UNL-AS on a single sentence: "The `scopeBlindingSecret` is stored alongside the agent's credential material in the agent's local secure storage." The threat model in §3.1 explicitly states: "The agent's local execution environment: The `scopeBlindingSecret` is generated and stored locally by the agent. The operator never receives it. This is the critical trust boundary." But the primary deployment environment for AI agents in 2026 is serverless and containerized: AWS Lambda, ECS Fargate, GKE. These environments have no persistent local storage between invocations. Lambda functions are stateless by design; container filesystems are ephemeral. The `scopeBlindingSecret` must survive across invocations of the same logical agent — otherwise the `scopedNullifier = Poseidon2(scopeId, scopeBlindingSecret)` changes between invocations and the RS double-spend nullifier set becomes inconsistent. The construction says to use "32 bytes from `/dev/urandom`, reduced mod $p$" and never transmit it — but it never specifies where it lives across Lambda cold starts or ECS task recycling. The practical answer is: it must live in AWS Secrets Manager, HashiCorp Vault, or a KMS-backed parameter store. Which means the operator's cloud account *does* hold the blinding secret, directly contradicting §2.4's operator-independence invariant. Auth0's M2M tokens use a client secret stored in Secrets Manager with zero additional developer burden — the key management is solved. Bolyra adds a new secret management surface for every agent deployment without addressing how that secret survives stateless execution.

- **Why it works:** §2.4's "rotation" section reveals the gap: "If the agent's local environment is compromised, the agent MUST generate a new credential (new enrollment in the Merkle tree) with a fresh `scopeBlindingSecret`." For cloud agents, "environment compromise" includes: Lambda function code leak, ECS task metadata service SSRF (common), secrets manager misconfiguration, or a shared-account breach. The construction's threat model boundary ("outside the adversary's control") does not map to any real cloud security boundary — AWS account access means access to all secrets stored in that account, and the Merkle re-enrollment process is not defined in the construction.

- **In-threat-model?** No. The construction assumes a trust boundary ("agent's local execution environment") that does not exist in the cloud-native deployment model where enterprise AI agents actually run. The construction must define: how does `scopeBlindingSecret` survive stateless execution? If the answer is "a secrets manager," it must address what happens when the secrets manager is in the same AWS account the operator controls — because that collapses the operator-independence invariant that the entire IND-UNL-AS game is built on.

---

### Attack 4: The Market Adversary Is Not "AS Correlates Traffic Graphs" — It's "Can I Ship This Without Firing My Compliance Team"

- **Attack:** This is the buyer-level objection. When I take this to an enterprise procurement call — say, a Costco fintech partnership team evaluating agent auth for their buyer program — the RFP checklist is: SOC 2 Type II, HIPAA BAA (if any health data flows), PCI-DSS (for payment agents), pen test report from a named firm, SLA with financial remedies, 99.99% uptime commitment, legal entity with >$10M in liability coverage. Auth0 ships all of these. WorkOS ships all of these. Bolyra is a solo-founder GitHub repo with an Apache 2.0 license and a provisional patent. The IND-UNL-AS game in §3.2 is a beautiful formal construction. Procurement at Cedars-Sinai (the healthcare scenario in §7) will not accept "tight reduction via hybrid argument to Poseidon PRF security" as a substitute for a signed HIPAA Business Associate Agreement. The formal proof in §4.2 is correct and elegant. It does not appear on any SOC 2 audit checklist. The construction addresses the cryptographic threat model with precision and leaves the enterprise trust model entirely unaddressed.

- **Why it works:** The construction's §8 comparison table lists 9 properties where Bolyra beats the baseline. Zero of those properties map to a procurement line item. The column headers are: "Agent-unlinkability against adversarial AS," "Delegation-entry anonymity," "Collusion resistance," "Formal security definition" — these are academic differentiators. The enterprise buyer's actual column headers are: "Who do I call at 2am when this breaks?", "What's your breach notification SLA?", "Do you have a BAA?", "Will you survive my legal team's vendor risk review?". The construction's genuine cryptographic advantage (AS elimination, formal unlinkability) is maximally valuable in a narrow segment — privacy-maximalist, lightly-regulated, technically sophisticated operators. The named examples (NFCU, Kaiser, Cedars-Sinai) are among the most regulated entities in the US, where the procurement barrier is highest and the regulatory conflicts (§§ BSA, HIPAA) are most acute.

- **In-threat-model?** No. The construction does not need to address this to be cryptographically sound. But it must address it to achieve the claim that "enterprises [would] adopt" it. The credible response is to narrow the initial target segment to a specific buyer profile where the formal unlinkability property is a purchase driver (not a compliance risk), the technical bar is owned by the buyer (crypto-native fintechs, not traditional CUs), and the procurement gate is lower (developer-led adoption vs. enterprise RFP).


## Persona: cryptographer

Applied cryptographer. Unless I see a threat model, a game definition, and a reduction sketch, it's marketing. Here, you've provided all three — so now I'll try to break them.

---

### Attack 1: IND-UNL-AS Game Restriction is Insufficient — Advantage-1 Attack Within the Stated Rules

**Attack:** The IND-UNL-AS game (§3.2) restricts the adversary from querying **(j₀, Sₐ)** and **(j₁, S_b)** before the challenge. It explicitly *permits* querying **(j₀, S_b)**. In world *b=0*, the challenge proof π_b is generated for agent j₀ at scope S_b. The `scopedNullifier` is `Poseidon2(S_b, s^{j₀}_b)` — deterministic for this (agent, scope) pair, and identical to what was returned by the permitted pre-challenge query of (j₀, S_b).

Concretely, the adversary ℬ:
1. In the query phase, queries agent j₀ at scope S_b. Receives `n* = Poseidon2(S_b, s^{j₀}_b)`.
2. Selects j₀, j₁, Sₐ, S_b as the challenge pair (legally: (j₀, Sₐ) and (j₁, S_b) were not queried).
3. Receives `(v⃗_a, v⃗_b)`. Extracts `scopedNullifier_b` from v⃗_b.
4. If `scopedNullifier_b == n*`: output b'=0. Else: output b'=1.

In world *b=0*, `scopedNullifier_b = Poseidon2(S_b, s^{j₀}_b) = n*` — exact match. In world *b=1*, `scopedNullifier_b = Poseidon2(S_b, s^{j₁}_b)` — independent value, matches with negligible probability.

**Why it works:** The scoped nullifier is *intentionally deterministic* for (agent, scope) to enable double-spend detection. This determinism is exactly what the IND-UNL-AS game fails to account for. The restriction forbids (j₀, Sₐ) and (j₁, S_b) — but (j₀, S_b) is the pair that appears *in the challenge* in world b=0, and querying it is unrestricted.

**Why it fails against the construction (or doesn't):** This is not an attack on the *protocol* — it's an attack on the *game*. The construction's nullifier determinism is a feature. The game definition doesn't capture the correct security notion. The fix is standard: restrict the adversary from querying *any* (challenge\_agent, challenge\_scope) pair for either agent in either scope, i.e., prohibit (j₀, Sₐ), (j₀, S_b), (j₁, Sₐ), (j₁, S_b). The current restriction is strictly weaker than necessary, and the proof in §4.2 is not tight against this attack — the hybrid argument implicitly assumes the adversary has no pre-challenge nullifier from the challenge scopes.

**In-threat-model?** No. The IND-UNL-AS game as defined is broken. A corrected restriction is needed before the reduction sketch in §4.2 is meaningful.

---

### Attack 2: Dual PRF Orientation Breaks the A-PRF Assumption

**Attack:** The construction uses `scopeBlindingSecret` s_b as a PRF key in *two different argument positions* across its gadgets:

| Output | Expression | Key position |
|---|---|---|
| `scopedNullifier` | `Poseidon2(scopeId, s_b)` | Position 2 |
| `entryNullifier` | `Poseidon2(s_b, sessionNonce)` | Position 1 |
| `blindingCommitment` | `Poseidon2(s_b, credentialCommitment)` | Position 1 |

The A-PRF assumption in §4.1 claims Poseidon2 is a secure PRF "keyed on `scopeBlindingSecret`," and §4.2 states the "PRF assumption is symmetric in its arguments." This claim is unsubstantiated and non-standard. For a hash-based PRF, security requires the key to occupy a *fixed position* throughout all evaluations. Poseidon2 is a sponge/permutation-based function; its algebraic structure over 𝔽_p does not guarantee that `Poseidon2(x, k)` and `Poseidon2(k, y)` behave as independent PRFs with key k. In particular, if an adversary receives both `Poseidon2(scopeId, s_b)` (from RS-facing proofs) and `Poseidon2(s_b, sessionNonce)` (from on-chain delegation entries), the joint distribution over these outputs may leak information about s_b that neither output individually would reveal. No known result establishes that a single Poseidon2 evaluation with the key in two positions is jointly PRF-secure.

**Why it matters:** The reduction sketch in §4.2 handles the RS-facing nullifier with a PRF oracle keyed by s_b at input (scopeId), then claims the same oracle "covers both uses since s_b is the shared key." The oracle in §4.2 is defined as `𝒪(scopeId)` for RS-facing queries and `𝒪(sessionNonce)` for delegation-entry queries. But the actual circuit evaluates `Poseidon2(scopeId, s_b)` in one circuit and `Poseidon2(s_b, sessionNonce)` in the other — these require the key at *different positions*. The oracle abstraction implicitly assumes the two are PRF-equivalent. This is an assumption gap, not a theorem.

A concrete separation scenario: if Poseidon2 has any symmetry or algebraic relation between `Poseidon2(a, b)` and `Poseidon2(b, a)` (e.g., Poseidon's round constants are symmetric in ways that make the permutation self-inverse in some inputs), an adversary who collects enough cross-position pairs might recover structural information about s_b. Even if Poseidon2 is collision-resistant and one-way in the standard sense, PRF security in a dual-orientation mode requires a separate, stronger analysis.

**In-threat-model?** No. The A-PRF assumption as stated does not cover dual-orientation usage. The security claim requires either (a) a proof that Poseidon2 is PRF-secure when the key appears in either argument position simultaneously, or (b) redesigning the construction so s_b always occupies a fixed key position — e.g., using a domain-separated input as `Poseidon2(s_b, Poseidon2(0, scopeId))` and `Poseidon2(s_b, Poseidon2(1, sessionNonce))`, fixing the key in position 1 throughout.

---

### Attack 3: `scopeCommitment` Exposes Permission Bitmask via Exhaustive Preimage Search

**Attack:** The on-chain `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` is stored in the registry's `lastScopeCommitment` mapping (§2.7). The `credentialCommitment = Poseidon5(modelHash, opPubAx, opPubAy, permissionBitmask, expiryTimestamp)` is computable by any party who knows the credential fields — and the adversarial AS/operator knows *all* credential fields by construction (§3.1).

The `permissionBitmask` is an 8-bit value: 256 possible values. The adversary who suspects that on-chain `scopeCommitment` value *c* belongs to agent j:

1. Recomputes `credentialCommitment_j` from known credential fields.
2. For each of 256 possible bitmask values *b*: evaluates `Poseidon2(b, credentialCommitment_j)`.
3. Compares against *c*. Exactly one value matches.
4. Recovers `permissionBitmask_j` with *O(256)* Poseidon evaluations.

This is not a PRF inversion — it is an exhaustive search over a tiny domain with a single known-input oracle (Poseidon2 is public). The unlinkability argument in §4.3 states that linking `scopeCommitment` to `scopedNullifier` requires breaking Poseidon PRF, which is correct. But it does not address the recovery of `permissionBitmask` from `scopeCommitment` itself, which requires no cryptographic assumption to break.

**Practical impact:** In the NFCU scenario (§7), on-chain observers learn the exact permission tier of every agent that initiates a delegation chain. In the healthcare scenario, the patient's `permissionBitmask = 0b10000001` (READ_DATA + ACCESS_PII) is recoverable from the delegation entry, revealing that the agent has PII access — a significant privacy disclosure even if the specific RS visited is hidden.

**Why it fails against unlinkability but succeeds against privacy:** The IND-UNL-AS game as stated asks whether two proofs can be linked to the same agent — it does not define a separate privacy game for `scopeCommitment` contents. The construction correctly claims unlinkability (in the corrected game) but incorrectly implies in §8 that "the on-chain path" is private. The `scopeCommitment` leaks permission level in $O(N \cdot 256)$ work across all enrolled agents.

**In-threat-model?** Partially. The IND-UNL-AS claim is not directly broken, but the construction's accompanying privacy claims for the delegation path (§7 item 8: "cannot determine which of its enrolled agents initiated the chain") are overstated — the adversary can still enumerate which agents have *which permission tiers* from on-chain `scopeCommitment` values, and can trivially brute-force the bitmask component.

---

### Attack 4: Public `epochId` Creates a Mandatory Cross-Scope Temporal Correlation Channel

**Attack:** The `epochId` is a *public input* to `ScopedAgentAuth` bucketed to 5-minute windows (§2.5). An adversary observing proofs at two colluding RSes receives, in both proof vectors, the literal `epochId` value — identical if the accesses occurred in the same epoch. The `epochBinding` values differ (`Poseidon2(scopedNullifier_A, epochId)` vs. `Poseidon2(scopedNullifier_C, epochId)`), so the *cryptographic* unlinkability guarantee holds. But the *public input* `epochId` is a temporal fingerprint shared across scopes.

Define a distinguisher: ℬ receives two proofs at Sₐ and S_b. If the public `epochId` values match, both accesses occurred within the same 300-second window. Even with no ability to link the nullifiers, the adversary knows: "access at RS-A epoch e" and "access at RS-B epoch e" co-occurred. In the NFCU scenario, even if NFCU cannot determine *which* agent made the Amazon and Costco authorizations, any adversary observing both RSes' incoming proofs at epoch e can conclude: "some agent accessed both merchants within 5 minutes." Over time, distinctive multi-merchant co-access patterns produce a behavioral fingerprint. With $T$ observations at RS-A and $T$ observations at RS-B, a simple frequency correlation of epochId matches yields a linking signal in $O(\sqrt{T})$ observations for any sufficiently active agent.

**Why the epoch bucketing is insufficient as a mitigation:** The construction recommends (§3.6) that agents "MAY add random delay within epoch." This is optional, not enforced at the circuit level. Nothing in the `ScopedAgentAuth` circuit prevents generating proofs at the same epochId in both RS-facing interactions. Mandatory padding to epoch boundaries, or per-scope jitter enforced as a circuit constraint, would require either larger epochs (degrading double-spend detection granularity) or proof batching (architectural complexity not present in the construction).

**Formal gap:** The IND-UNL-AS game does not model the public `epochId` field as a distinguisher. An adversary whose strategy is "compare epochId fields across received proofs" is not captured by the hybrid argument in §4.2, which only reduces unlinkability to the nullifier values. A formally complete proof would need to either (a) treat the epochId as adversarially controlled (adversary knows when in the epoch the proof was generated) and show the adversary gains no *additional* information about agent identity from this knowledge, or (b) explicitly state that timing correlation within epochs is an accepted non-goal of the construction's unlinkability claim, and bound the privacy leakage quantitatively. Neither is present in §3.6.

**In-threat-model?** Partially. The cryptographic unlinkability claim (IND-UNL-AS) is not directly broken by this attack since `epochId` correlation is a statistical/timing attack rather than an algebraic one. However, the construction's own §3.6 table lists "Timing of proof submission" as mitigated by epoch bucketing, and the mitigation relies on an optional behavior ("MAY add random delay") that is not protocol-enforced. The claim that epoch bucketing provides timing-channel resistance is overstated without a quantitative bound on the mutual information leakage from `epochId` co-occurrence.


## Persona: cu_ciso

---

### Attack 1: Audit Trail Destruction Defeats NCUA Part 748 §748.0(b)(2) and BSA/AML Obligations

- **Attack:** The construction's unlinkability guarantee is precisely the property that destroys my audit trail. Section 7 of the construction brags: "NFCU has no visibility into which merchants the agent subsequently contacts, when, or how often. The merchant graph is cryptographically hidden." My NCUA examiner reads that sentence and asks where my SAR (Suspicious Activity Report) evidence comes from. NCUA Part 748 Appendix A requires a security program that "responds to unauthorized access." If member agent #4821 sends `FINANCIAL_SMALL` transactions to 40 merchants in 20 minutes, I have a fraud event. My BSA officer needs to reconstruct the timeline, identify the merchant sequence, and file a SAR with FinCEN. The construction gives me: a Merkle root, a scope-local nullifier per RS, and epoch bindings bucketed to 5-minute windows. I cannot link `scopedNullifier_Amazon` to `scopedNullifier_Costco` without `scopeBlindingSecret` — and per §2.4 the construction expressly prevents me from having it. I cannot produce a complete transaction graph for SAR narrative purposes. I cannot comply with 31 U.S.C. 5318(g).

- **Why it works / why it fails against the construction:** The construction does not address this at all. Section 3.6 (side-channel table) mentions IP correlation as "out of scope." There is zero treatment of CU-side forensic obligations. The construction treats "NFCU cannot see merchant graph" as a feature and never asks whether NFCU is *required by law* to see the merchant graph in some form. There is no selective disclosure mechanism — no way for the member to waive unlinkability for audit purposes, no way for the CU to obtain a court-ordered disclosure, no escrow of linkage keys. The construction's security argument gives the adversary (NFCU-as-operator) all operator keys and *still* achieves unlinkability. That means a subpoena gets me the same nothing.

- **In-threat-model?** No — the construction must address this. Either it provides a compliant audit mode (selective disclosure / escrow), or it explicitly scopes itself to non-BSA-covered use cases (which excludes every credit union deployment scenario described in §7).

---

### Attack 2: `scopeBlindingSecret` Lives on a Member Device — GLBA Safeguards Rule Cannot Govern It

- **Attack:** Section 2.4 is the critical passage: `scopeBlindingSecret` is "stored alongside the agent's credential material in the agent's local secure storage" and "never transmitted to the operator." For any real member deployment, "agent's local secure storage" is a browser's IndexedDB, a mobile app's keychain, or a user-controlled laptop. The GLBA Safeguards Rule (16 CFR Part 314.4) requires the CU to implement a written information security program covering "customer information systems." The `scopeBlindingSecret` is the master key to all scope-local nullifiers — if it leaks, the entire unlinkability guarantee collapses (§3.1 explicitly acknowledges: "If the adversary compromises the agent's local storage, all unlinkability guarantees are void"). This secret constitutes member-identifying customer information under GLBA. My Vendor Management Policy requires me to enumerate where customer information is stored. I cannot enumerate member devices. I cannot enforce HSM requirements on member devices. I cannot detect leakage events. The rotation mechanism (§2.4, "generate a new credential with a fresh blinding secret") requires full re-enrollment in the Merkle tree — there is no lightweight key rotation. If a member's device is stolen and I am notified 72 hours later, I have no way to invalidate the old blinding secret without also revoking the entire credential. My incident response playbook has no entry for "member's ZK blinding secret may be compromised."

- **Why it works / why it fails against the construction:** The construction's threat model (§3.1) explicitly places the agent's local execution environment *outside* the adversary's control and calls this "the standard assumption that a user's secret key is not leaked." That framing works for a cryptography paper. It does not work for a GLBA examination. The NCUA examiner does not accept "we assume the member's device is secure" as a control. The construction has no HSM integration path, no discussion of secure enclave requirements (TEE, TPM), no key management spec. For a credit union deploying this, member device compromise is not a theoretical adversary — it is a weekly IT helpdesk event.

- **In-threat-model?** No — the construction must specify minimum key storage requirements (HSM, secure enclave, or equivalent) and a credential revocation path that does not require re-enrollment. Without these, no GLBA-regulated institution can deploy this for member-facing agents.

---

### Attack 3: On-Chain Registry SLA vs. Core Processor SLA — Single Point of Failure the Examiner Will Find

- **Attack:** Section 2.6 (verification flow, step 4) requires the RS to verify the PLONK proof "against the on-chain `agentMerkleRoot` (via root history buffer lookup)." Without a live, queryable on-chain registry, no RS can authorize any agent. The 30-entry root history buffer (§5 primitive mapping) provides latency tolerance — it does not provide availability. If the Base chain has an outage, or if the smart contract is behind on L2 finality, the RS verification call fails. My core processor (FIS, Fiserv, Jack Henry) has a contractual 99.9% uptime SLA — that is 8.7 hours of downtime per year. The question I ask every fintech vendor: what is your SLA, and who do I call at 2am? The construction does not state an availability target. There is no fallback when the on-chain registry is unavailable. There is no circuit-breaker design. There is no description of the node infrastructure behind the RPC calls. FFIEC CAT (Intermediate Baseline, availability domain) requires that critical third-party dependencies have documented RPO and RTO targets with contractual backing.

- **Why it works / why it fails against the construction:** The construction makes no mention of availability architecture anywhere. Section 3.6 side-channel table covers timing and proof latency but not infrastructure availability. The deployment scenario in §7 describes a live NFCU + Amazon + Costco flow but gives no operational detail about what happens when `eth_call` to the registry contract times out. The construction notes the Merkle root history buffer tolerates "proof generation latency without requiring tree-update synchronization" — this addresses a *correctness* concern, not an *availability* concern.

- **In-threat-model?** No — the construction must address availability SLA, fallback behavior when on-chain state is unreachable, and the operational model for smart contract maintenance (upgrades, bug fixes, emergency pause). A construction that is cryptographically sound but operationally unavailable 0.5% of the time will fail FFIEC CAT and NCUA third-party risk review.

---

### Attack 4: Smart Contract Is an Unvetted Third-Party Vendor Under NCUA's Third-Party Risk Framework

- **Attack:** The on-chain registry is not infrastructure I own — it is a smart contract operated (implicitly) by ZKProva Inc. / Bolyra. My NCUA Vendor Management Policy requires documented vendor due diligence: financial stability review, SOC 2 Type II (or equivalent), right-to-audit clause, business continuity plan, data classification of what the vendor receives, incident notification SLA. The construction's §3.1 security assumptions include "smart contract correctness assumption" — but NCUA does not accept a cryptographic assumption in lieu of vendor due diligence documentation. The construction also notes that `scopeCommitment` values are posted on-chain (§2.3) and are "visible to all on-chain observers." For a GLBA-regulated CU, posting any value derived from member credentials to a public blockchain is a data residency question. The construction argues this value is unlinkable — but if NCUA's examiner cannot independently verify that Poseidon PRF is secure, the argument is not auditable. The FFIEC CAT third-party management control requires that I "understand and monitor" third-party service providers. I cannot monitor a smart contract using standard vendor monitoring tools (Venminder, Vendor Tracker, etc.).

- **Why it works / why it fails against the construction:** The construction does not mention vendor risk, contractual SLAs, or right-to-audit. Section 8 (baseline comparison table) focuses exclusively on cryptographic properties. There is no operational ownership model for the on-chain registry — no description of who deploys it, who can pause it, who is liable if it has a bug, or what the upgrade governance process is. The construction's §3.1 explicitly treats smart contract correctness as a pure assumption rather than a managed risk. For a credit union board narrative, "we assume the smart contract is correct" is not a risk management posture.

- **In-threat-model?** No — the construction must define an operational governance model for the on-chain registry: who operates it, what the contractual relationship is, how upgrades are managed, what on-chain data is considered member-derived (and subject to GLBA), and how a CU conducts vendor due diligence on an immutable smart contract. Without this, the construction cannot pass NCUA third-party risk review regardless of its cryptographic strength.


## Persona: rfc7662_advocate

I've spent a decade shipping RFC 7662 for large enterprise deployments. Every claim in this construction gets measured against what a well-configured AS can already do — and against whether the construction's own fixes are internally consistent.

---

### Attack 1: Baseline Mischaracterization — JWT Introspection Response Removes the AS from the Hot Path Too

- **Attack:** Section 8's table asserts "AS must be contacted for every token issuance" as the baseline's core weakness. This is wrong. `draft-ietf-oauth-jwt-introspection-response` allows the AS to sign a JWT containing the full token metadata; the RS caches and revalidates it locally without contacting the AS, for a configurable cache lifetime. Combine with RFC 8707 audience binding (token is RS-specific), RFC 9449 DPoP (sender constraint), and a cache TTL matching the construction's 300-second epoch window. After the initial issuance, the RS verifies entirely locally — exactly what the construction claims as its architectural innovation. The construction's §2.6 says "The AS is never contacted. There is no token issuance step" — but post-enrollment that baseline statement is also false: the RS verifies a cached signed JWT, no live AS call.

- **Why it works / why it fails against the construction:** The attack correctly identifies that the §8 differentiation table overstates the baseline's hot-path dependency. However, the attack **does not break the construction's actual claim**. Even with cached JWT responses, the AS still issued tokens with scope × agent × timestamp in its issuance log and can reconstruct the full traffic graph retroactively. The construction's real differentiator — the only one that survives — is **AS-side unlinkability post-enrollment**: the AS never learns which RSes an agent contacted because the agent never contacts the AS at all after enrollment. The construction must restate the §8 entry: the differentiating claim is "AS learns zero post-enrollment authorization events," not "AS is off the hot path." Conflating these weakens every other comparison in the table.

- **In-threat-model?** Yes — the construction survives this attack, but only if it corrects the baseline characterization. The current §8 table entry is technically wrong and an RFC 7662 advocate will use this misstatement to dismiss the entire comparison.

---

### Attack 2: `scopeCommitment` is an O(N) Deanonymization Oracle for Delegation Initiators — the `entryNullifier` Fix was Incomplete

- **Attack:** Section 3.5 correctly identifies and fixes the `entryNullifier` brute-force vulnerability: the prior `Poseidon2(credentialCommitment, sessionNonce)` allowed an adversarial AS/operator to enumerate all N enrolled agents and match the on-chain value in O(N) Poseidon evaluations. The fix replaces `credentialCommitment` with `scopeBlindingSecret` in the nullifier, making the preimage unknown. But the `DelegationEntry` circuit also publicly outputs and stores on-chain `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)`. Both inputs are **fully known to the adversary**: `credentialCommitment = Poseidon5(modelHash, opPubAx, opPubAy, permissionBitmask, expiryTimestamp)` is computable from operator-held credential fields (§3.1, §3.4 explicitly states "the operator can recompute `credentialCommitment`"). The adversary evaluates `Poseidon2(permissionBitmask_j, credentialCommitment_j)` for every enrolled agent j and compares against the on-chain `scopeCommitment`. Exactly one matches — revealing which agent initiated the delegation chain. This is the same O(N) attack the `entryNullifier` fix was designed to close, applied to a different public output of the same circuit.

- **Why it works / why it fails against the construction:** The construction does not address this. Section 4.3 says "an adversarial operator who knows `credentialCommitment`... and therefore knows `scopeCommitment` cannot bridge to `scopedNullifier` without $s_b$" — but that only addresses bridging to the RS-facing proof, not **identifying the delegation initiator from the on-chain entry**. Section 3.3 and §7 claim "NFCU cannot determine which of its enrolled agents initiated the delegation chain" — this claim is **false** under the current construction. The `entryNullifier` fix achieved anonymity for one output while leaving the other output of the same circuit computable by the same brute-force. The fix must extend `scopeCommitment` to incorporate `scopeBlindingSecret`: e.g., `scopeCommitment = Poseidon3(permissionBitmask, credentialCommitment, scopeBlindingSecret)`. This preserves the delegation chain linking property (the delegatee's `ScopedDelegation` circuit must also know `scopeBlindingSecret` to verify the seed) but closes the deanonymization oracle. Alternatively, the construction can explicitly accept this as an information leak ("delegation initiators are identifiable by the operator, only non-delegating flows achieve full unlinkability") and scope the IND-UNL-AS game accordingly.

- **In-threat-model?** **No** — this is an unaddressed gap. The IND-UNL-AS game (§3.2) includes delegation-entry queries (step 2) and claims they are covered by the PRF bound (§4.2 extension paragraph). That claim is **incorrect** for `scopeCommitment`: the reduction shows `entryNullifier` is PRF-secure, but `scopeCommitment` is a deterministic function of adversary-known inputs, not a PRF output. An adversary querying agent $j_0$'s delegation entry observes `scopeCommitment` and can confirm which agent it is in O(N) — the PRF bound does not apply to this output. The construction must address this.

---

### Attack 3: PPID Cross-RS Unlinkability is Already RFC-Standard — The Construction's Only Load-Bearing Claim Is AS-Side Unlinkability, Which It Conflates With a Different Property

- **Attack (from toolbox: Pairwise Subject Identifiers):** The RS-layer unlinkability claim — "two proofs at two different scopes produce unlinkable outputs at the RS layer" — is structurally equivalent to what OIDC PPIDs already provide. RS-A receives `sub = PPID(agent, RS-A)` = `Poseidon(agent_id, RS-A_id, AS_secret)`, RS-B receives `PPID(agent, RS-B)`. The RS-layer cross-linkability is broken identically: colluding RS-A and RS-B compare `PPID(agent, RS-A)` vs `PPID(agent, RS-B)` — pseudorandom outputs under unknown key (AS_secret), unlinkable under the same PRF assumption the construction uses. The construction's §4.3 "Collusion Resistance" argument for colluding RSes is formally identical to the PPID PRF argument. The construction's differentiator must be exclusively and explicitly **AS-side unlinkability**: the AS cannot reconstruct the traffic graph because it is never contacted and cannot evaluate `scopedNullifier = Poseidon2(scopeId, scopeBlindingSecret)` without knowing `scopeBlindingSecret`. The current §8 table and §1 claim statement conflate RS-level and AS-level unlinkability, making the construction appear to overclaim.

- **Why it works / why it fails against the construction:** The attack correctly identifies that the RS-layer claim is redundant with existing standards. The construction's valid differentiator is precisely the AS-side property the PPID argument cannot provide: the AS who issues PPIDs maintains a lookup table `(real_id → PPID mappings)` and trivially reconstructs the traffic graph from its own issuance logs, regardless of what RSes see. Bolyra eliminates this because the AS is never in the authorization loop after enrollment. The attack **does not break the construction**, but it forces a critical restatement: the claim in §1 should be "Same agent accessing different RS instances produces cryptographically unlinkable authorizations **from the AS's perspective** even when the AS is also the credential operator" — not a general cross-RS claim. The current phrasing implies a novelty over PPID that doesn't exist at the RS layer.

- **In-threat-model?** Yes — the construction survives, but only if it sharpens its claim to AS-side unlinkability. The current claim conflates two distinct properties and will be dismissed by any OAuth working group reviewer who reaches for the PPID RFC.

---

### Attack 4: Epoch Bucketing Creates Correlated Anonymity Set Collapse in Low-Traffic Deployments

- **Attack (from toolbox: timing side channels):** The `epochBinding = Poseidon2(scopedNullifier, epochId)` uses a 300-second epoch window. Two RSes receiving proofs with identical `epochId` know both authorizations occurred in the same 5-minute window. In the stated deployment scenario — NFCU member agents authorizing at Amazon and Costco — the anonymity set is the number of distinct agents active in each epoch at each RS. During business hours for a large CU, this may be large. But the construction is also claimed for healthcare (§7): a patient's agent at Quest Diagnostics (RS-A) and Cedars-Sinai (RS-B) in the same epoch. Healthcare authorization events are sparse — at 3am, within a 300-second window, the anonymity set at each RS may be 1. If RS-A and RS-B each receive exactly one proof in epoch E, a colluding adversary has a probabilistic near-certainty that both proofs originated from the same agent, defeating the IND-UNL-AS game's unlinkability bound in any anonymity-set-of-1 epoch. The `epochId` is public in all proofs, so the adversary can directly compare epoch values across RSes without any cryptographic computation. This is a non-cryptographic timing attack that falls within the construction's stated threat model (§3.1: adversary controls colluding RSes and observes timing data) and is NOT fully mitigated by the §3.6 table's "Agent MAY add random delay within epoch" note — "MAY" is insufficient normative language and random delay within a 300s window only helps when the anonymity set has more than one active agent.

- **Why it works / why it fails against the construction:** The construction partially acknowledges timing in §3.6 ("timing of proof submission: epoch bucketing... agent MAY add random delay") but does not provide an anonymity set bound or threshold below which the unlinkability guarantee degrades. The IND-UNL-AS game (§3.2) makes no assumption about anonymity set size — it treats N agents as enrolled but doesn't model traffic density. In a dense system, epoch timing is harmless. In a sparse system (the healthcare scenario), it is decisive. The construction should either (a) explicitly state a minimum anonymity set size required for the timing guarantee to hold, (b) define a stronger epoch model (e.g., minimum k agents per RS per epoch before any proof is released — a k-anonymity threshold), or (c) acknowledge that in sparse deployments, the construction provides computational but not statistical unlinkability against a timing-observing colluding RS set.

- **In-threat-model?** **Partially** — the construction acknowledges timing as a side channel but does not bound its impact or link it to the formal IND-UNL-AS guarantee. The "MAY" language for random delay is insufficient for a construction targeting cryptographic unlinkability. An adversary controlling two low-traffic RSes in the healthcare scenario trivially wins the unlinkability game via epoch correlation in any sufficiently sparse traffic window — this is not covered by the Poseidon PRF reduction.


## Persona: spiffe_engineer

I run SPIFFE/SPIRE across 40,000 workloads at a Fortune 500. I co-author WIMSE drafts. My view: workload identity is a solved problem at the right abstraction layer, and ZK circuits belong in cryptography papers, not in the authorization hot path for cloud-native agents. Let me try to break C2.

---

### Attack 1: "The On-Chain Registry Is Just a Decentralized SPIRE Server — the AS-Free Claim Is Hollow"

**Attack:**
The construction's §2.6 verification flow claims "the AS is never contacted." But the RS in step 4 verifies `agentMerkleRoot` against the on-chain 30-entry root history buffer (§3.6 side-channel table). That smart contract *is* the AS — it's the root of trust for every authorization decision. In SPIFFE, the SPIRE server distributes trust bundles (X.509 root CAs) to all workloads. Bolyra replaced a centralized SPIRE server with a smart contract, but the trust anchor is identical in function. The IND-UNL-AS game (§3.2) models unlinkability against the *original* operator/AS, but it does not model the smart contract operators — the L2 block proposers, sequencers, and upgrade key holders on Base Sepolia — as adversaries. A sequencer on Base Sepolia who can selectively reorder or censor `DelegationEntry` transactions sees which session nonces get recorded and when, with packet-level timing. §3.1 lists "on-chain Merkle tree integrity (smart contract correctness assumption)" as *outside* the adversary's control without justification — this is exactly the assumption SPIFFE's trust bundle federation was designed to make explicit and auditable.

**Why it works / why it fails against the construction:**
The construction correctly restricts the unlinkability claim to the *original AS/operator* threat — NFCU cannot correlate traffic even with operator private keys. The smart contract is public and decentralized, so its governance is orthogonal to operator-level correlation. However, the construction introduces a *second* trust principal (blockchain operators) without any security model for it. The IND-UNL-AS game says nothing about sequencer-level observation of on-chain `scopeCommitment` and `entryNullifier` transaction ordering. A sequencer who sees two `DelegationEntry` transactions from different session nonces arrive within milliseconds has timing correlation the construction attributes entirely to transport-layer anonymization (IP side channel, noted as "out of scope" in §3.6 — but this is on-chain, not IP).

**In-threat-model?** No. The construction must address: (a) what the smart contract governance assumption implies for the threat model, and (b) whether sequencer-level transaction ordering constitutes a side channel not covered by epoch bucketing (which only quantizes *proof submission* timing, not *transaction submission* timing).

---

### Attack 2: "scopeBlindingSecret Has No Platform Attestation — the Trust Boundary Collapses in the Stated Deployment Scenario"

**Attack:**
§3.1 states: "The adversary does NOT control: The agent's local execution environment. The `scopeBlindingSecret` is generated and stored locally by the agent." The entire IND-UNL-AS reduction (§4.2) rests on this single assumption. The security of Poseidon PRF keyed on `scopeBlindingSecret` is only useful if the adversary cannot obtain `scopeBlindingSecret`. But look at §7, Scenario 1: NFCU is the operator. In every real enterprise AI agent deployment I have seen, the *operator also runs the agent's infrastructure* — container orchestration (EKS, GKE), secrets management (AWS Secrets Manager, Vault), and runtime execution environments. NFCU's DevOps team provisions the namespaces in which member agents run. The `scopeBlindingSecret`, stored in "the agent's local secure storage," lives in a Kubernetes secret or AWS Secrets Manager entry in NFCU's own AWS account.

SPIFFE/SPIRE solves *exactly this problem* via node attestors: AWS Instance Identity Document attestation, Kubernetes PSAT attestation, and TPM-backed attestation bind a workload's SVID to a specific platform identity, cryptographically verifiable by the SPIRE server without the server having access to the SVID private key. The Bolyra construction has no equivalent mechanism. §2.4 says the blinding secret "MUST NOT be derived from operator key material" but provides zero mechanism to enforce or *verify* that invariant. There is no attestation path that lets an RS (or an auditor) confirm that `scopeBlindingSecret` was generated in an environment the operator cannot access.

**Why it works / why it fails against the construction:**
This is not a cryptographic attack — the circuit constraints are correct. It is an architecture-layer attack: the formal security model (§3.1) assumes away exactly the capability that the primary threat actor (NFCU-as-operator) possesses in practice. In SPIFFE terms, we distinguish *workload identity* (cryptographically attested to a platform) from *workload secrets* (stored in operator-controlled infra). Bolyra promotes a secret into the security-critical path without a platform attestation binding.

§2.4 acknowledges key compromise: "If the agent's local environment is compromised, the `scopeBlindingSecret` is assumed leaked." But in an operator-controlled cloud, "compromised" and "normal operations" are the same thing.

**In-threat-model?** No. The construction must specify: what execution environment guarantees isolate `scopeBlindingSecret` from the operator, and how does a relying party (RS) verify those guarantees? Without a TEE attestation primitive (Intel TDX, AWS Nitro Enclaves) or a hardware security module binding, the "agent-local" trust boundary is an unverifiable policy assertion, not a cryptographic property.

---

### Attack 3: "WIMSE Token Binding Addresses AS Correlation at the Right Layer — ZK Circuits Are Solving the Wrong Level"

**Attack:**
WIMSE (draft-ietf-wimse-arch §4) separates workload identity (SPIFFE SVID) from per-request authorization (capability tokens). In the WIMSE architecture, an intermediary workload (acting as an AI agent) presents its SVID-bound capability token to a downstream RS *without* contacting the upstream AS for each request. The SVID is issued by SPIRE once (equivalent to Bolyra enrollment) and reused across RS calls with workload-bound DPoP-style proof-of-possession. The construction's claim in §8 — "OAuth/OIDC places the AS on the critical path of every authorization" — is *already addressed by WIMSE*. I don't need a 17,000-constraint PLONK circuit to remove the AS from the per-request path; I need WIMSE-compliant workload tokens bound to a SPIFFE SVID.

**Why it works / why it fails against the construction:**
WIMSE partially addresses the hot-path problem but does *not* close the AS=operator correlation gap. WIMSE's trust model assumes the SPIRE server (analogous to the Bolyra operator) is trusted. If NFCU operates the SPIRE server, NFCU's SVID issuance log reveals which workloads were issued SVIDs, and JWT SVIDs include `spiffe://nfcu.trust-domain/member-agent-4821` — the operator reads traffic intent from the SVID's path component. WIMSE's selective disclosure work is in scope (§6 of draft-ietf-wimse-arch) but has not shipped. Bolyra's construction survives this attack in the *AS=operator adversarial model* specifically — WIMSE provides no unlinkability when the SPIRE operator is the adversary.

The construction's §8 "structural impossibility" argument is correct for OAuth but overstates the gap against WIMSE. The construction should narrow its claim: the unlinkability property is specifically against operators who are also AS operators, a scenario WIMSE explicitly defers to future work.

**In-threat-model?** Yes, but the construction must acknowledge the narrower claim: WIMSE handles AS-hot-path removal; Bolyra's unique value is *AS=operator adversarial unlinkability*, not AS removal per se. Conflating these two properties (as §8 does) invites WIMSE co-authors to reject the comparison as a straw man.

---

### Attack 4: "The IND-UNL-AS Query Restriction Breaks in the AS=Operator Staging/Production Overlap — Determinism Is the Enemy"

**Attack:**
§3.2 step 2 requires: "The adversary may not query the same (agent, scope) pair that will appear in the challenge." This restriction is theoretically standard (analogous to CPA) but operationally catastrophic in the primary deployment scenario. In §7 Scenario 1, NFCU is the operator who provisions credentials. NFCU runs staging environments, integration tests, and compliance audits. In any standard enterprise SDLC, the *same credential* (same `credentialCommitment`, same `scopeBlindingSecret` if reused from staging) is exercised in pre-production against a staging RS at Amazon's sandbox endpoint. The `scopedNullifier = Poseidon2(scopeId_Amazon_staging, scopeBlindingSecret)` is observable by NFCU in the pre-production flow.

But here is the structural issue: the construction uses the *same `scopeBlindingSecret`* across all scopes for a single credential (§2.4: "It is generated once per agent credential and reused across all scopes"). This means staging and production share the same blinding secret. If `scopeId_Amazon_staging` and `scopeId_Amazon_production` differ (which they should — different environment identifiers), the staging nullifier and production nullifier are different and the query restriction is not violated. But §2.5 explicitly states that `scopedNullifier` is *deterministic per (agent, scope)*: "enabling double-spend detection within a scope." An adversarial NFCU who induces the agent to authorize once at the *exact same* `scopeId` (staging = production, which happens in lift-and-shift deployments) has broken the restriction and can compare nullifiers trivially — no cryptographic assumption needed, just determinism.

**Why it works / why it fails against the construction:**
The construction can respond that staging and production environments must use separate `scopeId` values (and SHOULD use separate credentials). §2.4 on rotation says "the agent MUST generate a new credential" on compromise. But the construction nowhere states that staging and production credentials must be independent, and the query restriction's operational meaning (you must never have observed this agent at this scope before) is never translated into deployment guidance. In SPIFFE, trust domains serve exactly this function: `spiffe://staging.nfcu/agent` and `spiffe://prod.nfcu/agent` are distinct, unfederated identities — the staging AS cannot observe production SVID issuance. Bolyra provides no equivalent trust-domain separation for the blinding secret.

The deeper issue: the IND-UNL-AS game restriction is standard in academic unlinkability proofs but produces a *gap between the formal model and operational deployment*. The construction's formal security holds under the restriction; the deployment guidance does not close the restriction.

**In-threat-model?** Partially — the query restriction is standard game machinery, so the formal model is internally consistent. But the construction must add explicit operational guidance: separate credentials (and separately-generated blinding secrets) MUST be used per environment, and `scopeId` namespaces MUST be environment-segregated. Without this guidance, the IND-UNL-AS game's restriction is silently violated in any standard enterprise staging/production overlap, collapsing unlinkability to $O(1)$ comparison with no cryptographic work.
