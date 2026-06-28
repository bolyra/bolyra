# Tier 3 Adversarial — C1 Selective scope proof

The file write needs your approval — please allow it in the permissions prompt. While you decide, here are the attacks:

---

## Persona: auth0_pm

### Attack 1: The 64-bit Brute-Force Admission Is Your Enterprise Coffin

- **Attack**: The PM reads the adversary knowledge hierarchy table the construction now transparently includes. Row 3 says: "adversary knows (modelHash, operatorKey, expiry) → degrades to 64-bit brute-force." Then the PM asks SECU's security team a single question: "In your deployment, does the credential operator — which is SECU itself — know its own operator key, the model hash of the agents it deployed, and the expiry it issued?" The answer is always yes. The AS *is* the operator in every enterprise deployment. The PM reframes this for procurement: "The vendor's own documentation says that when the issuer knows what it issued — which is every real deployment — your privacy guarantee is bounded by brute-forcing 64 bits. That's the privacy claim you're buying."

- **Why it works / why it fails**: The construction is transparent about the limitation and correctly frames it as an enrollment-layer property. The cryptographic rebuttal is that 2^64 Poseidon evaluations are computationally infeasible today. But the *GTM* rebuttal fails: "64-bit brute-force" sounds like nothing to a procurement officer who has read headlines about GPU clusters. Auth0 does not ask its customers to understand Poseidon throughput estimates. The construction needs a one-sentence buyer answer: "The AS knowing its own operator key does not help it determine what permissions it issued, because the bitmask is hidden from even the AS after enrollment." If that sentence is true, state it. If it's not — if the AS chose the bitmask at enrollment and therefore already knows it — the privacy game is protecting against a threat that doesn't exist in the semi-honest AS model.

- **In-threat-model?** No. The construction acknowledges the 64-bit regime but does not explain *to a buyer* why the semi-honest AS cannot trivially recover the bitmask it encoded. The threat model must clarify whether the AS knows `permissionBitmask` post-enrollment (it does — it chose it) and if so, what "privacy" the construction is actually providing against *that* AS. The current framing conflates "AS cannot alter a past commitment" with "AS cannot know what was committed."

---

### Attack 2: scopeCommitment Is Still a Cross-RS Tracking Cookie — And the Fix Breaks Your Only Delegation Story

- **Attack**: The PM points at the public outputs table: `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)`. The single-credential SI game fix is entirely about the privacy game for bitmask recovery — it doesn't touch `scopeCommitment`. Every SECU resource server still receives the same `scopeCommitment` on every Agent-X session, forever. The PM demonstrates: two RSes share a log line, correlate by `scopeCommitment`, and reconstruct the agent's full session history across all SECU systems with zero cryptographic work. Then the PM offers Auth0's approach: pairwise pseudonymous identifiers (`sub = PRF(RS_id || agent_id)`) gives each RS a different stable identifier for the same agent — no cross-RS correlation without AS cooperation. "You claimed unlinkability as Property 4. WorkOS ships better unlinkability today, without ZK."

- **Why it works / why it fails**: The construction's own current-revision note acknowledges the fix: `Poseidon3(bitmask, credComm, sessionNonce)`. But the construction also states this "breaks the delegation-chain-seed use case." This is the real trap: the construction's two strongest claims — cross-RS unlinkability and delegation scope narrowing — are in direct architectural tension. Per-session randomization of `scopeCommitment` severs the chain anchor that delegation circuits depend on. Fixing one falsified claim breaks another.

- **In-threat-model?** No. The construction must resolve the delegation-vs-unlinkability tension explicitly before claiming both properties. The current state concedes the tension without resolving it, leaving `scopeCommitment` as a permanent stable tracking tag in every deployed instance.

---

### Attack 3: Proving Time Multiplied by API Call Count Is Your Real Latency Budget — And It Isn't 5 Seconds

- **Attack**: The construction targets "<5 seconds" per PLONK proof (circuit at ~20,000 constraints). The PM asks SECU's platform team to walk through a realistic agentic loan origination workflow: balance check, fraud screen, eligibility assessment, rate fetch, compliance check, disclosure logging — six API calls to six resource servers. Six proofs at <5 seconds each = up to 30 seconds of pure proof overhead per member-initiated loan inquiry. Auth0 issues tokens in <100ms; the full OAuth exchange including network is <300ms. The PM presents a 100× latency regression as the enterprise conversation stopper.

- **Why it works / why it fails**: The fix to the SI game does nothing for latency. The construction's Section 6 is honest about constraint count and provides per-proof estimates but never models multi-call workflow latency. The rebuttal — proof pre-generation keyed to known `requiredScopeMask` values — only works for a closed, static RS set, which is exactly the scenario where RFC 8693 token pre-exchange already beats ZK on every dimension. For an open/dynamic RS set (the stated differentiator), pre-generation is not possible.

- **In-threat-model?** No. The construction must address workflow-level latency, not just per-proof latency. Either: (a) demonstrate proof caching or batching for known RS masks, (b) propose a hybrid where a single proof authorizes a short-lived session token valid for N calls in a time window, or (c) bound the use case to infrequent high-value authorizations where 5-second latency is acceptable. Without this, the latency objection closes the enterprise procurement door before cryptographic novelty is ever evaluated.

---

### Attack 4: "Solo Founder" Plus "We Admit 64-Bit Brute Force" Fails Vendor Assessment Before the Demo

- **Attack**: The PM never gets to cryptographic claims in an enterprise security review. SECU's vendor assessment asks: SOC 2 Type II? (No.) ISO 27001? (No.) Bug bounty program with public results? (No.) Indemnification clause? (Unknown.) How many enterprise customers? (Zero in production.) Then the assessor reads the security documentation and finds: "privacy degrades to 64-bit brute-force when the adversary knows non-bitmask credential fields." The assessor flags this as a documented vulnerability with no mitigating control. Auth0 has 18,000+ customers, SOC 2, and does not describe brute-force windows in its security docs — because it doesn't have to.

- **Why it works / why it fails**: This is not a cryptographic attack — it's a procurement process attack, which is the auth0_pm's actual weapon. The construction's transparency about the 64-bit limitation is technically correct and academically honest. In enterprise procurement, academic honesty about limitations reads as vendor risk. Auth0 does not document "if you know the client secret, you can forge tokens" — even though that's equally true — because the mitigating control (don't expose the client secret) is implicit and well-understood. The Bolyra construction surfaces a limitation without clearly stating what the mitigating control is or why the threat doesn't materialize in practice.

- **In-threat-model?** No. The construction must translate the 64-bit brute-force row into buyer language: who the adversary is in this row, why they don't already know the bitmask (they chose it), and what the actual residual risk is — or remove the row if it describes a non-threat. As written, it arms the incumbent's sales team against Bolyra in every competitive evaluation.


## Persona: cryptographer

---

### Attack 1: Credential Linkability via Public Merkle Leaf

**Attack:** The adversary (RS, or colluding AS+RS) observes `credComm` as a cleartext Merkle leaf. Every ZK Merkle-inclusion proof must commit to a public root and reveal the leaf (or its hash at the inclusion path nodes). Across all sessions where the same credential is presented to the same or colluding verifiers, `credComm` is a stable pseudonym — a long-lived public identifier. The nullifier `Poseidon2(credComm, sessionNonce)` is session-unique, but `credComm` itself is not. The adversary trivially links all presentations by correlating the leaf value before the nullifier is even computed.

**Why it works / fails:** The single-credential SI game fixes distinguishability of *bitmask values* but says nothing about *presentation unlinkability across sessions*. ZK hides the proof internals; it does not hide the Merkle leaf value from the opening. This is a separate property — call it `UNL` — that requires either credential rotation per session (expensive issuance), per-session re-randomized commitments (Groth16 has no native re-randomization; you'd need Pedersen + SXDH), or a blinded Merkle path (e.g., WHISK-style or Groth-Sahai).

**In-threat-model?** No — the construction claims AS-blind presentation and no linkability by the RS, but against a passive RS (let alone a colluding AS+RS), sessions sharing the same `credComm` leaf are linked. The construction must add a formal `UNL` game and show a reduction.

---

### Attack 2: Missing Operator Signature Check — Soundness is Unspecified

**Attack:** The circuit (per the CLAUDE.md AgentPolicy description) verifies: (a) `credComm` is in the Merkle tree, and (b) the bitmask satisfies the predicate. But the circuit does not appear to verify an operator signature over `(modelHash, operatorKey, bitmask, expiry)`. Therefore: an adversary who can write an arbitrary leaf into the Merkle tree (e.g., by operating their own node, or by exploiting a permissionless registry) can claim any bitmask they want. The Groth16 knowledge extractor (in the AGM) extracts *a witness consistent with the statement* — but the statement "there exists a bitmask `m` such that `credComm = Poseidon(modelHash, opKey, m, expiry)` and `m & pred == pred`" is satisfiable by *any* `m` the prover chooses, as long as they can insert the corresponding `credComm` into the tree.

**Formal demand:** State the soundness game. Define what it means for a credential to be *validly issued*. If issuance requires an operator signature, the circuit must check it (e.g., EdDSA verification constraint inside the circuit). The current construction description gives a privacy reduction (to Poseidon preimage + Groth16 ZK) but no soundness reduction. These are orthogonal security properties.

**In-threat-model?** No — there is no soundness game stated, and without one, the predicate-satisfaction claim is vacuous. An adversary who controls their own `credComm` enrollment can prove arbitrary predicates.

---

### Attack 3: Subverted Groth16 Setup Breaks AS-Blindness Entirely

**Attack:** One of the core differentiators claimed against RFC 7662 is *AS-blind presentation* — the RS gets cryptographic assurance independent of AS cooperation. But Groth16 requires a per-circuit trusted setup (`pot16.ptau` → circuit-specific `.zkey`). If the AS participates in or unilaterally controls the ceremony (common in enterprise deployments where the AS is also the identity provider), the toxic waste `τ` enables full witness extraction from any presented proof. Concretely: given `(π, pk, vk, statement)` and knowledge of `τ`, the AS extracts `bitmask` from any proof in polynomial time. AS-blindness collapses to zero.

**Mitigation path (incomplete without explicit claim):** Either (a) use the PLONK proving system (both `.zkey` variants ship per CLAUDE.md) with a universal, publicly verifiable SRS (no per-circuit toxic waste), or (b) conduct a multi-party ceremony with the AS provably excluded and publish the transcript. Neither is specified as a requirement in the construction. The PLONK path is available in the repo but the construction does not state *which* proof system is used for this property claim, which means the AS-blindness guarantee is proof-system-contingent and currently unspecified.

**In-threat-model?** No — the adversarial-AS scenario is listed in the CANDIDATE's gap-to-close, but the construction gives no ceremony model, no trust assumption on the CRS, and no discussion of subverted setup. A single sentence claiming Groth16 ZK (A6) does not discharge this.

---

### Attack 4: The SI Game Is Valid but Proves Too Little — No Reduction to the Claimed Differentiator

**Attack (meta-level):** The revised single-credential SI game correctly fixes the prior two-credential flaw (nullifier distinguishing in O(1)). Privacy reduces to Poseidon preimage resistance on `credComm` plus Groth16 ZK — this is credible *for the game as stated*. But the game as stated proves only that an adversary cannot distinguish *which bitmask* was committed, given a single fresh credential. This is **not** the claimed differentiator. The CANDIDATE claims: "runtime-adaptive predicate over permissions (not fixed at issuance)" and "constant-size proof regardless of bitmask width." Neither property is captured by the SI game.

- *Runtime-adaptive predicate*: The SI game fixes the bitmask at enrollment time. Nothing in the game or the circuit description shows that the predicate is evaluated at proof time rather than issuance time. RFC 7662 + AS-side policy can also evaluate a fixed-at-issuance scope; the differentiator requires proving the predicate is *not* fixed at issuance or that the bitmask is hidden even from the issuer.
- *Constant-size proof*: True for Groth16/PLONK (proof size is O(1) in statement size), but RFC 7662 with structured JWTs is also O(1) in the claim count for a fixed schema. The differentiator requires a formal comparison under a model where bitmask width grows; none is given.

**Demand:** State a distinguishing advantage experiment that separates Bolyra from the RFC 7662 + RFC 8693 + DPoP stack. The SI game proves *something*, but it does not prove the *claimed* differentiator. Without a game that explicitly captures "AS-blind, runtime-adaptive, constant-size selective disclosure," the title claim remains marketing.

**In-threat-model?** Partially — the SI game is sound for its stated scope. But the mismatch between the game proved and the property claimed means the construction does not formally establish its core competitive differentiation.

---

**Summary table:**

| Attack | Property | Addressed? |
|---|---|---|
| A1: credComm linkability | Unlinkability (UNL) | No — no UNL game exists |
| A2: No operator sig in circuit | Soundness | No — no soundness game stated |
| A3: Subverted Groth16 setup | AS-blindness | No — proof system unspecified for this claim |
| A4: SI game scope mismatch | Formal differentiation | Partially — game is valid but proves wrong property |

---

Regarding the file write: I'm operating in a read-only context here as a persona. To approve the write to `differentiation-autoresearch/construction.md`, you'll need to confirm the tool permission prompt when it appears — I can't grant filesystem permissions from within this response. Once approved, I can help finalize the construction text incorporating the above critique.


## Persona: cu\_ciso

### Attack 1: Zero Regulatory Mapping — The Examiner Won't Care

- **Attack:** I hand my NCUA examiner the construction and ask: "Which Part 748 control does Groth16 ZK satisfy? Which GLBA Safeguards Rule section does Poseidon preimage resistance fulfill? Which FFIEC CAT control domain is 'adversarial-AS model'?" The construction claims differential privacy over bitmasks — but zero of the control language in the examiner's questionnaire references ZK proofs, nullifier hashes, or credential commitments. The construction maps to no named control.
- **Why it works:** NCUA Part 748 Appendix A requires a documented information security program with named access controls and third-party oversight. The examiner expects to see OAuth 2.0 / OIDC scope enforcement — something they've already seen 50 times — not a novel cryptographic primitive from a VC-backed startup. "AS-blind presentation" reads to an examiner as *bypassing* the authorization server, which flags as a control gap, not a feature. The construction must produce a one-page control mapping: C1 → Part 748 §III.C.1 (access controls), C1 → GLBA §314.4(c)(3) (access controls for customer information). Without it, the risk narrative fails at the board level before the crypto is even evaluated.
- **In-threat-model?** No — the construction is entirely silent on regulatory mapping. Must address.

---

### Attack 2: Opaque Audit Trail — The Incident You Cannot Explain

- **Attack:** An AI agent with `FINANCIAL_MEDIUM` permission (bit 3) initiates a $9,800 wire transfer. Fraud is suspected. My Tier 1 ops team pulls logs. What they see: a nullifier hash (`0x3f9a...`), a sessionNonce, and a Groth16 proof blob. The agent's full bitmask was *intentionally hidden* — that's the entire point of C1. My incident responders cannot determine from the proof artifact what permissions were actually exercised. My forensics team cannot reconstruct which capability was invoked at the moment of the transaction.
- **Why it works:** The construction's privacy property is a liability in post-incident forensics. NCUA Part 748 requires "monitoring systems and procedures to detect actual and attempted attacks" and an audit trail sufficient to reconstruct events for examiners. A ZK proof that hides the permission set satisfies the *agent's* privacy — not the *institution's* audit obligation. RFC 7662 introspection, by contrast, produces a logged, human-readable scope claim that the core processor team understands. The construction needs a separable audit mode: a blinded proof for the RS at runtime, plus an institution-side audit log (encrypted to the CU's key) that reveals the full bitmask post-hoc to authorized examiners. Until that exists, C1's core privacy claim is a GLBA Safeguards Rule violation waiting to happen.
- **In-threat-model?** No — the construction explicitly values AS-blindness and scope hiding but does not address the institution's audit logging obligation. Must address.

---

### Attack 3: Key Custody is Undefined — The `operatorPrivKey` Question

- **Attack:** The construction references `(modelHash, operatorKey, expiry, bitmask)` as the credential commitment inputs. I ask: where does `operatorPrivKey` live at agent runtime? If it's in a `.env` file on a Lambda function, I've lost you. If it's in a browser JS heap for a member-facing flow, I've lost you faster. GLBA Safeguards Rule §314.4(c)(3) requires "access controls" including "encryption of customer information," and §314.4(f) requires multi-factor for any system with member data. An EdDSA private key stored in software without HSM-backed key custody is not a control — it's a liability.
- **Why it works:** The construction is completely silent on key custody architecture. The "64-bit brute-force when the adversary knows all non-bitmask fields" limitation the author acknowledged means that `operatorPrivKey` compromise + known `modelHash`/`expiry` reduces bitmask recovery to a manageable search. For a $6B AUM credit union, that's an unacceptable residual. FFIEC CAT Intermediate baseline requires encryption key management with formal key lifecycle. The construction must specify: HSM requirement (CloudHSM / Thales), key rotation cadence, and what happens to issued credentials after key rotation (revocation path). Right now none of that exists.
- **In-threat-model?** No — the construction addresses proof-layer security (A3, A6) but not enrollment-layer key management. Must address.

---

### Attack 4: Vendor Risk — On-Chain Registry SLA is Not Core-Processor SLA

- **Attack:** My core processor (FiServ DNA) has a 99.99% uptime SLA with contractual remedies. The construction depends on an on-chain registry (Base Sepolia → mainnet implied). Public blockchain validators have no SLA, no contractual relationship with my credit union, and no remediation path when a sequencer goes down. I ask: what is the contractual uptime guarantee for proof verification, who do I call during the 2am outage, and does Bolyra appear on my Vendor Management Policy as an assessed third party with a current SOC 2 Type II report?
- **Why it works:** NCUA examiner third-party risk questionnaires require: (1) due diligence documentation, (2) contractual protections including SLAs and audit rights, (3) business continuity provisions, (4) exit strategy. A ZK verifier deployed to a public blockchain satisfies none of these. "AS-blind presentation" means the AS is not in the verification path — but it also means the CU has no intermediary with contractual accountability. RFC 7662 + a known OAuth AS vendor (Okta, Ping, ForgeRock) has an existing vendor management footprint that an examiner recognizes. The construction must address: offline verification fallback (cache the `vkey.json` and verify locally without chain access), contractual wrapper (Bolyra must offer a business associate agreement or equivalent), and a SOC 2 audit roadmap. Without those, my Vendor Management Policy requires me to reject the engagement.
- **In-threat-model?** No — the construction addresses cryptographic claims only. Operational availability and contractual risk transfer are entirely unaddressed. Must address.


## Persona: rfc7662_advocate

*Ten years shipping introspection endpoints. I've seen ZK claims that dissolved on contact with a well-configured AS. Let's check this one.*

---

### Attack 1: JWT Introspection Response Already Removes the AS from the Hot Path

- **Attack:** Section "AS-blind presentation (no AS roundtrip)" is the load-bearing claim. But `draft-ietf-oauth-jwt-introspection-response` (now RFC 9701) lets the AS issue a *signed JWT introspection response* at token-issuance time or at first-introspection time. The RS caches and verifies this JWT offline using the AS's public key — no runtime AS roundtrip is required. The agent presents `(access_token, cached_jwt_introspection_response)` to the RS; the RS verifies the signature locally. This is structurally identical to the ZK construction's "agent presents proof offline" story, except the proof is an AS-signed JWT instead of a Groth16 proof.

- **Why it works / why it fails:** It works against the naive framing of "no AS roundtrip = ZK unique." It *fails* against the selective disclosure property: the signed JWT response still lists the *full scope set* (or an AS-chosen filtered set). The agent has no runtime control over what is disclosed — the scope list was fixed when the AS signed the response. The ZK construction allows the agent to choose, at presentation time, which predicate to prove without revealing the residual bitmask to the RS. That runtime agent-side selection is not achievable with a signed JWT response because the JWT is a commitment to a fixed field set.

- **In-threat-model?** Partially. The construction survives the "no roundtrip" framing only if it defends *agent-side runtime selection*. The current candidate text mentions this but does not pin the formal property. The construction must state explicitly: *"The agent selects the disclosed predicate at P-time; the AS cannot enumerate which predicates the agent has exercised across RS interactions."* Without that statement, RFC 9701 is a valid rebuttal.

---

### Attack 2: Per-RS Introspection Policy + PPIDs Make the RS-Level Privacy Claim Collapse

- **Attack:** RFC 7662 §2.1 allows the AS to return *different introspection responses for the same token depending on the requesting RS*. Combined with OIDC Pairwise Pseudonymous Identifiers (PPID), each RS sees a distinct `sub` and a filtered scope set. Cross-RS linkability at the RS level is broken: RS-A sees `{sub: "pairwise-A", scope: "read"}`, RS-B sees `{sub: "pairwise-B", scope: "write"}`. Neither RS can link the two sessions to the same agent. RFC 8707 Resource Indicators bind the token to a specific RS audience, preventing cross-RS token replay. The claim that ZK uniquely provides unlinkability at the RS level therefore requires the AS to be in the adversary's coalition — otherwise per-RS policy + PPIDs already achieve it.

- **Why it works / why it fails:** It works as a rebuttal to *RS-level* unlinkability. It fails at the *AS-level*: the AS observes every introspection call and can build a complete map of `(agent, RS, scope_predicate, timestamp)` across all interactions. The ZK construction (correctly) targets the AS-as-correlator threat. But the candidate text in C1 does not clearly separate "RS-side unlinkability" (achievable with PPIDs + per-RS policy) from "AS-side unlinkability" (the genuine ZK advantage). If the construction's privacy claim is only RS-side, the baseline already matches it.

- **In-threat-model?** Yes — construction survives — **but only if it sharpens the claim.** The current gap description uses "cross-RS linkability" without specifying whether the AS is in the adversary's coalition. The construction must commit: *"We claim unlinkability against an AS that logs all introspection traffic"*, which RFC 7662 cannot provide regardless of PPID configuration.

---

### Attack 3: RFC 8693 Token Exchange Is Runtime Scope Narrowing Without ZK

- **Attack:** The gap text lists "runtime-adaptive predicate over permissions (not fixed at issuance)" as a candidate distinguisher. RFC 8693 OAuth 2.0 Token Exchange lets the agent exchange its full-permission master token for a narrowly-scoped task token immediately before calling an RS. The RS only ever sees the minimal-scope token. Combined with DPoP (RFC 9449), the exchanged token is sender-constrained to the agent's current ephemeral key. The agent effectively selects its disclosed scope at runtime by choosing what to request in the exchange. Cost: one AS roundtrip per task.

- **Why it works / why it fails:** It works as a practical alternative for the "not fixed at issuance" property: scope narrowing happens at exchange time, not issuance time. It fails on two axes: (1) **The AS learns the usage pattern.** Every exchange request reveals `(agent_identity, target_scope_set, intended_audience)` to the AS. Over many exchanges the AS builds a complete behavioral profile. The ZK construction's agent presents proofs directly to RSes with no AS involvement. (2) **Constant-size proof claim.** As the permission space grows to 64 bits, the number of distinct predicates the agent might prove grows exponentially. RFC 8693 requires a separate token per distinct scope subset; the ZK construction produces a constant-size Groth16 proof regardless of bitmask width. The construction should cite both axes explicitly rather than treating them as separate "candidate" properties.

- **In-threat-model?** Yes — construction survives — **but it must stop treating AS-blindness and constant-size proof as optional "candidates."** RFC 8693 closes the runtime-selection gap for non-adversarial-AS deployments. The construction's discriminating property against RFC 8693 is specifically the zero-AS-roundtrip, zero-AS-observability guarantee.

---

### Attack 4: The Adversarial-AS Claim Requires Bootstrapped Trust That Reintroduces an Equivalent Assumption

- **Attack:** The construction's strongest unique claim is resistance to a *lying AS*: "RS needs cryptographic assurance independent of AS cooperation." But ask: who placed the credential commitment (`credComm`) into the on-chain Merkle tree and who controls the registry contract's `updateRoot` function? If the answer is "the Bolyra operator" or "a committee of issuers," we have not eliminated a trusted party — we have *renamed* it. A malicious entity with `updateRoot` access can insert a fraudulent `credComm` with an inflated bitmask, and the ZK proof will be valid because the circuit only checks Merkle membership and bitmask constraints, not the legitimacy of the enrollment. The adversarial-AS threat model is only meaningful if the on-chain registry root is managed by a *different trust domain* than the AS being distrusted. The candidate text does not establish this separation.

- **Why it works / why it fails:** This attack reframes the adversarial-AS claim as a trust-substitution rather than trust-elimination. It is partially blocked by the fact that the Bolyra registry is on-chain and therefore publicly auditable (unlike an AS's internal database), but auditability is not the same as correctness under an adversarial operator. The attack fully lands if the construction's deployment model allows a single operator to control both credential issuance and the Merkle root — in that case, the "even a malicious AS cannot lie about scope membership" claim is false: the operator simply lies at enrollment time instead.

- **In-threat-model?** **Yes — construction must address this.** The current candidate text cites "adversarial-AS model" as a scenario but does not specify the trust boundary between the AS (presumably distrusted) and the Merkle root authority (presumably trusted). Without that boundary, the construction has not proven a stronger security property than RFC 7662 — it has moved the trust assumption from the AS to the registry operator. Add a section: *"The Bolyra trust model treats the on-chain Merkle root as a separate trust domain from the issuing AS. The AS cannot unilaterally alter `credComm` without a registry transaction that is publicly visible and attributable."* Only then does the adversarial-AS advantage hold.


The write needs your approval (it'll prompt you). Here is the adversarial critique in the meantime:

---

## Persona: spiffe_engineer

### Attack 1: WIMSE SD-JWT Dissolves "AS-Blind Selective Disclosure"

- **Attack:** The construction's central differentiator is "AS-blind presentation — no AS roundtrip, agent chooses what to disclose at the moment of use." WIMSE `draft-ietf-wimse-s2s-protocol` + SD-JWT (`draft-ietf-oauth-sd-jwt-vc`) already delivers this. The SPIRE server issues an SD-JWT SVID at startup with each permission bit as a separate `_sd` disclosure. At presentation time the agent selectively discloses only the relevant hashes — no AS is contacted, no roundtrip occurs, the RS verifies offline. The agent chose what to reveal at the moment of use. Per the construction's own framing (gap-to-close: "AS-blind presentation"), this property is met by the existing standard stack.

- **Why it works / why it fails:** It works because SD-JWT is genuinely AS-blind at verification time. It partially fails because SD-JWT is a *selective-reveal* scheme, not a *predicate-proof* scheme. The RS in SD-JWT sees the *exact bits* the agent chose to disclose. The Bolyra construction lets the agent prove "bit 2 AND bit 5 are set" without the RS learning *which* bits those were or *what else* is set — a strictly stronger hiding property. But the construction does not articulate this distinction anywhere in the claim text. It says "agent chooses what to disclose," which SD-JWT satisfies.

- **In-threat-model?** No — construction must address. The claim must be sharpened from "selective disclosure" to "predicate proof with full-bitmask hiding." Those are not the same thing and the current text conflates them, leaving this attack unaddressed.

---

### Attack 2: SPIFFE Federation Already Gives You "Portable Identity"

- **Attack:** The candidate's scenario list includes "AS is semi-trusted and RS needs cryptographic assurance independent of AS cooperation." SPIFFE federation (`draft-ietf-spiffe-federation`) handles this without ZK. Trust domain A's bundle endpoint publishes its SVID signing keys; RS in trust domain B fetches the bundle and verifies SVIDs cross-domain with zero AS involvement at verification time. The SPIFFE ID `spiffe://bolyra-trust-domain/agent/model-hash` is cryptographically portable across domains. No AS cooperation is required after bundle exchange. This is the standard production path for Fortune 500 multi-cloud deployments today.

- **Why it works / why it fails:** Federation solves portability at the transport/attestation layer via PKI. It fails on the *privacy* axis — the SPIFFE ID and all its claims are plaintext to every RS that verifies it. Cross-RS correlation is trivial: the stable `spiffe://trust-domain/path` is a persistent identifier visible to all verifiers. The Bolyra construction uses nullifiers to provide cross-RS unlinkability. But again, the construction's *claim text* says "portable identity" and "AS-independent verification," not "unlinkable portable identity." SPIFFE federation satisfies the written claim.

- **In-threat-model?** No — construction must address. The claim must explicitly name unlinkability as the property SPIFFE federation cannot provide. Without naming it, the "portable identity" sub-claim is demolished by citing `draft-ietf-spiffe-federation` §4.

---

### Attack 3: The 64-Bit Brute-Force Regime Is Structurally Worse Than SVID Attestation

- **Attack:** The construction transparently documents that privacy degrades to a 64-bit exhaustive search when the adversary knows `(modelHash, operatorKey, expiry)`. In SPIFFE/SPIRE these fields are not secret — the SPIFFE ID is public by design, the X.509 SVID `Subject` is plaintext, and the notAfter field is visible. An adversary with network access to a single TLS handshake can read all non-bitmask fields directly from the certificate. That means any adversary with one intercepted SVID can brute-force the bitmask in under a second on commodity hardware (2^64 Poseidon evaluations ≈ hours, but with GPU acceleration and a 32-bit common bitmask space it's milliseconds). SPIFFE avoids this entirely: the permissions are SVID extension fields, signed by the SPIRE server's key. An adversary cannot enumerate possible permissions without forging an SVID — that requires breaking ECDSA P-256 or RSA-2048, not a birthday search over a 64-bit space.

- **Why it works / why it fails:** This is a genuine structural weakness. The construction calls it an "enrollment-layer limitation intrinsic to the Bolyra spec's credential commitment structure, not a proof-layer failure." That framing deflects but does not answer: if the proof layer composes with an enrollment structure that leaks under known-plaintext pressure, the system's privacy guarantee is conditional on adversary ignorance of public fields. In a SPIFFE production environment, `modelHash` is the container image digest (public in the registry), `operatorKey` is registered in the trust domain (public), and `expiry` is a well-known rotation schedule. All three are observable. The 64-bit privacy claim evaporates in practice.

- **In-threat-model?** Yes — but the construction must not deflect it as "enrollment-layer." It must either (a) require `(modelHash, operatorKey, expiry)` to be kept secret and formalize what that means for threat model scope, or (b) replace the commitment scheme so bitmask privacy holds even under full non-bitmask field exposure (e.g., add a blinding salt to the credential commitment).

---

### Attack 4: "Constant-Size Proof Regardless of Bitmask Width" Is Already Solved by BBS+, Not ZK Circuits

- **Attack:** One of the candidate's gap-to-close entries is "constant-size proof regardless of bitmask width." The IETF BBS Working Group (`draft-irtf-cfrg-bbs-signatures`) already provides constant-size selective disclosure proofs over multi-message credentials. A BBS+ credential with one message per permission bit produces a constant-size proof (a single G1 element ≈ 48 bytes on BLS12-381) that proves membership of any subset of bits without revealing the rest. BBS+ is further ahead on standardization than Groth16 in IETF contexts, has an active CFRG WG, and has working Go/Rust/TypeScript implementations today. Why is the construction using Groth16 circuits and a Circom-specific trusted setup when BBS+ achieves the same constant-size property with a single pairing check, no circuit compiler, and a transparent setup?

- **Why it works / why it fails:** It fails on one axis: BBS+ proofs are selective-reveal (same limitation as Attack 1 — the verifier learns *which* messages were included in the proof). Groth16 can express arbitrary predicates, including "bit 2 AND bit 5 are set" without revealing bit 2 or bit 5 as values. But for the specific use case written in the claim — "proves it satisfies a required permission predicate" — if the RS specifies the predicate (e.g., "must have FINANCIAL_SMALL"), the agent simply reveals the FINANCIAL_SMALL bit under BBS+ and the RS confirms. The predicate is satisfied with constant-size proof and no circuit. Only for *private* predicates (where even the predicate is hidden from the RS) does Groth16 win. The construction does not claim private predicates.

- **In-threat-model?** No — construction must address. If the predicate is public (RS says "prove you have bit X"), BBS+ is strictly simpler, faster, and more standardized. The construction must either (a) claim private predicates explicitly, or (b) explain why it chose Groth16 over BBS+ for the public-predicate case it actually describes.
