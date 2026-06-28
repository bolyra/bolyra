# Tier 3 Adversarial — C1 Selective scope proof

## Persona: auth0_pm

---

### Attack 1: The RS Reads From a Blockchain — That's an Enterprise Integration Blocker

**Attack:** The construction's entire adversarial-AS model (Section 4, Axis 1 and Axis 3) rests on the RS reading `agentMerkleRoot` from an on-chain registry. In Section 2, step 1 of the verification protocol reads: "RS generates fresh `sessionNonce`, reads current `agentMerkleRoot` from on-chain registry." In Section 5 the Bolyra primitive for this is "Agent root history buffer (30-entry circular)."

This means every enterprise RS — every API gateway, every fintech integration, every Navy Federal resource server — must:
- Maintain an RPC connection to Base Sepolia (or mainnet)
- Parse on-chain events to track the 30-entry root history buffer
- Handle RPC downtime, reorgs, and stale roots
- Integrate all of this into existing API gateway infrastructure (Kong, Apigee, AWS API Gateway)

WorkOS MCP auth, Auth0 MCP auth, and Stytch Connected Apps require none of this. The enterprise gets `verify_token()` — an SDK call against a JWKS endpoint. Their existing API gateway has native JWT verification. Cloudflare Access proxies MCP endpoints with zero client changes.

**Why it works / why it fails against the construction:** The construction deliberately removes the AS from the trust path — that's the cryptographic contribution. But it transfers the trust to the on-chain registry, which has its own availability, latency, and integration dependencies. The construction does not address: what happens when the Base Sepolia RPC is unavailable? What's the RS's fallback? The adversarial-AS argument (Section 4, Axis 3) is only valuable if the buyer considers AS compromise a credible threat. Most enterprise security teams don't — they hold AS vendors accountable via contracts, SLAs, and cyber insurance. The on-chain dependency adds integration cost to solve a threat that doesn't appear in a typical enterprise risk register.

**In-threat-model?** No — the construction must address the RS-side integration burden and the availability/latency of the on-chain root read. The cryptographic argument holds; the deployment assumption does not.

---

### Attack 2: 500ms Agent-Side Proving Latency vs. <10ms JWT — Enterprise API SLAs Kill This

**Attack:** Section 6 states "PLONK (rapidsnark, server): < 500ms." The construction presents this as the fast path. The browser path is "< 5s." The persona runs a product where Auth0, WorkOS, and Stytch issue tokens — including introspection responses — in under 10ms, and issue JWTs without any roundtrip in microseconds (local verification).

The construction requires the agent to run rapidsnark — a C/C++ native binary — to hit the 500ms target. That means:
- Every agent deployment must ship and manage a native binary for its platform (Linux x86-64, ARM64, etc.)
- The agent absorbs 500ms on every API call, not just session establishment
- The RS waits for the proof before it can respond; there is no "here's a cached token" fast path

A budgeting app's AI agent calling NFCU's transaction API (Section 7) makes dozens of read calls per second during a user session. At 500ms per proof, that's 2 req/s max throughput per agent. With JWT-based auth, the same agent makes thousands of req/s with sub-millisecond auth overhead.

The construction's own answer in Section 6 mentions `sessionNonce` replay detection — but the construction doesn't describe proof caching. If a proof can be reused within a session window, the 500ms cost is amortized. But proof reuse trades off against the freshness guarantee that justifies the construction's existence (adversarial-AS can't observe and replay). The construction doesn't resolve this tension.

**Why it works / why it fails against the construction:** The construction's cryptographic claim is valid — constant-size proof independent of bitmask width is real. But the latency argument is GTM-fatal. No buyer sees "500ms per API call" and "500ms overhead on agent operations" as acceptable when the alternative is `Bearer {jwt}` with local verification. The construction must show either: (a) proofs are generated once per session and cached with a session-binding argument, or (b) the latency target drops below 50ms via hardware acceleration — and explain the infrastructure cost.

**In-threat-model?** No — the construction must address proof caching semantics and the practical latency budget relative to the API patterns it targets.

---

### Attack 3: "Zero-Knowledge Predicate Evaluation" Is Not a Procurement Criterion

**Attack:** Section 8 leads with "Zero-knowledge predicate evaluation (not selective disclosure)" as Property 1, and the iter_006 refinement specifically made this the centerpiece differentiator over SD-JWT. The construction's SD-JWT failure modes (Section 7 "Why SD-JWT cannot match"): claim values are disclosed, claim count leaks structure, no implication closure at presentation time.

These are real cryptographic differences. They are not procurement criteria.

When a credit union's CISO evaluates auth vendors, the questions are:
- "Do you have SOC 2 Type II?" Auth0: yes. WorkOS: yes. Stytch: yes. Bolyra: no (solo founder).
- "Who do we call when it breaks at 2am?" Auth0 has 24/7 enterprise support. Bolyra has one person.
- "What does NCUA say?" NCUA Part 748 requires documented controls. It does not require zero-knowledge proofs. A signed JWT with a JWKS endpoint satisfies documented cryptographic controls.
- "Can our existing IAM team maintain this?" They know OAuth. They don't know circom or BN254.

The construction argues SD-JWT leaks claim count (iter_006, Section 7c). NFCU's CISO does not care that a claim count leaks to their own RS. They care about external breach. The construction's privacy game (Section 3) models cross-RS unlinkability — leaking unrequired bits to the RS. For most buyers, the RS is their own infrastructure. They're not protecting against themselves.

The specific NFCU scenario (Section 7) invokes NCUA Part 748 compliance. NCUA Part 748 governs information security programs — it's satisfied by access controls, audit logging, and documented risk assessments, not ZK proofs. There is no NCUA guidance that requires or benefits from AS-blind presentation.

**Why it works / why it fails against the construction:** The construction is technically sound but argues in a register that doesn't reach the buyer. The gap between "cryptographically superior" and "procurement-winning" is not addressed anywhere in Sections 1–8. The construction must translate each cryptographic property into a concrete business outcome that appears in a credit union's risk register, examiner checklist, or insurance questionnaire.

**In-threat-model?** No — the construction must add a "so what for the buyer" translation layer. Every cryptographic claim needs a paired business-risk sentence: not "AS cannot inflate permissions" but "this eliminates the class of breach where your auth vendor's compromise expands agent access."

---

### Attack 4: Auth0 + Draft Client Attestation (`draft-ietf-oauth-attestation-based-client-auth`) Is "Close Enough" — And Shipping Today

**Attack:** The construction's Section 1 specifically enumerates the baseline: "RFC 7662, jwt-introspection-response, RFC 8693, RFC 8707, DPoP, or BBS+." It does NOT enumerate `draft-ietf-oauth-attestation-based-client-auth` (Client Attestation), which Auth0 has already begun implementing.

Client Attestation lets a client prove its software identity (model hash, operator key, capability set) via a short-lived attestation JWT signed by an attester — without a roundtrip to the AS at every request. The attester can be the operator (equivalent to Bolyra's operator EdDSA key), and the RS can verify offline. The capability set is bound to the client at attestation time.

For the specific construction claim "no AS roundtrip at presentation time" (Section 2, step 4: "No AS is contacted. No token is exchanged."): Client Attestation + DPoP achieves the same property. The RS verifies the attestation JWT locally against the attester's public key (no AS roundtrip), and DPoP binds it to the agent's private key. The attester's public key is distributed out-of-band — analogous to the on-chain registry, except it's a standard JWKS endpoint.

For the "adversarial AS" claim: Client Attestation also degrades the AS's power — the AS issues an access token, but the client's capability set is attested by the operator (a separate key). A compromised AS cannot inflate capabilities if capabilities are in the attestation, not the AS token.

Yes, Client Attestation does not enforce implication closure in a circuit. But the operator enforces it at attestation issuance time. The construction's argument (Section 8, Axis 2) that "a compromised AS can issue invalid bitmask states" requires AS compromise — which Client Attestation's operator-attester separation also mitigates, without ZK circuits, without on-chain infrastructure, and using a standard that Auth0 will natively support.

The buyer's procurement team sees: "Auth0 supports this via a draft RFC that's becoming a standard. Bolyra requires on-chain infrastructure, a new circuit primitive, and a solo-founder vendor."

**Why it works / why it fails against the construction:** Client Attestation does not achieve the full construction — it cannot evaluate a bitwise predicate over a hidden bitmask (Axis 2), and it leaks the full capability set to the RS (no zero-knowledge property). But the buyer's actual workload — discrete permission claims, no 2^64 permission space, AS controlled by the same operator — means the "gap" the construction closes is theoretical for most deployments. The construction must identify a specific buyer persona for whom the AS-adversarial model and large bitmask space are both real operational requirements, not just academic.

**In-threat-model?** No — the construction must explicitly address Client Attestation (`draft-ietf-oauth-attestation-based-client-auth`) as a baseline competitor and identify the concrete scenario where its ZK properties close a gap that attestation-based client auth cannot close.


## Persona: cryptographer

---

### Attack 1: Adaptive Predicate Oracle Reconstructs Full Bitmask

**Attack:** The 8-bit cumulative permission encoding has a finite, publicly known structure. A polynomially bounded RS (or a coalition of RSes) issues a sequence of 8 challenge predicates: `pred_i(perm_set) := (bit_i == 1)` for `i ∈ {0..7}`. The agent, acting honestly, generates a ZK proof for each. After 8 proofs, the RS holds the complete bitmask — learning strictly more than the single boolean outcome the construction advertises.

**Why it works / why it fails:** The construction's Section 3 privacy game is defined per-presentation. It does not bound the *number* of predicate queries the RS may issue against a *single* credential. In the standard IND game the adversary gets an oracle; here the oracle is the honest agent replying to RS-chosen challenges. Constant-size proofs and ZK per evaluation are both preserved — but the *composition* across queries is not analyzed. Without a formal bound on the RS's query complexity relative to the credential's entropy (8 bits → 8 queries suffice), the "RS learns only `pred(perm_set)=1`" claim holds per-proof but fails for the multi-proof transcript.

**In-threat-model?** **No.** The construction must either (a) add a query budget enforced by a nullifier-per-predicate or rate-limit gadget, (b) require predicate commitments that bind RS to a single query at credential issuance, or (c) restrict the privacy guarantee to the single-query setting and say so explicitly in the threat model.

---

### Attack 2: Subverted Groth16 Setup Breaks the Adversarial-AS Claim

**Attack:** Groth16 requires a per-circuit trusted setup ("powers of tau + circuit-specific phase 2"). The `AgentPolicy` and `Delegation` circuits each have project-specific `.zkey` files (CLAUDE.md, Circuits table). If the party controlling phase 2 retains the toxic waste `τ`, they can compute a false witness for any statement and produce an accepting proof. Concretely: an adversarial AS who also controls (or bribes) the setup ceremony can mint a credential with `perm_set = 0b00000001` (READ_DATA only) and then generate a valid `AgentPolicy` proof asserting `FINANCIAL_UNLIMITED` without the agent's private input.

**Why it works / why it fails:** The construction's Section 8, Property 6 asserts simulation-extractable ZK under PLONK — but `AgentPolicy` is built with Groth16 (CLAUDE.md, Circuits table). Groth16 is not simulation-extractable; it is only knowledge-sound in the generic group model *assuming* an honest setup. Under a subverted setup, knowledge soundness fails: the toxic waste holder can extract the simulation trapdoor and forge proofs. PLONK variants (`AgentPolicy` dual-build) are transparent-setup-capable, but the construction ships both `.zkey` files and does not specify which is the production path. If Groth16 is used in production, the "adversarial-AS model where AS cannot lie about scope membership" claim is vacuous: a colluding AS + setup authority can lie with a valid proof.

**In-threat-model?** **No.** The construction must either (a) commit to PLONK with a universal SRS (already available as `pot16.ptau`) and deprecate Groth16 for `AgentPolicy` / `Delegation`, or (b) formally scope the adversarial-AS guarantee to exclude setup-colluding adversaries and document that gap in the threat model.

---

### Attack 3: Merkle Root Trust — "AS-Blind" Presentation Requires AS-Trusted Root

**Attack:** The AS-blind claim (no AS roundtrip; agent chooses disclosure at use time) requires the RS to verify against a credential Merkle root without contacting the AS. But the Merkle root *is* published and controlled by the AS (credential registry). A malicious AS can:

1. Insert a shadow entry for an agent with inflated permissions, prove Merkle membership for that entry, and present to an RS that trusts the published root.
2. Fork the Merkle tree — serving an honest root to auditors and an adversarial root to colluding RSes.
3. Silently revoke the honest root post-presentation (no revocation mechanism is specified), leaving RS with an unverifiable stale proof.

**Why it works / why it fails:** The construction frames the adversarial-AS model as "AS cannot lie about scope membership" (Section 8, Property 1), but the proof of Merkle membership is only as sound as the root's integrity. The threat model must answer: who signs the root, with what binding, and what is the equivocation resistance? Without a commitment scheme (e.g., log-backed append-only tree, smart-contract anchoring, or at minimum a root signature from a key the RS independently trusts), the AS-blind presentation reduces to AS-trusted-root presentation — no stronger than RFC 7662 with cached introspection responses.

**In-threat-model?** **No.** The construction must formally define the Merkle root as an *extractable commitment* under a concrete hardness assumption, specify the update / revocation protocol, and prove that the AS cannot equivocate on root values presented to different RSes. The on-chain registry (Solidity verifiers, CLAUDE.md) could serve this role, but no binding between the circuit's `humanMerkleRoot` / credential commitment and a specific on-chain state is formally stated.

---

### Attack 4: HVZK-to-Malicious-Verifier Lift Is Unstated

**Attack:** Groth16 and standard PLONK provide *honest-verifier* zero knowledge (HVZK): the simulator works when the verifier commits to its challenges before seeing the proof. A malicious RS can choose its "challenge" (i.e., the predicate it asks the agent to prove) *after* observing partial state — session nonces, prior nullifiers, or timing signals. In the multi-round or concurrent setting, HVZK does not compose to full ZK. Concretely: an RS that rejects proofs with a crafted error message can run a verifier-chosen challenge attack to extract partial information about `perm_set` that a simulator could not reproduce without the witness.

**Why it works / why it fails:** Section 8, Property 6 cites PLONK's simulation-extractable NIZK variant as the defense. SE-NIZKs in the random oracle model *do* achieve malicious-verifier ZK — but only if the construction correctly implements the Fiat-Shamir transform over the *full* statement, including the predicate and the credential commitment. If the Fiat-Shamir hash does not commit to the RS-chosen predicate, the RS can perform a selective-failure attack: present a sequence of false predicates, observe which proofs the agent generates (and which it refuses), and extract bit-level information. The construction does not provide a simulator description or a Fiat-Shamir binding argument. Without one, the ZK claim against a malicious RS is hand-waving per the construction's own language.

**In-threat-model?** **No.** The construction must exhibit a concrete simulator `Sim(vk, pred, 1)` that produces transcripts indistinguishable from real proofs without the witness, and prove this holds under the chosen Fiat-Shamir instantiation. If PLONK SE-ZK is the claimed primitive, cite the specific variant (e.g., Maller et al. 2019 or Bünz et al. 2020) and verify that the Bolyra predicate circuit falls within its scope conditions.


Now I have the full construction. Let me produce the adversarial critique from the CU CISO persona.

---

## Persona: cu_ciso

*Context: I'm looking at your iter_006 refinement on top of the iter_005 construction. I've read Sections 2, 3, 4, 7, and 8. I've seen the PLONK circuit, the 8-bit (now 64-bit) bitmask, the on-chain Merkle tree, and your Section 7.5 NCUA examination claim. Now let me tell you why my board isn't buying this.*

---

### Attack 1: The Audit Trail Is Cryptographically Opaque to My Examiners

- **Attack:** Your Section 7.5 says: *"The examiner can verify that every agent access was backed by a valid PLONK proof anchored to an on-chain root, providing a cryptographic audit trail without exposing member-agent permission details."* That last clause is the problem. NCUA Part 748 Appendix B requires my security program to include procedures for "detecting, responding to, and recovering from failures of safeguards controls." If Agent-X transfers $90K it wasn't authorized to move, I need to reconstruct — in plain English, for my board and for the examiner — *exactly what permissions that agent presented* at each resource server call. Your construction hides the bitmask from the RS by design (Property 1). The RS stores a PLONK proof, a nullifier hash, and a scope commitment. None of these are human-readable. None can be decoded by my Level-1 ops team at 2am, my forensics vendor, or my NCUA examiner without a ZK cryptographer on staff. The GLBA Safeguards Rule (16 CFR Part 314.4(c)(3)) requires me to detect and respond to security events affecting customer financial information. My audit log says "proof verified: yes/no." That is not a security event log — that is a boolean.

- **Why it works / fails:** The construction does not address how a post-incident investigator reconstructs the *effective permission set* exercised by an agent in a disputed transaction. The scopeCommitment and nullifierHash are one-way functions over the hidden bitmask. The construction explicitly argues the bitmask is unextractable (Section 4, PermExtract reduction). That security property *is* the audit problem. You cannot simultaneously claim the bitmask is cryptographically hidden from adversaries and also claim it provides a forensically useful audit trail for examiners.

- **In-threat-model?** **No — construction must address.** Either provide a supervisor-key escrow mechanism (operator can decrypt audit records under a separately-controlled audit key) with documented custody, or explicitly restrict deployment to scenarios where a boolean per-session accept/reject satisfies regulatory audit requirements. The SECU scenario in Section 7 involves loan originations and transfers — these are Category A events under NCUA exam. A boolean proof-valid log is insufficient.

---

### Attack 2: Operator BabyJubjub Key Custody Has No Regulatory Anchor

- **Attack:** Section 2, Enrollment Protocol step 1: *"Operator generates BabyJubjub keypair (sk, pk)."* Name the NCUA Part, GLBA section, or FFIEC control that governs where `sk` lives. You cannot, because the construction says nothing about it. I know what happens in practice: `sk` ends up in an `.env` file in a Kubernetes secret, or in a developer's laptop, or in a CI pipeline. The EdDSA signature over the credential commitment (Gadget G3) is your only binding between the permission bitmask and the on-chain registry. If `sk` is compromised, an attacker can enroll arbitrary agents with arbitrary permission bitmasks and get valid Merkle insertions. GLBA Safeguards Rule 314.4(f) requires "appropriate standards for the disposal of customer information and for the development, maintenance, and testing" of safeguards — including cryptographic key management. FFIEC IT Examination Handbook (Information Security, September 2016), Section II.C.17 requires HSM or equivalent for keys protecting customer authentication data. The construction treats key generation as a one-liner footnote. For a $2B CU, the operator key *is* the root of trust for every agent permission in the system.

- **Why it works:** The construction's security reduction (Section 4) reduces ScopeForge to "breaking A5: EdDSA unforgeability." A5 holds only if `sk` is secret. The construction assumes `sk` is held by an honest operator and provides zero specification for what "holding" means operationally. This isn't a cryptographic gap — it's an operational one that cryptographic reductions cannot close. My Vendor Management Policy requires that every authentication credential root-of-trust be in a FIPS 140-2 Level 3 (or higher) HSM with documented key ceremonies. The construction provides no path to that requirement.

- **In-threat-model?** **No — construction must address.** The construction must specify: HSM requirements for operator key storage, key rotation procedure and what happens to existing enrolled credentials after rotation, compromise response (revoke all issued credentials? Requires a new Merkle root), and at minimum a reference to FFIEC-compliant key management standards. Without this, the construction cannot be put in front of an NCUA examiner as a secure system.

---

### Attack 3: On-Chain Registry SLA Is Incompatible with FFIEC CAT Availability Requirements

- **Attack:** Property 3 (Section 8) and Section 7.4 make the RS verify `agentMerkleRoot` against the *on-chain root history buffer*. That buffer lives on Base (an L2 blockchain). My FFIEC CAT Maturity assessment under the "Cyber Risk Management and Oversight" domain requires documented SLAs for every critical dependency — and my core processor contract with Symitar gives me 99.95% uptime, a published RTO/RPO, and contractual penalties for breach. What is the SLA for Base mainnet? What is the contractual RTO if a sequencer outage lasts 4 hours? What is my examiner-defensible recovery procedure when agents cannot authenticate because the on-chain root is unavailable? Your Section 8, Property 2 argues that AS-blind presentation is an *advantage* — the agent needs no AS roundtrip. True. But the RS *still* needs a blockchain roundtrip (or a cached root). You've shifted the availability dependency from a CU-controlled AS to a public blockchain sequencer. That is a risk *increase* for operational resilience, not a decrease. The Section 7 "30-entry root history buffer" helps with transient latency but does nothing for a multi-hour sequencer outage or a L2 reorg above the buffer depth.

- **Why it works:** The construction's threat model (Section 3) explicitly excludes blockchain integrity as an adversary capability ("blockchain integrity assumption"). This is cryptographically appropriate. Operationally, it means the construction *assumes availability* rather than *providing it*. For a regulated CU, availability is not assumed — it is contracted, tested, and examined. There is no vendor contract for Base mainnet availability, no SOC 2 Type II for the sequencer operator, and no NCUA-recognized audit framework for L2 blockchain infrastructure.

- **In-threat-model?** **No — construction must address.** The construction must either (a) provide a fallback verification path when the on-chain registry is unavailable — e.g., a CU-operated sidecar that caches signed root snapshots with contractual SLA guarantees, or (b) explicitly scope the construction to non-critical-path operations where availability SLAs below 99.9% are acceptable, which contradicts the SECU loan origination scenario in Section 7.

---

### Attack 4: scopeCommitment Is a Persistent Cross-RS Fingerprint (Section 3, Section 7.3)

- **Attack:** Section 3, CrossLink game, step 6: *"scopeCommitment is identical across sessions for the same agent — this is true for BOTH agents from the adversary's view."* Section 7.3 claims *"the fraud service cannot link this request to the loan origination request."* These two statements are in direct contradiction. `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` is a deterministic function of the credential — it does not change across sessions. If SECU's loan origination server and fraud detection service both log the scopeCommitment from each proof (which they will, because it is a public output), those logs can be joined on scopeCommitment to correlate every session of Agent-X across every RS in the institution. The nullifier changes, which prevents double-spending. The scopeCommitment does not change, which enables cross-RS agent tracking. The construction's unlinkability claim in Section 7.3 is false for any RS that shares log infrastructure — which, in a $2B CU, is every internal resource server sharing a SIEM. From a member-privacy standpoint under state financial privacy laws (e.g., California CCPA, New York SHIELD Act), if the agent acts on behalf of a member, the correlation of all member-agent actions across services via a persistent identifier is a data linkage problem regardless of whether the bitmask itself is hidden.

- **Why it works:** The construction correctly identifies that the nullifier is session-unique. It does not acknowledge that the scopeCommitment is a permanent, unblinded agent pseudonym across all sessions. The CrossLink game in Section 3 tests whether the *bitmask* can be extracted, not whether the *agent identity* can be tracked. Tracking without extraction is a distinct privacy attack. The iter_005 summary mentions adding a randomized scopeCommitment (`Poseidon3(bitmask, credComm, sessionNonce)`) for per-session unlinkability — but the iter_006 construction.md being approved does not appear to carry this into Sections 2, 3, or 8. If it does, the construction must explicitly update G9, the public output table, and the CrossLink claim to reflect it. If it does not, the cross-RS unlinkability claim must be removed from Section 7.3.

- **In-threat-model?** **Yes, if the randomized scopeCommitment from iter_005 is correctly incorporated — the construction survives. No, if Section 7.3's unlinkability claim is asserted while G9 still outputs a deterministic `Poseidon2(permissionBitmask, credentialCommitment)`.** The construction must reconcile G9 with the unlinkability claim explicitly, or the examiner's cross-system audit will reveal agent fingerprinting that the construction claims does not exist.


Now I have the full picture. Let me produce the adversarial critique.

---

## Persona: rfc7662_advocate

*OAuth Working Group veteran. I have shipped introspection endpoints into production credit union cores, and I have watched ZK advocates confuse "novel machinery" with "novel properties." The refined construction demoted AS-blind presentation and elevated "ZK predicate evaluation where RS learns only `pred(perm_set)=1`" as the lead differentiator. That is a mistake. Let me show you why.*

---

### Attack 1: Boolean-Return Introspection Policy Achieves the Exact Lead Property

**Attack:** The refined Section 8 Property 1 states: "RS learns only `pred(perm_set)=1`, not any individual bit or structural hint." A well-configured AS implementing per-RS introspection policy achieves this verbatim under RFC 7662 today. The AS endpoint checks `(agent_scope & RS_required_mask) == RS_required_mask` server-side. If the predicate is satisfied, it returns `{"active": true}` — no `scope` field, no `sub`, no structural payload. If not, it returns `{"active": false}`. The RS receives exactly one bit of information: the predicate result. Claim count: zero. Hamming weight: zero. Claim values: zero. The construction's lead differentiator is achievable by a minimal RFC 7662 response body with six bytes of JSON.

The jwt-introspection-response draft compounds this: the AS can issue a signed JWT at token-issuance time with payload `{"active": true, "aud": "<RS_id>"}` — no scope claim, no structural data. The RS verifies offline. Zero AS roundtrip at presentation time. The agent presents an opaque bearer token; the RS verifies the pre-issued signed boolean.

The construction's genuine advantage — which the refinement *demoted* — is that the AS cannot observe which RS the agent is visiting at presentation time. That is AS-blindness, and it is still Property 2 in the revised document. By swapping the order, the construction now leads with a property RFC 7662 already provides and buries its actual differentiator.

**Why it works / why it fails:** It works as a framing attack because the construction's refined Property 1 is descriptively accurate but not uniquely achieved by ZK. It would fail only if the construction can show that the RFC 7662 boolean-return case *still* leaks structure that the ZK proof does not — e.g., the signed JWT's `aud` field reveals which RS the AS knew about at issuance, whereas the ZK construction's per-session proof is not indexed by RS at all. That argument exists, but it belongs under AS-blindness (Property 2), not under the "predicate evaluation" claim.

**In-threat-model?** No — the construction must address this. Either restore AS-blind presentation as Property 1 (it was the correct lead before the refinement), or add a "Critical distinction" paragraph under Property 1 that rules out the boolean-return RFC 7662 policy as insufficient. As currently framed, the lead claim is vulnerable to a one-line counterexample.

---

### Attack 2: RFC 8693 Token Exchange Provides Runtime-Adaptive Per-RS Predicate Evaluation with Amortized Roundtrip Cost

**Attack:** The construction's Section 8 Property 2 (AS-blind presentation) rests on the argument that after enrollment, the agent generates proofs locally for *any* `requiredScopeMask` without any AS/operator involvement — the mask is runtime-adaptive. RFC 8693 Token Exchange addresses this directly. The agent calls the AS once per RS:

```
POST /token
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=<enrollment_token>
resource=https://loan-origination.secu.org  (RFC 8707)
scope=loan_originate read_balance
```

The AS issues a derived token bounded to that RS with only the requested scope intersection. The RS receives a JWT introspection response (pre-signed) valid for the token lifetime. For all subsequent requests within the token's TTL, the RS verifies locally with zero AS calls. The initial roundtrip cost is amortized across all requests in the session.

For the SECU scenario in Section 7: an agentic banking session involves hundreds of API calls to the loan origination system over a session lasting minutes to hours. One RFC 8693 exchange at session start — sub-100ms latency — amortizes to negligible overhead per request. The ZK construction's advantage is eliminating this *single* initial exchange. The PermExtract game (Section 3) acknowledges the RS must use policy-fixed masks anyway. If masks are fixed per RS, the AS could issue pre-derived tokens offline (at enrollment time) for each RS the agent is authorized to access, eliminating even the session-start roundtrip.

**Why it works / why it fails:** It works unless the construction can quantify a deployment scenario where the RFC 8693 roundtrip cost is genuinely unacceptable — specifically, where an agent accesses a large number of *previously unknown* RSes dynamically and cannot pre-obtain derived tokens. The SECU scenario has a bounded, known set of internal RSes; this is the majority of enterprise agentic deployments. It fails if the construction targets a public agentic marketplace (unknown RSes, dynamic discovery) — but that scenario is not foregrounded in Section 7, and the SECU example works against it.

**In-threat-model?** No — the construction must address. Section 8 Property 2 must quantify the deployment scenario where RFC 8693 amortization fails. "Runtime-adaptive at moment of use" is a property; it is not automatically a *requirement*. The construction should cite a concrete scenario where session-start AS contact is prohibited — e.g., an agent operating in an offline-capable environment, or a protocol where the RS identity is not known until proof generation time.

---

### Attack 3: The PermExtract Concession Undermines the Hamming Weight Critique of SD-JWT

**Attack:** The refinement's Section 3 "Critical distinction" paragraph asserts that SD-JWT "reveals claim count, which leaks structural properties of the permission set." The construction uses this to argue ZK is superior: the proof reveals neither claim values nor count. But the construction's own Section 3 PermExtract game concedes:

> "If the RS chooses adaptive masks, it can recover B in at most 64 queries (one per bit). **Mitigation**: the RS is honest (threat model) and uses policy-fixed masks."

The construction prevents bit-by-bit extraction by requiring the RS to use fixed, non-adaptive `requiredScopeMask` values. This is a *trust assumption on the verifier*. Now apply the identical assumption to SD-JWT: if the RS uses a fixed disclosure frame (not adaptive, not probing), SD-JWT reveals only the pre-determined frame — no claim count leak, no structural hint beyond what the fixed frame conveys. Under honest-RS assumption, both systems reveal only the information necessary for the fixed predicate.

The SD-JWT "claim count leaks structure" argument (Section 7 "Why SD-JWT cannot match," item c) is correct in the adaptive-RS threat model. But the construction has already removed the adaptive RS from its threat model via the PermExtract mitigation. It cannot simultaneously use the adaptive-RS threat model to attack SD-JWT and exclude it from its own security game.

**Why it works / why it fails:** It works as a logical inconsistency attack on the comparative argument in Sections 3 and 7. The construction's SD-JWT critique relies on an adversary capability (adaptive verifier probing) that the construction's own threat model excludes for its own security argument. A symmetric analysis would show: SD-JWT with honest-RS fixed frames leaks no more structural information than a ZK proof with honest-RS fixed masks. The attack partially fails if the construction can show that SD-JWT's structural leakage occurs even under honest-RS with fixed frames (e.g., claim count is fixed in the credential at issuance, visible in the presentation header before any frame is opened). That is a legitimate argument, but it must be made precisely and is not the argument in the current draft.

**In-threat-model?** No — the construction must address. Either (a) restore the adaptive-RS adversary to the threat model and provide a PermExtract reduction that holds without the honest-RS mitigation, or (b) restrict the SD-JWT critique to issuance-time structural leakage (fixed claim count in the credential) rather than presentation-time probing, and show this issuance-time leakage is absent in the ZK construction. The current text conflates these two.

---

### Attack 4: PLONK Is Not SE-NIZK — the Section 8 Property 6 ZK-Tier Distinction Is Technically Incorrect

**Attack:** The refinement's Section 8 Property 6 contrasts "PLONK SE-ZK + blinding nonce randomization" against "BBS+ HVZK" and "SD-JWT no ZK property." This three-tier classification is incorrect for PLONK as deployed in Bolyra.

Standard PLONK (Gabizon, Williamson, Ciobotaru 2019) achieves **honest-verifier zero-knowledge** via blinding polynomials. After the Fiat-Shamir transform, this becomes a non-interactive argument with computational ZK in the random oracle model — the same security level as BBS+ ProofGen after Fiat-Shamir. Neither standard PLONK nor BBS+ achieves *simulation-extractability* (SE) without additional construction. SE-NIZK requires that an adversary who observes valid proofs cannot produce a new valid proof for a different statement without knowing the witness — this is a non-malleability property. Standard PLONK proofs *are* malleable: a verifier who sees a valid PLONK proof can produce a related valid proof for the same circuit and witness (by re-randomizing blinding factors). Full SE-NIZK for PLONK requires the Boneh-Drake construction or similar, which is not cited in the Bolyra AgentPolicy circuit specification.

The "blinding nonce randomization" described in the refinement is the `sessionNonce` public input — a domain separator that prevents nullifier reuse. This provides unlinkability across sessions, not simulation-extractability. These are orthogonal properties.

The practical consequence: the construction's claim that BBS+ is only HVZK while PLONK is SE-ZK will be challenged by any cryptographer reviewing the patent disclosure or the protocol spec. If the examiner asks "show me the SE-NIZK construction," the answer is not in the current AgentPolicy circuit.

**Why it works / why it fails:** It works because the SE-NIZK claim is technically unsupported by the cited primitive. It partially fails as a *practical attack* — the construction's actual ZK claims (RS learns only a boolean) hold under standard PLONK ZK without requiring SE-NIZK. SE-NIZK matters if a malicious RS could produce a proof forgery and attribute it to the agent; that threat is real but is not the primary claim. The attack succeeds as a *credibility* attack: overstating the ZK tier of PLONK makes the construction appear to oversell its primitives, which invites broader skepticism from reviewers.

**In-threat-model?** No — construction must address. Replace "PLONK SE-ZK" with "PLONK ZK (honest-verifier, Fiat-Shamir in ROM)" in Section 8 Property 6. If SE-NIZK is a required property (e.g., to prevent proof malleability attacks by a malicious RS), cite the specific SE-NIZK construction being used and add it to the assumption list in Section 4. BBS+ can remain classified as HVZK (its ZK argument is explicitly structured that way in the IRTF draft), but the tier distinction against PLONK should be drawn on *statement expressiveness* (arbitrary predicates vs structured disclosure) rather than on incorrectly elevated ZK security levels.


## Persona: spiffe_engineer

---

### Attack 1: The Predicate Binding Gap — Who Encodes `scope_id → required_perms`, and How Does the RS Verify It?

- **Attack:** The iter_006 construction sharpens the lead claim to "RS learns only `pred(perm_set) = 1`, not any individual bit or structural hint." This is the right framing — but it shifts the burden to a problem the construction does not solve: **predicate binding**. For the RS to accept the ZK proof as evidence of the right predicate, it must verify that the circuit's public inputs encode the predicate it actually requested. In the Bolyra circuit, `scope_id` is presumably a public input that keys into a mapping `scope_id → required_bitmask`. Three cases arise: (a) the mapping is hardcoded in the circuit — then each RS with distinct policy requirements needs a distinct circuit and distinct SRS; (b) the mapping is supplied at proof time by the prover — then a malicious agent can substitute a weaker predicate (`required_perms = 0x01` instead of `0x07`) and produce a valid proof for a predicate the RS never requested; (c) the mapping is committed to in a public registry the RS reads — now you have an AS-equivalent registry dependency, which reintroduces the AS roundtrip the construction claims to eliminate. In the SPIFFE/OPA composition, the RS defines policy declaratively in OPA and evaluates it locally against the SPIFFE identity claim; there is no predicate-encoding ambiguity. The ZK construction's "RS learns only pred=1" guarantee is vacuous unless the RS can verify that the proved predicate is the one it requested — and the construction's Section 3 and Section 7 do not address this binding.

- **Why it works / why it fails against the construction:** The iter_006 refinements tighten the privacy game (Section 3) and the SD-JWT comparison (Section 7) but neither section specifies the protocol by which the RS communicates its required predicate to the prover in a way that is (i) unforgeable by the prover and (ii) auditable after the fact. Without a binding mechanism, the "RS learns only pred=1" guarantee does not protect the RS — it protects the prover. The construction can survive this attack only by specifying a predicate-commitment protocol (e.g., the RS signs `(scope_id, required_bitmask, nonce)` and the circuit takes this signed pair as a public input verified via EdDSA inside the circuit). That mechanism is not present in the current construction.

- **In-threat-model?** No. The construction must specify a predicate-binding sub-protocol, prove it is unforgeable under the same adversarial-AS threat model, and show it does not reintroduce an AS roundtrip.

---

### Attack 2: WIMSE + OPA Transmits No Permission Structure — The SD-JWT "Claim Count Leaks" Critique Is a Deflection

- **Attack:** Section 7's "Why SD-JWT cannot match" subsection argues that SD-JWT reveals claim count, which leaks structural information. This is correct for SD-JWT. But the iter_006 refinement uses SD-JWT as the reference adversary for the SPIFFE/WIMSE composition, which is wrong. In a production SPIRE deployment, the `Workload-Identity-Token` (a JWT-SVID) carries a SPIFFE ID (`spiffe://trust-domain/path`) and standard JWT claims. It contains **no permission field at all**. Policy is evaluated at the RS side by OPA using the SPIFFE ID as the subject. The RS's OPA instance receives `{"spiffe_id": "spiffe://example.com/agent/X"}` and evaluates `allow { data.permissions[input.spiffe_id][_] == "financial_small" }`. Zero permission bits transit the wire; the RS evaluates policy from a local policy bundle. The iter_006 "claim count leaks structure" attack does not apply here because WIMSE+OPA transmits zero permission structure. The structural opacity the construction achieves via ZK is achieved by WIMSE+OPA via architectural separation of identity from policy. The four SD-JWT failure modes (Section 7) do not address this pattern, making the differentiation argument incomplete as written.

- **Why it works / why it fails against the construction:** The construction survives against SD-JWT — the iter_006 refinements are technically correct there. It does not survive against the WIMSE+OPA composition on the structural opacity claim. The actual residual ZK advantage must be stated as: "the RS does not need to maintain local OPA policy bundles synchronized with the AS; the agent self-asserts predicate satisfaction cryptographically." That is a deployment complexity argument, not a structural opacity argument, and it is weaker than the current framing implies.

- **In-threat-model?** No. Section 7's SD-JWT failure modes must be complemented by a dedicated "Why WIMSE+OPA cannot match" subsection that targets the architectural separation pattern rather than SD-JWT's disclosure mechanism. The surviving differentiator is likely: **runtime-supplied predicates from RS without AS-side policy synchronization** — which OPA bundles cannot handle without a bundle update cycle.

---

### Attack 3: A ZK Attestor Plugin for SPIRE Subsumes This Construction — You Are Building at the Wrong Layer

- **Attack:** SPIRE's architecture explicitly supports pluggable node and workload attestors via gRPC interface. A ZK attestor plugin would work as follows: the SPIRE agent holds an `operatorPrivKey`-committed credential; at attestation time, the agent generates a PLONK proof of `AgentPolicy` circuit satisfaction and sends it to the SPIRE server plugin; the SPIRE server plugin verifies the proof and, on success, issues a standard X.509 SVID with a `spiffe://bolyra.ai/agent/policyHash` path. From that point forward: standard X.509 mTLS between agent and RS, standard WIMSE token exchange, standard SPIRE trust domain federation, standard `WorkloadAPI` rotation, standard SVID short-lived TTL (no novel revocation mechanism needed). The "predicate evaluation" happens once at attestation — the SVID itself becomes the proof artifact. The RS never sees a PLONK proof; it sees a standard SVID it can verify with the SPIRE bundle endpoint it already trusts. Every property the construction claims — ZK predicate evaluation at enrollment, unlinkability via SPIFFE PPID-equivalent path hashing, AS-independence post-attestation, constant-size proof — is achieved inside the SPIRE plugin, not as a new protocol. The Bolyra construction, as specified, is more accurately described as a SPIRE attestor plugin specification than a new identity protocol. The iter_006 refinement's reframing of Section 8 Property 1 as "ZK predicate evaluation" does not address why this layering is wrong.

- **Why it works / why it fails against the construction:** The construction fails to address this unless it identifies a property that ZK at *presentation time* (agent→RS) provides that ZK at *attestation time* (agent→SPIRE server) does not. The candidate answer is: **runtime-adaptive predicate** — the RS supplies a predicate the agent has never seen before, and the agent proves it on-demand without a prior attestation round. SPIRE attestation is per-workload-startup, not per-request; it cannot handle per-request predicates. This is the genuine residual gap. But the current construction does not articulate this distinction; it frames ZK as a replacement for SPIFFE rather than as a complement to it for the specific case of request-time predicate evaluation over a stable credential.

- **In-threat-model?** No. The construction must explicitly address why ZK at *presentation time* (not attestation time) is required, name the "runtime-adaptive per-request predicate" as the property that makes a SPIRE plugin insufficient, and acknowledge that for static policies a SPIRE ZK attestor plugin is a strictly superior deployment path.

---

### Attack 4: The Adversarial-AS Claim Requires `operatorPrivKey` to Be Hardware-Bound — but the Construction Nowhere Requires This, and SPIFFE TEE Attestation Already Covers It

- **Attack:** Section 8's "adversarial-AS model where AS cannot lie about scope membership" is the construction's strongest claimed differentiator. The iter_006 refinement hardened PLONK SE-ZK and BBS+ HVZK comparison but did not address the foundational question: if the AS is adversarial, what prevents it from simply generating a fresh `AgentPolicy` witness itself? The `AgentPolicy` circuit takes `(modelHash, operatorPrivKey, permissions, expiry)` as private inputs. If the AS holds or can compute `operatorPrivKey` — which is standard in managed-agent deployments where the operator key is provisioned via the AS's secrets manager — the AS constructs a valid witness for any permission set and generates a valid PLONK proof. The construction's ZK soundness is irrelevant; the AS is the legitimate prover. The "adversarial-AS cannot lie" claim holds only if `operatorPrivKey` is generated and retained exclusively within a hardware root of trust (TPM/TEE) on the agent, inaccessible to the AS. This is not stated anywhere in the construction or in `CLAUDE.md`. SPIFFE, by contrast, explicitly handles this via TPM node attestation (SPIRE's `tpm` plugin) and Intel TDX workload attestation — the SVID is bound to hardware attestation that even a compromised SPIRE server cannot forge without physical hardware access. The construction makes a stronger security claim than SPIFFE but with a weaker hardware binding specification.

- **Why it works / why it fails against the construction:** The iter_006 refinement's PLONK SE-ZK hardening closes malleation attacks by honest-but-curious adversaries. It does not close the adversarial-AS scenario unless `operatorPrivKey` is hardware-bound. As written, the adversarial-AS claim is valid only in a deployment where the agent self-generates `operatorPrivKey` in a TEE and the AS never sees the private scalar. The construction needs to make this an explicit deployment requirement — not a security property of the cryptography — and compare it against SPIFFE TPM attestation, which achieves the same hardware binding via a standardized, production-deployed mechanism.

- **In-threat-model?** No. The construction must either (a) downgrade the adversarial-AS claim to "semi-honest AS (follows protocol but may be compelled)" and remove "adversarial" from the threat model, or (b) add an explicit `operatorPrivKey` hardware custody requirement as a deployment precondition and specify which TEE/TPM profiles satisfy it. Option (b) then requires a comparison against SPIFFE TPM attestation to show what the ZK layer adds on top of hardware binding that SPIFFE does not already provide.
