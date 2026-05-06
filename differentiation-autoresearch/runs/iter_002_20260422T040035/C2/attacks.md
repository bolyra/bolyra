# Tier 3 Adversarial — C2 Cross-scope unlinkability

## Persona: auth0_pm

---

### Attack 1: Proof Latency Is a Non-Starter for Any Operator

**Attack:** The construction's §6 pegs ScopeIsolatedAuth at ~28,200 constraints with a WASM prover running at 5,000–6,000 constraints/second — that's a 4.7–5.6 second proof time per RS access, rising to <8s with revocation composition. A PM running MCP auth at Auth0, WorkOS, or Stytch is issuing signed tokens in <100ms end-to-end, including network round-trips. The construction acknowledges this: the RS-issued `challengeNonce` has a 30s TTL (§2.4), which implies the proof generation must complete within that window. No operator onboarding a real-time payment agent or interactive chat agent will accept a 50–80x latency penalty per authorized scope access.

The construction's mitigation — "batch proof generation for all scopes within a configurable 500ms jitter + random delay ∈ [0, 2s]" (§7, step 6) — makes the latency *worse* as a defensive measure. You're now asking the operator to add up to 2.5s of intentional delay on top of proof generation time to defeat timing correlation.

**Why it works:** The construction never compares latency against incumbent alternatives in its §8 table. The comparison column ("Baseline") is OIDC, not WorkOS. An operator choosing between WorkOS (<100ms, SLA-backed) and Bolyra (5–8s, self-hosted WASM prover) faces a concrete, measurable regression for every user-facing interaction. The construction's §8 claims structural superiority on privacy — true — but does not address the regime where the operator's users churn because RS access latency quintupled.

**In-threat-model?** No — the IND-UNL-AS game (§3) is purely cryptographic and has no latency parameter. The construction must address this in §6 or §7 with a concrete mitigation: hardware-accelerated provers (GPU/FPGA timings), a proof delegation model (trusted prover service with its own trust assumptions), or a tiered deployment where ZK proofs are generated asynchronously and OAuth tokens are used for synchronous access until the ZK proof is ready. Without this, the construction is technically sound but commercially blocked.

---

### Attack 2: The Audit Mechanism (§2.6) Makes the AS the Cross-Scope Oracle

**Attack:** The stated GLBA Reg P requirement in §7 is: "SECU-as-AS must not learn which merchants a member's agent transacts with." The construction immediately violates this in the same section: "SECU's compliance officer holds Shamir share 2 of the audit key." The `auditPayload` stored per-authorization is `(scopeId, scopeNullifier, authTag, currentTimestamp, epochIndex)`. The `scopeId` is `Poseidon("https://merchant-a.secu.org/")` — it directly encodes which merchant was accessed.

The §7 deployment scenario then explicitly states: "The examiner (share 3) and SECU compliance officer (share 2) reconstruct the audit key. They decrypt the agent's audit log, verifying that all authorizations were for valid scopes." Translation: SECU's compliance officer — an employee of the AS — learns the complete cross-scope authorization history of every member agent during any examination. This is precisely the graph the construction's IND-UNL-AS game (§3) is designed to protect.

The construction's defense is: "At no point does SECU learn the audit contents unilaterally — the examiner's share is required." But GLBA Reg P is not about unilateral access — it restricts the AS from building member transaction profiles under any circumstances without member consent. A compliance officer + examiner reconstruction IS SECU learning the merchant graph, with regulatory cover.

**Why it works:** The construction threads itself into a contradiction. §3 defines the adversary as controlling the AS and forbids it from learning cross-scope access patterns. §2.6 hands the AS (via share 2) the decryption key to exactly those patterns, mediated only by needing one other party. The IND-UNL-AS game does not model the audit mechanism at all — the `auditKey = Poseidon2(agentSecret, "audit")` is outside the game's adversary capabilities, so the security theorem in §4 says nothing about audit-path correlation.

**In-threat-model?** No — the construction's formal claim (§1) is that "no PPT adversary wins the IND-UNL-AS game." The audit mechanism is not in scope for that claim. But the deployment scenario (§7) makes a practical privacy claim that the audit mechanism directly undermines. The construction must either: (a) exclude the AS (SECU) from holding any Shamir share, routing share 2 to an independent escrow agent, or (b) restrict the `auditPayload` to exclude `scopeId` and instead use the `scopeNullifier` alone (making the audit log RS-specific, not scope-revelatory to an AS-side auditor). As written, the §7 GLBA Reg P compliance claim does not hold.

---

### Attack 3: Epoch Batching Collapses to k=1 Anonymity in Sparse Deployments

**Attack:** §2.2 sets `MIN_BATCH_SIZE = 16` with a `MAX_BATCH_DELAY = 24 hours`. In sparse deployments — a small credit union with 50 active AI agents — epoch rotations are rare. If agents rotate every 30 days (as recommended in §2.5), a 50-agent credit union sees ~1.7 epoch rotation events per day. The registry waits up to 24 hours for a batch of 16. If only 8 agents rotate within a 24-hour window, the registry pads with 8 dummy commitments and publishes.

Now: the AS knows the timing of every epoch registration transaction. The AS also knows which agents were enrolled and when. If an agent is observed making an RS access using a particular `epochMerkleRoot`, and that root was published in a 24-hour window where only 3 real agents rotated (plus 13 dummies), the anonymity set is 3, not 16. The AS cannot identify which of the 3, but the k-anonymity guarantee of "minimum 16" is a formal claim (§2.2: "providing a minimum k-anonymity of 16 per epoch") that is only met if exactly 16+ real agents always rotate together — a deployment constraint the construction cannot enforce.

The construction's §2.2 says dummies are "indistinguishable from real ones in the tree." True. But the AS does not need to distinguish dummies from real commitments in the tree — it observes the *timing and count of real enrollment/rotation transactions* off-chain. Each real epoch rotation requires an on-chain `registerEpoch(epochRoot)` transaction from a real agent wallet. The number of such transactions in a batch window is observable even if the contents are pseudonymous.

**Why it works:** The construction's anonymity set argument assumes an observer cannot count real vs. dummy insertions. But real insertions are wallet-signed transactions with gas costs; dummies are registry-inserted with no corresponding wallet. An on-chain observer can distinguish transaction origin (operator wallet vs. registry padding) unless the registry itself submits all insertions in a single bundled transaction — which the construction does not specify. This is an implementation gap that collapses to k=1 in sparse deployments.

**In-threat-model?** Yes — the adversary in §3 controls on-chain state observation. The construction must specify that all batch insertions (real + dummy) are submitted in a single atomic registry transaction with no per-insertion wallet signatures observable on-chain. Without this, the k-anonymity claim of §2.2 is not achieved by the protocol as described.

---

### Attack 4: No Answer to Procurement's Solo-Founder Question That Survives a Legal Review

**Attack:** The §7 deployment scenario names SECU (State Employees' Credit Union, $56B AUM, 2.8M members) as the concrete stakeholder. Assume SECU's CISO reads this construction and agrees the cryptography is sound. Their legal and procurement teams then ask:

- Who indemnifies SECU if a circuit soundness bug results in unauthorized agent access to member accounts?
- What is the SOC 2 Type II audit scope for the on-chain registry, the Merkle root history buffer, and the `forceRevoke()` emergency path?
- Who is on-call when `epochRoot` batch transactions fail and agents cannot authorize?
- What is the SLA for the `challengeNonce` cache TTL enforcement across RS instances?
- Who holds the universal SRS for the PLONK circuits (§4, Assumption 2)? If the SRS ceremony was compromised, all proofs are forgeable. What is the incident response protocol?

The construction has no answers to any of these. The SRS ceremony question is particularly acute: PLONK with a universal SRS requires a trusted setup. The construction does not specify whether this was done, by whom, with what ceremony parameters, and how SECU verifies the SRS integrity. Auth0 and WorkOS do not require SECU to trust a cryptographic ceremony they cannot audit.

**Why it works:** The IND-UNL-AS game (§3) and the reduction (§4) are cryptographic arguments under named assumptions. They do not constitute the operational trust package an enterprise credit union requires to deploy production authorization infrastructure. The construction's §8 comparison table has no row for "vendor has existing procurement relationship with NCUA-regulated institutions," "vendor carries cyber liability insurance," or "vendor has undergone SOC 2 Type II audit of the proving infrastructure." These are not cryptographic properties — but they are the actual decision criteria for the buyer the construction targets. WorkOS ships MCP auth today with an enterprise agreement, indemnification clause, and a SOC 2 report. The construction ships a PLONK circuit and a game definition.

**In-threat-model?** No — entirely outside the formal model. But this is the correct objection level for the stated buyer (SECU). The construction must address operational trust: SRS ceremony provenance, incident response runbook for registry failures, and a path to SOC 2 scope that includes the ZK proving infrastructure. Without this, the SECU deployment scenario is aspirational, not a reference customer.


## Persona: cryptographer

*Applied cryptographer reviewing C2 (Cross-scope unlinkability). I will steelman the construction where it earns it and break it where it does not.*

---

### Attack 1: Scope-local revocation is bypassable by epoch rotation

**Attack:**
The adversary is an agent whose RS-A–scoped access has been scope-locally revoked (§2.3). The agent performs an epoch rotation: it increments `epochIndex`, computes `epochSecret_{i+1} = Poseidon2(agentSecret, epochIndex_{i+1})`, and publishes a new `epochRoot_{i+1}` to the epoch Merkle tree (batched). It then presents a fresh proof to RS-A with `scopeNullifier' = Poseidon2(scopeId_A, epochSecret_{i+1})`. RS-A's local revocation set contains only the old `scopeNullifier = Poseidon2(scopeId_A, epochSecret_i)`. The new nullifier is not in the set, so verification step 7d passes. The revocation is completely circumvented.

**Why it works:**
Scope-local revocation (§2.3) is keyed on `scopeNullifier`, which is epoch-dependent. The construction's own forward-secrecy design—nullifiers change across epochs—makes the revocation set obsolete after any rotation. There is no cross-epoch linking mechanism available to RS-A (by design), so RS-A cannot know that `scopeNullifier'` belongs to the same agent as the one it revoked. The global revocation path (§2.3, operator-initiated) is correctly described as "the nuclear option" and is not available to RS-A acting alone.

**Why the construction does not address it:**
Section 2.3 defines two revocation vectors but does not note that scope-local revocation is epoch-scoped. The security argument in §4 does not include revocation in the threat model or proof. There is no constraint that ties epoch rotation eligibility to the absence of an active scope-local revocation. An RS that revokes an agent for cause (fraud, abuse) has no durable handle on that agent; the epoch rotation period (as short as the next batch window) is the evasion window.

**In-threat-model?** No — the construction must address this. Options: (a) make `scopeNullifier` include the epoch Merkle leaf index so RS-A can revoke by leaf index, checking that the presenting agent's epoch Merkle proof maps to a revoked leaf; (b) require operators to co-sign epoch rotation transactions with an RS-revocation clearance check; (c) explicitly acknowledge that scope-local revocation is advisory and global revocation is the only durable mechanism.

---

### Attack 2: The IND-UNL-AS reduction uses multi-query PRF security but the stated assumption is single-query

**Attack:**
This is a formal flaw in the reduction sketch (§4), not an operational attack. The adversary A in the IND-UNL-AS game is permitted to query proofs for `a₀` and `a₁` at any scope other than the challenge scope `s*`. After q such queries, A has observed:

```
{Poseidon2(s₁, epochSecret_{a_b}), Poseidon2(s₂, epochSecret_{a_b}), ..., Poseidon2(sₙ, epochSecret_{a_b})}
```

In Hybrid 2, the construction claims that replacing `scopeNullifier* = Poseidon2(s*, epochSecret_{a_b})` with a uniform random value is indistinguishable by Poseidon-PRF. But the Poseidon-PRF assumption as stated in §4 is a **single-query** distinguishing game: `|Pr[D(Poseidon2(x, k)) = 1] - Pr[D(R(x)) = 1]| < negl(λ)`. This covers one evaluation at one point. The reduction requires security under a **q-query** adaptive PRF game, where the adversary has seen q prior evaluations under the same key `epochSecret_{a_b}` before being challenged at `s*`.

For standard cryptographic PRFs (AES, HMAC-SHA256), q-query security follows from 1-query security by a standard hybrid over queries. For Poseidon2, this equivalence is **assumed but not stated**. The Poseidon-PRF assumption in §4 does not cover the multi-query case, and the gap must be closed either by (a) replacing the assumption with an explicit q-query PRF statement, or (b) providing the hybrid argument that folds q evaluations back to a single evaluation for Poseidon2.

**Why it matters:**
Poseidon2 is an arithmetization-friendly hash function designed for ZK proof efficiency, not to replace AES. Its security in the multi-query PRF setting is far less studied. Known algebraic attacks (interpolation, Gröbner basis, Feistel differential distinguishers on round-reduced variants) are evaluated against single-query distinguishers. The multi-query PRF assumption for Poseidon2 with a fixed key and adversarial, chosen-point queries is an open research question, not a textbook reduction.

**In-threat-model?** No — the formal claim in §1 ("no PPT adversary wins IND-UNL-AS with advantage greater than negl(λ)") requires a valid reduction. The current reduction has a gap in the PRF assumption that must be patched explicitly.

---

### Attack 3: Network-layer deanonymization is a complete break in the T-real model, with no cryptographic mitigation

**Attack:**
The adversary AS controls the Authorization Server and colludes with up to k-1 RS instances. In the T-real model (§3, side-channel extension), A observes per-proof generation timestamps. But the construction's threat model explicitly includes "network observation: A sees encrypted traffic metadata (timing, packet sizes) between the agent and all RS instances."

In §2.1 step 3, the agent "sends a session initiation request to RS-A (no identity information included)." This TCP session has:

1. **Source IP address**: identifies the agent's network location. If the AS controls infrastructure (credit union AS = SECU, which likely controls the network), source IP is trivially observable.
2. **TLS SNI (Server Name Indication)**: even before the TLS handshake completes, the ClientHello exposes the RS hostname in plaintext. An AS observing network traffic between the agent and RS-A reads `rs-a.example` from the SNI field. This requires no ZK break — it is a passive observation at the IP layer.
3. **Connection timing**: the construction's mitigation (§7 step 6) is "500ms jitter + random delay ∈ [0, 2s]." This is an operational recommendation with no formal security proof. A ±2s timing window against a 5-second proof generation time leaves a well-defined fingerprint. Critically, the RS-issued `challengeNonce` has a 30-second TTL — if the AS colluding with RS logs the `(challengeNonce, issuedAt)` tuple and also observes network traffic, the correlation window is tight.

**Why it works:**
The unlinkability claim is that the AS cannot determine which RS the agent accessed. But SNI reveals the RS hostname to any on-path observer. The SECU credit union AS (§7 scenario) is on-path: it operates the credit union's network or can subpoena ISP logs. Zero-knowledge proofs provide no protection at OSI layers 3–4.

**What the construction says:**
Section 3 parameterizes the game with T-none / T-batch / T-real but states only that "security degrades to computational indistinguishability of proof generation times" in T-real. This is too vague to be a security claim. No reduction from T-none to T-real is provided. The T-batch mitigation (§7 step 6) relies on the agent batching all connections within a 500ms window — but the RS-issued challenge forces a *sequential* interaction (get nonce → generate proof → send proof) per RS, making true batching of distinct RS connections operationally implausible without a mix network or onion routing layer.

**In-threat-model?** No — the threat model includes "network observation" but the T-real security claim is unsubstantiated. The construction must either (a) formally exclude network-layer correlation from the threat model (scoping the claim to the cryptographic layer only), or (b) specify and prove a network-layer mitigation (e.g., required use of Tor / mix network, or a privacy-preserving proxy layer), or (c) replace the vague T-real clause with an explicit impossibility result noting that IP-layer correlation is out of scope.

---

### Attack 4: On-chain `registerEpoch` transactions create an enrollment-linkable deanonymization oracle

**Attack:**
The construction requires agents to publish epoch roots via `registerEpoch(epochRoot)` transactions (§2.5). These are Ethereum (or EVM-compatible) smart contract calls. Every such call is signed by an Ethereum address, which is observable on-chain by the adversary AS.

Consider the following distinguishing attack:

1. At enrollment time, the operator calls the `AgentPolicy` contract to insert `credCommitment` into the agent Merkle tree. This call is signed by the operator's key at address `addr_op`.
2. At epoch rotation time (every ~30 days), the agent or operator calls `registerEpoch(epochRoot)`. If `addr_op` (or any address derivable from it) signs this transaction, the AS trivially links the epoch root to the enrolled agent by address correlation — no ZK break required.
3. Even if the operator uses a fresh Ethereum address per epoch, funding that address (ETH for gas) from a known operator address creates a transaction graph traceable by standard blockchain analysis tools (e.g., Chainalysis, arkham intelligence).

The batching policy (§2.2 extended to epoch rotations) provides k-anonymity of 16 within a tree root, but does **not** anonymize the *transaction sender*. An adversary who can link `addr_op` to an enrollment transaction can link it to every subsequent epoch registration, collapsing the anonymity set to 1 regardless of batch size.

**Why the reduction does not cover this:**
The IND-UNL-AS game (§3) includes "A sees all enrollment transactions" and "epoch root publication events" as part of A's view. The game correctly models these as visible. But the game does not model transaction-level metadata (sender address, gas pattern, transaction graph). The reduction's Hybrid 3 analysis (§4, step 7) concludes A's view consists of simulated proofs and shared Merkle roots — but this analysis is at the circuit output level. It does not account for the blockchain transaction metadata that accompanies those outputs.

**Formal gap:**
The IND-UNL-AS game needs to specify whether A can observe the sender address of `registerEpoch` transactions. If yes, the game is trivially won for any agent whose operator reuses addresses (which is the common case). If no, the game definition understates A's real capabilities against on-chain systems.

**In-threat-model?** No — the construction must either (a) specify a mandatory transaction obfuscation protocol (e.g., require use of a relayer / meta-transaction system that breaks sender linkage, or require all epoch registrations to flow through a privacy-preserving relay with ring signatures), or (b) acknowledge this as a gap and bound the anonymity guarantee to cases where operators enforce strict key hygiene and fund fresh addresses via a coin-mixing protocol.


## Persona: cu_ciso

---

### Attack 1: Key Custody — agentSecret in Member-Controlled Hardware

**Attack:**
Section 2.7 states the RS verification depends on the agent computing proofs "locally," and §2.5 says "the agent stores only `agentSecret` and the current `epochIndex`." The construction never specifies where `agentSecret` lives. If this is a WASM prover in a browser, `agentSecret` sits in `localStorage` or `IndexedDB` — neither of which qualifies as a regulated key store. If it's a mobile app, the construction is silent on iOS Secure Enclave or Android Keystore integration. If it's a server-side agent (the healthcare and merchant-bot scenarios in §7 imply this), then the agent operator's infrastructure is now in scope for NCUA third-party due diligence under Part 748 Appendix B, and the credit union owns that examination finding.

The `agentSecret` is not just a session key — §2.5 makes clear that every `epochSecret` past and future is derivable from it (`epochSecret_i = Poseidon2(agentSecret, epochIndex_i)`). Compromise of `agentSecret` compromises the entire credential chain across all epochs. The audit key is also derived from it (§2.6: `auditKey = Poseidon2(agentSecret, "audit")`). This is a single point of complete failure.

**Why it works / why it fails against the construction:**
The construction explicitly excludes agent-side compromise from its threat model (§3: "The adversary A does NOT control the agent's local computation environment"). This is an honest scoping choice. However, NCUA examiners examining vendor-managed AI agents will ask exactly this question under GLBA Safeguards Rule §314.4(f) (encryption of customer information in transit and at rest) and NCUA Part 748 §748.0 (security program for member information). The construction gives the examiner no answer. The IND-UNL-AS game is provably secure; the key storage story is entirely absent.

**In-threat-model?** No — construction must address. Requires: minimum specification of acceptable key storage environments (TEE, HSM, OS Keychain), a classification of which deployment topologies are in scope, and a risk disclosure for browser-based deployments. Without this, a GLBA Safeguards examination finding is a near-certainty for any member-facing deployment.

---

### Attack 2: Dual-Control Audit Deadlock at 2am Incident Response

**Attack:**
Section 2.6 specifies that audit records require 2-of-3 Shamir reconstruction to decrypt. For "incident response," the construction designates share holders as: operator (share 1), credit union compliance officer (share 2), independent auditor or regulator (share 3). For rapid investigation the required coalition is "operator + compliance officer."

Scenario: A member's agent triggers a suspicious transaction pattern at 11:45pm on a Friday. My Tier 1 ops team escalates. My CISO is on call. The compliance officer is not on call — she is a business-hours role. The operator (the AI agent vendor) has an SLA of 4 business hours. I need to know within 30 minutes whether this was an authorized transaction or fraud, to comply with my SAR filing timeline under BSA/AML. The construction's audit mechanism cannot be opened without two specific humans cooperating, and it specifies no emergency access path, no break-glass procedure, and no SLA for key holder availability.

Section 2.6 mentions "rapid investigation" as a use case for the operator+compliance coalition, but rapid is undefined. The share holders are people, not systems. No key escrow SLA, no paging protocol, no fallback. The audit chain head on-chain proves completeness but reveals nothing about content.

**Why it works / why it fails against the construction:**
The construction's privacy design is sound — the dual-control mechanism correctly prevents unilateral AS surveillance. But it conflates "privacy-preserving audit" with "operationally available audit." NCUA Part 748 Appendix A §III.C requires incident response procedures that are actually executable. FFIEC CAT Baseline Domain 5 (Cyber Incident Management) requires timely detection and response. A privacy mechanism that makes incident response depend on scheduling a call between three parties across organizational boundaries fails this control category regardless of its cryptographic properties.

**In-threat-model?** No — construction must address. Requires: defined SLA for share holder availability, break-glass emergency procedure (e.g., time-locked key escrow with audit trail), and explicit mapping to NCUA Part 748 §III.C incident response requirements. The current §2.6 footnote that "the scheme merely formalizes the access control" is insufficient for an examination narrative.

---

### Attack 3: On-Chain Registry Availability — RS Verification Has No Fallback

**Attack:**
RS verification step 7 (§2.1) requires the RS to check: (c) `agentMerkleRoot` is in the on-chain root history buffer, and (f) `epochRoot` is in the on-chain epoch root set. Section 2.3 requires RS instances to refresh the revocation sparse Merkle root at least every 15 minutes. The construction is built on an on-chain registry with no specified availability SLA, no fallback behavior, and no degraded-mode operation.

FFIEC CAT Baseline requires critical third-party systems to meet the credit union's own RTO/RPO. My core processor (Symitar/Fiserv) contractually commits to 99.95% availability — roughly 4.4 hours downtime per year. A public blockchain (Ethereum mainnet or any L2) does not offer contractual SLA. Network congestion, RPC provider outages, or finality delays are outside my control and outside any vendor SLA I can present to my board. What happens when the RS cannot reach the on-chain registry during a 15-minute outage? The construction does not say. If the RS fails closed (rejects all proofs), my members cannot transact. If the RS fails open (accepts proofs without on-chain verification), the revocation and Merkle root guarantees evaporate entirely.

The 30-entry circular root history buffer (§2.2, §5) provides a window, but it is a freshness mechanism, not an availability mechanism.

**Why it works / why it fails against the construction:**
The cryptographic properties are unaffected by this attack — the construction is sound when the on-chain state is accessible. The operational failure is that the construction treats blockchain availability as an infrastructure assumption, not a risk to be mitigated. NCUA examiners reviewing third-party technology risk under Part 748 Appendix B will ask for a BCP/DRP that covers "what happens when your identity registry is unavailable." The construction provides no answer and no contractual hook for SLA enforcement.

**In-threat-model?** No — construction must address. Requires: specification of acceptable RPC provider configuration (redundant endpoints), defined RS fail-close/fail-open policy with rationale, maximum tolerable registry downtime and mapping to FFIEC CAT business continuity controls, and if targeting credit unions specifically, a disclosure that no blockchain-based registry meets FFIEC BCP expectations without additional contractual and architectural mitigation.

---

### Attack 4: Out-of-Band Enrollment Correlation — MIN_BATCH_SIZE Assumes AS is Cryptographically Blind

**Attack:**
Section 2.2 states that the minimum batch size of 16 "provides a minimum k-anonymity of 16 per epoch even in sparse deployments." The security argument in §4 (Hybrid 2, step 3) depends on the `agentMerkleRoot` being shared by multiple agents, preventing the AS from identifying which agent's proof is being presented.

But the AS is the credit union. When I enroll a member's agent under the AgentPolicy circuit, I already know:
- The member's legal name, SSN, account number (KYC/AML records)
- The date and time the enrollment transaction was submitted
- The permission bits in the credential commitment (e.g., `[payments, loans, insurance]`)
- Which batch the enrollment landed in (I see the transaction)

My anonymity set is not 16 unknown agents — it is 16 agents I enrolled, whose real-world identities I know from my membership records. The Merkle batch commitment proves nothing to my examiner about anonymity, because I hold the out-of-band mapping from commitment to member. The MIN_BATCH_SIZE is a cryptographic mechanism applied to a layer that is already transparent to the AS through non-cryptographic channels.

More concretely: in the SECU scenario (§7), SECU enrolls agents for specific members. SECU's CRM system records "Member 00482193 enrolled agent on 2026-04-03T14:22:11Z." The batch containing that enrollment maps directly to a small set of members who enrolled that day. With 16 minimum batch size at a large CU, this might be a few hours' worth of enrollments. At a $2B AUM credit union with 80,000 members, this is a lookup table SECU already has. The IND-UNL-AS game models the AS as seeing only cryptographic signals — it does not model the AS as a regulated institution with KYC records predating the enrollment transaction.

**Why it works / why it fails against the construction:**
The cryptographic unlinkability claim is valid within the stated threat model (§3), which explicitly restricts the AS to on-chain and protocol-level observations. The gap is that the threat model does not account for the AS's administrative data. For a financial institution adversary, the enrollment-time correlation through CRM/membership records is not a cryptographic attack — it is a database join. No amount of Merkle batching prevents it. The construction conflates cryptographic anonymity with operational anonymity against an AS that is also your KYC processor.

This is not hypothetical: GLBA Reg P's definition of nonpublic personal information explicitly includes transaction data linking a financial product to a specific consumer. SECU-as-AS already has this link before the first proof is ever generated.

**In-threat-model?** No — construction must address. Requires: explicit acknowledgment that MIN_BATCH_SIZE provides cryptographic anonymity against passive on-chain observers but does NOT provide anonymity against an AS that holds enrollment-time administrative records; a threat model section distinguishing "AS as cryptographic adversary" from "AS as regulated institution with member records"; and a deployment guidance note that the privacy guarantee is strongest when the AS is a neutral infrastructure provider, not the credit union itself acting as enrollment authority.


## Persona: rfc7662_advocate

*OAuth Working Group veteran. Ten years shipping production introspection. Every ZK claim is suspect until proven not achievable by RFC 7662 + extensions. Cites RFCs by number. Demands a baseline counterexample.*

---

### Attack 1: JWT Introspection Response Removes AS from the Hot Path — §8 Comparison Table Row 1 Is Wrong

- **Attack:** §8 claims "AS sees which RS is accessed: Yes — AS signs audience-bound tokens per RS." I concede the AS produces audience-bound tokens at issuance. But `draft-ietf-oauth-jwt-introspection-response` (signed JWT introspection responses) combined with RFC 8707 resource indicators means the AS signs a JWT that the RS caches for the token's full lifetime. After the first introspection call, the AS is not contacted again. The construction collapses "AS on hot path" and "AS has issuance log" into a single row — these are distinct properties. A cached JWT introspection response removes the AS from the hot path without removing it from the correlation chain.

- **Why it works / fails against the construction:** The attack correctly identifies a loose framing in §8, but the construction's actual security claim does not rest on the AS being on the authorization hot path — it rests on the AS observing the *issuance-time* audience claim. Since RFC 8707 requires the client to specify `resource` at token request time, the AS issuance log still contains `(agentId, resource=https://rs-a.example/, timestamp)` regardless of how long the RS caches the JWT introspection response. The construction's real claim should be: "the AS issuance log is the unavoidable correlation oracle under OAuth 2.0, regardless of caching." The hot-path framing in §8 is imprecise, but the underlying claim survives.

- **In-threat-model?** No — the construction survives, but §8 row 1 must be rewritten to distinguish "AS on hot path" from "AS holds issuance-time audience binding." Leaving this conflated invites exactly this objection in peer review.

---

### Attack 2: On-Chain `registerEpoch` Transactions Trivially Deanonymize Agents — §2.5 Has an Unaddressed Gap

- **Attack:** §2.5 epoch lifecycle, step 2: "the agent publishes `epochRoot_i = Poseidon2(agentSecret, epochSecret_i)` on-chain via a new `registerEpoch(epochRoot)` transaction." Every EVM transaction has a `tx.from` address. If the agent's operator signs the `registerEpoch` transaction with a key that was also used at enrollment (or is otherwise linkable to the enrollment — e.g., the same operator key that submitted the `AgentPolicy` proof), the adversarial AS trivially maps `epochRoot → agent identity` by reading `tx.from`. The batch policy in §2.2 prevents anonymity-set-of-one for *Merkle root updates*, but it does not anonymize the transaction sender. §7 deployment step 2 asserts "SECU sees epoch root insertions but cannot link them to specific agents within the batch" — this assertion is false under the stated threat model unless transaction-level anonymity is provided.

- **Why it works / fails against the construction:** The construction provides no mechanism for anonymous on-chain epoch registration. The adversarial AS (§3) "can read all public on-chain state" and can observe transaction metadata including `tx.from`, gas price, and nonce sequences. A colluding AS operating the chain's RPC node can further correlate submission IP addresses. Once `epochRoot → agent` is known, the AS can check which proofs include an `epochMerkleRoot` containing that `epochRoot` — partially undermining the IND-UNL-AS game, because the epoch Merkle tree modification introduced in §4 step 6 outputs `epochMerkleRoot` as a *public signal* (signal index 7). The AS doesn't need to break Poseidon-PRF; it reads the registration ledger.

- **In-threat-model?** Yes — the adversary in §3 controls the AS and observes on-chain state. The construction must either (a) require epoch registration via a privacy-preserving relay (Tornado Cash-style, or via a designated anonymizing submitter contract), (b) use a stealth address scheme for epoch registration keys, or (c) explicitly scope the IND-UNL-AS game to exclude on-chain transaction metadata. As written, this is an unaddressed deanonymization vector that survives the Poseidon-PRF reduction.

---

### Attack 3: DPoP (RFC 9449) Provides Sender-Constraint — Name the Property It Cannot Provide, Then Prove the Construction Provides It

- **Attack:** §8 lists "Forward secrecy on compromise: Partial — DPoP key rotation is per-session but AS-visible." I'll press harder. RFC 9449 DPoP allows the agent to use a *different DPoP key pair per RS* — generated ephemerally at session initiation, never registered with the AS, bound only to the specific access token audience. The AS sees `dpop_jkt` (the public key thumbprint) only at token issuance. After issuance, each RS session has a distinct ephemeral key. Cross-RS correlation via `dpop_jkt` is broken at the RS level with per-RS DPoP keys. The construction's §8 "Colluding AS+RS can de-anonymize: Yes — AS reverses PPID; DPoP proofs are AS-visible" conflates DPoP proof visibility with linkability. DPoP proofs sent to RS-A are not sent to RS-B; the AS does not receive them post-issuance.

- **Why it works / fails against the construction:** The attack correctly identifies that per-RS ephemeral DPoP keys break RS-to-RS correlation via public key comparison. However, it does not escape the issuance-log attack: the AS issued audience-bound tokens for RS-A and RS-B at separate issuance events, recording `(agentId, dpop_jkt_A, resource=RS-A)` and `(agentId, dpop_jkt_B, resource=RS-B)` — both keyed on `agentId`. The AS need not reverse the PPID; it simply joins on `agentId` in its issuance log. The property DPoP *cannot* provide: scope-bound nullifier separation at the identity level, where the identifier presented to RS-A is cryptographically independent of the identifier presented to RS-B *and also independent at the issuer's issuance log*. DPoP achieves transport binding; it cannot achieve issuer-log unlinkability without removing the issuer from per-scope authorization — which is exactly what ScopeIsolatedAuth does.

- **In-threat-model?** No — the construction survives. But the §8 row "DPoP proofs are AS-visible" is the wrong attack surface; the correct framing is "DPoP at issuance still produces a correlated issuance log entry." The construction should make this argument precisely instead of claiming DPoP proofs are globally AS-visible (they aren't, post-issuance).

---

### Attack 4: Colluding AS + (k−1)-of-k RS Instances Reconstructs the Full Traffic Graph Except One Scope — The Residual Privacy Loss Is Unquantified

- **Attack:** The threat model (§3) allows the adversary to collude with "up to k−1 of k RS instances." The IND-UNL-AS game restriction (§3) prevents A from seeing proofs from both a₀ and a₁ *at the challenge scope s** — but A freely observes all other scopes. In the SECU deployment (§7), SECU operates merchants, loan originators, and insurance providers. If SECU colludes with all but one RS (say, the insurance RS), SECU sees the full merchant and loan authorization graph — complete cross-scope correlation for all but one scope — because each proof carries `scopeId` as a *public signal* (signal index 5, §2 public signal layout). The construction's claim "adversarial AS that tries to correlate per-agent traffic graphs" is refuted for (k−1)/k of the graph by design. The IND-UNL-AS game protects only the one honest RS's scope.

- **Why it works / fails against the construction:** The construction does not claim to hide *which RS is accessed* — `scopeId` is public. The game is correctly scoped to same-agent vs. different-agent attribution. The Poseidon-PRF argument holds: even if A collects `(scopeNullifier_A, scopeId_A)` and `(scopeNullifier_B, scopeId_B)` from k−1 colluding RSes, A cannot determine whether they came from the same agent without breaking Poseidon-PRF. The construction survives the formal game. However, the *deployment scenario in §7* implicitly assumes SECU does not operate all the RSes it cares about — if SECU operates both Merchant RS-A and Insurance RS-B, GLBA Reg P compliance requires it *not* to share data between them internally, but the construction permits this correlation via the colluding AS+RS pathway once scopeIds are preimage-invertible (RS URI → Poseidon hash, trivially invertible with a lookup table since RS URIs are enumerable in a closed credit union ecosystem).

- **In-threat-model?** Yes — but this is a *deployment scope mismatch*, not a construction break. The formal claim (IND-UNL-AS, k-1 colluding RSes) holds. The gap is that §7 presents SECU-as-AS operating all RSes, which means the adversary controls all RSes, violating the "strict subset" requirement in §3. The construction must either (a) require RS instances to be operated by parties independent of the AS, or (b) explicitly bound the privacy guarantee to the case where at least one RS is operated by a non-AS party — and acknowledge that SECU's internal merchant network does not qualify.


## Persona: spiffe_engineer

---

### Attack 1: ZK Attestor at the Wrong Layer

**Attack:**
SPIRE's workload attestor interface is a plugin boundary. I can drop a ZK attestor into SPIRE today: the agent generates a Poseidon-based commitment at node attestation time, SPIRE signs a short-lived X.509 SVID against it, and the RS does mTLS. Your §2.1 "No AS interaction occurs" property is already achievable by tuning SVID TTL below one request-response cycle. Your `challengeNonce` (§2.4) is a TLS handshake nonce. Your `authTag = Poseidon2(scopeNullifier, challengeNonce)` is a private-key signature over that nonce. The new primitives are unnecessary indirection.

**Why it works / why it fails against the construction:**
It fails on the core unlinkability claim. An X.509 SVID embeds the full SPIFFE URI (`spiffe://trust-domain/agent/alice`) in the Subject Alternative Name. The RS sees that URI in the TLS handshake. A ZK attestor changes *how* SPIRE validates the workload at enrollment — it does not remove the workload's identity from the SVID presented to each RS. Cross-RS correlation via shared SAN is trivially achievable by any party performing TLS inspection, including a colluding AS. The construction's `scopeNullifier = Poseidon2(scopeId, epochSecret)` is specifically designed to be *different* at each RS. SPIFFE provides no such per-audience pseudonymization primitive.

**In-threat-model?** Yes — construction survives this attack. The ZK-attestor-in-SPIRE path closes the enrollment privacy gap but cannot close the per-RS correlation gap without replacing the SVID content model, which would make it a new protocol anyway.

---

### Attack 2: WIMSE Non-Engagement — Contributing at the Wrong Forum

**Attack:**
I co-author WIMSE drafts. `draft-ietf-wimse-arch` explicitly scopes: (a) subject tokens representing workload identity, (b) context tokens scoping that identity for a specific audience, and (c) token exchange flows. Nothing stops WIMSE's token exchange from using BBS+ selective disclosure: the workload presents a subject token, the exchange server issues a context token revealing only the permission bitmask subset required for that audience, and the exchange server is blinded to the full bitmask via selective disclosure. Your §8 comparison table dismisses "BBS+" with "does not remove the issuer from the authorization path" but does not engage with WIMSE at all. Why are you not contributing `ScopeIsolatedAuth` as a WIMSE extension or profiling it as a WIMSE-compatible token type?

**Why it works / why it fails against the construction:**
The attack lands a real gap: §8 is silent on WIMSE. But the core critique overstates BBS+. Even with BBS+ selective disclosure in a WIMSE token exchange, the *exchange server* necessarily sees the target audience URI to produce the context token — it cannot be blinded to the audience and simultaneously bind the token to that audience. The AS-is-audience-aware structural constraint (§8, last paragraph) applies to any AS-mediated issuance, including WIMSE token exchange. The only escape is what the construction does: move proof generation fully to the agent using a locally-held secret, so no server is in the path.

**In-threat-model?** No — the construction must address this. §8 should explicitly engage WIMSE, show that WIMSE token exchange cannot achieve IND-UNL-AS (the exchange server always observes the audience claim), and position `ScopeIsolatedAuth` as a protocol that could be profiled into WIMSE as an alternative token type rather than a competing standard. Failure to engage with WIMSE is a standardization risk, not a cryptographic one — but it is the attack vector that will be used in any IETF review.

---

### Attack 3: Epoch Boundary Timing Linkage at Colluding RS (T-real Underspecification)

**Attack:**
The construction's epoch rotation (§2.5) is deterministic in duration: `SHOULD rotate every 30 days`, hard upper bound `MAX_EPOCH_DURATION = 90 days`. A colluding RS-A maintains `revokedNullifiers[scopeId_A]` (§2.3). Under T-real, RS-A observes its own nullifier log with timestamps:

```
days  0-30:  nullifier_X  active (presented N₁ times)
day  30:     nullifier_X  stops appearing
day  30+δ:   nullifier_Y  first appearance
days 30-60:  nullifier_Y  active (presented N₂ times)
```

RS-A did not generate this correlation — it emerged from its own replay-detection log. RS-A passes `(nullifier_X, nullifier_Y, transition_timestamp)` to the colluding AS. The AS now knows: whatever agent was using scope A before the epoch boundary is the *same* agent using scope A after it, with overwhelming probability (the transition window is parameterized, bounded, and public knowledge). The cross-epoch identity link at RS-A is not a PRF break — it is a traffic analysis event the construction's IND-UNL-AS game explicitly excludes from the T-none model and only loosely addresses in T-batch.

**Why it works / why it fails against the construction:**
The T-batch mitigation (§7.6: "500ms jitter + random delay ∈ [0, 2s]") is about *proof generation* timing, not *epoch transition* timing. Epoch transitions are governed by `MAX_EPOCH_DURATION`, which is public. A colluding RS does not need millisecond timing resolution — it needs only the day-granularity transition in its nullifier log. The construction's §2.5 "Compromise recovery" section addresses the case where `epochSecret_i` is *leaked*, but does not address the case where the epoch transition itself is a linkability event at a colluding RS.

**In-threat-model?** No — the construction must address this. Options: (1) formally restrict the IND-UNL-AS game to require that A cannot access RS-A's nullifier log across epoch boundaries (weakens the threat model claim); (2) redesign scope nullifiers to rotate independently of the epoch boundary, e.g., `scopeNullifier = Poseidon2(scopeId, Poseidon2(epochSecret, rsNonce))` where `rsNonce` is refreshed by the RS at a frequency uncorrelated with epoch rotation; (3) explicitly model this in the T-real game and prove that the transition is indistinguishable from normal nullifier churn given MIN_BATCH_SIZE.

---

### Attack 4: Trust Domain Federation Covers the Portable Identity Gap — State the Residual Precisely

**Attack:**
SPIFFE trust domain federation (`spiffe://cu-a/member/agent` federated with `spiffe://cu-b/`) gives the "portable identity" property cited in §7 (cross-credit-union member agent). CU-B trusts CU-A's bundle, validates the SVID, and authorizes the agent. The construction claims: "Cross-scope unlinkability even under adversarial AS." But CU-A-as-AS knows its own SVIDs — federation does not help when the threat is the *home* trust domain learning the agent's activity at *federated* domains. The SPIFFE engineer would ask: is your threat model specifically *intra-domain* (the home AS learning which of its own RS instances the agent uses) or *cross-domain* (a federated AS learning cross-domain activity)?

**Why it works / why it fails against the construction:**
The construction's threat model (§3) is clear: the adversary AS controls enrollment and logs issuance — this is the *home* AS in SPIFFE terms. SPIFFE federation does not address intra-domain correlation because the home SPIRE server is the issuer of all SVIDs within its trust domain. A federated SPIFFE deployment does not prevent `spiffe://cu-a/` from knowing that its member agent accessed `https://merchant-a.secu.org/` and `https://insurance-b.secu.org/` — it merely prevents CU-B from de-referencing the SPIFFE ID without CU-A's bundle. The residual gap SPIFFE federation cannot close is exactly the one the construction closes: same-trust-domain AS learning intra-domain RS access patterns.

**In-threat-model?** Yes — construction survives. But the construction should state this residual precisely in §8's comparison row for "SPIFFE federation" (currently absent). The claim "trust-domain federation gives you portable identity, name the gap" is a fair challenge from a SPIFFE engineer, and the answer is well-supported by the construction — it just isn't written down. The absence of this row in §8 will be the first objection from any reviewer with SPIFFE background.
