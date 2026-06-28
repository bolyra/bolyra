# Tier 3 Adversarial — C1 Selective scope proof

## Persona: auth0_pm

---

### Attack 1: The Latency Tax Compounds in Agentic Workloads

**Attack:**
The construction claims Groth16 proving time of "<0.5s with rapidsnark" (§6). WorkOS, Auth0, and Stytch issue access tokens in under 100ms on a bad day, typically <20ms at p50. An MCP agent making 30 tool calls in a session doesn't make one auth decision — it makes 30. At 0.5s per proof, that's 15 seconds of pure auth overhead per session. At 5s (snarkjs, browser or edge), it's 2.5 minutes of wall-clock latency hidden in what looks like "agent thinking time." The construction's §6 notes proving time targets but never models a session budget or compares to incumbent latency at realistic call volumes.

**Why it works:** The construction is optimized for single-proof analysis. It never presents a latency model for multi-tool-call sessions. The credit union scenario in §7 shows one agent accessing one RS — not the realistic pattern where an agent probes READ, then conditionally does WRITE, then delegates to a sub-agent, each hop requiring a fresh proof with fresh `agentBlind`. At that point the user is waiting on ZK math that exists because the AS might theoretically be compromised — a threat no credit union CISO has raised in a risk register.

**Why it partially fails:** Rapidsnark at 0.5s is real and the construction is honest about it. Server-side agentic use (not browser) keeps this <1s. But the construction gives no latency SLA, no p99 number, and no comparison against the baseline's token issuance time. Saying "< 5s" next to WorkOS's "< 100ms" in a procurement scorecard is a losing row.

**In-threat-model?** No — the construction must address cumulative session latency and provide a realistic comparison against incumbent token issuance, not just single-proof benchmarks.

---

### Attack 2: "Adversarial AS" Is a Threat Model No Buyer Has Signed Up For

**Attack:**
The construction's crown jewel is AS-blindness (§3, Game 3; §8, Axis 1, Axis 3): "If the credit union's OAuth AS is compromised (e.g., by a supply-chain attack on the AS vendor), the RS still has cryptographic assurance." From a buyer's perspective this is asking: *pay more, move slower, onboard harder, in order to protect against your identity provider being fully compromised and actively lying to your resource servers about agent permissions.* No NCUA examination framework, SOC 2 vendor questionnaire, or credit union third-party risk policy encodes this threat. If your AS is fully adversarial, you have a breach notification obligation and a board-level incident — ZK proofs over permission bitmasks are not your problem at that point.

The construction's §7 scenario ("credit union compliance officer... adversarial AS resilience... satisfying NCUA expectations around data minimization") conflates *data minimization in vendor relationships* with *AS-blind cryptographic assurance*. NCUA data minimization means "don't share member PII with vendors who don't need it" — not "prove scope without contacting your authorization server." These are different properties and the construction uses regulatory language to elevate a cryptographer's threat model into buyer-relevant compliance language it doesn't earn.

**Why it works:** Every incremental complexity in procurement gets scrutinized. "We need this because your AS might lie to your resource servers" will get laughed out of a credit union vendor risk assessment. The construction needs a threat model that appears in NCUA IT Examination Handbook (2023), NIST SP 800-207 (Zero Trust), or FFIEC Cybersecurity Assessment Tool — not in a game-theoretic security definition.

**Why it partially fails:** The AS-blind property *does* have a real use case in multi-tenant federated deployments where the agent operator is not the same party as the RS operator and neither trusts the other's AS. The construction hints at this in its "adversarial AS" game but never names this as the primary scenario. It retreats to a credit union example where the credit union *operates* the AS and the RSes — making AS-blindness irrelevant to the actual buyer.

**In-threat-model?** No — the construction must name a concrete buyer segment where the AS is actually semi-trusted and adversarial, not one where the operator controls both the AS and the RSes. The credit union scenario actively undermines the claimed differentiator.

---

### Attack 3: On-Chain Enrollment Is a Hidden Onboarding Moat That Kills the Deal

**Attack:**
Section §7 casually states: "The credit union's compliance officer enrolls an AI agent with `permissionBitmask = 0b00001111`... into the on-chain agent Merkle tree, signed by the operator's EdDSA key." This sentence hides the entire onboarding stack:

1. The operator needs a Baby Jubjub EdDSA keypair. Where is the key management UI? Who holds the key in a credit union? How does it rotate?
2. They need to submit an on-chain transaction to the Registry contract on Base Sepolia (or mainnet). This requires a funded wallet, gas estimation, transaction signing, and waiting for block confirmation (12s+ on Base).
3. If the enrollment transaction fails (gas spike, nonce collision, RPC outage), the agent cannot prove anything until re-enrollment succeeds and the Merkle root updates.
4. The RS must verify `agentMerkleRoot ∈ on-chain root history buffer (last 30 roots)` — meaning the RS needs an RPC endpoint to Base or a trusted oracle. Enterprise procurement will ask: "What's your RPC uptime SLA? Who operates the contract? Can we audit the contract? What happens during a blockchain reorganization?"

Auth0, WorkOS, and Stytch onboarding: create an account, copy a client ID and secret, paste them in, call `/oauth/token`. Time to first token: 3 minutes. The construction's onboarding is potentially days when you factor in security review of a Solidity registry contract.

**Why it works:** The construction is technically rigorous about the circuit but hand-waves the key management and enrollment UX entirely. The gap between "compliance officer enrolls an agent" and "compliance officer submits a BN254-encoded Merkle leaf to a smart contract on a blockchain" is the entire product. The on-chain anchoring (§5, "30-entry circular root history buffer") is presented as a trust advantage but it's also a liveness dependency on an external system that enterprise procurement must approve.

**Why it partially fails:** The 30-root history buffer and on-chain anchoring are genuinely clever for decentralized trust — the construction just doesn't address what happens at the enrollment layer, where all the friction lives. This is a product gap, not a cryptographic one.

**In-threat-model?** No — the construction must specify the key management and enrollment UX, address RPC dependency in the verification path, and explain how credential rotation works when a key is compromised (re-enrollment requires a new Merkle leaf and a new on-chain transaction, during which the agent has a gap in provability).

---

### Attack 4: This Sits on Top of MCP Auth, Not Instead of It

**Attack:**
The MCP specification (2025-03-26 and later) mandates OAuth 2.0 for remote MCP server authentication. Every MCP client — Claude Desktop, Cursor, Windsurf, VS Code Copilot — implements the OAuth PKCE flow and expects an `Authorization: Bearer <access_token>` header. A Groth16 proof in a `X-Bolyra-Proof` header is not a bearer token. The construction nowhere explains the HTTP layer integration.

From the MCP client's perspective, the protocol is: discover the MCP server's auth metadata, redirect to the AS for authorization, exchange code for token, present token. Bolyra doesn't replace any step in this flow — it either (a) runs alongside it (agent holds both an OAuth token and a ZK proof, doubling the auth surface), or (b) requires every MCP client to implement a new auth method that no current client supports, or (c) wraps inside an OAuth extension that requires AS cooperation — which reintroduces the AS dependency the construction claims to eliminate.

Auth0 MCP auth, WorkOS MCP, Stytch Connected Apps, and Cloudflare Access all integrate with MCP's OAuth mandate today, out of the box, with existing MCP clients. The construction's §5 "Bolyra primitive mapping" table maps to circuit signals, not to OAuth token fields, MCP protocol headers, or existing MCP server middleware.

**Why it works:** The construction is protocol-complete at the ZK layer but protocol-absent at the HTTP/MCP integration layer. A buyer who asks "how do I configure my MCP server to accept a Bolyra proof instead of a WorkOS token?" has no answer in this document. The construction proves scope without revealing it to an RS — but the RS is a *MCP server* that currently expects `Bearer eyJ...`, not `Proof groth16:BN254:...`.

**Why it partially fails:** The construction could be positioned as a proof-of-concept for a future MCP auth extension (IETF draft, MCP spec PR). The spec references `spec/draft-bolyra-mutual-zkp-auth-01.md`, suggesting awareness of standardization. But the adversary's point stands: today, in production, with real MCP clients, this doesn't plug in. WorkOS plugs in today.

**In-threat-model?** No — the construction must specify the transport binding: how does a `(π, pubSignals)` tuple get presented to an MCP server, how does the server verify it without an on-chain RPC call on every request, and what the path is to being an accepted MCP auth method rather than a parallel system that requires buyers to run two auth stacks.


## Persona: cryptographer

Applied cryptographer. I review for CRYPTO and S&P. My prior: unless there is a game definition with an explicit adversary model, a named assumption, and a concrete reduction, the claim is a whitepaper. Let me read this construction carefully.

---

### Attack 1: Assumption A1 is misstated — Groth16 does not use Fiat-Shamir, and the trusted setup is outside the threat model

**Attack: Toxic waste extraction from the SRS ceremony**

The construction's §4 lists A1 as "Knowledge soundness of Groth16 — ε_ks ≈ 2^{-128} (generic group model + **random oracle model for Fiat-Shamir**)." This is a category error. Groth16 is not made non-interactive via Fiat-Shamir — it is made non-interactive via a *structured reference string* (SRS) generated in a multi-party computation ceremony. The ROM/Fiat-Shamir combination describes PLONK or Bulletproofs, not Groth16. Groth16's knowledge soundness holds in the algebraic group model (AGM) + generic group model (GGM) *under the assumption that the SRS trapdoor (τ, α, β, γ, δ) has been faithfully destroyed*.

The adversary model (§3) says the on-chain verifier contract is trusted, the AS is fully compromised, and the network is adversary-controlled — but it says nothing about who ran the AgentPolicy and Delegation trusted setup ceremonies and whether the toxic waste is gone. The BOLYRA spec says `pot16.ptau` is used for project-specific Groth16 keys. That MPC ceremony is not the Semaphore v4 ceremony (which has broad participation and public verification); it is a project-internal ceremony.

**Concrete attack**: Suppose a ceremony participant retained their share of τ. They can now:
1. Construct `(A, B, C)` in BN254 that satisfies the Groth16 pairing equation for *any* false statement, including `requiredBits[i] * (1 - permBits[i]) === 0` with bits that do not satisfy the predicate.
2. Set `permissionBitmask = 0` in the extracted witness and produce a proof that claims `0 & M = M` for any M.
3. Present this to any RS. The RS's pairing check passes. The on-chain verifier also passes (it checks the same equation). SCOPE-FORGE advantage = 1.

**Why it works**: Under subverted SRS, the knowledge soundness extractor fails — the "extractor" for Groth16 is the CRS trapdoor itself. With τ in hand, no extraction is needed; the adversary simply synthesizes a proof directly. The claimed bound Adv[SCOPE-FORGE](A) ≤ ε_ks + ε_col collapses because ε_ks → 1.

**In-threat-model?** No. The threat model excludes on-chain contract compromise but is silent on SRS integrity. A construction claiming SCOPE-FORGE security must either (a) define a trust assumption on the SRS ceremony and reduce to it formally, (b) use PLONK (universal, transparent setup) where the toxic waste problem does not arise, or (c) use the Semaphore v4 ceremony for all circuits (not just HumanUniqueness). §3's BOLYRA spec note that "AgentPolicy uses pot16.ptau" means the project *has* a trusted setup that must be in scope. The adversary model must address it — and the construction must not misattribute Fiat-Shamir to Groth16 in the assumption table.

---

### Attack 2: agentBlind is an unverifiable private input — the CROSS-RS-UNLINK game's "honest agent" assumption silently carries a CSPRNG trust

**Attack: Deterministic or biased agentBlind restores advantage to 1**

Game 4 (CROSS-RS-UNLINK) in §3 states: "The adversary does NOT control... the honest agent's private inputs, including agentBlind." But the circuit imposes *zero constraints* on agentBlind beyond its membership in F_p. The gadget list in §2 has no range check, commitment, or entropy floor on agentBlind. It is a free private input signal.

**Concrete attack**:

1. Adversary controls an agent implementation (or supplies a client library). Agent derives `agentBlind` as a deterministic function: `agentBlind = Poseidon2(credentialCommitment, sessionNonce)`.
2. When RSes RS₁ and RS₂ coordinate identical nonces `n`, the agent computes `agentBlind₁ = Poseidon2(cred, n) = agentBlind₂`. Therefore `blindedNonce₁ = Poseidon2(n, agentBlind₁) = blindedNonce₂`.
3. Now `scopeCommitment₁ = Poseidon3(B, cred, blindedNonce₁) = scopeCommitment₂`. CROSS-RS-UNLINK advantage = 1 — same as the pre-fix construction.

**Why the circuit cannot prevent this**: The Circom circuit for AgentPolicy as described takes `agentBlind` as a private input signal. A signal in Circom is a field element. There is no `assert agentBlind ← Uniform(F_p)` expressible in R1CS — the circuit can only constrain *algebraic relationships* between signals. Randomness generation is outside the R1CS model entirely.

**In UC terms**: The environment ε can fork the agent's process, inspect its state, or supply a malformed library implementing `agentBlind ← f(credential, sessionNonce)`. The ideal functionality for CROSS-RS-UNLINK must explicitly model agentBlind as a local oracle call `agentBlind ← CSPRNG()` and include a separate assumption about the CSPRNG's integrity. Without this, the security proof has a gap: the reduction at the end of §4 says "agentBlind values are chosen by the honest challenger (not the adversary)" — but in a real deployment, the challenger is the *agent process*, and the adversary (controlling both RSes) can also control the agent's software or induce it to run on predictable hardware.

**What the construction must address**: Either (a) add a hardware attestation binding agentBlind to a TPM/HSM random-number generator, (b) state explicitly that CROSS-RS-UNLINK holds only under a separate CSPRNG assumption (and name it), or (c) acknowledge that a deterministically-derived agentBlind restores vulnerability to the nonce coordination attack the construction claims to fix. As written, §3 buries this in "adversary does NOT control the honest agent's local randomness source" — which is a trust assumption that is not in the named assumption table (§4).

**In-threat-model?** Partially — the game says the adversary does not control agentBlind's sampling. But the construction does not (a) name this as a numbered assumption, (b) discuss the failure mode when it is violated, or (c) provide any mechanism (circuit-level or protocol-level) to enforce it. It is a security-critical unverifiable local obligation and must be treated as a named assumption with its own discussion.

---

### Attack 3: Adaptive chosen-predicate queries reconstruct the full bitmask in 64 rounds — SCOPE-HIDE is a one-shot game in a multi-shot world

**Attack: Oracle separation of all 64 permission bits via sequential mask queries**

Game 2 (SCOPE-HIDE in §3) fixes `requiredScopeMask = M` and generates *a single proof*. The adversary sees one transcript and tries to guess which of two satisfying witnesses was used. The construction reduces this to Groth16's ZK property (A4) and claims Adv[SCOPE-HIDE](A) ≤ ε_zk.

This is correct for the one-shot game. The adversary does not extract `permissionBitmask` from a single proof. But the construction's §8 ("Axis 2: Runtime-adaptive bitwise predicate") explicitly highlights that "the RS specifies requiredScopeMask at verification time" as a strength. An RS that can choose the mask at runtime can choose it *adaptively across sequential requests*, and no bound on the number of proofs is stated anywhere.

**Concrete attack**:

1. RS issues 64 sequential requests, each with `sessionNonce_i` fresh and `requiredScopeMask_i = 2^i` for `i = 0..63`.
2. For each i, the RS asks: "does this agent have bit i?" The agent must prove it does (or the RS learns the agent cannot satisfy the predicate and refuses service, getting 1 bit of information either way).
3. In 64 rounds, the RS has learned every bit of `permissionBitmask`. The `scopeCommitment` values are all different (fresh agentBlinds), but the *predicate result* is a Boolean that the RS reads directly from verification: accept = bit set, reject = bit not set.

**Why ZK doesn't save you**: Zero-knowledge says the proof does not reveal more than the *public inputs and the fact that the witness satisfies the relation*. Here the relation is `permBits[i] = 1` (bit i is set), so the proof revealing that bit i is set is exactly what the RS asked for. Leaking the predicate result is *by design*. ZK prevents leaking permBits[j] for j ≠ i, but with 64 sequential queries, each bit j is eventually queried directly. The ZK property is not violated in any single round, but sequential composition leaks the full witness.

**Why the construction must address this**: The construction claims (§8, Axis 2): "the RS learns only that the predicate holds — not which additional bits are set." This is true per-proof. But the *sequence* of proofs with unit-vector masks leaks all bits. The construction needs either (a) a formal multi-proof privacy game (e.g., a q-bounded SCOPE-HIDE game where the adversary makes q adaptive queries) and a proof that Adv[q-SCOPE-HIDE] ≤ q · ε_zk (which would still be ≤ 64 · ε_zk — trivially vacuous), or (b) acknowledgment that bitmask privacy is per-proof, not against an adaptive RS that sequences queries. As written, the construction overstates the privacy guarantee: the bitmask is NOT fully hidden from an RS that can ask multiple permission questions.

**Comparison with BBS+**: Ironically, BBS+ with holder-selective disclosure has the same adaptive leakage problem. The Bolyra construction is no worse than BBS+ on this axis — but the construction's own §8 claims a qualitative advantage over BBS+ that it does not have in the adaptive multi-query setting.

**In-threat-model?** Yes — this attack is fully within the stated threat model (RS is honest but curious, controls requiredScopeMask choice at verification time). The construction survives per-proof; it does not survive adaptive sequential queries. The threat model must bound query count or define a new game.

---

### Attack 4: The scopeCommitment leaks predicate-matching structure across sessions within a single RS — intra-RS longitudinal profiling

**Attack: Bitmask range narrowing from scopeCommitment collision frequency**

Within a single RS relationship over many sessions, the RS accumulates a table of `(sessionNonce_i, scopeCommitment_i)` pairs. Each `scopeCommitment_i = Poseidon3(B, cred, Poseidon2(nonce_i, agentBlind_i))`. With fresh `agentBlind_i` each session, all commitments are distinct — no direct equality.

However: if the RS also stores the result of proof verification (accept/reject) against a fixed `requiredScopeMask`, then across many sessions with the same mask, it has a large sample of valid proofs from the same (B, cred) pair, all producing *structurally identical* Poseidon3 evaluations except for the blinded nonce input. Under a chosen-plaintext model where the RS can vary `requiredScopeMask` across sessions:

**Concrete attack**: The RS collects `(π_i, scopeCommitment_i)` for 1000 sessions. It then presents all 1000 `scopeCommitment_i` values to a statistical oracle that checks: "are these consistent with a fixed `permissionBitmask = B'`?" Using the SCOPE-HIDE game's own logic, a simulator that knew B could produce these commitments. An adversary who has a candidate B' can evaluate `Poseidon3(B', cred', r)` for random r and compare the distribution of outputs to the observed commitments. If cred' is linkable (e.g., the RS knows which `agentMerkleRoot` it always sees), the RS can test candidate bitmasks by generating synthetic commitments and checking distributional match.

**Why this is not cleanly in-threat-model**: The SCOPE-HIDE game's challenger uses a single honest proof. The attack I describe is a distinguishing game against many transcripts with *fixed* B. This is the sequential composability question for ZK: does Groth16's ZK hold for unboundedly many proofs with the *same* witness? Standard ZK does not guarantee this for adaptive provers. For Groth16, each proof is independently zero-knowledge (the simulator uses the CRS trapdoor), so this extends to any polynomial number of proofs. The distributional attack above does not succeed if Poseidon3 is modeled as a random oracle — outputs for distinct inputs are independent.

**Where the construction is actually vulnerable**: The attack works when combined with Attack 3. After the RS narrows the bitmask to a set of candidates via adaptive predicate queries, it can use the `scopeCommitment` accumulation to distinguish among candidates by testing each one. This is a combination attack that neither sub-attack alone achieves as efficiently but together reduces the search space.

**In-threat-model?** Partially — the construction claims the RS learns "nothing else about the permission bitmask" per proof, which holds per proof. But the construction does not provide a multi-session privacy game. The claim in §1 that the proof is "AS-blind" and provides "selective disclosure" overstates per-session privacy when an RS accumulates many proofs.

---

**Summary table**:

| Attack | Breaks which game | In-threat-model? | Severity |
|---|---|---|---|
| A1: Subverted SRS / Fiat-Shamir mislabel | SCOPE-FORGE, AS-BLIND | No — threat model omits CRS integrity | Critical: Adv → 1 |
| A2: agentBlind unforceability | CROSS-RS-UNLINK | Partially — "honest agent" CSPRNG is unnamed assumption | High: unlinkability collapses to advantage = 1 if violated |
| A3: Adaptive chosen-predicate (64-round) | SCOPE-HIDE multi-query extension | Yes — RS controls mask choice | High: full bitmask recovery in bounded rounds |
| A4: Multi-session commitment accumulation | Unstated multi-session game | Partially — strengthened by A3 | Medium: narrows candidate set, not a standalone break |


## Persona: cu_ciso

---

### Attack 1: On-Chain Dependency Is an Unregistered Critical Vendor with No Examiner-Visible SLA

- **Attack**: The construction's central differentiator — "adversarial-AS resilience" (§8, Axis 3) — pivots the trust anchor away from the OAuth AS and onto "the on-chain Merkle root and root history buffer" (§2, §3). I will ask my NCUA examiner what vendor contract covers that blockchain network. There is none. Base/Ethereum L2 has no legal entity I can send a vendor due-diligence questionnaire to, no MSA, no right-to-audit clause, no indemnification, no defined SLA for block finality or contract availability, and no SOC 2 Type II report. Under **NCUA Part 748 Appendix B** (Third-Party Relationships) and the **FFIEC IT Handbook: Third-Party Risk Management**, I must conduct due diligence on all critical service providers and document the relationship. A public blockchain is not a vendor I can examine. Furthermore, NCUA has issued explicit guidance (Letter 21-CU-02 and its successors) expressing regulatory unease about credit unions taking on blockchain operational dependencies. The construction frames "no AS" as a feature. My examiner reads it as: "they replaced a vendored OAuth AS with an uncontracted, unexaminable distributed network." The claim in §7 ("The NCUA examiner can verify on-chain that all enrolled agents have operator-signed credentials") assumes my examiner can and will run a blockchain node or use a block explorer. That assumption is false.

- **Why it works / why it fails**: The construction does not address this at all. §7 names the credit union scenario and cites "NCUA examiner" twice but never maps to a specific NCUA Part or FFIEC control, and never addresses how a critical dependency on a public blockchain satisfies third-party risk management requirements. The construction's silence is the attack surface.

- **In-threat-model?** No — the construction must address this. The adversarial-AS model is only valuable to me if I can replace the AS vendor with something that satisfies NCUA third-party risk requirements. A blockchain with no contractable operator fails that bar. The construction needs either a permissioned validator set with contractual SLAs and right-to-audit, or an alternative root anchoring mechanism (HSM-backed notary with SOC 2) that doesn't require blockchain engagement.

---

### Attack 2: Credential Revocation Has No Defined Kill Time — GLBA Incident Response Gap

- **Attack**: §2 and §3 state the RS checks `agentMerkleRoot ∈ root history buffer (last 30 roots)`. §7 says the compliance officer "enrolls an AI agent… into the on-chain agent Merkle tree." At 2am, a member calls because an AI agent made an unauthorized $9,800 loan pre-qualification inquiry. My SOC identifies the agent credential as compromised. I need to revoke it now. What is my kill time? The construction is entirely silent. Revocation requires removing the credential from the Merkle tree and updating the on-chain root. The 30-root history buffer — necessary for proof freshness across normal network latency — means that if roots are updated every N minutes, a revoked credential can remain valid for up to 30 × N minutes after I initiate revocation. The construction never specifies root rotation cadence, and never defines a revocation SLA. Under **GLBA Safeguards Rule §314.4(h)**, I must have an incident response plan that addresses unauthorized access to customer information systems. "Await the next Merkle root cycle" is not an incident response plan. The construction's "adversarial-AS model" means there is no AS I can call to immediately invalidate a token — the on-chain proof is the only path, and its latency is architecturally unbounded.

- **Why it works / why it fails**: The construction acknowledges the root history buffer in §2 and §7 but frames it as a freshness mechanism, not a revocation mechanism. The two requirements are in tension: a larger buffer improves liveness (tolerates root update delays) but worsens revocation latency. The construction takes no position on this tradeoff and provides no revocation protocol.

- **In-threat-model?** No — the construction must address this. A concrete revocation SLA (e.g., "root rotation every 60 seconds, maximum credential validity after revocation = 30 minutes") and a defined emergency revocation path (e.g., a separate on-chain blocklist contract checked before Merkle root validation) are required for GLBA incident response defensibility. Without this, my board narrative is: "we know the agent is compromised, and we cannot stop it for an architecturally indeterminate period."

---

### Attack 3: The ZK Proof Is Optimized for Minimum Disclosure — The Examiner Needs Maximum Disclosure

- **Attack**: The construction's §8 cites "least-privilege compliance: RS₂ cryptographically cannot learn about permissions it didn't ask for" as a credit union benefit. That is a correct cryptographic property and the wrong compliance property. When my NCUA examiner sits down for a **FFIEC CAT** Domain 3 (Cybersecurity Controls) review, they ask for audit logs demonstrating: who (which agent) accessed what resource, when, under what authorization, and whether that access was appropriate in retrospect. The construction produces `nullifierHash = Poseidon2(credentialCommitment, blindedNonce)` as its session artifact. That is a BN254 field element. My Tier 1 ops team cannot read it. My external auditor (for SOC 2 Type II) cannot read it. My NCUA examiner cannot read it. The same ZK properties that create the competitive differentiation (§8, Axes 1–6) destroy after-the-fact auditability. The construction is optimized for *proving authorization at the moment of use* but produces *no human-intelligible record of what happened*. NCUA Part 748 Appendix A requires "audit trails" as a specific security control element. A Poseidon hash output does not satisfy this requirement in any form an examiner has historically accepted.

- **Why it works / why it fails**: The construction mentions "NCUA examiner" defensibility twice in §7 but in both cases the examiner action described is verifying enrollment (reading the on-chain tree), not auditing access logs. The access audit trail is the gap. The construction produces `scopeCommitment` and `nullifierHash` that are cryptographically meaningful but regulatory-audit-meaningless without a separate logging layer that the construction does not specify.

- **In-threat-model?** No — the construction must address this. The construction needs a companion logging protocol: at minimum, a tamper-evident, human-readable access log (agent identifier, RS identifier, timestamp, predicate mask satisfied, nullifierHash as correlation key) stored off-chain in an auditable system. This log would need to be included in the architecture and its confidentiality/integrity model specified. Without it, the NCUA examiner will flag the absence of audit trails as a finding under Part 748, regardless of how elegant the ZK construction is.

---

### Attack 4: Operator Key Custody Is Unspecified — The New Single Point of Failure Inherits AS Risk Without AS Auditability

- **Attack**: §8, Axis 3 correctly states: "A compromised AS cannot alter the agent's enrolled credential commitment." What §8 does not state: the construction replaces AS trust with operator key trust. Every agent credential requires a valid `EdDSAPoseidonVerifier` check against `operatorPubkeyAx/Ay` (§2, gadget 6). The operator private key over Baby Jubjub is the root of trust for the entire agent credential tree. If that key is exfiltrated, an attacker can issue valid credentials for any `(modelHash, permissionBitmask, expiry)` tuple and enroll them in the Merkle tree. The construction says the compliance officer "enrolls an AI agent… signed by the operator's EdDSA key" (§7) but never specifies where that key lives. **GLBA Safeguards Rule §314.4(c)(2)** requires encryption of customer information in transit and at rest, with key management controls. **NCUA Part 748 Appendix A** requires encryption key management as a specific program element. My Vendor Management Policy requires that any third-party system handling privileged key material demonstrate HSM custody, key ceremony documentation, and key rotation procedures. The construction traded a distributed, OIDC-auditable OAuth AS (which has well-understood operational key management: JWKS endpoint, key rotation, HSM backing by major vendors) for a single Baby Jubjub private key with zero specified custody requirements. The attack surface is smaller in one dimension (AS is eliminated) and catastrophically unspecified in another (operator key has no framework at all).

- **Why it works / why it fails**: The construction's §4 names the EdDSA operator signature as assumption A3 ("Discrete log hardness on Baby Jubjub, ε_dl ≈ 2^{-126}") but this is a mathematical assumption about the curve, not an operational assumption about key custody. Mathematical hardness does not protect a .env file. The construction is silent on HSM requirements, key rotation cadence, multi-party signing threshold, key ceremony auditability, and what happens operationally when the operator key is rotated (existing enrolled credentials used the old key — does the circuit accept both?).

- **In-threat-model?** No — the construction must address this. The operator key custody model needs to be fully specified: HSM requirement (FIPS 140-2 Level 3 minimum for a CU deployment), key ceremony documentation, threshold signing (e.g., 2-of-3 operator keys required to enroll a new agent), rotation procedure, and the circuit's handling of key rotation. Without this, the construction's "adversarial-AS resilience" argument is academically correct and operationally hollow: I've replaced a known-risk vendor (OAuth AS) with an unknown-risk artifact (an unprotected EdDSA private key).


## Persona: rfc7662_advocate

*OAuth WG veteran, 10+ years shipping token introspection at scale. Every ZK claim gets the RFC treatment until proven structurally impossible, not merely inconvenient.*

---

### Attack 1: SD-JWT + Key Binding Closes the "Offline Presentation" Gap — Axis 1 Overstated

**Attack:**

The construction's Axis 1 (§8) declares AS-blind presentation "structurally impossible" for the baseline. But Selective Disclosure JWT (draft-ietf-oauth-selective-disclosure-jwt, now heading toward RFC) with key binding (`cnf` claim) + DPoP (RFC 9449) achieves offline, holder-initiated presentation without AS roundtrips:

1. The AS issues a single SD-JWT at enrollment time. Each permission bit is a separate SD-JWT claim with an independent salt and hash.
2. At presentation to RS₂ (which needs bits 0 + 2), the agent constructs a derived presentation disclosing only those two claims — entirely local, no AS contact.
3. RS₂ verifies the issuer signature over the hash commitments offline. DPoP key binding provides sender-constraint equivalent to Bolyra's `credentialCommitment` binding.

Under RFC 9728 (PRM), the RS can advertise which `scope_values` it requires, and the agent selects the matching SD-JWT claims. This mirrors the construction's `requiredScopeMask` concept at the claim-set level.

**Why it works / why it fails against the construction:**

It fails on Axis 2, not Axis 1. SD-JWT *discloses claim values* — the RS learns that `bit_0 = 1` and `bit_2 = 1`. It cannot prove the predicate `permissionBitmask & M == M` over *hidden* bits. If the agent holds bits {0, 1, 2, 3} and presents to RS₂ (requires {0, 2}), RS₂ learns exactly `{bit_0: true, bit_2: true}` — not whether bit_1 or bit_3 exist at all, since undisclosed claims are structurally hidden. But critically: RS₂ cannot receive a *proof* that the remaining bitmask satisfies cumulative implication constraints (bit 3 → bit 2, bit 4 → bit 3) without the agent disclosing those bits too. The bitwise AND predicate over hidden bits is inexpressible.

The construction's Axis 1 claim is an overstatement — SD-JWT achieves offline holder presentation. The genuine differentiator is Axis 2: runtime-evaluated Boolean predicate over cryptographically hidden bits with implication closure. The construction should center its "why-not-baseline" argument there.

**In-threat-model?** Partially. The construction **survives** on the predicate expressiveness axis but the Axis 1 language is imprecise — it should say "offline *zero-knowledge* predicate presentation" rather than "offline presentation is impossible." The current framing invites dismissal by reviewers who know SD-JWT.

---

### Attack 2: `agentMerkleRoot` Is a Supercookie — The Unlinkability Claim Is Epoch-Scoped, Not Global

**Attack:**

The Cross-RS Unlinkability game (Game 4, §3) and the deployment scenario table (§7) both dismiss `agentMerkleRoot` as "Shared across all agents — no signal." This dismissal is incorrect in realistic deployments.

The 30-entry root history buffer means `agentMerkleRoot` is stable for ~30 on-chain epochs (however long an epoch is — likely minutes to hours). During this window, *every proof generated by any agent enrolled in the same tree* carries the same `agentMerkleRoot`. If the credit union has 10 enrolled agents and the tree is per-operator, all 10 agents share the same public `agentMerkleRoot` across all RSes for the entire epoch.

Colluding RSes can therefore partition all proof traffic by `(agentMerkleRoot, epoch)`:

- All traffic sharing an `agentMerkleRoot` came from agents in the same operator tree.
- In a deployment with 5 credit unions, each with their own tree, cross-RS traffic is partitioned into 5 anonymity buckets — not a global anonymity set.
- If one of those credit unions has only 2 enrolled agents, the anonymity set is 2.

Compare to RFC 7662 + PPID (OIDC Core §8.1): pairwise subject identifiers are RS-specific at the *credential level*, not the *operator/tree level*. An AS using PPID leaks no operator-level grouping signal. Bolyra's `agentMerkleRoot` is a coarser partition signal than PPID — it leaks the enrollment epoch and operator identity to all RSes simultaneously.

**Why it works / why it fails against the construction:**

The construction's Game 4 is defined with two agents `C₀` and `C₁` **both in the same tree** — so `agentMerkleRoot` is identical in both proof transcripts by construction. The game correctly models this. But the game is weaker than the deployment claim: it only proves unlinkability *given* that both proofs come from the same tree. It does not prove anything about distinguishing agents *across* different trees. More concretely: if RS₁ sees `agentMerkleRoot = R₁` and RS₂ sees `agentMerkleRoot = R₂` where `R₁ ≠ R₂`, the RSes immediately know different operators are involved — no ZK helps here.

The Merkle root epoch also creates a timing channel: a root update (enrollment of a new agent, revocation, or scheduled refresh) changes `agentMerkleRoot` and leaks the timing of tree mutations to all RSes observing the chain.

**In-threat-model?** No. The construction does not address the `agentMerkleRoot` epoch-correlation attack in its threat model. An adversary who correlates by `(agentMerkleRoot, epoch)` across RSes is not modeling in Game 4. The construction must either expand Game 4 to bound the `agentMerkleRoot` leakage or acknowledge it as an explicit residual (and quantify the anonymity set size).

---

### Attack 3: Delegation Breaks the AS-Blind Property for Multi-Hop Chains — Liveness Requirement Not Disclosed

**Attack:**

The construction's AS-blind claim (Axis 1, §8) states: "The agent generates proof entirely from its local private inputs... The AS is not in the protocol at all." This is accurate for single-hop proofs. It is **false** for delegation chains.

From §2 (Delegation chain linking):

> "Within a delegation chain, the delegator must communicate their `blindedNonce` to the delegation prover so the chain-linking constraint can be verified."

This is a **mandatory online interaction between delegator and delegatee** at proof-generation time. In RFC 8693 (Token Exchange), the delegatee obtains a token from the AS independently — the delegator does not need to be online or cooperative at delegation time. The delegatee's proof generation is stateless with respect to the delegator's runtime state.

In the Bolyra delegation protocol:

- The delegator must be online at the moment the delegatee generates its proof.
- The delegator must correctly compute and share `delegatorBlindedNonce = Poseidon2(sessionNonce, agentBlind)`.
- If the delegator is unavailable (crashed, rate-limited, or terminated), the delegation sub-chain breaks — even if the delegator's on-chain credential is valid and the delegatee's credential is valid.

Additionally: the delegatee now learns `delegatorBlindedNonce`. While this doesn't directly leak `agentBlind` (Poseidon preimage resistance), a delegatee who also controls an RS that observed `nullifierHash_delegator = Poseidon2(cred_delegator, delegatorBlindedNonce)` can now verify: `Poseidon2(cred_delegator?, delegatorBlindedNonce)` matches the observed nullifierHash by brute-forcing `cred_delegator` over a small space (if the delegator's credential commitment is guessable, e.g., for a known operator with few models).

**Why it works / why it fails against the construction:**

The construction correctly notes the `Poseidon3` chain-linking constraint prevents substitution attacks (Poseidon collision resistance, A2). The circuit is sound. But the *protocol* introduces a liveness dependency and information disclosure that the construction does not analyze. The RFC 7662 advocate's point: RFC 8693 Token Exchange achieves delegation without delegator online presence, without leaking any delegator session state to the delegatee. The Bolyra delegation protocol is strictly *more dependent* on runtime coordination than the baseline it claims to improve upon.

**In-threat-model?** No. The threat model (§3) does not model a delegatee-as-adversary who receives `delegatorBlindedNonce` and correlates with observed RS nullifier logs. The liveness requirement is not addressed anywhere in the construction.

---

### Attack 4: Adversarial-AS Resilience Is a Strawman in the Credit Union Scenario — The Claim Is Circular in §7

**Attack:**

The construction's §8, Axis 3 claims: "A compromised AS can claim an agent has permissions it does not have... the RS has no recourse." This motivates adversarial-AS resilience as a key differentiator. The credit union deployment (§7) is the primary concrete scenario.

But in the §7 scenario, the credit union IS the AS. The credit union's compliance officer enrolls AI agents. RS₁, RS₂, RS₃ are all "operated by the credit union" or "operated by Jack Henry (core banking vendor)." The claim "if the credit union's OAuth AS is compromised" describes a scenario where the *operator* of the on-chain Merkle tree contract is also compromised — and the Bolyra construction offers no protection in that case either, because:

1. A compromised compliance officer can enroll a credential with arbitrary `permissionBitmask` into the on-chain Merkle tree.
2. Once enrolled, a proof with the forged bitmask is valid and RS-verifiable.
3. The construction's security in AS-BLIND (Game 3, §3) explicitly models the AS as adversary but treats the on-chain enrollment as the honest party. If the same entity controls both the AS and the enrollment key, AS-BLIND provides no protection.

This is the same trust assumption as RFC 7662: the AS's authority over scope assignment must be trusted by the RS. Bolyra moves the trust from "AS runtime attestation" to "Merkle tree enrollment-time signature." Both require trusting the credential issuer. In the credit union single-operator scenario, this is the same entity.

The adversarial-AS model is genuinely stronger in a *federated* deployment where the AS and the RSes are under different operators, and the Merkle tree enrollment is governed by a smart contract with independent governance. But §7 does not describe this scenario — it describes a single credit union deploying all three RSes. The baseline (RFC 7662 with the credit union as the AS) offers equivalent security to the Bolyra construction against an adversarial credit union, because in both cases the credit union controls the root of trust.

**Why it works / why it fails against the construction:**

The construction fails to distinguish the single-operator scenario (where AS-blindness is circular) from the multi-operator federated scenario (where AS-blindness is genuinely stronger). The NCUA deployment example weakens rather than strengthens the construction's adversarial-AS claim — it should use a *multi-party federated* scenario as the primary example, not a single credit union. Against the actual threat in §7 (AS compromise by supply-chain attack), the baseline and the construction have identical security: both root trust in the credential issuer's key material.

**In-threat-model?** No. The construction conflates AS-blind presentation (valid) with AS-adversarial resilience in single-operator deployments (not addressed). The §7 concrete scenario does not instantiate the adversarial-AS model it invokes.


## Persona: spiffe_engineer

You renamed the AS. The on-chain contract operator is now the AS. Let's work through this systematically.

---

### Attack 1: The Operator EdDSA Key Is the AS Under a Different Name

- **Attack:** The construction claims "adversarial-AS resilience" (§3 Game 3, §8 Axis 3) because the RS's assurance derives from the on-chain Merkle root rather than an AS attestation. But the on-chain Merkle root is only as trustworthy as whoever controls the smart contract that writes roots to the 30-entry circular history buffer. That entity — the operator who holds the EdDSA key pair (`operatorPubkeyAx`, `operatorPubkeyAy`) and who calls the registry contract — is functionally the AS. A compromised operator can enroll any `credentialCommitment = Poseidon5(modelHash, opAx, opAy, permissionBitmask, expiry)` with an arbitrary `permissionBitmask` into the Merkle tree. The on-chain verifier will accept the proof because the Merkle inclusion check (`BinaryMerkleRoot(20)` in §2 gadget 7) only verifies membership, not the legitimacy of what was enrolled. §3 Game 3 says the adversary "cannot alter the agent's enrolled credential commitment," but the operator-as-adversary is never scoped into the threat model — the threat model explicitly grants the adversary control over "the Authorization Server" while implicitly treating the operator key and smart contract admin as trusted. In SPIFFE terms: you've replaced the SPIRE server CA with an EdDSA key you haven't placed in a threat model.

- **Why it works / why it fails:** It works because the construction draws a bright line between "AS" (untrusted) and "operator/on-chain contract" (implicitly trusted) without analyzing what happens when they are the same entity or are colluding. In a credit union deployment (§7), the core banking vendor that operates RS₁–RS₃ may also be the operator who enrolled credentials — this is the exact adversary the construction claims to defeat. The construction doesn't fail on soundness (the circuit is fine) but the trust model argument in §8 Axis 3 is circular: "a compromised AS cannot alter what the agent can prove" is true only if the operator and AS are distinct, non-colluding parties, which is never asserted.

- **In-threat-model?** **No.** §3 explicitly models the adversary as controlling the AS but does not include the operator key holder or the smart contract admin in the adversary's capability set. The claim in §8 Axis 3 that "the AS cannot retroactively alter what the agent can prove" must be qualified: the *operator* cannot be the adversary. This gap needs a trust model section that separates operator, AS, and RS into distinct principals with explicit collusion assumptions.

---

### Attack 2: `agentBlind` Freshness Is an Unenforceable Agent Obligation That Breaks CROSS-RS-UNLINK

- **Attack:** The entire CROSS-RS-UNLINK hardening (§3 Game 4, §2 Modification 2) rests on the agent sampling `agentBlind` uniformly at random from F_p for each proof. The construction acknowledges this as an "agent obligation" (§2: "The agent MUST sample `agentBlind` uniformly at random from F_p for each proof. This is a local operation requiring no coordination or AS involvement"). The circuit cannot enforce this. `agentBlind` is a private input — the circuit verifies that `blindedNonce = Poseidon2(sessionNonce, agentBlind)` is consistently used inside the proof, but it places no constraint on `agentBlind` being fresh or non-repeating. An agent runtime that is resource-constrained, deterministically seeded (e.g., a containerized workload with a weak entropy pool at startup), or that implements `agentBlind` as a function of the credential rather than fresh randomness will silently reuse blinding factors. When `agentBlind₁ = agentBlind₂` and `sessionNonce₁ = sessionNonce₂`, the prior construction's vulnerability (advantage = 1) is fully restored. SPIFFE's SPIRE agent addresses this class of problem structurally: SVIDs have hard TTLs enforced by the SPIRE workload API, and SVID rotation is a protocol property — freshness cannot be omitted by an agent implementation bug. The Bolyra construction places a load-bearing security property in a "MUST" that no protocol party can verify.

- **Why it works / why it fails:** The reduction sketch in §4 for CROSS-RS-UNLINK states "agentBlind values are chosen by the honest challenger (not the adversary)" — but in deployment the "challenger" is the agent runtime, which may be buggy, deterministic, or compromised. The security proof holds in the formal model but breaks at the implementation boundary. The game definition (§3 Game 4 Step 3) models `agentBlind₁ ≠ agentBlind₂` as holding "with overwhelming probability over uniform sampling" — this is only true if the agent actually samples uniformly, which the protocol cannot verify.

- **In-threat-model?** **No.** The threat model in §3 scopes out adversarial control of "the honest agent's local randomness source" but does not model a faulty (non-adversarial but non-uniform) randomness source, which is the real-world failure mode. The construction needs either: (a) a circuit constraint that makes `agentBlind` freshness verifiable (not obvious how), or (b) an explicit implementation requirement with a known-good entropy source specification, or (c) an acknowledgement that the unlinkability guarantee degrades gracefully to the prior construction's guarantee when `agentBlind` is reused (and quantify the degradation).

---

### Attack 3: The Bitwise Predicate Gap Is Real, But the Correct Contribution Point Is WIMSE, Not a New Protocol

- **Attack:** The construction's Axis 2 (§8) claims that "bitwise AND over a 64-bit field with cascading implication constraints has no BBS+ extension" — this is correct but incomplete. WIMSE (draft-ietf-wimse-arch) is an IETF WG explicitly in scope for workload-to-workload token exchange with selective disclosure extensions. The WIMSE architecture is designed as an extensible framework: the WIT (Workload Identity Token) exchange (§5 of the WIMSE arch draft) allows scope narrowing and is explicitly open to ZK-based selective disclosure as an extension point. The correct contribution is a WIMSE extension draft that adds a ZK selective-disclosure attestor type — not a new wire protocol. The Bolyra spec (spec/draft-bolyra-mutual-zkp-auth-01.md) introduces a new DID method, a new handshake protocol, and a new credential format. This is `N` new moving parts where the delta above WIMSE is ~1: a ZK attestor. Co-authoring a WIMSE extension would achieve the same differentiation while inheriting WIMSE's SPIFFE trust domain federation, X.509 SVID interop, and existing SPIRE deployment infrastructure. You are not contributing; you are fragmenting.

- **Why it works / why it fails:** It's valid as a deployment and standardization argument, not a cryptographic break. The construction is internally consistent. But the claim "no configuration of RFC 7662 + ... can match" is set up as a comparison against a static 2024-era baseline. WIMSE is an active WG. The gap the construction is filling may close at the standards layer before Bolyra achieves critical deployment mass. The adversarial-AS model (Game 3) is the only property WIMSE structurally cannot inherit from RFC 7662 — because WIMSE still relies on the SPIRE server as the trust anchor, and SPIRE is an AS. This is the real, irreducible claim: not selective disclosure, not constant-size proof, but the elimination of the AS from the verification path entirely when the AS is adversarial.

- **In-threat-model?** **Yes, but narrowly.** The construction survives this attack only on Axis 3 (adversarial AS). Axes 1, 2, 4, 5 are all within reach of a WIMSE ZK extension. The construction should sharpen its claim to: "The one property no SPIFFE/WIMSE configuration can achieve is RS-side verification of scope predicates that is cryptographically independent of a potentially-adversarial SPIRE server." Everything else is a matter of standards-track timing.

---

### Attack 4: The Delegation Chain's `delegatorBlindedNonce` Transfer Is an Out-of-Band Channel Without a Security Model

- **Attack:** The delegation chain linking (§2, delegation chain linking; §4, impact on delegation chain security) requires the delegator to pass `delegatorBlindedNonce` as a private input to the delegatee's Delegation circuit. The circuit verifies the chain-linking constraint but does not model how `delegatorBlindedNonce` is transmitted from delegator to delegatee. This is an out-of-band channel. The construction says "The delegator simply passes the derived value" — but over what channel? If transmitted over an authenticated-but-not-ZK channel (e.g., mTLS with an X.509 SVID), the channel reveals `delegatorBlindedNonce` to any observer with access to that channel. Since `blindedNonce = Poseidon2(sessionNonce, agentBlind)` and `sessionNonce` is public, an observer who learns `delegatorBlindedNonce` can brute-force `agentBlind` if `agentBlind` has low entropy (see Attack 2 above). More critically: there is no protocol specification for how the delegator authenticates to the delegatee before transferring `delegatorBlindedNonce`. An adversary who can impersonate the delegator and substitute a crafted `delegatorBlindedNonce` can cause the delegatee's chain-linking constraint to verify against a `previousScopeCommitment` that commits to a different `delegatorScope` than what was actually used — if they can find a Poseidon3 collision, which A2 precludes, but the *authentication* of the delegator-to-delegatee transfer is not modeled anywhere. SPIFFE's SVID-based mTLS handles delegated identity transfer as a first-class protocol primitive with defined authentication semantics. The Bolyra delegation chain leaves this as an exercise for the implementer.

- **Why it works / why it fails:** It doesn't break the cryptographic construction — the Poseidon3 collision resistance argument holds if the transmission channel is authenticated. But "authenticated" is doing a lot of work that the construction doesn't specify. The threat model (§3) models the adversary controlling the network between agent and RS, which would include the delegator-to-delegatee channel. If the adversary can observe or modify this channel, and if `agentBlind` has low entropy (Attack 2 failure mode), the unlinkability guarantee collapses for the delegator's identity as well.

- **In-threat-model?** **No.** The construction models the network adversary for the agent-to-RS channel but does not analyze the delegator-to-delegatee channel for `delegatorBlindedNonce` transfer. The delegation chain security section (§4) asserts soundness under A2 but does not include a protocol specification for the transfer or a threat model for it. This needs either: (a) a specified authenticated channel for `delegatorBlindedNonce` transfer (e.g., encrypted under delegatee's public key, with delegator authentication via its own SVID or credential commitment), or (b) an in-circuit commitment that allows the delegatee to verify `delegatorBlindedNonce` without a separate channel (likely impractical without additional public outputs).
