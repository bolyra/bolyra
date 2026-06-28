# Tier 3 Adversarial — C2 Cross-scope unlinkability

## Persona: auth0_pm

---

### Attack 1: The AS-Free Path Destroys the Audit Trail Regulators Require

- **Attack:** The construction's core differentiator — "the AS sees zero per-request signals" — is a **compliance disqualifier** for both named deployment scenarios. NCUA examination requirements (12 CFR Part 748) mandate that credit unions maintain access logs attributing each transaction to an authenticated principal. HIPAA's Audit Controls standard (§164.312(b)) requires the covered entity to record who accessed what PHI and when. The construction deliberately severs the causal chain between agent identity and RS access: there is no per-request log at the AS, and the RS only sees `scopeNullifier_B` — a pseudonym it cannot attribute to a legal person or organizational account without out-of-band enrollment records. An NCUA examiner or OCR auditor asks: "Show me every transaction Alice's agent executed." The CU-A AS cannot answer. The RS can only show a nullifier it has no name for. The healthcare HIE scenario in §7 makes this worse — it explicitly frames "the PCP cannot reconstruct which hospitals the agent contacted" as a *feature*, but HIPAA Minimum Necessary is about limiting *access*, not destroying *audit logs after the fact*.
- **Why it works / why it fails:** The construction provides no reconciliation mechanism. It does not explain how a post-incident forensic investigation recovers the mapping `scopeNullifier_B → Alice`. The enrollment record links `credentialCommitment` to Alice, but there is no committed log of which RSes were contacted. A deployment that adds such logging would require re-involving the AS or a separate audit oracle — recreating the linkage the scheme is designed to prevent.
- **In-threat-model?** No. The construction treats regulatory audit as a deployment detail but the named scenarios (credit unions under NCUA, healthcare under HIPAA) are structurally incompatible with AS-invisible per-RS authorization. This is not a cryptographic gap — it is a product-market fit gap that makes §7 illustrative only.

---

### Attack 2: The Base Sepolia Merkle Tree Is a Public Correlation Oracle

- **Attack:** The construction shifts correlation risk from the AS to the on-chain Merkle tree — but does not fully account for what the blockchain leaks. Every `credentialCommitment` insertion into the agent Merkle tree on Base (§2, step 1; §7 deployment step 1) is a **public, timestamped event**. The adversarial AS (CU-A) is the one submitting this transaction — it knows the block timestamp, the transaction sender address, and the leaf value. Even though `agentSecret` is never revealed, CU-A sees: (a) the Merkle leaf = `credentialCommitment = Poseidon5(modelHash, opPubAx, opPubAy, permBitmask, expiry)` and (b) the on-chain insertion time. When Alice's agent subsequently submits proofs to CU-B and CU-C, the RS-side proof times are observable on the network. A timing correlation attack — enrollment at T₀ on-chain, proof submission to CU-B at T₀+Δ₁, proof to CU-C at T₀+Δ₂ — is feasible for a CU-A adversary watching Base mempool and CU-B/CU-C API endpoints. The IND-UNL-AS game in §3 explicitly carves out "network-level metadata: timing of proof submissions" as outside the adversary's formal capabilities, but simultaneously grants the adversary full AS control, which *is* the entity submitting on-chain enrollment transactions. The 30-second batching relay in §7 mitigates proof-submission timing but does nothing to hide the correlation window between enrollment and first use.
- **Why it works / why it fails:** The construction's formal game (§3, §4) is sound for transcript indistinguishability. But the reduction to Poseidon PRF assumes the adversary cannot link enrollment events to proof events via out-of-band timing. The on-chain Merkle tree creates exactly this side channel for an adversary who controls the AS *and* can observe Base chain state. The 30-entry root history buffer (§5) additionally creates a correlation window: if CU-A knows Alice enrolled at Merkle root R₁₇ and the RS accepted a proof anchored to R₁₇, CU-A can narrow the set of candidate agents to those enrolled in that root epoch.
- **In-threat-model?** No. The threat model grants the AS full visibility into "all Merkle tree insertions" (§3) but does not model the AS cross-referencing enrollment epochs with RS proof-acceptance events via the root history buffer. The construction must either (a) commit to a formal bound on what enrollment metadata the AS is permitted to use in the IND-UNL-AS game, or (b) treat the root history buffer epoch as a linkage surface and address it.

---

### Attack 3: `agentSecret` Is an Unrotatable Single Point of Failure

- **Attack:** The construction's unlinkability guarantee is entirely contingent on `agentSecret` remaining secret. §2 states it is "generated client-side and never leaves the agent." But the construction provides no key rotation path. If `agentSecret` is compromised — malware on the agent host, a memory-safe bug in the proving client, operator key material leak — the attacker can compute `Poseidon(rsScopeId, agentSecret)` for any `rsScopeId` and reconstruct the agent's full identity across every RS the agent ever contacted (past scope nullifiers are deterministic and on-chain-verifiable via the `agentMerkleRoot`). Compare this to the OAuth baseline: WorkOS/Auth0 can revoke a token in < 100ms via introspection or short TTL. Here, revocation requires an on-chain Merkle tree update (new leaf, new root). The RS won't know to re-check until its next proof submission. The root history buffer holds 30 entries — if the Merkle tree is active, that 30-entry window could span minutes or hours during which a compromised agent continues to successfully authenticate to every RS it previously accessed. More critically, rotating `agentSecret` requires re-enrollment: a new `credentialCommitment`, a new Merkle insertion, new scope nullifiers. The construction does not describe how an operator triggers this without revealing to the AS that agent X was compromised (which itself leaks information via the enrollment event).
- **Why it works / why it fails:** The construction inherits this from the human `secret` pattern in HumanUniqueness (§5) — a deliberate architectural choice. But HumanUniqueness is a one-time enrollment for a human identity; `agentSecret` is used for continuous per-RS authentication across an indefinite session lifetime. The threat surface is larger. The construction has no §-level treatment of key compromise, rotation, or forward secrecy. An adversary who breaks `agentSecret` retroactively de-anonymizes all historical RS accesses via the deterministic nullifier.
- **In-threat-model?** No (as written). The threat model (§3) lists "compromise the agent's local secret `agentSecret`" as outside adversary capabilities. That assumption must be explicitly bounded with a lifecycle model — otherwise the construction claims security under an assumption that cannot hold for long-lived agent credentials in production environments. WorkOS's answer to "what happens when credentials are compromised" is "revoke the token." The construction's answer is currently silence.

---

### Attack 4: The Batching Relay Reconstructs the AS You Removed

- **Attack:** §7 introduces a "consortium-operated batching relay that collects proof submissions from agents in 30-second windows and submits them in randomized order" as the timing side-channel mitigation. This relay is an unmodeled trusted third party — and it has exactly the visibility that the construction claims to remove from the AS. The relay sees: the agent's raw proof (all public signals, including `rsScopeId`), the source IP/connection metadata, and the target RS endpoint, all before batching. If the relay is operated by the consortium (which includes CU-A, the adversarial AS), then CU-A has reconstructed per-request (agent, RS, scope, timestamp) tuples — the exact information the IND-UNL-AS construction is designed to prevent. Even if the relay is operated by a neutral party, it is now a new trust anchor not present in the threat model, with no described key ceremony, audit requirement, or compromise recovery path. In the OAuth world, the AS *is* this trusted intermediary — it is audited, SOC 2 certified, and its access logs are the compliance record. The construction replaces an audited AS with an informal relay and calls it a deployment detail.
- **Why it works / why it fails:** The relay is architecturally necessary to address timing correlation (correctly identified as a residual threat in §4 and §7). But introducing it without modeling it as a trust boundary creates a gap between the formal IND-UNL-AS game (which the relay operates outside of) and the actual security of the deployment scenario. An enterprise procurement team at a CU will ask: "Who operates this relay? Can we audit it? What's its SLA?" The construction has no answer. Auth0 and WorkOS answer this question with a SOC 2 Type II report.
- **In-threat-model?** No. The relay is introduced in §7 as a deployment-layer defense but is absent from the threat model in §3. The IND-UNL-AS game assumes proof submissions arrive directly at the RS. A deployment that routes proofs through a relay must extend the game to include the relay as a potential adversarial entity — otherwise the formal security argument does not cover the deployment as described.


## Persona: cryptographer

*Stance: Unless I see a threat model, a game definition, and a reduction sketch, it's marketing. You've provided all three. So now I get to break them.*

---

### Attack 1: scopeCommitment Is a De-anonymization Oracle for a Colluding AS

**Attack:**
The circuit outputs `scopeCommitment = Poseidon(permissionBitmask, credentialCommitment)` as a **public output** (§2, public outputs table). At enrollment the AS observes `credentialCommitment` for every agent inserted into the Merkle tree (§2, protocol flow step 1). The AS also assigned `permissionBitmask` to each agent at issuance time. Therefore, for every enrolled agent *i*, the AS can precompute:

```
expected_scopeCommitment_i = Poseidon(permissionBitmask_i, credentialCommitment_i)
```

and maintain a lookup table indexed by these values. When the AS (acting as colluding RS or observing the RS's verification transcript) sees a proof with public output `scopeCommitment`, it performs a table lookup and identifies exactly which credential — and therefore which agent — generated the proof.

**Why it works against the construction:**
The IND-UNL-AS game (§3) asks whether A can link two proofs to the same agent. The above is strictly stronger: A can *identify* the specific agent behind any single proof. The AS breaks the game with advantage ε = 1 − 1/|{agents with matching bitmask and commitment}|. In the stated cross-CU scenario (§7), CU-A knows every enrolled agent's `credentialCommitment` and `permissionBitmask`. CU-A trivially reconstructs Alice's agent identity from any proof Alice's agent submits to CU-B or CU-C. The claim that "CU-A sees zero per-request signals" (§8, point 1) is false: it sees `scopeCommitment`, which is a per-agent fingerprint the AS itself authored.

**In-threat-model?** **No.** The adversary is given full AS compromise (§3, adversary capabilities). This is a direct, practical break. The `scopeCommitment` output must either be removed, replaced with a blinded version (e.g. `Poseidon(permissionBitmask, credentialCommitment, scopeBlindingNonce)` keeping the blinding nonce private), or the threat model must concede that the AS can identify which credential is used per-proof.

---

### Attack 2: The IND-UNL-AS Game Is Trivially Winnable via Phase 1 Nullifier Prelearning

**Attack:**
The `scopeNullifier = Poseidon(rsScopeId, agentSecret)` is **deterministic** and a **public output**. The game (§3) allows unrestricted Phase 1 adaptive queries. The adversary A executes the following strategy:

1. In Phase 1, query agent₀ → RS-A. Receive `scopeNullifier_{0,A}`.
2. In Phase 1, query agent₀ → RS-B. Receive `scopeNullifier_{0,B}`.
3. Choose challenge RSes RS-A and RS-B (the game says "not yet queried **in this combination**" — an ambiguous restriction that does not preclude individual RS queries per agent).
4. In the challenge phase, observe the two proof transcripts. Match the `scopeNullifier` outputs against the prelearned table. If `scopeNullifier_{0,A}` appears at RS-A, output *b' = 0*; otherwise output *b' = 1*. Win with advantage 1.

**Why it works against the construction:**
The restriction "not yet queried in this combination" does not say the adversary cannot have queried agent₀ → RS-A individually. The nullifier is pseudorandom across RSes but **fixed** for a given (agent, RS) pair — exactly by design for sybil detection (§2, step 3). The same property that enables per-RS continuity enables per-RS identification after a single Phase 1 observation. This is not a subtle timing attack; it is a deterministic lookup. The game is trivially winnable unless Phase 1 queries are restricted to exclude the challenge (agent, RS) pairs entirely — i.e., A must commit to the challenge RSes before Phase 1, or the game must exclude any prior query of any challenge agent to any challenge RS.

**In-threat-model?** **No.** The game definition has a fundamental structural flaw. A valid IND-UNL-AS game must either (a) require A to commit to challenge RS choices before Phase 1 begins, or (b) add a Fresh oracle that ensures challenge (agent, RS) pairs were never queried, analogous to the `fresh` predicate in CK security models. As written, the security definition proves nothing.

---

### Attack 3: The Reduction to Poseidon PRF Is Circular Under Knowledge Soundness

**Attack:**
The reduction sketch (§4) claims: B embeds `k*` as `agentSecret` of a challenge agent, then invokes the Groth16/PLONK zero-knowledge simulator to produce "valid-looking proofs for the other signals." This is wrong. Knowledge soundness of Groth16 (cited as assumption Groth16-KS) states that any prover producing a valid proof must "know" all private witnesses. Specifically, there exists an extractor that, given a valid proof and the proving key, extracts a witness. This means a valid Groth16 proof for `ScopedAgentAuth` requires B to know:

- `agentSecret` (to compute `scopeNullifier` in the circuit),
- the full Merkle opening for `credentialCommitment`,
- the EdDSA signature,
- all other private inputs.

In the PRF reduction, `k* = agentSecret` is the unknown PRF key. B has access only to the oracle `O(·)` which evaluates `Poseidon(·, k*)` without revealing `k*`. B cannot supply `k*` as a private input to the circuit. B cannot therefore generate a valid Groth16 proof for the challenge agent — it fails at the proving step, not at the embedding step.

The claim that "the simulator can produce valid-looking proofs for the other signals given that Groth16 is zero-knowledge" confuses the ZK *simulator* (which requires a trapdoor from the trusted setup) with the *reduction prover* (which needs witnesses). In Groth16, the simulator requires the toxic waste `τ`. Without it, B cannot simulate. With it, the reduction only holds relative to an honest setup — precisely the condition the construction is most at risk of violating in the CU consortium scenario, where the on-chain verifier's setup ceremony must be trusted by parties who are themselves adversaries.

**In-threat-model?** **No.** The reduction is invalid as sketched. A correct reduction must either: (a) treat the ZK proof as a commitment scheme and argue unlinkability without invoking a ZK simulator that needs trapdoor access, or (b) use a simulation-extractable SNARK (SE-SNARK) variant where simulation does not require setup trapdoors, and explicitly cite the SE-SNARK assumption. Neither is done.

---

### Attack 4: Credential-Secret Decoupling Allows Nullifier Forking Without Sybil Detection

**Attack:**
The circuit enforces `agentSecretCommitment = Poseidon(agentSecret, credentialCommitment)` as an **internal intermediate signal that is not output** (§2, constraint 10). The comment says this "binds the long-lived secret to the enrolled credential, preventing secret reuse across credentials." This constraint does nothing externally verifiable. The RS receives no public output that links `agentSecret` to the specific enrolled credential. The constraint only ensures the circuit is internally consistent for any `agentSecret` the prover chooses.

Concretely: the Merkle tree is on-chain and public. Any party observing the chain sees all `credentialCommitment` values and can obtain Merkle paths for any leaf. An attacker who obtains a valid `credentialCommitment` (e.g., a compromised agent, a public on-chain commitment from an agent enrolled by the same operator) can choose an arbitrary `agentSecret'` and generate valid `ScopedAgentAuth` proofs, because:

1. The EdDSA check verifies the operator signed `credentialCommitment` — no secret required.
2. The Merkle check verifies `credentialCommitment` is in the tree — path is public.
3. `scopeNullifier = Poseidon(rsScopeId, agentSecret')` — computed from attacker's chosen secret.
4. No constraint checks that `agentSecret'` is the one the legitimate agent uses.

Two agents using the same `credentialCommitment` with different `agentSecret'` values produce different `scopeNullifier` values at the same RS. The RS's sybil detection (§2, step 3) treats them as distinct agents. The claim "one credential = one agent identity" is broken: credentials can be multiplexed, rate limits can be evaded by forking secrets, and the unlinkability guarantee is undermined because the IND-UNL-AS game assumes two distinct agents with distinct enrolled credentials — not two provers sharing a credential with different secrets.

**In-threat-model?** **No.** The fix requires binding `agentSecret` to the credential in a publicly verifiable way. The standard approach: output `agentIdentityCommitment = Poseidon(agentSecret, credentialCommitment)` as a public signal, register it at enrollment time (AS checks it matches), and have the RS verify it matches the enrollment registry. This makes `agentSecret` non-transferable without re-enrollment. Without this, credential sharing is undetectable.


## Persona: cu_ciso

### Attack 1: The AS-Free Path Destroys My NCUA Part 748 Audit Trail

- **Attack:** Section 7 ("Per-RS authorization, AS-free") explicitly removes the Authorization Server from the per-request path. That is the construction's core differentiator. But it also eliminates the only point in the OAuth stack that produces a centralized, member-identity-linked access log. What my NCUA examiner sees at the RS is: "an agent with `scopeNullifier 0xd3f7…` presented a valid ZK proof at 14:32 EST." That is a cryptographic receipt, not an audit record. NCUA Part 748.1 and GLBA §314.4(b)(3) require audit trails that map access events to member identities. The construction's unlinkability *is* the privacy guarantee — and it is structurally incompatible with the regulator's linkability requirement. These two goals conflict at the protocol layer, not the deployment layer.

- **Why it works / why it fails:** The construction survives a cryptographic adversary but fails a compliance adversary. The IND-UNL-AS game (§3) proves an adversarial AS cannot correlate proofs. But my NCUA examiner *is* the entity that needs to correlate proofs — to Alice's member record — after an incident. The `scopeNullifier` gives me per-RS pseudonymity; it gives my examiner nothing. The construction offers no mapping layer between `scopeNullifier` and member identity that is available to regulators but not to the AS-as-adversary. That mapping layer either breaks the unlinkability claim or it doesn't exist.

- **In-threat-model?** No. The construction must address how a post-incident examiner, operating under a lawful supervisory order, can reconstruct which member's agent accessed which RS at what time. A selective-disclosure path (e.g., a member-controlled reveal key that maps `scopeNullifier` to member ID, disclosed only under subpoena) is not proposed.

---

### Attack 2: Incident Response Is Forensically Blind (NCUA Appendix B to Part 748)

- **Attack:** Assume Alice's `agentSecret` is compromised — either through a breach of the AI agent operator's infrastructure or a supply chain attack on the client. The attacker presents valid `ScopedAgentAuth` proofs to CU-B and CU-C, exfiltrating loan rate data. My Tier 1 SOC detects anomalous proof volume on CU-B. Here is what I can recover: the `scopeNullifier_B` that was presented, the timestamp, the `blindedSessionTag` values. Here is what I cannot recover: which member this is, whether the same agent also hit CU-C (different nullifier, different RS — no cross-RS correlation by design), and whether to trigger NCUA Appendix B member notification. NCUA Appendix B requires notification when I have reason to believe a member's financial information was accessed without authorization. I cannot even confirm it is one member or fifty without breaking the unlinkability that is the construction's primary claim.

- **Why it works / why it fails:** The construction's §7 states revocation works via the on-chain Merkle tree — a compromised credential commitment can be removed from the tree (or a separate revocation list maintained). But revocation does not tell me *whose* data was accessed during the breach window. The `credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)` contains no member identifier — by design, to avoid leaking identity. Forensically, I have a revoked leaf commitment and a list of `scopeNullifier_B` values; I do not have "Alice Nguyen, member #00041827, was affected."

- **In-threat-model?** No. The construction must define a regulatory forensics path: either (a) a separate, AS-held mapping of `credentialCommitment → member_id` that is available only under supervisory order, or (b) acknowledgment that the construction is incompatible with Appendix B notification requirements and deployment must layer a compliant incident response mechanism on top. Neither is addressed.

---

### Attack 3: Key Custody Lives at the AI Agent Operator — GLBA Service Provider Rule

- **Attack (directly from the attack prompts):** "Key custody: where does the member secret live?" Section 7, step 1: "Alice's agent generates `agentSecret` locally — CU-A never sees it." In the cross-CU scenario, Alice's "agent" is an AI service (the construction references "AI agent negotiating auto loan rates"). In production, that agent is a hosted LLM service — Claude, GPT-4o, a fintech wrapper. The `agentSecret` is a 251-bit Baby Jubjub scalar. It lives in the memory or persistent storage of that hosted AI service at proof generation time. That AI service operator is now a third-party vendor in possession of the keying material that proves Alice's identity and authorizes financial transactions up to the `FINANCIAL_SMALL` / `FINANCIAL_MEDIUM` permission bits. Under GLBA §314.4(f), I must "oversee service providers" — contractually require them to safeguard member information and monitor their compliance. Under my Vendor Management Policy, that operator needs a risk tier, annual SOC 2 Type II review, and a data security addendum. The construction is entirely silent on this. The cryptographic unlinkability proof is valid; the vendor risk boundary is not addressed.

- **Why it works / why it fails:** The construction correctly states the AS never sees `agentSecret`. But "never seen by the AS" and "securely custodied" are orthogonal properties. If the AI agent operator is breached, `agentSecret` is extracted, and the attacker can generate valid `ScopedAgentAuth` proofs indefinitely (until revocation is processed on-chain). The construction offers no HSM requirement, no key derivation hierarchy that limits blast radius per-agent, and no specification of acceptable key storage environments. A browser localStorage implementation (trivially XSS-extractable) and an HSM-backed key enclave produce identical ZK proofs — the circuit cannot distinguish them.

- **In-threat-model?** No. The construction must specify a minimum key custody requirement — at minimum, prohibiting plaintext key storage in browser-accessible storage, and specifying that the AI agent operator must be a GLBA-compliant service provider. This is a deployment constraint, not a cryptographic one, but it gates regulatory acceptance.

---

### Attack 4: The Batching Relay and On-Chain Registry Are Uncharacterized Infrastructure with No BCP/DR

- **Attack:** Section 7, timing mitigation: "a consortium operates a batching relay that collects proof submissions… in 30-second windows and submits them in randomized order." Section 5: the on-chain root verification uses a "30-entry circular root history buffer" on Base Sepolia (§5, §7). My FFIEC CAT Maturity Domain 4 (External Dependency Management) question: what is the availability SLA for (a) the batching relay and (b) the Base Sepolia / Base mainnet sequencer? The construction explicitly acknowledges in §4 that timing mitigation is "non-cryptographic" and deployment-layer. That means the security guarantee degrades gracefully when the relay is down — the *cryptographic* unlinkability holds, but the timing side channel is live. More critically: the on-chain registry is the root of trust for *all* RS verifications. If Base mainnet sequencer goes down (it has had outages), no RS can verify any `agentMerkleRoot`, and zero authorizations can occur. My core processor SLA is 99.95% (< 4.4 hours downtime/year). A public L2 sequencer with no contractual SLA is not a credible infrastructure dependency for member-facing financial authorization.

- **Why it works / why it fails:** The construction is correct that per-RS proof verification is AS-free and thus removes the OAuth AS as a single point of failure. It introduces two new single points of failure: the batching relay (new infrastructure, zero SLA specified) and the on-chain registry (public blockchain, no contractual SLA, no BCP). The 30-entry root history buffer partially mitigates sequencer latency by allowing proofs against slightly stale roots — but it does not address extended outages. The construction must provide: (a) a specified uptime target and operator model for the batching relay, (b) a fallback authorization path if the on-chain registry is unreachable (or acknowledgment that the system degrades to total unavailability), and (c) mapping to FFIEC CAT External Dependency Management controls.

- **In-threat-model?** No. Operational availability under failure conditions and regulatory defensibility of infrastructure dependencies are not addressed. The IND-UNL-AS game proves unlinkability under adversarial cryptographic attack; it says nothing about what my examiner sees when I explain "we couldn't process member loan queries for 6 hours because Base mainnet had a sequencer incident."


## Persona: rfc7662\_advocate

---

### Attack 1: RFC 9701 Signed JWT Introspection Caches the AS Off the Hot Path — Strawman in §8

- **Attack:** §8, Claim 1 states "AS-layer unlinkability is structurally impossible in OAuth/OIDC" because every token requires an AS roundtrip. This has been false since draft-ietf-oauth-jwt-introspection-response (now RFC 9701). The AS issues a signed JWT introspection response; the RS caches and verifies it locally using the AS's public key. With a 60-second TTL, the AS is contacted exactly once at issuance and zero times during active request processing — structurally identical to the ZK construction's per-RS authorization path. Pair this with RFC 8707 audience binding (different `aud` per RS), RFC 9449 DPoP (sender-constraint without ZK), and a PRF-derived PPID (HMAC-SHA256 over `(master_key, agent_id || rs_domain)`): the AS is off the verification path, each RS sees a different pseudonym, and the AS doesn't log the PPID mapping. The construction's §8 argument is a strawman against a 2013-era introspection endpoint, not against a well-configured 2025 AS.

- **Why it fails against the construction / why it works:** The claim survives for one structural reason the attack doesn't fully close: even with cached JWTs and PRF-derived PPIDs, the AS *issued* a token for each RS at some point. In the ZK construction, the per-RS proof is generated entirely client-side with no issuance event — the AS sees one enrollment, period. The timing metadata channel (which RS triggered issuance, in what order) is permanently eliminated. Under RFC 9701, the issuance log exists; it is merely not exposed to RSes. The AS retains the full traffic graph internally. The construction's §7 CU scenario — where the issuing CU is itself the adversary monetizing the merchant graph — requires that even the issuance event be hidden. RFC 9701 does not provide this.

- **In-threat-model?** Partial. §8 Claim 1 is overstated: the correct framing is "OAuth/OIDC cannot eliminate the issuance event from the adversarial AS's log," not "AS must be on the hot path for verification." The construction survives, but §8 should be rewritten to attack issuance-time leakage, not verification-time leakage. Leaving the current framing gives ammunition to any reviewer who knows RFC 9701 exists.

---

### Attack 2: PRF-Derived PPID Is Computationally Equivalent to `scopeNullifier` — §8 Claim 2 Needs Tightening

- **Attack:** §8, Claim 2 says PPID is inferior because "PPIDs are assigned by the AS (which knows the mapping)." I can implement `PPID(rs) = HMAC-SHA256(K_ppid, agent_id || rs_domain)` where `K_ppid` is a per-agent secret generated client-side, never transmitted to the AS, and embedded in a client-authenticated TLS session. The AS receives a `client_assertion` (RFC 7521 private\_key\_jwt) and issues a PPID-bearing token without knowing `K_ppid`. From the RS's perspective this is indistinguishable from the ZK construction: different RS → different pseudonym; same RS → same pseudonym; adversary breaking cross-RS linkability must break HMAC-PRF. The computational hardness claim is identical: unlinkability reduces to PRF security. The construction's §4 reduction to Poseidon PRF has exactly the same logical structure as a reduction to HMAC-PRF under HKDF. The ZK circuit enforces *circuit-side* constraints (scope satisfaction, expiry, cumulative bit encoding) that the OAuth baseline cannot enforce without an AS-side policy check — but that is an enforcement argument, not an unlinkability argument.

- **Why it fails against the construction:** The construction's advantage is not cryptographic unlinkability per se — that's achievable with PRF-derived PPIDs. The advantage is *verifiable enforcement* without AS mediation: the RS can confirm that the agent's permission bitmask satisfies `requiredScopeMask`, that the credential is unexpired, and that the cumulative bit encoding is valid, all without trusting the AS's token contents. Under OAuth, the RS trusts the AS's introspection response or signed JWT. If the AS is adversarial (the explicit threat model in §3), the AS can issue a token claiming broader permissions than the agent was enrolled for. The ZK circuit makes overclaiming impossible — the proof is valid only if the witness satisfies the constraints over the enrolled credential. This is the load-bearing property the baseline genuinely cannot match, and §8 should lead with it rather than with the (weaker) unlinkability argument.

- **In-threat-model?** No — the construction must strengthen §8. The current framing conflates PRF-unlinkability (which both sides achieve) with verifiable-enforcement-under-adversarial-AS (which only ZK achieves). Mixing these weakens both arguments.

---

### Attack 3: IND-UNL-AS Game Definition Permits Trivial Win via Phase 1 Pre-Query Exhaustion

- **Attack:** The game in §3 states: "A chooses two distinct RSes (RS-A, RS-B) **not yet queried in this combination**." Emphasis mine — "this combination" restricts only the *pair* (RS-A, RS-B), not individual prior queries. Under this definition, A executes Phase 1 as follows:
  1. Query agent₀ → RS-A: receive `scopeNullifier₀_A = Poseidon(rsScopeId_A, agentSecret₀)` as a public output.
  2. Query agent₁ → RS-A: receive `scopeNullifier₁_A = Poseidon(rsScopeId_A, agentSecret₁)`.
  3. Query agent₀ → RS-B: receive `scopeNullifier₀_B`.
  4. Query agent₁ → RS-B: receive `scopeNullifier₁_B`.
  
  A now holds all four nullifiers. In the challenge, A selects (RS-A, RS-B) — never queried *together* but individually queried. A receives the challenge proofs containing either `{scopeNullifier₀_A, scopeNullifier₁_B}` (b=0) or `{scopeNullifier₁_A, scopeNullifier₀_B}` (b=1). A matches against its Phase 1 table and wins with advantage 1, not ε. This is not a break of Poseidon PRF; it is a break of the game formalization.

- **Why it fails against the construction:** The underlying cryptographic construction is not broken — the `scopeNullifier` is pseudorandom at fresh RSes never queried with either agent. The game simply fails to exclude the degenerate case. The correct restriction is: **challenge RSes must not have been queried with either challenge agent in any prior phase**. With this correction, the Phase 1 table attack is prohibited, and the PRF reduction in §4 goes through cleanly (the adversary has no oracle outputs for the challenge RS inputs).

- **In-threat-model?** Yes — the construction survives, but the game definition as written is unsound. It must add the restriction "RS-A and RS-B have not been queried with agent₀ or agent₁ in any prior query" to close the trivial distinguisher. This is a standard issue in PRF security game definitions and does not require modifying the circuit.

---

### Attack 4: `blindedSessionTag` Provides No Cross-RS Unlinkability — §4 Reduction Sketch Is Confused About What It Protects

- **Attack:** The §4 reduction sketch states: "The `blindedSessionTag = Poseidon(scopeNullifier, sessionNonce, scopeBlindingNonce)` adds an additional layer: even if A could detect correlations in `scopeNullifier`, the random `scopeBlindingNonce` masks it." This is incoherent. `scopeNullifier` is a **public output** of the circuit (Table 2, §2). A colluding RS-B and RS-C each receive `scopeNullifier_B` and `scopeNullifier_C` respectively as cleartext. The `blindedSessionTag` is a *separate* public output derived from `scopeNullifier_B` at RS-B — it does not hide `scopeNullifier_B`. If there were a correlation detectable between `scopeNullifier_B` and `scopeNullifier_C`, the `blindedSessionTag` at RS-B would be irrelevant because RS-C never sees RS-B's `blindedSessionTag`. The argument in §4 appears to confuse the role of `blindedSessionTag` (within-RS replay prevention, since `sessionNonce` is RS-supplied) with cross-RS unlinkability (which rests solely on the PRF security of `scopeNullifier` under distinct `rsScopeId` inputs). DPoP's `jti` mechanism (RFC 9449 §4.1) provides equivalent within-RS replay prevention without ZK. The construction's formal claim reduces correctly to P-PRF via the nullifier; the `blindedSessionTag` layer is a replay fence, not a privacy primitive, and §4 mislabels it.

- **Why it fails against the construction:** The underlying privacy claim is correct — cross-RS unlinkability holds because `Poseidon(rsScopeId_B, k) ≠ Poseidon(rsScopeId_C, k)` with pseudorandom outputs under P-PRF. The `blindedSessionTag` does serve a legitimate purpose: it prevents an RS from using the stable `scopeNullifier` as a session token by requiring a fresh per-proof commitment. But the §4 text claiming it "masks" nullifier correlations is wrong — the nullifier is public before the blinded tag is computed. The security argument needs to be restructured to cleanly separate: (a) cross-RS unlinkability ← P-PRF on `scopeNullifier`, (b) within-RS replay prevention ← freshness of `blindedSessionTag` bound to RS-supplied `sessionNonce`.

- **In-threat-model?** Yes — the construction survives, but the §4 sketch contains a false premise that a reviewer will catch immediately. The mislabeling also makes it easier for future implementors to accidentally remove `scopeBlindingNonce` on the grounds that "the nullifier already provides unlinkability," which would break within-RS session binding. Clean the argument separation before non-provisional filing.


## Persona: spiffe_engineer

---

### Attack 1: `scopeCommitment` is a persistent cross-RS correlation handle that breaks IND-UNL-AS

**Attack:**
The construction publishes `scopeCommitment = Poseidon(permissionBitmask, credentialCommitment)` as a public output of every `ScopedAgentAuth` proof (§2, Public outputs table). For a fixed agent, `credentialCommitment = Poseidon5(modelHash, opPubAx, opPubAy, permBitmask, expiry)` is a constant of the credential — it doesn't vary by RS. Therefore `scopeCommitment` is *identical* across every proof the agent generates, regardless of which RS receives it.

Two colluding RSes — say CU-B and CU-C in the credit-union scenario (§7) — receive proofs with different `scopeNullifier` and `blindedSessionTag` values (which the construction protects), but identical `scopeCommitment` values. They trivially link the two proofs to the same credential by comparing this field.

The IND-UNL-AS game (§3) is broken under its own rules: in Phase 1, the adversary queries agent₀ to *any* RS and records `scopeCommitment_0`. In the challenge phase, two proofs arrive — one from agent₀ and one from agent₁. The adversary matches `scopeCommitment_0` against the two challenge proofs and identifies agent₀'s proof with certainty. Advantage = 1/2 (trivial win), not negligible.

The reduction in §4 does not address this. It argues that `blindedSessionTag` masks the `scopeNullifier`, and that `agentSecretCommitment` is internal — but neither of those signals is what leaks. The leaking signal (`scopeCommitment`) is not `agentSecret`-derived and is not blinded. The reduction's PRF argument simply doesn't cover it.

**Why it works / why it fails:**
The construction correctly blinds `scopeNullifier` via `blindedSessionTag` but leaves `scopeCommitment` unblinded. The fix is straightforward: scope-bind the commitment as `Poseidon(rsScopeId, permissionBitmask, credentialCommitment)`, or remove it from public outputs and move scope satisfaction to a constraint-only check. Neither option requires changing the IND-UNL-AS game definition.

**In-threat-model?** **No** — the construction must address this. The claim in §8.3 ("colluding RSes see different `scopeNullifier` values and different `blindedSessionTag` values") is technically correct but incomplete. It omits the third correlation handle that colluding RSes *do* see identically.

---

### Attack 2: SPIFFE SVIDs already remove the AS from the per-request path — §8.1 overstates the delta against the actual prior art

**Attack:**
Section 8.1 asserts "AS-layer unlinkability is structurally impossible in OAuth/OIDC" and treats this as the primary differentiation. That framing is accurate against OAuth/OIDC but ignores the SPIFFE/SPIRE architecture that I run in production.

In SPIFFE: the SPIRE server does node attestation and SVID issuance on startup and on renewal (~1-hour TTL). After that, workloads authenticate to each other via mTLS using their X.509 SVID — the SPIRE server sees zero per-request traffic. The SPIRE server (the AS analog) is architecturally off the per-request path, identical to the "AS-free per-request path" described in §2. The construction's §8.1 argument applies against OAuth/OIDC, not against the infrastructure-layer identity model the construction will actually compete with at Fortune 500 deployments.

The *real* gap of SPIFFE relative to this construction is cross-RS linkability: a SPIFFE SVID carries a fixed `spiffe://trust-domain/path` identifier that every RS sees identically, enabling trivial cross-RS correlation. That gap is genuine and worth addressing. But the construction's §8 never mentions SPIFFE or WIMSE — it benchmarks exclusively against OAuth/OIDC. A staff engineer evaluating this for production deployment will immediately ask: "Why not a ZK attestor plugin for SPIRE instead?"

**Why it works / why it fails:**
The construction's core cryptographic contribution (scope-bound nullifiers, client-side agentSecret, AS-free per-request proofs) is a *real* delta over SPIFFE's unlinkability properties. But the "baseline" comparison in §8 is underspecified. A SPIFFE-aware reader will conclude the authors don't know the prior art at the infrastructure layer, which undermines trust in the security argument.

**In-threat-model?** **Partially yes** — the construction survives technically, but §8 must be revised. Add a SPIFFE/SPIRE row to the baseline comparison: acknowledge that SPIFFE already removes the AS from the per-request path, then narrow the claim to cross-RS nullifier unlinkability (the actual gap) rather than "AS-free per-request path" (which SPIFFE also achieves).

---

### Attack 3: WIMSE token exchange covers the delegation scenario — §8.5 claims a gap it hasn't demonstrated

**Attack:**
Section 8.5 claims "every delegation hop requires an AS roundtrip" under RFC 8693 (token exchange) and concludes the delegation graph is visible to the AS. I co-authored the WIMSE architecture draft (`draft-ietf-wimse-arch`), and this claim is out of date.

WIMSE workload-to-workload token exchange allows a delegating workload to present its own SVID alongside a bound token for the delegatee — the exchange can be performed peer-to-peer between workloads using self-signed tokens, without contacting an AS. The WIMSE token types draft (`draft-ietf-wimse-s2s-auth`) defines `Workload-Identity-Token` (WIT) and `Workload-Proof-Token` (WPT) bindings specifically to enable AS-less workload-to-workload delegation chains.

What WIMSE does *not* provide is cross-RS unlinkability of the delegation chain — if CU-B and CU-C both receive WITs from the same delegating workload, the workload's SPIFFE ID is visible identically to both RSes. That is the construction's actual gap to fill. But §8.5 asserts "delegation chains are AS-invisible" as a Bolyra advantage without showing that WIMSE cannot achieve AS-invisible chains — it can, under the peer-to-peer token exchange model.

**Why it works / why it fails:**
The construction adds genuine value: scope-bound nullifiers in `ScopedDelegation` make the *identity* of the delegatee unlinkable across RSes, not just the AS involvement. But the framing in §8.5 claims a broader advantage than the evidence supports. The adversary (or a WIMSE WG reviewer) will reject the "why the baseline cannot match" argument on this point, weakening the overall credibility of §8.

**In-threat-model?** **No** — §8.5 must be revised to distinguish WIMSE peer-to-peer delegation (which achieves AS-invisibility) from cross-RS delegatee-identity unlinkability (which WIMSE does not achieve and Bolyra does). The claim survives with a narrower, accurate scope.

---

### Attack 4: The `agentMerkleRoot` is a global public constant — its Merkle path *length* leaks credential epoch

**Attack:**
The `agentMerkleRoot` (public output, §2) is the root of the global on-chain agent Merkle tree at depth 20. It is shared across all agents and changes whenever any new credential is inserted. This is correctly designed — a single global root leaks no per-agent information.

However, the on-chain root history buffer (30-entry circular buffer, §5 Bolyra primitive mapping) creates a timing oracle. The construction requires the prover to use a root from the history buffer (to handle latency between Merkle tree updates and proof generation). An adversarial AS that observes (a) the sequence of Merkle tree insertions on-chain and (b) which root value a proof uses can bound the proof's generation time to a specific 30-slot window. In the credit-union scenario (§7), if CU-A inserts Alice's credential as insertion #8,432, and the buffer holds 30 roots, then any proof using roots #8,432–#8,462 was generated within that window. If CU-A counts its own insertions relative to other agents' insertions, it can narrow the epoch of when Alice's agent contacted CU-B or CU-C, even without seeing the proof content.

This is distinct from the timing side channel acknowledged in §4 ("deployment-level mitigation requires fixed-interval proof batching"). That mitigation addresses submission timing to the RS. This attack uses the *root selection* as a timing signal visible to the AS via the public blockchain — no network observation required.

**Why it works / why it fails:**
The construction's §4 correctly excludes timing from the formal IND-UNL-AS game, acknowledging non-cryptographic timing side channels. But the Merkle root epoch attack is partially cryptographic: the public output `agentMerkleRoot` + the public chain state allows the adversarial AS to bound *when* (not *to whom*) the proof was generated. For the healthcare scenario (§7.2), this may violate HIPAA minimum-necessary if the adversary infers referral timing from root epochs.

Mitigation: enforce that provers always use the *oldest valid root* in the buffer (maximizing epoch ambiguity to 30-slot window) and document the residual timing disclosure in §4 as a known limitation alongside the formal game.

**In-threat-model?** **Partially yes** — the formal IND-UNL-AS game excludes timing by design, so the *cryptographic* construction survives. But the threat model statement in §3 says "Network-level metadata: timing of proof submissions, proof sizes, RS endpoints contacted" is in scope — it does not mention root-epoch timing from on-chain state, which the adversarial AS can observe passively without any network observation. The threat model must be expanded to include on-chain observable signals, or explicitly exclude them with justification.
