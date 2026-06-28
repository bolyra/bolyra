# Tier 3 Adversarial — C1 Selective scope proof

## Persona: auth0_pm

### Attack 1: The Latency Tax Is a Non-Starter

- **Attack:** Section 6 admits T_prove = 500 ms (rapidsnark) or 3 s (snarkjs) per auth check, AND the constant-time discipline from Section 2 mandates agents spend the full T_prove even on successful proofs. More damaging: `currentTimestamp` is a RS-supplied public input, which means proofs cannot be cached — every RS interaction requires a fresh proof generation. A typical loan pre-qualification workflow makes 30–80 downstream API calls. At 500 ms per call, that's 15–40 seconds of mandatory ZK proving overhead per workflow. WorkOS issues an introspection response in <100 ms (cached JWT-introspection-response, RFC 8693 token exchange). That is a 5–40x latency multiplier, compounding per call.

- **Why it works against the construction:** The construction does not propose proof reuse, batching, or session-scoped caching. It explicitly ties each proof to a `currentTimestamp` supplied by the RS, making the proof single-use. Section 7 cites a consortium loan scenario but never quantifies per-workflow latency or proposes a mitigation. The circuit cost table (Section 6) gives single-proof numbers; there is no discussion of pipelining or pre-proving.

- **In-threat-model?** No. The construction must address this. Either: (a) define a `proofTTL` window where the RS accepts proofs generated within N seconds (at the cost of weakening freshness), (b) propose a session token issued after first successful proof (collapsing to a hybrid model the construction criticizes), or (c) quantify the workflow latency and explain why the tradeoff is acceptable to operators.

---

### Attack 2: Blockchain Dependency Trades One SPOF for Another

- **Attack:** Section 1 claims adversarial-AS soundness and Section 7 motivates the construction with "CrowdStrike-style outage, Columbia CU's AS goes offline for 14 hours." But the RS must read `onChainAgentRoot` from the Bolyra on-chain registry (Base L2) to fill the public input in step 2 of the verification protocol. Base L2 (Optimism-based) has had sequencer outages. When the sequencer is down, no new roots are published; the RS falls back to its 30-entry root history buffer. That buffer covers historical roots, not a guaranteed freshness window — the construction does not specify how frequently roots are published or what the maximum staleness is before the buffer is exhausted. An RS operator who must verify agent credentials during a Base L2 outage faces identical lockout to the "AS offline" scenario the construction promises to solve. Cloudflare Access with workers-kv caches tokens globally across 300 PoPs with <5 ms read latency and a 99.99% SLA — no blockchain dependency.

- **Why it works against the construction:** Section 5 maps `onChainAgentRoot` to "BolyraRegistry with 30-entry root history buffer" but provides no liveness guarantee or fallback. The construction's own adversary model (Section 3) says "The adversary does NOT control the on-chain registry (Ethereum/Base L2 consensus assumptions)" — but this only holds while the chain is live. The CrowdStrike-scenario motivation is directly undercut by introducing a different infrastructure dependency with no uptime SLA.

- **In-threat-model?** No. The construction must specify: (a) root publication frequency and maximum buffer coverage window, (b) RS behavior during root staleness (hard-reject, soft-reject, or fallback), and (c) how this availability guarantee compares to Auth0/WorkOS SLAs.

---

### Attack 3: Constant-Time Discipline Is SDK Policy, Not Protocol Enforcement

- **Attack:** Section 2's "rejectIndistinguishably" mechanism requires agent developers to invoke the SDK's `proveSelectiveScope()` wrapper — which enforces `T_prove` budgeting via `sleep()` — rather than calling the underlying prover directly. The circuit itself (G1–G9) does not enforce timing; it only checks constraint satisfaction. Any agent developer who wraps the snarkjs/rapidsnark call directly, adds logging between the prover call and the response, or deploys in a serverless environment with a 1-second execution timeout will bleed timing. The formal privacy argument in Section 4 assumes "Challenger returns... after exactly T_prove wall-clock time" — but in production the adversary is a real RS querying a real agent, not a game-theoretic challenger. The privacy bound `|Pr[A wins] - 1/2| <= Adv_PLONK_zk` only holds when the timing assumption holds. When it does not, the 64-query single-bit sweep from Section 3's attack discussion succeeds exactly as described — 64 binary observations fully recover the bitmask.

- **Why it works against the construction:** Section 2 explicitly says agents "MUST implement" this behavior but provides no enforcement mechanism beyond documentation and SDK defaults. Compare to TLS constant-time crypto where the property is in the implementation of the cryptographic primitive, not in caller discipline. The construction's threat model defines a chosen-predicate adversary who can query the honest agent — this adversary can probe from outside the SDK wrapper. A consortium partner RS probing the agent does not care whether the agent is using the official SDK; it observes wall-clock response times.

- **In-threat-model?** Partially. The construction identifies the timing attack (Section 7, consortium scenario) and proposes the mitigation, but fails to identify that the mitigation is unenforced. The construction must address enforcement: either (a) move the constant-time guarantee into the circuit/proving system (not possible at current circuit level), (b) mandate a proxy/middleware layer that enforces timing before responses reach the network (deployable, but adds infrastructure), or (c) acknowledge the timing guarantee as a deployment recommendation rather than a security property, and adjust the formal claim accordingly.

---

### Attack 4: The Buyer Cannot Evaluate the Trust Root

- **Attack:** Section 4's security argument depends on PLONK knowledge soundness, Poseidon collision resistance over BN254, Baby Jubjub discrete log, and EdDSA-Poseidon unforgeability. The construction's Section 8 tells credit union IT procurement that the new trust root is "the on-chain Merkle tree contains this commitment, the operator's signature is valid, and the bitmask satisfies the predicate — verified inside a zero-knowledge proof." The buyer cannot evaluate this. WorkOS answers procurement with: SOC 2 Type II report (audit firm: Ernst & Young), HIPAA BAA, PCI-DSS SAQ-A, $200M ARR, 100+ named enterprise customers, enterprise SLA with financial penalties, and a legal entity with D&O insurance. Bolyra's answer requires the CISO to assess whether Poseidon's resistance over BN254 is adequate, whether the PLONK trusted setup (`pot16.ptau`) was correctly generated, whether Circom constraint encoding is bug-free, and whether the solo-founder will exist in 18 months to patch a circuit bug. The procurement question "you are a solo founder" is not answered by the construction anywhere — not in the threat model, not in the deployment scenario, not in the regulatory alignment section.

- **Why it works against the construction:** This is not a cryptographic attack — it is a GTM attack the construction structurally cannot rebut within its own scope. Section 7 cites "NCUA Letter to Credit Unions 24-CU-03" and "FFIEC 2025 guidance on API security" as regulatory alignment, but those documents do not endorse ZK-proof-based authorization or certify any Circom circuit. A credit union's examiner will ask for a SOC 2 report that covers the Bolyra infrastructure — not a citation to regulatory guidance. The competitive landscape (Auth0 AI, WorkOS MCP auth, Stytch Connected Apps) all have or are actively pursuing SOC 2 + FedRAMP + HIPAA certifications. The cryptographic superiority of the construction is irrelevant if the buyer cannot take it to their board.

- **In-threat-model?** No — by design. The construction is a cryptographic specification, not a go-to-market document. But the adversary persona is a senior PM whose customers will raise this objection on day one. The construction must acknowledge this gap explicitly and propose a path (e.g., third-party circuit audit from Trail of Bits, SOC 2 scope that covers key management and on-chain registry operations, consortium co-sponsorship with a named CUSO). Without this, the five-property claim is moot — the buyer will never reach the evaluation stage.


## Persona: cryptographer

Applied cryptographer. If your security argument has a gap I can fit a truck through, I'll find it. Let me work through this construction.

---

### Attack 1: Privacy Game Is Trivially Broken by Public Nullifier

**Attack:** In the ChosenPredicateScopeExtraction challenge phase (Section 3, tightening note), the adversary enrolls both `C0* = Poseidon5(..., B0, ...)` and `C1* = Poseidon5(..., B1, ...)`. When the challenger generates the challenge proof for bitmask `Bb`, the proof's **public output** includes:

```
agentNullifier = Poseidon2(credentialCommitment_b, requiredScopeMask)
```

The adversary already knows both `C0*` and `C1*` (stated explicitly in the tightening note). It computes:

```
N0 = Poseidon2(C0*, R_challenge)
N1 = Poseidon2(C1*, R_challenge)
```

It observes the proof's public output `agentNullifier`. By collision resistance of Poseidon (Assumption 2, the very assumption the construction invokes), `N0 ≠ N1` with overwhelming probability. The adversary checks which matches and recovers `b` with advantage `1 - negl(λ)` — not `Adv_PLONK_zk` as claimed.

**Why it works:** ZK only hides the witness — it does not hide the public outputs. `agentNullifier` is a public output that is a deterministic, computable function of the private `credentialCommitment`. The construction acknowledges the adversary can compute both candidate nullifiers, then incorrectly concludes this "reduces to distinguishing the PLONK proof pi itself." That reduction is invalid: the adversary does not need to analyze `pi` at all. The distinguisher is entirely in the public signal, not the proof.

The Section 4 privacy reduction says "Replace the real prover with Sim for the challenge proof; A's advantage drops to Adv_PLONK_zk." This argument fails because the simulator must also produce the correct public outputs, which are uniquely determined by `b`. No PLONK ZK property can hide a value that is a public output.

**In-threat-model?** Yes — the adversary specified in the game controls C0*, C1*, and observes all public outputs. **Construction must address this.** The privacy game as stated is unsound. A fix requires either (a) replacing the nullifier with a blinded variant (e.g., `Poseidon3(credentialCommitment, requiredScopeMask, randomness)` with `randomness` as a private input, publishing only a commitment to it) or (b) restricting the game to a single-commitment model where B0 and B1 differ only in bits the chosen predicates cannot distinguish — i.e., abandoning the tightening note entirely and tightening in a different direction.

---

### Attack 2: Subverted SRS Collapses All Soundness Claims

**Attack:** The construction uses PLONK with `pot16.ptau` (Section 5, Section 6). PLONK is not transparent. Its soundness relies entirely on the SRS being honestly generated — specifically, that the toxic waste (`τ`, the secret trapdoor) was not retained by any participant in the Powers of Tau ceremony.

An adversary holding `τ` can compute a "simulated proof" for **any** circuit statement, satisfying or not. Concretely, for `SelectiveScopeProof`, an adversary with `τ` can produce an accepting proof `π*` where G5 constraints are NOT satisfied — i.e., a credential whose `permissionBitmask & requiredScopeMask ≠ requiredScopeMask` but whose proof passes `Verify(vk, π*, pubSignals) = ACCEPT`. This directly wins SelectiveScopeForgery.

The construction's threat model (Section 3) lists what the adversary controls: the AS, network position, up to N-1 agents. It conspicuously omits the SRS setup as an attack surface. The reduction sketch in Section 4 invokes "knowledge soundness of PLONK (with universal SRS)" as Assumption 1, qualified with "with universal SRS" — but never states what honesty assumptions on the ceremony are required, who ran the ceremony, or whether a transcript is publicly auditable.

The "adversarial-AS soundness" claim (Property 3, Section 8) states that "even a fully compromised AS cannot forge a valid proof." This is true *conditional on SRS integrity*, which is a separate and unstated trust assumption at least as strong as trusting the AS. The construction rhetorically moves trust from the AS to the on-chain Merkle tree, but silently imports equivalent trust in the ceremony participants.

**Why it works / fails:** There is no construction-specific ceremony referenced. `pot16.ptau` refers to a general Powers of Tau artifact. If this is a public multi-party ceremony with a published transcript (e.g., Hermez, Zcash), the adversary must corrupt ALL participants — a strong but unstated assumption. If it is an internal ceremony, a single compromised party breaks everything. Either way, this is a threat model omission, not a cryptographic proof.

**In-threat-model?** No — subverted setup is not in the adversary model. **Construction must address this** by (a) naming the specific ceremony and linking the public transcript, (b) specifying the SRS corruption model (one-of-N honest suffices, etc.) and extending the security game to cover setup phase adversaries, or (c) migrating to a transparent proving system (FRI-based, e.g., STARK) that eliminates the setup assumption entirely — consistent with the post-quantum roadmap many deployments require anyway.

---

### Attack 3: Response-Size Side-Channel Survives Constant-Time Budgeting

**Attack:** Section 2 specifies constant-time discipline: both accepted proofs and rejected predicates return after exactly `T_prove` wall-clock time. The threat model includes a network adversary who "can observe all RS-agent traffic, including timing." The construction's argument in Section 4 claims `SD(D_accept, D_reject) = 0` because both response-time distributions are `δ(T_prove)`.

This is true of timing. It is not true of **response size**.

- Accepted proof response: `{"proof": "<768-byte PLONK proof>", "scopePredicateHash": "<32 bytes>", "agentNullifier": "<32 bytes>"}` — approximately 1,100 bytes of JSON, or ~900 bytes of binary encoding.
- Rejected predicate response: `{"error": "scope_insufficient", "retry_after": <int>}` — approximately 60 bytes.

These produce different TLS record counts and sizes. A network adversary with passive access to the TLS stream observes different payload patterns at the TLS layer even though the application-layer timing is identical. This is not a theoretical concern: TLS record size leakage is the mechanism behind CRIME, BREACH, and HEIST attacks.

Concretely, the bit-extraction attack the construction claims to defeat (Section 3 privacy game discussion, Section 7 scenario step 4) can be mounted as follows: submit `requiredScopeMask = 2^i` for each `i ∈ [0, 63)`. Wait `T_prove` for each. Observe whether the response carries ~900 bytes (bit `i` is set) or ~60 bytes (bit `i` is not set). Recover the full 64-bit bitmask in 64 queries — the same attack the construction claims "fails under this game."

**Why it works:** The constant-time claim in Section 4 addresses exactly one distinguishing channel: wall-clock response time. The adversary in the threat model has network position, which grants access to packet sizes and TLS record sizes. These are orthogonal distinguishing channels. The SDK's `proveSelectiveScope()` method returning `Result<Proof, ScopeError>` where `ScopeError` is a unit type prevents application-layer payload leakage, but the transport layer still leaks.

**In-threat-model?** Yes — "Network position — can observe all RS-agent traffic, including timing" is explicitly listed. **Construction must address this.** Fixes include: (a) padding all responses (accepted or rejected) to a constant size before transport, (b) using a response format where rejected proofs are padded to 768 bytes of indistinguishable random bytes, or (c) revising the threat model to exclude network-layer side-channels and explicitly acknowledging this as a deployment-time countermeasure requirement.

---

### Attack 4: `currentTimestamp` Is RS-Controlled — No Proof Freshness

**Attack:** The RS supplies `currentTimestamp` as a public input (Section 2, public inputs table). The circuit enforces `currentTimestamp < expiryTimestamp` (G7). There is no constraint binding `currentTimestamp` to actual wall-clock time. The construction provides no freshness mechanism equivalent to RFC 9449's DPoP nonce or OAuth 2.0's `jti` / replay detection.

Two concrete adversarial scenarios:

**4a — Proof replay by a compromised RS:** An RS that caches a valid `(π, pubSignals)` tuple from a previous presentation (say, `currentTimestamp = T_yesterday`) can present this cached proof to a downstream service as if it were generated now. The `scopePredicateHash = Poseidon3(requiredScopeMask, credentialCommitment, T_yesterday)` binds the predicate to `T_yesterday`, but downstream services that only call `Verify(vk, π, pubSignals)` cannot detect staleness — `pubSignals` contains `T_yesterday` as the timestamp, and the proof remains valid indefinitely until `expiryTimestamp` is reached.

The construction's Section 5 nullifier pattern (`agentNullifier` enables "rate-limiting") does not address replay, only duplicate-proof detection within a single RS's nullifier table. Cross-RS replay is unaddressed.

**4b — Clock-skew expiry bypass:** An RS supplying `currentTimestamp = 0` causes G7 to accept any credential with `expiryTimestamp > 0` — including credentials the operator intended to expire at Unix timestamp `1` (effectively immediately). There is no lower bound on `currentTimestamp` enforced anywhere in the circuit. The construction's expiry enforcement is entirely conditional on the RS supplying an honest `currentTimestamp`.

**Why it works:** The threat model says the RS is not adversarial in the soundness game — the adversary controls the AS, not the RS. But in the privacy game (chosen-predicate model), the RS IS the adversary issuing chosen predicates. The privacy game says nothing about the RS supplying honest timestamps. A chosen-predicate adversary that also controls `currentTimestamp` can probe with `currentTimestamp = expiryTimestamp - 1` to test exactly one credential expiry boundary, or `currentTimestamp = 0` universally.

More fundamentally: even with an honest RS, proof replay across RSes is not addressed anywhere in the formal model. Section 8's "Property 1: AS-blind presentation" specifically touts that no AS roundtrip is needed — but the AS roundtrip in RFC 7662 also serves a freshness function (the AS can revoke or time-bound tokens between queries). Removing the AS roundtrip without a replacement freshness mechanism (e.g., RS-supplied per-request nonce committed inside the proof) creates a new attack surface.

**In-threat-model?** Partially. Proof replay across RSes is not modeled in either the soundness or privacy game, making it an unclaimed (and unaddressed) property. The RS timestamp-supply issue lies in the privacy game's adversary model. **Construction must address this** by either (a) adding an RS-supplied session nonce to the public inputs and constraining `sessionNonce` inside the proof (similar to the existing handshake `sessionNonce` in `AgentPolicy.circom`), or (b) explicitly scoping the threat model to exclude replay and acknowledging this as a deployment-layer responsibility.


## Persona: cu_ciso

---

### Attack 1: Operator Key Custody — Where Does the Signing Key Live?

- **Attack:** Section 2 defines `operatorPubkeyAx / operatorPubkeyAy` as public inputs and `sigR8x, sigR8y, sigS` as a private EdDSA signature over the credential commitment. This means somewhere — on the agent host, in a secrets manager, in memory — there is an operator private key that signs credentials. The construction never names where this key lives, how it is rotated, or what the breach-response procedure is.

  I ask the author: is this key in the browser? A `.env` file? An HSM? If the operator key is exfiltrated, an adversary can sign arbitrary credentials and enroll them via the Merkle tree update path. The on-chain root doesn't save you — a legitimate enrollment of a fraudulent credential looks identical to a legitimate enrollment of a legitimate credential.

- **Why it works:** The construction's soundness reduction (Section 4) assumes the adversary cannot forge an EdDSA signature without the operator key. That's correct cryptographically. But it says nothing about key custody operationally. NCUA Part 748 Appendix A, Item 5 requires the credit union's information security program to address "access controls" for systems that process member data. GLBA Safeguards Rule (16 CFR § 314.4(c)) requires the CU to oversee service providers' safeguards. "The circuit is sound" is not a key management policy. My examiner will ask for a Key Management Plan, an HSM certification, and a rotation schedule. The construction provides none of these.

- **In-threat-model?** No — the construction explicitly excludes operator key compromise from the adversary model ("The adversary does NOT control… the honest agent's private inputs (secret, operator key)"). The construction must address this: specify HSM requirement, key rotation protocol, and what "on-chain enrollment update" looks like when a key is rotated.

---

### Attack 2: The Audit Trail Is a 768-Byte Blob My Examiner Cannot Read

- **Attack:** Section 7 claims "NCUA examiners reviewing consortium data-sharing agreements can verify that only cryptographically proven minimum-necessary permissions were exercised at each access point." I call this bluff. Show me the examiner workflow. An NCUA exam produces a Document of Resolution or a Matter Requiring Attention. My examiner opens an evidence packet. What is in it?

  The construction produces: a 768-byte PLONK proof, a `scopePredicateHash` (`Poseidon3(requiredScopeMask, credentialCommitment, currentTimestamp)`), and an `agentNullifier`. My examiner does not run `snarkjs.plonk.verify()`. My examiner reads a spreadsheet. The construction's privacy guarantee — opaque `scope_insufficient` errors, no payload beyond a unit-type `ScopeError` — means the audit log for a DENIED access is identical for: (a) wrong permissions, (b) expired credential, (c) stale Merkle root, (d) network error. Section 2 explicitly states this is by design.

  NCUA Letter 24-CU-03 is cited as if it mandates ZKP. It does not. It mandates documented third-party AI risk controls, monitoring, and periodic review. GLBA Safeguards § 314.4(h) requires "regular testing or monitoring of the effectiveness of your safeguards' key controls." How do I test this? How do I demonstrate to my examiner that the minimum-necessary principle was enforced, if my logs contain only `scopePredicateHash` values that require a PhD to interpret?

- **Why it works:** The construction optimizes for cryptographic privacy and correctness. It does not address the artifact layer — the human-readable audit record that maps `agentNullifier = 0x3f7a...` to "agent acting for Columbia CU accessed loan pre-qualification endpoint at 14:32:07 UTC with READ_DATA | FINANCIAL_SMALL, DENIED because SUB_DELEGATE predicate not satisfied." Without this translation layer, the CU cannot produce exam-ready evidence.

- **In-threat-model?** No — audit trail readability is outside the formal security model entirely. The construction must address this: specify a logging schema that maps on-chain events and local RS logs into NCUA-presentable evidence without compromising the ZK privacy guarantee (log the predicate outcomes, not the bitmask).

---

### Attack 3: Credential Revocation Window vs. 36-Hour Breach Notification

- **Attack:** An agent credential is compromised — operator key leaked, agent host breached, or insider threat. I need to revoke it NOW. What does the construction's revocation path look like?

  The RS caches `onChainAgentRoot` and validates proofs against it. The construction specifies a "30-entry root history buffer" in the `BolyraRegistry` (Section 5). Revocation requires: (1) removing the credential commitment from the on-chain Merkle tree, (2) submitting an on-chain transaction that updates the root, (3) waiting for Base L2 confirmation (~2 seconds optimistically, minutes under congestion), (4) waiting for RSes to refresh their cached root. Steps 3 and 4 are not bounded anywhere in the construction.

  During the window between compromise detection and RS cache refresh, the compromised credential remains valid at every partner RS caching an old root. The 30-entry root history buffer actually WIDENS this window — RSes can accept proofs against any of the 30 most recent roots.

  NCUA Part 748 Appendix B requires notification of a reportable cyber incident within 36 hours of discovery. GLBA Safeguards § 314.15 requires a written incident response plan. My incident response plan for a compromised agent credential needs a guaranteed revocation SLA. The construction provides none. "The blockchain will update eventually" is not an SLA.

- **Why it works:** This is an architectural gap, not a cryptographic one. The Merkle tree construction is sound. But revocation in Merkle trees requires updating all valid roots, and the 30-entry history buffer means up to 30 "old valid roots" remain usable until flushed. The construction does not specify a maximum root age, a forced root flush mechanism, or an RS-side revocation check (e.g., a nullifier blocklist for revoked commitments).

- **In-threat-model?** No — the adversary model assumes the on-chain registry reflects truth and that compromised credentials are out of scope. The construction must address this: specify a maximum cache TTL, a revocation nullifier list that RSes MUST check before accepting any proof, and a documented SLA for "credential revoked → all RSes reject within T minutes."

---

### Attack 4: Operational Indistinguishability Breaks My 2am Triage

- **Attack:** Section 2 (predicate rejection behavior) states the mandatory behavior: all failures return the same opaque `{"error": "scope_insufficient", "retry_after": <backoff>}` — whether the predicate is unsatisfied, the credential is expired, the Merkle root is stale, or the rapidsnark binary crashed. This is the same error. By design.

  My Tier 1 ops team gets a 2am alert: 800 loan pre-qualification requests failing across the consortium. The error is `scope_insufficient`. My ops team opens the runbook. The runbook says: ???

  Is the problem: (a) the agent's credential expired and nobody renewed it? (b) the on-chain registry root is stale because Base L2 had a sequencer hiccup? (c) the rapidsnark binary on the agent host is OOM-killed? (d) the partner RS updated their `requiredScopeMask` without coordinating with us? (e) the operator key was rotated but the new credential wasn't enrolled? These five failure modes have completely different remediation paths. The construction deliberately makes them indistinguishable at the RS-facing API layer.

  FFIEC Cybersecurity Assessment Tool, Domain 3 (Cyber Risk Management) requires operational resilience with documented escalation paths. A system where all error conditions produce the same opaque response is not operationally resilient — it is operationally blind.

  The construction correctly argues (Section 2) that this indistinguishability is necessary to prevent bit-extraction timing attacks. I accept the cryptographic argument. But "we need this for security" and "this is deployable in a regulated CU" are two different claims. The construction makes both claims simultaneously without resolving the conflict.

- **Why it works:** There is a genuine tension here that the construction does not acknowledge. The constant-time opaque rejection protocol is cryptographically correct. It is also operationally hostile. A deployment that is secure but not operable will be bypassed — ops teams will add diagnostic logging, add timing instrumentation, or fall back to a plaintext permission check "just for debugging." The construction needs a separate operator-facing diagnostics channel (e.g., signed, encrypted diagnostic payloads to the credential issuer, not the RS) that preserves RS-facing privacy while giving ops teams triage capability.

- **In-threat-model?** No — operational ergonomics are outside the formal model. The construction must address this: specify a diagnostics channel architecture that gives the credential-owning operator (Columbia CU's ops team) structured error codes while preserving RS-facing opacity. Without this, the security property will be eroded in production by well-meaning ops staff within the first 90 days.


## Persona: rfc7662_advocate

---

### Attack 1: Per-RS Introspection Policy Already Achieves Selective Disclosure Without ZK

**Attack:** Section 8, Property 1 ("AS-blind presentation") and Property 2 ("runtime-adaptive predicate") are undermined by a well-configured AS with per-RS introspection scope filtering.

RFC 7662 §2.2 leaves the introspection response content to AS policy. A production AS (Keycloak, Okta, Auth0, or a custom implementation) can maintain a scope allow-list per registered RS: when RS-A introspects, it receives only `["read_data", "financial_small"]`; when RS-B introspects, it receives only the scopes RS-B is permitted to learn about. Combined with draft-ietf-oauth-jwt-introspection-response (signed, encrypted JWT response), the RS can verify offline — the AS is not in the hot path after the first signed response is cached. RFC 8707 resource indicators bind the token to the intended RS audience, so a token presented to the wrong RS is structurally invalid.

The net result: RS-A learns only the bits relevant to RS-A at issuance time, the AS's signed response provides offline verifiability, and audience binding prevents cross-RS replay — all without ZK. The construction's counter-argument is "adversarial AS," but the adversarial-AS threat is precisely the threat the per-RS policy architecture is designed to address: the AS can be audited, the policy tables are inspectable, and in a consortium of 12 credit unions, the AS can be operated as a federated multi-party system (RFC 8693 token exchange across trust domains) rather than a single point of trust.

**Why it partially fails against the construction:** Selective disclosure via AS policy is *issuance-time*, not *presentation-time*. The RS cannot supply an arbitrary `requiredScopeMask` at verification time and have the credential system evaluate it dynamically — that predicate must have been baked into the introspection policy before the token was issued. The construction's runtime-adaptive predicate (Section 2, "RS supplies `requiredScopeMask` as a public input") is genuinely novel here.

**In-threat-model?** **Partially.** The construction survives on runtime-adaptivity, but Section 8 Property 1 overstates the AS-blind advantage. The construction must explicitly acknowledge that for the non-adversarial-AS case, per-RS introspection policy with jwt-introspection-response is a complete substitute for Properties 1 and 4 and is operationally simpler. The adversarial-AS argument only justifies the construction for a narrower threat model than is advertised.

---

### Attack 2: The 64-Query Bitmask Oracle Is Deployment-Equivalent to Full Disclosure

**Attack:** Section 3 formally admits the single-bit extraction attack succeeds — the construction reframes this as "optimal privacy" by appeal to the game's consistency constraint. But this reframing does not survive operational scrutiny.

Any RS in the consortium can learn the agent's full 64-bit permission bitmask by issuing 64 sequential single-bit predicate queries: `requiredScopeMask = 2^0, 2^1, ..., 2^63`. The construction correctly notes this is not a "privacy violation" under the formal game (Section 3, "Why the naive 64-query attack fails") because the game's consistency constraint forces B0 = B1 if all bits have been probed. But the game is constructed specifically to exclude this attack from counting as a violation. In practice, the attacker (a malicious RS) doesn't need the formal-game framing to do real damage: 64 queries × T_prove (500 ms with rapidsnark) = 32 seconds of probing, and the attacker has the full bitmask.

RFC 7662 with per-RS filtered introspection requires *one* roundtrip and reveals *only* the bits the policy allows. The construction requires 64 roundtrips and reveals *every* bit — at a cost of 32 seconds — while calling this "optimal." The Section 7 concrete scenario describes a malicious partner CU probing with `requiredScopeMask = 0b01000000` (one bit); the correct attack is simply probing all 8 bits in 8 queries. Section 7 never addresses this 8-query (not 64-query) full-disclosure case, which takes 4 seconds with rapidsnark and reveals the entire 8-bit permission set used in the credit union scenario.

**Why it fails against the construction:** It doesn't. The construction explicitly concedes (Section 3): "an adversary issuing `q` adaptive predicate queries learns at most `q` bits." For an 8-bit or 64-bit bitmask, `q = 8` or `q = 64` is the optimal attack, and it works.

**In-threat-model?** **Yes — construction must address.** The construction must either (a) bound the RS's query budget (rate-limiting via `agentNullifier` is mentioned in step 5, but not tied to bitmask-exhaustion prevention) or (b) drop the claim that the RS "learns nothing about unqueried bits" in contexts where the RS can repeat queries. The agentNullifier is scoped to `Poseidon2(credentialCommitment, requiredScopeMask)` — a distinct nullifier per predicate — so a 64-query sweep produces 64 distinct nullifiers and the rate-limit table is trivially circumvented. This is a gap in Section 2's verification protocol step 5.

---

### Attack 3: Structural Revocation Lag Inverts the Availability Argument

**Attack:** Section 7 Property 3 ("adversarial-AS soundness") and the concrete scenario cite AS unavailability as a key Bolyra advantage ("During a CrowdStrike-style outage, Columbia CU's AS goes offline for 14 hours"). But the construction's on-chain revocation model has a structural lag that RFC 7662 does not.

Section 5 states the `BolyraRegistry` maintains a "30-entry root history buffer" of valid Merkle roots. The construction never specifies (a) the L2 block time governing root transitions, (b) the policy for how quickly a revoked credential's commitment is excluded from all roots in the buffer, or (c) what an RS must do when the on-chain state is unavailable (the same availability threat the construction uses against the AS). A credential revoked at block N remains provable against any of the 30 historical roots — roots at blocks N-1, N-2, ..., N-29. On Base (L2, ~2s block time), this is a revocation lag of up to 60 seconds if the RS accepts any root in the buffer; if the RS caches the root locally (as step 1 of the verification protocol implies), the revocation lag extends to the RS's cache TTL.

RFC 9449 DPoP + RFC 7662 with a 60-second token lifetime and real-time introspection provides *immediate* revocation: the AS returns `active: false` on the next introspection, and the RS rejects. The construction trades immediate revocation for AS-availability independence — a tradeoff that is not acknowledged in Section 8 and may be unacceptable under NCUA supervisory expectations for timely revocation of compromised AI agent credentials.

**Why it fails against the construction:** The construction has no explicit answer. The 30-entry root history buffer is a deliberate design choice (enabling proof generation against recent roots without requiring the agent to update its Merkle witness on every block), but it structurally creates a revocation window. The Section 7 regulatory alignment claim ("NCUA examiners reviewing...") is weakened by an unspecified revocation lag.

**In-threat-model?** **Yes — construction must address.** The construction should specify maximum acceptable root history depth as a function of revocation SLA, and acknowledge the revocation-lag tradeoff explicitly in Section 8 rather than presenting AS-availability as a one-sided advantage.

---

### Attack 4: Trust Root Substitution — Blockchain Validators Are Not Strictly More Trustworthy Than a Consortium AS

**Attack:** Section 8 Property 3 ("adversarial-AS soundness") moves the trust root from "the AS said so" to "the on-chain Merkle tree + blockchain consensus." The construction presents this as categorically superior. It is not — it substitutes one trust assumption for a different set of trust assumptions, some of which are worse for the stated deployment.

The concrete deployment (Section 7) is 12 Pacific Northwest credit unions sharing a federated data lake. For this deployment to use `SelectiveScopeProof`, every RS at every partner CU must:

1. Trust Base L2's sequencer (currently a centralized Optimism-stack sequencer operated by Coinbase) not to censor, reorder, or manipulate Merkle root updates to the `BolyraRegistry`.
2. Trust the `BolyraRegistry` smart contract to have no exploitable bugs — a newly deployed contract with no audit history equivalent to a decade of RFC 7662 implementations.
3. Accept that the operator's EdDSA key (not the AS, but functionally equivalent to an issuance authority) is not compromised. G3 verifies the operator signature, but if the operator key is stolen, the adversary can issue unlimited credentials with arbitrary permission bitmasks — the same attack possible against a compromised AS, but now without the revocation mechanisms that a well-operated AS provides (key rotation, token invalidation, audit logs).
4. Maintain RPC connectivity to Base L2 to read `onChainAgentRoot`. If Base's RPC endpoints are unavailable — the same availability argument used against RFC 7662 in Section 7 — the RS cannot refresh its root cache, and credential verification degrades to stale-cache behavior with unknown security properties.

A consortium of NCUA-regulated credit unions operating a federated OAuth AS (with RFC 8693 trust federation across institutions) has 30+ years of operational precedent, regulatory guidance, and auditor familiarity. The construction's trust model requires NCUA examiners and consortium auditors to understand ZK soundness assumptions, Poseidon collision resistance, Baby Jubjub DL hardness, and L2 sequencer trust — none of which appear in the FFIEC IT Examination Handbook.

**Why it partially fails against the construction:** In the *adversarial-AS* threat model specifically — where one consortium member's AS is actively malicious, not merely unavailable — the blockchain trust model is genuinely stronger, provided Base L2 is not itself compromised. The construction's formal security argument (Section 4) is sound under its stated assumptions.

**In-threat-model?** **Partially.** The construction survives in the narrow adversarial-AS subcase. But the construction's framing in Section 8 ("The baseline's limitations are architectural, not configurational... This is a category difference, not a degree difference") is an overclaim. The accurate claim is: "For deployments where the AS is actively adversarial and blockchain consensus is trusted, the construction provides stronger guarantees. For deployments where the AS is honest-but-curious or simply unavailable, RFC 7662 with jwt-introspection-response and short-lived tokens is operationally equivalent with lower operational complexity and established regulatory precedent." The construction must narrow its superiority claim to the adversarial-AS threat scenario and acknowledge the trust substitution explicitly.


## Persona: spiffe_engineer

> Staff engineer, SPIFFE/SPIRE production for a Fortune 500, WIMSE co-author. Position: workload identity is a solved problem at the right layer. You are building a new trust root at the wrong layer, and the construction has four structural cracks I'd reject in a security review.

---

### Attack 1: RS-Controlled Timestamp Breaks Expiry Enforcement

**Attack:** `currentTimestamp` is a **public input supplied by the RS** (Section 2, public inputs table, G7). The circuit enforces `currentTimestamp < expiryTimestamp` — but `expiryTimestamp` is **private**, invisible to the RS. A malicious RS supplies `currentTimestamp = 1` (or any value in the past). The agent's prover happily produces a valid proof for an already-expired credential, because the circuit constraint is satisfied: `1 < expiryTimestamp` is trivially true for any non-zero expiry. The RS learns nothing from this — it only sees that the proof accepted.

**Why it works against the construction:** The construction never attestates that the RS-supplied `currentTimestamp` is accurate. There is no mechanism — not a signed NTP timestamp, not a beacon from the on-chain registry, not a TEE quote — that forces `currentTimestamp` to be ≥ "now." The RS is trusted implicitly on this value. Section 4's threat model explicitly lists the RS as a non-adversary ("The adversary does NOT control: the RS's local copy of the PLONK verification key"), but offers no mitigation if the RS itself is compromised or colluding.

Compare: X.509 SVID expiry is enforced by the TLS library against the **local system clock**, not against a caller-supplied value. CRL/OCSP gives an independent check. Neither is manipulable by the relying party.

**Gap to close:** Commit `currentTimestamp` to an on-chain oracle value or include a recent block hash as the timestamp anchor (the agent reads it; RS reads the same block), eliminating RS control over the time signal. Alternatively, make `expiryTimestamp` a **public input** (not private) so the RS can independently verify expiry using its own clock. The current design trades privacy for correctness in a way that isn't justified.

**In-threat-model?** No — the construction's threat model does not consider a dishonest RS manipulating the timestamp public input. Must address.

---

### Attack 2: Audience-Free Proof Enables Cross-RS Replay

**Attack:** `agentNullifier = Poseidon2(credentialCommitment, requiredScopeMask)` (G9). This is deterministic across all RSes that request the same predicate. Proof `pi` is generated with public inputs `[requiredScopeMask, currentTimestamp, onChainAgentRoot]`. There is **no RS identity, no nonce supplied by the RS, no audience claim** anywhere in the circuit.

Scenario: RS-1 (Columbia CU) sends `requiredScopeMask = 0x05` and timestamp `T`. Agent returns `(pi, scopePredicateHash, agentNullifier)`. A network adversary or a malicious RS-1 replays this exact `(pi, pubSignals)` to RS-2 (partner CU) at the same second — or any second where RS-2 accepts `currentTimestamp = T` as valid. RS-2 calls `Verify(vk, pi, pubSignals)` → ACCEPT. The agent never interacted with RS-2.

`scopePredicateHash = Poseidon3(requiredScopeMask, credentialCommitment, currentTimestamp)` binds to a timestamp, not to an RS identity. Two RSes operating within the same timestamp granularity (same Unix second, or same cached block) are indistinguishable to the proof.

**Why it works:** The construction explicitly compares to DPoP (RFC 9449) in Section 8 as a baseline it surpasses, but DPoP binds tokens to HTTP method + URI + a fresh `jti` nonce per request. The `SelectiveScopeProof` has weaker binding — no URI, no nonce, no recipient identity. A deployment scenario where 12 consortium credit unions all accept the same PLONK verification key and the same on-chain root means a single proof is valid at all 12.

**In-threat-model?** No. Section 3's adversary model covers timing side-channels and chosen-predicate queries but does not model a passive adversary who intercepts and replays a valid proof to a different RS. Must address — add an RS nonce or RS SPIFFE ID as a public input to the circuit.

---

### Attack 3: BolyraRegistry Contract as Trust Anchor Substitution Vector

**Attack:** Property 3 ("Adversarial-AS soundness," Section 8) claims: "A fully compromised AS cannot forge a valid proof" because the on-chain Merkle root is under "blockchain consensus." But the on-chain registry is a Solidity contract (`contracts/BolyraRegistry`). The construction does not specify:
- Whether the contract has an admin key or upgrade proxy (OpenZeppelin `TransparentUpgradeableProxy`, `UUPS`)
- Who controls that key
- What the timelock policy is, if any

If the `BolyraRegistry` contract has an admin owner — even a multisig — then compromising the admin key is strictly easier than compromising an Ethereum validator set. The adversary inserts a fraudulent `credentialCommitment` into the Merkle tree, generates a valid `SelectiveScopeProof` against it, and the RS verifies it as legitimate. This attack bypasses all five properties simultaneously.

The 30-entry root history buffer (Section 5, "contracts/") compounds this: a fraudulent root entered and then removed leaves a 30-root window where replayed proofs remain valid.

**SPIFFE comparison:** SPIRE's trust bundle is an X.509 root CA controlled by the operator, with explicit key custody and rotation procedures defined in RFC 9632. There is no equivalent governance doc for the `BolyraRegistry` admin key. "Blockchain consensus" is not a substitute for specifying the admin key model.

**In-threat-model?** Partially. Section 3 places "on-chain registry" outside adversary control, but this assumption is unverified at the contract level. The construction must either (a) prove the contract is non-upgradeable with no admin key, or (b) specify the governance model and threat surface for the admin key. As written, Property 3 is conditional on an unverified assumption.

---

### Attack 4: This Is a SPIRE ZK Attestor + WIMSE Selective Disclosure — Not a New Protocol

**Attack (architectural):** The construction's five claimed properties reduce to two SPIFFE/WIMSE extension points that already exist in the architecture and would not require a new trust root:

1. **ZK node attestor in SPIRE.** SPIRE's attestation interface is pluggable (`NodeAttestor`). A ZK attestor would let a workload prove `(modelHash, operatorKey, permissionBitmask) ∈ EnrolledSet` to the SPIRE server without revealing private inputs. The SPIRE server issues an SVID with a SPIFFE ID encoding the minimum necessary claims. This achieves Property 3 (adversarial-AS soundness is now blockchain-rooted attestation, not AS trust) without abandoning the SVID/trust-bundle infrastructure.

2. **ZK-derived scope in WIMSE token exchange.** `draft-ietf-wimse-arch` §5 defines workload-to-workload token exchange where the RS can specify an audience-scoped token. A WIMSE extension carrying a ZK-derived scope predicate (identical to G5 here) achieves Property 2 (runtime-adaptive predicate) and Property 1 (AS-blind presentation, since the ZK proof is self-contained in the token). WIMSE already mandates `aud` binding — which this construction lacks (Attack 2 above).

**Why this matters to the claim (Section 8):** The construction's Section 8 compares against "RFC 7662 + BBS+ + DPoP" and declares a category difference. But WIMSE + ZK attestor is not in that comparison. The construction does not address why the Bolyra protocol cannot be a contribution to WIMSE rather than a separate protocol. Specifically, WIMSE provides audience binding, workload lifecycle management (short-lived tokens via Workload API), and federation — all of which Bolyra lacks and would need to re-implement.

**In-threat-model?** This is not a soundness attack — the ZK construction is still correct. This is a scope/deployment attack: the construction claims a "category difference" from existing infrastructure, but the actual cryptographic innovation (ZK scope predicate over a committed bitmask) could be a 3-page SPIRE plugin + WIMSE extension rather than a new protocol with a new trust root, new on-chain registry, and new governance surface. The construction must justify why a new protocol is preferable to a contribution to the existing workload identity stack — or acknowledge WIMSE as a deployment alternative rather than comparing only against 2016-era RFC 7662.
