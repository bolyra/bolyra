# Tier 3 Adversarial — C5 Bolyra as MCP auth, generally

## Persona: auth0_pm

---

### Attack 1: The Human Proof Is Absent in Your Own Deployment Scenario

- **Attack:** Section 7 defines the primary deployment scenario as "generic Claude agent talking to third-party MCP server" — an **autonomous agentic pipeline**. The construction's headline differentiator (H1, the mutual ZK handshake) requires the human to produce a Groth16 HumanUniqueness proof "via browser wallet or passkey-backed prover" sharing `sessionNonce`. But in an autonomous agent pipeline, **no human is present at authentication time**. The agent is acting on behalf of a human who may be asleep, offline, or running a cron job. The construction's Section 2.4 says the RS receives `(modelBindingTag, epochNullifier, scopeCommitment)` — conspicuously, the human proof is dropped from the RS verification step. So at authentication time, the mutual handshake **degrades to a single-sided agent proof**, which is structurally identical to DPoP + client_credentials. The differentiation from H1 evaporates in the exact scenario used to motivate it.

- **Why it works / fails:** The construction never specifies the fallback when the human is absent. It elides the gap between "one-time enrollment" and "per-session authentication" — the human signs off at enrollment, not at every tool call. This is fine operationally but kills the "atomic human+agent composition" claim (Section 8, point 4) as a general differentiator. The claim becomes: "we can bind human+agent *when a human is synchronously present*," which is the exact condition under which OAuth OIDC + DPoP also works.

- **In-threat-model?** No. The construction must either (a) define the security model for human-absent agent sessions explicitly and stop claiming H1 as a general differentiator, or (b) provide a mechanism for asynchronous human proof delegation that doesn't require the human to be online per tool call. As written, H1 is a regulated-niche feature (human-supervised agentic workflows), not a general-case property.

---

### Attack 2: Model Hash Trust Bootstrap Is Just OAuth Client Registration, Redistributed

- **Attack:** The `modelBindingTag = Poseidon3(modelHash, permissionBitmask, sessionNonce)` is meaningless unless the RS knows, before verification, which `modelHash` values are legitimate for which operator. Section 7 states: "The RS checks it against expected model hashes (published by the operator)." But **"published by the operator" is an out-of-band communication channel** — Anthropic must tell Stripe, somehow, that `H("claude-opus-4-6") = 0xABC...`. This is structurally identical to OAuth client registration: the AS tells the RS which `client_id` values map to which application. The construction moves the trust anchor from the AS (Auth0) to the operator (Anthropic), but does not eliminate it. When Anthropic ships claude-opus-4-7, Stripe must update its model manifest. Who pushes that update? What's the format? What's the SLA? Auth0's OIDC well-known endpoint solves this with standard discovery (RFC 8414). The construction provides no equivalent.

- **Why it works / fails:** Section 8 claims "no OAuth RFC provides a mechanism for the RS to verify runtime state of the client without trusting an intermediary." That's true — but Bolyra *also* requires trusting an intermediary (Anthropic's model manifest publication), just a different one. The ZK proof cryptographically binds the authenticated model hash to the session, but it cannot tell the RS which hash is the *correct* one for "Claude." The construction's H2 claim (runtime model identity binding) is cryptographically sound but **operationally hollow**: the RS's model-hash whitelist must be kept current by the same party (Anthropic) that OAuth would trust for client registration, through a process the construction doesn't specify.

- **In-threat-model?** No. The construction must define a discovery protocol for how RSes obtain and update canonical model hashes, including rotation on model updates, revocation on compromised checkpoints, and multi-operator scenarios. Without this, the `modelBindingTag` is unforgeable but unverifiable in practice.

---

### Attack 3: The Latency Stack Is 30–80× Worse and Compounds Per Tool Call

- **Attack:** Section 6 estimates "browser WASM: ~2-3s" for the PLONK agent circuit and "browser WASM: ~3-5s" for the Groth16 human circuit. Even taking the optimistic end (2s + 3s), that's **5s of client-side proving per session**. Then the RS must read the on-chain Merkle root (blockchain RPC: 100–500ms, variable, no SLA) and run on-chain proof verification (~600K gas, non-trivial latency on L1). Compare: WorkOS or Auth0 MCP auth issues a DPoP-bound token in <100ms end-to-end, with 99.99% uptime SLAs. The attack isn't "your math is wrong" — it's that **a Claude agent calling 20 MCP tools per session** incurs either (a) 5s × 20 = 100s of proving overhead if proofs are per-call, or (b) session-level proofs that reduce security to session granularity rather than per-invocation binding. The construction doesn't specify which granularity the `sessionNonce` operates at, and the answer determines whether the construction is usable or not.

- **Why it works / fails:** Section 6 acknowledges the 15s Groth16 target but frames it as "browser WASM: ~3-5s; native: <1s." Native proving requires a local trusted execution environment — the construction doesn't specify who runs it, how it's attested, or what prevents the prover from lying about `modelHash` in a native context. If the prover is the agent itself (as implied), a compromised agent can supply any `modelHash` as private input; the circuit proves consistency but not that the hash corresponds to what's actually running. This is a separate trust assumption the construction doesn't name.

- **In-threat-model?** Yes and no. The latency gap is a GTM attack, not a protocol attack. But the prover-trust assumption (the agent supplies its own `modelHash` as private input) **is** an in-scope protocol question the construction must address. Who or what attests that the private `modelHash` input matches the running model?

---

### Attack 4: The Ratchet's Forward-Secrecy Guarantee Requires Operational Discipline the Construction Never Specifies

- **Attack:** Section 2.1 initially claims forward secrecy via epoch erasure of `epochSecret_e`. Then Section 4 correctly self-corrects: "if the adversary obtains `longTermSecret`, forward secrecy is broken for epoch-secret derivation." The fix proposed is a hash-chain ratchet where "Agent stores only `epochSecret_e` (erases `epochSecret_{e-1}` and **never stores `longTermSecret` after initialization**)." This is a strong operational requirement. In practice, AI agents run in: (a) containerized runtimes subject to snapshot/checkpoint by the orchestrator, (b) environments with memory dumps on crash, (c) CI/CD pipelines where secrets are injected via environment variables (logged), and (d) inference servers where the same process handles many users. The construction's forward secrecy guarantee reduces to "trust that the agent process correctly erases secrets and is never checkpointed" — an assertion, not a cryptographic property. DPoP (RFC 9449) with short-lived tokens (5-minute expiry) achieves a comparable practical window without this operational discipline, and the expiry is enforced by the AS, not by an agent promising to delete a scalar.

- **Why it works / fails:** Section 4's Theorem (Forward-Secure Unlinkability) is stated correctly under the assumption that erasure happens. The construction provides **no mechanism** for verifying erasure — no TEE attestation, no hardware binding, no audit trail. For a procurement conversation at a credit union, "we cryptographically erase epoch secrets every hour" is an unauditable claim. The NCUA examiner asking how the credit union verifies secret erasure will receive a protocol reference to a hash-chain ratchet, not an auditable control. Auth0 can show a SOC 2 Type II report covering token lifecycle management. Bolyra cannot, and the construction doesn't address how it would.

- **In-threat-model?** Partially. The forward-secrecy theorem is sound under stated assumptions. But the construction must specify: (a) the execution environment required for the erasure discipline to hold (TEE? Hardware security module?), (b) how operators verify compliance, and (c) the threat model for agents running in cloud-hosted inference environments where the operator controls the runtime. Without this, H4 is a theorem about a non-existent deployment, not a deployable property.


## Persona: cryptographer

*Applied cryptographer, IACR; reviews for CRYPTO/EUROCRYPT/S&P. Unless I see a game definition and a reduction, it's marketing. The construction has a game section — let's stress it.*

---

### Attack 1: `agentMerkleRoot` and `scopeCommitment` are per-credential constants — unlinkability is broken by construction

**Attack:** Two colluding Resource Servers compare public outputs from separate sessions. Per §2.2, `agentMerkleRoot` is the BinaryMerkleRoot output computed from `credentialCommitment`, which is `Poseidon5(modelHash, opAx, opAy, permissionBitmask, expiry)`. None of these inputs vary per session — they are fixed at enrollment. Similarly, `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` (constraint 12) contains no session-variant randomness. An adversary operating two RSes receives `(agentMerkleRoot, scopeCommitment, modelBindingTag, epochNullifier)` from each session. The first three are deterministic functions of the credential alone. Any two sessions by the same agent yield identical `(agentMerkleRoot, scopeCommitment)` pairs, providing a cross-RS linking tag that survives epoch rotation.

**Why it works:** The construction explicitly says (§8, point 3): *"No party learns which agent authenticated to which RS."* This is false by inspection. `agentMerkleRoot` is the same in every valid proof from the same credential. It is a public output handed to every RS. Two colluding RSes — or any passive observer of the on-chain verification log — can trivially cluster sessions by credential without breaking any hash function or zero-knowledge assumption. The `epochNullifier` is session-fresh, but the other two public outputs are not.

**Formal statement of the gap:** The unlinkability game is never defined. There is no Game 4 (LINK-ACROSS-RS) with a formal adversary, winning condition, or reduction. The authors assert "scope-free" and "no correlator" in prose (§3, Game 2 discussion) while simultaneously publishing a deterministic per-credential identifier as a mandatory public circuit output.

**In-threat-model?** No. The construction must either (a) add session randomness into `agentMerkleRoot` computation (breaking the standard Merkle membership argument) or (b) introduce a per-session commitment that hides the credential root (e.g., a Pedersen re-randomization), or (c) drop the unlinkability claim entirely. This is not a minor gap — the H4/H3 differentiation from OAuth collapses.

---

### Attack 2: `modelBindingTag` RS-side verification is semantically vacuous — private `permissionBitmask` makes the tag unverifiable by the RS

**Attack:** §2.4 instructs the RS to check: *"`modelBindingTag` matches an expected value computed from the operator's published model manifest."* The RS wants to verify `modelBindingTag == Poseidon3(H(M_expected), bitmask_expected, sessionNonce)`. But `permissionBitmask` is a **private** circuit input (§2.2, private inputs table). The RS receives only `sessionNonce` (public input), `requiredScopeMask` (its own policy), and `scopeCommitment` (hides the bitmask behind another Poseidon call). The RS does not know the agent's actual `permissionBitmask`. Therefore the RS cannot evaluate `Poseidon3(H(M_expected), ?, sessionNonce)` without enumerating all possible bitmasks that satisfy `requiredScopeMask`.

**Why it works:** The RS-side verification procedure is underspecified in a way that makes the model-binding claim hollow. Game MCP-FORGE (§3) asks whether an adversary can produce a valid proof with `modelHash' ≠ H(M)` such that `modelBindingTag` matches the RS's expectation. But if the RS cannot independently evaluate the expected tag (because it lacks the bitmask), the RS is not actually checking model identity — it is only checking that some Poseidon evaluation is self-consistent. An adversary with a credential for model M' but the same `permissionBitmask` and `sessionNonce` produces a tag `Poseidon3(H(M'), bitmask, sessionNonce)` that the RS cannot distinguish from `Poseidon3(H(M), bitmask, sessionNonce)` without knowing `bitmask`.

**Deeper structural issue:** For the binding check to mean anything, either (a) `permissionBitmask` must be a public output (defeating the privacy claim), or (b) the operator must publish a lookup table mapping `(model_hash, expected_bitmask_set)` → expected tags per scope, which requires the operator to enumerate all (model, bitmask) combinations and publish them — a significant operational assumption absent from the construction. The reduction in §4 sidesteps this by positing "the RS checks `modelBindingTag` against expected value" as an axiom, not proving that the RS *can* form this expected value.

**In-threat-model?** No. The MCP-FORGE game is stated correctly, but the protocol does not give the RS the inputs needed to evaluate the winning condition check. This is a protocol completeness failure, not just a formal gap.

---

### Attack 3: Ratcheted epoch scheme requires a different circuit — `longTermSecret` as private input is inconsistent with the security argument

**Attack:** §3 (Game EPOCH-LINK discussion) correctly identifies that the simple scheme `epochSecret_e = Poseidon2(longTermSecret, e)` has no forward secrecy: the adversary holding `longTermSecret` recomputes all past epoch secrets by evaluating Poseidon with known `e`. The construction introduces a ratcheted scheme in §3: `epochSecret_{e+1} = Poseidon2(epochSecret_e, e+1)`, and states *"Agent stores only `epochSecret_e` (erases `epochSecret_{e-1}` and never stores `longTermSecret` after initialization)."*

This directly contradicts the circuit specification in §2.2, which lists `longTermSecret: F_p` as a private input, and encodes the derivation `epochSecret = Poseidon2(longTermSecret, epochCounter)` as constraint 2. If the ratcheted scheme is deployed (no stored `longTermSecret`), the circuit as written cannot be used — the agent would need to prove knowledge of `epochSecret_e` directly, bypassing the `longTermSecret` derivation step.

**Why it works:** The ratcheted scheme and the circuit are mutually exclusive operational configurations, and the construction presents them as if they are compatible. If the circuit is used as specified (with `longTermSecret` as private input), the simple non-ratcheted scheme is in use and forward secrecy against `longTermSecret` compromise is absent. If the ratcheted scheme is deployed, the circuit must be rewritten: `longTermSecret` is removed as a private input, `epochSecret_e` becomes a direct private input, constraint 2 is dropped, and the `epochFloor` enforcement must now be over the ratchet chain depth rather than the epoch counter. Additionally, Merkle membership does not involve `epochSecret` at all (it uses `credentialCommitment`), so the circuit revision would need to add a chain-binding constraint to prevent an adversary from mixing a past epoch secret with a different credential commitment.

**Formal gap:** The Theorem (Forward-Secure Unlinkability) in §4 is stated against A3 (Poseidon PRF) with "epoch-erasure discipline." But the circuit that would be proven using that theorem does not exist in §2.2. A security proof for a circuit not defined is not a security proof.

**In-threat-model?** No. The authors must either (a) specify and publish the ratcheted-scheme circuit separately, or (b) restrict the forward-secrecy claim to the weaker property achievable with the simple scheme (unlinkability across RSes in the same epoch, not across long-term key compromise).

---

### Attack 4: PLONK universal SRS subversion invalidates all agent proofs simultaneously — threat model omits setup adversary

**Attack:** The construction uses Groth16 for the human circuit (§2.3) with "Semaphore ceremony" (circuit-specific CRS) and PLONK for the agent circuit (§2.2, §5) with a "universal SRS." The threat model in §3 defines three games but includes no adversary with power over the proving system setup. For PLONK with universal SRS, the SRS is a single structured reference string used across all circuits sharing that SRS. A party that retains the SRS toxic waste can produce valid PLONK proofs for **any statement** over the corresponding field without knowing a valid witness — including false model hashes, invalid scope satisfactions, and arbitrary credential commitments — for every circuit using that SRS.

The blast radius is larger than Groth16. With Groth16 (circuit-specific CRS), a compromised ceremony breaks only circuits generated from that ceremony. A compromised PLONK universal SRS breaks every circuit in the system: AgentPolicyV2, the Delegation circuit (§5, §2.4), and any future circuit derived from the same SRS. The construction presents the universal SRS as an operational advantage ("no per-circuit ceremony," §8 point 5), but does not model the adversary who subverts it.

**Game definition (missing from §3):** Let **Game 4 (SRS-FORGE)** be: Adversary is given the toxic waste `τ` from the PLONK SRS generation. Adversary wins if it produces a valid AgentPolicyV2 proof π for any (public inputs, public outputs) tuple without supplying a valid witness. Under standard PLONK security (A4), knowledge soundness holds only when the SRS is generated honestly. Under subverted SRS, knowledge soundness fails unconditionally. The reduction sketch in §4 ("By A4, extract witness W") is vacuously true only when A4's setup precondition holds.

**Why it matters specifically for this construction:** The `modelBindingTag` security argument (Theorem 1, §4) reduces to "we extract `modelHash` from the PLONK proof via knowledge soundness." This extraction is impossible under subverted SRS. The entire model-binding claim collapses. The authors cite a "universal SRS" as a differentiating advantage over the RFC stack in §8 without acknowledging that the PLONK trust assumption is strictly stronger than what UC composition requires for the Groth16 human circuit.

**Partial mitigation (not mentioned):** Kate-Zaverucha-Goldberg (KZG) commitments in PLONK admit a ceremony-agnostic security argument in the algebraic group model (AGM) under the q-DLOG assumption — but the construction cites only ROM (A6) and knowledge soundness (A4), not AGM. This gap needs to be closed.

**In-threat-model?** No. The threat model must add a Game 4 that bounds the subverted-SRS adversary and either (a) argues security holds under AGM + q-DLOG (with explicit parameter sizes), or (b) explicitly places "honest SRS generation" as a named trust assumption at the top of §4 with operational guidance (multi-party computation ceremony for the PLONK SRS, or SNARKs with transparent setup such as STARK-based PLONK variants).


## Persona: cu_ciso

---

### Attack 1: Audit Trail Opacity vs. NCUA Part 748 Appendix B

**Attack:** During a simulated NCUA examination, I pull session logs from the Bolyra-integrated MCP server for incident review. The logs contain: `epochNullifier = 0x3f4a...`, `modelBindingTag = 0x9c12...`, `scopeCommitment = 0x71ab...`. My examiner asks: "Which member account was accessed, by which agent, at what time, and what data was returned?" I cannot answer. The construction (§2.4, step 6c) stores `modelBindingTag` in session records and declares this satisfies NCUA examination requirements for audit of approved model checkpoints. But `modelBindingTag = Poseidon3(modelHash, permissionBitmask, sessionNonce)` is a privacy-preserving commitment — it proves the correct model was used without revealing who used it, when, or for what. The ZK property that is the construction's selling point is structurally opposed to the ledger of facts an NCUA examiner needs.

**Why it works / why it fails:** The construction does not address this. §7 asserts "NCUA's compliance team audits modelBindingTag logs to verify only approved model checkpoints accessed member data" but the word "audit" here means something different to a cryptographer than to an NCUA examiner. An examiner reading Part 748 Appendix B wants a reproducible, human-readable record of who did what. The construction provides a proof that someone with the right credential did something — not a record of what.

**In-threat-model?** No. The construction's threat model (§3) addresses MCP-FORGE, EPOCH-LINK, and SCOPE-CLIMB. It does not model the regulatory auditor adversary who needs plaintext attribution. Construction must address how to reconcile ZK unlinkability (§8, point 3: "No party learns which agent authenticated to which RS") with NCUA's audit logging requirement under Part 748 §748.0 and Appendix B item II.C.

---

### Attack 2: Forward Secrecy Is an Operational Discipline, Not a Cryptographic Guarantee — and the Construction Admits This

**Attack:** I read §4 carefully. The construction states: "Critical subtlety: The adversary CAN recompute epoch secrets from longTermSecret — forward secrecy holds ONLY if the adversary does NOT obtain longTermSecret." It then introduces a ratchet and says the agent must "never store longTermSecret after initialization." My question: who enforces this? Where is the key ceremony? What HSM profile? What happens when a developer at the integration shop initializes the agent on a dev laptop, the longTermSecret lands in a `.env` file, and that repo is later breached? The ratchet construction (§4, "Ratcheted epoch secret") is sound on paper, but it terminates in an operational assertion — "agent never stores longTermSecret" — that is outside the cryptographic proof entirely.

**Why it works / why it fails:** The construction's Theorem (Forward-Secure Unlinkability) is technically correct given the stated adversary model. But the adversary model excludes the most operationally realistic attack: longTermSecret exfiltration via misconfigured key storage, not post-compromise. GLBA Safeguards Rule §314.4(c) requires "monitoring and testing" of controls including key management. The construction provides no key lifecycle spec, no HSM requirement, no audit mechanism for proving that erasure discipline was followed. I cannot tell my examiner that forward secrecy is enforced; I can only tell them it would hold if the vendor followed their own procedure.

**In-threat-model?** No. The construction treats erasure discipline as axiomatic. For a credit union deployment, this is a vendor management risk under NCUA's third-party vendor guidance (NCUA Letter to Credit Unions 07-CU-13). Construction must address: key ceremony requirements, HSM profile (FIPS 140-2 Level 2 minimum), and an auditable erasure attestation mechanism.

---

### Attack 3: modelHash Trust Anchor Is Shifted, Not Eliminated — and the New Anchor Is Weaker

**Attack:** §7 states: "Anthropic registers Claude's model checkpoint hash and operator key in the Bolyra agent Merkle tree." NFCU's RS verifies `modelBindingTag` against this registration. My question: what is the Merkle tree operator's governance model? Who has write access? Is it a multisig? Who audits insertions? §8 claims Bolyra eliminates the AS from the verification path, but it introduces a Merkle tree registry that plays the same structural role. If Anthropic's enrollment key is compromised, a malicious actor enrolls a rogue model hash, and the RS's verification passes — cryptographically correctly — for a model NFCU never approved. The construction has not eliminated the trusted third party; it has replaced a federated OAuth AS (with an RFC-specified trust model) with a smart contract registry (with an unspecified governance model).

**Why it works / why it fails:** §8, point 3 says "Bolyra proofs are verified against an on-chain Merkle root. No AS is in the loop." This is true at verification time, but enrollment is the new attack surface. The construction says nothing about who can enroll, under what conditions, with what multi-party authorization, or how NFCU gets notified if a new model hash is inserted on their behalf. OAuth AS governance is mature (RFC 6749, OpenID Provider metadata, well-known discovery endpoints). The Bolyra registry governance is unspecified.

**In-threat-model?** No. The construction's MCP-FORGE game (§3, Game 1) assumes the Merkle tree is honest — the adversary gets a valid credential but wrong model. It does not model a compromised tree operator who inserts a malicious leaf. Construction must address registry governance: who controls enrollment, what authorization is required for new leaves, how NFCU audits the registry for unauthorized insertions, and what revocation mechanism exists at the registry level (distinct from per-credential revocation).

---

### Attack 4: On-Chain Registry SLA Introduces a New Availability Dependency with No FFIEC Mapping

**Attack:** §2.4 and §7 require on-chain verification of Merkle roots and nullifier sets. §6 notes gas costs on L1 (~$0.30/tx) and L2 (<$0.01). My FFIEC CAT assessment requires me to identify all dependencies in the critical authentication path. I now have: core processor (99.99% SLA, contractual), card network (99.95%), and — new — a blockchain L2 sequencer with no contractual SLA, no published uptime history, no NCUA-examined vendor management profile, and a known failure mode (sequencer downtime on Optimism/Arbitrum has historically reached hours). If the on-chain registry is unavailable, can members authenticate? Can the MCP server fall back to cached Merkle roots? How stale can the root be before it's a security control failure vs. an availability failure? The construction is silent on all of this.

**Why it works / why it fails:** §7 describes a "per-session" flow that generates an AgentPolicyV2 proof and verifies against the on-chain registry. There is no mention of caching, fallback, or degraded-mode operation. In credit union operations, every authentication dependency must be in the BCP/DR plan. A construction that requires liveness of an external blockchain network — with no contractual SLA and no regulatory history — introduces a new category of third-party risk that maps to no existing FFIEC CAT control and would require me to build a novel vendor risk assessment from scratch. The FFIEC CAT (Cyber Risk Management and Oversight domain) requires documented dependencies. "On-chain Merkle root" is not a category in any existing FFIEC questionnaire.

**In-threat-model?** No. The construction's threat model addresses cryptographic adversaries, not infrastructure availability adversaries. Construction must address: fallback behavior when the L2 sequencer is down, maximum acceptable Merkle root staleness, whether the RS can cache roots and for how long, and how cached-root verification interacts with the nullifier freshness check (§2.4, step 5i) — since a stale cached root combined with a stale nullifier set creates a replay window that the construction's security argument does not bound.


## Persona: rfc7662_advocate

*OAuth Working Group veteran, ten years shipping production introspection. Every ZK claim is suspect until proven unreachable by the RFC stack.*

---

### Attack 1: modelBindingTag Proves Credential Binding, Not Execution Binding

- **Attack:** The circuit takes `modelHash` as a **private input** (§2.2 private inputs table). The PLONK proof establishes that the prover knows a `modelHash` such that an operator-signed `credentialCommitment = Poseidon5(modelHash, ...)` exists in the Merkle tree. It does not establish that the code currently executing is the model whose SHA256 is `modelHash`. A rogue MCP client enrolls with `H(claude-opus-4-6)`, receives an operator EdDSA signature over the resulting commitment, then runs `modelHash = H(claude-opus-4-6)` as a hardcoded constant in the prover software while executing an entirely different model at inference time. The proof verifies. `modelBindingTag` matches. The RS's manifest check passes.

  The MCP-FORGE game in §3 scopes the adversary to someone who "controls a rogue agent with a valid credential but running model M' ≠ M." That adversary cannot win MCP-FORGE as defined — they don't have a valid credential for M. But a **fourth adversary class** not in the game definition is the agent who has a valid credential for M and lies in the witness. There is no TEE quote, no remote attestation, no hardware root of trust that binds proof generation to the actual inference process. This is a gap the construction inherits alongside vanilla OAuth's `client_id`, not a property it eliminates.

  Vanilla OAuth makes the same assumption: `client_id` trusts the registered client to behave as registered. Bolyra's `modelBindingTag` trusts the registered prover software to pass honest private inputs. Both reduce to the same behavioral trust anchor at the endpoint.

- **Why it works / fails:** The reduction sketches in §4 are tight *within the stated threat model*, but the threat model excludes the most natural adversary in MCP deployments: a legitimate operator who updates the model behind a static enrollment. The construction claims to solve what `client_id` cannot (§8.1); it solves it against third-party forgery, not against operator-side equivocation.

- **In-threat-model?** No — §7's NFCU compliance scenario is the exact use case (auditing "only approved model checkpoints accessed member data"), and it breaks under this attack. The construction must address attestation roots of trust or narrow the claim to "model identity as asserted by the prover software."

---

### Attack 2: RFC 9701 Signed JWT Introspection Responses Eliminate the AS from the Hot Path

- **Attack:** Section 8.3 asserts "Every OAuth flow requires the AS to issue, introspect, or exchange the token." This was accurate for RFC 7662 (synchronous introspection). It is not accurate for [RFC 9701](https://www.rfc-editor.org/rfc/rfc9701) (the finalized *JWT Response for OAuth Token Introspection*). Under RFC 9701, the AS returns a signed JWT introspection response. The RS caches and verifies this JWT offline — no AS roundtrip on subsequent presentations within the token lifetime. Combine this with:

  - **RFC 8707 resource indicators** at issuance time: the introspection JWT is audience-bound to a single RS, preventing cross-RS replay without AS involvement.
  - **OIDC PPID/pairwise subjects**: the `sub` in the introspection JWT is RS-specific. RS_A receives `sub = PPID_A`, RS_B receives `sub = PPID_B`. The token itself contains no cross-RS correlating identifier.
  - **Short-lived tokens + precomputed introspection JWTs**: the AS can batch-sign introspection responses at issuance time, handing them to the client. The RS verifies the AS's signature offline.

  The result: after the first issuance event, the RS verifies with zero AS roundtrips, sees no cross-RS correlating identifier in the token payload, and the AS does not observe per-RS access patterns at use time. Section 8.3's claim that "the AS retains the full mapping" is only true for *issuance* (the AS knows which RS-audience was requested via RFC 8707 at grant time) — not for ongoing use.

- **Why it works / fails:** The construction's AS-blindness argument rests on the AS seeing "every RS the agent accesses, every delegation hop, every scope request" (§8.3). RFC 9701 + RFC 8707 reduce this to: the AS sees which RS the token was originally requested for, once. Correlation across multiple RSes remains possible if the agent requests audience-bound tokens for multiple RSes in a single session. But for single-RS sessions (the §7 Stripe scenario), the RFC stack achieves functional AS-blindness at verification time. The construction's §8.3 argument overclaims.

- **In-threat-model?** Partially yes — the construction's forward security and model binding claims stand independently. But §8.3's "structural limitation" framing fails against RFC 9701. The claim should be scoped to properties that RFC 9701 genuinely cannot provide (model binding, human+agent atomic composition), not to AS hot-path presence.

---

### Attack 3: The EPOCH-LINK Game Breaks Under Its Own Ratchet Initialization Assumptions

- **Attack:** Section 4's first forward-secrecy argument concedes defeat explicitly: "The adversary CAN recompute epoch secrets from `longTermSecret`." The ratchet fix introduces `epochSecret_0 = Poseidon2(longTermSecret, salt_0)` and states the agent must "never store `longTermSecret` after initialization." This is the load-bearing operational claim. Three problems:

  1. **Enrollment requires a durable identity.** The Merkle leaf is `credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, ...)`. `longTermSecret` feeds the ratchet, not the enrollment commitment directly — but enrollment still requires stable operator key material. The ratchet's "never store" claim applies to `longTermSecret` as the ratchet seed, but the construction doesn't specify how an agent recovers from device loss or re-enrollment without reconstructing the seed from backup. If any backup of `longTermSecret` exists (hardware wallet, cloud HSM, operator-side escrow), the forward secrecy is conditional on that backup's security, not the ratchet's.

  2. **DPoP with hardware-bound keys (RFC 9449 §5) achieves equivalent operational forward secrecy.** TPM-backed or Secure Enclave DPoP keys are non-exportable. After a session using short-lived tokens (e.g., 60-second `exp`), an adversary who later compromises the device gains a signing key they cannot use to retroactively verify or link expired tokens — the tokens are gone from the RS, and a recorded DPoP-PoP JWT is worthless after `exp`. The operational requirement (key material that survives only as long as needed, erasure discipline) is identical to Bolyra's ratchet assumption.

  3. **The EPOCH-LINK game is trivially won if `sessionNonce` values are logged.** Section 3 game step 4 states the adversary has "recorded all public signals (`epochNullifier`, `modelBindingTag`, `scopeCommitment`)." With `longTermSecret` and recorded `sessionNonce`, the adversary computes `epochSecret_e = Poseidon2(longTermSecret, e)` for all e, then recomputes every nullifier. The ratchet breaks this only if `longTermSecret` is truly erased. But who erases it — the agent process, the OS, the hardware? In a software prover (browser WASM, §6), reliable erasure in the presence of swap, hibernation, and GC is not guaranteed.

- **Why it works / fails:** The ratchet argument in §4 is mathematically sound under its stated assumptions. But those assumptions (durable-secret-free initialization, reliable erasure, no backup) are identical in operational burden to hardware-bound DPoP. The construction's §8 claim that this is an "information-theoretic gap" between DPoP and Bolyra is valid only when hardware DPoP is excluded from the baseline comparison. The construction should specify the exact threat model distinguishing ratcheted Bolyra from DPoP-in-HSM.

- **In-threat-model?** Yes — the ratchet security argument survives if operational assumptions hold, but the construction must state those assumptions explicitly and compare them to RFC 9449 §5 hardware binding rather than treating bearer-token DPoP as the baseline.

---

### Attack 4: The Delegation Latency Claim Is a Performance Argument, Not a Security Argument — and RFC 8693 Has an Offline Mode

- **Attack:** Section 8.5 argues that "RFC 8693 token exchange requires one AS roundtrip per delegation hop." Two sub-attacks:

  **4a. RFC 8693 §2.1 supports self-issued token exchange.** When the delegating entity has sufficient trust (e.g., it holds a client certificate and is pre-authorized to issue narrow sub-tokens), the AS can validate a structured JWT presented by the delegating client without a synchronous call. Many FAPI 2.0 financial API deployments use exactly this pattern: the orchestrating client issues a signed narrow-scope assertion, the downstream RS verifies the chain signature offline. The roundtrip is a policy choice, not a protocol requirement.

  **4b. Even granting the roundtrip cost, this is a performance/latency argument, not a security capability argument.** The construction's §1 claim is *strict* dominance in the "general case" (C5's claim). For the PLONK delegation proof to be a strictly superior primitive, it must offer a security property the RFC 8693 chain cannot. The construction's delegation section claims "cryptographically enforced (scope subset constraint), not policy-asserted by a trusted third party." But in RFC 8693, scope narrowing IS cryptographically enforced by the AS's signature over the narrowed token. The adversary cannot escalate scope without the AS co-signing. Bolyra's scope narrowing is enforced by PLONK knowledge soundness on the delegating agent's credential — but a compromised delegating agent with a valid credential can issue arbitrarily narrow (or even fraudulent) delegations without AS audit. RFC 8693 with a trusted AS provides stronger **audit trail** for delegation chains, not weaker enforcement.

- **Why it works / fails:** The delegation circuit (§2.2 last row, §8.5) is genuinely useful for multi-vendor agent chains where no shared AS exists (the Claude → ChatGPT → Stripe scenario in §7). That specific cross-vendor, no-shared-AS case is a real gap the RFC stack cannot address without a pre-established federation arrangement. But the general-case dominance claim fails: within a single operator's ecosystem, RFC 8693 with proper trust anchors provides delegation chains with comparable enforcement and stronger auditability.

- **In-threat-model?** Partially yes — the cross-vendor, no-shared-AS scenario (§7 step 4) is the genuine differentiator. The construction should narrow its delegation claim to that specific scenario rather than asserting general dominance over RFC 8693.


## Persona: spiffe_engineer

---

### Attack 1: modelHash Is an Operator Assertion, Not Runtime Attestation — Game 1 Is Misspecified

**Attack:**

Section 2.2 lists `modelHash` as a **private input** to AgentPolicyV2. The circuit proves, in zero knowledge, that the prover knows a scalar `modelHash` such that:

1. `credentialCommitment = Poseidon5(modelHash, opAx, opAy, bitmask, expiry)` 
2. The operator EdDSA signature over `credentialCommitment` verifies.
3. `modelBindingTag = Poseidon3(modelHash, permissionBitmask, sessionNonce)` matches.

This proves **"I hold a credential that an operator signed while attesting to model hash H(M)."** It does not prove **"the process generating this proof is executing model M right now."**

Game 1 (MCP-FORGE, §3) defines the adversary as a rogue agent "with a valid credential enrolled in Merkle tree but running model M' ≠ M." That adversary wins trivially: they supply `modelHash = H(M)` from their legitimately-issued credential as the private witness, run M' in the inference layer, and the PLONK proof verifies. `modelBindingTag` matches the RS's expectation. The RS is convinced it is talking to M. The adversary has won, because the ZK circuit has no oracle into the executing process.

The §4 reduction sketch addresses only two cases — hash collision and EdDSA forgery. It silently assumes Case 1 ("extracted modelHash = H(M) — contradiction, adversary is running M") is a contradiction. It is not. Knowing H(M) and being M are orthogonal. Knowledge soundness extracts the witness the prover supplied; it says nothing about what is actually executing.

Compare: SPIRE workload attestation uses the OS kernel + node agent to measure what is running (k8s ServiceAccountToken, AWS IID, TPM PCR extend). The attestation is physically bound to the process by the platform. Your modelHash is bound by an EdDSA signature issued at credential-enrollment time, which the credential-holder carries forward into any execution context they choose.

**Why it works / why it fails:** The reduction in §4 conflates "operator certified H(M) at issuance time" with "prover is running M at proof time." No ZK circuit over private inputs can close this gap without a hardware root of trust (TEE, TPM measurement) or a trusted execution environment that generates the proof from within the isolated model process. The construction provides neither.

**In-threat-model? No** — the construction must address this. The modelBindingTag delivers credential-bound model attestation, not runtime model attestation. H2's claim ("cryptographic binding of model instance to tool call") is overstated. The correct claim is "cryptographic binding of operator-issued model credential to tool call," which is weaker and not equivalent to OAuth's `client_id` being "just a static string" in the way §8 argues.

---

### Attack 2: The Forward-Secrecy Ratchet Requires longTermSecret to Live Somewhere — SPIRE SVIDs Already Solve This More Cleanly

**Attack:**

Section 2.1 introduces the ratcheted epoch secret:

```
epochSecret_0 = Poseidon2(longTermSecret, salt_0)
epochSecret_{e+1} = Poseidon2(epochSecret_e, e+1)
```

§4 states: "Agent stores only `epochSecret_e` (erases `epochSecret_{e-1}` and never stores `longTermSecret` after initialization)."

"Never stores longTermSecret after initialization" is operationally fictional for an MCP agent. The agent must be bootstrapped — `longTermSecret` must arrive from somewhere: provisioned at container startup, loaded from a KMS, stored in a secrets manager, derived from a hardware key. In any realistic deployment:

- If derived from a hardware key (HSM/TPM), the TPM holds the root secret indefinitely. The "ratchet" provides no additional forward secrecy beyond what the TPM already provides, because an adversary who compromises the TPM at epoch T also compromises the root and can derive all past `epochSecret_e` values by replaying the Poseidon chain forward from e=0. The ratchet is **forward-secure only if the root is truly ephemeral** — but the root must be persistent for the agent to survive restarts.

- If the root is rotated by a KMS, then the KMS retains the old root (or must, for audit). The "erased" property holds only if the KMS cooperates and itself deletes material — which is now an external trust assumption not stated in the threat model.

- If `longTermSecret` is provisioned from a secret store and deleted from memory after initialization, a process restart rebuilds `epochSecret_0` from the same stored secret, reconstructing past epochs. Persistent storage for the ratchet state (current epoch index + current epochSecret) is also required, or the agent re-derives from scratch.

By contrast: SPIRE issues short-lived X.509-SVIDs (default TTL: 1 hour, configurable to minutes). The private key for each SVID is generated ephemerally in the SPIRE agent's memory, not derived from a stored root. At SVID expiry, the key material is discarded. There is no root secret. Compromise at time T yields only the live SVID, not any SVID issued in prior hours. This is strictly stronger forward secrecy than the ratchet construction, delivered by the OS process model and SPIRE's rotation loop, with no ZK machinery.

**Why it works / why it fails:** §4's "Theorem (Forward-Secure Unlinkability)" relies on the adversary not obtaining `longTermSecret`. But the entire point of forward secrecy is guaranteeing security *when* the long-term secret is eventually compromised. The ratchet does provide forward secrecy under `epochSecret_e` compromise, but the §4 argument is circular: if you never let the adversary get `longTermSecret`, you don't need the ratchet; the vanilla nullifier would already be fine. The operationally interesting case — persistent agent deployment where `longTermSecret` is stored — is exactly where the ratchet fails to deliver the claim.

**In-threat-model? No** — the construction must specify the trust model for longTermSecret storage. Is it in a TEE? In a KMS? The forward-secrecy security argument changes materially depending on the answer. H4 as stated ("agent secret exfiltration does not retroactively deanonymize prior sessions") is only true if the adversary cannot access the secret store from which `longTermSecret` was loaded at initialization.

---

### Attack 3: This Is a SPIFFE ZK Attestor — You Are Building a Protocol Where SPIRE Needs a Plugin

**Attack:**

SPIRE's attestation model is explicitly pluggable. A SPIRE workload attestor is a process that communicates with the SPIRE agent over a local Unix socket, examines the calling workload (by PID, cgroup, namespace, or any other signal the plugin reads), and returns a set of selectors that SPIRE maps to a SPIFFE ID.

What Bolyra needs is:
- A workload attestor that measures the model checkpoint hash (e.g., SHA256 over the model binary or weights manifest, fed into the circuit)
- A node attestor that binds the SPIRE agent to the operator's signing key (Anthropic's Baby Jubjub key could be an HSM-backed Ed25519 SVID root)
- A SPIFFE ID encoding the operator + model: `spiffe://anthropic.com/model/claude-opus-4-6/perm/0x1F`

An MCP server (RS) configured to accept SVIDs from `spiffe://anthropic.com/model/claude-opus-4-6/**` gets mutual TLS with model binding encoded in the SPIFFE ID — without a new proof system, without Poseidon, without a circuit, without BN254.

H1 (mutual ZK handshake) is mTLS with SVIDs. H2 (model binding) is the SPIFFE ID path segment. H3 (zero-config portability) is SPIFFE trust-domain federation — an RS in trust domain `stripe.com` federates with `anthropic.com`; no per-RS client registration; no dynamic registration roundtrip. The cross-vendor handoff scenario in §7 (Claude → ChatGPT) is inter-domain SPIFFE federation, which SPIRE supports today.

The construction in §7 asserts "No external IdP sees member-to-agent session bindings." SPIRE's Workload API delivers SVIDs to workloads via a local socket; the SPIRE server sees attestation events but not per-call session bindings. The correlation concern is equivalent.

**Why it works / why it fails:** The SPIFFE/SPIRE approach is weaker on two specific points: (a) it does not provide unlinkability across RSes (the SPIFFE ID is stable and visible in the TLS handshake), and (b) it does not provide human+agent atomic binding (H1's mutual handshake). These are real gaps for privacy-preserving scenarios (the NFCU use case in §7). However, the construction's claim is that it "strictly dominates vanilla OAuth 2.1 + MCP baseline **in the general case**" (emphasis from the claim statement). The general case for MCP is enterprise agent infrastructure where privacy from the RS is not a requirement — the RS is a first-party service. In that general case, SPIFFE + a ZK workload attestor plugin is the right layer, not a new auth protocol.

**In-threat-model? No** — the construction must defend why adding ZK to SPIFFE is wrong and adding SPIFFE to a new ZK protocol is right. The architectural argument in §8 is framed against OAuth. It does not address the SPIFFE alternative, which provides model binding, delegation (via SPIFFE nested SVIDs or WIMSE), and federation without a new proof system.

---

### Attack 4: WIMSE Covers H5 — You Are Forking a Standard in Progress

**Attack:**

Draft `draft-ietf-wimse-arch` (Workload Identity in Multi-Service Environments) is an active IETF working group document. Its explicit scope includes:

- Workload-to-workload authentication in multi-hop service chains
- Delegation with scope narrowing across hops
- Token binding to workload identity (covering DPoP's limitation §8 point 2)
- Interoperability with SPIFFE SVIDs as the base identity layer

The WIMSE architecture's token exchange profile specifically targets the "one AS roundtrip per hop" problem identified in §8 point 5. WIMSE-draft proposes bound tokens (tokens cryptographically bound to the workload's SVID) that can be exchanged offline using a signed token-exchange request, eliminating the AS roundtrip from the hot path.

H5 ("narrow-scope delegation is a primitive, single proof per hop") is exactly what WIMSE's offline delegation token profile is designed to deliver. The Bolyra delegation circuit (§5, "Composable Delegation") is a ZK re-implementation of WIMSE's scope-narrowing token exchange — a re-implementation that is incompatible with WIMSE consumers, requires a new verifier at every RS, and fragments the emerging standard.

The NFCU scenario in §7 ("compliance team audits modelBindingTag logs") is implementable with WIMSE's audit-log fields and SPIFFE SVID metadata, without asking NFCU's compliance infrastructure to run a BN254 verifier.

**Why it works / why it fails:** The WIMSE gap is real: WIMSE as currently drafted does not address privacy-preserving unlinkability across RSes, and the human-in-the-loop atomic binding (H1's Groth16 + PLONK shared nonce) is novel. However, those properties address regulated niches (the NFCU case), not "the general case." The construction's claim — **general-case** dominance, not just regulated-niche — is the target. For the general case (Claude agent talking to Stripe), WIMSE + SPIFFE provides delegation, model binding via SPIFFE ID, and federation without ZK.

**In-threat-model? No** — The construction must either (a) scope its claim down to privacy-sensitive deployments where WIMSE is insufficient, or (b) justify why a ZK layer atop WIMSE is better than contributing the privacy-preserving extensions to WIMSE directly. The current §8 argument does not engage WIMSE at all, which is the most directly competitive standard for H5.
