# Tier 3 Adversarial — C1 Selective scope proof

## Persona: auth0\_pm

### Attack 1: The Latency Math Doesn't Work in Your Favor

- **Attack:** The construction claims AS-blindness as a feature — no AS roundtrip. But the honest latency accounting for an actual RS is: (a) RS generates and sends `sessionNonce` → (b) agent generates Groth16 proof → (c) RS verifies on-chain Merkle root freshness → (d) RS verifies proof. Step (b) with rapidsnark is <500ms. But step (c) requires reading Base Sepolia: either a live RPC call (~100–300ms latency, plus retry budget) or a cached signed root that introduces a staleness window (the construction says "cached signed root" without specifying freshness). Net round-trip: 500ms proof + 200ms RPC + serialization overhead ≈ ~800ms minimum in the happy path. WorkOS MCP auth token introspection is one HTTPS call: <50ms P50, <150ms P99, from their CDN edge. The claim "no AS roundtrip saves latency" is inverted — the ZK prover is the bottleneck, not the AS call.

- **Why it works:** §6 quotes <500ms for rapidsnark native but doesn't include the full protocol flow latency (nonce round-trip + on-chain read + network to RS). The "no AS roundtrip" saving is ~50ms; the proving cost is ~500ms. The construction wins on architectural properties but loses on wall-clock performance for the latency-sensitive RS operators (payment APIs, real-time scoring).

- **In-threat-model?** No — the construction must address this. It should specify: (1) the expected end-to-end P99 latency including nonce round-trip and Merkle root read, (2) a concrete caching policy for the on-chain root (max staleness, how the RS gets notified of root rotation), and (3) the operational cost of rapidsnark deployment vs. snarkjs, since <500ms depends on the native binary being present on the agent's host.

---

### Attack 2: Onboarding Cliff Kills Enterprise Distribution

- **Attack:** Compare day-one integration cost. WorkOS MCP auth: create a WorkOS account, register an MCP app, get `client_id` + `client_secret`, configure `WORKOS_CLIENT_ID` in your MCP server. Done in ~30 minutes. Stytch Connected Apps: same pattern, plus a dashboard for token lifetimes. Auth0 MCP: set up an Auth0 tenant you likely already have. Bolyra `SelectiveScopeProof`: generate a Baby Jubjub key pair (novel curve, no tooling in most enterprise stacks), compute `Poseidon5(modelHash, Ax, Ay, bitmask, expiry)` — which requires knowing your `modelHash` at key-generation time (what if the model gets updated?), submit an enrollment transaction on Base Sepolia and wait for L2 finality (~2s but subject to sequencer availability), wait for the next Merkle root update cycle to include your commitment, give the RS your operator public key and the Merkle root source-of-truth. The RS now must run a node or trust a third-party RPC provider for Base Sepolia, introducing a new infrastructure dependency. Day-one for a mid-market fintech is not 30 minutes; it is weeks of platform work.

- **Why it works:** The construction's §7 deployment scenario describes Alliant CU integrating with Acme Corp and Contoso Ltd's agent populations. In the OAuth model, Alliant already has an identity vendor. In the Bolyra model, Alliant's RS team must integrate with: circom-generated verification keys, Groth16 `vkey.json`, an on-chain registry address, and a Poseidon-based nullifier registry to prevent replay. Each RS must deploy and maintain a new verifier. The construction provides no SDK for the RS side — §5 maps circuit components to Bolyra primitives but doesn't address the RS integration path.

- **In-threat-model?** No — this is a GTM gap, not a cryptographic one, but it determines whether the construction is a research artifact or a product. The construction should specify: (1) what the RS integration looks like (ideally: a one-line SDK call that handles vkey pinning, root caching, and nullifier deduplication), (2) whether there is a hosted verifier mode for RSes that cannot run on-chain, and (3) what `modelHash` means when model versions change mid-deployment.

---

### Attack 3: The Adversarial-AS Threat Model Is a Non-Buyer Problem

- **Attack:** The construction's sharpest differentiator — "compromising one operator's AS cannot forge proofs for another operator's agents" — requires a specific deployment topology: multiple independent operators (Acme, Contoso) enrolling into a shared Bolyra tree and presenting to a third-party RS (Alliant) that has no bilateral AS relationship with either employer. The construction itself acknowledges in §7 ("Honest assessment") that in the single-institution case — which is the case for every enterprise evaluating a new auth protocol today — "the adversarial-AS claim is weaker." But the single-institution case is exactly what Auth0 MCP, WorkOS, Stytch, and Cloudflare Access target. The multi-operator agent marketplace (multiple independent employers, one shared RS, no bilateral AS) does not exist at production scale yet. MCP is 18 months old. The scenario that makes Bolyra uniquely necessary is speculative. Procurement's question is: "What risk does this solve for me *now*, not in a hypothetical future agentic economy?"

- **Why it works:** The construction's §8 comparative table describes the gap as "sharpest in the multi-operator setting." For a procurement decision at a credit union running MCP today, that setting is not their setting. They have one AS (their identity vendor), one set of agents (their own IT or a single fintech partner), and existing OAuth infrastructure. The adversarial-AS game (§3) is technically rigorous but is a non-event for their threat model. The scope privacy property (GLBA data minimization, §7 secondary scenario) is real and present-tense, but it doesn't require the full construction — BBS+ selective disclosure over a credential with individually enumerated permission claims achieves data minimization without ZK proving infrastructure.

- **In-threat-model?** Partially. The construction survives the cryptographic critique — the claim is valid for the multi-operator model. But the construction must address: why the RS should invest in this infrastructure *before* the multi-operator agent economy exists. A credible answer might be: future-proofing, regulatory alignment (GLBA data minimization is present-tense), or a bridging deployment model where a hosted AS-compatible proxy wraps the ZK layer so existing OAuth clients don't need to change.

---

### Attack 4: Revocation Is a Silent Hole

- **Attack:** The construction handles credential expiry (G7: `LessThan(64)(currentTimestamp, expiryTimestamp) === 1`) but provides no mechanism for immediate revocation. If an agent's EdDSA key is compromised at 14:00 and the credential's `expiryTimestamp` is set to midnight, the credential is cryptographically valid for proof generation for 10 hours. The on-chain Merkle tree is append-only (the construction says credentials are "enrolled" but doesn't describe a removal mechanism). Rotating the Merkle root to exclude a compromised credential requires: (1) the operator re-enrolling the entire tree minus the revoked leaf, (2) the RS picking up the new root. Step 5 of the RS verification protocol says "RS reads `agentMerkleRoot` from on-chain registry *or a cached signed root*" — the staleness of the cached root determines the revocation lag. No maximum staleness is specified. In the OAuth model, revocation is synchronous: AS marks the token invalid, next introspection call returns `active: false`. For financial RSes under GLBA and BSA transaction monitoring requirements, a 10-hour revocation lag for a compromised agent credential is a compliance gap that OAuth does not have.

- **Why it works:** The construction's §3 threat model lists adversary capabilities and the construction's security games (SSU, SP) but neither game addresses post-compromise revocation. The construction removes the AS from the real-time path as a feature (AS-blindness) but inherits the AS's revocation capability gap as a consequence. The RS caching policy for the Merkle root is the revocation latency floor, and the construction leaves it unspecified. This is an architectural trade-off that a compliance officer at a credit union will ask about on the first evaluation call, and the current construction has no answer.

- **In-threat-model?** No — the construction must address this. Concrete options: (1) specify a maximum Merkle root cache TTL (e.g., 5 minutes) and require the RS to re-read the root at that interval, giving revocation lag equal to TTL + one root-rotation cycle; (2) introduce a nullifier-based soft-revocation list (operator publishes revoked `credentialCommitment` hashes, RS checks before accepting proof); (3) make short credential lifetimes (`expiryTimestamp` set to current time + 1 hour) the operational recommendation, accepting that operators must re-enroll frequently. Each option has a cost; the construction should pick one and be explicit.


## Persona: cryptographer

Applied cryptographer. IACR publications. Reviews for CRYPTO/EUROCRYPT/S&P. I have read the construction. Here are four attacks.

---

### Attack 1: Blinded Nullifier Is Not a Nullifier — Replay Prevention Is Absent

**Attack:**

The RS is expected to store observed `blindedNullifier` values and reject duplicates. But `blindedNullifier = Poseidon2(Poseidon2(credentialCommitment, sessionNonce), blindingNonce)`, where `blindingNonce` is sampled fresh per presentation by the prover. An honest prover presenting the same credential with the same `sessionNonce` (e.g., if the RS naïvely reuses nonces, or if the adversary replays the RS's challenge to a second agent presentation) produces a *different* `blindedNullifier` each time due to the fresh `blindingNonce`. The RS cannot detect replay because the deduplication token changes on every honest submission — the blinded nullifier set never matches.

Conversely: replay prevention is the *only* mechanism that actually works here — it comes from the RS generating a fresh `sessionNonce` and requiring the proof to bind to it (G8 includes `sessionNonce` as an input). The `blindedNullifier` output adds no additional replay prevention that the `sessionNonce` binding doesn't already provide. So the circuit outputs a field element called a nullifier that provides zero nullifier semantics.

**Why it works against the construction:** The construction's §2 states `blindedNullifier` serves "replay prevention" (public output table). This is false. A scheme where the prover controls an unconstrained random field element as part of the deduplication token cannot provide replay prevention. The blinding is correct for *unlinkability*, but naming and describing this output as a "nullifier" is a category error with protocol-level implications.

**In-threat-model?** No. The construction must either: (a) drop the replay-prevention claim for `blindedNullifier` and rely solely on the sessionNonce binding (which is sufficient — state this explicitly), or (b) output a deterministic nullifier `Poseidon2(credentialCommitment, sessionNonce)` for replay detection as a *separate* public signal, accepting that this deterministic value is linkable within a single RS's session (which is acceptable since the RS already knows the sessionNonce). The current construction conflates two orthogonal goals — unlinkability and replay prevention — into a single output that achieves neither cleanly. The threat model never defines what "replay" means in the game definition, which is how this slipped through.

---

### Attack 2: Prover-Chosen Blinding Nonce Is Unconstrained — The SP Game Is Mis-Modeled

**Attack:**

The Scope Privacy game SP(λ) in §3 has the *challenger* sample `blindingNonce` "uniformly at random from F_p" (Step 2). In the actual protocol (§2, verification protocol Step 3), the *agent* samples `blindingNonce` locally. The circuit G9 and G10 accept any field element as `blindingNonce` — there is no circuit constraint that enforces uniformity, unpredictability, or even non-zero values. A prover setting `blindingNonce = 0` produces `blindedScopeCommitment = Poseidon2(scopeCommitment, 0)`, a deterministic value. Setting `blindingNonce = H(credentialCommitment)` (some fixed function) produces correlated outputs across sessions.

The reduction sketch for SP (§4) argues: "each blinded output is pseudorandom and independent of the agent index." This argument holds only when `blindingNonce` is genuinely uniform and independent across presentations. If the agent (prover) is adversarially controlled or uses a biased PRNG (seeded from model inference state, wall clock, or a constant), the PRF reduction over A5 fails because A5 requires the randomness input to be uniform. The game does not model an adversary who controls the prover's entropy source.

This is not a hypothetical concern. Agent implementations running inside LLM inference engines may have access to deterministic execution modes (e.g., fixed random seeds for reproducibility). An operator who wants to correlate an agent's presentations (to track which resources it accessed across RSes) needs only ship an implementation that uses `blindingNonce = 0`. The circuit accepts this and produces a valid proof. The RS has no way to detect it.

**Why it works:** The SP game's security argument requires the prover to be honest with respect to randomness. No part of the circuit or protocol forces this. The construction should either: (a) define the SP game in terms of an *adversarial* prover who controls `blindingNonce`, and prove that even then the RS cannot distinguish (this would require committing to the nonce before the challenge — a harder claim), or (b) add an explicit assumption that the prover samples `blindingNonce` honestly, escalate it to a named assumption (A6), and explain what deployment mechanism enforces it.

**In-threat-model?** No. The adversary model in §3 says "The agent's choice of `blindingNonce` (sampled locally by the prover)" is outside adversary control. But this is an assumption, not a protocol property. The threat model must state: what happens when the agent is compromised? Right now the answer is "unlinkability vanishes silently with no detectability." Compare BBS+ blind signatures: the blinding factor is committed before the issuer interacts, providing verifiable randomization at the protocol level. Bolyra has no equivalent mechanism.

---

### Attack 3: Groth16 Trusted Setup Is the Real Trust Anchor — The Adversarial-AS Narrative Displaces It

**Attack:**

The construction's headline claim (§1, §8) is that it achieves "adversarial-AS soundness" — the RS trusts math, not the AS. The SSU reduction (§4) argues that forgery requires breaking knowledge soundness of Groth16 (A1). This reduction is correct *conditional on the CRS being honestly generated*.

But the `SelectiveScopeProof` is a **new circuit**, distinct from the `AgentPolicy` circuit and the `HumanUniqueness` circuit that reuses the public Semaphore ceremony. §5 (Bolyra primitive mapping) says the proving system is "Groth16 (REQUIRED)" but does not specify what ceremony is used for the `SelectiveScopeProof` circuit's `.zkey`. The project's `pot16.ptau` is the powers-of-tau for project-specific keys. If the entity that ran this ceremony retained the toxic waste, they can forge a Groth16 proof for any statement — including `scopeSatisfied = 1` with an arbitrary claimed `permissionBitmask` that is *not* in the Merkle tree and *not* authorized by any operator. The adversarial-AS becomes irrelevant because the adversary doesn't need the AS; they forge proofs directly.

Formally: in the SSU game (§3), the challenger runs `Setup(1^λ)`. This hides the question of who computes the CRS. If the setup is subverted, the adversary A can win SSU with probability 1 (produce a valid `(π*, pubSignals*)` for any statement). The CRS trust assumption is at least as strong as — and arguably harder to audit than — the AS trust assumption. AS behavior is auditable (logs, compliance audits, behavioral anomalies). CRS toxicity is computationally undetectable after the ceremony.

The construction replaces one unauditable trust party (the AS) with another (the ceremony participants), without quantifying the comparative risk. The adversarial-AS narrative is compelling but is not formally superior unless: (a) the ceremony is a multi-party computation with published transcripts and threshold security (n-of-n honest majority), or (b) a transparent proof system (STARK, Halo2 with universal SRS) is used that eliminates per-circuit setup.

The construction acknowledges PLONK as an "OPTIONAL alternative." PLONK avoids per-circuit ceremony (uses a universal SRS), but still requires a universal powers-of-tau ceremony. The comparative setup trust between Groth16 (circuit-specific, pot16.ptau) and PLONK (universal SRS) is not analyzed.

**In-threat-model?** No. The threat model in §3 treats the CRS as outside adversary control by axiom ("Groth16 CRS (trusted setup is assumed honest)"). This is legitimate as a named assumption, but: (1) the assumption is not quantified (who ran the ceremony? how many parties? what's the multi-party threshold?), (2) the comparison with RFC 7662's trust assumptions is incomplete — RFC 7662 can be deployed with HSM-backed AS keys and real-time audit logs; the Groth16 ceremony is a one-time event with no forward auditability, and (3) the adversarial-AS claim in §8 ("RS trusts math, not any operator or AS") is overstated — the RS trusts the CRS, which is not math but a ceremony artifact.

---

### Attack 4: The SP Reduction Uses Honest-Verifier ZK; Malicious Verifier Attacks Break It in Composition

**Attack:**

The SP security argument (§4, Reduction sketch for SP, Step 1) invokes A4: "By A4, there exists a simulator S that, given only the public inputs and public outputs, produces a proof transcript indistinguishable from a real proof. Replace the real prover with S."

Groth16 satisfies *computational honest-verifier zero-knowledge* (HVZK) in the CRS model under the generic group model. In HVZK, the verifier follows the protocol honestly — specifically, it sends the public inputs (including `sessionNonce`, `currentTimestamp`, `requiredScopeMask`) without deviating. The simulator takes these public inputs and produces a fake proof.

But in Game SP (§3), Step 3 gives the adversary "oracle access to all prior proof transcripts from either agent to any RS (each with independently sampled blinding nonces)." Each RS in this oracle generates its own `sessionNonce` — some of these RSes may be *malicious* (controlled by the adversary). A malicious RS can deviate from the protocol in the choice of `sessionNonce`, for example:

- Setting `sessionNonce = H(agentMerkleRoot, requiredScopeMask)` — a value that correlates across RSes.
- Adaptively choosing `sessionNonce` based on previously observed `blindedNullifier` values.

Against a malicious verifier (RS), Groth16's HVZK guarantee does not directly apply — HVZK requires the verifier to be honest about its challenge. The Step 1 simulator replacement is only valid when the verifier generates its challenge (sessionNonce) honestly. Under adaptive challenge selection by a malicious RS, the simulator may not exist, or may not produce indistinguishable transcripts.

The construction doesn't claim UC security (correct — the document makes no UC claim). But the SP game includes oracle access to proofs sent to adversarial-controlled RSes (the adversary controls the AS, and potentially some RSes via §3 threat model: "observation of all prior proof transcripts to/from this RS and other RSes"). If those RSes are adversarial verifiers, the Step 1 HVZK simulation argument is incomplete.

This matters concretely: suppose an adversary (controlling a malicious RS) queries the agent oracle with a sequence of adaptive nonces chosen to probe the blinding nonce distribution. The oracle access in SP Step 4 is to "all prior proof transcripts" — which includes responses to these adversarially-crafted nonces. An adversary who can choose the sessionNonce as a function of previously observed outputs can potentially extract information about the blinding structure that a passive adversary cannot.

The reduction should be stated as: "for any PPT adversary A playing SP(λ), A's advantage is bounded under the assumption that all queried RSes generate sessionNonces independently and uniformly." This is a significant constraint that reduces the scope of the SP claim to the *honest RS* model, not the *adversarial RS* model. Given that the construction's headline adversarial claim is against a malicious AS, the reader expects a similarly strong adversarial model for the RS in the privacy game — and that model is not provided.

**In-threat-model?** Borderline. The SP game as written doesn't explicitly say the queried RSes are honest. The reduction sketch silently assumes HVZK suffices, which it does only for honest verifiers. The construction must either: (a) restrict the SP game to honest RSes and state this limitation explicitly, or (b) upgrade to simulation-extractable NIZK (e.g., Groth16 with a separate commitment binding the proof to a random oracle output), which provides security against malicious verifiers. Option (a) weakens the privacy claim; option (b) increases circuit overhead.


## Persona: cu_ciso

### Attack 1: Blinded Nullifier is Not an Audit Trail — NCUA Part 748 Appendix A §III.C

- **Attack:** An agent authorized under this construction executes a bill-pay transaction at 2:47am. The transaction is later flagged as suspicious. My NCUA examiner sits down and asks: *show me the access log proving this agent was authorized at the time of the transaction, and show me exactly what permissions it held.* What I can produce is a log entry containing `blindedNullifier = 0x1a4f…` and `blindedScopeCommitment = 0x93c2…` — two opaque 254-bit field elements. The RS cannot reverse them. The `blindingNonce` is prover-chosen and never persisted anywhere. The construction explicitly and correctly states (§3, Scope Privacy game) that two presentations from the same agent produce *distinct* blinded outputs — meaning I can't even correlate this log entry to prior sessions. My incident response produces: a random-looking number.

- **Why it works:** NCUA Part 748 Appendix A §III.C requires maintaining logs of access to member information systems in a form that supports examination review. The construction's privacy guarantee — fresh `blindingNonce` per presentation producing pseudorandom output — is cryptographically correct and operationally catastrophic for audit purposes. The construction cannot simultaneously provide unlinkability (§3 SP game) and produce an examiner-readable audit trail linking a transaction to a specific agent identity. This is not a gap the construction addresses; §7 and §8 mention GLBA data minimization but say nothing about how the credit union produces incident evidence.

- **In-threat-model?** No. The construction must address this. Either (a) a side-channel audit ledger stores the unblinded `rawNullifier` in a tamper-evident log accessible only to the institution's auditors (which undermines the unlinkability claim and raises its own custody questions), or (b) the construction explicitly scopes out audit trail requirements and defers to a layer-above logging system — which means the credit union needs to build that system before the construction is deployable.

---

### Attack 2: Operator Key Custody is a Third-Party Vendor I Have No Agreement With — GLBA Safeguards Rule §314.4(f)

- **Attack:** Under §7's primary scenario, the agents accessing Alliant Credit Union's bill-pay API are credentialed by *Acme Corp* and *Contoso Ltd* — employers I, Alliant's CISO, have never heard of and have no contractual relationship with. The construction's security argument (§4, A3) depends entirely on operator EdDSA private key integrity. My NCUA examiner opens my Vendor Management Policy and asks: *what due diligence have you performed on the entities whose cryptographic signatures you are accepting as authorization for member account access?* The construction provides zero mechanism for me to assess, audit, or contractually bind Acme Corp. I don't know whether Acme's Baby Jubjub key is in an HSM, a developer's laptop, or a CI/CD secret. I don't know their key rotation policy. I don't know who at Acme has access to that key.

- **Why it works:** GLBA Safeguards Rule §314.4(f) requires financial institutions to "select and retain service providers that maintain appropriate safeguards" and to "contractually require service providers to implement appropriate safeguards." The construction reframes this relationship — the on-chain Merkle root is the trust anchor, not the operator — but this doesn't dissolve my vendor management obligations. Any entity whose signing key can authorize access to member financial data is a de facto critical service provider under GLBA. The construction's adversarial-AS model (§3) correctly isolates compromise to per-operator scope, but this is a cryptographic property, not a compliance artifact. My examiner does not accept "Groth16 knowledge soundness" as a substitute for a vendor risk assessment. The construction says nothing about how a resource-server credit union manages the population of operators it implicitly trusts.

- **In-threat-model?** No. The construction must address this. The architecture needs either (a) a registry permissioning layer where the credit union explicitly allowlists operator public keys (creating a bilateral trust relationship the construction was designed to avoid), or (b) a formal acknowledgment that GLBA §314.4(f) vendor management obligations attach to operators and that deployers must build that governance layer on top of this protocol.

---

### Attack 3: My Trust Anchor is a Public L2 Blockchain with No SLA — FFIEC CAT Business Continuity

- **Attack:** Verification step 5 (§2 verification protocol) requires the RS to check that `agentMerkleRoot` matches the on-chain registry. The construction acknowledges a 30-entry circular history buffer as a caching mechanism (§5), but does not specify the cache TTL, who can invalidate it, or what happens when the cache is stale. Base Sepolia has experienced multi-hour degraded states. My core processor (Jack Henry) contractually guarantees 99.99% availability — 52 minutes of downtime per year. A public L2 blockchain operated by Coinbase has no SLA I can sign. When Base is degraded and my agents can't get fresh Merkle roots, and my cached roots are older than my risk policy allows, do I fail open or closed? The construction doesn't say.

- **Why it works:** FFIEC CAT Business Continuity domain requires documented RTO and RPO for all systems supporting critical member services. The construction's §3 threat model lists what the adversary doesn't control — including "the on-chain registry contract" — but doesn't model the availability failure scenario at all. This isn't an adversarial scenario; it's routine infrastructure. The 30-entry root history buffer (§5) is the right direction, but the construction needs to specify: maximum acceptable root age, procedure when all cached roots are stale, and how the credit union demonstrates documented availability controls to an FFIEC examiner. "Trust the blockchain" is not an RTO. My board expects me to tell them what happens to bill-pay when the trust anchor is unavailable.

- **In-threat-model?** No. The construction must address this. A concrete liveness spec is needed: maximum root cache age (e.g., 24 hours), fail-closed behavior (reject proofs when all cached roots exceed TTL), and a business continuity narrative mapping to FFIEC CAT "Business Continuity Management" controls.

---

### Attack 4: Proof Verification is Binary — My Tier 1 Ops Cannot Diagnose Failure at 2am

- **Attack:** A member calls at 2:17am: "My financial assistant just got blocked trying to pay my mortgage." My Tier 1 ops agent opens a ticket. The API returned a 403. The only diagnostic artifact is that `Groth16.Verify(vkey, pubSignals, π)` returned false. The construction produces a single-bit result. It does not — cannot, by design — indicate *why* verification failed: Is the credential commitment not in the current Merkle root? Did the operator fail to re-enroll after a credential rotation? Is the `currentTimestamp` outside tolerance? Has the credential expired (G7)? Is the on-chain root stale? Is the `sessionNonce` replayed? Without the private witness, no one can distinguish these failure modes from the outside.

- **Why it works:** The construction's zero-knowledge property (§4, A4) is precisely what makes failure diagnosis impossible at the RS layer — hiding the witness is the point. But NCUA examination question 748-A §II "Access Rights Administration" asks how the institution *administers and monitors* access — which requires operationally actionable error states. The construction exports `scopeSatisfied ∈ {0, 1}` as the only access control signal. This is correct for privacy; it is a Tier 1 ops nightmare. The verifier cannot tell the difference between "this agent was never enrolled" and "this agent's credential expired yesterday" — both produce the same binary failure. My ops team cannot triage the member's complaint, cannot determine whether this is a configuration issue or a security event, and cannot decide whether to escalate to an incident.

- **In-threat-model?** No. The construction must address this. A structured error taxonomy is needed at the protocol layer above the proof verifier — a way for the agent (if honest) to provide a non-ZK diagnostic reason for expected failures (e.g., "credential expired, please re-enroll") without undermining proof integrity. This is an operational layer the construction currently delegates silently to implementers. Without it, the credit union cannot meet NCUA examination requirements for access rights monitoring or produce operationally manageable member-facing error handling.


## Persona: rfc7662_advocate

---

### Attack 1: RFC 8693 Token Exchange Collapses the AS-Blind Claim at Runtime

- **Attack:** The construction defines "AS-blind" as: no AS roundtrip *at proof time* (§2, verification protocol steps 1–6). But RFC 8693 (Token Exchange) lets an agent request a narrowed, RS-specific token *immediately before presenting to an RS*, scoped only to that RS's required permissions via the `scope` and `resource` parameters (combining RFC 8707). This exchange is a single POST to the token endpoint — comparable latency to generating a Groth16 proof. The resulting JWT (with per-RS scope, audience-bound, short-lived) is then presented to the RS offline, no introspection roundtrip needed (signed JWT introspection response per draft-ietf-oauth-jwt-introspection-response). The agent drives the disclosure. The RS sees only the exchanged scope.

- **Why it works / why it fails:** It works in the honest-AS model and eliminates the "AS must pre-configure per-RS policy" objection raised in §8. It fails against §3's adversarial-AS model: if the AS is compromised, it can issue a fraudulent exchanged token claiming escalated scope, and the RS has no independent verification path — the signed JWT proves only "the AS said this." The construction is correct that **under adversarial-AS, token exchange is worthless because the trust anchor is the entity you've declared adversarial.** But the RFC 8693 path demolishes the claim that AS-blindness is *unique* to ZK in the honest-AS case, which is the realistic deployment case for §7's secondary (single-institution) scenario.

- **In-threat-model?** Partially. The construction survives in the adversarial-AS, multi-operator model (§7 primary). But it has not scoped its uniqueness claim tightly enough: §1's claim "no composition of RFC 7662… can simultaneously achieve AS-blindness…" overstates. The correct claim is "no composition achieves AS-blindness *under an adversarial AS*." The construction must either sharpen the claim to require the adversarial-AS model, or acknowledge that RFC 8693 + signed JWT introspection matches AS-blindness in the honest case.

---

### Attack 2: PPIDs + RFC 8707 Already Provide RS-Layer Unlinkability — the AS-Correlation Advantage Is Not Load-Bearing in Honest Deployments

- **Attack:** Section 8 claims "cross-RS unlinkability (full)" as a differentiator. The RFC 7662 toolbox provides this at the RS layer today: OIDC Pairwise Pseudonymous Identifiers (PPIDs, §8.1 of OIDC Core) give each RS a distinct `sub` for the same agent. RFC 8707 audience-bound tokens prevent token reuse across RSes. The RS never sees a stable cross-RS identifier. The agent presents a different token (different `jti`, pairwise `sub`, RS-specific `aud`) to each RS. RS A and RS B cannot correlate these presentations without colluding with the AS — and §8 of the construction acknowledges "BBS+ presentations are unlinkable at the RS layer" for the W3C VC baseline.

- **Why it works / why it fails:** The attack surfaces a precision problem in the uniqueness table (§8, row "Cross-RS unlinkability"). The construction's actual advantage is specifically **AS-layer unlinkability**: the AS cannot correlate which RSes an agent visits because it's never contacted at proof time. The `blindingNonce` design (§4, SP game) achieves per-presentation output randomization — but so does issuing per-RS short-lived JWTs with pairwise subjects. The construction never names AS-layer correlation as the specific distinguishing property; it conflates it with the broader "full" unlinkability claim. Against an adversarial AS (§3), PPIDs are worthless — the AS holds the PPID mapping and can trivially correlate. The Bolyra construction wins there. But the §8 row should read: "AS-layer correlation eliminated; RS-layer correlation: both achieve this." The current framing overstates the distinction.

- **In-threat-model?** Partial. The construction survives under adversarial-AS. But the §8 cross-RS unlinkability row needs qualification: PPIDs + RFC 8707 match Bolyra at the RS layer. The unique property is AS-layer unlinkability, and the construction must call this out explicitly rather than presenting "full" unlinkability as unambiguously unique.

---

### Attack 3: BBS+ Over a Committed Bitmask + Sigma-Protocol Bitwise Predicate Matches the Core Claim in Honest-Issuer Deployments

- **Attack:** Section 8 states: "BBS+ does not support bitwise AND over a multi-bit field, nor implication closure across hierarchical permission tiers." This is conflating BBS+'s native predicate set with what BBS+ *can be composed with*. The standard technique: encode the 64-bit bitmask as a single committed BBS+ message (one element of the scalar field). The issuer (AS-equivalent) signs it. At presentation time, the holder opens a Pedersen commitment to the bitmask and runs a supplementary Sigma protocol (or Bulletproof range/bit decomposition) that proves `bitmask & requiredMask == requiredMask` in zero knowledge — without revealing other bits. Implication closure (G6 constraints) is expressible as additional linear constraints in the same Sigma protocol. This is not theoretical: BBS+ + Bulletproofs is the approach in Hyperledger AnonCreds v2 and academic work (Camenisch-Lysyanskaya credentials). Proof size is *not* constant — Bulletproof bit decomposition grows O(log n) in the bit width — but for n=64, this is small and fixed.

- **Why it works / why it fails:** It partially matches: honest-issuer, no-AS-roundtrip-at-presentation, bitwise predicate, implication closure are all achievable. It fails on: (1) Proof size — Bulletproofs are ~600–1200 bytes for 64-bit decomposition vs. 192 bytes Groth16, not constant in the sense the construction claims (though still compact). (2) Adversarial-AS soundness — the BBS+ issuer can sign a fraudulent bitmask, and the holder's predicate proof is sound only over the value the issuer committed to; if the issuer lies at issuance, the predicate reflects the lie. No on-chain enrollment anchor exists. (3) Model identity binding — BBS+ has no concept of `modelHash`. The construction survives on points 2 and 3. But §8's categorical "BBS+ does not support bitwise AND" is wrong as written and needs correction: the correct statement is "BBS+ alone does not, but BBS+ composed with bit-decomposition proofs does — and the remaining gaps are adversarial-AS soundness and model binding."

- **In-threat-model?** Construction survives on the adversarial-AS and model-binding grounds. But the §8 comparison table contains a factual mischaracterization of BBS+ expressiveness that a well-prepared reviewer will flag. Fix the row or the claim narrows to "native BBS+."

---

### Attack 4: The Circular Root Buffer Creates a Revocation Lag the RFC 7662 Baseline Doesn't Have — and the Construction Is Silent on This

- **Attack:** Section 5 notes the on-chain anchor is an "Agent root history buffer (30-entry circular)." The RS accepts proofs against any of the 30 most recent Merkle roots. This is necessary for liveness — agents generate proofs while new enrollments update the root. But it creates a structural revocation lag: to revoke a credential, the operator removes the leaf from the tree and posts a new root. The revoked credential remains provable against any of the 29 prior roots still in the history buffer. An adversarial or compromised agent can continue generating valid `SelectiveScopeProof` instances — for potentially 30 root epochs — after the operator has revoked the credential on-chain.

  Compare RFC 7662: the AS returns `{ "active": false }` and the RS honors it immediately. Revocation latency is bounded by the RS's token cache TTL (configurable, often 60 seconds). Even with signed JWT introspection response (offline verification), the short expiry (5–15 minutes) bounds the revocation window tightly. The RFC 7662 baseline handles *revocation as a first-class operation*; the construction handles it as an eventual side-effect of the root rotation schedule.

  The construction's §3 threat model explicitly makes the AS adversarial — meaning an AS that would return `active: false` for a valid credential (denying service) or `active: true` for a revoked one (granting escalated access). But the construction never defines what "revoke" means in the Bolyra model, what the expected root rotation frequency is, or what the maximum revocation lag is. The adversary from §3 who controls `n - 1` colluding agents can pair this with a compromised agent to exploit the lag window.

- **Why it works:** The attack is in-threat-model and unaddressed. Section 7 argues that Bolyra prevents a compromised AS from upgrading an agent's permissions — correct. But the construction does not address the dual case: preventing a revoked-but-still-valid-against-old-root agent from continuing to prove permissions it no longer holds. The RFC 7662 advocate can legitimately claim that the baseline's AS-mediated revocation is strictly faster and more operationally predictable than waiting 30 root epochs.

- **In-threat-model? Yes — construction must address.** The construction needs either: (a) a defined root rotation cadence and explicit maximum revocation lag as a protocol parameter, (b) a revocation registry or nullifier set on-chain that the RS checks in addition to root membership (which reintroduces a hot-path check, partially re-coupling to an on-chain call), or (c) acknowledgment that revocation latency is a known tradeoff and that for use cases requiring instant revocation, the construction is not suitable.


## Persona: spiffe_engineer

You are building a new identity layer to solve a trust-anchor problem that the workload identity stack has already internalized. I run SPIFFE/SPIRE at a Fortune 500 — hundreds of trust domains, millions of SVIDs, WIMSE co-authorship. Let me show you where your construction breaks or reinvents, and where it genuinely outpaces what I have.

---

### Attack 1: ZK Attestor Plugin — You Built at the Wrong Layer

- **Attack:** SPIRE's node and workload attestation pipeline is pluggable. A custom ZK attestor could verify EdDSA credential commitments and Merkle membership during SVID issuance, then embed the operator-signed permission bitmask as a custom X.509 extension OID in the resulting X.509 SVID. The RS presents the mTLS certificate, reads the extension, enforces scope policy. No new wire protocol, no Circom circuit, no on-chain dependency — just a SPIRE plugin and standard mTLS. Your §3 Verification Protocol is architecturally isomorphic to SVID issuance + mTLS handshake. You call it a "Groth16 proof"; I call it a certificate with a custom SAN.

- **Why it works / why it fails:** The attack is fatal to the *existence* claim ("we need a new protocol") but not to the *property* claim. X.509 extensions are opaque blobs to the RS — the RS reads the full bitmask from the extension. There is no mechanism for "prove bit 2 is set without revealing bits 5 and 7" in X.509. JWT SVID is closer, but BBS+ selective disclosure (your §8 baseline) still cannot evaluate `reqBits[i] * (1 - permBits[i]) === 0` inside a credential-committed bitfield with implication closure (G5 + G6). The scope privacy property (§3, Game SP) is not achievable via SVID extension, because the full bitmask must appear somewhere the RS can verify — and that is exactly the bit you are encrypting.

- **In-threat-model?** **Yes** for scope privacy. The construction survives on that property. But the construction MUST explicitly acknowledge the SPIFFE attestor path and explain *which* properties it cannot achieve at the SVID layer — currently §8 addresses only the RFC 7662 / BBS+ baseline. The absence of any SPIFFE discussion will be the first question from any enterprise operator reading this.

---

### Attack 2: On-Chain Root Oracle ≡ New AS (Trust Anchor Substitution Attack)

- **Attack:** Your §3 Verification Protocol step 5 reads `agentMerkleRoot` "from on-chain registry (or a cached signed root)." This parenthetical hides the entire trust model. An RS has three paths to get that root: (a) run a Base Sepolia full node — operationally equivalent in complexity and attack surface to running a SPIRE server; (b) query an RPC endpoint (Alchemy, Infura, QuickNode) — this is structurally an AS: a trusted third party whose introspection response the RS accepts without independent verification; (c) accept a signed root from a designated party — that signing party is the new AS, directly. The "adversarial AS" threat in §3 collapses if the RPC provider is the adversary, because the RS has no way to distinguish a tampered root from a legitimate one without a full node or a light client. The construction evicts the Authorization Server and installs an RPC provider in its place — same trust shape, different branding.

- **Why it works / why it fails:** This attack is strongest against the "RS trusts math, not any operator or AS" claim in §8. The math is only as trustworthy as the root the RS reads. Against the *formal* security game (§3, Game SSU), the attack is outside scope — the challenger provides `agentMerkleRoot` directly, eliding the oracle delivery problem. But real deployments must solve root delivery, and the construction says nothing about how. In SPIFFE terms: the SPIRE server's CA bundle delivery has the same problem, and the solution is bundle endpoint authentication (RFC 8555 ACME equivalent). The construction needs a comparable answer — e.g., a Base Sepolia light client, EIP-1186 storage proofs, or a signed root delivered over an authenticated channel with explicit trust assumptions stated.

- **In-threat-model?** **No** — the construction must address root delivery trust. The formal game sidesteps it; the deployment scenario (§7) does not. This is a gap the construction must close.

---

### Attack 3: Delegation Chain `blindedScopeCommitment` Reuse Breaks the Unlinkability Claim

- **Attack:** §2 "Delegation chaining interop" states that the on-chain registry stores `blindedScopeCommitment` from the initial `SelectiveScopeProof`, and the `Delegation` circuit re-derives it internally using the same `blindingNonce` as a private input, matching it against the stored value. This means `blindedScopeCommitment` is a *stable, public, on-chain value* that is shared between the initial selective scope proof and every downstream delegation proof. Any observer — including two colluding RSes, or a passive on-chain observer — can correlate: (1) the initial RS presentation (which produced the stored `blindedScopeCommitment`) with (2) every delegation proof that references the same stored value. §8 claims "cross-RS unlinkability (full)" and "neither RS can correlate the presentations to the same agent — even if they collude." This claim is false when a delegation chain exists: the on-chain registry publicly links the initial presentation to its delegation chain through the shared `blindedScopeCommitment`.

- **Why it works:** The blinding nonce is fresh *per presentation* in the standalone `SelectiveScopeProof` case (Scope Privacy, Game SP). But in the delegation case, the construction explicitly reuses the *same* `blindingNonce` to allow chain linking. Reuse of `blindingNonce` across the initial proof and the delegation proof makes `blindedScopeCommitment` a pseudonym for that credential in that delegation chain — and because it is stored on-chain, it is globally visible. This is a design contradiction: the `blindingNonce` cannot simultaneously provide per-presentation unlinkability (requiring it be discarded after use) and delegation chain continuity (requiring it be retained and reused).

- **In-threat-model?** **No** — the construction's §8 unlinkability claim is overstated. The construction must either (a) restrict the unlinkability claim to the non-delegation case and explicitly carve out delegation chains, or (b) redesign delegation continuity to use a different chain-link mechanism that does not reuse the `blindingNonce` — e.g., a separate delegation commitment with its own fresh randomness, linked via a private commitment the on-chain registry verifies without public exposure.

---

### Attack 4: WIMSE Token Exchange Already Scopes This — You Are Not Contributing; You Are Forking

- **Attack:** `draft-ietf-wimse-arch` §4 (Workload to Workload Interactions) defines a token exchange pattern where a caller workload presents a bound token to a service, which can narrow scope and re-issue. WIMSE's "caller POP" (proof of possession) mechanism binds the token to the caller's runtime workload identity — analogous to your model hash binding. The selective disclosure requirement is already in the WIMSE working group's scope: WIMSE-arch explicitly identifies "minimal disclosure" as a design goal. The right contribution is a WIMSE ZK attestor profile: a WIMSE extension where the "scope token" is replaced by a Groth16 proof, preserving the WIMSE wire format and trust federation model while adding ZK-based scope privacy. Instead, you have defined a new wire protocol, a new on-chain registry, a new proof format, and a new trust anchor — none of which are composable with existing SPIFFE/WIMSE deployments. Enterprise operators will not deploy a new identity stack; they will extend what they have.

- **Why it fails against the construction:** This is a standards-process attack, not a cryptographic one. The construction's formal claims (SSU, SP games) are not weakened by WIMSE's existence. But "the construction is correct" and "the construction will be adopted" are orthogonal. The WIMSE gap is real: WIMSE does not currently have a ZK proof profile, so Bolyra's circuit is not redundant today. The construction should frame itself as a WIMSE extension candidate — contributing the `SelectiveScopeProof` circuit as a WIMSE ZK token type — rather than as a competing protocol. That framing also addresses the "wrong layer" objection: you are not replacing SPIFFE; you are adding a ZK token type to WIMSE's token exchange, with SPIFFE SVIDs as the workload identity anchor for the operator's EdDSA key.

- **In-threat-model?** **Yes** — the construction's cryptographic claims survive. But the construction must acknowledge WIMSE explicitly, position itself as a WIMSE ZK profile rather than a replacement protocol, and identify the specific WIMSE gap it closes (no standardized ZK scope proof type). Failing to do so will cause every SPIFFE/WIMSE practitioner reviewer to reject the protocol as NIH engineering.
