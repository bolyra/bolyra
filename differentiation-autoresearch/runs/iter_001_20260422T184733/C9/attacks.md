# Tier 3 Adversarial — C9 Forward-secure agent delegation

## Persona: auth0_pm

---

### Attack 1: Epoch Discipline Collapse — Forward Secrecy Is Only as Good as Your Operators

- **Attack:** The construction's forward secrecy guarantee is conditioned on the agent actually rotating epoch secrets. Section 2 (Construction) defines a Poseidon one-way hash chain `s_{i+1} = H(s_i || epoch_i)` and places epoch rotation logic in `EpochRotation` (~879 constraints). But *who triggers the rotation, and when?* Auth0 and WorkOS rotate tokens automatically — the platform enforces the policy. In Bolyra, epoch rotation is a circuit invocation the operator must orchestrate. A 30-day autonomous Claude agent (Scenario 1) that never calls `EpochRotation` between day 1 and day 31 has effectively one epoch — and compromise on day 31 yields the entire session graph. The construction's forward secrecy window is operator-defined, not cryptographically enforced.

- **Why it works / why it fails:** The construction does not appear to specify a *maximum epoch lifetime* enforced at the protocol level, nor a mechanism that prevents a session proof from being generated without a recent epoch rotation. A lax operator gets zero forward secrecy while believing they have it. This is worse than DPoP: at least DPoP's failure mode (key compromise = full history exposed) is documented and understood. Bolyra's failure mode is silent.

- **In-threat-model?** **No** — the construction must address: (a) protocol-enforced epoch rotation bounds (e.g., `assert epoch_age < MAX_EPOCH_WINDOW` in `ForwardSecureAgentSession`), and (b) what the security claim degrades to when operators skip rotations.

---

### Attack 2: The TCO Argument — You Are Selling ZK Infrastructure to a Credit Union IT Department

- **Attack:** Auth0 MCP auth is an API call. WorkOS MCP auth is an API call. The Bolyra construction requires a PLONK prover running alongside every agent. Section 6 (Circuit Cost) claims <5s proving time per epoch rotation and per session. A credit union running 500 concurrent autonomous agents (realistic for loan processing, fraud screening, member services) needs 500 parallel PLONK provers — or a queued prover that introduces latency into every tool call. At $0.08/vCPU-hour on EC2, continuous proving for 500 agents costs ~$35k/month in compute alone, before staffing a ZK infrastructure engineer. Auth0 charges per MAU. The buyer's CFO comparison is trivial: Auth0 invoice vs. AWS invoice + hire.

- **Why it works / why it fails:** Section 6 addresses constraint counts and wall-clock time but not infrastructure topology or cost-at-scale. The forward secrecy property only matters if the customer actually deploys it — and the deployment cost may make the threat model academic. A solo founder cannot provide the managed prover service that would close this gap without significant capital.

- **In-threat-model?** **No** — the construction must address the operational architecture: is there a hosted prover? What is the SLA? What does a credit union's IT department actually have to run?

---

### Attack 3: The Audit Framework Gap — Your CISO Won't Sign "Poseidon PRF Security"

- **Attack:** Section 4 (Security Argument) reduces to four assumptions: Poseidon preimage resistance (A1), Poseidon PRF security (A2), PLONK knowledge soundness in AGM+ROM (A3), DL on Baby Jubjub (A4). None of these appear in NIST SP 800-57, FIPS 140-3, or any framework a credit union's auditor recognizes. NCUA examiners audit against FFIEC guidelines; their cryptography checklist references AES-256, SHA-2/3, RSA, and ECDH over NIST curves. Auth0 is SOC 2 Type II certified, FedRAMP in process. When procurement asks "what certifications does Bolyra have," the answer today is: none. The CISO will not approve a production dependency on an uncertified hash function (Poseidon was designed for ZK circuits, not general-purpose NIST-reviewed security) regardless of how elegant the reduction is.

- **Why it works / why it fails:** The construction's baseline impossibility argument (Section 8) correctly shows DPoP cannot match the IND-FS-AGENT game. But the procurement question is not "which is cryptographically superior" — it is "which vendor will I be fired for choosing." Poseidon's security is well-studied in the ZK literature but has no NIST standing. Baby Jubjub is not a NIST curve. A solo founder cannot obtain SOC 2 Type II or FIPS 140-3 validation on a 6-month runway.

- **In-threat-model?** **No** — the construction must address the compliance posture: either argue why Poseidon + Baby Jubjub is acceptable under existing NCUA/FFIEC guidance, or define a migration path to NIST-approved primitives (SHA-256-based Merkle chains, P-256) with quantified constraint cost impact.

---

### Attack 4: Short-Lived Token Parity — The Practical Equivalence Attack

- **Attack:** Section 8 (Baseline Impossibility) argues DPoP cannot satisfy IND-FS-AGENT because "compromise of the key retroactively reveals the agent's prior activity graph." This is true for long-lived keys. But Auth0, WorkOS, and Stytch all issue access tokens with 15-minute lifetimes by default, bound to short-lived DPoP key pairs generated per-session. The practical forward secrecy window for a 15-minute DPoP-bound access token is 15 minutes — the adversary who compromises the key after expiry gets an expired token that the resource server rejects. For Scenario 2 (leaked key in public repo), if the agent rotates its DPoP key pair every session and access tokens expire, what does the adversary actually recover from the git leak? Expired tokens for completed sessions. The construction's impossibility argument requires the reader to assume operators use long-lived DPoP keys; it does not engage with the short-lived-token + per-session-key-pair pattern that all three incumbents recommend and enforce by default.

- **Why it works / why it fails:** The construction's Section 8 argument (specifically "retroactive verifiability" and "deletion ≠ forward secrecy") would need to show that even with 15-minute token lifetimes and per-session DPoP key pairs, a DPoP construction still fails IND-FS-AGENT while Bolyra passes. If the adversary receives the DPoP private key at time T and all prior access tokens are expired, what is the concrete attack? The construction does not formalize this. If the answer is "the adversary can still link sessions via correlation of the DPoP public key across resource server logs," then the construction needs to say so explicitly — because that is a much narrower claim than "no bearer-token or DPoP-bound OAuth construction achieves this."

- **In-threat-model?** **No** — the construction must add a formalized comparison case: DPoP with per-session key pairs + 15-minute token lifetimes, and show where this configuration still fails IND-FS-AGENT. Without it, the impossibility argument is attacking a strawman configuration that no security-conscious incumbent operator uses.


## Persona: cryptographer

I'll critique C9 against its stated reductions (A1–A4) and the three circuits. No construction exists without a simulator, a game, and a reduction. Let's stress-test each.

---

### Attack 1: Epoch Public Key Sequence Breaks Pseudonymity Without a Separate Unlinkability Argument

**Attack:** The adversary compromises the agent key at epoch T, obtaining `s_T`. The construction derives session identifiers (or nullifiers) as `nul_t = H(s_t ∥ scope_id)` and the epoch public key as `pk_t = g^{s_t}` on Baby Jubjub. During normal operation the AS sees `(epoch_id_t, pk_t, nul_t)` for each session. Post-compromise, the adversary has the sequence `{pk_1, pk_2, ..., pk_T}` from observed transcripts. The adversary knows `s_T` and thus `pk_T`. They now ask: can they verify, for any `s'`, that `H(s') = s_T` and `pk' = g^{s'}` — i.e., does `pk_{T-1}` correspond to `s_{T-1}`? Preimage resistance says they cannot *find* `s_{T-1}`, but the construction must additionally show that `pk_1, ..., pk_{T-1}` are computationally pseudorandom / unlinkable to `pk_T` even given `s_T`. The security argument only reduces to **Poseidon preimage resistance (A1)** and **DL on Baby Jubjub (A4)** independently. There is no hybrid argument showing the joint distribution `(pk_1, ..., pk_T, s_T)` reveals nothing about which `pk_i` corresponds to which `s_i`. If the epoch key sequence is deterministic from the initial seed and the adversary can enumerate forward from a guessed `s_0`, this becomes a brute-force-plus-verification attack on the seed space.

**Why it (partially) fails:** If `s_0` has enough entropy and H is a PRF (not just one-way), the chain is pseudorandom and enumeration fails. But the construction's Section 4 claims reduction to *preimage resistance*, not PRF security. Preimage resistance is strictly weaker than PRF security.

**In-threat-model?** No — the construction must either (a) replace assumption A1 with "Poseidon is a PRF" and add a hybrid argument across the epoch chain, or (b) explicitly show that the epoch public key sequence leaks nothing about prior sessions even given `s_T`. As written, the unlinkability claim for the public key sequence is unsupported.

---

### Attack 2: Subverted SRS Collapses PLONK Knowledge Soundness

**Attack:** The construction invokes "PLONK knowledge soundness in AGM+ROM" (assumption A3). PLONK's SRS is updatable but not universally composable under a subverted setup. If the Bolyra platform (or any party controlling the ceremony) generates a trapdoor `τ` for the SRS, they can extract the witness from any proof — specifically, they can extract `s_t` from any `ForwardSecureAgentSession` or `EpochRotation` proof. With `{s_1, ..., s_T}` extracted from pre-T proofs, the adversary recovers the full epoch chain retroactively, reconstructs every nullifier, and links every session. Knowledge soundness *requires* the SRS to be honestly generated; the reduction in A3 assumes this. The construction does not specify a trust model for the SRS or whether the ceremony is multi-party.

**Why it matters beyond standard ZK:** In Groth16, the per-circuit toxic waste is fatal if retained. PLONK's updatability mitigates this with sufficient contributors, but the construction gives no ceremony specification. For the whistleblower scenario (Section 7), a single-contributor SRS generated by Bolyra itself is catastrophically broken: Bolyra becomes an extraction oracle for every session proof ever generated.

**In-threat-model?** No — the threat model (IND-FS-AGENT) specifies adversary capabilities in terms of key compromise but is silent on the setup assumption. The construction must either (a) add a "subverted setup" experiment and show the property degrades gracefully (e.g., to computational binding without knowledge extraction), or (b) specify a verifiable multi-party ceremony with a trust threshold and prove that a minority-corrupted ceremony preserves A3.

---

### Attack 3: IND-FS-AGENT Game is Under-Specified for Colluding AS+RS

**Attack:** The claim is "sessions executed before T remain cryptographically unlinkable." The threat model defines an adversary that "receives the key at time T and sees all prior transcripts." But the construction's Section 3 (Threat Model) does not specify whether the adversary controls the Authorization Server (AS), the Resource Server (RS), or both. These are three different games:

- **Passive external adversary:** sees ciphertexts and proofs only. Reduction to A1–A4 plausibly works.
- **Active AS:** sees `(epoch_id, pk_t, nul_t, scope_id)` in the clear per session — the AS must see these to validate. Post-compromise, the AS can build the complete `(scope_id → nullifier)` mapping for all served sessions and check whether newly discovered sessions share a scope_id pattern.
- **Colluding AS+RS:** AS contributes scope metadata; RS contributes response payload fingerprints and timing. Correlating both reveals behavioral patterns that the ZK proof does not hide.

The nullifier scheme specifically: `nul_t = H(s_t ∥ scope_id)`. The AS necessarily knows `scope_id` (it issues the authorization). Post-compromise, the AS holds `(scope_id_i, nul_i)` pairs for every session it served. Given `s_T`, it cannot compute past `s_t` (preimage resistance), so it cannot check `H(s_t ∥ scope_id_i) = nul_i` for t < T. This is fine. But if the AS is the adversary *during* operation (active AS), it can log `(epoch_id_t, scope_id, nul_t)` tuples before any compromise and retroactively correlate once `s_T` is obtained — *if* it can enumerate the chain forward from any guessed anchor. This connects to Attack 1: the joint security argument is missing.

**In-threat-model?** Partially. The passive-adversary case is argued. The active-AS case is not addressed; the claim's comparison to DPoP explicitly mentions the AS ("compromise of the key retroactively reveals the agent's prior activity graph"), yet the AS's runtime view of the protocol is unmodeled.

---

### Attack 4: Delegation Chain Forward Secrecy Does Not Compose — No UC Argument

**Attack:** The `ForwardSecureDelegation` circuit (~9,064 constraints) enables agent A to delegate to sub-agent B. Suppose A delegates to B at epoch `t_A`, and B further delegates to C at epoch `t_B > t_A`. If C is compromised at time T (revealing `s_C^T`), what does the IND-FS-AGENT game guarantee about A's and B's prior sessions? The construction defines the game for a *single* agent. Composing forward secrecy through a delegation chain requires either:

1. A UC-style composition theorem showing the delegation protocol is a subroutine that preserves IND-FS-AGENT for the delegator, or
2. An explicit multi-party game where the adversary corrupts leaf agent C and the experiment measures linkability of A's sessions.

Neither appears in the security argument. The `ForwardSecureDelegation` circuit proves that B's delegation credential is bound to A's epoch key at time `t_A`, but if A's epoch key at `t_A` is derivable from the transcript (via the same public-key-sequence attack in Attack 1), the entire chain unravels. More concretely: if the delegation proof binds the delegatee's key as `H(s_A^{t_A} ∥ delegatee_pk_B)`, and the AS sees this commitment, then knowing `s_A^T` for any T ≥ `t_A` plus preimage resistance *prevents* computing `s_A^{t_A}` — but only if A's chain is truly one-way, which again requires the PRF argument missing from A1.

**Why the UC gap is not cosmetic:** In the CFPB whistleblower scenario (Section 7), the relay agent is B and the source is implicitly A. If B is seized (compromised at T), the adversary tries to link B's sessions back to A. Without a composition theorem, the construction has only argued single-agent forward secrecy; the multi-hop case is open.

**In-threat-model?** No — the delegation composition case is not covered by the stated IND-FS-AGENT game, and no UC argument is given. The construction must either bound the delegation depth and provide an inductive security argument, or prove a UC-composition theorem for the delegation circuit.


## Persona: cu_ciso

---

### Attack 1: Unlinkability Is the Exam Problem, Not the Solution

- **Attack:** The construction's core property — that pre-T sessions are *cryptographically unlinkable* even to the credit union — is precisely what fails NCUA Part 748 Appendix B and GLBA Safeguards Rule §314.4(e). Appendix B requires a "system to detect and monitor intrusions and unauthorized access to sensitive member data." If an autonomous Claude agent spends 30 days touching member loan files and I cannot reconstruct that activity graph after a compromise, I cannot satisfy the examiner's first question: *"Show me what the agent did and confirm no member PII was exfiltrated."* The construction conflates adversarial unlinkability (good) with operational unlinkability (catastrophic). It never defines a *privileged audit path* that lets the credit union's security team reconstruct session history using a separately-held audit key while still denying that capability to an external attacker. Without this, the construction's flagship scenario — "Bolyra prevents the attacker from reconstructing full activity history" — applies equally to the credit union's own forensics team. That is a compliance disqualifier, not a feature.

- **Why it works:** The construction (§7, Deployment Scenarios) describes the 30-day SECU agent but says nothing about how SECU's SOC team would respond if NCUA asks for an activity log of that agent during a routine examination or after a member complaint. The IND-FS-AGENT game in §3 correctly models the *external* adversary but does not model the *internal auditor* who needs read access.

- **In-threat-model?** No — construction must address. Propose: a dual-path log where sessions produce an encrypted audit blob under the credit union's HSM-held audit key in addition to the ZK proof. Unlinkability holds for external adversaries; forensic accountability holds for examiners.

---

### Attack 2: `s_0` Custody Collapses the Hash Chain

- **Attack:** The entire forward-secrecy argument reduces to the Poseidon one-way chain starting from epoch secret `s_0`. Section §2 (Construction) defines `s_{i+1} = Poseidon(s_i)` and claims compromise at epoch T cannot recover `s_0, …, s_{T-1}`. True — but only if `s_0` itself is never recoverable. The construction says nothing about *where `s_0` is generated, stored, or destroyed*. If `s_0` lives in the agent runtime (Lambda env var, K8s secret, browser memory), then a sufficiently early compromise — or a backup restore, a cold snapshot, a misconfigured CloudTrail export, a developer's local `.env` — yields `s_0` and the attacker re-derives the entire forward chain. GLBA Safeguards Rule §314.4(c)(3) requires "secure development practices" including encryption key management. NCUA examiners will ask: *"Where is the initial agent key material? Is it in an HSM? What is the key ceremony procedure? Who are the custodians?"* The construction has no answer. It assumes `s_0` is unrecoverable without defining how that property is operationally guaranteed.

- **Why it works:** This is not a cryptographic break — it's a deployment break. The circuits are correct; the key management posture is undefined. A credit union CISO cannot sign a vendor attestation that says "forward secrecy is guaranteed" when the guarantee depends on an undocumented assumption about where a seed lives.

- **In-threat-model?** No — construction must address. Propose: define `s_0` generation as a one-time HSM ceremony with the resulting commitment published on-chain and `s_0` immediately zeroized. Add a key ceremony section to §7. Reference FIPS 140-3 Level 2 minimum for the HSM.

---

### Attack 3: On-Chain Registry Availability vs. Core Processor SLA

- **Attack:** Section §6 (Circuit Cost) claims PLONK proving under 5 seconds and circuit overhead of 6.1%. What it does not address is the *on-chain nullifier registry availability SLA*. The construction requires checking nullifiers on-chain to prevent replay. If the on-chain registry has even a 0.1% monthly outage, that is ~43 minutes/month of unavailability. A credit union's core processor (Symitar, Fiserv) typically contracts 99.95% uptime (~4.4 hours/year of downtime). If the ZK nullifier registry is less available than the core, the construction creates a *single point of failure above the core* — any agent session attempted during registry downtime either (a) fails, breaking member-facing workflows, or (b) proceeds without nullifier check, breaking the replay-prevention guarantee. The FFIEC CAT Baseline domain "Cybersecurity Controls" requires that third-party dependencies do not degrade the institution's own availability posture. This is also a Vendor Management Policy trigger: the registry operator must provide an SLA, a business continuity plan, and an incident notification timeline — none of which are defined in the construction.

- **Why it works:** The construction never defines whether the nullifier registry is on a public L1, a permissioned L2, or an off-chain append-only log. The scenarios in §7 assume it just works. Operational staff at 2am cannot debug a ZK proof rejection caused by a stale registry state.

- **In-threat-model?** No — construction must address. Propose: define a fallback mode (e.g., optimistic local nullifier cache with deferred on-chain settlement) and specify minimum registry SLA. Cite the off-chain mode mentioned in the repo's prior commit history as a candidate path.

---

### Attack 4: SOC 2 Type II Gap — No Vendor Assurance for the Poseidon Implementation

- **Attack:** The security argument in §4 reduces to four assumptions: Poseidon preimage resistance (A1), Poseidon PRF security (A2), PLONK knowledge soundness in AGM+ROM (A3), and discrete log on Baby Jubjub (A4). All four depend entirely on Bolyra's *specific circuit implementations* being correct. The construction maps everything to "Bolyra spec sections" — but there is no reference to an independent audit of those circuits, a published security review, a bug bounty scope, or a SOC 2 Type II report covering the proving infrastructure. NCUA third-party risk guidance (Letter 07-CU-13, superseded by 2023 Interagency Guidance on Third-Party Relationships) requires that critical technology vendors provide evidence of independent controls testing. A ZK circuit library that has never been externally audited is categorically not an approved vendor under any credit union's Vendor Management Policy. If Bolyra's Poseidon gadget has an under-constrained wire — a class of bug that has burned Tornado Cash, Zcash, and multiple zkEVM implementations — the forward secrecy proof is void and the credit union has no contractual recourse because the construction never scoped the vendor relationship.

- **Why it works:** This is not a theoretical attack — under-constrained ZK circuits are a known production failure mode. The construction presents formal security reductions but those reductions are only as strong as the implementation they reduce *to*. A CISO cannot sign off on a construction whose security argument terminates at "trust Bolyra's gadgets."

- **In-threat-model?** No — construction must address. Propose: cite existing audits (e.g., if Bolyra circuits have been reviewed by Trail of Bits, Zellic, or similar), define a continuous fuzzing/differential-testing commitment, and scope a contractual security SLA with Bolyra as the upstream vendor. This is the difference between a cryptography paper and a deployable compliance artifact.


## Persona: rfc7662_advocate

---

### Attack 1: Ephemeral-key DPoP already achieves per-session forward secrecy

**Attack:** RFC 9449 Section 4 says nothing about key persistence. An agent runtime that generates a fresh DPoP key pair per session, binds the access token to that ephemeral key, and discards the private key on session close achieves exactly what the construction claims: compromise of any later key reveals nothing about prior sessions, because the prior keys are already gone. Paired with RFC 8693 Token Exchange for delegation, the downstream RS never sees a long-lived key. The construction's baseline impossibility argument (Section 8, "retroactive verifiability") asserts that "compromise of the key reveals every DPoP proof the agent ever generated" — but this presupposes a single persistent DPoP key, which is an implementation choice, not an RFC requirement.

**Why it works / fails:** The construction fails to draw a line between *key architecture* and *protocol*. The impossibility claim holds only for DPoP deployed with a single long-lived agent keypair. It does not hold for ephemeral-per-session DPoP. The construction must either (a) formally define the DPoP baseline as a single persistent key and justify why that is the *necessary* architecture, or (b) acknowledge that ephemeral-key DPoP narrows the gap and specify the residual advantage of the epoch hash chain.

**In-threat-model?** No — the construction must address this or the baseline impossibility section collapses.

---

### Attack 2: OIDC PPID + per-RS introspection policy breaks cross-RS linkability without ZK

**Attack:** The construction's unlinkability claim is about the *activity graph* — linking sessions across resources after key compromise. RFC 9449 + pairwise pseudonymous identifiers (OIDC PPID, Section 8 of the OIDC Core spec) already assign a distinct `sub` per RS. An AS that enforces per-RS introspection policy (RFC 7662 with policy-filtered responses) can return different stable pseudonyms to different resource servers. The signed JWT introspection response (draft-ietf-oauth-jwt-introspection-response) removes the AS from the per-request hot path, so real-time AS-side linkability is also eliminated. Post-compromise at time T, the adversary holds the agent's key but each RS only ever saw an RS-specific PPID — there is no single identifier to link sessions across resources.

**Why it works / fails:** The construction's Section 3 (Threat Model) does not distinguish AS-side from RS-side linkability. If the threat is RS-side linkability, PPID already addresses it. If the threat is AS-side linkability (AS sees all sessions), then the AS is the trust anchor and the construction must explain why an AS you've already trusted with epoch commitments is a weaker trust assumption than an AS that issues PPID tokens. The construction is not obviously stronger here — it has merely moved the trust to a different party (the Bolyra contract).

**In-threat-model?** No — the construction must scope the linkability threat and demonstrate PPID leaves a residual gap it closes.

---

### Attack 3: The IND-FS-AGENT game assumes secure deletion, which is an operational precondition not a cryptographic guarantee

**Attack:** The forward secrecy reduction in Section 4 (Security Argument) reduces to Poseidon preimage resistance (A1): given s_T, the adversary cannot compute s_{T-1}. This is sound *if and only if* s_{T-1} is not available by any other means. But the adversary in a real deployment does not need to invert Poseidon — they read it from swap files, cloud provider snapshots, checkpoint state persisted between tool calls (Section 7 references a "30-day autonomous Claude agent"), container image layers, or debug logs. RFC 9449 Section 11.1 warns explicitly that DPoP key material must be protected against extraction from persistent storage — the same attack surface exists for epoch secrets. The IND-FS-AGENT game (Section 3) hands the adversary the key "at time T" but does not model memory forensics or snapshot access. The game is therefore easier than the real threat.

**Why it works / fails:** This attack does not falsify the cryptography — it falsifies the threat model coverage. A long-running autonomous agent (the primary deployment scenario in Section 7) almost certainly checkpoints state to survive restarts, meaning prior epoch secrets may persist in storage. The construction needs a secure deletion protocol bound to epoch rotation, and the IND-FS-AGENT game needs a "persistent storage oracle" adversary capability to be realistic.

**In-threat-model?** No — the construction must either extend the game to cover storage forensics or add a secure deletion requirement to Section 7 with explicit justification for why it is achievable in the target deployment.

---

### Attack 4: WIMSE workload delegation + RFC 8707 audience binding already provides delegation unlinkability at the RS layer

**Attack:** The ForwardSecureDelegation circuit (~9,064 constraints, Section 2) is supposed to provide unlinkable agent-to-agent delegation. The WIMSE draft (draft-ietf-oauth-wimse) defines a workload-to-workload identity model where a delegating workload obtains a short-lived token bound via RFC 8707 Resource Indicators to a specific downstream RS, with a `wid` claim carrying a workload-specific identifier. Each hop issues a fresh token; the receiving RS sees only the immediate presenter's identity. With short TTLs (minutes), retroactive replay requires both the token and the sender-constraint key — and with per-hop ephemeral DPoP keys (Attack 1 above), the sender constraint is already forward-secure. The construction's Section 6 (Baseline Impossibility) claims "no unlinkability primitive" in the OAuth stack, but does not cite WIMSE or model its delegation chain.

**Why it works / fails:** WIMSE is pre-RFC but its delegation model is operationally deployed (SPIFFE/SPIRE implementations). The construction's omission of WIMSE from the baseline comparison leaves a gap: if WIMSE + ephemeral DPoP + PPID achieves the delegation unlinkability property, then the 9,064-constraint ForwardSecureDelegation circuit is overhead without differentiated benefit. The construction must either cite the specific WIMSE property it exceeds, or concede that the delegation unlinkability claim requires scoping to a narrower threat (e.g., the WIMSE AS is itself compromised).

**In-threat-model?** No — the construction's Section 8 baseline impossibility argument must be rewritten to include WIMSE and explicitly demonstrate the residual gap.


## Persona: spiffe_engineer

---

### Attack 1: The ZK Attestor Plugin — You Built a New Protocol When You Needed a Plugin

**Attack:**
SPIRE's attestation pipeline is fully extensible via gRPC plugin interface. I can write a `NodeAttestor` and `WorkloadAttestor` that derive X.509 SVID private keys from a Poseidon hash chain keyed on epoch — call it `k_epoch = Poseidon(k_{epoch-1}, t)`. SVIDs already have configurable TTLs (default 1h, prod floors at 5m). I rotate the SVID every epoch. The SPIRE agent holds only `k_epoch`; it does not persist `k_{epoch-1}`. That is a one-way ratchet. I did not write a single ZK circuit. Where exactly does your `EpochRotation` circuit (§3, ~879 constraints) add something I cannot get from a 40-line Go attestor plugin?

**Why it works / why it fails against the construction:**
Partially works as a surface-level attack. Fails on two structural gaps the construction must articulate more clearly. First, SPIRE's CA still signs every SVID — compromise of the SPIRE intermediate CA retroactively reveals the signing lineage of every past SVID. The hash-chain on the *private* key side gives forward secrecy for key material, but the *public* side (the certificate chain) is permanently logged in the SPIRE datastore and links every epoch to the same workload entry. Second, the construction's `ForwardSecureAgentSession` circuit (§3) produces a *nullifier* `n = Poseidon(s_k, session_id)` that is published without revealing `s_k`. SVID rotation produces no such nullifier — a replayed SVID is syntactically valid until TTL expiry; there is no on-ledger revocation primitive that is also unlinkable.

**In-threat-model?** Partially. The construction survives on the CA-linkage and nullifier arguments but **must add a section explicitly explaining why SPIRE's ZK attestor extension is insufficient** — specifically that SPIRE's datastore creates a durable linkage graph even when epoch keys are rotated. Without this, the claim that "no bearer-token construction achieves this" reads as dismissing SPIFFE without engaging it.

---

### Attack 2: WIMSE Token Exchange + SD-JWT Already Has Selective Disclosure In Scope

**Attack:**
Section 5 of `draft-ietf-wimse-arch-06` defines workload-to-workload token exchange. Pair it with SD-JWT (`draft-ietf-oauth-selective-disclosure-jwt`) and I get: (a) short-lived tokens bound to the workload's current SVID, (b) selective disclosure of claims at presentation time, (c) token exchange that mints fresh credentials for each hop so the downstream service never sees the upstream token. The construction's §8 "Baseline Impossibility" claims WIMSE "has no unlinkability primitive" — but the SD-JWT `_sd_alg` mechanism with per-disclosure salts is a one-way commitment, which is an unlinkability primitive. Justify the gap or contribute to the WIMSE working group instead of building a new wire protocol.

**Why it works / why it fails against the construction:**
The attack correctly identifies that SD-JWT salts provide *presentation-time* unlinkability — a verifier cannot correlate two presentations of the same credential if different salts are used. It fails because SD-JWT selective disclosure operates at the *claim* level, not the *session* level. The adversary in the IND-FS-AGENT game (§4) obtains `k_T` and all prior transcripts. With SD-JWT: the issuer's signing key (or in WIMSE, the SPIRE CA) is the root of trust — key compromise retroactively makes every issued token verifiable and attributable because the signatures are deterministic. The construction's `ForwardSecureAgentSession` circuit never reveals `s_k` in any transcript; the PLONK proof is the only artifact. A WIMSE token carries a signed JWT whose signature is a fixed function of the key and payload — given the key, you recompute every proof of issuance.

**In-threat-model?** Yes, construction survives — but §8 must be sharpened. The current impossibility argument is stated informally. It needs one sentence: *"SD-JWT unlinkability is at presentation granularity conditioned on verifier isolation; IND-FS-AGENT requires unlinkability conditioned on key exposure, which no HMAC-or-signature-based scheme can provide because the signing operation is deterministic given the key."*

---

### Attack 3: Your Nullifier Is a Keyed Hash — This Is Symmetric HMAC With Extra Steps

**Attack:**
The nullifier `n = Poseidon(s_k, session_id)` (§3, `ForwardSecureAgentSession`) is structurally a keyed PRF evaluation. RFC 6238 TOTP is `HOTP(K, T) = Truncate(HMAC-SHA1(K, T))`. Your nullifier is `Poseidon(K, session_id)`. Both are one-way under key secrecy. Both produce a per-session token that cannot be replayed if the verifier stores seen values. TOTP does not require a ZK circuit. A SPIRE workload can get a fresh TOTP token per tool call, register the HMAC output in a replay-detection log, and achieve FS-REPLAY (§4) without any proof system. What does the PLONK wrapper around Poseidon buy that HMAC-SHA256 with a rotated symmetric key does not?

**Why it works / why it fails against the construction:**
This is the sharpest attack and the construction does not fully address it in the current sections. The attack fails for one reason: the ZK wrapper proves *correctness of derivation* without revealing the epoch key. In a symmetric TOTP-style scheme, the verifier must hold a copy of `K` (or a KDF output from it) to verify the HMAC — that means the verifier is a potential leak point for `K`. In the construction, the verifier checks a PLONK proof that `n` was correctly derived from some valid `s_k` committed in the policy without learning `s_k`. This is the knowledge-hiding property of PLONK (§5, A3). A replaying adversary who compromises the *verifier* in the TOTP scheme recovers `K` and can forge all future tokens. The construction's verifier learns only `n` and the proof — it cannot extract `s_k`.

**In-threat-model?** No — the construction does **not** address verifier-side key exposure in §4's threat model. The IND-FS-AGENT game models compromise of the *agent* signing key, not the *verifier* symmetric key. This is a gap: add a verifier-compromise sub-game or explicitly state "verifier is trusted" as a boundary condition.

---

### Attack 4: SPIFFE Trust-Domain Federation Gives You Portability — Name the Remaining Gap Precisely

**Attack:**
The SPIFFE Federation spec (and RFC 8705 certificate-bound tokens) gives workload identity that travels across organizational trust domains. My Claude agent at `spiffe://acme.corp/agents/claude-prod-7` can present its X.509 SVID to a relying party in `spiffe://partner.org/services/api` after bundle exchange. The relying party validates the cert chain against the federated bundle. The agent's identity is portable. The construction's deployment scenario (§7, SECU 30-day agent) claims "portable pseudonymous identity across credit union domains." SPIFFE federation already does this. What gap remains?

**Why it works / why it fails against the construction:**
The attack correctly frames portability. It fails because SPIFFE federation is *persistent-identity* portability: `spiffe://acme.corp/agents/claude-prod-7` is the same identifier across every federation boundary. Every relying party that accepts the SVID can correlate all interactions from that workload across time and across domains — the SPIFFE ID is a global persistent handle. The construction's pseudonymous sessions mean the partner-org API sees `(nullifier_i, proof_i)` for session `i` with no persistent handle linking it to any other session. Two sessions from the same agent at different times are unlinkable to the partner-org verifier. SPIFFE federation with SVIDs achieves cross-domain authentication; it explicitly does *not* achieve cross-session unlinkability because that would break auditability at the SPIRE server.

**In-threat-model?** Yes, construction survives — but §7's deployment section must explicitly call out the SPIFFE comparison. Currently §8 attacks DPoP/WIMSE/TokenExchange but does not mention SPIFFE federation by name. A reviewer with SPIFFE background will read the portability claim and immediately ask this question. Add one paragraph: *"SPIFFE federation provides cross-domain authentication with a stable SPIFFE ID; this construction provides cross-domain authorization with per-session pseudonyms. They solve different properties; they are not substitutes."*
