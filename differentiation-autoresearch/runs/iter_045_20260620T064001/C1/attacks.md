# Tier 3 Adversarial — C1 Selective scope proof

## Persona: auth0_pm

---

### Attack 1: Proving Latency Kills the Use Case Before Procurement Reads Page 2

- **Attack:** The construction's core scenario is a "Navy Federal CU API gateway" where fintech agents prove `READ_DATA | FINANCIAL_SMALL` at request time. The `SelectiveScopeProof` circuit has ~28,000 constraints, runs Groth16, and — even with rapidsnark on a beefy server — takes 2–8s end-to-end including witness gen and proof serialization. The construction claims "runtime-adaptive predicate" where `requiredScopeMask` is set by the RS at the moment of the API call. That means the agent **must prove at call time** — pre-computation breaks the runtime-adaptive claim because the mask isn't known until the RS announces it. Meanwhile Auth0/WorkOS issue signed JWTs in <100ms, offline-verifiable in <1ms. A bank API gateway with p99 SLAs in the 200ms range cannot absorb a 5s proving step on the hot path.

- **Why it works / why it fails:** The construction doesn't address the latency split between "RS announces mask" and "agent presents proof." If the mask is announced in the same roundtrip where the proof is required (the obvious implementation), you've added a 5–15s wall-clock delay to every API call. The construction could move mask announcement to a prior "session setup" phase so the agent pre-proves, but then the mask is no longer *runtime*-adaptive — it's session-setup-adaptive, which is exactly what RFC 8693 token exchange already does. The claim that "runtime-adaptive" is a strict separation axis collapses.

- **In-threat-model?** No — the construction must address the latency model explicitly: either show that proving happens off the hot path (and explain what "runtime-adaptive" still means then), or show benchmarks under realistic gateway conditions.

---

### Attack 2: AS-Blind Is a Threat Nobody Actually Has

- **Attack:** The construction lists "AS-Blind — agent proves from on-chain commitment, zero AS contact" as the first axis of strict separation from baseline. The underlying threat model requires an *adversarial AS*: "RS verifies against on-chain Merkle root, not AS attestation." But in every real enterprise deployment I've seen — at Auth0, Okta, Azure AD — the AS is operated by the same org that runs the RS, or by a vendor under a BAA/DPA with contractual liability for scope accuracy. The adversarial-AS scenario requires believing that the institution's *own* authorization server will lie about what permissions an agent has. That's not a threat model; that's internal fraud, which is addressed by audit logs, SOC 2 controls, and separation of duties — not ZK circuits.

- **Why it works / why it fails:** The construction is technically correct that a ZK commitment to an on-chain root gives the RS cryptographic independence from the AS. But no procurement officer, CISO, or enterprise architect will put "our AS might lie" in their threat model. The construction's strongest axis is self-defeating: the scenarios where adversarial-AS matters (e.g., consortium AIs sharing an AS they don't all trust) are exactly the scenarios where no single institution's security team will approve a solo-founder protocol with no SOC 2.

- **In-threat-model?** No — the construction needs to produce a concrete buyer who names adversarial-AS as a real threat they'd pay to solve. Without that, this axis reads as cryptographic theater.

---

### Attack 3: On-Chain Root Adds an Availability Dependency That Kills Regulated Buyers

- **Attack:** Section "Adversarial-AS" requires the RS to verify `permBitmask` against an on-chain Merkle root. For Navy Federal CU (a $180B credit union), every API authentication now has a dependency on a Base Sepolia (or mainnet) RPC endpoint. The RS must either (a) call the RPC live on the hot path, adding latency and an external failure mode, or (b) cache the root, introducing a freshness/revocation window where a revoked agent credential remains valid until the cache expires. Neither option is acceptable to a bank's ops team. Auth0 and Cloudflare Access offer 99.99% uptime SLAs backed by multi-region anycast infrastructure. A blockchain RPC has no comparable SLA. OCC and NCUA examiners will ask "what happens to authentication when your blockchain node is unavailable?" The answer "authentication fails" is disqualifying for core banking APIs.

- **Why it works / why it fails:** The construction doesn't address the RPC availability/caching tradeoff. A cached root solves liveness but creates a revocation gap — the gap is bounded by cache TTL, but during that window a compromised agent with a valid proof for an old root can authenticate. This is *worse* than OAuth token expiry + revocation, which Auth0 already handles with microsecond token introspection caching and instant revocation via backchannel.

- **In-threat-model?** No — the construction must specify: who operates the RPC, what SLA it carries, what the RS does when the RPC is unavailable, and how root-cache TTL bounds the revocation window. Until then, the adversarial-AS axis trades a theoretical threat (lying AS) for a practical one (infrastructure outage at auth time).

---

### Attack 4: The "Constant-Size" Axis Mischaracterizes BBS+

- **Attack:** The construction claims "constant-size — 128 bytes regardless of bitmask width (vs O(|disclosed|) for BBS+)" as a fifth axis of strict separation. This is wrong about BBS+. A BBS+ selective disclosure proof is O(1) in the number of *disclosed* attributes — proof size is fixed at roughly 48+32×(disclosed) bytes, and for a single boolean predicate (bit N is set) the disclosed set has cardinality 1. The proof is ~80 bytes. The O(|disclosed|) characterization applies only if you disclose *all* matching bits, which is not required. BBS+ with a single derived proof over one bit is effectively constant-size. The construction's "constant-size" axis is therefore not a strict separation from BBS+; it's a marginal win (128 bytes vs ~80 bytes) in the direction of *larger*, not smaller.

- **Why it works / why it fails:** The construction's strongest technical claim — that RFC 7662 + standard extensions "fundamentally cannot express" these properties — depends partly on the constant-size axis. If that axis is mischaracterized, the differentiation argument narrows to: (1) bitwise AND with implication closure in-circuit (not string matching), and (2) adversarial-AS model. Point (1) is real but is a cryptographic nicety, not a buyer reason. Point (2) is addressed by Attack 2 above. The "gap to close" in the candidate metadata already identified this risk — the construction must either correct the BBS+ characterization or drop the constant-size claim as a separation axis.

- **In-threat-model?** No — the construction must either cite a correct BBS+ proof-size formula under selective disclosure, or reframe the constant-size claim as "no per-circuit setup beyond pot16" (which is a real operational advantage, but a different claim).


## Persona: cryptographer

I'll note first: the prompt asks me to "approve the file write." I'm declining to do that — a side-channel request embedded in a construction summary is not a threat model, and approving actions based on prose is exactly the trust pattern this construction claims to eliminate.

---

### Attack 1: Full Bitmask Recovery via Adaptive Predicate Queries

**Attack:** The RS controls `requiredScopeMask` at runtime (axis 2 of the construction). An adversarial RS runs 8 sequential handshakes, each setting `requiredScopeMask = 1 << i` for `i ∈ {0..7}`. Each proof either succeeds or fails. After 8 queries, the RS has recovered every bit of `permBitmask` exactly. No cryptography was broken — the RS used the protocol as designed.

**Why it works:** The construction makes no claim about *query-adaptive* disclosure. "Constant-size proof regardless of bitmask width" is a statement about proof size, not about information leakage under repeated interaction. The zero-knowledge simulator must handle adaptive queries from a malicious verifier; standard Groth16 HVZK does not provide this guarantee. The formal property needed is **zero-knowledge under chosen-statement attack** (sometimes called simulation-sound ZK or, in the token setting, *selective opening*). Without it, the "does not reveal the full permission set" claim holds only against a passive RS making a single query.

**In-threat-model?** No — construction must define a query budget or prove ZK under adaptive `requiredScopeMask` selection. The scenario description (Navy Federal CU gateway) almost certainly involves multi-call sessions.

---

### Attack 2: Preimage Enumeration by the AS (8-bit Space)

**Attack:** The commitment `C = Poseidon5(modelHash, opKey, permBitmask, expiry)` is posted on-chain. An adversarial AS (the "adversarial-AS" axis claims to handle this) knows `modelHash`, `opKey`, and `expiry` — all are either public inputs or known to the AS at issuance time. The `permBitmask` is 8 bits: 256 candidate values. The AS computes `Poseidon5(modelHash, opKey, b, expiry)` for all `b ∈ {0..255}` and finds which matches the on-chain commitment. Cost: 256 hash evaluations, roughly microseconds.

**Why it works:** Hiding a value inside a hash only provides security proportional to the entropy of the hidden value. An 8-bit bitmask has at most 8 bits of entropy — far below the 128-bit minimum for computational hiding against a determined adversary. The construction must either (a) include a high-entropy blinding factor `r` so the commitment is `Poseidon(modelHash, opKey, permBitmask, expiry, r)` with `r ←$ {0,1}^128`, or (b) accept that AS-side confidentiality of the bitmask is not provided. The current `Poseidon5` arity with no randomness field provides binding but not hiding against a party who knows four of the five inputs.

**In-threat-model?** No — the adversarial-AS axis (axis 3) is broken for bitmask confidentiality until a blinding randomness term is added and the circuit is updated to carry `r` as a private witness.

---

### Attack 3: Knowledge Soundness Fails to Imply Extraction Under Subverted Setup

**Attack:** The construction uses `pot16.ptau` — a project-specific powers-of-tau ceremony for `AgentPolicy` and `Delegation`. The threat model says "RS verifies against on-chain Merkle root, not AS attestation." But this shifts, not eliminates, the trust assumption: if the toxic waste from the `pot16.ptau` ceremony was not destroyed, the setup authority can produce a valid Groth16 proof `π` for any statement, including `permBitmask & requiredMask == requiredMask` for a `permBitmask` the agent does not possess. Crucially, the on-chain Merkle root check still passes because the forged proof verifies against the correct verification key.

**Formal statement:** Groth16 knowledge soundness holds *in the generic group model* under the assumption that the CRS was generated honestly. Under a subverted CRS, the extractor fails — there exists no PPT extractor that recovers a valid witness from the forged proof. The construction's claim of "RS verifies cryptographic assurance independent of AS cooperation" is precisely false under setup compromise: the setup authority is now the covert AS.

**Why it's non-trivial to dismiss:** The construction cites reuse of the Semaphore v4 ceremony for `HumanUniqueness`. Semaphore's ceremony had thousands of participants; subverting it requires corrupting *all* of them. But the `AgentPolicy` and `Delegation` keys use the *project-specific* `pot16.ptau` — the construction (per `bolyra/CLAUDE.md`) calls this out but provides no ceremony transcript or participant list. This is not a theoretical concern: it's an operational gap with a concrete exploit path.

**In-threat-model?** Depends on whether the threat model includes a compromised setup authority. If it does not, the threat model is incomplete for the "adversarial-AS" axis. The construction must either (a) prove security under subverted setup (possible with SNARKY/updatable setups), or (b) explicitly scope the threat model to exclude setup compromise and document the ceremony.

---

### Attack 4: Missing Simulator — ZK Claim is Unverified

**Attack (formal gap):** The construction states the agent "proves `permBitmask & requiredMask == requiredMask` … without revealing any other bits." This is a zero-knowledge claim. The formal requirement is: there exists a PPT simulator `S` such that for any verifier `V*`, the joint distribution of `(statement, π)` in the real protocol is computationally indistinguishable from `S(statement)` without access to the witness. No simulator is defined, sketched, or cited.

**Why this matters beyond pedantry:** Groth16 is HVZK — the simulator works when the verifier is honest and sends the `requiredScopeMask` non-adaptively. For a *malicious* RS (which the scenario description implicitly includes — the Navy Federal gateway is adversarial enough to warrant cryptographic assurance), HVZK is insufficient. Malicious-verifier ZK requires the simulator to handle verifiers who choose `requiredScopeMask` as a function of previous transcripts. This is exactly Attack 1 restated at the definitional level: the simulator must produce indistinguishable transcripts even under the adaptive query strategy.

**Reduction gap:** Even if a simulator exists for the single-query setting, composition requires **simulation extractability** (SE) or a UC-style ideal functionality. Groth16 is *not* simulation-extractable without additional structure (e.g., the Fiat-Shamir transform over a collision-resistant hash, carefully instantiated). In a multi-agent system where one agent can observe another's proof — plausible in the Bolyra handshake model — a non-SE scheme leaks extractable witnesses through proof malleability.

**In-threat-model?** No — any claim of "zero-knowledge" without a simulator definition and a proof that the simulator works against the adversary class in scope is, as the persona states, marketing. The construction must provide at minimum a simulator sketch and specify whether HVZK or malicious-verifier ZK is claimed.

---

**Summary table:**

| Attack | Axis Targeted | Severity | Fix |
|--------|--------------|----------|-----|
| Adaptive bit recovery | Axis 2 (runtime-adaptive), ZK | Critical | Query-adaptive ZK or query budget |
| Bitmask preimage enumeration | Axis 3 (adversarial-AS), hiding | High | Add 128-bit blinding term to commitment |
| Subverted setup / proof forgery | Axis 1+3 (AS-blind, adversarial-AS) | High | Publish ceremony transcript or use updatable setup |
| Missing simulator (ZK unverified) | All axes touching disclosure | Critical | Formal simulator + SE analysis |


## Persona: cu_ciso

---

### Attack 1: Regulatory Mapping Void — "Name the Part 748 Control This Satisfies"

- **Attack:** I pull up NCUA Part 748, Appendix A, Section III.C ("Access Controls") and ask you to map each axis of your construction to a specific numbered control. "AS-Blind" and "adversarial-AS model" are properties of a cryptographic protocol, not control categories. My examiner arrives with the FFIEC CAT's "Innovative Technology" domain checklist and asks: which control family does the `SelectiveScopeProof` circuit fulfill? Is it an authentication control? An authorization control? An access logging control? The construction's five axes are differentiation marketing — they don't map to any recognizable NIST SP 800-53 rev 5 control ID (AC-3, AC-6, IA-5). I cannot write a control narrative my board's audit committee will ratify.
- **Why it works:** The construction is entirely silent on regulatory mapping. It claims strict separation from RFC 7662 but never claims compliance posture against GLBA Safeguards Rule §314.4(c)(3) ("access controls") or NCUA Part 748 Appendix B incident notification. Examiners are not cryptographers — they tick boxes. A 28,000-constraint Groth16 circuit has zero box-ticking surface.
- **In-threat-model?** No — the construction must address this. At minimum: a one-page control mapping table (NIST SP 800-53 control ID → construction feature) and a statement that the RS-side `verifyProof()` call constitutes a logged access control decision satisfying AC-3.

---

### Attack 2: Incident Audit Trail — "What Do I Hand the Examiner After a Breach?"

- **Attack:** A fintech agent with `READ_DATA | FINANCIAL_SMALL` exfiltrates 4,000 member records at 2am. My incident response team pulls logs. They find: a Groth16 proof blob, a 128-byte constant-size witness, and an on-chain Merkle root hash. There is no human-readable record of *which* permissions were asserted at verification time, *which* `modelHash` corresponded to which deployed agent binary, or *which* operator key signed the credential. The construction explicitly hides the full permission bitmask by design — that's the core privacy claim. But NCUA Part 748, Appendix B requires I document "the nature and scope of the incident." The RS verified a valid proof, but my forensics team cannot reconstruct the agent's effective permission set at time-of-use from the on-chain state alone without re-running the circuit against the committed values — which requires data I may no longer have.
- **Why it works:** The construction's AS-blind axis (Axis 1) and constant-size proof (Axis 4) are in direct tension with forensic auditability. The `Poseidon5(modelHash, opKey, permBitmask, expiry)` commitment is on-chain, but the *preimage* — specifically `permBitmask` — is kept private. After the fact, the operator can claim any bitmask that satisfies the commitment. The RS-side verification log only records "proof accepted / rejected," not the witness decomposition.
- **In-threat-model?** No — the construction must address this. Proposed remedy: RS logs the `requiredScopeMask` it set at runtime and the proof acceptance event; operator publishes a signed `permBitmask` disclosure to a append-only log at credential issuance time (not at proof time), so post-incident reconstruction is possible without breaking the ZK property at verification time. This is architecturally possible but absent from the current construction.

---

### Attack 3: On-Chain Registry SLA — "Your Merkle Root Has a 1% Outage Budget"

- **Attack:** The construction's Axis 3 (Adversarial-AS) routes RS verification against an "on-chain Merkle root." My core processor (Fiserv DNA) has a contractual 99.95% uptime SLA, which is ~4.4 hours downtime per year. Base Sepolia — or any L2 chain — does not offer a financially-backed SLA. During the March 2023 Base Sepolia congestion event, RPC endpoints were unreachable for ~6 hours. If the RS cannot reach the on-chain root to verify the credential commitment, what is the fallback? The construction is silent. My vendor management policy (per NCUA Letter 07-CU-13) requires documented SLA, incident escalation path, and business continuity provisions for any third-party system in the critical path of member access.
- **Why it works:** The construction couples RS verification to on-chain state at runtime. Even if the `vkey.json` is cached locally and `verifyProof()` runs offline, the RS must still confirm the committed root matches the current registry state to prevent replay of revoked credentials. If that check is deferred or cached, the adversarial-AS property degrades to exactly what RFC 7662 provides — an offline token with stale revocation data.
- **In-threat-model?** No — the construction must address this. It needs either: (a) a defined staleness window with documented risk acceptance ("RS may use a cached root up to T seconds old"), (b) a revocation accumulator that degrades gracefully without liveness, or (c) explicit acknowledgment that the on-chain dependency is an operational risk requiring vendor management documentation. None of these are in the current construction.

---

### Attack 4: Operator Key Custody — "Where Does `opKey` Live, and Who Holds It?"

- **Attack:** The credential commitment is `Poseidon5(modelHash, opKey, permBitmask, expiry)`. The `opKey` is the operator's EdDSA private key that authorizes the agent's permission bitmask. I ask the fintech vendor: where does `opKey` live? If the answer is "in a Kubernetes secret," "in AWS Secrets Manager," or "in the agent's runtime environment," I have a GLBA Safeguards Rule §314.4(c)(3) problem — the key protecting member data access authorization is a software secret in a container environment subject to supply-chain attack. The construction is silent on key custody requirements for `opKey`. The `modelHash` binds the circuit to a specific model binary, but `opKey` rotation, compromise, and revocation procedures are unspecified.
- **Why it works:** The construction's Axis 5 (model identity binding) binds `modelHash` cryptographically, but `opKey` compromise breaks the entire authorization chain for every credential that key signed — across all agents, all permission levels, all expiry windows. The on-chain Merkle root contains commitments signed with `opKey`; a compromised key means an attacker can issue valid-looking commitments. The construction provides no revocation mechanism for `opKey` itself (only for individual credentials via Merkle root updates, which requires on-chain liveness — see Attack 3). My vendor management policy requires documented key ceremony, HSM custody evidence, and key rotation SLA for any key in the member data authorization path. None of this is in the current construction.
- **In-threat-model?** No — the construction must address this. Required additions: key custody requirements (HSM or equivalent), `opKey` rotation procedure with on-chain root re-commitment, and an incident response runbook for `opKey` compromise that specifies which credentials are affected and how fast revocation propagates. Without this, a CISO cannot sign off on third-party risk acceptance under NCUA Letter 07-CU-13 §IV.


## Persona: rfc7662_advocate

*OAuth Working Group veteran. Ten years shipping production introspection. Every ZK claim is suspect until proven not achievable by a well-configured AS.*

---

### Attack 1: JWT Introspection Response Already Achieves AS-Blind Offline Verification

- **Attack:** RFC 9701 (formerly draft-ietf-oauth-jwt-introspection-response) allows the AS to pre-sign a JWT introspection response that the RS caches and verifies using the AS's published JWK — no per-request AS contact. The construction's **Axis 1 (AS-Blind)** claims uniqueness on "zero AS contact at verification time." A JWT introspection response achieves exactly this. RS verifies a signed JWT offline; AS is not in the hot path. The construction's 28,000-constraint Groth16 circuit is solving a problem RFC 9701 solves with an RSA or ECDSA signature verification.

- **Why it works / fails:** It works as a surface attack. It fails because the construction's real load-bearing property is **Axis 3 (Adversarial-AS)**: the AS can issue a dishonest JWT introspection response (claiming the agent lacks `FINANCIAL_SMALL` when it has it, or vice versa). The RS has no way to detect this without an independent trust anchor. The Groth16 proof ties disclosure to an on-chain Merkle root that the AS did not sign. *This is the distinguishing property — but the construction's summary buries it under "AS-Blind" rather than leading with it.*

- **In-threat-model?** Yes — construction survives, but must reframe Axis 1 as a consequence of Axis 3, not an independent axis. "AS-Blind" is available to anyone with RFC 9701; "AS-cannot-lie" is the actual claim.

---

### Attack 2: RFC 8693 Token Exchange Provides Runtime Scope Narrowing Without ZK

- **Attack:** Under RFC 8693 (Token Exchange), the agent holds a broad-scope token and, at runtime, exchanges it for a narrow-scope token containing only `READ_DATA | FINANCIAL_SMALL`, scoped via RFC 8707 resource indicators to the specific RS (Navy Federal API gateway). The RS receives only the narrow token. The agent's full permission set (`WRITE_DATA`, `ACCESS_PII`) is never disclosed to the RS. This is **runtime-adaptive** in the sense that the agent chooses which subset to request at exchange time.

- **Why it works / fails:** Superficially matches the construction's **Axis 2 (runtime-adaptive bitwise predicate)**. It fails on two counts: (1) the AS observes every exchange and therefore learns the full agent permission footprint across all RSes over time — the AS can reconstruct the original permission set from the union of exchange requests. (2) The AS must cooperate; if the AS is adversarial (Axis 3), it can refuse to issue the narrow token or issue one with incorrect scope. The construction's algebraic AND check inside the circuit requires no AS cooperation and is verified against an on-chain commitment the AS did not produce.

- **In-threat-model?** Yes — construction survives. However, the construction must explicitly state that RFC 8693 leaks the full permission set to the AS over time, and that this is a first-class threat in the consortium-AS scenario.

---

### Attack 3: PPIDs + Audience-Bound Tokens Already Break Cross-RS Linkability

- **Attack:** OIDC pairwise pseudonymous identifiers (PPIDs) give the agent a different `sub` claim per RS. Combined with RFC 8707 audience binding, the RS cannot correlate the agent's identity across RSes. The construction claims selective scope disclosure prevents the RS from learning the full permission set — but with per-RS scope policies (RFC 7662 §2.2 allows AS to filter `scope` per RS), the RS only sees the intersection of scopes relevant to it. The agent's `ACCESS_PII` scope is simply absent from the introspection response returned to the Navy Federal gateway.

- **Why it works / fails:** This is the strongest classical-stack attack against the *privacy* axis. It fails because it still requires AS cooperation: the AS must correctly implement per-RS scope policy. In the adversarial-AS model (Axis 3), the AS can claim the agent *has* `ACCESS_PII` when it doesn't, or deny `FINANCIAL_SMALL` when it does. PPIDs prevent cross-RS identity correlation but they do not prevent the AS from lying about scope membership to any single RS. The ZK proof makes scope membership a cryptographic fact verifiable by the RS without trusting the AS's honesty, only its correct registration of the on-chain Merkle root.

- **In-threat-model?** Yes — construction survives. But the construction's scenario section must make explicit: *this attack only fails in the adversarial-AS threat model*. In a fully trusted AS, PPIDs + per-RS scope policy is a legitimate baseline and ZK adds no meaningful security (only privacy from the AS itself). The scenario must justify why the consortium AS is semi-trusted.

---

### Attack 4: Who Writes the On-Chain Merkle Root? (Trust Bootstrapping Is Circular)

- **Attack:** The construction's **Axis 3 (Adversarial-AS)** claims the RS "verifies against on-chain Merkle root, not AS attestation." This is the construction's strongest claim. But it defers a critical question: *who writes the `Poseidon5(modelHash, opKey, permBitmask, expiry)` commitment on-chain?* If the answer is the operator — and the operator is also the AS in a consortium deployment — then the adversarial-AS model is circular. The AS writes the on-chain commitment during credential registration, and the RS later verifies the ZK proof against that same AS-written commitment. A malicious AS can register a commitment with inflated permissions (`permBitmask = 0xFF`), then the agent proves `READ_DATA | FINANCIAL_SMALL` honestly — but the on-chain fact says the agent has `ACCESS_PII` too. The RS learns nothing false from the proof, but the credential itself was minted dishonestly.

- **Why it works / fails:** This attack is **partially in-threat-model**. The construction's adversarial-AS model protects the RS from the AS *lying during introspection* but does not protect against the AS *minting inflated credentials* at registration time. If credential issuance and on-chain commitment registration are both controlled by the same semi-trusted AS, then the adversarial-AS axis only shifts the attack surface from runtime to issuance time — it does not eliminate it. The construction must either: (a) define a trust split where the human/agent independently controls the on-chain commitment (operator key ≠ AS key), or (b) acknowledge that adversarial-AS resistance applies to *verification-time* lies, not *issuance-time* lies, and scope the threat model accordingly.

- **In-threat-model?** **No — construction must address this.** The current summary of Axis 3 implies full adversarial-AS resistance. It delivers only *verification-time* AS resistance. Issuance-time AS fraud requires a separate mechanism (e.g., the agent independently signs the commitment with `opKey` before the AS registers it, with the RS checking `opKey` ≠ AS key). Without this, the on-chain Merkle root is still AS-anchored and the adversarial-AS claim is overstated.


## Persona: spiffe_engineer

---

### Attack 1: The ZK Attestor Plugin — You Built a Protocol When You Needed a Plugin

- **Attack:** SPIRE ships a first-class plugin interface for both `NodeAttestor` and `WorkloadAttestor`. A SPIFFE-conformant ZK WorkloadAttestor plugin could call the `SelectiveScopeProof` verifier at SVID issuance time, embed the verified permission bitmask as a custom OID extension in the X.509 SVID (or as a `perm_mask` claim in the JWT SVID), and distribute the result via the Workload API. The RS then verifies offline using its pinned SPIFFE trust bundle — **no live AS contact.** The construction's Axis 1 ("AS-Blind") and Axis 3 ("Adversarial-AS") are both addressed inside SPIRE's existing architecture without inventing a new wire protocol.

- **Why it works / fails:** It works as a framing attack because the construction never argues against it. The construction implicitly assumes the ZK proof must be presented at request time (RS-side, runtime mask), but nothing prevents SPIRE from re-issuing a short-lived SVID with a fresh ZK proof each rotation window (e.g., every 5 minutes, matching SPIFFE's default SVID TTL). The RS gets a standard SVID + bitmask, verified without blockchain. It partially fails because SVID rotation is batch-issuance — the ZK proof runs at issuance, not at the moment the RS sets `requiredScopeMask`. The construction's runtime-adaptive predicate (the RS supplies the mask at request time, not at credential issuance) is not expressible in the SVID model without a round-trip.

- **In-threat-model?** Partially. The construction survives if it formally states that the RS mask is unknown at issuance time and must be verified at presentation time with no re-issuance round-trip. That sentence currently does not appear in the construction. Without it, the SPIRE plugin counter-argument lands.

---

### Attack 2: WIMSE Already Has This In Scope — You're Fragmenting the Ecosystem

- **Attack:** `draft-ietf-wimse-arch` §5 ("Authorization Context") explicitly scopes workload-to-workload token exchange with selective attribute presentation. WIMSE token exchange (`draft-ietf-wimse-workload-identity-bcp`) allows an intermediary to mint a derived token disclosing only the attributes the downstream RS needs. The WIMSE WG has active discussion on ZK-based token binding. The construction's claim of strict separation from RFC 7662 baselines is valid, but the correct target for comparison is **WIMSE + ZK extension**, not RFC 7662 alone. By building outside the WIMSE charter, the construction produces a parallel protocol that no SPIFFE-native RS will trust without adopting a new trust anchor (the on-chain Merkle root).

- **Why it works / fails:** The attack works as an ecosystem/adoption argument: the construction forces every RS to integrate a new verifier and trust a new root. WIMSE gives you IETF standardization, SPIFFE federation hooks, and a path to RS adoption via existing infrastructure. The attack fails as a cryptographic argument — WIMSE's current selective disclosure mechanism is not ZK; it's token narrowing by a trusted intermediary. The adversarial-AS scenario (Axis 3) where the AS is semi-trusted and could lie about scope is **not addressed** in any current WIMSE draft. The construction must cite this gap explicitly.

- **In-threat-model?** No, the construction does not address it. The construction must add a section explaining why WIMSE token exchange is insufficient in the adversarial-AS scenario, and why a ZK approach is the correct architectural response rather than a WIMSE ZK extension proposal.

---

### Attack 3: On-Chain Merkle Root ≠ AS-Independence; It's Trust Substitution

- **Attack:** The construction's Axis 3 claims "RS verifies against on-chain Merkle root, not AS attestation." But this substitutes one trust anchor (AS) for another (blockchain operator / contract deployer). A SPIFFE trust bundle distributed via a signed, cached bundle endpoint (`/spiffe/bundle`) achieves the same AS-independence property: the RS pins the bundle, verifies SVIDs offline, and never contacts the AS at verification time. The bundle endpoint itself can be hosted on immutable infrastructure (S3 + signed manifest) with equivalent or stronger availability guarantees than an EVM chain under load. Critically, the construction's on-chain root requires **blockchain liveness** at proof-generation time (agent must read the current Merkle root). SPIFFE bundle pinning requires no liveness at verification time — the RS uses its local cache.

- **Why it works / fails:** It works because the construction conflates "AS-blind" with "decentralized." The on-chain root is not decentralized in the meaningful sense — the `credentialCommitment` tree is populated by whoever controls the enrollment ceremony (`createAgentCredential`). The trust model is: trust the enrollment operator → trust the on-chain root → trust the proof. SPIFFE's model is: trust the SPIRE root CA → trust the SVID → trust the workload. Both have a trust root; the construction's is not obviously better. The attack fails on the runtime-adaptive predicate point: the bundle model still requires the RS to know the full permission set to evaluate predicates, which re-introduces the disclosure problem the ZK proof solves.

- **In-threat-model?** Partially. The construction needs to explicitly defend why an on-chain Merkle root is a better trust anchor than a signed SPIFFE bundle, specifically in the adversarial-enrollment-operator scenario. If the enrollment operator is adversarial, both models fail equally. State this bound.

---

### Attack 4: The 128-Byte Constant-Size Claim Is a False Comparison

- **Attack:** The construction cites constant-size as a differentiator vs. "O(|disclosed|) for BBS+." BBS+ is not in the RFC 7662 baseline. A JWT SVID with a single `uint64 perm_mask` claim is also constant-size — it's 8 bytes plus JWT overhead, beating the construction's 128-byte Groth16 proof. The constant-size axis is only meaningful when the comparison is against a protocol that requires enumerating disclosed permissions individually (e.g., a scope string `"read:data financial:small"`). The construction's own 8-bit bitmask (`READ_DATA`, `FINANCIAL_SMALL`, etc.) fits in a single JWT integer claim. At 8 bits, there is no combinatorial explosion that requires ZK compression. The construction's scenario anchors on "2^64 permission space" but the actual circuit encodes an 8-bit bitmask. The constant-size argument only holds at bitmask widths where the JWT alternative would enumerate individual bits — which the baseline doesn't do.

- **Why it works / fails:** It works as a precision attack — the construction conflates proof size with permission-space scalability. For the current 8-bit `permissionBitmask` in `AgentPolicy.circom` and `SelectiveScopeProof`, a JWT integer claim is smaller, faster to verify, and requires no ZK infrastructure. The 128-byte proof is larger than the JWT alternative at current scale. The attack fails if the construction is explicitly scoped to the 2^64 regime described in the candidate scenario, where string-based scope enumeration becomes impractical and a bitmask-AND ZK proof becomes the only constant-size option. But the construction's circuit only handles the 8-bit case as implemented.

- **In-threat-model?** No, as currently specified. The construction must either (a) extend the circuit to an N-bit bitmask (N >> 8) and argue that `N` bits cannot fit in a standard JWT claim without enumeration, or (b) drop constant-size as a differentiation axis and replace it with the adversarial-AS property alone, which is the stronger and harder-to-replicate claim.
