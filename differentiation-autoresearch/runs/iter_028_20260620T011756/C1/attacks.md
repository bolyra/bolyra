# Tier 3 Adversarial — C1 Selective scope proof

## Persona: auth0_pm

### Attack 1: The 0.5 s Claim Is a Marketing Number — Real Agents Will Hit 5 s

- **Attack:** Section 6 buries the split: "Groth16 (snarkjs, WASM): < 5 s" for browser/Node. rapidsnark at < 0.5 s requires a compiled native binary pre-deployed on the agent's host. In practice, MCP agents run in cloud functions (Lambda, Cloud Run), edge workers, and browser-side copilots — none of which can exec a native binary. Every one of those agents falls into the WASM path. My platform issues tokens at < 100 ms P99. You are asking operators to accept a 50× latency penalty for the auth step alone, on every request, before the actual API call happens.

- **Why it works / why it fails:** The construction does not address the deployment reality for the environments where MCP agents actually run. The §6 table presents two numbers side-by-side as if they are equally reachable, but the footnote conditions on "Server-side agent" for the fast path. An RS receiving proofs from mixed-runtime agents cannot know which path the agent took — and 5 s proofs will dominate any production fleet.

- **In-threat-model?** No. The construction must either (a) bound which runtime environments are in scope and explicitly exclude browser/edge, or (b) explain how a WASM prover hits < 500 ms with `~20,700` constraints at production load. The "< 5 s" number needs a P99 at 100 concurrent prove calls, not a single-shot benchmark.

---

### Attack 2: `scopeCommitment` Is a Persistent Cross-RS Fingerprint

- **Attack:** Section 2 defines `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` as a **public output** that is deterministic and session-invariant. `credentialCommitment` commits to `(modelHash, operatorPubKey, permissionBitmask, expiryTimestamp)` — none of those change between sessions for the same credential. `permissionBitmask` also doesn't change. Therefore `scopeCommitment` is **identical across every proof this agent ever generates**, regardless of RS, nonce, or `requiredScopeMask`.

  Section 3 lists "cross-RS linkability attacks" as an adversary capability the construction must defend against. It does not. Any two colluding RS endpoints (or a network-level observer) that see `scopeCommitment` can trivially correlate every auth event for this agent across services, sessions, and time. The `nullifierHash` is session-scoped, but `scopeCommitment` is a permanent identifier.

- **Why it works / why it fails:** The Scope Privacy game in §3 is defined against a *single RS* seeing *one proof*. The multi-RS correlation attack is acknowledged as an adversary capability but is outside the formal game. Section 7's credit union scenario explicitly involves 200 CUs sharing one platform — every RS sees `scopeCommitment`, so every CU can track every agent's full activity log across the federation, defeating the claim that "the CUSO platform learns only that the predicate holds."

- **In-threat-model?** No. Either `scopeCommitment` must be session-randomized (e.g., `Poseidon3(permissionBitmask, credentialCommitment, sessionNonce)`) — which breaks downstream delegation chain-linking as currently designed — or the construction must add a multi-RS unlinkability game and prove it. The current §3 game does not cover this.

---

### Attack 3: The RS Has a New Operational Dependency That Can Take Down Auth

- **Attack:** Section 2 (Verification Protocol, step 5) requires the RS to check `agentMerkleRoot ∈ on-chain root history buffer (last 30 roots)`. This is a live RPC call to Base Sepolia (or mainnet). Section 7 says the system is "deployed on Base Sepolia, graduating to Base mainnet" — meaning the production scenario today is a testnet.

  My platform's auth path is: verify JWT signature against a cached JWKS — no network call at request time. Yours requires a node RPC call. Base Sepolia has had multiple multi-hour outages. Base mainnet has had sequencer downtime. A 30-entry root history buffer means roots are consumed — how often? If the CUSO platform can't reach Base during a regional AWS/Alchemy outage, every agent auth call fails. That's a correlated auth failure across 200 credit unions simultaneously, triggered by L2 infrastructure Bolyra doesn't control.

- **Why it works / why it fails:** The construction's §4 threat model treats the on-chain Merkle root as the trust anchor ("secured by the underlying L1/L2 consensus") but does not address liveness. An adversary who can cause Base sequencer downtime wins a denial-of-auth attack against all RSes simultaneously. The construction must specify: how does the RS behave when the root cannot be fetched? What is the acceptable cache TTL? A stale root cache opens a replay window for revoked credentials.

- **In-threat-model?** No. The construction's adversary model (§3) does not include a network availability adversary. The deployment scenario (§7) specifically involves NCUA-regulated credit unions where auth downtime is a compliance event. A mitigation path (e.g., a signed root bundle the RS can cache for N minutes) must be specified, along with the revocation-vs-liveness tradeoff this creates.

---

### Attack 4: The Adversarial-AS Framing Is a Strawman for the Actual Buyer

- **Attack:** Section 8, Gap 3 ("Adversarial-AS resilience") argues that "a compromised AS can assert that an agent holds scopes it does not." This is the central differentiator claim. But in the credit union scenario (§7): who issued the operator EdDSA key? Who enrolled the credential into the Merkle tree? The CUSO, presumably, or each CU's own operator. That operator IS the trust root. If the CU's operator is compromised, they enrolled a fraudulent credential commitment in the first place — the ZK proof faithfully proves a lie. The construction moves the trust anchor from "AS signing key" to "on-chain Merkle leaf + operator EdDSA key," but the operator key is still a secret held by someone, and that someone can be compromised.

  My actual buyers — CU compliance officers — are not worried about their AS lying. They run Okta or Azure AD and trust it. They're worried about SOC 2 Type II, NCUA examination findings, vendor viability, and a 24/7 support phone number. "Adversarial-AS resilience" does not appear in any NCUA examiner checklist. The §7 "Regulatory value" paragraph is aspirational: "ZK proof provides cryptographic assurance that satisfies third-party due diligence requirements" — this is not established. No NCUA guidance recognizes ZK proofs as satisfying §701.27 due diligence. That claim requires a legal opinion, not a construction.

- **Why it works / why it fails:** The construction addresses a genuine cryptographic property but misattributes it as a *buyer-level* motivator. The procurement question is not "does the AS trust model allow forgery?" — it's "will this vendor exist in 18 months, can I show it to an examiner, and does it integrate with Okta in an afternoon?" The construction has no answer to any of those.

- **In-threat-model?** No — this attack is outside the cryptographic threat model but inside the *product* threat model. The construction must either (a) narrow the deployment claim to contexts where adversarial-AS is a realistic threat (multi-operator federations, cross-org agent marketplaces), or (b) acknowledge that the credit union scenario, as described, does not face an adversarial AS and therefore the cryptographic differentiator does not drive the purchase decision. Conflating "technically superior" with "buyer-motivating" is how solo founders lose deals to incumbents with worse products.


## Persona: cryptographer

The construction is more carefully specified than most ZK token proposals I review. The game definitions exist, the assumptions are named, and the reduction sketch is at least mechanically sound under its stated premises. That said, I found four problems, two of which I consider breaks.

---

### Attack 1: SP Game — `scopeCommitment` is a Deterministic Distinguisher

**Attack:** The SP game (§3) asks whether A can determine which of two agents (with bitmasks b₀, b₁) produced a proof. The public signals include `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)`. In the SP game setup, A supplies b₀ and b₁. Both credential commitments — `cc₀ = Poseidon5(modelHash₀, opAx₀, opAy₀, b₀, exp₀)` and `cc₁ = ...` — are Merkle leaves, hence on-chain and publicly readable. A computes `Poseidon2(b₀, cc₀)` and `Poseidon2(b₁, cc₁)`, compares to the observed `scopeCommitment` in `publicSignals`, and recovers c with probability 1.

**Why it works:** `scopeCommitment` is not session-randomized. Unlike `nullifierHash`, which is blinded by a fresh `sessionNonce`, `scopeCommitment` is a deterministic function of the full private bitmask. The SP reduction sketch (§4) claims "A cannot distinguish b₀ from b₁" under Poseidon preimage resistance — but preimage resistance is irrelevant when A has the preimage in hand. The ZK property of Groth16 (A6) guarantees that A cannot extract the witness from π, but `scopeCommitment` directly leaks a Poseidon commitment to the witness that A can evaluate without breaking anything.

**In-threat-model?** **No.** The SP game as written is broken. `scopeCommitment` must either be removed from public outputs, rerandomized per session (e.g., `Poseidon3(permissionBitmask, credentialCommitment, sessionNonce)`), or the SP game must be weakened to exclude adversaries with on-chain access — which would make the privacy claim uninteresting.

---

### Attack 2: Cross-RS Linkability — `scopeCommitment` as a Permanent Agent Fingerprint

**Attack:** The adversary A controls "any number of RS endpoints" (§3, adversary capabilities). A operates RS₁ and RS₂. The same agent presents proofs to both with distinct `sessionNonce` values. Each proof produces a different `nullifierHash` (by design), but an identical `scopeCommitment`. A observes `(scopeCommitment₁, scopeCommitment₂)` from the two sessions and sets `scopeCommitment₁ == scopeCommitment₂` to link the agent across endpoints. This is a passive correlation attack — no forging, no preimage inversion.

**Why it works:** The nullifier scheme provides replay prevention within a single RS but zero cross-RS unlinkability. `scopeCommitment` is a static fingerprint tied to the full credential — it does not change across sessions or across RS endpoints. The SP game considers only one RS seeing one proof and never formalizes multi-session, multi-RS unlinkability. No session randomness is mixed into `scopeCommitment`.

**Why it matters for the concrete scenario (§7):** The CUSO platform (RS) serves 200 credit unions' agents. All API endpoints on the shared platform observe `scopeCommitment`. Endpoint-to-endpoint correlation is trivial — the CUSO operator can reconstruct a complete activity graph for each agent, indexed by `scopeCommitment`, across all resources. This undermines the NCUA audit claim ("ZK proof provides cryptographic assurance without creating a centralized authority"), because the CUSO accumulates a surveillance record anyway.

**In-threat-model?** **No.** The construction claims "AS-blind" and "selective disclosure" but provides no cross-session, cross-RS unlinkability. The gap requires a formal unlinkability game distinct from SP.

---

### Attack 3: Subverted Phase 2 Ceremony — SSU Breaks Under CRS Compromise

**Attack:** Groth16 for `AgentPolicy` requires a circuit-specific Phase 2 ceremony (§5, Table row: "Proving system (primary): Groth16 with project `pot16.ptau` Phase 1"). The pot16.ptau is a public Phase 1. But Phase 2 — the circuit-specific `zkey` generation — must be run by Bolyra or ceremony participants. If any participant retains the toxic waste τ (the trapdoor from Phase 2), they can evaluate `τ` and forge valid Groth16 proofs for arbitrary witness values, including forged bitmasks. This directly wins the SSU game.

**Why it works:** Groth16 knowledge soundness (A1) is a property of the honest CRS. Under a subverted CRS, knowledge soundness does not hold — an extractor cannot be defined because the toxic waste allows simulation of any statement. The SSU game's "Setup" step says "Generate CRS for AgentPolicy circuit" but provides no specification of the ceremony: participant count, contribution transcript, attestation mechanism, or verifiability. "Honest-majority ceremony assumption" is stated but not bound to any ceremony with a defined N. For a startup Phase 2 with one or two internal contributors, "honest majority" may mean one person.

**How the construction partially addresses this:** It notes PLONK as an alternative that "avoids per-circuit ceremony." But the deployment scenario (§7) and the primary row in §5 use Groth16. If PLONK is meant to be the adversarial-AS-safe path, it should be the primary, and the Groth16 variant should be flagged as requiring a public Phase 2 ceremony with verifiable transcripts.

**In-threat-model?** The threat model explicitly places "the Groth16/PLONK trusted setup (honest-majority ceremony assumption)" outside adversary control — meaning it's assumed away rather than argued. Under a concrete deployment where the Phase 2 is controlled by a single entity, this is the dominant attack vector and the assumption is unjustified.

---

### Attack 4: Low-Entropy Bitmask — Dictionary Attack Defeats Adversarial-AS Privacy Claim

**Attack:** The construction defines 8 tiers (bits 0–7) with implication constraints (§2, gadget 6): bit 4 → bits 3 and 2; bit 3 → bit 2. Bits 0, 1, 5, 6, 7 are independent. Valid bitmask combinations are: {3 options for bits 2/3/4: `001, 011, 111`} × {32 options for bits 0,1,5,6,7: `2^5`} = at most 96 valid values (adding the `000` case: 4 × 32 = 128 valid patterns). A compromised AS that participated in enrollment knows `modelHash` (registered by operator), `operatorPubkeyAx/Ay` (public key, observable), and `expiryTimestamp` (present in the credential). The on-chain Merkle tree stores `credentialCommitment` leaves publicly. A evaluates `Poseidon5(modelHash, opAx, opAy, candidate, expiryTimestamp)` for all 128 candidate bitmasks and compares to the on-chain leaf. Recovery costs 128 Poseidon5 evaluations — effectively zero.

**Why it works:** The SSU reduction sketch (§4, step 6) argues that extracting `permissionBitmask` from `credentialCommitment` requires inverting Poseidon (A3, preimage resistance). This is correct for an arbitrary preimage. But the actual preimage space is 128 elements, not 2^64. Poseidon preimage resistance provides no protection against a dictionary over a space the adversary can enumerate in microseconds. The SP reduction sketch makes the same error: it claims "recovering `permissionBitmask` from `scopeCommitment` is infeasible" under A3, but infeasibility requires the preimage to be uniformly distributed over a large domain.

**In-threat-model?** **No.** The adversarial-AS model (§3) includes AS compromise, yet the AS can trivially recover every enrolled agent's full bitmask from on-chain data. The concrete scenario (§7) explicitly claims the adversarial-AS property: "RS trusts the on-chain Merkle root and the proving system's knowledge soundness, not the AS's attestation. A compromised AS cannot forge scope satisfaction proofs." True — it cannot forge proofs. But it *can* learn every agent's full bitmask, which is the primary privacy claim the construction is designed to enforce. The fix requires either: (1) expanding the bitmask domain with a high-entropy salt as an additional private input committed in `credentialCommitment`, or (2) explicitly restricting the adversarial-AS scope to unforgeability only, not privacy.


## Persona: cu_ciso

---

### Attack 1: The Audit Trail Inversion Problem

- **Attack:** During an NCUA examination or incident response, the examiner asks: "Show me what permissions this agent had when it accessed member PII on March 14th." The CUSO platform's logs show `proof verified, requiredScopeMask=0b10000001` — and nothing else. The ZK property that protects competitive intelligence simultaneously destroys the forensic trail. The CISO cannot produce a record of the agent's *full* permission set for any historical request. The examiner cannot determine whether the agent was over-provisioned, whether `SIGN_ON_BEHALF` or `SUB_DELEGATE` were live at breach time, or whether the operator issued an overly broad credential.

  NCUA Part 748 Appendix A requires a security program with incident detection and response procedures including logging sufficient for after-the-fact review. GLBA Safeguards Rule §314.4(h) requires monitoring and testing that presupposes you can reconstruct what happened. The `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` is opaque — it's a commitment, not a disclosure.

- **Why it works / why it fails:** The construction offers on-chain enrollment audit (§7: "NCUA examiners can audit the on-chain enrollment registry") but this only shows what permissions were *enrolled*, not what was *presented* and *used* at each API call. Enrollment ≠ usage log. The proof's zero-knowledge property is adversarial to the audit requirement. There is no mechanism in §2 or §7 for the RS to log a human-readable authorization record without breaking the SP game.

- **In-threat-model?** No. The construction does not model the regulator as a party who needs post-hoc full disclosure. It treats ZK as uniformly desirable; NCUA Part 748 treats opacity as a liability. The construction must address how a CU produces a NCUA-defensible audit trail for each agent invocation without collapsing scope privacy.

---

### Attack 2: Revocation Has No SLA — The 30-Root Grace Window

- **Attack:** At 2:47 AM, a SOC alert fires: a fraud-detection agent's operator key is suspected compromised. The ops team pages the CUSO, who removes the credential leaf from the Merkle tree and submits an updated root. The root history buffer holds 30 entries (§2, §5: "30-entry circular buffer on-chain"). Until 30 subsequent Merkle updates push the old root out of the buffer, the compromised credential remains verifiable by any RS checking `agentMerkleRoot ∈ on-chain root history buffer`.

  The construction provides no update frequency SLA. If the Merkle tree is updated once per hour (a reasonable rate for 200 CUs each independently enrolling/revoking), the compromised credential is valid for up to 30 hours post-revocation. NCUA Part 748 Appendix B (Incident Response Program) requires containment timelines. FFIEC CAT Domain 3 (Cyber Risk Management) requires the institution to demonstrate effective response. "We revoked it but it remained usable for 30 hours because of a circular buffer design" is not a defensible examiner answer.

- **Why it works / why it fails:** The construction explicitly defers revocation timing: §7 says "Revocation is handled by updating the Merkle tree (removing the credential leaf)" with no SLA, no maximum root age, no emergency revocation path. The buffer size of 30 is an availability-revocation tradeoff that the construction made without acknowledging the regulatory time constraint it implies.

- **In-threat-model?** No. The adversary model in §3 does not include "time-bounded compromise response" as a game parameter. The SSU game has no time dimension — it does not model what happens between enrollment and the next root update. The construction must define maximum root age, emergency revocation (out-of-band path that invalidates all proofs against a specific `nullifierHash` prefix or `credentialCommitment`), and bind this to an incident response SLA.

---

### Attack 3: scopeCommitment Is a Permanent Cross-RS Tracker

- **Attack:** `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` is a **public output** (§2) that is **constant** across every proof this agent ever generates. The `nullifierHash` changes per session (good), but `scopeCommitment` does not change unless the agent re-enrolls with a new bitmask.

  The CUSO platform at RS-1 logs `scopeCommitment = 0xabc...`. RS-2 (a different CU's API gateway) logs the same value from a proof the same agent generated two weeks later. Any party with read access to both RS-1 and RS-2 logs — including the CUSO itself, a compliance auditor, a subpoena, or a data breach at the logging layer — can correlate every action by this agent across all resource servers for the lifetime of the credential.

  This is a GLBA member privacy concern if agents act on behalf of members (which the credit union deployment scenario implies). It is a competitive intelligence concern (the exact scenario §7 claims to protect against: "without revealing that it also holds `FINANCIAL_UNLIMITED`" — but the same `scopeCommitment` links every request from this agent regardless of which RS it hits).

- **Why it works / why it fails:** The SP game in §3 asks whether an adversary can distinguish `b₀` from `b₁` given a *single* proof. It does not model multi-RS correlation over *multiple* proofs from the *same agent*. The construction's own §4 (SP reduction sketch) defends against single-proof bitmask recovery, but the `scopeCommitment` value is a durable pseudonym. Two RSes comparing logs can determine "this is the same agent" without recovering the bitmask, which is sufficient for linkability attacks. The SP game does not capture this because it has one challenger and one proof.

- **In-threat-model?** No. The construction conflates "bitmask privacy" with "agent unlinkability" — it achieves the former but explicitly publishes a constant identifier that defeats the latter. The construction must either (a) make `scopeCommitment` session-ephemeral (include `sessionNonce` in the Poseidon2 preimage), losing the delegation-chaining property it cites in §2, or (b) acknowledge that cross-RS agent tracking is in-scope for the SP game and re-define the privacy guarantee accordingly.

---

### Attack 4: The Adversarial-AS Claim Collapses When Operator = Operator

- **Attack:** Gap 3 (§8) claims "A compromised AS cannot forge scope satisfaction proofs for agents it did not enroll." True — but the operative threat for a credit union is not "rogue AS." It is "compromised operator key."

  The `operatorPubKey` is the entity that signs `credentialCommitment` (§2, gadget 3: `EdDSAPoseidonVerifier`). In the CUSO scenario (§7), each credit union's compliance officer is the "operator" who signs agent credentials. The Baby Jubjub private key that authorizes credential issuance is held by... whom? Where? The construction is silent on operator key custody: HSM, KMS, browser local storage, a script on an EC2 instance, a shared Slack secret?

  If the operator private key is compromised — a spear-phishing attack on the CU's IT admin is a routine NCUA examination finding — the adversary can sign a new `credentialCommitment` with arbitrary `permissionBitmask`, submit it to the Merkle tree enrollment endpoint, and generate valid proofs against the live on-chain root. The on-chain verifier accepts it. The RS accepts it. The SSU game's §4 reduction sketch (step 6, second bullet) explicitly handles this: "A enrolled a different agent whose bitmask does satisfy the predicate. This is not a forgery against the honest agent." Correct — it is something worse: the adversary enrolled a fraudulent *new* agent that the on-chain registry treats as legitimate.

  The construction's "adversarial-AS model" is presented as a selling point. For a CU CISO, the practical threat model is not a rogue OAuth AS — it is a compromised employee credential granting enrollment rights. The construction shifts the trust anchor from AS signing key to operator signing key without reducing the attack surface; it may expand it (every CU now has an independently-held key that must be protected).

- **Why it works / why it fails:** §3 threat model explicitly excludes "the agent's private credential fields (for the honest agent under test)" but says nothing about operator key compromise leading to fraudulent *new* enrollments. The Merkle tree has no admission control described in the construction — any valid EdDSA signature from any enrolled operator key results in a valid leaf. NCUA third-party due diligence (§701.27) requires the CU to assess the security controls of any party holding keys with authority over member-data-adjacent authorization.

- **In-threat-model?** No. The construction must specify operator key custody requirements (HSM mandate? multi-sig enrollment? time-delayed enrollment with challenge period?), an enrollment admission control policy, and a mechanism for the RS to distinguish "legitimate operator enrollment" from "fraudulent enrollment via compromised operator key" — or acknowledge that operator key compromise is a full break of the adversarial-AS resilience claim.


## Persona: rfc7662_advocate

---

### Attack 1: `scopeCommitment` Is a Stable Cross-RS Deanonymizer — Worse Than PPID

- **Attack:** `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` is listed as a **public output** (§2, public outputs table). Both inputs are fixed at enrollment time and never change. Therefore `scopeCommitment` is **identical in every proof the agent ever generates**, across every RS it ever contacts. Any two colluding RSes can trivially confirm they are serving the same agent by comparing this value.

  My toolbox offers pairwise pseudonymous identifiers (OIDC PPID, §3.3 of [OpenID Connect Core]): the AS issues a *different* `sub` to each RS using a per-RS sector identifier. Cross-RS linkability is broken at the AS, not just at the agent. The Bolyra construction is **strictly worse** than the PPID baseline on this dimension.

- **Why it works / fails:** The Scope Privacy (SP) game (§3) only asks whether, given *one* proof, A can distinguish agent b₀ from b₁. That's a one-shot, single-RS game. It says nothing about a multi-session, multi-RS adversary linking all proofs from the **same** agent. The adversary capability list explicitly includes "any number of RS endpoints." A colluding-RS adversary trivially wins the real-world linkability game using `scopeCommitment` alone — no cryptographic attack needed.

- **In-threat-model?** **Yes** — adversary controls "any number of RS endpoints." The construction must address this. Mitigation candidates: per-RS `scopeCommitment = Poseidon3(permissionBitmask, credentialCommitment, RS_identifier)` as additional public input, or suppress `scopeCommitment` as a public output and add a per-RS commitment channel.

---

### Attack 2: Trusted Setup Failure Is Undetectable and Total — AS Key Compromise Is Not

- **Attack:** Section 8, Gap 3 frames "adversarial-AS resilience" as a fundamental advantage over RFC 7662. But the construction silently substitutes one trust anchor (AS signing key) for a more severe one (Groth16 ceremony trapdoor, §4, A1/A2). I raise RFC 9449 DPoP as the comparison point: DPoP's sender-constraint trust anchor is the agent's short-lived ephemeral key pair, generated per-request, with no ceremony and no long-lived secret material.

  The failure modes are asymmetric:
  - **AS key compromise**: detectable (certificate transparency, anomalous issuance patterns); bounded (revoke the key, issue new tokens); doesn't retroactively invalidate accepted proofs.
  - **Groth16 ceremony trapdoor leak**: computationally undetectable in principle; the holder can forge valid proofs for **any** circuit statement (arbitrary `permissionBitmask` satisfying any predicate); all past and future proofs become worthless; recovery requires full re-ceremony + circuit redeployment + re-enrollment of every agent.

  The `pot16.ptau` used is a project-specific Phase 1 (§2.3, §5). The document states "honest-majority ceremony assumption" without specifying the number of participants, ceremony log, or attestation. A Phase 1 with 3 participants is materially less trustworthy than the Semaphore or Hermez ceremonies with hundreds.

- **Why it works / fails:** The security argument in §4 (reduction sketch for SSU) reduces to A1 (knowledge soundness of Groth16), which implicitly assumes the ceremony was not compromised. If it was, the entire soundness argument collapses, and the adversarial-AS resilience claim inverts: a ceremony-compromised adversary has **more** power than a compromised AS, because it can forge proofs the AS could never issue.

- **In-threat-model?** **No** — the adversary model (§3) excludes "the Groth16/PLONK trusted setup (honest-majority ceremony assumption)" from adversary control. This means the construction does not address ceremony compromise. The document should either (a) specify minimum ceremony parameters that make this assumption credible, or (b) switch to PLONK with a universal SRS (which only requires the CRS to be structured, not per-circuit ceremony honesty), and reframe the trust comparison honestly.

---

### Attack 3: Revocation Latency — 30-Root Buffer vs. Real-Time Introspection

- **Attack:** Section 2.1 and §5 specify a 30-entry circular root history buffer for `agentMerkleRoot` validation. Section 7 states revocation is handled by "updating the Merkle tree (removing the credential leaf)." But neither section specifies the root update frequency or the maximum acceptable revocation latency.

  RFC 7662 with `active: false` revokes a token **immediately** on the next introspection call. `draft-ietf-oauth-jwt-introspection-response` with short-lived cached JWTs (e.g., `exp` = 60 seconds) bounds revocation lag to under 2 minutes. For high-security use cases (a compromised AI agent making wire transfers, the §7 CUSO scenario), what is the maximum revocation-to-denial latency in the Bolyra construction?

  If the on-chain root updates every block on Base (~2 seconds), and 30 roots are retained, the revocation window is at most 60 seconds — comparable to cached introspection. But if root updates are batched less frequently (hourly, or on-demand by the CUSO), revoked agent credentials remain valid against historical roots for hours. The construction provides no bound.

- **Why it works / fails:** This attack is not cryptographic — it's operational. The construction's correctness proofs say nothing about the time between Merkle tree update and the expiry of all valid proofs against prior roots. An adversary who learns their credential is about to be revoked can pre-generate a proof against the current root and use it within the 30-root window, even after the leaf is removed. RFC 7662 has no such window by design.

- **In-threat-model?** **Yes** — the threat model includes "network adversaries who observe, delay, and replay messages." The construction must (a) specify a maximum root update cadence and express the revocation bound as a concrete SLA, or (b) introduce a revocation accumulator or nullifier-set that prevents use of historical roots for revoked credentials, analogous to how RFC 7009 token revocation works with immediate effect.

---

### Attack 4: The "Constant-Size" and "Implication Closure" Claims Are Only Advantages at the Wrong Scale

- **Attack:** Section 8, Gap 4 compares Groth16's 128-byte proof against jwt-introspection-response payloads that "scale linearly with disclosed scopes." This is true in the limit but misleading for the concrete deployment in §7: 8 bits, 8 permission names. A signed JWT introspection response for 8 scopes is under 400 bytes, entirely within one TLS record.

  More pointedly: the cumulative-bit implication closure (§2, constraint 6) enforces exactly **three** constraints (bits 2→3→4). If the permission model were extended — which the construction explicitly anticipates with the phrase "64-bit bitmask with 2^64 combinations" — every new implication relationship requires a new circuit constraint, a new trusted setup, and redeployment of the verifier contract. Meanwhile, AS-side policy in RFC 7662 can express arbitrary implication rules in policy code, updated at any time, without a new ceremony.

  The claim "no composition of the baseline stack can match constant-size proof regardless of permission-space cardinality" (§8, Gap 4) is only a meaningful advantage when the permission space is large enough that enumeration fails. For the 8-bit `FINANCIAL_UNLIMITED → FINANCIAL_MEDIUM → FINANCIAL_SMALL` model in §7, RFC 8693 Token Exchange with a scope downgrade policy on the AS is simpler, auditable, and updatable without circuit changes.

- **Why it works / fails:** The construction conflates the theoretical claim (constant-size regardless of 2^64 combinations) with the concrete deployment (8 bits). Implication closure in the circuit is a rigidity, not a feature: every change to the permission hierarchy requires a new circuit constraint, new `.zkey`, new verifier contract, and re-enrollment. The baseline's AS-side policy table handles hierarchy changes with a config update. The construction's advantage on this axis is real only beyond approximately 20–30 distinct permission types — a threshold the §7 scenario does not approach.

- **In-threat-model?** **No** — this is a scope/framing issue, not a forgery attack. But the construction must either (a) tighten the claim to acknowledge it is advantageous primarily for large permission spaces, or (b) demonstrate a concrete path for adding implication constraints without full circuit re-ceremony when the permission model evolves.


## Persona: spiffe_engineer

*I run SPIRE in prod for 40,000 workloads across six AWS regions. I co-authored sections of draft-ietf-wimse-arch. Here is where your construction either solves a real gap or re-implements infrastructure I already have.*

---

### Attack 1: "This Is a SPIRE Attestor, Not a Protocol"

**Attack:** SPIRE's plugin architecture accepts custom node and workload attestors via gRPC extension points. The entire `AgentPolicy` circuit could be packaged as a SPIRE workload attestor: at workload registration time, the SPIRE agent calls the attestor, which runs the Groth16 proof against the on-chain Merkle root and returns a `spiffe://bolyra.ai/agent/{modelHash}` SPIFFE ID. The downstream RS gets an X.509 SVID or JWT SVID through the standard Workload API — a Unix socket call, not a network AS roundtrip.

The claim in §8 Gap 1 ("no AS is contacted at presentation time") is partially true of SPIRE today: the Workload API is local, short-TTL, and the SPIRE agent caches SVIDs. An agent calling `/member/transactions` hits a Unix socket, not a remote authorization server.

**Why it works / fails:** The attack is correct that the "AS-blind" framing is partially misleading — SPIRE's Workload API is not a remote AS. But it fails on two specifics of the construction: (1) SPIRE attestors produce *static* SVID claims bound at issuance. The construction's §2 runtime-adaptive predicate — where the RS chooses `requiredScopeMask` at the moment of the request and the agent proves satisfaction *without reissuance* — cannot be expressed as a certificate extension evaluated at issuance time. You would need to re-attest (and re-issue an SVID) per `requiredScopeMask` value, defeating the "no roundtrip" property. (2) The cumulative-bit implication closure (§2, constraint 6) is enforced inside the R1CS; encoding this as SVID claims would push the enforcement into the RS's policy engine, where it is bypassable by a misconfigured RS.

**In-threat-model?** Yes — the construction survives, but §8 should explicitly state why a SPIRE attestor plugin does not close the gap. As written, the comparison table in §8 ignores SPIFFE entirely, and a reviewer from the IETF workload-identity community will notice.

---

### Attack 2: "WIMSE Local Token Exchange Already Covers Your AS-Blind Claim"

**Attack:** draft-ietf-wimse-arch (Section 4, "Workload Token") defines a workload-to-workload token exchange where the local SPIRE agent (not a remote AS) mints a short-lived JWT SVID for the target audience. From the perspective of the calling workload, this exchange is:

```
workload → local SPIRE agent (Unix socket) → JWT SVID[aud=RS]
```

No remote AS contact. The RS verifies the JWT SVID against the SPIFFE bundle cached locally or fetched from the SPIRE server's bundle endpoint (not an introspection roundtrip). WIMSE Section 5 further defines an "on-behalf-of" token for delegated contexts. The construction's §8 Gap 1 ("RFC 8707 requires audience-specific token issuance") is accurate for RFC 8707 as standalone, but WIMSE resolves exactly this by making audience-scoped issuance a local Workload API call.

Furthermore, WIMSE's charter explicitly includes selective disclosure extensions (the working group has discussed BBS+ over WIMSE tokens). Selective scope disclosure is in-scope for WIMSE, not out-of-scope.

**Why it works / fails:** The attack correctly identifies that the construction conflates "remote AS" with "SPIRE Workload API." However, it fails on the adversarial-AS dimension (§3). WIMSE's local token exchange still trusts the SPIRE server as the credential authority. Under the construction's threat model — §3, "The adversary controls the AS" — a compromised SPIRE server can mint JWT SVIDs claiming `FINANCIAL_UNLIMITED` for an agent that was only enrolled with `READ_DATA`. There is no cryptographic recourse for the RS: it verifies only that the SPIRE server said X, not that X is extractable from a knowledge-sound proof over an on-chain commitment. This gap is real and the construction does address it; it just does not name WIMSE by name when doing so.

**In-threat-model?** Yes — the construction survives on the adversarial-AS axis. But the construction must stop saying "no AS" generically and say "no trust in the credential-issuing authority." The current §8 does not engage WIMSE, and that will read as ignorance rather than informed rejection.

---

### Attack 3: `scopeCommitment` Is a Cross-RS Tracking Vector Outside the Stated SP Game

**Attack:** `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` (§2, public output) is fully deterministic. For a fixed agent, `credentialCommitment` is fixed (bound at enrollment), and `permissionBitmask` is fixed. Therefore `scopeCommitment` is a constant across all invocations of that agent, regardless of which RS is being called or what `requiredScopeMask` is presented.

An adversary controlling multiple RS endpoints — explicitly within the construction's threat model (§3: "any number of RS endpoints for cross-RS linkability attacks") — can trivially correlate all requests from the same agent by the shared `scopeCommitment`. This is a pseudonymous tracking anchor with the same entropy as a static bearer token identifier.

The Scope Privacy game (§3) is defined as a *single-RS, single-proof* experiment: one challenger, one adversary, one proof. It does not prove cross-RS unlinkability. The security claim in §3 Game SP therefore does not bound this attack.

SPIFFE's JWT SVIDs are *audience-specific* (`aud` claim is the RS's SPIFFE ID). No two RSes see the same token, so correlation across RSes requires active collusion between them plus access to out-of-band linking information. The construction has weaker cross-RS privacy than JWT SVIDs on this axis, despite the ZK proof.

**Why it works:** This attack is not addressed by the construction. The reduction sketch for SP in §4 notes that `scopeCommitment` is public but argues preimage resistance prevents recovery of `permissionBitmask`. That is true but irrelevant — the attack does not need to recover `permissionBitmask`. It only needs to observe that the same 32-byte value appears in proofs sent to RS-1 through RS-N. The construction gives the RS a stable pseudonym for free, without the agent's knowledge or consent.

**In-threat-model?** No — the construction does not address this. If §3 claims the adversary may control "any number of RS endpoints for cross-RS linkability attacks," the SP game must be extended to multi-RS, multi-proof, and the `scopeCommitment` needs to be either (a) nonce-randomized per presentation, (b) dropped from public outputs, or (c) its stable-pseudonym property must be disclosed as a design choice with explicit trade-offs documented.

---

### Attack 4: SPIFFE Federation Gives "Portable Identity" — Identify the Residual Gap Precisely

**Attack:** The CUSO scenario in §7 — 200 credit unions, no single trusted AS, agents from CU-A accessing CU-B data — is the canonical SPIFFE federation deployment pattern. SPIFFE federation (RFC-equivalent: draft-ietf-spiffe-spiffe) allows:

- Each CU runs its own SPIRE server (trust domain: `spiffe://cu-a.example/`)
- The CUSO establishes federation with each CU's bundle endpoint
- A CU-A agent presents its X.509 SVID to the CUSO RS, which validates against CU-A's cached trust bundle
- No single centralized AS; each CU is authoritative only for its own trust domain

The construction's §7 claim — "the CUSO cannot run a single centralized AS trusted by all 200 CUs" — is exactly the problem SPIFFE federation solves. Name the residual gap that federation does not address, or the scenario is moot.

**Why it fails against the construction:** SPIFFE federation trusts each CU's SPIRE server as authoritative for that CU's agents. If CU-A's SPIRE server is compromised, it can mint SVIDs claiming `FINANCIAL_UNLIMITED` for a CU-A agent that was enrolled with only `READ_DATA`. The CUSO RS cannot distinguish a legitimate SVID from a fraudulently issued one — both have valid signatures from CU-A's SPIRE CA.

The Bolyra construction's adversarial-AS model (§3) goes strictly further: even a compromised CU-A enrollment infrastructure cannot forge a scope satisfaction proof for a bitmask that was not committed at enrollment time, because forgery requires breaking Groth16 knowledge soundness or Poseidon collision resistance (§4, reduction for SSU). The on-chain Merkle root is the trust anchor, not CU-A's SPIRE CA.

This is the construction's strongest genuine differentiator. But §7 and §8 never say "SPIFFE federation does X but not Y." They only compare against RFC 7662. A WIMSE/SPIFFE reviewer will assume the authors don't know federation exists.

**In-threat-model?** Yes — the construction survives, but only if §7 is rewritten to explicitly contrast with SPIFFE trust-domain federation and state the residual gap: *SPIFFE federation removes centralized AS trust but does not remove trust in each domain's SPIRE CA. Bolyra removes both — the trust anchor is the on-chain enrollment root, not any CA.* Without this, the CUSO scenario reads as a straw man.
