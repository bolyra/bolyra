# Tier 3 Adversarial — C1 Selective scope proof

## Persona: auth0_pm

### Attack 1: The Revocation Vacuum

- **Attack**: The construction is AS-blind by design — no roundtrip to an authorization server. That's the headline property. But AS-blindness eliminates the revocation channel. When a credit union's loan agent is compromised at 2am, the security team needs to kill it *now*. The construction's trust anchor is the on-chain Merkle tree with a 30-entry root history buffer (§2 / Spec §2). A credential committed to root #1 is valid until `expiryTimestamp` — and the construction offers no mechanism to invalidate a specific leaf before expiry. The RS caches roots; the agent generates proofs against historical roots in the buffer. Emergency revocation does not exist in this model.

- **Why it works / why it fails**: The construction addresses replay via `nullifierHash` (§2, gadget 8), but replay prevention and revocation are orthogonal. The nullifier prevents the *same proof* from being replayed; it does nothing to prevent the *same credential* from generating a new proof with a fresh `sessionNonce`. The construction has no `credentialRevocationList`, no on-chain nullifier set for credential IDs, and no mechanism to purge a leaf from the Merkle tree. Compare: WorkOS and Auth0 both offer token revocation endpoints with sub-second propagation. JWT introspection (RFC 7662) with a short-lived token + revocation list gives near-real-time kill. The construction's answer to "the agent is compromised" is "wait for expiry."

- **In-threat-model?** No — the threat model (§3) scopes adversary capabilities to forgery and linkability, not to *legitimate credential compromise followed by emergency termination*. The construction must address this. A credit union under NCUA examination cannot accept a revocation story of "set a short expiry."

---

### Attack 2: The rapidsnark Deployment Assumption

- **Attack**: The construction's §6 table lists the production proving path as "Groth16 (rapidsnark, native) < 1s on a server with the rapidsnark binary." The §7 scenario implicitly assumes the loan agent runs on an always-on server with this binary installed. Real enterprise AI agents run in AWS Lambda, Azure Functions, GCP Cloud Run, or containerized Kubernetes workloads with ephemeral runtimes. The WASM fallback (snarkjs) is listed at < 8s. For a request/response authorization flow, 8s is not a latency budget — it's a timeout. WorkOS and Auth0 issue tokens in < 100ms over HTTPS. The construction's §6 "targets" are aspirational; the WASM path is the deployment reality for the vast majority of agentic runtimes today.

- **Why it works / why it fails**: The construction does acknowledge the two proving paths but frames rapidsnark as "the production recommendation." It does not address: (a) how the binary is distributed, versioned, and updated across an agent fleet; (b) what happens in cold-start Lambda scenarios where the binary isn't cached; (c) whether the <1s target holds under concurrent proving (rapidsnark is single-threaded per invocation). The construction argues constant-size proof (§8, Gap 4) beats O(disclosed claims) JWT payloads — but JWT issuance at 100ms with a 500-byte payload wins against a 320-byte proof that takes 8s in WASM. Proof size is not the bottleneck the buyer cares about.

- **In-threat-model?** No — the construction's threat model is cryptographic, not operational. The performance claims in §6 need a companion deployment architecture that makes the < 1s path reachable without requiring every operator to manage a native binary. This is a GTM blocker, not a cryptographic flaw.

---

### Attack 3: Operator Key Blast Radius

- **Attack**: The credential commitment is `Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiry)` (§2, gadget 2). The operator's EdDSA key signs this commitment; the EdDSA verification gadget (gadget 3) enforces it. Every enrolled agent credential for a given operator is signed by the *same* operator EdDSA private key. If that key is compromised, an attacker can forge `credentialCommitment` values for any `permissionBitmask`, sign them with the stolen key, insert them into the Merkle tree (or present them off-chain against a valid root), and generate valid proofs. The fix requires the operator to rotate the key — but since `operatorPubkeyAx` and `operatorPubkeyAy` are baked into every `credentialCommitment` leaf, rotating the key means re-enrolling *every* agent credential under the new key and waiting for the new Merkle root to propagate on-chain. The construction describes no key rotation mechanism, no multi-key operator model, and no sub-operator key hierarchy.

- **Why it works / why it fails**: Auth0, WorkOS, and Stytch rotate their JWKS signing keys on a schedule with zero-downtime dual-key windows — old and new keys both valid for a grace period. RFC 7591 (Dynamic Client Registration) supports key rotation at the client level. The construction's operator key is a single point of catastrophic failure with a recovery path (re-enrollment) measured in hours or days for a large fleet. The security argument in §4 explicitly excludes "operator key compromise" from the adversary capabilities — the adversary "does not possess any honest operator's EdDSA private key." That assumption is load-bearing and unaddressed.

- **In-threat-model?** No — the adversary model (§3) treats the operator key as an axiomatically honest party. The construction must either specify a key rotation protocol or acknowledge that operator key compromise is an out-of-scope catastrophic failure mode, and let buyers decide if that's acceptable.

---

### Attack 4: scopeCommitment Is the Default Privacy Hole

- **Attack**: The construction's §4 (privacy game SI) explicitly acknowledges: "If the RS colludes with the enrollment authority and obtains the `credentialCommitment`, it can check `Poseidon2(candidateBitmask, credentialCommitment) == scopeCommitment` for each candidate bitmask. For a 64-bit space this is feasible by brute force." The proposed fix is `AgentSelectiveScopeMinimal` — a variant circuit that drops `scopeCommitment` from the public outputs. But the *main construction* in §2 includes `scopeCommitment` as a defined public output. The §5 Bolyra primitive mapping lists it. The §7 deployment scenario does not specify which variant is deployed. The §6 proof size table does not distinguish the two variants. The headline claim (§1) is "without revealing any bits of `permissionBitmask` beyond what the predicate logically implies" — that claim holds only for the minimal variant, not the default circuit.

- **Why it works / why it fails**: The core banking RS in the §7 scenario is "a separate entity (a CUSO or fintech partner)." The credit union does not want the partner to learn its full permission topology (§7, "Why ZK matters here"). But the partner RS receives `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` as a public signal. If the partner RS can obtain `credentialCommitment` — from the on-chain Merkle tree leaf data, from a prior enrollment event, or from a colluding party — it can brute-force the 64-bit bitmask in approximately 2^64 Poseidon evaluations. With GPU acceleration, that's feasible offline. The construction introduces the privacy-preserving variant as a footnote but deploys the leaky version as the primary circuit. This is a gap between the claimed privacy property and the default instantiation.

- **In-threat-model?** Partially — the construction acknowledges the attack (§4, SI privacy caveat) but does not elevate `AgentSelectiveScopeMinimal` to the primary circuit or update §7 to specify which variant the deployment uses. The construction must either (a) make the minimal variant the default, or (b) formally restrict the claim in §1 to exclude scenarios where the RS has access to `credentialCommitment`.


## Persona: cryptographer

Applied cryptographer. I have read the construction carefully. My objection style: if you cannot point me at a game, a simulator, and a reduction, I will assume the property does not hold. Four attacks follow. Two break the SI game outright. One breaks the SSU game under subverted setup. One identifies a missing game the authors have not defined at all.

---

### Attack 1: Adaptive Scope-Oracle Recovers Full Bitmask in O(64) Queries

**Attack:** The threat model (§3) explicitly admits colluding resource servers. `requiredScopeMask` is an RS-chosen public input at request time — this is a design feature, not a bug. An adversary controlling a set of colluding RSes sends 64 sequential requests to the same agent, each with `requiredScopeMask = (1 << i)` for i ∈ [0, 63). Each request succeeds (proof verifies) iff bit i is set in `permissionBitmask`. After 64 queries the adversary has reconstructed `permissionBitmask` exactly.

**Why it works:** The SI game (§3, Privacy game) is defined over a **single** proof transcript against a **fixed** mask M. The game gives A one proof and asks it to guess which credential generated it. That is not the relevant adversarial setting. In deployment, the same enrolled credential authorises arbitrarily many requests over its lifetime. The runtime-adaptability of `requiredScopeMask` — the construction's primary differentiator over RFC 7662 — is precisely what enables the oracle. Groth16 ZK is zero-knowledge per proof; it says nothing about what an adversary learns from adaptively chosen public inputs across many proofs.

**What a correct game would need:** A multi-proof indistinguishability game where A is given q oracle accesses to a proving oracle Prove(C_b, M_j) for adaptively chosen masks M_j, and must still guess b. The construction provides no such game and no reduction.

**In-threat-model?** Yes — colluding RSes are explicitly in-scope. **Construction must address this.** The SSU survives (you cannot forge a proof for permissions you don't have), but SI is dead.

---

### Attack 2: scopeCommitment Brute-Force via On-Chain Leaf Publication

**Attack:** `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` is a public output in every proof (§2, Public outputs). The on-chain agent Merkle tree stores `credentialCommitment` values as leaves; standard Solidity Merkle tree implementations emit a `LeafInserted(index, leaf)` event on enrollment — this is how the Merkle root is updated. Any observer (including an RS, an AS, or a passive network adversary) can enumerate all `credentialCommitment` values from the public event log.

Given `credentialCommitment` and `scopeCommitment`, the attack is: enumerate all valid `permissionBitmask` values and check `Poseidon2(candidate, credentialCommitment) == scopeCommitment`. The spec defines 8 meaningful permission bits (bits 0–7). With the 3 cumulative-implication constraints enforced by the circuit, the valid bitmask space is at most 2^8 = 256 values. Poseidon evaluations are cheap. Full recovery completes in microseconds.

**Why the construction's caveat fails:** Section 4 (privacy reduction) states: "recovering the bitmask requires inverting Poseidon — which contradicts A3 (preimage resistance)." This is wrong. Preimage resistance says: given h, it is hard to find x such that H(x) = h. That hardness argument requires x to have sufficient min-entropy. With only 256 candidate preimages, there is no preimage resistance argument — the adversary does not invert Poseidon; it evaluates it forward 256 times. A3 is irrelevant.

The construction proposes `AgentSelectiveScopeMinimal` (dropping `scopeCommitment`) as a mitigation, but that variant is not the primary construction, has no circuit spec, and is not covered by the SSU/SI game definitions. The gap between "we could drop this output" and "here is a security proof for the variant that drops it" is not closed.

**In-threat-model?** Yes — passive network adversary is in scope (§3: "A observes all proof transcripts"). **Construction must address this.**

---

### Attack 3: Groth16 Phase-2 Subversion Collapses SSU

**Attack:** The SSU reduction (§4) reduces to A1: knowledge soundness of Groth16 in the generic group model. Knowledge soundness holds only if the Groth16 CRS `(pk, vk)` is generated honestly — specifically, that the "toxic waste" (the trapdoor elements α, β, γ, δ in the phase-2 structured reference string) is discarded after setup. If an adversary holds the toxic waste, it can produce a valid proof π* for any statement, including false ones. The extractor in the knowledge soundness reduction does not function against a prover who exploits the trapdoor.

The construction's SSU game (§3) delegates setup to a trusted Challenger. But the construction (§5, Bolyra primitive mapping) says: "Project-specific keys (Agent/Delegation) use pot16.ptau." The `pot16.ptau` is the phase-1 powers-of-tau. Groth16 requires a **circuit-specific phase-2 ceremony** on top of it. The construction is silent on: who runs the phase-2 MPC, how many participants, what happens if all participants collude, and whether the verification key is derived deterministically from a public transcript.

For Gap 3 (§8, Adversarial-AS Soundness), the construction claims: "even a compromised AS cannot forge a proof for permissions the operator never signed." This claim is false under subverted phase-2. An adversary who ran (or compromised) the phase-2 ceremony can forge any proof, regardless of the operator EdDSA key or the Merkle root. The EdDSA binding and the Merkle membership are enforced only within the circuit constraints; if the CRS is malformed, constraint satisfaction is not required for proof verification.

PLONK (the alternative proving system) uses a universal setup (Groth16's circuit-specific phase-2 is replaced by a universal SRS), partially mitigating this. But the construction's production recommendation is Groth16 (rapidsnark, <1s). The security argument under the primary deployment path has a gap.

**Formal statement:** The SSU game should be parameterized by a setup algorithm that may be adversarially controlled. The reduction sketch in §4 does not cover the subverted-CRS case. A correct claim would be: SSU holds under honest CRS *and* collapses entirely under subverted CRS. The construction should at minimum (a) specify the phase-2 ceremony or reference a public transcript, (b) argue the PLONK path is the security-prioritized recommendation, or (c) add a game variant for subverted setup.

**In-threat-model?** No — the current threat model assumes the BN128 pairing and the CRS are honest. But the construction's Gap 3 claim ("adversarial AS cannot forge") implicitly assumes setup trust that is never established. **Construction must either bound the setup trust assumption explicitly or argue the PLONK universal-setup path as primary.**

---

### Attack 4: scopeCommitment Is a Permanent Cross-RS Credential Fingerprint

**Attack:** `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` is deterministic and credential-specific — it does not depend on `sessionNonce`, `requiredScopeMask`, or `currentTimestamp`. Every proof generated by the same credential produces the same `scopeCommitment` regardless of which RS is queried or what scope is requested.

A passive adversary observing proof transcripts across multiple RSes sees a stable identifier for every credential. Two colluding RSes that both received proofs from the same agent immediately know they served the same credential — even if the agent presented different `requiredScopeMask` values, even if the agent changed its session nonce, and even if the agent used different network paths. The fingerprint is immutable for the credential's lifetime.

This is strictly weaker unlinkability than what BBS+ achieves. A BBS+ derived presentation with a fresh blinding factor is unlinkable across verifiers even without selective disclosure. The construction's §8 compares against BBS+ and claims superior privacy; the `scopeCommitment` output makes this comparison false on the cross-RS linkability dimension.

**Why the zero-knowledge argument does not save it:** The ZK property of Groth16 says the proof itself leaks nothing beyond the public signals. `scopeCommitment` is a public signal. The ZK property is doing exactly what it promises — it hides everything *except* the public outputs. The cross-RS tracking comes from the public outputs by design, not from a weakness in the Groth16 ZK proof.

**What a correct SI game would need to say:** The game must define an adversary that sees transcripts from multiple RSes and wins if it links two transcripts to the same credential. The current game gives A a single transcript and asks it to distinguish two credentials — a much weaker and irrelevant formulation.

**In-threat-model?** Yes — colluding RSes are in scope. The `scopeCommitment` output is in the primary construction. **This is a structural flaw in the public output selection, not an edge case.**


## Persona: cu_ciso

### Attack 1: Credential Revocation Is Absent — NCUA Part 748 Fails on Incident Response

- **Attack**: A disgruntled employee at the credit union exfiltrates the loan agent's credential fields (the `credentialCommitment` witness plus the Merkle proof siblings). They sell this to a fraudster. The credit union's security team detects the breach at 11pm on a Friday and calls me. I ask: "How do we revoke the loan agent's credential right now?" The construction offers no answer. The Merkle tree is described as "append-only" (§5, "on-chain Merkle tree"). The root history buffer holds 30 entries, but §2 provides no mechanism to invalidate a leaf or exclude a specific `credentialCommitment`. The only lever is waiting for the compromised root to age out of the 30-entry buffer — but the construction does not specify how long that takes or what triggers new root insertions. Meanwhile, the fraudster can generate valid proofs until the root cycles.

- **Why it works**: NCUA Part 748 Appendix B, Incident Response Program, requires the credit union to "contain and control the incident" and "prevent further unauthorized access." If the answer to "how do we terminate this agent's access" is "wait for the Merkle root to age out," no examiner will accept that. The construction does not define a revocation primitive, an emergency root-rotation procedure, or a nullifier blocklist at the verifier level. Compare: FFIEC CAT Domain 1 (Cyber Risk Management) explicitly calls for "controls to prevent and detect the exfiltration of sensitive data" and "ability to terminate access."

- **In-threat-model?** No. The SSU game (§3) only models forgeability — it does not model revocation after legitimate credential compromise. The construction must address this: either a revocation leaf that overrides the original enrollment, a blocklist at the on-chain verifier contract for specific nullifier hashes, or a defined maximum credential lifetime with forced re-enrollment.

---

### Attack 2: Operator EdDSA Key Custody Has No HSM Anchor — FFIEC Key Management Control Gap

- **Attack**: I read §3 closely. The construction's trust anchor is the operator EdDSA private key: "even a compromised AS cannot forge a proof for permissions the operator never signed, because the credential commitment is operator-EdDSA-signed." I ask the vendor: "Where does this private key live?" The construction is silent. If it lives in an environment variable on an EC2 instance, or in a secrets manager, it is not in a FIPS 140-2 Level 2 or Level 3 HSM. My NCUA examiner will open the FFIEC IT Examination Handbook (Information Security booklet, §III.C, Cryptographic Key Management) and ask for key generation records, dual-control evidence, and hardware custody attestation. The Baby Jubjub key used in `EdDSAPoseidonVerifier` is not a NIST-approved curve. FIPS 140-3 validated HSMs support P-256, P-384, and Ed25519 — not Baby Jubjub over BN254. There is no FIPS-validated HSM that can generate or store this key natively, which means either (a) the key is generated in software and wrapped, or (b) the credit union accepts a gap finding.

- **Why it works**: The construction's security argument (§4) reduces EdDSA security to DLP on Baby Jubjub, which is fine cryptographically. But regulatory defensibility is not the same as cryptographic soundness. NCUA Part 748 §748.0(b) and the GLBA Safeguards Rule §314.4(c)(3) require "access controls, including technical and physical controls" for systems storing member data. A signing key that authorizes AI agents to perform `FINANCIAL_SMALL` ($0–$100) or `FINANCIAL_MEDIUM` ($0–$10K) operations (§7 scenario) is a sensitive control — and the construction gives no guidance on protecting it.

- **In-threat-model?** No. The threat model (§3) explicitly excludes operator private key compromise: "A does not control… the Baby Jubjub discrete log." But the CISO's threat model does include insider threat and key exfiltration. The construction must either (a) define a key custody requirement (HSM or equivalent), (b) specify a key rotation and re-enrollment procedure, or (c) acknowledge this as an out-of-scope deployment concern and direct operators to FIPS-compliant alternatives such as wrapping the Baby Jubjub key under an HSM-protected KEK.

---

### Attack 3: Blockchain RPC Is an Uncontracted Third-Party with No SLA — NCUA Third-Party Risk Exposure

- **Attack**: RS verification step 5 (§2) reads: "RS verifies: `agentMerkleRoot` ∈ on-chain root history buffer (read from contract or cached)." "Or cached" does heavy lifting here. If the RS reads the Merkle root from the on-chain contract in real time, it has a hard dependency on a blockchain RPC endpoint (Base mainnet or Base Sepolia per the CLAUDE.md deploy target). My core banking processor (FIS, Fiserv, Jack Henry) SLAs at 99.99% uptime. Public blockchain RPC endpoints — even Alchemy or Infura enterprise tiers — are typically 99.9% (8.76 hours downtime/year). If the RPC is down when my loan agent needs to process a disbursement, the agent cannot prove authorization. That is a service outage my board will hear about. If the RS uses a cached root instead, I ask: what is the cache staleness window? During that window, could a revoked root still be accepted? The construction does not specify cache invalidation policy, maximum cache age, or fallback behavior.

- **Why it works**: NCUA Letter to Credit Unions 01-CU-20 (Third-Party Arrangements) and NCUA Part 712 (CUSOs and third-party relationships) require due diligence on all vendors in critical path systems. The blockchain and the RPC provider are not just technical dependencies — they are third-party service providers. My vendor management policy requires: SLA documentation, business continuity plans, right-to-audit clauses, and concentration risk assessment. The construction names no RPC provider, specifies no SLA, and provides no business continuity procedure for blockchain unavailability. My examiner will ask for the vendor contract; there is none.

- **In-threat-model?** No. The threat model (§3) assumes the on-chain Merkle tree state is available and treats it as an integrity primitive ("immutable once committed; root history buffer is append-only"). Availability is not modeled. The construction must specify: maximum acceptable cache staleness, behavior when the chain is unreachable (fail-open vs. fail-closed), and the identity of the infrastructure provider subject to vendor management review.

---

### Attack 4: The Audit Trail Is Cryptographically Sound but Examiner-Illegible — NCUA Exam Defensibility Theater

- **Attack**: §7 states: "Under NCUA examination, the credit union can replay the proof transcript to demonstrate that the agent was authorized for exactly the requested scope at the time of the transaction, with cryptographic assurance independent of the partner's attestation." I call my NCUA examiner. I hand them a 320-byte Groth16 proof and six 32-byte field elements. They look at me. The proof is `{π_A: [0x1a3f..., 0x2b4c...], π_B: [...], π_C: [...]}`. The public signals are six BN254 scalar field elements. The examiner cannot run the verifier. They do not have the verification key. They cannot independently confirm the proof is valid without trusting my software. What they need is: "At 14:34:07 UTC on 2026-06-15, Agent ID `loan-agent-001` was authorized for `WRITE_DATA | FINANCIAL_SMALL` to `core-banking-api.example.com/disbursements`, session nonce `0xdeadbeef`, proof verified against on-chain root `0x1234...` (block 19,482,331)." That is an audit artifact. A Groth16 proof blob is not. Additionally: the `requiredScopeMask` is a 64-bit integer. The construction nowhere maps `0b00000110` to human-readable labels in the audit log. An examiner reading the transaction record cannot confirm without bespoke software that `0b00000110` means WRITE_DATA | FINANCIAL_SMALL and not something else.

- **Why it works**: NCUA Part 748 Appendix A §III.D (Audit Procedures) and FFIEC CAT Domain 3 (Cybersecurity Controls, Baseline, Audit Logging) require logs that are human-interpretable by examiners and auditors, not just cryptographically verifiable by specialists. GLBA Safeguards Rule §314.4(h) requires "monitoring and testing" of the safeguards program — which implies someone must be able to read the logs. The construction produces cryptographic evidence, not an examiner-readable audit trail. A SOC 2 Type II auditor testing the "logical access" criterion will hit the same wall: the control evidence is a ZK proof, not a log entry.

- **In-threat-model?** No — and the construction cannot fix this cryptographically. It must be addressed at the deployment layer: a logging wrapper that translates proof verification events into structured, human-readable audit records (`agent_id`, `scope_labels`, `timestamp`, `rs_endpoint`, `proof_hash`, `merkle_root_block`), stored in a tamper-evident log (e.g., CloudTrail, immutable S3) separate from the cryptographic proof. The proof is the integrity anchor; the log is the examiner artifact. The construction currently conflates these.


## Persona: rfc7662_advocate

*OAuth Working Group, ten years shipping production introspection. I accept that Groth16 is sound. My job is to find where the construction's claimed gaps against the baseline either don't hold or create new problems the author didn't notice.*

---

### Attack 1: `scopeCommitment` Is a Stable Cross-Session Tracker

**Attack:**
Every proof emits `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` as a public output (§2, public outputs table). Neither input changes across sessions — `permissionBitmask` is fixed at enrollment, and `credentialCommitment` is deterministic from the same inputs. Therefore `scopeCommitment` is identical across every proof generated from the same credential, regardless of `sessionNonce`, RS, or time. Any party that collects two proofs from the same agent — including a passive network observer or colluding RSes — can link them trivially by matching the `scopeCommitment` field. The nullifier prevents replay but does nothing to prevent linkage.

**Why it matters against the construction:**
The construction's threat model (§3) lists "colluding resource servers" as an adversary and claims the proof reveals "nothing about `permissionBitmask` beyond satisfaction of M." That claim is true for the bitmask value, but the construction doesn't claim or achieve *unlinkability*. The `scopeCommitment` is a persistent pseudonym — worse than DPoP because DPoP key material can be rotated per-RS (pairwise keys), while `scopeCommitment` is derived from immutable credential fields. OIDC PPIDs achieve per-RS pseudonymity exactly by deriving the sub identifier from a per-RS sector identifier. Bolyra achieves the opposite: a single global identifier stable across all RSes.

**In-threat-model?** Partially. The construction doesn't claim unlinkability as a goal, but §8 Gap 1 frames the construction as superior to "AS-side policy" approaches for privacy. A reader will reasonably infer cross-RS privacy. The `AgentSelectiveScopeMinimal` variant (mentioned as a caveat in §4) drops `scopeCommitment` and would address this — but it's not the primary construction and doesn't appear in the deployment scenario (§7). The construction must either (a) make `scopeCommitment` include `sessionNonce` (breaking delegation chain linking) or (b) promote the minimal variant as the default and treat the full variant as opt-in for delegation contexts only. As written, the primary circuit leaks a stable cross-session identifier the baseline doesn't.

---

### Attack 2: JWT Introspection Pre-Issuance Eliminates the AS Hot-Path Argument

**Attack:**
The construction's Gap 1 (§8) is titled "AS-Blind Presentation" and argues that "every credential and every introspection response originates from the AS" — implying the AS is always in the hot path. This is false under draft-ietf-oauth-jwt-introspection-response (§3 of that draft, "offline verification"). An AS pre-issues a signed JWT introspection response for each expected scope combination; the RS caches it. At request time the RS verifies the JWT signature locally — no AS roundtrip, no online call. The AS is out of the hot path.

The construction correctly identifies Gap 2 (Runtime-Adaptive Predicate) as the stronger distinction: the RS choosing `requiredScopeMask` at request time without re-issuance is something pre-issued JWTs cannot match. But Gap 1 is presented as a *separate, independent* gap. It isn't. It collapses to Gap 2 when the baseline is deployed correctly.

**Why it matters against the construction:**
By framing Gap 1 as structurally distinct from Gap 2, the construction implies two independent failure modes in the baseline. A careful reviewer will notice they reduce to one. This weakens the argument at §8 and risks letting critics dismiss the entire §8 analysis as conflated. If the author's actual strong claim is runtime-adaptive predicates (which is genuinely novel), that claim should stand alone — it doesn't need the AS-hot-path framing that draft-ietf-oauth-jwt-introspection-response already addresses.

**In-threat-model?** No — this is an argument quality issue, not a cryptographic break. The construction survives because Gap 2 is real and is the load-bearing claim. But the author must collapse Gap 1 into Gap 2 or acknowledge the pre-issuance case. Leaving Gap 1 as written invites dismissal of the entire §8 comparison.

---

### Attack 3: The Effective Permission Space Is 8-Bit — Constant-Size Advantage Is Premature

**Attack:**
The construction's Gap 4 (§8) claims constant-size proof as a structural advantage: "128 bytes always, whether the bitmask is 8 bits or 2048 bits." The concrete deployment scenario (§7) defines exactly 8 permissions (bits 0–7). A JWT `scope` claim encoding those 8 permissions as space-delimited strings — `read_data write_data financial_small financial_medium` — fits in under 80 bytes, smaller than the 320-byte Groth16 payload. The constant-size argument only beats the baseline when the permission space exceeds roughly 20–25 discrete claims (where scope-string enumeration exceeds 320 bytes). At 8 defined bits, the baseline is 4× more compact.

Separately: the cumulative implication rules (§2, gadget 5) constrain the valid bitmask space to well under 2^8. Bits 2/3/4 have forced relationships; only a subset of 256 bitmasks are valid. An RS that learns `scopeCommitment` and the `credentialCommitment` (both public) can enumerate all valid bitmasks (fewer than 200 after implication filtering) and recover the exact `permissionBitmask` by brute-force hash-check — a computation that takes milliseconds on commodity hardware. The construction acknowledges this in §4 ("For a 64-bit space this is feasible by brute force") but downplays it by citing 64-bit space, when the effective valid space is orders of magnitude smaller due to the implication rules the circuit itself enforces.

**In-threat-model?** Mixed. The scalability claim is forward-looking (64-bit space, future expansion) and the construction is honest that it is a 64-bit *encoding*, not a 64-bit *enumeration*. But the brute-force attack is in-threat-model and underdisclosed: §4's caveat says "64-bit space… feasible" but should say "effective space after implication filtering is ≤ 200 values, recoverable in microseconds." The `AgentSelectiveScopeMinimal` variant must be the default for any deployment where bitmask privacy is claimed.

---

### Attack 4: The Root History Buffer Is Silent Revocation Without RFC 7009 Semantics

**Attack:**
The on-chain root history buffer holds 30 entries (§2, table row "Root history buffer"). Credentials are proven against a root in this buffer. When the buffer rotates out a root — due to new enrollments, tree updates, or simply time — agents whose `credentialCommitment` is a leaf under an evicted root can no longer generate valid proofs, even if their `expiryTimestamp` has not elapsed and their permissions were never revoked. The 30-root capacity provides no wall-clock guarantee: if the operator enrolls 31 agents in a burst, the oldest root is evicted immediately, regardless of credential expiry.

RFC 7009 (OAuth 2.0 Token Revocation) provides explicit, synchronous revocation with defined error responses (`invalid_token`, `revoked`). A client that presents a revoked token gets a clear error code. An agent whose root has rotated out of the Bolyra buffer gets a proof-verification failure indistinguishable from a forged proof, an expired credential, or a Merkle path mismatch. There are no defined error codes, no distinction between "revoked by operator" and "root buffer overflow."

**In-threat-model?** Yes — this is a liveness and operational correctness issue the construction must address. The deployment scenario (§7) is a regulated credit union context under NCUA examination. Silent, ambiguous proof failure in a financial authorization flow is an audit risk. The construction should either (a) define a minimum root retention window in terms of wall-clock time (not entry count), enforced by the contract, or (b) define error conditions distinguishing root-not-found from proof-invalid. As written, root buffer overflow creates a denial-of-service vector for any party that can trigger rapid Merkle tree updates — and the AS, which controls enrollment, can do exactly that.


## Persona: spiffe_engineer

*Context: I co-author WIMSE drafts and run SPIFFE/SPIRE at scale. I'm not here to dismiss cryptography — I'm here to ask whether you've solved the right problem at the right layer.*

---

### Attack 1: Your Trust Anchor Is a Software Secret — SPIRE Roots Trust in Hardware

**Attack:** The construction's security in §3 ("A does not control any honest operator's EdDSA private key") and §4 (EdDSA EUF-CMA under Baby Jubjub DLP) treats the operator keypair as if it were equivalent to a hardware-rooted attestation. It is not. The operator EdDSA private key lives somewhere — a KMS, a CI/CD secret, a developer's keychain, a `.env` file. SPIRE's node attestation roots trust in TPM chips, AWS Instance Identity Documents, GCE metadata tokens, or k8s projected service accounts. These are hardware-backed secrets that cannot be leaked by a misconfigured pipeline. The construction's §8 Gap 3 argues "a compromised AS cannot forge an operator signature" — true, but a compromised secrets manager *can* forge every credential that operator would ever sign, retroactively and prospectively. The `credentialCommitment` in the on-chain Merkle tree is then worthless: it proves the key signed, not that the signing was authorized by a hardware-attested node.

**Why it works / fails:** The construction explicitly scopes out key compromise ("A does not possess...") but gives no mechanism for *binding the operator key to a hardware attestation*. There is no hardware root in the threat model. This is not a zero-knowledge weakness — it is a key management weakness that SPIFFE solved in 2018 with node attestors.

**In-threat-model?** No. The construction must either (a) acknowledge that operator key compromise is catastrophic and specify a HSM/KMS binding requirement, or (b) extend the enrollment flow to include a node-attestation proof that the operator key is hardware-resident. As specified, the "adversarial AS" argument (§8 Gap 3) is valid only when the AS is the point of compromise — it breaks down when the operator keypair is the point of compromise, which is the more common enterprise incident.

---

### Attack 2: AS-Blind Presentation Destroys Audit Trails in Regulated Deployments

**Attack:** The construction's Gap 1 (§8) claims AS-blind presentation as a *property*. The deployment scenario (§7) explicitly targets NCUA-supervised credit unions. NCUA examination guidance for AI agents requires complete authorization audit trails anchored to the institution's own systems — not to a partner RS's log. The credit union's loan agent authorizes a $50,000 disbursement; the RS logs the proof. The credit union's internal AS has *no record* that authorization was requested, granted, or against what scope. The proof is RS-resident. SPIRE's Workload API creates a logged SVID issuance event for every workload credential access; WIMSE token exchange (draft-ietf-wimse-workload-identity-bcp §6) creates a token exchange audit record. The Bolyra construction's "AS-blind" property means the operator's AI governance and compliance stack is blind to its own agents' authorization events.

**Why it works / fails:** §7 says "the RS can replay the proof transcript to demonstrate authorization." This proves the proof was valid — it does not prove that the credit union's own internal policies were followed, that the agent was still in good standing at proof time, or that the authorization conforms to the institution's documented AI governance framework. An NCUA examiner asks: "Show me your authorization logs." The credit union's answer is "ask the fintech partner for their RS logs." That is not acceptable.

**In-threat-model?** No. The construction optimizes for a property (AS-blind) that is actively harmful in its target deployment scenario (§7). The threat model (§3) does not include "regulatory examiner who requires institution-side authorization logs" as a principal at all. The construction must specify either a callback/notify pattern to the operator AS, or a hybrid where the agent logs a proof commitment to an operator-controlled audit ledger before presenting to the RS.

---

### Attack 3: "Runtime-Adaptive Predicate" Is Limited to Bitwise AND — WIMSE Policy Engines Cover the Real Cases

**Attack:** §8 Gap 2 claims runtime-adaptive predicates as a structural differentiator. The construction's predicate is exactly `permissionBitmask & requiredScopeMask == requiredScopeMask` — a 64-bit AND evaluated in-circuit. In production workload authorization, RSes need predicates that the circuit cannot express without re-enrollment: "WRITE_DATA is allowed only for loan records where `loan.assigned_officer_id == agent.credential.subject_id`" or "FINANCIAL_MEDIUM is allowed only if `transaction.counterparty` is on the institution's approved vendor list." These are data-plane predicates that depend on the request payload, not just the credential's static bitmask. SPIFFE + OPA (or Cedar) evaluates these at the RS's local policy engine against a full SVID and request context — no circuit required, no re-enrollment required. The WIMSE `draft-ietf-wimse-arch` §4 calls this "workload authorization" as distinct from workload identity, and explicitly leaves policy evaluation to the RS-local engine. The construction conflates identity proof with authorization policy and pays 42,400 constraints for a predicate that OPA evaluates in microseconds with richer semantics.

**Why it works / fails:** The circuit is a fixed predicate. Any authorization policy that goes beyond `AND(required_bits, actual_bits)` requires either (a) a new circuit instantiation with different gadgets, (b) re-enrollment to encode the additional constraint into the bitmask, or (c) an out-of-band policy check that reintroduces the AS or a policy engine. The "runtime-adaptive" property holds strictly for the bitmask-AND predicate — it does not generalize. A SPIFFE engineer at a Fortune 500 with 200 distinct RS authorization policies cannot encode those in a 64-bit bitmask.

**In-threat-model?** Partially. The construction's claim is technically correct for its stated predicate. But the §7 scenario (core banking API disbursement) almost certainly requires contextual predicates beyond `requiredScopeMask`, and the construction gives no path to expressing them. The "why the baseline cannot match" argument (§8) would be stronger if it acknowledged the predicate limitation and positioned it as a first-pass capability that complements a local policy engine.

---

### Attack 4: ScopeCommitment Is a Stable Cross-Session Correlator — SPIFFE Rotates SVIDs Every Hour

**Attack:** `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` (§2, §5) is deterministic. For a fixed agent with a fixed credential, `scopeCommitment` is identical across every proof, every session, and every RS. §4 (SI privacy game caveat) acknowledges that a colluding RS plus enrollment authority can brute-force the bitmask from `scopeCommitment`. The proposed mitigation is `AgentSelectiveScopeMinimal` — a variant circuit that drops `scopeCommitment` — mentioned in a single paragraph with no formal specification, no deployment guidance, and no analysis of what chain-linking properties are lost when it is omitted. More critically: the `expiryTimestamp` field (§2) has no specified maximum — a credential could be valid for years. SPIFFE SVIDs rotate every hour by default precisely to bound the linkability window. Two RSes that compare `scopeCommitment` values — even without the enrollment authority — can determine that the same agent authorized both requests, across the full credential lifetime, potentially years. The colluding RS threat (§3: "A controls multiple RSes that compare notes") is in the threat model but the mitigation requires using a non-default, underspecified circuit variant.

**Why it works / fails:** The primary circuit (`AgentSelectiveScope`) as fully specified outputs `scopeCommitment` in the public signals (§2, table). The default deployment produces cross-session correlators. The Scope Indistinguishability game (§4 SI) assumes the RS does not know `credentialCommitment` — but §7's RS *does* verify `agentMerkleRoot` against the on-chain tree, and the tree is public. Any RS that knows the leaf set of the Merkle tree (which is the point of the public tree) can enumerate `credentialCommitment` candidates and check `Poseidon2(candidateBitmask, credentialCommitment) == scopeCommitment` with at most 2^64 trials — feasible for the 8-bit bitmasks in §7's concrete example (`0b00010111` is 256 candidates if the RS guesses the model hash). SPIFFE avoids all of this by rotating credentials aggressively; the construction has no rotation protocol.

**In-threat-model?** Partially. The threat (colluding RSes) is in scope but the mitigation is underspecified. The construction must either (a) formally specify `AgentSelectiveScopeMinimal`, make it the default, and specify what delegation chain-linking is lost, or (b) introduce a per-session randomization of `credentialCommitment` (re-randomizable commitment scheme) to prevent cross-session correlation — which requires significant circuit changes. As specified, the default circuit is linkable across all sessions for the full credential lifetime.
