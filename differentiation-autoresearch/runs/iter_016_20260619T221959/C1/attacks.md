# Tier 3 Adversarial — C1 Selective scope proof

## Persona: auth0_pm

---

### Attack 1: `scopeCommitment` Is a Persistent Cross-RS Fingerprint

- **Attack:** The construction publishes `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` as a public output in every proof (§2, "Public outputs" table). Both inputs are fixed for the lifetime of a credential — `permissionBitmask` never changes and `credentialCommitment` is enrollment-time. So `scopeCommitment` is a constant across all proofs from the same credential, regardless of session.

  Any two RSes that compare their received proof transcripts can trivially link "same agent" by matching `scopeCommitment` values — no on-chain correlation needed, no AS involvement, just a dictionary lookup. The construction's §7 claim that cross-RS linkability "requires on-chain correlation, which reveals only that *some* agent accessed both — not which agent" is false: the public output alone identifies which agent.

- **Why it works:** The SCOPE-HIDE game in §3 (Game 2) analyzes single-proof indistinguishability — can A distinguish B₀ from B₁ from one proof? It does not analyze multi-proof linkability across sessions or RSes. The reduction sketch in §4 is silent on this. The ZK proof hides `permissionBitmask`, but a fixed `scopeCommitment` re-identifies the agent across sessions more efficiently than any OAuth `client_id` would.

  The fix (include `sessionNonce` in `scopeCommitment`) breaks the delegation chain seeding claimed in §5 ("Delegation-compatible output" row), where `scopeCommitment` is used as a "delegation chain seed" across proofs. You can't have a per-session commitment serve as a stable chain anchor.

- **In-threat-model?** **No.** Construction must address this. The privacy claim in §7 (multi-RS privacy) is contradicted by its own public output layout.

---

### Attack 2: Revocation Latency Is Structurally Weaker Than RFC 7662 — and Unacceptable for Regulated Use

- **Attack:** RFC 7662 revocation is instant: AS flips `active: false` and the token is dead on the next introspection call, typically within seconds. The Bolyra construction's revocation path is: remove the agent leaf → publish new Merkle root → wait for the 30-root history buffer to fully roll over before the old credential stops working (§2: "agentMerkleRoot ∈ on-chain root history buffer (last 30 roots)").

  The construction nowhere specifies root update cadence. If roots are published on new enrollments or weekly, a revoked agent may remain valid for days to weeks. The §7 "NCUA examiner can verify on-chain" framing papers over the fact that between a compromise event and full revocation, the agent continues to generate valid proofs.

- **Why it works:** For credit unions specifically, NCUA guidance and BSA/AML obligations require immediate credential invalidation when an agent is suspected of unauthorized access. A 30-root buffer without a defined flush schedule is not a revocation mechanism — it is a grace period that regulators will not accept. The threat model (§3) explicitly does not cover "timely revocation under regulatory constraint." The adversarial-AS resilience argument (Axis 3, §8) is irrelevant here: the AS is not the problem — the enrollment contract's state lag is.

  WorkOS and Auth0 offer token revocation lists, introspection caching controls, and short-lived token issuance policies that credit union compliance teams already understand and that regulators have reviewed.

- **In-threat-model?** **No.** The construction's §7 credit union scenario demands instant revocation; the 30-root buffer makes that impossible without adding a separate emergency invalidation mechanism the construction does not define.

---

### Attack 3: Proving Latency and Binary Deployment Dependency Destroy the "No AS Roundtrip" Value Claim

- **Attack:** The construction claims "< 0.5s" proving time but buries the asterisk: that requires the native `rapidsnark_prover` binary (§6, §CLAUDE.md). The browser/Node fallback is "< 5s." For credit union call-center agents, insurance workflow agents, or any edge-deployed agent, the Node path is the reality. A local OAuth AS roundtrip is 5–20ms on the same network. The ZK proof generation penalty is 250–1000x.

  The construction justifies this by claiming the offline path eliminates AS dependency. But "no AS roundtrip" is only valuable if the AS roundtrip is the bottleneck or a failure mode. In the credit union scenario of §7, the credit union *already operates* its own AS (typically Okta or Azure AD). The AS is not a remote third party — it is on their internal network with sub-10ms latency. The construction trades a 10ms reliable call for a 5s local computation, and calls it a feature.

  Deploying rapidsnark adds: native binary compilation per platform (ARM vs. x86-64), versioning and security patching lifecycle, and a fail-open question — what does the agent do when the prover binary is absent or crashes?

- **Why it works:** The construction never benchmarks against the actual alternative (local AS on the same network). It benchmarks against the strawman of an AS with high network latency. Any enterprise deploying Bolyra alongside an existing IdP will compare 5s ZK vs. 10ms introspection, not 5s ZK vs. "AS might be offline." The latency claim is not false — it is framed against a scenario that doesn't match the credit union deployment described in §7.

- **In-threat-model?** **No.** The construction needs a latency analysis against a co-located AS, not a remote one, to validate the "no AS roundtrip" tradeoff claim.

---

### Attack 4: No Construction Survives the Vendor Risk Committee

- **Attack:** The §7 scenario names Navy Federal Credit Union (13M members) as the target buyer. Navy Federal's vendor risk program requires SOC 2 Type II, penetration test reports, cyber liability insurance with coverage minimums, SLAs with financial penalties, and a business continuity plan. NCUA Letter 07-CU-13 and FFIEC guidance on third-party due diligence codify these requirements. None of them are satisfiable by a solo founder.

  WorkOS has SOC 2 Type II. Auth0 has it. Stytch has it. None of them require the buyer to understand Groth16 or Poseidon hash collision resistance to pass vendor review. The security argument in §4 is addressed to cryptographers; the procurement questionnaire is addressed to a vendor risk analyst who will write "no SOC 2" and escalate to legal.

  The Axis 5 claim (§8) — "no cryptographic binding to runtime agent identity" in the baseline — is real. But it doesn't matter to the buyer if the vendor can't indemnify them. A cryptographically weaker solution with SOC 2 and a $10M E&O policy wins every credit union procurement over a cryptographically superior solution from a solo founder with none of those.

- **Why it works:** This attack is not addressable by improving the construction. The five axes in §8 can all be valid and the sale still fails at procurement. The construction's competitive comparison (§8, "structural vs. configurational gap") is entirely technical and does not engage with the buyer's actual decision process. Calling it a "structural" gap implies the incumbents cannot close it; but procurement doesn't buy structures, it buys vendors.

- **In-threat-model?** **No.** The construction should acknowledge that the cryptographic moat requires a viable vendor wrapper (SOC 2, insurance, support SLA) before any of §8's axes translate into buyer decisions. Without this, the differentiation exists only in academic comparison.


## Persona: cryptographer

Applied cryptographer, skeptical reader. I am going to take the construction at face value and try to win the games it defines — or show the games are too weak to mean what the authors claim.

---

### Attack 1: `scopeCommitment` is a permanent cross-session pseudonym — SCOPE-HIDE is trivially broken

**Attack:**

The public output `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` appears in every proof the agent ever produces. Both `permissionBitmask` and `credentialCommitment` are fixed for the lifetime of the credential. Therefore `scopeCommitment` is **deterministic and constant across all sessions and all resource servers.** Any two RSes (or any passive network observer) that collect proofs can link them by matching `scopeCommitment` values.

**Why it works against the construction:**

The SCOPE-HIDE game (§3, Game 2) is defined for a **single proof transcript**. The adversary A is given `(π, all public signals)` and must guess which bitmask was used. The construction's reduction argues indistinguishability via the ZK simulator. That argument is correct for a single proof — but the game is too weak.

Extend to the multi-session variant: the adversary requests proofs for the same credential with two different RSes (or the same RS at two time points). Both proofs share the same `scopeCommitment`. The adversary wins the linkability game with advantage 1, **without breaking ZK or Poseidon**. The simulation produces identical `scopeCommitment` values regardless of `b`, so the adversary's distinguisher is simply `sc₀ == sc₁`.

Furthermore, the construction's own §7 asserts "neither RS learns the other's required permissions" and that cross-RS linkability requires "on-chain correlation, which reveals only that *some agent* accessed both." This is false: `scopeCommitment` is off-chain, revealed directly in proof public outputs, and is a stable per-credential fingerprint.

**In-threat-model?**

No. The SCOPE-HIDE game as defined does not capture session unlinkability. The construction needs to either:
- Randomize `scopeCommitment` per session (e.g., `Poseidon3(permissionBitmask, credentialCommitment, sessionNonce)`), losing the delegation-chain-seed property claimed in §5; or
- Explicitly disclaim cross-session unlinkability and remove the misleading §7 cross-RS privacy claim.

The fix has a cost: if `scopeCommitment` is session-nonce-dependent, it can no longer serve as a stable "delegation chain seed" (§5, Delegation circuit chain linking row).

---

### Attack 2: SCOPE-HIDE brute-force distinguisher via small effective permission space

**Attack:**

The adversary knows the agent's public enrollment parameters: `modelHash, operatorPubkeyAx, operatorPubkeyAy, expiryTimestamp` (these are either revealed at enrollment or derivable from the on-chain Merkle insertion transaction). Given the observed `scopeCommitment` in the proof, the adversary enumerates all candidate bitmasks:

```
for b in CandidateSpace:
    cc_b = Poseidon5(modelHash, opAx, opAy, b, expiry)
    sc_b = Poseidon2(b, cc_b)
    if sc_b == observed_scopeCommitment: return b
```

**Why it works against the construction:**

The SCOPE-HIDE reduction (§4) argues that `scopeCommitment` is a Poseidon one-way commitment under A2 (Poseidon collision resistance). But one-wayness is not the same as hiding against an adversary who knows all other inputs. One-wayness means you cannot invert `f(x)` without knowing `x`; it says nothing when `x` is drawn from a small known set.

The permissions table in the Bolyra spec defines **8 named bits (bits 0–7)**. The cumulative implication constraints (bits 4→3→2) eliminate invalid combinations. The total valid bitmask space is at most 2^8 = 256 entries, and cumulative closure reduces this further. An adversary runs 256 Poseidon evaluations — sub-millisecond — and recovers `permissionBitmask` exactly.

Even without the small-space shortcut: the SCOPE-HIDE game (§3) has A choose B₀, B₁ before seeing the proof. If A chooses B₀ = `0b00001111` and B₁ = `0b00000101`, the two produce different `scopeCommitment` values (with overwhelming probability by A2). A computes both candidate `scopeCommitment` values offline and matches the observed output. The game is won with advantage ~1 using 2 Poseidon evaluations, breaking the privacy claim without any cryptographic reduction.

**Why the reduction is wrong:**

The reduction in §4 claims: "since `permissionBitmask` is a private input and does not appear in any public output… the adversary's view is simulatable for any satisfying witness." This is correct for the ZK property of the proof itself — the proof bits reveal nothing. But `scopeCommitment` is a public **output** that is a deterministic function of `permissionBitmask`. The simulator produces the same `scopeCommitment` for different bitmasks only if the commitment is binding against itself — but binding and hiding are dual properties and the construction only invokes collision resistance (binding), not pseudorandomness (hiding against known-input brute force).

**In-threat-model?**

No. The SCOPE-HIDE game must explicitly bound the adversary's ability to enumerate preimages. In the practical deployment (§7), the effective permission space is small enough that SCOPE-HIDE provides no meaningful protection. The construction must either use a blinded commitment (adding a fresh random salt to `scopeCommitment`) or restrict the SCOPE-HIDE claim to adversaries who do not know `(modelHash, opAx, opAy, expiry)`.

---

### Attack 3: Public Merkle leaves enable nullifier precomputation — agent deanonymization

**Attack:**

The on-chain agent Merkle tree stores `credentialCommitment` values as public leaves. Enrollment is an on-chain transaction (§7: "the compliance officer enrolls an AI agent… into the on-chain agent Merkle tree"). Therefore, every `credentialCommitment_i` for every enrolled agent `i` is public.

Given a `sessionNonce` emitted by an RS, any party — including a passive RS or a colluding AS — can precompute:

```
for each credentialCommitment_i in on-chain tree:
    nullifier_i = Poseidon2(credentialCommitment_i, sessionNonce)
```

When the agent submits `nullifierHash`, the adversary matches it against the precomputed table and identifies the agent exactly, recovering `credentialCommitment` and therefore the Merkle position.

**Why it works against the construction:**

The construction claims "The RS learns nothing else about… Merkle position." But Merkle position is directly recoverable: once `credentialCommitment` is identified via nullifier precomputation, its position in the tree is determined by the on-chain insertion order. The `scopeCommitment` attack (Attack 1) further confirms identity. Together: the RS learns model hash, operator key, permission bitmask (via Attack 2), and Merkle position — precisely the things claimed to be hidden.

The AS-BLIND game (§3, Game 3) asks whether A_AS can cause the RS to accept or reject a proof — it does not define a game over agent identity leakage. The "adversary sees" clause lists "all public signals" but the threat model never asserts that the agent's identity is hidden from the RS. The §7 privacy claim ("RS learns nothing about… model hash, operator identity") is asserted in prose without a corresponding game.

The Semaphore v4 design addresses this by not publishing identity commitments publicly during registration — they are added to the tree, but which commitment belongs to whom is not on-chain. This construction enrolls agent credentials with operator-signed structured data, making the leaves attributable.

**In-threat-model?**

No (claimed property not formalized, claimed protection is absent). There is no Game that captures "RS cannot identify the agent." If the authors intend agent pseudonymity, they need to define the game and either (a) make Merkle leaves unlinkable to agents (by hiding enrollment metadata) or (b) use a session-specific nullifier domain that does not reveal the leaf. The current construction provides **traceability**, not pseudonymity, when Merkle leaves are public.

---

### Attack 4: Trusted setup subversion breaks adversarial-AS resilience — the threat model is circular

**Attack:**

The construction's signature property — "adversarial-AS resilient" (Axis 3, §8) — is premised on: "the proof's validity depends only on the on-chain Merkle root and the circuit constraints." The named assumption A1 invokes "knowledge soundness of Groth16 ε_ks ≈ 2^{-128} (generic group model)."

Groth16 knowledge soundness holds only under an **honest trusted setup**. The AgentPolicy and Delegation circuits use a project-specific `pot16.ptau` (per CLAUDE.md: "Project-specific keys (Agent/Delegation) use `pot16.ptau`"). The party or parties who conducted the `pot16.ptau` ceremony hold toxic waste `τ`. Whoever holds `τ` can compute `α, β, γ, δ` for any circuit and forge arbitrary proofs — `Adv[SCOPE-FORGE] = 1`, not `ε_ks`.

Now observe: the threat model names the AS as the primary adversary (Game AS-BLIND). But if the AS operator also participated in, or compromised, the `pot16.ptau` ceremony (or ran it unilaterally, which a solo-founder project often does), then:

1. The AS holds `τ`.
2. The AS can forge a Groth16 proof for any `(requiredScopeMask, agentMerkleRoot)` pair.
3. The RS verifies the proof and accepts — the pairing check passes by construction of the forged proof.
4. The AS has "won" AS-BLIND with advantage 1, **without breaking Poseidon or ECDLP**.

The threat model explicitly puts the AS in the adversary's hands but never excludes it from the trusted setup. The two threat surfaces — "adversary controls the AS" and "adversary did not subvert the setup" — are in tension, and the construction does not resolve this tension.

**The PLONK escape hatch is insufficient as stated:**

§2 notes PLONK as an alternative ("universal setup, no per-circuit ceremony"). PLONK uses a universal SRS that is circuit-agnostic, which reduces the per-circuit ceremony risk. But the construction presents PLONK as optional ("Groth16 required, PLONK optional" per CLAUDE.md) and does not bound the adversary's advantage under PLONK in any of the three games. The security argument (§4) references only Groth16. If the adversary-AS controls the Groth16 setup, PLONK is the only defense — but it is not the default and is not argued in the reduction.

**In-threat-model?**

No. The threat model as defined cannot handle a setup-compromising AS adversary. The construction must either:
- Add "honest trusted setup" as an explicit named assumption (A5) and bound the scheme's security claim to that assumption, acknowledging the attack surface;
- Mandate PLONK (universal SRS, no per-circuit toxic waste) and provide security arguments against the Game 1–3 adversaries under PLONK's specific assumptions; or
- Use a publicly verifiable multi-party ceremony for `pot16.ptau` with enough independent participants that a compromised AS cannot alone hold `τ`.

Until this is resolved, "adversarial-AS resilience" is marketing. The adversary that controls the AS in Game AS-BLIND is strictly weaker than a real-world adversary who also had a seat at the trusted setup ceremony.


## Persona: cu_ciso

### Attack 1: Audit Trail Opacity — The ZK Property Is Your Liability, Not Mine

- **Attack**: Section 7 says "The NCUA examiner can verify on-chain that all enrolled agents have operator-signed credentials without accessing any agent's full permission set." I will hand this sentence to my examiner and watch them stare at it. NCUA Part 748 Appendix B and the FFIEC CAT Domain 3 (Cyber Incident Management) require that I produce a **human-readable audit trail** linking each action to an authorized principal. When my wire-transfer AI agent (RS₃ in §7) initiates a $250K transfer that turns out to be fraud, I need to hand the examiner: *who* authorized it, *what* permission was invoked, *when*, and *via what chain of custody*. What I get from this construction is a `nullifierHash = Poseidon2(credentialCommitment, sessionNonce)` and an `agentMerkleRoot`. Neither is readable by my Tier 1 ops team, my incident response retainer, or my NCUA field examiner. The zero-knowledge property that Section 8 Axis 2 celebrates — the RS learns nothing about the permission bitmask beyond the predicate result — directly contradicts GLBA Safeguards Rule 16 CFR §314.4(h)(2), which requires monitoring and logging of access to customer information systems "sufficient to detect actual or attempted attacks." I cannot log what I cannot see. The construction optimizes for privacy precisely where regulators demand transparency.

- **Why it works**: The construction's threat model (§3) never names a regulator or an auditor as a principal. It models the AS as adversarial and the RS as a verifier, but it does not model the NCUA examiner who will arrive with a questionnaire asking for event logs, not pairing checks. Section 7 asserts NCUA benefits without citing a single Part 748 control number or FFIEC CAT maturity indicator.

- **In-threat-model?** No — the construction must address how `nullifierHash` + `agentMerkleRoot` maps to a FFIEC-CAT-compliant audit log that a Tier 1 operator can read and an examiner can accept as evidence.

---

### Attack 2: `scopeCommitment` Is a Persistent Agent Fingerprint — Cross-RS Linkability Is Trivially Off-Chain

- **Attack**: Section 7 claims: "cross-RS linkability requires on-chain correlation, which reveals only that *some* agent accessed both — not *which* agent." This is wrong. The public output `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` (§2, Table: Public outputs) is **deterministic and session-independent**. `permissionBitmask` is fixed at enrollment; `credentialCommitment = Poseidon5(modelHash, opAx, opAy, permissionBitmask, expiry)` is also fixed at enrollment. Therefore, every proof generated by the same agent with the same credential produces the **identical `scopeCommitment`**, regardless of `sessionNonce` or `requiredScopeMask`. RS₁ and RS₃ from §7 can share their received `scopeCommitment` values over a side channel and immediately determine that the same credential holder touched both — no blockchain query required. For a credit union, this means the member's AI agent that does account inquiry (RS₁) and the one that initiates wire transfers (RS₃) are trivially linked by any colluding RS pair or by a network observer who sees two proof submissions with matching `scopeCommitment`. The privacy guarantee stated in §7 is false under the construction's own signal layout.

- **Why it works**: The SCOPE-HIDE game (§3, Game 2) proves that the *bitmask* is hidden, but it never games the linkability of the proof across sessions. The `nullifierHash` correctly binds the `sessionNonce`, preventing replay. But `scopeCommitment` has no session component — it was designed (§5, "delegation chain seed") to be stable for the Delegation circuit, and that stability is exactly what creates the fingerprint.

- **In-threat-model?** No — this is a gap in the construction. The fix requires binding `scopeCommitment` to `sessionNonce` (e.g., `Poseidon3(permissionBitmask, credentialCommitment, sessionNonce)`), but that breaks the delegation chain linking described in §5. The construction must resolve this tension explicitly.

---

### Attack 3: Operator Key Custody Has No Answer — This Fails My Vendor Management Policy on Day One

- **Attack**: The entire construction's security reduces to the EdDSA private key at `operatorPubkeyAx`/`operatorPubkeyAy` (§2, Private inputs). Section 3 defines the adversary as controlling "up to N-1 agents' secrets" but conspicuously leaves the **operator private key** out of the corruption model. In the §7 credit union scenario, the compliance officer "enrolls an AI agent" using the operator's EdDSA key. My questions: Where does that key live? Is it in an HSM? Which HSM vendor? What's the FIPS 140-2 Level? What's the key rotation schedule? What happens if the operator private key is exfiltrated — can I revoke all enrolled agents, or are their `credentialCommitment` values permanently valid Merkle leaves until the tree is rebuilt? The construction says the AS "cannot retroactively alter what the agent can prove" (§8, Axis 3) as a feature. That same property means a compromised operator key allows silent enrollment of malicious agents that the construction cannot revoke. My NCUA vendor management policy (Part 748 Appendix A) requires documented key management procedures for any third-party cryptographic system. The construction provides none.

- **Why it works**: Section 8 Axis 3 correctly identifies AS-blindness as a strength against a compromised AS. But it creates an unaddressed single point of failure: the operator EdDSA key. If that key leaks, the attacker can enroll arbitrary agents with arbitrary `permissionBitmask` values (including `FINANCIAL_UNLIMITED`, bit 4) into the on-chain Merkle tree. Nothing in the protocol detects this enrollment — the `agentMerkleRoot` simply updates to include the new leaf, and the root history buffer (30 entries) will soon contain only roots that include the malicious agent.

- **In-threat-model?** No — the construction must specify key custody requirements (HSM class, key rotation cadence, compromise recovery procedure) and a revocation mechanism that does not rely on the AS. Without this, the construction cannot pass a GLBA Safeguards Rule risk assessment or an NCUA examination.

---

### Attack 4: Availability SLA — The Root History Buffer Is a 60-Second Cliff

- **Attack**: Section 2 (Verification protocol, step 3b) requires that `agentMerkleRoot` be within the on-chain root history buffer of the **last 30 roots**. Section 5 confirms this is a "30-entry circular root history buffer." Base Sepolia (§5, "Deploy target chain") produces blocks approximately every 2 seconds. That means the root history window is **roughly 60 seconds of on-chain activity** before a root ages out. If my agent is mid-session and the Merkle tree contract receives 30 new root updates — from any other credit union, any other operator, any other enrollment event — my agent's root is evicted and its proof fails verification. For a wire transfer that takes 90 seconds to settle, this is not an edge case. My core processor (Fiserv/Jack Henry/Symitar) has a contractual SLA of 99.95% with sub-second response. Any dependency on an EVM chain for real-time authorization is a reliability regression. RFC 7662 introspection with a local JWT cache has no such cliff. The construction does not specify what the RS does when `agentMerkleRoot ∉ root history buffer` — fail open, fail closed, or retry? Each option has a different risk profile, and none is acceptable without a documented fallback that passes FFIEC Business Continuity Planning review.

- **Why it works**: The construction's §7 scenario describes RS₂ verifying a loan pre-qualification proof, but does not specify the time budget, the fallback path, or the SLA guarantee. "Less than 5s proving time on commodity hardware" (§6) addresses agent-side latency, not on-chain availability. A single Ethereum RPC node outage or gas spike that delays the root update transaction breaks every in-flight agent session simultaneously.

- **In-threat-model?** No — the construction must specify (a) the minimum root update frequency and window size in wall-clock terms, (b) the RS's behavior when root lookup fails, and (c) the availability guarantee of the on-chain registry contract. Without this, the construction cannot pass FFIEC Business Continuity Planning or Operational Resilience review.


## Persona: rfc7662_advocate

### Attack 1: `scopeCommitment` is a static cross-RS fingerprint — worse than PPID

**Attack:**
Section 2 defines `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` as a **public output**. Both inputs are fixed for the lifetime of a credential (`credentialCommitment` is the Merkle leaf; `permissionBitmask` is baked in). Therefore every proof this agent ever generates — to RS₁, RS₂, RS₃, across all sessions, across all `sessionNonce` values — produces the **identical `scopeCommitment`**.

Any two RSes that compare notes (or any passive observer watching the chain or the agent's TLS-visible proof submissions) can trivially correlate all of an agent's activity across all resource servers. The `nullifierHash` varies per session (good), but `scopeCommitment` is a permanent, public, cryptographic fingerprint of the agent.

**Why it works:**
Section 7's "Multi-RS privacy" claim states "neither RS learns the other's required permissions" and "cross-RS linkability requires on-chain correlation, which reveals only that some agent accessed both — not which agent." This is wrong on both counts. The `scopeCommitment` in the proof transcript — visible to both RSes, not requiring any on-chain lookup — tells them it's the *same agent* with certainty. The on-chain Merkle root narrows it further to a specific enrolled leaf.

Compare this to OIDC pairwise identifiers (PPID, `sector_identifier_uri`): the AS issues a different opaque `sub` to each RS, so RSes cannot correlate without AS cooperation. RFC 9449 DPoP + per-RS audience binding adds sender-constraint on top. The baseline baseline *already solves* cross-RS correlation at the protocol level. The construction *reintroduces* it via `scopeCommitment`.

**In-threat-model?** Yes — and it's unaddressed. Construction must either (a) randomize `scopeCommitment` per session by mixing in `sessionNonce`, accepting that `scopeCommitment` is no longer a stable delegation chain seed, or (b) acknowledge the cross-RS linkability and remove the Section 7 privacy claim for `scopeCommitment`. The delegation chain linking use case (Section 5 "Delegation-compatible output") and cross-RS unlinkability are in direct tension. The paper doesn't name this tension, let alone resolve it.

---

### Attack 2: Public implication closure leaks bits beyond the predicate — SCOPE-HIDE is broken

**Attack:**
The cumulative-bit constraints are circuit-enforced (Section 2, Gadget 4) and the constraint semantics are public knowledge from the spec. When the RS presents `requiredScopeMask = 0b00001000` (bit 3, `FINANCIAL_MEDIUM`) and the proof verifies, the RS immediately infers:

- Bit 2 (`FINANCIAL_SMALL`) is **also set** — because the circuit enforces `permBits[3] * (1 - permBits[2]) === 0`.
- Bit 4 (`FINANCIAL_UNLIMITED`) is **either 0 or, if set, also forces bits 2+3** — so if the agent later presents a proof for a mask requiring bit 4, the RS now knows bit 3 was set in the prior session.

The RS learns permission bits it did not ask about — specifically, all bits implied by the satisfied mask under the public implication rules. A sequence of proof interactions with different `requiredScopeMask` values progressively leaks the full permission bitmask via deduction.

**Why it works:**
The SCOPE-HIDE game (Section 3) defines the adversary as choosing two bitmasks `B₀, B₁` both satisfying the predicate `B & M = M`. But after observing the proof, the RS applies the public implication rules and rules out `B₀` values that would violate them. If `B₀` has bit 3 set but bit 2 cleared, the circuit would have rejected it — so the RS eliminates that from the hypothesis space. After enough queries with varied masks, the implication closure forces a unique solution.

The security argument in Section 4 reduces SCOPE-HIDE to ZK of Groth16 + Poseidon PRF. Both reductions are correct for a *single* proof in isolation. The argument does not account for the *composed* information leakage across multiple proofs from the same credential to the same or different RSes. Zero-knowledge for a single statement does not compose to zero-knowledge across adaptive multi-query sessions when the constraint structure itself is public.

**In-threat-model?** Yes — the Section 3 threat model specifies "A receives all public signals from prior proofs" but the SCOPE-HIDE game is defined as single-shot. The adversary in the multi-query setting wins with non-negligible advantage. Construction must either restrict the RS to a single `requiredScopeMask` per credential lifetime (operationally crippling) or add a gadget that hides which implication constraints fired, e.g., by committing to a re-randomized permission vector.

---

### Attack 3: RFC 8693 bulk pre-issuance + offline JWT kills the "zero AS roundtrips" differentiator

**Attack:**
The construction's AS-blindness argument (Section 8, Axis 1) conflates two distinct properties: *AS-free at request time* and *AS-adversarial resilience*. Axis 1 addresses only the former, then slides to the latter without acknowledging the gap.

The baseline can achieve zero AS roundtrips at request time via a one-time pre-issuance step:

1. At agent enrollment, the operator requests **N scoped tokens via RFC 8693 Token Exchange**, one per known RS, each with RFC 8707 `resource` audience binding and the minimal `scope` for that RS. Each token is a signed JWT (jwt-introspection-response format) that the RS verifies offline.
2. RFC 9449 DPoP binds each token to the agent's ephemeral proof-of-possession key, preventing replay by any other party.
3. The RS caches the AS public key (JWKS endpoint, fetched once). All subsequent agent requests are verified offline without any AS contact.

From the moment of first use: zero AS roundtrips. The DPoP-bound, audience-scoped JWT is presented; the RS verifies the signature offline. This is *structurally identical* to the construction's "no AS in the verification path" at request time.

**Why the adversarial-AS argument is the real load-bearing claim — and why the construction undersells it:**
The genuine non-replicable property is not "zero roundtrips" but "AS cannot retroactively lie." In the baseline, if the AS is compromised *after* token issuance, it could issue revocation claims, or previously-issued tokens could have been forged from the start. In the construction, the on-chain Merkle root is immutable once the block is finalized — a compromised AS that didn't control the enrollment transaction cannot alter the proof basis. But Section 8 buries this under "Axis 3" and does not distinguish *pre-issuance compromise* from *post-issuance compromise*. A compromised AS that controlled enrollment (plausible if the AS also operates the Merkle tree contract) has identical power in both systems.

**In-threat-model?** Partially. The "zero roundtrips" framing in Axis 1 is not a clean win over the baseline and should be dropped or qualified. The genuine claim — "on-chain enrollment root cannot be retroactively altered by a post-compromise AS" — is real but requires the construction to specify who controls the Merkle tree write access and prove that AS compromise after enrollment cannot inflate permissions. Neither is addressed in the current spec.

---

### Attack 4: BBS+ per-bit attribute model satisfies the bitwise predicate — Axis 2 is overclaimed

**Attack:**
Section 8, Axis 2 states: "bitwise AND over a 64-bit field with cascading implication constraints has no BBS+ extension. The RS would need to pre-enumerate all valid permission combinations and request BBS+ equality proofs for each — exponential in bitmask width."

This is incorrect. Issue a BBS+ credential with 64 scalar attributes, one per bit (`bit_0 ∈ {0,1}, bit_1 ∈ {0,1}, ..., bit_63 ∈ {0,1}`). Implication constraints are enforced by the issuer (they simply refuse to issue credentials violating cumulative rules — same as the circuit enforcement, but at issuance time, which is the same moment the circuit's private inputs are set).

At verification time, the RS specifies `requiredScopeMask` as a set of bit indices `{i : mask[i] = 1}`. The agent presents a BBS+ PoK that proves `bit_i = 1` for each `i` in the RS-specified set, while all other bits remain hidden. The PoK protocol is verifier-driven: the RS sends the set of indices to reveal/prove at verification time, before the agent responds — exactly matching "runtime-adaptive" semantics. Proof size is O(|required bits|) — for the credit union scenario where `requiredScopeMask` has 2-3 bits set, this is 2-3 disclosed attributes, not 64.

**Why constant-size is not load-bearing:**
The construction's 192-byte Groth16 proof vs. BBS+ O(|required|) PoK matters only if `|required|` is large. In the concrete scenario (Section 7), RS₂ requires 2 bits, RS₃ requires 3 bits. BBS+ proof sizes for 2-3 disclosed attributes over BLS12-381 are ~300-500 bytes — comparable to PLONK's 768 bytes. The "constant-size regardless of bitmask width" property is real but the differential is negligible in all practical deployments. "2^64 permission space" does not mean "2^64 bits are disclosed" — it means a large domain from which a small mask is sampled.

**In-threat-model?** Yes — Axis 2 as written is refuted. The valid residual claim is narrower: BBS+ requires issuer enforcement of implication constraints (off-chain policy), while the circuit enforces them cryptographically (any credential violating cumulative rules is unprovable, regardless of what the issuer signed). That is a genuine hardness advantage — but it belongs in Section 8 as "Axis 2b: cryptographic vs. policy enforcement of implication closure," not as "bitwise predicates are inexpressible in BBS+."


## Persona: spiffe_engineer

### Attack 1: Adaptive Chosen-Mask Bit Recovery

- **Attack**: The SCOPE-HIDE game (§3, Game 2) is a *one-shot* game: the adversary selects M *before* the credential is issued, and both bitmasks must satisfy M. But in the real deployment (§7), an adversarial RS controls the `requiredScopeMask` signal at *every* session. An adversarial RS runs 64 sequential probes: set `requiredScopeMask = 1 << i` for i ∈ [0, 63]. The agent either produces a valid proof (bit i is set) or fails to produce one (bit i is unset). The accept/reject side-channel is not a proof-system leak — it is an *application-level* observable. 64 sessions, bitmask fully recovered.

- **Why it works**: The security argument in §4 reduces to the one-shot game, which is strictly weaker than the real multi-session, adversary-controlled-mask setting. The circuit enforces zero knowledge *given* a fixed mask; it says nothing about what an adaptive sequence of masks reveals. The RS's `sessionNonce` freshness requirement is satisfied on every probe. Nothing in the threat model (§3) forbids an adversarial RS from doing this — in fact §3 explicitly grants A control of the RS.

- **In-threat-model?** **Yes — and the construction fails to address it.** This is a gap, not a survivable attack. The SCOPE-HIDE game must be upgraded to an *adaptive multi-query* game where A issues polynomially many `requiredScopeMask` queries before guessing. Under that game, the "zero knowledge" claim collapses unless the protocol adds noise (e.g., rate-limiting at the protocol layer, one-time credential binding per RS), which is not specified.

---

### Attack 2: `scopeCommitment` Is a Stable, Cross-RS Correlation Handle

- **Attack**: The `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` is a *public output* (§2, public outputs table). Both inputs are constants for the lifetime of a credential — `credentialCommitment` is Poseidon5 of the enrollment parameters (fixed), and `permissionBitmask` is fixed at enrollment. Therefore `scopeCommitment` is **identical across every proof the agent generates for any RS**, for the credential's entire validity window.

  RS₁ and RS₂ (§7) both receive the same `scopeCommitment`. They can trivially correlate all proofs from the same agent by joining on this value — no on-chain lookup required. The construction claims (§7): *"cross-RS linkability requires on-chain correlation, which reveals only that some agent accessed both"*. This is false — the `scopeCommitment` is a direct, off-chain correlation handle present in the proof's public signals.

- **Why it works**: SPIFFE addresses this with short-lived SVIDs (TTL typically 1 hour) that rotate, breaking long-term correlation. The Bolyra construction anchors `scopeCommitment` to the credential commitment, which is stable for the full `expiryTimestamp` window (unstated duration). If the bitmask or credential hash never changes, `scopeCommitment` is permanent. The construction provides no rotation mechanism for this value.

- **In-threat-model?** **Yes — construction must address it.** §3 grants A network observation of all public signals. The multi-RS privacy guarantee stated in §7 is incorrect as written. Fix candidates: session-scoping `scopeCommitment` by including `sessionNonce` (i.e., `Poseidon3(permissionBitmask, credentialCommitment, sessionNonce)`), or dropping it as a public output entirely and relying only on `nullifierHash` for replay prevention. Either changes the public signal layout.

---

### Attack 3: The Trust Anchor Shifts, Not Disappears — On-Chain Operator Is the New AS

- **Attack**: §8 Axis 1 argues the construction is "AS-blind" because *the AS has no role in proof generation or verification.* This is true of the OAuth AS. But the construction substitutes a different authority: whoever controls writes to the on-chain Merkle tree contract. The credit union's *compliance officer* enrolls credentials (§7). That enrollment action is the moment of authority delegation, and it is controlled by the contract owner (operator). An adversarial operator can:
  - Refuse to enroll a credential (denial-of-service equivalent to AS refusing to issue a token).
  - Enroll a credential with a false `permissionBitmask` (forged enrollment).
  - Rotate the Merkle root to exclude a valid credential (retroactive revocation).

  From a SPIFFE perspective: SPIRE's node attestation (AWS IID, TPM, k8s service account) provides a *hardware-rooted* trust anchor. The on-chain Merkle root is rooted in a smart contract that has an owner — this is architecturally equivalent to an AS with immutable storage, not elimination of a central trust authority.

- **Why it fails partially**: The construction does *improve* on RFC 7662 in one specific way — the operator cannot silently alter a *committed* credential after enrollment without changing the Merkle root (and the 30-root history buffer would surface this). So retroactive forgery is detectable. But the enrollment-time trust assumption is not addressed.

- **In-threat-model?** **Partially no — construction must address the enrollment trust model.** The threat model (§3) does not define the adversary capabilities for the enrollment ceremony itself. The phrase "trusted smart contract model" appears without defining what trust is granted to the contract owner. This is not a cryptographic gap but an omission in the threat model that practitioners will flag immediately: *who guards the Merkle tree enrollments?*

---

### Attack 4: SPIFFE + ZK Attestor Plugin Achieves AS-Blindness Without a New Protocol

- **Attack**: The §8 differentiator "AS-blind presentation is structurally impossible" in RFC 7662 is accurate, but the claim that Bolyra is the necessary solution is not. SPIRE has a pluggable attestation architecture: node attestors and workload attestors are loaded as gRPC plugins. A ZK attestor plugin would work as follows:
  1. At SPIRE server initialization, the operator enrolls agent credential commitments (model hash, operator key, permission bitmask) into a local database — equivalent to the Bolyra Merkle tree, without the on-chain component.
  2. The workload attestor generates a ZK proof of bitmask predicate satisfaction locally (identical circuit to AgentPolicy).
  3. The SPIRE agent verifies the proof locally and issues an X.509 SVID whose SubjectAlternativeName encodes `requiredScopeMask` and `nullifierHash` as URI SANs. No SPIRE *server* roundtrip is needed after initial SVID issuance.
  4. mTLS with the SVID provides replay prevention (TLS session keys) and identity binding — exactly what Bolyra's `nullifierHash` and `sessionNonce` provide.

  WIMSE (draft-ietf-wimse-arch §5.3) specifies a Workload Identity Token (WIT) that is a short-lived, audience-bound JWT with proof-of-possession. Combining SPIFFE SVIDs + a WIT where the WIT's claim set is a ZK-derived scope satisfaction result covers the "AS-blind, runtime-adaptive, constant-size" properties with existing IETF-registered infrastructure.

- **Why it partially fails**: Bolyra's cumulative-bit implication closure (§2 gadget 4) is not present in SPIFFE or WIMSE. Encoding `bit 4 → bit 3 → bit 2` as circuit constraints and enforcing them cryptographically — not by AS policy table — is genuinely novel. SPIFFE policy is expressed in Rego or SPIRE policy files, which are AS-side configuration, not ZK-enforced. A compromised SPIRE server *can* issue an SVID that violates implication rules; the Bolyra circuit cannot.

  Additionally, WIMSE WIT issuance requires a Security Token Service roundtrip — it is not locally generated by the workload without a network call, which reintroduces the AS dependency Bolyra eliminates.

- **In-threat-model?** **No — the construction survives, but must sharpen its claim.** The differentiation narrative should be repositioned: the novel property is not "AS-blindness" in the abstract (achievable via SVID push delivery), but specifically the **circuit-enforced cumulative implication closure** evaluated over a private bitmask with a ZK proof. That is the property unreachable by any SPIFFE/WIMSE configuration, and it is what should be foregrounded in §8 Axis 2 rather than buried in a subordinate clause.
