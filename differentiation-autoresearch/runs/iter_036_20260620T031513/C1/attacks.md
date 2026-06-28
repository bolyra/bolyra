# Tier 3 Adversarial — C1 Selective scope proof

## Persona: auth0_pm

---

### Attack 1: The `scopeCommitment` Is a Permanent Cross-RS Correlation Handle

**Attack:**
The construction publishes `scopeCommitment = Poseidon2(permBitmask, credCommitment)` as a public output (§2, Public outputs table). Both inputs are **fixed for the lifetime of a credential** — `permBitmask` doesn't change, and `credCommitment` is deterministic from the enrollment inputs. Therefore, every presentation from the same credential — to every RS, in every session — produces **the identical `scopeCommitment`**.

Two colluding RSes (which the adversary controls per §3) exchange transcripts. They match on `scopeCommitment`. They now know: the same agent visited both services, how frequently, and at what times. They cannot extract the exact bitmask (Poseidon preimage resistance holds), but they have built a complete visit-graph for this credential.

**Why it works / why it fails against the construction:**
The SSZK game (§3) is defined over **two distinct credentials** (`C0 ≠ C1`) — it tests whether the adversary can distinguish *which credential* was used. It does **not** model a single credential presented to multiple colluding RSes. The game's simulation guarantee (`Adv_SSZK(A) ≤ Adv_ZK(A) + negl(λ)`) only holds for the single-presentation oracle it defines. The multi-RS correlation attack is entirely outside the game boundary.

`nullifierHash = Poseidon2(credCommitment, sessionNonce)` correctly randomizes per-session and prevents replay. But `scopeCommitment` has no session-specific randomization. The construction conflates "session unlinkability" (handled by `nullifierHash`) with "RS unlinkability" (not handled at all).

Fix requires `scopeCommitment = Poseidon2(permBitmask, credCommitment, sessionNonce)` — but then the RS cannot use `scopeCommitment` as a stable audit anchor, which is part of the claimed on-chain use case.

**In-threat-model?** No — the construction must address this. The SSZK game needs to be extended to the multi-RS setting, and `scopeCommitment` needs per-presentation randomization or the property it provides must be redefined.

---

### Attack 2: Revocation Is Not Instant — The 30-Root Buffer Is a Compliance Gap

**Attack:**
The RS accepts proofs if `agentMerkleRoot ∈ root history buffer (30-entry window)` (§2, Step 4a). Credential revocation means removing the leaf from the Merkle tree and publishing a new root on-chain. But the construction doesn't specify what drives root updates, and it explicitly allows 30 stale roots to remain valid.

If the agent tree is append-heavy (many enrollments) but revocation-light, old roots may persist for days or weeks. A stolen credential key can generate valid proofs against any of those 30 roots **until all 30 have been superseded**. For the NFCU scenario specifically (§7): a compromised portfolio management agent can continue executing trades against any RS that accepts historical roots.

Compare to RFC 7662: `active: false` takes effect in the next introspection call — sub-second revocation. The construction's adversarial-AS argument correctly notes the AS cannot suppress a presentation *already verified*, but it ignores that the AS's revocation speed is a feature, not a bug. Enterprises don't want adversarial-AS; they want instant kill-switches.

**Why it works / why it fails against the construction:**
§4 ("Why the adversarial-AS model holds") argues the AS "cannot retroactively revoke a presentation already verified on-chain." That's true but irrelevant — procurement doesn't care about past presentations, it cares about stopping future ones immediately. The construction provides no mechanism for emergency revocation faster than the rate at which 30 on-chain root updates accumulate. The NFCU compliance RS requires `ACCESS_PII` denial to be cryptographic and instant, not cryptographic and "within 30 tree epochs."

**In-threat-model?** No — revocation latency is outside the SSU/SSZK games entirely. The construction must specify tree update cadence, bound the revocation window, and acknowledge the tradeoff explicitly rather than framing AS revocation purely as a liability.

---

### Attack 3: The Agent Must Run a Native Binary — "AS-Blind" Is a Compute Burden Shift

**Attack:**
The construction's "AS-blind" property means **the agent bears the full proving cost**. Production proving requires `rapidsnark_prover` — a native binary (§, CLAUDE.md: "production proving uses the native `rapidsnark_prover` binary"). The claimed <0.5s target is rapidsnark on capable hardware. snarkjs is explicitly "dev/test only."

Real agent deployment environments:
- Cloudflare Workers (WASM sandbox, no native binary exec)
- AWS Lambda with limited tmp storage and no persistent fs
- Sandboxed Docker containers in enterprise AI platforms
- Browser-based agents (Claude.ai artifacts, OpenAI ChatGPT plugins)
- Mobile SDKs

None of these can run `rapidsnark_prover`. The snarkjs fallback takes 3-5s per proof (§6 table). That's a 3-5 second latency penalty on **every single API call**, injected at the agent-to-RS boundary, with no caching possible (each `sessionNonce` is fresh). WorkOS MCP auth issues a token once; the agent presents it in-header at zero marginal cost per call.

**Why it works / why it fails against the construction:**
§6 presents a two-row table (snarkjs at <3s, rapidsnark at <0.5s) without acknowledging that only one row is available in constrained environments. The "concrete deployment scenario" (§7) mentions rapidsnark without discussing NFCU's actual agent runtime. Enterprise AI stacks are not bare-metal Node.js servers — they are managed runtimes with strict sandboxing.

This is a deployment-architecture gap, not a cryptography gap. The claim "AS-blind" is technically correct but practically means: every call site must support native binary execution. Enterprises evaluating WorkOS vs. Bolyra will discover this in the proof-of-concept phase.

**In-threat-model?** No — the construction's operational model assumes a capable local runtime that many target environments cannot provide. The construction should address WASM-compiled proving (e.g., Bellman WASM, Halo2) or acknowledge the constraint explicitly.

---

### Attack 4: The Operator Key Is a New Single Point of Failure the Construction Does Not Model

**Attack:**
The construction eliminates the AS as a trust anchor and replaces it with the **operator's EdDSA private key** (§2, private inputs: `sigR8x, sigR8y, sigS`; §4 Theorem 1 reduction: "EdDSA on Baby Jubjub is forgeable"). The security of every credential issued by an operator now depends entirely on that operator's key management hygiene.

In the RFC 7662 model, the AS is a managed service (Auth0, WorkOS) with HSM-backed key storage, SOC 2 audits, automatic key rotation, and breach incident response SLAs. The operator in Bolyra is the enterprise customer. NFCU's engineering team is now responsible for:
- Storing Baby Jubjub private keys in HSMs
- Key rotation without invalidating all enrolled credentials (the construction doesn't address rotation)
- Revocation of the operator key if compromised (invalidates the entire agent tree, not just one credential)
- Auditing which credentials were signed before a key compromise

The construction's §4 adversary model excludes "the operator's EdDSA signing key" from adversary control. But in practice the operator is a credit union DevOps team. Key compromise doesn't break the cryptography — it's worse: it requires re-enrolling every agent in the tree under a new operator key, since the old `credentialCommitment` values are all invalid.

**Why it works / why it fails against the construction:**
The SSU reduction (§4 Theorem 1) correctly identifies that forging proofs requires breaking EdDSA. What it doesn't address is: what happens *after* legitimate key compromise? The RFC 7662 model has a clear answer (revoke AS credentials, issue new ones). The Bolyra model has no key rotation protocol — the CLAUDE.md and construction are silent on it. The operator key is load-bearing for the entire deployment, and the construction's security argument stops at "the adversary doesn't control it" without providing key lifecycle management.

**In-threat-model?** No — the construction's threat model excludes operator key compromise by assumption. Enterprises facing procurement review will identify this gap immediately: "You've replaced our managed identity provider with a raw cryptographic key we have to protect ourselves." The construction must specify operator key rotation and the migration path for enrolled credentials.


## Persona: cryptographer

Applied cryptographer. Unless I see a tight game definition, a precise reduction, and named hardness assumptions that match the proof structure, it's a whitepaper. Let's go through this.

---

### Attack 1: SSZK Game is Trivially Won — Nullifier Distinguishes Credentials with Probability 1

**Attack:**

The SSZK game (§3) enrolls two agents C0, C1 with different `permBitmask`s, challenges the adversary to guess which produced the observed proof. The adversary controls the AS, sees all prior transcripts, and can read the on-chain Merkle tree.

`nullifierHash = Poseidon2(credCommitment, sessionNonce)`

`credCommitment = Poseidon5(modelHash, opPkAx, opPkAy, permBitmask, expiry)`

Since C0 and C1 have different `permBitmask`s, their `credCommitment`s differ (assuming Poseidon collision resistance). Both `credCommitment` values are **leaves in the public on-chain Merkle tree**. `sessionNonce` is sent in plaintext from RS to agent and is a public signal in the proof transcript.

The adversary's winning strategy:
1. Read both `credCommitment_0`, `credCommitment_1` from the on-chain tree.
2. Receive the challenge proof transcript containing `(nullifierHash, sessionNonce, ...)`.
3. Compute `Poseidon2(credCommitment_0, sessionNonce)` and `Poseidon2(credCommitment_1, sessionNonce)`.
4. Match against observed `nullifierHash`. Exactly one matches. Output `b' = b` with probability 1.

**Why it works / why it fails:**

The reduction sketch in §4 (Theorem 2) states "Cross-session linking requires inverting Poseidon" — but this addresses cross-session linking within the *same* credential, not distinguishing *between* credentials. The SSZK game asks the latter, and it requires no Poseidon inversion at all. The adversary performs a forward evaluation over a known input.

The formal ZK property says the simulator produces indistinguishable transcripts for "any valid witness satisfying the public signals." But the public signals include `nullifierHash`, which is credential-specific and computable from public data. The simulator argument does not salvage this because the *public output itself* is a deterministic function of the credential identity.

**In-threat-model?** No. The SSZK game as written is a broken definition — it asks for bitmask indistinguishability but the nullifier construction makes credential identity distinguishable with advantage 1. The game must be revised or the nullifier must not be computable from public on-chain state.

---

### Attack 2: `scopeCommitment` is a Static Cross-Session Pseudonym and a Brute-Forceable Bitmask Oracle

**Attack (two sub-attacks, same root cause):**

**2a — Persistent pseudonym.** `scopeCommitment = Poseidon2(permBitmask, credCommitment)`. Both `permBitmask` and `credCommitment` are constants for a given credential. `scopeCommitment` is therefore identical across every presentation of the same credential, regardless of `sessionNonce`. Any two RSes that share transcripts (the adversary controls up to n−1 colluding RSes, §3) can trivially correlate all sessions:

```
RS_A sees (nullifier_1, scopeCommitment_X, nonce_1)
RS_B sees (nullifier_2, scopeCommitment_X, nonce_2)
```

Same `scopeCommitment_X` → same credential. The agent is fully trackable across all RSes it ever contacts.

The deployment scenario (§7) explicitly shows one agent presenting to three different RSes (market data, trade execution, compliance). All three see the same `scopeCommitment`. If those RSes share data — or if the AS eavesdrops — the agent's complete interaction graph is reconstructable.

**2b — Bitmask recovery via small preimage space.** The cumulative-bit enforcement (§2, gadget 6) and the 8-bit semantic definition (CLAUDE.md permissions model) constrain the effective `permBitmask` space to at most 2^8 = 256 values, further reduced by implication closure to ~100 valid combinations. Given `credCommitment` (public, on-chain) and `scopeCommitment` (public output), the adversary:

1. Enumerates all valid `permBitmask_i` (≤ 256 values).
2. Computes `Poseidon2(permBitmask_i, credCommitment)` for each.
3. Matches against observed `scopeCommitment`.

This recovers the exact `permBitmask` in O(256) Poseidon evaluations. The SSZK reduction (§4, Theorem 2) claims "A cannot extract permBitmask from scopeCommitment" and cites Poseidon preimage resistance. But preimage resistance assumes a computationally large preimage space. The circuit enforces a *tiny* space, and the adversary uses forward evaluation, not inversion.

**Why it works / why it fails:**

The zero-knowledge property is stated against a computationally unbounded preimage space, but the circuit's own constraints (cumulative bits, 8-bit semantics) collapse that space. The argument in §4 is structurally circular: "Poseidon preimage resistance means A can't invert" — but A doesn't need to invert; A evaluates forward over a polynomially (in fact, *constantly*) bounded input set.

The `scopeCommitment` output serves a legitimate purpose (on-chain audit trail, §7 step 5), but exposing it as a public output without session binding contradicts the "RS learns NOTHING else" claim in §2 presentation step 5.

**In-threat-model?** No. The SSZK claim is false for the concrete parameter setting. The construction must either (a) bind `scopeCommitment` to `sessionNonce` (`Poseidon3(permBitmask, credCommitment, sessionNonce)`) to prevent cross-session linking, and (b) acknowledge that the effective preimage space must be analyzed concretely, not asymptotically.

---

### Attack 3: SSU Reduction Requires Simulation-Extractability; Only Knowledge Soundness is Cited

**Attack:**

The SSU game (§3) gives the adversary A oracle access to the honest prover: "receives the Merkle root, the verification key, **all public signals from any number of prior valid presentations** by the honest agent." The adversary then attempts to produce a forgery.

The SSU reduction (§4, Theorem 1) proceeds: "By knowledge soundness (A1), extract witness w from A's proof."

Knowledge soundness of Groth16 (in the CRS model, [Groth16]) gives an extractor *E* that, given a prover *P* and auxiliary input, outputs a witness when *P* outputs a valid proof. Crucially, this extraction holds for a *fixed prover strategy* that does not take prior valid proofs as input.

But the SSU adversary A:
- Receives polynomially many valid proofs `(π_1, ..., π_t)` from the honest prover oracle before producing its forgery `π*`.
- A may compute `π*` as an algebraic function of `π_1, ..., π_t`.

Groth16 is **not simulation-extractable (SE)** [Bowe-Gabizon-Green 2017]. An adversary that receives simulated proofs (or oracle-produced proofs, which the honest prover constitutes here) can construct malleated proofs that are valid but for which no valid witness extraction is guaranteed. The gap between knowledge soundness and simulation-extractability is precisely what SE-SNARKs [Kosba et al., LegoSNARK, PLONK with SE] address.

For PLONK in ROM, knowledge soundness in the AGM+ROM [Fuchsbauer-Kiltz-Loss 2018] does give a form of extraction, but only under the **Algebraic Group Model**, which is not cited in the named assumptions (§4 lists ROM for Fiat-Shamir but not AGM). The reduction as written is incomplete.

The concrete concern: given two valid Groth16 proofs `π_1 = (A_1, B_1, C_1)` and `π_2 = (A_2, B_2, C_2)` for the same or related statements, algebraic adversaries may construct `π* = f(π_1, π_2)` that passes verification for a modified public input without the extractor finding a valid witness for that input. Groth16 malleability (specifically the `C` element) is a known property that complicates SE arguments.

**Why it works / why it fails:**

The theorem statement is correct in spirit — SSU should follow from knowledge soundness — but the reduction sketch does not handle the adaptive oracle case. As written, the extractor applies to a *single* proof in isolation. The adversary in the SSU game is adaptive. The missing citation is either (a) SE-SNARK construction, (b) AGM assumption, or (c) a rewinding argument showing the oracle proofs are independent of A's forgery strategy (which would need to be proved, not assumed).

This is not a practical attack today (no known concrete Groth16 malleability that enables SSU-breaking), but it's a gap in the reduction that a CRYPTO/S&P reviewer would return as "major revision."

**In-threat-model?** Partial. The claim survives in practice under reasonable assumptions, but the proof is incomplete. The named assumptions must include either AGM (for PLONK) or SE-SNARK security (for Groth16), and the reduction must be re-stated accordingly.

---

### Attack 4: Groth16 Trusted Setup is Not in the Adversary Model — Startup-Run Ceremony Collapses All Security

**Attack:**

The adversary model (§3) states the adversary does NOT control "the BN128 pairing or Baby Jubjub discrete log problem." It does not state whether the adversary controls the entity that generated the Groth16 circuit-specific CRS (`.zkey` files).

The CLAUDE.md confirms: "project-specific keys (Agent/Delegation) use `pot16.ptau`" and the build command is `npm run compile:circuits → writes circuits/build/`. This is a startup-run trusted setup. The ceremony generates circuit-specific `(.r1cs, .zkey)` from `pot16.ptau` using local toxic waste `τ`. Standard snarkjs workflow: `snarkjs groth16 setup AgentPolicy.r1cs pot16.ptau AgentPolicy_0000.zkey` followed by contributions. If contributions are not MPC'd with external parties (and a startup's `compile:circuits` script is not a multi-party ceremony), then ZKProva Inc. retains `τ`.

With knowledge of `τ`, any Groth16 proof can be forged for any public input, regardless of whether the witness exists. This includes forging a proof that an agent has `permBitmask = 0b11111111` (all permissions) even when the operator never signed such a credential. The SSU game collapses: the adversary is ZKProva itself, and it wins trivially.

The SSU Theorem 1 reduction terminates at step 2 "extract witness w by knowledge soundness" — but knowledge soundness only holds if the CRS was generated honestly. A subverted CRS invalidates the soundness property entirely; there is no witness to extract because the proof is not generated from one.

The `pot16.ptau` (Hermez/Aztec/PSE ceremony) is trustworthy as a universal SRS. But the *circuit-specific phase 2* ceremony is what produces the Groth16 proving/verification keys, and this is the step requiring either (a) MPC with independent parties, (b) trusted hardware, or (c) switching to PLONK (which the construction already supports but treats as optional). The threat model must explicitly state "the Groth16 CRS was generated by a trusted, non-subverted ceremony with at least one honest participant" — or SSU holds only conditionally on ZKProva's honesty, which is a strong trust assumption for an adversarial-AS construction.

The PLONK path avoids per-circuit ceremony (universal SRS, pot16.ptau), but `pot16.ptau` still has its own structured reference string with toxic waste from its generation ceremony. If the same startup ran `pot16.ptau` generation (unlikely for the public ceremonies, but possible for a private deployment), the same issue applies.

**Why it works / why it fails:**

This is the standard subverted CRS attack [Bellare-Fuchsbauer-Scafuro 2016]. The construction does not fail here because it uses PLONK as an alternative, but the *Groth16 path explicitly ships .zkey artifacts* from `circuits/build/` and the threat model does not exclude the circuit generator. The adversarial-AS claim ("even if the AS is fully compromised, it cannot forge a proof") is contingent on the AS not having participated in the trusted setup. For a startup where the AS and the circuit compiler are the same legal entity, this is a material gap.

**In-threat-model?** No — this is the single highest-severity finding. The threat model must either (a) explicitly assume an honestly-generated CRS and document the ceremony, (b) mandate the PLONK path and remove Groth16 from the SSU-security claim, or (c) reference a public MPC ceremony log. The adversarial-AS resilience claim is the construction's headline property; it cannot hold unconditionally if the AS operator also generated the CRS.


## Persona: cu_ciso

### Attack 1: `scopeCommitment` Is a Permanent Cross-RS Tracking Handle

- **Attack**: The adversary controls colluding RSes — explicitly permitted in the threat model. `scopeCommitment = Poseidon2(permBitmask, credCommitment)` is deterministic and constant for the lifetime of a credential (Section 2, public outputs). Every RS that interacts with the same agent receives the same `scopeCommitment` value. A colluding market data RS and a trade execution RS share their received `(scopeCommitment, currentTimestamp, sessionNonce)` tuples and trivially link the two sessions to the same agent with the same full permission bitmask — not just "same predicate satisfaction," but same underlying identity. The SSZK proof in Section 4 only argues that `permBitmask` cannot be extracted from `scopeCommitment` via Poseidon preimage resistance. It says nothing about cross-RS correlation. The construction claims RS learns "NOTHING else about the agent's identity" (Section 2, step 5) — this is false under a colluding-RS adversary who simply compares `scopeCommitment` values across sessions. The SSZK game as written is a single-presentation game; no multi-RS transcript is provided to the adversary, which is precisely what the deployment scenario creates.

- **Why it works**: The SSZK security reduction in Section 4 cites nullifierHash for cross-session unlinkability: "Cross-session linking requires inverting Poseidon." This is true for nullifierHash (session-nonce bound), but scopeCommitment has no nonce binding. It is the same across every presentation of the same credential. The proof simply does not address it.

- **In-threat-model?** No. The construction must address this. Options: randomize scopeCommitment per session (`Poseidon3(permBitmask, credCommitment, sessionNonce)`), or eliminate it from the public outputs and make it an on-chain logged value only under operator control.

---

### Attack 2: Audit Trail Is Cryptographically Opaque — NCUA Part 748 Failure

- **Attack**: NCUA Part 748.2(b) requires a documented audit program with records sufficient for an examiner to reconstruct access events. GLBA Safeguards Rule 16 CFR §314.4(c) requires monitoring and logging of access to customer information. My examiner will ask: "Show me the access log for agent X touching member record Y on March 14." What I can show is a `nullifierHash` and a `sessionNonce`. Neither maps to a human-readable record of what resource was accessed, by which agent, under which authorization. The construction's replay prevention (Section 2, step 4c) consumes nullifiers without recording any semantic access event. There is no logging specification. The `agentMerkleRoot` doesn't tell me which operator enrolled this agent. The `modelHash` is a private input — it never appears in the audit trail.

- **Why it works**: The construction is complete as a cryptographic protocol and silent as an audit architecture. A PLONK proof verifying to `true` tells me "some enrolled agent satisfied this predicate at this nonce" — not "Claude claude-opus-4-5 instance #42, authorized by NFCU AI Ops team, accessed member portfolio data." My SOC 2 Type II auditor and my NCUA examiner both need the latter. The proof provides the former only.

- **In-threat-model?** No. The construction must specify: (a) what the RS logs alongside the verified proof; (b) how `modelHash` (private) is surfaced to authorized auditors without breaking ZK; (c) which operator key maps to which business unit for the board-level access review.

---

### Attack 3: The 30-Entry Root History Buffer Has No SLA and No Fallback

- **Attack**: Section 2 (verification step 4a) requires `agentMerkleRoot ∈ on-chain root history buffer (30-entry window)`. This means every RS must query on-chain state at verification time, or cache it. If Base Sepolia (or mainnet) experiences congestion, finality delay, or RPC node outage, the window check fails and every agent presentation fails. My core processor (Fiserv, Jack Henry, Symitar) has a contractual 99.97% uptime SLA with 15-minute RTO. What is the SLA for the on-chain root? Who is the vendor? What is the RTO when the root cache is stale? FFIEC CAT Domain 3 (Cyber Risk Management) and NCUA's third-party risk guidance (Letter to Credit Unions 01-CU-20) require me to assess the availability posture of every technology dependency in a critical access control path. "Blockchain" is not a vendor I can put in my Vendor Management Policy with a signed SLA.

- **Why it works**: The construction names "30-entry root history buffer" as a parameter (Section 3.1 reference, Section 2 step 4a) without specifying root rotation frequency, maximum cache age, or behavior when the on-chain state is unreachable. If roots rotate faster than the RS's cache refresh, valid credentials will fail verification. If the CU runs its own node, that node is now a critical infrastructure component requiring its own BCP/DR plan — which the construction does not acknowledge.

- **In-threat-model?** No. The construction must specify: root rotation interval, RS cache policy, behavior under chain unavailability, and the vendor management classification for the on-chain dependency.

---

### Attack 4: Emergency Revocation Is Undefined — Regulatory Action Scenario

- **Attack**: NCUA has emergency cease-and-desist authority. On a Friday at 6pm, the examiner calls: "You have a compromised AI agent that accessed 8,000 member records. Terminate its access now." I need to revoke that agent's credential within the hour. The Bolyra agent Merkle tree is described as "append-only, consensus-protected" (Section 4, adversary model). The only revocation mechanism mentioned is expiry (`LessThan(64)` check in-circuit). If the credential has 6 months left on its `expiryTimestamp`, I cannot revoke it before then without either (a) rotating the Merkle root to exclude the leaf — which the construction does not define as a supported operation — or (b) relying on the 30-entry root history buffer to age out the root containing the compromised leaf, which is a timing-dependent and operator-controlled process with no specified bounds. The credential commitment is enrolled in the tree; nothing in the circuit or protocol prevents a compromised agent from generating valid proofs until its embedded expiry timestamp.

- **Why it works**: Section 4 under "adversarial AS" correctly notes the AS can perform denial of service (refuse new enrollments) but cannot forge proofs. The inverse problem is unaddressed: what does the *operator* do when they need to affirmatively deny a specific agent? The SSZK game assumes the challenger enrolls honest agents; it has no oracle for "revoke credential C0 and prove C0's proofs no longer verify." GLBA Safeguards Rule §314.4(e) requires a response program for security events including the ability to terminate unauthorized access. "Wait for expiry" is not a compliant incident response.

- **In-threat-model?** No. The construction must specify a revocation primitive — whether a revocation list committed on-chain, a dedicated nullifier accumulator, or a mandatory short-lived expiry policy (e.g., max 24h expiry enforced by the RS policy) — and map it to NCUA Part 748.3 incident response requirements.


## Persona: rfc7662_advocate

---

### Attack 1: `scopeCommitment` Is a Stable Cross-Session Fingerprint — SSZK Is Broken by Construction

**Attack:**

Look at §2, Public outputs: `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)`. Both inputs are fixed for the lifetime of a credential. There is no `sessionNonce` component. This value is therefore **identical across every presentation this agent ever makes**, to every RS, forever.

The `nullifierHash` rotates per session (it binds `sessionNonce`). Good. But the construction also publishes `scopeCommitment` as a public output in step 3 of the presentation protocol. Any two colluding RSes that compare their logs trivially link every session from the same agent: `scopeCommitment_RS1 == scopeCommitment_RS2` iff same credential. The construction has handed colluding RSes a **permanent, unforgeable, cross-RS agent tracking identifier**.

Compare: RFC 7662 + OIDC PPIDs gives the RS a subject identifier that is *RS-local* — `sub` is a different opaque value per RS by construction. The RS cannot correlate across services without AS involvement. Bolyra's `scopeCommitment` is the *opposite* — a universally stable identifier that every RS gets for free.

**Why it works / why it fails against the construction:**

The SSZK game (§3) allows A to control colluding RSes and share transcripts. With `scopeCommitment` constant across sessions, A trivially wins the linkability game. This is not a novel cryptanalytic attack — it follows directly from reading the public signals list. The construction's §8 claim that "RS learns NOTHING else about the agent's identity" is falsified by the construction's own output specification.

A fix would be `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment, sessionNonce)`, but then `scopeCommitment` can no longer serve as a stable chain entry for audit across sessions, creating a new design tension the construction doesn't address.

**In-threat-model?** Yes — the construction must address this. The adversarial-AS + colluding-RS model is explicitly in-scope (§3), and the SSZK game specifically names colluding RSes sharing transcripts.

---

### Attack 2: Low-Entropy Permission Space Makes `scopeCommitment` a Full Permission Oracle via Brute Force

**Attack:**

The Bolyra spec defines 8 meaningful permission bits (bits 0–7, §Permissions Model in CLAUDE.md) with cumulative implication closure enforced by 3 circuit constraints (§2, gadget 6). After applying these constraints, the valid permission space is not 2^64 — it is a small subset of 2^8 = 256 values, further reduced by the implication rules (bit 4 ⇒ bits 3 and 2, bit 3 ⇒ bit 2). In practice, the valid bitmask set has at most ~200 distinct values.

An RS (or the adversary from §3) who observes `scopeCommitment` can brute-force the full `permissionBitmask` in at most 256 Poseidon evaluations, provided it also knows `credentialCommitment`. And `credentialCommitment` is partially constrainable: from multiple sessions with the same `scopeCommitment` (attack 1) and varying `nullifierHash = Poseidon2(credCommitment, sessionNonce)` where `sessionNonce` is public, an attacker can enumerate candidate `credCommitment` values by inverting the nullifier function over the known session nonces. Under a meet-in-the-middle approach across sessions, `credCommitment` becomes recoverable at cost proportional to the square root of the search space.

The construction's §8 Failure 4 claims a 64-bit BBS+ space. But the *effective* permission entropy here is 8 bits with structure, not 64 bits. This makes the "Poseidon preimage resistance" reduction in Theorem 2 (§4) misleading — the theorem is formally correct (inverting Poseidon is hard), but the *preimage space* is not the full field; it's a small known set. A preimage search is not a preimage attack.

**Why it works / why it fails against the construction:**

The formal reduction in §4 does not account for the case where the preimage domain is publicly known and small. The SSZK security argument relies on "given Poseidon preimage resistance (A2), A cannot extract `permBitmask` from `scopeCommitment`." This is only valid when `permBitmask` is drawn uniformly from F_p. When `permBitmask ∈ {valid 8-bit cumulative patterns}`, the preimage resistance assumption provides no cover.

**In-threat-model?** Yes. The adversary model explicitly allows colluding RSes accumulating transcripts (§3). The construction must either (a) acknowledge the effective permission entropy is ~8 bits and argue why brute-force is still infeasible (it isn't), or (b) redesign `scopeCommitment` to not be recoverable in a small search.

---

### Attack 3: The Adversarial-AS Model Silently Assumes Operator Key Is AS-Disjoint — This Doesn't Hold in Realistic Deployments

**Attack:**

The entire SSU theorem (§4, Theorem 1) rests on: "the adversary controls the AS completely but does NOT control the operator's EdDSA signing key." The §7 deployment scenario (NFCU) has NFCU's operator signing agent credentials with an EdDSA key. In realistic deployments, that signing key is stored in an HSM or KMS managed by NFCU's infrastructure team — the same team that operates the OAuth AS.

An adversary who "controls the AS completely" (§3 adversary model) by definition has access to NFCU's infrastructure. In practice, AS compromise = credential store compromise = HSM API access = operator key compromise. The threat model's explicit carve-out ("does NOT control the operator's EdDSA signing key") is a paper assumption that severs a dependency that exists in every real deployment.

Compare: RFC 7662 + jwt-introspection-response uses ECDSA/RSA signing keys stored in HSMs, with the same infrastructure threat. But the RFC 7662 stack does not *advertise* AS-adversarial resilience. Bolyra's construction makes a strong marketing claim (§8, Failure 3: "the adversarial-AS game has no baseline solution") premised on a separation that requires an additional architectural constraint — operator key isolation in a separate HSM boundary from AS infrastructure — that the construction spec never mandates, never mentions, and the deployment scenario never enforces.

The construction's §4 argument is formally valid under the stated model. But the model is wrong for the claimed use case. An honest comparison to RFC 7662 must hold both to the same infrastructure assumption: either both use HSM-backed signing keys in the same trust domain, or neither does. Under the same infrastructure threat, RFC 7662 + offline JWT introspection responses achieves AS-hot-path independence. DPoP (RFC 9449) provides sender constraint. RFC 8707 provides audience binding. The residual differential is smaller than §8 claims.

**Why it works / why it fails against the construction:**

The construction is technically correct under its stated threat model. But the threat model is not correctly matched to the deployment scenario in §7, creating a gap between the claim and what is actually proven. An RFC 7662 advocate would demand the construction explicitly state: "this security property requires the operator's EdDSA private key to be managed in a separate trust boundary from AS infrastructure, and provides no benefit if both are co-located."

**In-threat-model?** No — the threat model explicitly excludes operator key compromise. But the construction must add this as an **explicit deployment requirement** or retract the adversarial-AS resilience claim, because as written, it implies a property it only delivers conditionally.

---

### Attack 4: JWT Introspection Response + Per-RS Audience Binding Eliminates the AS from the Trust Path — the "Trust Path vs. Hot Path" Distinction Doesn't Do the Work Claimed

**Attack:**

§8, Failure 1 states: "The jwt-introspection-response removes the AS from the *hot path* but not from the *trust path* — the RS trusts the AS's signed assertion. If the AS never issued an assertion for a particular predicate, the RS has no basis for accepting it."

This argument is correct for RFC 7662 classic. But the construction is arguing against a weakened version of the baseline. Consider the following RFC 7662 composition that the construction does not analyze:

1. Issue agent a **BBS+ credential** signed by the operator (not the AS) encoding the 8 permission bits as individual messages.
2. The agent performs BBS+ selective disclosure to each RS, revealing only the bits the RS requires.
3. The RS verifies against the operator's BBS+ public key (obtained from a DID document or JWKS endpoint — no AS call).
4. RFC 9449 DPoP binds the presentation to the agent's ephemeral key, providing sender constraint.
5. RFC 8707 resource indicators bind the presentation to the specific RS, preventing cross-RS replay.
6. OIDC PPIDs per RS prevent cross-RS identity linkage at the RS level.

In this composition: the operator signs (not the AS), the AS is not in the trust path, the presentation is selective, replay is bound to DPoP key + resource indicator, and cross-RS linkage requires RS collusion to correlate DPoP keys (which rotate per session). This matches or exceeds Bolyra's construction on: AS-blind presentation (operator-signed, no AS trust path), per-RS audience binding (RFC 8707), sender constraint (DPoP), and partial selective disclosure.

The construction's §8 Failure 2 correctly notes BBS+ doesn't support bitwise AND across a multi-attribute field with implication closure — but the correct response is that encoding 8 boolean BBS+ messages (one per bit) with an application-level implication check is precisely how you'd implement this. The implication closure can be enforced by the operator at issuance: don't issue bit 3 without bit 2 set. This is a policy constraint, not a cryptographic one, but the same is true of the circuit's cumulative bit gadget — it enforces that the *prover* cannot claim bit 4 without bits 3 and 2, but it does NOT prevent the operator from issuing a credential with bit 4 set and bits 3/2 clear and simply passing those malformed values as private inputs. The circuit only prevents valid-proof forgery, not operator issuance error.

The one remaining differentiator is §8 Failure 4 (proof size): BBS+ over 8 hidden messages is ~8 group elements (~400 bytes on BLS12-381), versus 192 bytes for Groth16. The construction's constant-size advantage is real but the magnitude is ~2x, not qualitative.

**Why it works / why it fails against the construction:**

The "adversarial AS" claim in §8 Failure 3 is the strongest differentiator and is real. But the "AS-blind presentation" claim in §8 Failure 1 is overstated: operator-signed BBS+ credentials are equally AS-blind. The construction conflates "the AS issued the credential" (RFC 7662 classic) with "an AS-controlled entity issued the credential" — but BBS+ credentials can be issued by the same operator EdDSA key Bolyra uses. The SSZK claim is also weakened by Attack 1 above. What remains after removing overstated claims is: (a) adversarial-AS resilience (conditional on Attack 3), (b) constant-size proof regardless of bitmask width, and (c) in-circuit implication closure enforcement that the operator cannot bypass even at issuance. These are real but narrower than the paper claims.

**In-threat-model?** Partially. The construction must narrow its "cannot be matched by any baseline composition" claim to the specific properties it actually delivers uniquely, and must include the operator-signed BBS+ composition in its §8 analysis rather than only analyzing RFC 7662 classic + BBS+ issued by the AS.


## Persona: spiffe_engineer

---

### Attack 1: `scopeCommitment` is a Permanent Cross-Session Tracking Vector

**Attack:**
Section 2 lists `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` as a public output sent to every RS in step 3 of the presentation protocol. Both inputs are static constants for a given agent credential — they contain no session entropy. Therefore `scopeCommitment` is identical across every presentation by the same agent, regardless of which RS is contacted or which `requiredScopeMask` is used.

An adversary controlling `n-1` colluding RSes (explicitly inside the threat model, Section 3) trivially links all presentations from the same agent by matching `scopeCommitment` values. No cryptography is broken — this is plain equality matching on a public output.

**Why it matters against the construction:**
Step 5 of the presentation protocol states: *"RS learns NOTHING else about the agent's identity, operator, model, or remaining permissions."* This is false. Every RS learns a stable pseudonym for the agent — one that is shared across all RS interactions. The construction has `nullifierHash = Poseidon2(credCommitment, sessionNonce)` which correctly adds per-session entropy, but `scopeCommitment` receives no such treatment.

The SSZK game (Section 3) is defined over a single proof, so the formal statement technically survives — a simulator can produce one indistinguishable transcript. But the game does not model multi-session, multi-RS correlation, which is the realistic threat. The privacy claim made in the deployment scenario (Section 7, step 4) collapses under this attack.

**Mitigation available:** Replace `scopeCommitment = Poseidon2(permBitmask, credCommitment)` with `Poseidon3(permBitmask, credCommitment, sessionNonce)`. This makes it session-specific and unlinkable, at the cost of losing a stable on-chain audit anchor — which appears to be the only reason for the current design. The construction must acknowledge this tradeoff explicitly or fix it.

**In-threat-model?** YES — adversary controlling colluding RSes is explicitly in scope. Construction does NOT survive as written. Must address.

---

### Attack 2: SPIFFE ZK Attestor — You Built at the Wrong Layer

**Attack:**
SPIRE's node attestation interface is a gRPC plugin point (`NodeAttestor` + `WorkloadAttestor`). A ZK-based attestor can be registered that accepts a Groth16/PLONK proof of operator-signed credential membership as attestation evidence. The SPIRE server issues an X.509 SVID whose Subject Alternative Name encodes `spiffe://bolyra.operator.example/agent/<nullifierHash>`, with a custom OID extension carrying `credentialCommitment` and `agentMerkleRoot`. The SPIFFE Workload API delivers this SVID to the workload process.

At RS contact time, the agent presents its X.509 SVID in the TLS handshake (mTLS). The RS verifies:
1. Certificate chain back to the SPIFFE trust bundle (already supported by every TLS library).
2. The custom OID extension carrying ZK credential metadata, verified offline against the on-chain root.

This achieves: AS-blind identity (SPIRE doesn't query an OAuth AS), operator-key binding (the SVID was attested by a ZK proof of the EdDSA-signed credential), Merkle membership, and standard TLS — all without a new wire protocol.

**Why it partially fails against the construction:**
The SVID is issued once at attestation time. The X.509 extension would carry the full `credentialCommitment` (binding the full bitmask), not a per-RS selective scope proof. When the trade execution RS presents `requiredScopeMask = 0b00001111`, the SVID cannot generate a fresh proof for that specific mask — the scope is already encoded in the certificate, not evaluated at request time.

This is the runtime-adaptive predicate property (Section 1, Failure 2) and it is the genuine gap. A SPIFFE SVID is a static bearer credential. The ZK circuit is evaluated once at attestation, not at every RS interaction. The construction's claim that the RS specifies `requiredScopeMask` at request time — and the agent evaluates it fresh — is architecturally impossible inside SVID issuance.

**However**, the construction does not acknowledge that it could be implemented as a SPIFFE extension with a per-request proof layer on top of mTLS. The presentation protocol in Section 2 is presented as a standalone protocol; there is no discussion of layering it inside an existing SPIFFE identity channel. This is a standardization objection, not a cryptographic one: the construction should be specified as a SPIFFE/WIMSE profile, not a competing identity system.

**In-threat-model?** NO — this is a deployment/standardization critique, not a cryptographic break. Construction survives cryptographically but must address why it is not a SPIFFE profile.

---

### Attack 3: The 30-Entry Root History Buffer Has an Undefined Revocation Window

**Attack:**
Section 2 (presentation protocol step 4a) and Section 5 (mapping table) both specify that the RS accepts `agentMerkleRoot ∈ root history buffer (30-entry window)`. The construction does not specify:
- How frequently the on-chain Merkle tree root is updated.
- Whether the 30-entry window is indexed by block number, wall clock, or update count.
- What the maximum revocation latency is.

In SPIFFE: SVIDs have a configurable TTL with a recommended default of one hour. SPIRE agents rotate credentials automatically. A compromised agent credential expires within `TTL` regardless of any out-of-band revocation signal.

In Bolyra: An operator revokes an agent by removing its `credentialCommitment` from the Merkle tree and publishing a new root. But the RS accepts proofs generated under any of the last 30 roots. If the operator updates the tree once per day, a revoked credential remains valid for up to 30 days. If the tree is updated once per hour, the window is 30 hours. The construction is silent on this.

**Concrete attack scenario (Section 7, NFCU deployment):**
A rogue employee extracts the agent's private credential fields. The operator discovers the breach and removes the credential from the Merkle tree. The rogue agent continues generating valid PLONK proofs against roots in the 30-entry history buffer for up to 30 update cycles. NFCU's RS accepts these proofs because `agentMerkleRoot ∈ root history buffer` passes check 4a.

The construction explicitly claims in Section 4 that "a compromised AS cannot retroactively revoke a presentation already verified on-chain (immutability)" as a feature. But the buffer design means the window isn't about already-verified presentations — it's about future presentations with a stale root. These are opposite properties.

**Why SPIFFE handles this better:**
SPIRE's short-lived SVIDs make revocation latency bounded and configurable. Bolyra's root history buffer trades revocation latency for liveness (tolerating short chain delays), but the tradeoff is not analyzed or even acknowledged as a tradeoff.

**In-threat-model?** YES — credential compromise is within scope. Construction must specify the maximum root update interval and bound the revocation window, or replace the 30-entry buffer with a timestamp-bounded window (e.g., "roots no older than 2 hours").

---

### Attack 4: WIMSE Token Exchange Already Models This — Justify the Fork

**Attack:**
`draft-ietf-wimse-arch` (Workload Identity in Multi-Service Environments, IETF active WG) defines a "service token" architecture where a workload's SPIFFE SVID is exchanged for a context-specific token scoped to a particular downstream service. Section 4 of the WIMSE architecture draft explicitly addresses the case where the workload needs different permission surfaces at different RSes without revealing its full authority.

The WIMSE WG has an open discussion thread on ZK-based claims in service tokens. Contributing the selective scope proof circuit as a WIMSE `token_type` extension (analogous to how DPoP is an extension to RFC 9449) would:
- Achieve IETF standardization.
- Reuse SPIFFE's existing trust bundle and federation model.
- Interoperate with every SPIRE-integrated service without a new SDK.

**Why the construction must respond:**
Section 8 of the construction argues that the baseline (RFC 7662 + BBS+) "fails on four independent axes." It does not engage with WIMSE at all. WIMSE is not RFC 7662 — it is specifically designed for the multi-service workload credential problem the construction is solving. The claim that "no combination of DPoP, RFC 8707, or BBS+" can match Bolyra is accurate against 2016-era OAuth, but it sidesteps the 2024-era WG that is directly scoped to this problem.

The construction needs either: (a) a concrete analysis of what WIMSE-with-ZK-service-tokens cannot express that Bolyra can, particularly the runtime-adaptive predicate property, or (b) a statement of intent to contribute the circuit as a WIMSE token type.

**In-threat-model?** NO — this is a positioning/standardization objection. Construction survives cryptographically. But the "no existing protocol can match" claim in Section 8 is overstated without engaging WIMSE, and an informed reviewer (or patent examiner) will notice the omission.
