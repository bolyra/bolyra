# Tier 3 Adversarial — C1 Selective scope proof

## Persona: auth0_pm

---

### Attack 1: Proving Latency Is a Non-Starter for Enterprise API SLAs

- **Attack**: The construction claims Groth16 proving time of "< 5s on commodity hardware (snarkjs)" and "< 0.5s (rapidsnark, server)." The attack-prompt seed explicitly pegs this at ~15s in practice. Even the optimistic 0.5s rapidsnark figure assumes the operator runs native binary infrastructure — not a browser, not a serverless function, not a Lambda cold start. Enterprise API SLAs at credit unions (Jack Henry, Fiserv integrations) are typically p99 < 200ms. WorkOS issues tokens in < 100ms with zero additional infrastructure. The construction's Section 6 gives circuit cost estimates but makes no commitment to end-to-end latency including network, proof generation, and on-chain root lookup. A procurement engineer will ask: what is the p99 latency added to my API call? The construction cannot answer this without operator-controlled proving infrastructure, which is an entirely new operational burden.

- **Why it works / why it fails**: The construction does not address this. It separates "proving system" (< 5s / < 0.5s) from the full end-to-end flow. In the Section 7 scenario, the agent generates a Groth16 proof at call time — but call time for RS₂ (loan pre-qualification) means the member is waiting. The construction has no async proof pre-generation mechanism described. The rapidsnark path requires the agent runtime to have access to a native binary and `.zkey` artifact; no web or mobile agent can do this without a server-side proxy, reintroducing a roundtrip.

- **In-threat-model?** No — the construction must address end-to-end latency, pre-generation strategies, and the infrastructure gap between "< 0.5s rapidsnark" and a realistic enterprise deployment.

---

### Attack 2: Trusted Setup Is a Solo-Founder Trust Assumption That Procurement Will Reject

- **Attack**: Groth16 requires a per-circuit Phase 2 trusted setup ceremony. The construction says AgentPolicy and Delegation use `pot16.ptau` — but this is only Phase 1 (universal SRS). The per-circuit `.zkey` files require a Phase 2 MPC ceremony, which is circuit-specific and must be trusted. Section 4 names the assumption "Knowledge soundness of Groth16 (generic group model + random oracle model for Fiat-Shamir)" but does not disclose who ran the Phase 2 ceremony, how many participants, or whether the toxic waste was destroyed. For a credit union under NCUA examination, the question from the examiner is: "Who conducted the trusted setup, and how many independent parties participated?" A solo-founder Phase 2 ceremony with a single participant means a single point of compromise can generate fake proofs for any agent, defeating the entire construction's soundness. PLONK is offered as an alternative (no per-circuit setup), but the construction treats Groth16 as "required" for the agent circuit (§ Proving system row in Table 5).

- **Why it works / why it fails**: Section 4 (Security argument) reduces SCOPE-FORGE soundness to ε_ks (Groth16 knowledge soundness), but ε_ks is only negligible if the `.zkey` was generated with an honest Phase 2. A solo-founder `.zkey` does not satisfy this. The construction explicitly says "AgentPolicy circuit — Groth16 required, PLONK optional" — the required path carries this trust assumption. Auth0's trust root is a SOC 2 Type II-audited key management system with third-party attestation. The construction's trust root is an unaudited `.zkey` file.

- **In-threat-model?** No — the construction must either commit to a multi-party Phase 2 ceremony with verifiable transcript, or declare PLONK (universal setup, no per-circuit ceremony) as the required proving system and deprecate Groth16 for agent circuits.

---

### Attack 3: No Revocation Mechanism — Worse Than JWT for NCUA Compliance

- **Attack**: Section 7 explicitly names NCUA examiners as the compliance audience. NCUA examination guidelines on third-party vendor risk (Letter 07-CU-13) and AI-specific guidance require that credit unions demonstrate the ability to revoke compromised vendor access immediately. The construction has no revocation mechanism. An enrolled agent credential is a Merkle leaf — removing it requires updating the on-chain root. The 30-entry circular root history buffer (§ Table 5) means the RS accepts any `agentMerkleRoot` from the last 30 state updates. If a compromised agent credential needs to be revoked, the operator must: (1) remove the leaf, triggering a new root, (2) wait for the history buffer to cycle past all 30 roots that include the old leaf, (3) during which window the compromised credential is still provably valid. With low-traffic root updates, this window could be days or weeks. RFC 7662 token revocation is immediate: revoke at the AS, next introspection returns `active: false`. DPoP adds binding but doesn't change revocation semantics. The construction provides no equivalent.

- **Why it works / why it fails**: Section 3 (Threat model) defines adversary capabilities but does not include a "compromised operator key" scenario. The operator's Baby Jubjub private key signs credential commitments (§ EdDSAPoseidonVerifier). If the operator key is stolen, every credential it ever signed remains valid until the history buffer cycles. The construction acknowledges the 30-root buffer as a design parameter but provides no guidance on buffer sizing relative to revocation urgency or how to perform an emergency revocation.

- **In-threat-model?** No — the construction must specify a revocation path, address the history-buffer window as a security parameter with a defined maximum revocation lag, and explain how this satisfies NCUA third-party risk expectations better than immediate JWT revocation.

---

### Attack 4: Cross-RS Unlinkability Is a CISO Liability, Not a Feature

- **Attack**: Section 2 (Game 4) and Section 7 present cross-RS unlinkability as a selling point for credit unions: "Even if RS₁, RS₂, and RS₃ are operated by the same vendor... they cannot correlate the agent's proofs across sessions." From a security operations standpoint, this is an anti-feature. A credit union CISO's threat model includes: an AI agent that is compromised mid-session performing fraudulent transactions across multiple resource servers. Under the Bolyra construction with session-randomized scope commitments, the SIEM sees independent, uncorrelated events at each RS with no shared identifier — the `scopeCommitment` and `nullifierHash` are distinct by construction, and the `agentMerkleRoot` is shared across all agents and provides no signal. There is no audit trail to correlate that RS₁'s access and RS₃'s wire transfer were the same agent. WorkOS and Auth0 provide correlated session IDs, device fingerprints, and user-level audit logs as standard features. SOC 2 Type II requires demonstrating comprehensive audit log coverage of privileged access. The construction's unlinkability guarantee would likely *fail* a SOC 2 audit.

- **Why it works / why it fails**: The construction frames the threat in §3 as "colluding RSes... attempt to correlate [proofs] to the same agent" — positioning the RS as an adversary. But in the Section 7 credit union scenario, the RSes are operated *by the same credit union* and correlation is desirable, not adversarial. The construction does not distinguish between legitimate operational correlation (same operator, audit use) and adversarial cross-RS tracking (independent operators, privacy violation). There is no opt-in correlation mechanism described — a deterministic identifier per session that the credit union's own RS cluster can use while remaining unlinkable to external parties. The feature is implemented as an absolute property with no escape hatch for legitimate audit.

- **In-threat-model?** No — the construction must distinguish adversarial cross-RS correlation (blocked) from legitimate same-operator audit correlation (permitted via an operator-scoped session identifier or structured audit log mechanism), and explicitly address SOC 2 audit log completeness requirements.


## Persona: cryptographer

Applied cryptographer. Unless I see a tight game definition, a named assumption, and a reduction that closes, it's a whitepaper, not a proof. The construction in front of me has real structure — more than most — but four attacks survive contact with formalism.

---

### Attack 1: Trusted-Setup Subversion Breaks All Soundness Claims

**Attack:**
The AgentPolicy and Delegation circuits are proved under Groth16 using `pot16.ptau`, a project-specific ceremony (§2, §5: "project-specific keys (Agent/Delegation) use `pot16.ptau`"). Groth16 soundness is only as strong as the assumption that the toxic waste (the CRS trapdoor `τ`) was destroyed. An adversary who participated in or compromised the ceremony retains `τ` and can compute a simulated proof for **any** public input vector — including one where `requiredScopeMask = M` is not satisfied by the enrolled bitmask. This breaks Game SCOPE-FORGE (§3) completely: the reduction to knowledge soundness is vacuous when the CRS itself is trapdoored.

**Why it works against the construction:**
The threat model (§3) lists what the adversary does NOT control: the AS, the on-chain contract, and the honest agent's private inputs. It says nothing about the trusted setup. The AS-BLIND game (§3, Game 3) explicitly argues the AS is irrelevant to proof validity — but the setup authority is equally irrelevant to the AS and equally dangerous. A ceremony participant who retains `τ` can forge proofs that pass the on-chain verifier, enroll arbitrary agents into the Merkle tree via a forged Merkle witness, and satisfy any `requiredScopeMask` without holding any credential. The on-chain contract verifies the proof, which passes. The Merkle root check passes because the forged proof supplies an arbitrary `agentMerkleRoot` consistent with the trapdoor.

**In-threat-model?** **No — the construction must address this.** PLONK is listed as "optional" (§5 table, §2 circuit cost). If PLONK's universal setup (e.g., Aztec Ignition or Zcash Powers of Tau) is the proving system, the per-circuit toxic waste attack disappears. The construction should either (a) mandate PLONK for all agent circuits and justify the universal setup trust model, (b) run a public multi-party ceremony for `pot16.ptau` and cite it explicitly, or (c) add a "subverted setup" game to §3 and show PLONK closes it. The current spec leaves this as a critical unaddressed assumption.

---

### Attack 2: Colluding-RS Nonce Coordination Trivially Breaks CROSS-RS-UNLINK

**Attack:**
The threat model (§3) explicitly places "one or more colluding RSes" in the adversary's hands. Nothing in the protocol prevents two colluding RSes from choosing `sessionNonce₁ = sessionNonce₂`. If they coordinate to send the same nonce to the agent:

```
scopeCommitment₁ = Poseidon3(B, cred, nonce)
scopeCommitment₂ = Poseidon3(B, cred, nonce)
→ scopeCommitment₁ == scopeCommitment₂
```

```
nullifierHash₁ = Poseidon2(cred, nonce)
nullifierHash₂ = Poseidon2(cred, nonce)
→ nullifierHash₁ == nullifierHash₂
```

Both public outputs are identical. The colluding RSes trivially win Game CROSS-RS-UNLINK (§3, Game 4) with advantage 1 by checking equality of these values and inferring that the proofs came from the same agent.

**Why it works against the construction:**
Game CROSS-RS-UNLINK (§3) has the *challenger* sample both nonces "fresh, distinct" — this is a game-design choice that excises the attack from the model. In the real deployment scenario (§7), RS₁ and RS₂ are potentially "operated by the same vendor (common in credit union core provider ecosystems — e.g., Jack Henry, Fiserv)." A single vendor controls both RSes, sets both nonces, and can trivially coordinate them. The claim "the session-randomized construction eliminates this channel entirely" (§7) is true only under the challenger's guarantee of distinct nonces, not under the adversary model where RSes are colluding principals.

The reduction sketch for CROSS-RS-UNLINK (§4) says "fix `nonce_1` as the key" and argues PRF security. But the PRF game is only meaningful when the key is chosen independently of the challenge. If the adversary (controlling both RSes) picks `nonce₁ = nonce₂`, there is no PRF argument to make — the inputs to Poseidon are identical.

**In-threat-model?** **No — the construction must address this.** The fix requires the agent to enforce nonce freshness globally: maintain a per-credential used-nonce registry and refuse to prove under a reused nonce. Alternatively, the agent should generate the nonce and commit to it first (commit-reveal), with the RS binding its `requiredScopeMask` to the agent's committed nonce. Neither mechanism is specified. The current game definition should be replaced with one where the *adversary* chooses both nonces subject only to being valid field elements.

---

### Attack 3: Binary Search via Adaptive Single-Bit Mask Queries Recovers the Full Bitmask

**Attack:**
A malicious RS (which is in-model — "The adversary A controls... the network between agent and RS") makes 64 sequential proof requests, each with a different single-bit `requiredScopeMask`:

```
Session 1:  requiredScopeMask = 0b00000001  → proof produced or not
Session 2:  requiredScopeMask = 0b00000010  → proof produced or not
...
Session 64: requiredScopeMask = 0b...10...0  → proof produced or not
```

If bit `i` is set in the agent's bitmask, the circuit is satisfiable and a proof is produced. If bit `i` is not set, the circuit constraint `requiredBits[i] * (1 - permBits[i]) === 0` is violated — the circuit has no satisfying witness and the agent cannot produce any proof. The RS observes success or silence. After 64 sessions, every bit of `permissionBitmask` is determined exactly.

With the 8-bit named permission space and implication closure (§5: bits 4→3→2 cascade), the effective enumerable space is even smaller: at most ~20 valid configurations. A single pass over single-bit masks uniquely identifies the bitmask in the first 8 queries.

**Why it works against the construction:**
Game SCOPE-HIDE (§3, Game 2) is formulated as a **one-shot** indistinguishability game: the adversary sees a single proof for a single mask and guesses which of two satisfying bitmasks was used. This is the wrong game for the actual protocol. In deployment, the *same* agent credential is reused across many RS interactions (that is the entire point — the agent has one credential and proves different predicates to different RSes). A security notion for this setting requires a multi-session game where the adversary makes adaptive mask queries and the advantage bound must account for the information leaked by both successful and failed proof attempts.

The ZK claim (A4, §4) is that the proof transcript is simulatable for any satisfying witness. This is correct per session. It does not prevent the RS from learning via *which masks the agent refuses to prove* — a side channel orthogonal to the cryptographic content of any individual proof. The construction has no response to this attack because the protocol specification (§2, Step 2) gives no mechanism for the agent to decline adaptive mask queries without revealing information.

**In-threat-model?** **No — the construction must address this.** A multi-session game definition is required (the adversary issues up to `q` mask queries adaptively; advantage must be bounded as a function of `q`). One mitigation: require the RS to commit to `requiredScopeMask` before the agent acknowledges the session, and limit the agent to one proof per RS per credential epoch. But the current protocol has no such restriction.

---

### Attack 4: SCOPE-HIDE Reduction Incorrectly Invokes Collision Resistance as One-Wayness

**Attack:**
The SCOPE-HIDE reduction (§4, "Reduction sketch for SCOPE-HIDE") states: "under A2 (collision resistance implies one-wayness) and A5 (PRF security), the commitment does not leak information about the bitmask." The parenthetical claim **collision resistance implies one-wayness** is false as a general statement. Collision resistance and one-wayness are independent properties: a function can be collision-resistant while being easily invertible (e.g., an identity function on a large domain is trivially collision-resistant but not one-way). The IACR literature treats these as distinct hardness assumptions.

The concrete exploitation: `scopeCommitment = Poseidon3(permissionBitmask, credentialCommitment, sessionNonce)`. The RS observes `scopeCommitment` and `sessionNonce` (both public). `credentialCommitment` is private, but `nullifierHash = Poseidon2(credentialCommitment, sessionNonce)` is also public. If an adversary can jointly invert both outputs by brute-forcing the pair `(permissionBitmask, credentialCommitment)`, they recover the full private credential. The `credentialCommitment` is a Poseidon5 hash over a 256-bit field element, so joint inversion is infeasible in the standard (high-entropy credential) case. However, the security argument as written provides no formal basis for this claim — it cites A2 (collision resistance) where it needs A5 (PRF security / pseudorandomness of Poseidon keyed by `sessionNonce`).

**Why it works against the construction:**
The reduction as written has a logical gap. For the SCOPE-HIDE claim to hold formally, the construction needs to argue: given (`nullifierHash`, `scopeCommitment`, `sessionNonce`), no PPT adversary can compute `permissionBitmask` with non-negligible probability. This requires Poseidon to behave as a PRF (A5), not merely a collision-resistant hash (A2). The two assumptions are not interchangeable. If A5 is used for SCOPE-HIDE, the reduction is sound. As written, invoking only A2 leaves a gap that is invisible in the ideal case (Poseidon is conjectured to have PRF-like behavior) but constitutes an incorrect reduction.

Additionally, the cumulative-bit implication closure (§2, Gadget 4) severely restricts the entropy of `permissionBitmask`: bits 4, 3, 2 are constrained by the cascade rules, and the 8 named bits (out of 64) have implications that reduce valid configurations. Under low-entropy distribution assumptions (e.g., a regulator that issues only a handful of standard permission profiles), the PRF assumption on Poseidon may need to be invoked over a very small effective key space, which weakens the concrete security bound. The construction should quantify this explicitly.

**In-threat-model?** **Partially.** The attack is a logical error in the proof, not an immediate practical exploit — Poseidon is conjectured PRF-secure. But a published security argument that invokes the wrong assumption is unsound by IACR standards and would not survive peer review at CRYPTO or S&P. The fix is simple: replace "A2 (collision resistance implies one-wayness)" with A5 (Poseidon PRF security) in the SCOPE-HIDE reduction and add a sentence bounding the concrete advantage as a function of the effective bitmask entropy. The reduction then closes correctly.


## Persona: cu_ciso

---

### Attack 1: Operator Key Custody — "Where does the signing key live, and who controls it?"

**Attack:** Section 7 states "The credit union's compliance officer enrolls an AI agent… signed by the operator's EdDSA key." The CISO asks: where is that Baby Jubjub private key stored? Is it in a browser wallet? A software key store? A developer's laptop? Beyond enrollment, the agent must hold `credentialCommitment`, `merkleProofSiblings[20]`, and the EdDSA signature material as live private inputs to the prover at runtime. If the agent is an LLM call routed through a third-party cloud (OpenAI, Anthropic, etc.), those private inputs must be stored and injected into the proving sidecar at request time.

The construction is entirely silent on:
- Where the operator EdDSA signing key is stored (HSM, Vault, software KMS?)
- Who has administrative access to rotate or revoke it
- Where the agent's proving-time private inputs live in the deployment topology
- Key rotation procedures and how rotation invalidates existing credentials

**Why it works against the construction:** GLBA Safeguards Rule §314.4(c)(3) requires documented encryption key management including generation, storage, access control, rotation, and destruction. NCUA Part 748 Appendix B Part II requires a written information security program covering cryptographic controls. SOC 2 CC6.1 requires access controls on cryptographic material. The construction's security argument depends entirely on the privacy of `permissionBitmask`, `credentialCommitment`, and the operator signing key — but the deployment scenario (Section 7) never specifies how any of these secrets are protected at rest or in transit to the prover.

The CISO cannot answer the examiner question: "Show me your key management policy for the ZK credential signing key and agent secrets inventory."

**In-threat-model? No.** The construction must specify a key custody model. At minimum: operator signing key requires HSM or cloud KMS with hardware root of trust; agent proving-time secrets require secrets manager integration with audit logging; key rotation triggers immediate credential re-issuance and Merkle tree update.

---

### Attack 2: Audit Trail Opacity — "The nullifier hash is not an audit log."

**Attack:** Section 4 (Verification Protocol, step 4) states: "RS records `nullifierHash` for replay detection within the session scope." Section 7 claims: "The NCUA examiner can verify on-chain that all enrolled agents have operator-signed credentials without accessing any agent's full permission set."

The CISO inverts this: the unlinkability properties that make the construction cryptographically elegant make it operationally unauditable. `nullifierHash = Poseidon2(credentialCommitment, sessionNonce)` is:
- An opaque 254-bit field element
- Intentionally unlinkable to agent identity (the whole point of cross-RS unlinkability)
- Unlinkable to which member's account was accessed
- Unlinkable to which specific permissions beyond `requiredScopeMask` were exercised

When a member calls at 2am saying an AI agent moved money without authorization, the Tier 1 ops team looks at the RS access log and sees: `nullifierHash: 0x1a3f...`, `requiredScopeMask: 0b00001011`, `proof verified: true`. They cannot determine: which enrolled agent this was, who the operator is, or whether this was the same agent that accessed three other RSes in the same window.

**Why it works against the construction:** NCUA Part 748 Appendix B Part III requires audit trail capability sufficient to reconstruct access to member information. FFIEC CAT Domain 2 (Threat Intelligence) requires that access events be attributable to specific actors. GLBA §314.4(d)(2) requires detecting unauthorized access to customer information — which requires knowing *who* accessed it. The construction's Game 4 (Cross-RS Unlinkability) is a direct proof that RSes cannot correlate proofs to the same agent. This is the same property that makes post-incident forensics impossible.

Section 7's claim that the construction provides "examiner audit" capability is false on its face. On-chain enrollment visibility is not access-event attribution.

**In-threat-model? No.** The construction must define a separate, permissioned audit channel — likely operator-controlled structured logging outside the ZK layer — where the credit union's compliance officer (not the RS) can deanonymize access events for their own agents during regulatory examination. This breaks no cryptographic property: the credit union knows which agent it enrolled and can maintain an off-chain mapping of `credentialCommitment → agent identity`. The construction needs to specify this explicitly and provide a reference architecture.

---

### Attack 3: On-Chain Registry as Unexamined Critical Vendor

**Attack:** The RS's sole trust anchor for agent enrollment is the check `agentMerkleRoot ∈ on-chain root history buffer`. This requires a live RPC call to a smart contract on Base (or Base Sepolia per the deployment scenario in Section 7). The registry contract is presumably operated by ZKProva Inc. on Coinbase's Base network.

The CISO maps this to the vendor management chain: ZKProva Inc. is a pre-revenue startup. Base is operated by Coinbase. The smart contract, if immutable, cannot be patched. NCUA's third-party risk guidance (Letter 07-CU-13, updated through NCUA's 2023 examination procedures) classifies any entity providing critical operational support to a credit union as a third-party vendor requiring due diligence, SLA documentation, audit rights, and an exit strategy.

Specific attack scenarios:
1. **Base network outage**: No new root updates propagate. The 30-root history buffer provides a finite offline window, but the construction doesn't specify root rotation frequency. If the operator updates the Merkle tree on every enrollment (common pattern), roots rotate frequently and the 30-root window could be as short as 30 × T_update_interval.
2. **ZKProva Inc. insolvency or acquisition**: Who controls the registry contract admin key? Can the credit union migrate to a self-operated contract? The construction has no answer.
3. **Smart contract upgrade**: If the registry uses a proxy pattern (upgradeable), the upgrade key holder can alter root semantics unilaterally. If immutable, bugs cannot be fixed.

**Why it works against the construction:** The construction explicitly claims "Adversarial-AS resilience" by removing AS from the trust path — but replaces it with a blockchain infrastructure dependency that has *less* contractual accountability than a typical AS vendor. An AS vendor can sign an SLA and provide audit rights. A smart contract cannot. The NCUA examiner will ask: "Who is your vendor for the cryptographic registry, what is their SLA, have you reviewed their SOC 2, and what is your exit plan?" None of these questions have answers in the construction.

**In-threat-model? No.** The construction must address: registry contract governance (admin key custody, upgrade policy), availability SLA with fallback mode, TPRM classification guidance for credit union legal/compliance teams, and a self-hosting path for institutions that cannot accept third-party infrastructure dependency.

---

### Attack 4: Revocation Latency for Financial-Scope Credentials

**Attack:** The construction contains no revocation mechanism. `expiryTimestamp` provides a hard outer bound, but there is no path to immediately invalidate a compromised credential before expiry. The implicit revocation model is: remove the credential from the Merkle tree, publish a new root on-chain, and wait for the 30-root history buffer to cycle past all roots that included the compromised leaf.

For an agent holding `FINANCIAL_MEDIUM` permissions (bits 0+1+2+3 — wire transfers up to $10K), the attack window after compromise detection is:

```
T_revocation_window ≥ T_detection + T_chain_confirm + (30 × T_root_rotation_interval)
```

During this window, the adversary holding the stolen private inputs (`credentialCommitment`, `merkleProofSiblings[20]`, operator signature) can continue generating valid proofs. The proofs are **AS-blind** — there is no session refresh, no token revocation endpoint, no OAuth revocation list. The only signal the RS has is the root check, and the compromised root is still in the history buffer.

The construction's Section 3 threat model explicitly excludes this: "The adversary does NOT control… the honest agent's private inputs." But private inputs can be exfiltrated from a compromised proving sidecar, secrets manager, or agent runtime. This is not a cryptographic break — it's a secrets management failure, but the construction must account for it.

**Why it works against the construction:** NCUA's Bank Secrecy Act requirements and FinCEN's wire transfer rule (31 CFR §103.33) require the ability to freeze a compromised actor's access in near-real-time for transactions over $5K. The credit union's incident response plan must document a Maximum Tolerable Downtime for access revocation of financial-scope credentials. The construction provides no revocation SLA and no emergency cutoff path. A credit union that cannot guarantee immediate revocation of a `FINANCIAL_MEDIUM` agent credential has a control gap that NCUA examiners will cite under Part 748 §748.0(b) (incident response) and the FFIEC CAT Cyber Risk Management domain.

The 30-root history buffer — specifically designed in the construction to provide liveness tolerance — is the mechanism that makes emergency revocation impossible to guarantee. There is a direct trade-off the construction does not acknowledge: liveness tolerance and revocation speed are in conflict.

**In-threat-model? No.** The construction must define a revocation SLA, specify a maximum root history buffer depth that bounds the revocation window, and provide an emergency invalidation path (e.g., a separate nullifier registry that RSes check before accepting any proof, independent of the Merkle root cycle).


## Persona: rfc7662_advocate

---

### Attack 1: JWT Introspection Response Achieves AS-Blind Offline Verification — Axis 1 Overstated

- **Attack**: `draft-ietf-oauth-jwt-introspection-response` (§3) lets the AS issue a *signed JWT* containing the introspection result. The RS caches and verifies it offline using the AS's public key — no roundtrip at presentation time. Combined with DPoP (RFC 9449) for sender constraint and short-lived tokens, the AS is not in the hot path at the moment of resource access. The construction's §8 Axis 1 claim "the AS must have been involved at issuance or introspection time" is technically true but operationally equivalent: the Bolyra agent also uses a credential issued offline at enrollment time. In both cases, the live component is *not present* at the moment of RS verification. The construction does not distinguish between "AS not contacted at proof time" (its claim) vs "AS not in the verification trust path at access time" (what jwt-introspection-response actually achieves).

- **Why it partially fails against the construction**: The RS specifies `requiredScopeMask` at verification time (§2, public inputs). A jwt-introspection-response's scope set is *fixed* in the signed JWT at issuance. The RS cannot inject a runtime bitwise predicate into a cached JWT — it can only accept or reject based on what the AS wrote. The construction's runtime-adaptive predicate (Game 1, §3) is structurally inexpressible in any signed-at-issuance document. The attack exposes that AS-blindness alone is not the load-bearing property — runtime predicate adaptability is where the gap truly lies, and the construction undersells this in §8 Axis 1 by conflating the two properties.

- **In-threat-model?** Partially. AS-blindness as an independent axis (Axis 1) is overstated — jwt-introspection-response achieves it for cached credentials. The construction survives because the runtime-adaptive predicate (Axis 2) is the genuine gap. **The construction must disentangle Axes 1 and 2 to avoid a strawman.**

---

### Attack 2: BBS+ With 64 Per-Bit Messages Achieves Selective Disclosure Without Circuits

- **Attack**: Issue the agent a BBS+ credential (e.g., via BBS Signature Draft §4) with 64 Boolean messages, one per permission bit. At presentation time, the RS specifies which attributes it needs disclosed (e.g., "reveal message 0 and message 2"). The holder generates a BBS+ proof of knowledge revealing only the requested bits. This achieves: (a) holder-selective disclosure at moment of use with no AS roundtrip, (b) RS only learns the bits it asked for, (c) proof size is O(|disclosed bits|) not O(2^64) — typically 2–4 attributes per RS, constant in practice. The construction's §8 Axis 2 dismisses this by claiming "bitwise AND over a 64-bit field with cascading implication constraints has no BBS+ extension" and implies exponential blowup, but this is wrong for the common case: the RS requests exactly the bits in `requiredScopeMask` as individual attribute disclosures. No enumeration required.

- **Why it partially fails against the construction**: The cumulative-bit implication constraints (§2, gadget 4: bit 4 → bit 3 → bit 2) are *not enforced by BBS+*. The AS must have enforced them at issuance and the RS must trust the AS did so. In the adversarial-AS model (§3, Game 3), a compromised AS issues a BBS+ credential with bit 4 set and bit 3 unset, violating the invariant. The RS has no cryptographic recourse. The Bolyra circuit enforces the implication closure on the *private bitmask* regardless of AS honesty — the constraint fires on hidden bits, not just disclosed ones. Additionally, BBS+ attribute disclosure reveals the *exact value* of each disclosed message; Bolyra proves only that the mask predicate holds, leaking no individual bit values even for required bits (though in practice revealing a bit is set is equivalent for binary attributes).

- **In-threat-model?** Honest-AS scenario: BBS+ matches the construction's selective disclosure claim with no ZK needed. The construction's Axis 2 argument only holds under the adversarial-AS model (§3). **The construction must explicitly scope its claim: "BBS+ cannot match this property when the AS is adversarial" rather than claiming BBS+ fundamentally cannot express bitwise predicates.**

---

### Attack 3: The Operator Key Is the AS in Disguise — Adversarial-AS Resilience Is Circular

- **Attack**: The construction's centerpiece claim (§8 Axis 3, Game 3) is that a compromised AS "cannot alter the agent's enrolled credential commitment (it would need to forge a Poseidon preimage or corrupt the Merkle tree contract)." But the on-chain Merkle tree is *not immutable* — agents are enrolled by adding leaves (§7: "the credit union's compliance officer enrolls an AI agent... into the on-chain agent Merkle tree"). Someone must have write access to the tree. That party holds the enrollment key. In the §7 scenario, this is the "compliance officer" / operator EdDSA key. If the threat model permits an adversarial AS, what prevents the adversary from *also being the operator*, or from compromising the operator key? The construction's §3 threat model says the adversary controls "the Authorization Server" but does **not** include the operator key in the adversary's capabilities, without justifying this separation. In practice, the same vendor that operates the AS (e.g., Okta, Auth0) often manages operator credentialing and key ceremony. A supply-chain attack on the AS vendor (the construction's own motivating example in §8 Axis 3) likely also compromises the operator key. An adversary with the operator EdDSA key can sign new credential commitments with arbitrary `permissionBitmask` values and enroll them into the Merkle tree — exactly what a compromised AS could do in the RFC 7662 model.

- **Why it partially fails against the construction**: The construction is not *claiming* operator-key security — it's claiming that the on-chain Merkle root is verified trustlessly by the RS. If the operator key is a separate, hardware-secured, air-gapped key (different threat surface than the AS), then compromising the AS does not compromise the enrollment authority. The construction survives if the operator key and AS are genuinely independent. But the construction never specifies the governance of Merkle tree write access, the key management ceremony, or the on-chain access control for tree insertions. The "adversarial-AS resilient" framing implicitly assumes these are separate, which is a deployment assumption, not a protocol property.

- **In-threat-model?** Yes — this is an unaddressed gap. **The construction must specify: who has write access to the on-chain Merkle tree, under what access control, and why operator-key compromise is out of scope for the adversarial-AS game.** Without this, the adversarial-AS resilience argument is asserting a property of the deployment, not the protocol.

---

### Attack 4: RFC 8693 Token Exchange Provides Runtime Scope Narrowing — Axis 2 is Partly Wrong

- **Attack**: RFC 8693 Token Exchange allows an agent, at the moment it decides to access a specific RS, to exchange a broad-scope token for a *narrowed-scope token* targeting exactly that RS with exactly the required scopes. Flow: (1) agent holds a broad `urn:ietf:params:oauth:token-type:access_token` with `scope: "read write financial"`, (2) agent calls AS with `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, specifying `requested_token_type`, `audience=RS₂`, `scope=read financial_small`, (3) AS issues a narrowed token; (4) agent presents it to RS₂ with DPoP binding. The construction's §8 Axis 2 claims the baseline "cannot express runtime-adaptive predicates" but RFC 8693 explicitly moves scope selection to the moment of access, not credential issuance. The RFC 7662 veteran has been doing this since 2021. The `requiredScopeMask` in Bolyra is equivalent to the `scope` parameter in the exchange request — the RS communicates what it needs, the agent fetches a token matching that exact scope set.

- **Why it fails against the construction**: RFC 8693 *still requires an AS roundtrip* — the exchange call contacts the AS at the moment of access. This breaks the AS-blind property (Axis 1). More critically: with an adversarial AS, the AS can issue a token claiming `scope: "financial_unlimited"` for an agent that was enrolled with only `read`. The RS has no cryptographic check that the agent's actual permission set contains the claimed scopes — it trusts the AS's introspection response or JWT. The construction's proof binds the scope-satisfaction result to a private bitmask that was cryptographically committed at enrollment time (via Poseidon5 and Merkle inclusion), which an adversarial AS cannot retroactively alter. Additionally, the RS in Bolyra *independently selects* `requiredScopeMask` — in RFC 8693, it's the agent that selects scopes in the exchange request (the RS signals requirements out-of-band, not as a cryptographically bound parameter in the proof).

- **In-threat-model?** No — the construction survives on the AS-blind and adversarial-AS axes. **However, the construction's §8 Axis 2 claim ("runtime-adaptive predicate is inexpressible") is imprecise: RFC 8693 is a counterexample for honest-AS deployments. The construction should qualify: "the baseline cannot achieve RS-specified runtime predicates over cryptographically hidden bitmasks without an AS roundtrip."** As written, the claim invites this exact RFC 8693 objection from any OAuth WG reviewer.


## Persona: spiffe_engineer

---

### Attack 1: "You replaced the AS with a trusted setup ceremony — that's a worse trust anchor"

**Attack:**
The construction's adversarial-AS resilience claim (§3 Game 3, §8 Axis 1) rests on: "A compromised AS cannot alter the agent's enrolled credential commitment." True. But the RS's assurance that a proof is valid derives entirely from the Groth16 verification key, which was produced by a *project-specific trusted setup ceremony* using `pot16.ptau`. Per the spec, the `AgentPolicy` and `Delegation` zkeys require this ceremony, and it is explicitly noted in CLAUDE.md as project-specific (as opposed to the Semaphore v4 ceremony reuse for `HumanUniqueness`).

Whoever generated the `AgentPolicy.zkey` holds toxic waste that, if not destroyed, permits arbitrary proof forgery — including forging `permissionBitmask & requiredScopeMask == requiredScopeMask` for *any* bitmask. The circuit constraints are meaningless if the setup is compromised. The Groth16 verifier on-chain cannot distinguish a real proof from a trapdoor-forged one.

**Why it works / why it fails:**
The construction's threat model (§3) enumerates adversary capabilities but notably excludes the trusted setup party from the adversary model entirely — it treats Groth16 knowledge soundness as a named assumption (A1, §4) without modeling what happens if the ceremony is compromised. In an OAuth deployment, "the AS is the trust anchor" is well-understood and monitorable via audit logs. A zkey ceremony is a one-time event; if the toxic waste escaped, you won't know until a forged proof surfaces. SPIFFE's root CA compromise is at least a well-exercised incident response scenario.

Additionally, the construction claims PLONK as an alternative (§2, circuit cost table) because it has a *universal* setup (no per-circuit ceremony). But the proving time comparison favors Groth16 (~0.5s rapidsnark vs. ~5s PLONK), and the construction's default is Groth16. The construction should either: (a) mandate PLONK for the adversarial-AS story and pay the latency cost, or (b) enumerate the trusted setup party explicitly in the threat model and require a public, auditable multi-party ceremony (e.g., Hermez-style) for the project-specific zkeys.

**In-threat-model?** **No** — the trusted setup is outside the threat model. The construction survives the *claimed* adversary model but has a gap: an adversary who compromises the ceremony entirely bypasses every game in §3. This needs to be addressed, either by switching to PLONK universally or by citing a specific public ceremony.

---

### Attack 2: "Your on-chain Merkle registry IS your Authorization Server — just wearing Solidity"

**Attack:**
The construction's AS-blindness story (§2 verification protocol step 3, §8 Axis 1) depends on the RS checking `agentMerkleRoot ∈ on-chain root history buffer`. The RS trusts the on-chain registry contract as the ground truth for which agent credentials are valid. The threat model (§3) explicitly excludes the registry contract from the adversary's control, calling it the "trusted smart contract model."

But the 30-entry circular root history buffer has to be *written to by someone*. That write path is not specified anywhere in the construction. If the registry contract has an owner, admin, or operator role that can call `updateMerkleRoot()`, then that key is functionally identical to an OAuth Authorization Server: it decides which agents are enrolled and therefore who can generate valid proofs that the RS will accept. A compromised registry admin can insert a fraudulent Merkle root containing forged agent credentials — and the RS, faithfully checking `agentMerkleRoot ∈ history buffer`, will accept proofs built against it.

Concretely: in §7 (the credit union scenario), the compliance officer "enrolls an AI agent... into the on-chain agent Merkle tree." Who calls the contract to update the root? If it's a multisig with known signers, those signers are the new AS. The claim "no AS in the verification path" is accurate at the *proof layer* but misleading at the *system layer*.

**Why it works / why it fails:**
The construction handles this partially — on-chain contracts are transparent and auditable in ways that private AS logs are not. Enrollment events are observable on-chain. But transparency is not decentralization. The construction needs to specify: is the root update permissioned (owner key → AS equivalent), governed by a DAO (multisig → committee AS), or based on a smart-contract-enforced enrollment process that itself requires the operator EdDSA signature (in which case, make that explicit and the attack weakens)?

The current construction's threat model says the adversary controls the AS but not the on-chain contract — which dodges the question of who controls the contract. SPIFFE's trust model at least explicitly documents the SPIRE server as the trust root, its CA hierarchy, and its compromise blast radius. The construction should provide an equivalent governance specification for the registry contract.

**In-threat-model?** **No** — the construction explicitly excludes the registry contract from the adversary model without specifying who controls it. This is a gap the construction must address.

---

### Attack 3: "Workload API + short-TTL SVIDs already give you AS-blindness within the window that matters"

**Attack (from §8 Axis 1 directly):**
You claim "AS-blind: generated by the agent at the moment of use with zero AS roundtrips" as a novel property. A production SPIRE deployment gives you this within the SVID TTL window. Here's how:

SPIRE issues X.509 SVIDs with TTLs as short as 1 minute. The SPIRE agent (sidecar, deployed on the same node as the workload) serves SVIDs via the Workload API unix socket — no network roundtrip from the workload's perspective. After initial attestation, the workload calls `FetchX509SVID()` locally and uses the cached SVID for all requests within that TTL. If the SPIRE server goes offline *after* the SVID is issued, the workload continues operating with its cached credential for the full TTL.

For the "adversarial-AS" scenario (§8 Axis 1): a SPIRE server that issues a forged SVID is equivalent to a compromised AS. But a SPIRE deployment with hardware attestation (TPM, AWS Nitro IID, k8s service account tokens) means the *attestation* can't be faked — the server issues the SVID but the attestation evidence is hardware-rooted. The scope claim ("the agent has `FINANCIAL_MEDIUM`") comes from the SPIRE selector policies, which are admin-configured but also auditable.

The actual gap your construction closes is: "what if the SPIRE server is offline *permanently*?" A SVID expires and the agent is dead. In the Bolyra construction, the agent can generate proofs indefinitely as long as the on-chain root is valid. But the construction's `LessThan(64)` expiry check (gadget 8) means credentials expire too — the agent also eventually becomes inoperable if it can't re-enroll. The advantage collapses to: "Bolyra proofs can be generated offline against a stale-but-valid Merkle root for up to 30 root transitions; SPIRE SVIDs can be used offline until TTL expiry." These are operationally comparable.

**Why it works / why it fails:**
This attack doesn't break the ZK construction cryptographically. But it does challenge the *necessity* argument. The construction needs to specify: what is the concrete operational scenario where (a) the SPIRE/AS is unavailable, (b) but the on-chain Ethereum/Base Sepolia RPC is available (for root history verification), and (c) the security properties of the Bolyra construction are strictly better than SPIRE + hardware attestation + short TTL? The Base Sepolia RPC dependency is itself a centralized bottleneck that the construction doesn't address.

**In-threat-model?** **Yes** — the construction's AS-blindness claim survives this attack if you accept that "never requires AS, ever" is a stronger property than "requires AS only for periodic SVID renewal." But the construction should make this comparison explicit rather than comparing only to OAuth RFC 7662, which does not include SPIRE/Workload API.

---

### Attack 4: "Your threat model omits WIMSE — the spec the IETF is actually standardizing for this problem space"

**Attack:**
The construction's baseline comparison (§8) is: `RFC 7662 + jwt-introspection-response + RFC 8693 + RFC 8707 + DPoP + BBS+`. This list conspicuously omits **draft-ietf-wimse-arch** (WIMSE), the active IETF working group chartered specifically for *workload identity in multi-service environments* — the exact problem domain of §7's credit union scenario.

WIMSE's charter includes:
- Workload-to-workload token exchange with delegation
- Binding tokens to workload identity (model hash equivalent: SPIFFE ID encodes runtime identity)
- Selective disclosure extensions (in scope for WIMSE, not yet standardized but chartered)

As a WIMSE co-author: if Bolyra's construction were contributed to the WIMSE WG as a ZK attestor profile, it would: (a) gain IETF interoperability with every SPIFFE-aware RS, (b) avoid requiring RSes to deploy a new on-chain Groth16 verifier, and (c) benefit from IETF's security review process. The construction instead proposes a parallel protocol that every RS must independently adopt.

The specific gap this exposes: §8 Axis 2 claims "bitwise AND over a 64-bit field with cascading implication constraints has no BBS+ extension." This is true *today*. But WIMSE is working on ZK-based selective disclosure extensions. If those extensions land in an IETF RFC before Bolyra achieves adoption, the "no configuration of [RFC list] can match" claim becomes "here is a new RFC that can match."

The construction's five axes would be more robustly defended by engaging WIMSE directly — either showing WIMSE's architecture is structurally incapable of the adversarial-AS model (Game 3 in §3) even with ZK extensions, or by positioning Bolyra as a WIMSE ZK attestor profile rather than a competing protocol. The current construction argues against a deliberately scoped baseline that excludes the most relevant ongoing standards work.

**In-threat-model?** **No** — the omission of WIMSE from the baseline comparison is a gap in the claim scope, not a cryptographic break. But the construction's practical claim to uniqueness is weakened if the WIMSE WG produces a ZK-selective-disclosure workload identity profile. The construction should either engage WIMSE explicitly or stake a claim that is durable against WIMSE succeeding.
