# Tier 3 Adversarial — C2 Cross-scope unlinkability

## Persona: auth0_pm

### Attack 1: The `agentMerkleRoot` is a cross-scope correlator hiding in plain sight

- **Attack:** The adversary (AS colluding with RS-A and RS-B) compares the `agentMerkleRoot` public output across proofs. Section 2 defines `agentMerkleRoot` as a public output on every proof. All proofs from the same enrolled credential share the same root — or more precisely, the root of the same tree snapshot. RS-A receives `(scopeNullifier_A, agentMerkleRoot_X, freshnessBind_A)`. RS-B receives `(scopeNullifier_B, agentMerkleRoot_X, freshnessBind_B)`. The AS, which controls the tree (explicit in threat model §3), can match on `agentMerkleRoot_X` across colluding RS logs and link the two access events to the same enrollment — without inverting any nullifier.

- **Why it works / why it fails:** The IND-UNL-AS game in §3 asks whether the adversary can distinguish `scope_β`. But the game doesn't model the `agentMerkleRoot` as a side channel that directly groups proofs by credential. If the tree has N enrolled agents and the root changes rarely (Section 7 describes a stable SECU deployment), the root version narrows the anonymity set. In a targeted attack the AS can perform a partitioning attack: enroll the agent in a fresh single-leaf tree (or time a root update to isolate the agent), observe one proof, then cross-reference RS logs. The reduction sketch in §4 assumes PLONK simulation and P-CR but never models the root-version grouping attack.

- **In-threat-model?** No — the construction must address this. Either (a) decouple credential proof from tree root by committing to a blinded root or using an accumulator that produces per-agent membership proofs without revealing a shared root, or (b) explicitly bound the anonymity set size and show the partitioning attack fails when N exceeds a threshold. As written, §1's claim of "cryptographically unlinkable" is too strong given the public root correlator.

---

### Attack 2: BIP-32 recovery is a privacy trapdoor for the operator

- **Attack:** Section 7 specifies "BIP-32-derived `agentBlinder` for recovery." BIP-32 hierarchical deterministic derivation means every `agentBlinder` descends from a master seed. In any enterprise deployment — credit union, healthcare — the operator or a custody provider holds the master seed for key recovery (otherwise member lockout is unacceptable). Anyone with the master xprv can derive `agentBlinder` for every enrolled agent, compute `Poseidon2(scope_id, agentBlinder)` for any scope_id, and reconstruct the full merchant graph the construction is supposed to hide. The AS doesn't need to break P-PRF; it can get `agentBlinder` through the recovery path.

- **Why it works / why it fails:** §3 threat model says the adversary "Cannot: ... compromise agent's local `agentBlinder` storage." That assumption breaks the moment BIP-32 recovery is in scope, because recovery requires the master seed to be held somewhere accessible. WorkOS and Auth0 solve enterprise key recovery with HSM-backed key escrow; this construction punts by appealing to BIP-32 without specifying who holds the master seed. The recovery story and the privacy story are in direct conflict and §7 mentions both in the same paragraph without resolving the tension.

- **In-threat-model?** No. The construction must either (a) explicitly restrict the threat model to self-custodied agents with no enterprise recovery, or (b) specify a threshold secret-sharing scheme for the master seed that requires k-of-n AS+operator participation to reconstruct — and then prove the unlinkability claim still holds when k < n collude. As written the adversary gains `agentBlinder` through a legitimate enterprise operational path.

---

### Attack 3: Hiding scope from the AS is a compliance liability, not a feature, for regulated credit unions

- **Attack:** The entire unlinkability claim rests on a threat model where the AS is adversarial and must not see the member's merchant graph (§7, §8 "AS-invisible scope selection"). For federally regulated credit unions this is backwards. NCUA examination rules, BSA/AML obligations, and FinCEN reporting require SECU to maintain complete records of member transactions and authorizations. A credit union AS that cannot see `(member_agent, scope, timestamp)` fails its own compliance audit. The "adversarial AS" framing that is the construction's core innovation is precisely the property that SECU's compliance team will reject in procurement.

- **Why it works / why it fails:** §8 correctly identifies "AS observes scope-to-RS mapping at token issuance time" as an architectural property of OAuth. It frames this as a deficiency. For Auth0/WorkOS customers — which are the enterprises buying MCP auth — AS-visible authorization logs are a required feature for SOC 2 evidence, SIEM integration, and regulator examination. The construction offers no mode where the AS retains a compliant audit trail while the member retains unlinkability from colluding RS pairs. WorkOS ships audit log streaming to Splunk/Datadog on day one; this construction ships a compliance gap on day one.

- **In-threat-model?** No. The construction needs a dual-mode design: a privacy mode (AS-blind) for consumer-facing agents and a compliance mode where the AS sees enough for audit while RS-to-RS correlation is still cryptographically blocked. Without this, the sales motion at any regulated FI stalls at legal review.

---

### Attack 4: 5-second proving time fails real-time payment authorization SLAs

- **Attack:** Section 6 estimates ~12,850 constraints with a "proving time target: < 5 seconds (PLONK agent)." The candidate C2 gap statement says the original pain point is circuits taking ~15s. Section 7 scenario RS-A is a merchant payment gateway (`merchant:payments`). Real-time payment networks — Visa, Mastercard, ACH Same Day, RTP — have authorization latency SLAs of 100–500ms end-to-end. A 5-second ZK proof sits entirely outside that budget. The freshness binding `Poseidon2(scopeNullifier, currentTimestamp)` with 30-second epoch quantization means an agent must generate a fresh proof at every epoch, not cache across requests, compounding the latency problem under load.

- **Why it works / why it fails:** §5 maps `freshnessBind` to replay prevention, which is correct. But the operational consequence is that every payment authorization requires a fresh PLONK prove cycle. Auth0 issues opaque access tokens with 1-hour TTL in <50ms; WorkOS MCP auth returns tokens in <100ms. The construction provides no token-caching mechanism that preserves unlinkability (caching `freshnessBind` across requests leaks timing correlation; not caching imposes the full prove latency on every call). The timing side-channel mitigation (batched proof submission) directly conflicts with real-time authorization — you cannot batch a payment that needs a response in 300ms.

- **In-threat-model?** Yes for the cryptographic claim, but the construction must address operational deployment. It needs either (a) a proof-caching scheme that allows reuse within an epoch without sacrificing unlinkability, or (b) an explicit disclaimer limiting applicability to non-real-time authorization flows (investment portal, bill pay with settlement delay) and dropping merchant payments from §7. Claiming merchant payment gateway as a deployment scenario while requiring 5-second proof generation is a spec inconsistency that any enterprise evaluator will flag immediately.


## Persona: cryptographer

*Applied cryptographer, IACR / CRYPTO / EUROCRYPT. Policy: if the game definition doesn't prove what the claim says, the claim is marketing.*

---

### Attack 1: IND-UNL-AS game does not prove cross-proof linkability — the claimed property

**Attack:** The adversary A observes $k$ proofs submitted to $k$ different RSes during Phase 1, then asks: "Do all $k$ proofs originate from the same agent, or from $k$ distinct agents?" This is the traffic-graph attack described in the C2 claim. A standard traffic analysis adversary does **not** need to distinguish $\text{scope}_0$ vs $\text{scope}_1$; it only needs to decide whether $\pi_1, \pi_2, \ldots, \pi_k$ share a common `agentBlinder`.

**Why it matters:** The IND-UNL-AS game in §3 challenges A to produce a bit β distinguishing which of **two specific scopes** was accessed in a single proof. That is:

> **Defined:** "Which scope did the agent choose, given one proof?"
>
> **Claimed:** "The AS cannot correlate per-agent traffic graphs across arbitrary proof sequences."

These are fundamentally different properties. The defined game is closer to **target anonymity** (hide the choice among two alternatives) than to **linkability resistance** (no PPT distinguisher can determine that $\pi_i$ and $\pi_j$ share a secret). The correct game is a k-challenge anonymity game: the challenger samples either one agent producing $k$ proofs for $k$ scopes, or $k$ independent agents each producing one proof, and the adversary must decide. This is the standard formulation for untraceability (cf. Camenisch-Lysyanskaya, AnonCred literature).

**Why the current construction does not survive:** The reduction in §4 is a PRF reduction against a single challenge query. It does not compose to multi-proof unlinkability because the PRF game says nothing about the joint distribution of $(\text{Poseidon2}(s_1, b), \text{Poseidon2}(s_2, b), \ldots)$ as a **jointly-indistinguishable** set — it only implies each is pseudorandom marginally. While a standard PRF **is** multi-query secure (all evaluations jointly pseudorandom), the reduction sketch doesn't invoke this explicitly, and more critically, the game definition doesn't set it up. A PPT adversary seeing $k$ nullifiers from $k$ scopes — all signed under the same `enrolledLeaf` — has a richer attack surface than the game models.

**In-threat-model?** **No.** The formal definition does not match the informal claim. §1 says "no PPT adversary... can distinguish which of two scopes a challenged agent accessed" — a weaker statement than "cannot build a traffic graph." The construction must either (a) restate the claim to match the game, or (b) upgrade the game to a $k$-unlinkability definition with a multi-query PRF reduction.

---

### Attack 2: Poseidon simultaneously modeled as PRF and as random oracle — incompatible assumptions

**Attack:** PLONK knowledge soundness (§4, KS-PLONK assumption) is proved in the Algebraic Group Model + **Random Oracle Model**, where the Fiat-Shamir hash (typically instantiated with Poseidon in ZK circuits) is treated as a random oracle — meaning the adversary has direct black-box oracle access to every Poseidon query. Separately, the P-PRF assumption treats `Poseidon2(·, agentBlinder)` as a **standard-model PRF**, where the adversary does **not** have oracle access to the underlying function.

These two models are incompatible. In the ROM, the adversary A is given oracle access to the Poseidon random oracle $\mathcal{H}$. Nothing prevents A from submitting $(s_\text{target},\, b^\ast)$ queries for guessed blinder values $b^\ast \in F_p$ and checking whether $\mathcal{H}(s_\text{target}, b^\ast) = \text{scopeNullifier}_A$ (obtained from colluding RS-A). If the `agentBlinder` distribution has any exploitable structure (e.g., BIP-32 derivation as suggested in §7), the adversary can prune candidates with RO queries in $O(|\text{keyspace}|)$ time.

More formally: if Poseidon is the **same function** instantiated as both the PLONK FS oracle and the nullifier PRF, then the PRF assumption is vacuous in the ROM — a PRF in the random oracle model is trivially broken because the adversary *is* the oracle. The construction would need to argue that the PLONK FS hash and the nullifier hash are **domain-separated** and that the PRF security of the nullifier hash survives ROM access to the FS hash. No such argument appears in §4.

**Why it matters for the construction:** §4 lists "KS-PLONK: AGM + ROM" and "P-PRF: Poseidon2(·, agentBlinder) is a PRF" as separate named assumptions, with no discussion of their co-instantiation. The reduction sketch in §4 invokes PLONK ZK simulation (which needs the ROM for FS) while simultaneously invoking P-PRF (which needs standard-model secrecy). These cannot be composed naively.

**In-threat-model?** **No.** The security proof must either (a) use separate Poseidon instances with distinct domain tags for FS hashing vs. nullifier hashing and argue PRF security survives ROM access to the former, or (b) replace P-PRF with a ROM-based pseudorandomness assumption consistent with the PLONK security model.

---

### Attack 3: No explicit domain separation — AS can craft enrollment collisions

**Attack:** `enrolledLeaf = Poseidon2(innerCommitment, agentBlinder)` and `scopeNullifier = Poseidon2(scope_id, agentBlinder)` use **identical function calls** over `(x, agentBlinder)`. The only semantic distinction between enrollment and nullifier computation is that the first argument is `innerCommitment` vs `scope_id`. There is no domain separation constant (e.g., a fixed prefix or domain tag appended to inputs).

An adversarial AS controls all five fields that hash to `innerCommitment`:

```
innerCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)
```

The AS issues credentials and **chooses these five fields**. The attack: the AS attempts to find $(m, K_x, K_y, \text{perm}, T)$ such that $\text{Poseidon5}(m, K_x, K_y, \text{perm}, T) = \text{scope\_id\_target}$ for a target RS it colludes with. If such a pre-image exists, then:

$$\text{enrolledLeaf} = \text{Poseidon2}(\text{scope\_id\_target},\, b) = \text{scopeNullifier\_target}$$

The AS knows `enrolledLeaf` at enrollment time. The colluding RS returns `scopeNullifier_target`. The AS checks equality and immediately identifies the agent — without knowing `agentBlinder`.

**Why it partially fails:** Finding such a Poseidon5 pre-image requires solving a second-preimage problem against P-CR, which is hard. However: (1) the construction's security argument **implicitly** relies on this infeasibility without stating it; (2) if the AS can choose `scope_id_target` freely (pick an RS scope string, hash it), it needs only find **any** Poseidon5 pre-image mapping to that target, which is a generic pre-image attack — hard but not covered by the stated assumptions; (3) if a future Poseidon variant or parameterization weakens collision resistance, this becomes exploitable with no warning from the proof.

**In-threat-model?** **Borderline.** The attack is blocked by P-CR (stated assumption), but the construction relies on it **implicitly**. The fix is cheap: prepend a fixed domain tag to distinguish enrollment from nullifier computation (e.g., `Poseidon2(0x01 || innerCommitment, agentBlinder)` for leaf, `Poseidon2(0x02 || scope_id, agentBlinder)` for nullifier). Without this, the security argument has an unacknowledged dependency on Poseidon5 pre-image hardness that should be stated as a named assumption.

---

### Attack 4: `freshnessBind` is a deterministic same-epoch linkage oracle for colluding RS pairs

**Attack:** The construction quantizes `currentTimestamp` to 30-second epochs to prevent timing side-channels (§3, §7). As a consequence:

```
freshnessBind = Poseidon2(scopeNullifier, epoch)
```

is **identical** for any two proofs from the same agent, for the same scope, within the same 30-second window. Both `scopeNullifier` and `epoch` are public outputs.

A colluding pair (RS-A, RS-B) that both serve the **same** scope (e.g., two different service endpoints of the same merchant) will observe identical `freshnessBind` values when the same agent accesses them within one epoch. The colluding pair immediately concludes: same agent, same scope, same epoch — and the linkage is cryptographically certain (it's an equality check on public outputs), not probabilistic.

More dangerously: the quantized `freshnessBind` is a **replay oracle** within the epoch. A proof submitted to RS-A at second 0 is valid — with identical public outputs — at RS-B at second 29. The `scope_id` public input prevents cross-scope replay, but **same-scope cross-RS replay** within an epoch is not prevented. Neither the circuit (§2 constraints 1–10) nor the threat model (§3) includes a mechanism for RS to enforce per-proof uniqueness beyond nullifier deduplication. The nullifier only prevents double-spending within one RS; `freshnessBind` collisions enable replay to a second RS for the same scope.

**Why it's not fully mitigated by batching:** §3 states "batched proof submission" as a side-channel mitigation. Batching delays proof submission but doesn't eliminate the `freshnessBind` collision — it just shifts when the collision is observed. An adversary can wait for the batch and still check equality.

**In-threat-model?** **Yes, partially.** The same-scope cross-RS replay attack is in-threat-model (the AS colludes with RSes). The construction must either (a) include a per-request nonce from the RS in the circuit (committed before proof generation, not post-hoc), or (b) make `freshnessBind` RS-specific: `Poseidon2(scopeNullifier, Poseidon2(currentEpoch, RS_pubkey))`. As written, §2's `currentTimestamp` (public input, set by "verifier / RS") is the only RS-bound randomness — but it is epoch-quantized, defeating its purpose when multiple RSes share the same epoch.


## Persona: cu_ciso

---

### Attack 1: The Privacy Guarantee Destroys My NCUA Audit Trail

- **Attack:** NCUA Part 748.0(b)(2) requires the credit union to implement monitoring and logging of access to member financial data. My NCUA examiner will hand me a questionnaire asking me to demonstrate that I can reconstruct what systems accessed member accounts, when, and why. Section 7 of the construction explicitly proves that SECU — as the AS — *cannot* link `scopeNullifier_A` (merchant gateway access) to `scopeNullifier_B` (investment portal access) even when colluding with RS-A. That unlinkability guarantee is the *entire point* of the construction. But it is also the exact mechanism that destroys my audit log. I cannot produce a coherent member-level access audit for an examiner because the system is cryptographically designed to prevent me from doing exactly that. When my examiner asks "show me all third-party data access for member ID 4821 in Q3," my answer is: "We cannot, by design."

- **Why it works / why it fails:** The construction's Section 3 (Threat Model) explicitly lists "SECU cannot compute either nullifier without `agentBlinder`" as a *feature*. From an IND-UNL-AS perspective this is a strength. From NCUA Part 748 and FFIEC CAT Domain 2 (Threat Intelligence and Collaboration) this is an unmitigated control gap. The construction offers no mechanism for a lawful, examiner-accessible audit reconstruction path.

- **In-threat-model?** No — construction must address. The IND-UNL-AS game treats the AS as a pure adversary. A real credit union AS is simultaneously a regulated entity with affirmative audit obligations. The construction needs a dual-mode design: cryptographic unlinkability for cross-scope correlation *plus* a member-controlled, examiner-disclosable audit path (e.g., member voluntarily reveals `agentBlinder` under legal hold, or an escrow mechanism). Without this, no NCUA-supervised institution can deploy it.

---

### Attack 2: GLBA Breach Notification Is Impossible

- **Attack:** Under 16 CFR Part 314.4(h) (GLBA Safeguards Rule, amended 2023), I have 30 days to notify the FTC and notify affected members after a breach involving customer financial information. Suppose RS-A (ServiceCU Merchant Gateway) is breached and the attacker exfiltrates every `scopeNullifier_A` and associated payment record. My incident response team calls me at 2am. I need to identify which SECU members had agents connected to RS-A. The construction proves this is cryptographically impossible: `scopeNullifier_A = Poseidon2(scope_id_A, agentBlinder)` and SECU never learns `agentBlinder`. I have a list of nullifiers from a breached RS. I cannot map them back to members. I miss my 30-day window. That is a regulatory enforcement action, not a cryptography paper discussion.

- **Why it works / why it fails:** Section 7 ("AS observes") explicitly states SECU cannot recover `agentBlinder` from `enrolledLeaf`. The reduction in Section 4 proves that mapping nullifiers back to agents breaks P-PRF. The construction is correct — and that correctness is the liability. There is no out-of-band member-to-nullifier registry the AS can use for breach response without retroactively breaking the unlinkability claim.

- **In-threat-model?** No — construction must address. The construction needs a breach-response appendix that specifies how the member asserts "my agent accessed RS-A" in a way that satisfies regulatory notification timelines without requiring the AS to maintain a reversible index. One approach: member-published, member-signed linkage assertions stored off-chain; another: NCUA-supervised escrow of encrypted `agentBlinder` with court-order-only decryption key. Neither is specified.

---

### Attack 3: `agentBlinder` Key Custody Is Hand-Waved Into Oblivion

- **Attack:** Section 7 states "`agentBlinder` is BIP-32-derived for recovery" in a single parenthetical. My NCUA examiner's third-party risk questionnaire asks me to document the key management lifecycle for any cryptographic material protecting member financial access: generation entropy source, storage location, backup procedure, rotation policy, revocation mechanism. "BIP-32-derived" answers none of these. Where does `agentBlinder` live? Section 2 says "agent locally samples `agentBlinder ← F_p`." If this is a browser-based agent, it is in `localStorage` or an in-memory session — neither of which survives a device wipe, browser reset, or app uninstall. When the member calls Tier 1 ops at 2am saying their agent stopped working after a phone upgrade, my support team cannot recover anything: SECU never held `agentBlinder`, and the enrolled Merkle leaf is now orphaned. The member's agent is permanently dead. NCUA Part 748, Appendix B (Information Security Program) requires me to have a documented recovery process for member-facing authentication credential loss.

- **Why it works / why it fails:** The construction correctly avoids giving AS custody of `agentBlinder` — that would break unlinkability. But it offers no specified custody model at all. BIP-32 derivation implies a master seed somewhere, but the construction does not define where that seed lives, how it is backed up, or how revocation of an orphaned Merkle leaf works without re-enrollment. Re-enrollment re-adds a new leaf but does not remove the old one — a depth-20 tree with 1M leaves has no specified nullification path for stale credentials.

- **In-threat-model?** No — construction must address. The construction needs a concrete key management section specifying: (a) derivation path and seed storage (hardware secure element, passkey, or operator-managed TEE), (b) recovery ceremony that does not require AS holding `agentBlinder`, and (c) revocation mechanism that tombstones a Merkle leaf without leaking which leaf belongs to which member.

---

### Attack 4: `scope_id` Namespace Is Uncontrolled — RS Impersonation With No AS Visibility

- **Attack:** Section 7 defines `scope_id = hash("merchant:payments@servicecu.org")`. The AS (SECU) does not authorize which RS identifiers are valid before a proof is generated — the agent selects `scope_id` locally at proof time (Section 8 explicitly calls this "AS-invisible scope selection" as a feature). A malicious operator registers `servicecu-merchant.org` and sets up a rogue RS. The member's agent — or a compromised agent binary — generates a proof against `scope_id = hash("merchant:payments@servicecu-merchant.org")`. The scopeNullifier is distinct and unlinkable. The proof is valid against the Merkle tree (credential membership check passes; scope satisfaction checks the bitmask, not the RS identity). SECU, per the construction, cannot see which RS instances its members' agents are accessing. My NCUA vendor management policy (Part 748, Third-Party Relationships) requires me to maintain an approved vendor registry and prevent member data from flowing to unapproved third parties. The construction makes this enforcement impossible.

- **Why it works / why it fails:** The circuit (Section 2, constraint breakdown) verifies: inner commitment reconstruction, Merkle membership, operator signature, permission bitmask, expiry, nullifier derivation, freshness binding. It does NOT verify that `scope_id` maps to an AS-approved RS registry. The `scope_id` is a public input from the verifier/RS — but the AS never sees it. An RS can claim any `scope_id` it wants; the circuit cannot distinguish legitimate from rogue RS identity.

- **In-threat-model?** No — construction must address. The unlinkability guarantee was designed to prevent the AS from learning the merchant graph. A side effect is that the AS also cannot enforce an approved RS allowlist. The construction needs an RS registry commitment (e.g., a separate Merkle root of approved `scope_id` values, committed to by the AS at enrollment time and verified in-circuit) that allows scope-satisfaction enforcement without revealing which specific scope was proven. This is a meaningful circuit addition and should be in the constraint breakdown.


## Persona: rfc7662_advocate

---

### Attack 1: Merkle Root Version Deanonymization (§2, §3 threat model)

- **Attack:** The AS controls the Merkle tree and publishes `agentMerkleRoot` as a public output. The AS knows the exact state of the tree at every leaf insertion — it enrolled each `enrolledLeaf` itself. When a proof arrives with `agentMerkleRoot = R_k`, the AS identifies that `R_k` is the root after the k-th enrollment. Every agent enrolled after step k+1 is eliminated from the anonymity set. If the tree is updated frequently (agents enroll, leaves expire, the operator rotates), the effective anonymity set for a given root can shrink to O(1). An adversarial AS that processes enrollments sequentially and triggers RS introspection calls immediately after each enrollment can use root-version as a near-unique identifier.

  The construction's threat model (§3) asserts the AS "observes all `enrolledLeaf` values" and "maintains Merkle tree" but grants this capability without accounting for the anonymity-set collapse it enables. The IND-UNL-AS game (§3) says A "receives `enrolledLeaf`, full Merkle tree, and `innerCommitment`" — it already has the information needed to execute this attack without inverting Poseidon.

- **Why it partially works:** The game gives A the full tree, so A can enumerate which root corresponds to which enrollment epoch. The batch size between proof submissions determines the residual anonymity set size. At tree sizes of O(10) concurrent users — realistic for a credit union pilot — K-anonymity collapses to K=1.

- **In-threat-model?** **No — construction must address.** The reduction to P-PRF (§4) proves unlinkability of nullifiers across scopes, but says nothing about linkability via root version. The AS does not need to break Poseidon to execute this attack; it only needs the root timestamp correlation it already has by construction.

---

### Attack 2: Signed JWT Introspection Response Removes AS from Hot Path — Why Isn't That Equivalent? (§8, claim 1)

- **Attack:** Section §8 argues "OAuth requires the AS to issue tokens per-scope; the AS log contains (agent_id, scope, timestamp) for every authorization." This is accurate for opaque tokens with live introspection (RFC 7662 §2). But `draft-ietf-oauth-jwt-introspection-response` (now near-RFC) allows the AS to sign a structured JWT introspection response that the RS caches. Combine with RFC 8693 token exchange: the agent presents a parent opaque token to the AS once; the AS issues a scope-specific signed JWT introspection response. Subsequent RS access uses cached signed responses — the AS is not called again, so the AS sees only the initial exchange, not the downstream RS access pattern. Further, scope can be deferred to the JWT claims rather than embedded at issuance, reducing AS-side scope logging.

  Under this configuration the claim "AS observes scope-to-RS mapping at token issuance time" is weakened — the AS sees one exchange, not per-RS access. Add PPID (OIDC §8.1) so each RS sees a different `sub`, and the RS coalition cannot link subjects across RS either. Where exactly does the construction's unlinkability property exceed this?

- **Why it fails against the construction:** The JWT introspection approach requires the AS to know the scope bundle at token-exchange time (even if it doesn't observe per-RS introspection calls later). An AS that logs `(agent_id, {scope_1, scope_2, ...}, exchange_timestamp)` has the full authorization graph at exchange time, before any RS is accessed. The construction's blinded enrollment means the AS never learns which scopes will be requested — the agent selects scope at proof-generation time with no AS involvement after enrollment. This is the genuine structural gap: scope selection is absent from the AS's view entirely, not just deferred.

- **In-threat-model?** **Yes — construction survives**, but §8 should explicitly name `draft-ietf-oauth-jwt-introspection-response` + RFC 8693 as the closest baseline and articulate why deferred scope (token exchange + cached JWT introspection) still leaks the scope bundle at exchange time.

---

### Attack 3: Freshness Binding Epoch Correlation Under AS+RS Collusion (§3 side-channel extension, §7 step 4)

- **Attack:** `freshnessBind = Poseidon2(scopeNullifier, currentTimestamp)` where `currentTimestamp` is quantized to 30-second epochs. Consider the adversary AS colluding with RS-A and RS-B simultaneously. In epoch T, the agent accesses RS-A → the AS/RS-A observes `(scopeNullifier_A, freshnessBind_A, T)`. In the same epoch T, the agent accesses RS-B → RS-B observes `(scopeNullifier_B, freshnessBind_B, T)`. The AS, even without linking the two nullifiers, observes that exactly two proofs were submitted in epoch T. If the agent is the only active agent in that epoch (realistic for small credit union deployments), the AS knows: "agent X (identified by enrolledLeaf) was active in epoch T, and two proofs were submitted in epoch T." The epoch-level traffic graph is recoverable without breaking any cryptographic assumption.

  The construction proposes "batched proof relay" as a mitigation but does not specify this in the circuit or protocol. `freshnessBind` is computed per-proof and includes `currentTimestamp` — if two proofs are submitted in the same epoch to two RS, the epoch value is identical in both public outputs. Batch relay via a mixnet or proxy addresses the network layer, but the construction's circuit does not enforce batching, and `freshnessBind` is a per-proof public output observable by each RS independently.

- **Why it works:** This attack requires no cryptographic breaks. It operates purely on the timing metadata that the construction explicitly makes public (epoch-quantized `currentTimestamp` in `freshnessBind`). The epoch quantization reduces but does not eliminate the correlation window.

- **In-threat-model?** **No — construction must address.** Section §3 "side-channel extension" claims timing is "addressed by" epoch quantization and batched submission, but the circuit does not enforce batch submission and `freshnessBind` is a public output available to every colluding RS independently. The construction needs either: (a) a mixnet/proxy requirement in the deployment spec (§7) that is cryptographically enforced, or (b) a rate-limiting argument that proves the epoch window exceeds plausible adversarial correlation windows given realistic traffic volumes.

---

### Attack 4: Pairwise Subject Identifiers Already Break Cross-RS Linkability at the RS Level — Why Is the AS-Side Advantage Load-Bearing? (§8, claim 2)

- **Attack:** OIDC Pairwise Pseudonymous Identifiers (PPIDs, §8.1 of OIDC Core) compute `sub = hash(sector_identifier, local_account_id, salt)` per RS. Each RS sees a different `sub` for the same user. Combined with RFC 8707 resource indicators (audience-binding tokens to specific RS), cross-RS correlation at the RS layer is eliminated — RS-A's observations are unlinkable to RS-B's observations even under full RS collusion, because RS-A's PPID is computationally independent of RS-B's PPID under the hash assumption.

  The construction's §8 claim 2 dismisses PPIDs as "AS-computed and reversible." Reversibility is AS-internal: the AS can invert `sub_A → account_id` because it holds the salt. But this only matters if the adversarial AS actively correlates — which it can do in both the PPID baseline and the ZK construction: in the ZK construction, the AS holds `enrolledLeaf` and knows which physical agent enrolled (enrollment required the operator's signature over `innerCommitment`, which the operator knows). The AS can trivially maintain a side-channel mapping `(operator, enrolledLeaf) → physical agent`. Reversibility of the AS-side mapping is therefore equally available in both cases.

  The claim that "OIDC PPIDs are AS-computed and reversible" is true but does not distinguish the constructions if the AS-side correlation capability exists in both.

- **Why it partially fails against the construction:** The genuine differentiator is not PPID reversibility — it is that under ZK blinded enrollment, even AS+RS-A collusion cannot produce `scopeNullifier_B` for a different RS-B, because `agentBlinder` is never transmitted to the AS. Under PPID, the AS can compute `sub_B = hash(sector_B, account_id, salt_B)` without any additional information, since it holds the salt. So the AS+RS-A coalition can predict RS-B's PPID for any target account. Under the ZK construction, the AS+RS-A coalition learns `Poseidon2(scope_A, agentBlinder)` but cannot compute `Poseidon2(scope_B, agentBlinder)` without `agentBlinder`, under P-PRF. This is the load-bearing distinction — but §8 claim 2 does not articulate it in these terms.

- **In-threat-model?** **Yes — construction survives**, but §8 claim 2 mis-states the attack vector. The relevant PPID weakness is not reversibility (which both constructions share at the AS level) — it is that PPID salts are AS-held secrets, so an adversarial AS can precompute all RS-specific PPIDs for any enrolled agent without any additional capability. The construction's §8 should replace "reversible" with "AS can precompute all cross-RS identifiers from the salt, requiring no additional cryptographic capability" to make the argument precise.


## Persona: spiffe_engineer

---

### Attack 1: You Built a SPIRE Plugin, Not a Protocol

- **Attack:** The entire construction can be reframed as a custom SPIRE *workload attestor plugin*. SPIRE's plugin API separates node attestation (what machine am I on?) from workload attestation (what process am I?). A ZK attestor plugin registers a `workloadSelector` that, given a per-workload `agentBlinder` in secure storage, derives a scope-isolated SPIFFE ID `spiffe://secu.org/agent/{Poseidon2(scope_id, agentBlinder)}` at proof time. The SPIRE server issues an X.509 SVID carrying that ID; the SVID rotation cycle is tunable to minutes. The RS verifies the SVID chain against the SECU trust bundle — standard mTLS. No new proving system, no new protocol. Write the plugin.

  The construction's Section 8 "Structural Impossibility" argument targets OAuth's scope-issuance model, not SPIFFE's. SPIFFE does not require the SPIRE server to observe which RS a workload is targeting. Authorization is entirely separated (OPA, Kyverno, SPIRE federation bundles). The AS-observes-scope-selection claim is false at the SPIFFE layer.

- **Why it works / why it fails:** The construction has no response to this because Section 8 compares against OAuth 2.0 / OIDC / BBS+, not SPIFFE. The Poseidon PRF unlinkability argument is identical whether the nullifier appears in a PLONK proof or inside a SPIRE plugin that computes the SPIFFE path component. The cryptographic core is fungible across delivery mechanisms. The adversary is arguing the novel work is in the plugin, not the proof.

  The genuine gap: SPIRE's WorkloadAPI issues SVIDs via a Unix domain socket. The SPIRE agent logs workload attestation events server-side. If the SPIRE server is operated by the AS (SECU runs SPIRE for its member agents), the agent-to-SPIRE interaction produces a log that correlates agent identity with SVID issuance timing per scope — the very leakage the construction claims to eliminate. The construction's Merkle-blinded enrollment model eliminates *this specific log*. That is the real delta, and the construction never argues it.

- **In-threat-model?** Partially. The construction survives if it explicitly scopes its claim against SPIFFE's SVID issuance log side channel. It must add to Section 8: "SPIFFE/SPIRE with a ZK attestor plugin reduces but does not eliminate AS observability; the SPIRE server sees SVID issuance timestamps per workload attestation event. The blinded enrollment model here removes the issuance event from the AS's view entirely." Without that, the attack is unanswered.

---

### Attack 2: WIMSE Already Scoped This Work

- **Attack:** draft-ietf-wimse-arch §3 defines the *workload* as the subject and explicitly covers token exchange from an initial credential to a target-service-bound credential. §4.3 of current WIMSE drafts discusses per-target derived tokens. A WIMSE-conformant deployment with blind-issued derived tokens (BBS+ or blind RSA) satisfies the informal claim: the AS signs a derived credential for target RS-A without learning which RS the workload is targeting, if the workload blinds the RS identifier before presenting it to the AS for signature. The formal unlinkability property (your IND-UNL-AS game) is not defined in WIMSE yet — but that is a contribution to an IETF WG, not justification for a new protocol.

  The adversary's ask: submit a WIMSE-arch issue, propose the IND-UNL-AS game as a formal security property, and propose the blinded enrollment + scope-isolated nullifier as the mechanism to achieve it under WIMSE's token exchange model. The Bolyra circuit becomes a WIMSE profile, not a competing protocol.

- **Why it works / why it fails:** The construction provides no discussion of WIMSE at all (Sections 5-8). The comparison in Section 8 covers OAuth 2.0, OIDC, and BBS+. WIMSE is an active IETF draft specifically for workload identity, in precisely the deployment scenario described (cross-institutional agent access). The adversary's point is procedural and ecosystem-strategic, not cryptographic — but it's the right infrastructure-layer objection: you are duplicating standards work happening in the right venue.

  The construction *does* have a genuine advantage: WIMSE does not yet define a formal security game, and the blinded enrollment gadget (Section 2) is a concrete mechanism WIMSE lacks. However, the construction presents this as if WIMSE does not exist.

- **In-threat-model?** No — this is out of scope for a cryptographic construction document, but it is fatal for the deployment claim. Section 7's SECU scenario will be dead on arrival at any standards-aware credit union CISO who asks "why aren't you filing this with WIMSE?"

---

### Attack 3: The Freshness Binding Is a Timing Oracle That Requires an Unspecified Anonymization Network

- **Attack:** `freshnessBind = Poseidon2(scopeNullifier, currentTimestamp)` is a **public output** of the circuit (Section 2, Public outputs table). The construction quantizes `currentTimestamp` to 30-second epochs and claims "batched proof submission" as mitigation (Section 3, Side-channel extension). But the circuit *enforces* `currentTimestamp < expiryTimestamp` via `LessThan(64)` in-circuit (constraint 8), which means the RS must validate that `currentTimestamp` matches wall clock time to within acceptable drift. In practice, proofs presented with a `currentTimestamp` more than ~30 seconds stale are rejected. This makes the 30-second epoch quantization the effective anonymity set window.

  In the SECU deployment scenario (Section 7), off-peak hours at a regional credit union: if one member agent accesses RS-A at 02:17 local time, the anonymity set for that 30-second epoch at RS-A is likely 1. The AS observing proof relay timing (even without breaking ZK) can correlate enrollment → RS-A access → RS-B access by the time-bucket pattern. The "batched proof relay" mentioned in Section 3 is not specified: no mixing service, no relay topology, no k-anonymity floor guarantee. It is an unimplemented deployment assumption.

  In SPIFFE, X.509 SVIDs rotate every hour by default. The SPIRE agent pre-fetches rotations on a schedule, not on demand per target service. This gives a much larger k-anonymity window for timing correlation than 30 seconds.

- **Why it works:** The threat model (Section 3) states the adversary "observes timing and metadata of all proof submissions" but the mitigations against this capability are external to the cryptographic construction. The IND-UNL-AS game (Section 3) does not model timing side channels — the challenger returns proofs without specifying *when*. The reduction in Section 4 is over the PRF, not over timing. A colluding AS+RS that sees (epoch T, enrolledLeaf X at enrollment) + (epoch T+5min window, proof at RS-A) + (epoch T+8min window, proof at RS-B) can correlate without inverting Poseidon. The nullifiers are unlinkable; the *access events* are not.

- **In-threat-model?** Yes, but inadequately addressed. The construction claims timing is mitigated; the mitigation is underspecified and weaker than stated. The IND-UNL-AS game must be extended to an *IND-UNL-AS-timing* variant, or the construction must formally bound the required k-anonymity floor and specify the relay architecture needed to achieve it.

---

### Attack 4: BIP-32 Recovery Breaks the Adversary Boundary

- **Attack:** Section 7 states: "`agentBlinder` — BIP-32-derived for recovery." BIP-32 hierarchical deterministic derivation means `agentBlinder` is derived from a root seed via a deterministic path, e.g. `m/44'/agent_index'`. For recovery to work, the root seed must be backed up. In enterprise credit union deployments, the agent runs on infrastructure the credit union operates — SECU's cloud, SECU's HSM policy, SECU's IT department. The recovery seed is almost certainly in SECU's custody (HSM, key ceremony, break-glass procedure).

  If SECU holds (or can reconstruct) the root seed, SECU can derive `agentBlinder` at any time. The construction's entire unlinkability guarantee collapses: SECU computes `Poseidon2(scope_id_A, agentBlinder)` for any scope it knows about, cross-references against RS-A's nullifier log obtained under collusion, and de-anonymizes the member agent's merchant graph. The cryptographic boundary in Section 3 — "Cannot: ... compromise agent's local `agentBlinder` storage" — assumes the AS is computationally separated from the agent's key storage. That assumption is violated by the recovery mechanism.

  In SPIFFE, this problem is well-studied: the SPIRE agent holds private keys and the SPIRE server never sees them (bootstrap attestation via TPM, node agent, etc.). The key custody question is explicit in SPIRE's threat model. Bolyra's threat model treats `agentBlinder` custody as solved by assumption.

- **Why it works:** The construction conflates the operator (who runs the agent infrastructure) with the AS (SECU). In the healthcare scenario (Section 1, "healthcare agent delegation across providers"), the provider *is* the operator who deployed the agent. Provider-as-operator holds the recovery seed. Provider-as-AS wants to learn the referral network. These are not separated entities — they are the same institution. The IND-UNL-AS game models the AS as an abstract adversary; the game setup says "Challenger C enrolls agent with blinder b" but does not specify who controls the environment in which `b` was generated and stored. If the AS controls that environment, the game is trivially broken before any ZK proof is issued.

- **In-threat-model?** No. The construction must add a key custody threat model sub-section specifying: (a) `agentBlinder` must be generated and stored in an environment the AS cannot access (e.g., TEE, hardware wallet, user-controlled device), (b) recovery via BIP-32 requires the recovery seed to be in the agent's custody, not the operator's, and (c) the deployment scenario in Section 7 must identify which party holds the recovery seed and whether that party is AS-affiliated. Without this, the reduction in Section 4 reduces to a broken assumption.
