# Tier 3 Adversarial — C3 Delegation audit without exposure

## Persona: auth0_pm

---

### Attack 1: The Central Witness Assembler Destroys the Privacy Claim

- **Attack**: Section 2 lists every private input: all `MAX_HOPS` scopes, all credential commitments, all delegator pubkeys, all EdDSA signatures. *Someone* must assemble this full witness before proving. In the cross-org handoff variant (Section 7), that means NFCU's pipeline operator holds the appraisal vendor's internal delegation details, the vendor's pubkeys, and the vendor's scope values. That is exactly the information the construction promises to hide from the auditor. The prover-is-omniscient assumption is smuggled in silently: privacy is preserved from the *auditor* but not from the *proof assembler*, who by construction sees the entire chain. In any realistic multi-org deployment the proof assembler is one of the parties the system is supposed to protect privacy *from*.

- **Why it works / why it fails**: The construction's Section 4 (CHAIN-PRIVACY game) assumes a single challenger who generates the proof. Real multi-org pipelines have no such trusted aggregator. Either (a) you designate a central aggregator who sees everything — defeating cross-org scope privacy — or (b) you require MPC/collaborative proving across org boundaries, which the construction does not specify and which would add 100×+ proving latency. The privacy claim in Section 8 ("intermediate scopes private") is accurate only when there's a single operator controlling the entire chain; the moment orgs are genuinely independent the claim silently fails.

- **In-threat-model?** No. The threat model (Section 3) explicitly says "the adversary controls up to n−1 of n participants." It does not model a colluding proof assembler or the MPC requirement for cross-org witness construction. Construction must address.

---

### Attack 2: The Root Scope Is Unanchored — Anyone Can Start a Chain From Nothing

- **Attack**: Section 2 defines `rootScopeCommitment = Poseidon2(scopes[0], credCommitments[0])`. This is a commitment to the root scope — not a proof it was legitimately issued. Gadget G4 enforces chain-linking from hop 1 onward via EdDSA signature verification, but hop 0 has no predecessor, so there is no G4 constraint on it. I can construct a chain where scopes[0] = `FINANCIAL_UNLIMITED | ACCESS_PII` (all 8 bits set), derive a valid delegation narrowing from it, generate a valid PLONK proof, and the auditor receives `narrowingHolds = 1`, `policyMet = 1`. The auditor has no way to verify that the root agent was ever legitimately granted those permissions — `rootScopeCommitment` is an opaque Poseidon hash. The on-chain registry is mentioned once in Section 3 setup but is never wired into the circuit constraints.

- **Why it works / why it fails**: The construction claims in Section 8 that the auditor can verify "chain narrowed monotonically" — but monotonic from *what*? An adversarial pipeline operator picks an inflated root scope, proves perfect narrowing from it, and submits a valid proof. The auditor's `policyFloor` check (G7, Section 2) confirms the final hop meets a minimum — it says nothing about whether the root scope was legitimate. This is equivalent to a bank auditor confirming a transaction ledger balanced without checking whether the opening balance was real.

- **In-threat-model?** No. The threat model in Section 3 does not include an adversary who fabricates the root credential commitment. It assumes "enrolled agents" are legitimately registered but provides no circuit-level enforcement of that registration against `credCommitments[0]`. Construction must address by adding a Merkle membership proof against the on-chain registry for the root credential.

---

### Attack 3: The 4-Second Proof Window Means Operators Control Audit Timing and Scope

- **Attack** (cite Section 6): The construction targets `< 4s` PLONK proving (`< 1.5s` with rapidsnark). The Section 7 audit flow says the pipeline operator generates the proof *when the auditor requests it*. This creates an adversarial timing window: the operator selects which chain snapshot to prove at audit time. Unlike Auth0 / WorkOS server-generated audit logs (append-only, tamper-evident, operator-invisible), the Bolyra operator assembles the witness after the fact. They can choose to prove a *historically valid* chain that does not reflect actual runtime behavior — e.g., the live pipeline granted `ACCESS_PII` temporarily then revoked it; the operator proves the non-PII-touching variant. A 4-second window with operator-controlled witness assembly is not audit-grade evidence; it is operator-selected attestation.

- **Why it works / why it fails**: Section 7 does not specify *when* the witness is committed or how runtime delegation events are recorded. WorkOS / Auth0 audit logs are generated at event time by infrastructure the operator does not control. Bolyra's audit is generated on demand by the operator. PLONK's soundness guarantees that *the witness satisfies the circuit* — it says nothing about whether the witness matches what actually happened at runtime. This is a missing layer: a commitment scheme tying witness inputs to on-chain event logs at delegation time, not audit time.

- **In-threat-model?** No. The threat model (Section 3) treats the adversary as a static chain constructor, not as a pipeline operator who controls retrospective witness assembly. Construction must address by requiring each hop to commit (on-chain or via signed timestamp) to its scope at delegation issuance time, and the circuit must verify against those commitments.

---

### Attack 4: The 8-Bit Bitmask Is a Toy Model That Blocks Real Enterprise Adoption

- **Attack**: The construction's entire formalism rests on a 64-bit (extended from 8-bit spec, Section 2) cumulative permission bitmask. Every gadget — G1 (subset check), G7 (policy floor), G8 (narrowing flag), the entire Section 5 primitive mapping — assumes permissions are integers with a fixed bit-implication ordering. Real enterprise MCP deployments use OAuth scopes as strings (`read:accounts`, `write:transactions:acct_*`), RBAC role hierarchies (hundreds of roles, not 8 bits), ABAC conditions (`time < 17:00 AND department = "lending"`), and resource-level permissions. The construction explicitly bounds to 8-bit (spec) or 64-bit (extended) with three hardcoded implication rules (bits 4→3→2). Enterprises cannot map their IAM model into this. An Auth0 enterprise customer has 500+ scopes in their authorization server. Bolyra requires them to discard their IAM model and adopt a custom bitmask scheme — that conversation ends before procurement starts.

- **Why it works / why it fails**: No circuit trick solves this at the product layer. ZK circuits over arbitrary string-set subset predicates exist in theory (Merkle set membership) but the construction does not provide them, and they would increase constraint count by orders of magnitude for realistic scope vocabularies. The claim in Section 1 that this is "usable beyond narrow regulatory niches" is undercut by a permission model that fits only the narrow niche of fixed-vocabulary numeric bitmasks.

- **In-threat-model?** Not applicable as a cryptographic attack, but as a product/GTM constraint it is disqualifying. If the construction cannot handle real enterprise IAM vocabularies, the NFCU deployment scenario (Section 7) is illustrative fiction — NFCU uses a full RBAC model, not 8 bits. Construction must address by specifying a scope vocabulary commitment scheme (Merkle tree of allowed scope strings) and a subset-proof gadget over committed sets, or explicitly scope the claim to bitmask-encodable permission systems and stop claiming general enterprise applicability.


## Persona: cryptographer

---

### Attack 1: Pubkey–Commitment Decoupling Breaks Chain Integrity

**Attack:**
Gadget G4 verifies `EdDSAPoseidonVerifier(delegationToken[i], delegatorPubkeys[i], delegationSigs[i])`. Both `delegatorPubkeys[i]` and `delegationSigs[i]` are **private inputs**. Nowhere in the circuit is `delegatorPubkeys[i]` constrained to equal — or even be derivable from — `credCommitments[i-1]`.

An adversary controlling hops $k$ and $k+1$ can proceed as follows:

1. Generate a fresh key pair $(sk^\star, pk^\star)$ under their control.
2. Set `delegatorPubkeys[k+1] = pk^\star` (arbitrary; never touches the honest hop-$k$ credential commitment).
3. Compute and sign `delegationToken[k+1] = Poseidon4(scopeCommitment[k], credCommitments[k+1], scopes[k+1], expiries[k+1])` with $sk^\star$.
4. The circuit accepts: the EdDSA signature is valid against the provided pubkey, and the delegation token commits to the correct predecessor scope. But the "delegator" is not hop $k$'s honest participant — it is the adversary.

The auditor receives `narrowingHolds = 1` and `chainDigest` binding all scope commitments, but the chain-of-custody is severed: hop $k$'s honest agent never issued the delegation. The claim of "proof that a delegation chain narrowed monotonically" is vacuous without binding `delegatorPubkeys[i]` to `credCommitments[i-1]` via a commitment opening constraint.

**Why it works:** The security argument for Theorem 1 (CHAIN-NARROW-SOUNDNESS) covers *scope subset* violations. It does not cover *identity authenticity* of delegators. G4's EdDSA check proves *someone* signed the token, not the *right someone*.

**Fix required:** Add `credCommitments[i-1] === Poseidon(delegatorPubkeys[i][0], delegatorPubkeys[i][1], delegator_salt[i])` (or equivalent commitment opening) for each active hop $i > 0$.

**In-threat-model? No** — the construction must address this. The stated adversary model assumes A2 (EdDSA unforgeability) but the attack does not require forgery: it uses a valid signature under an adversary-chosen key.

---

### Attack 2: Phantom Root — `rootScopeCommitment` is Unanchored to Any Registry

**Attack:**
`rootScopeCommitment = Poseidon2(scopes[0], credCommitments[0])` is a public output. Nothing in the circuit, the on-chain verifier, or the proof system constrains `credCommitments[0]` to correspond to an agent enrolled in the Bolyra registry with permission level ≥ `scopes[0]`.

Concretely: the adversary chooses `scopes[0] = 0xFF` (all 64 bits set) and `credCommitments[0] = H(adversary_key, adversary_salt)` where the adversary controls the key. They construct a syntactically valid narrowing chain ending at any desired `finalScopeCommitment`. The PLONK proof is accepting, `narrowingHolds = 1`, `policyMet = 1`.

The auditor has proven that *some* chain narrowed monotonically from *some* root. They have not proven the root agent was authorized to hold the claimed permissions.

**Why it works / fails:** The CHAIN-NARROW-SOUNDNESS game (§3) defines winning as producing a proof where `narrowingHolds = 1` but narrowing actually violated. The game says nothing about root legitimacy. The game is too weak — it lets the adversary choose the root freely. A complete soundness game should require: the root `credCommitments[0]` is a commitment to an enrolled identity with verified scope ≤ `scopes[0]` per the registry.

**In-threat-model? No** — the game definition itself is incomplete. The construction conflates *syntactic narrowing* (which the circuit does prove) with *authoritative narrowing from a legitimately-scoped root* (which requires a registry membership proof gadget, e.g., a Merkle inclusion check against an on-chain registry root, as in the `HumanUniqueness` circuit).

---

### Attack 3: Prover-Controlled Salt Enables Cross-Session Chain Correlation

**Attack:**
`chainDigest = Poseidon(salt, Poseidon-chain-of-all-scopeCommitments)` where `salt` is a **private input chosen by the prover** (the pipeline operator), not by the auditor or the registry. Nothing in the circuit constrains the salt to be fresh, random, or unpredictable.

Consider two audit sessions for the same chain (e.g., NFCU runs a compliance audit in January and April). If the operator uses a deterministic salt (e.g., `salt = 0`, or `salt = H(operatorKey)`), then:

- Both sessions produce identical `chainDigest`.
- The on-chain registry can trivially correlate the two audits: same `chainDigest` → same chain structure, same participants (up to chain length).
- An external observer with access to on-chain state learns that the pipeline topology has not changed between the two audit dates, which in the whistleblower variant can be meaningful linkage information.

The `auditNullifier = Poseidon2(chainDigest, auditSessionNonce)` prevents *replay* (same nonce), but replay prevention ≠ unlinkability across sessions.

**Formal statement:** CHAIN-PRIVACY as defined (§3) is a one-session game; it does not define multi-session unlinkability. The zero-knowledge property of PLONK hides the *witness* conditioned on fixed public outputs, but if `chainDigest` is deterministic across sessions due to prover-chosen fixed salt, the public output itself is the leakage vector — and ZK provides no protection over public outputs by definition.

**Fix required:** Either (a) the registry issues a fresh per-audit salt (making salt a public input committed by the auditor before proof generation, similar to `auditSessionNonce`), or (b) the security claim must be weakened to "single-session privacy only." As written, the privacy claim implicitly assumes the prover behaves honestly and samples fresh salts — this is not enforced and should be stated as a trust assumption.

**In-threat-model? No** — the construction must address multi-session correlation. The GENIUS Act compliance scenario (§7, NFCU variant) involves repeated audits of the same pipeline; this is precisely where the attack applies.

---

### Attack 4: Universal SRS Subversion — PLONK's "Ceremony-Free" Claim is Overstated

**Attack:**
The construction justifies using PLONK over Groth16 in §2.3 ("PLONK avoids per-circuit ceremony") and repeats this in §8. This is a correctness claim about the *number* of ceremonies, not about eliminating trust. A universal SRS for PLONK still requires a **one-time multi-party computation** (the Powers-of-Tau ceremony, generating $\{g^{\tau^i}\}_{i \leq d}$ and $\{g^{\alpha \tau^i}\}$ etc.). If any single participant in that ceremony retains the toxic waste $(\tau, \alpha)$, soundness of **every** circuit using that SRS is broken: the attacker can produce accepting proofs for any false statement.

The security argument (Assumption A3: "knowledge soundness of PLONK in the AGM + ROM") is stated in the *algebraic group model*, which models the SRS as honestly generated. The AGM does not capture subverted setup. Under a subverted SRS, A3 is vacuous.

Contrast with `HumanUniqueness` (§2): that circuit reuses the public Semaphore v4 ceremony (Powers-of-Tau, widely audited, 2^20 contributors), which is specified. The `DelegationChainAudit` circuit requires either:

- A new project-specific universal SRS ceremony (unspecified — who runs it? what contribution count? what auditor?), or  
- Reuse of an existing universal SRS (e.g., Hermez ceremony, Aztec ceremony) — which must be cited and justified, and whose constraint bound (2^17 ≤ SRS depth) must be verified.

Neither is specified. The construction says `pot17.ptau` for Groth16 context but relies on an unnamed "universal PLONK SRS at depth 17."

**Why this is distinct from a generic SRS objection:** The specific threat here is subversion by the SRS coordinator. In the NFCU compliance scenario, if NFCU itself hosts the SRS ceremony (plausible for an in-house deployment), NFCU can generate proofs that claim `narrowingHolds = 1` for chains that actually violated narrowing — defeating the entire audit purpose. For the whistleblower variant, a government adversary subverting the SRS can deanonymize the chain by generating fake proofs and observing distinguishing behavior.

**In-threat-model? No** — the adversary model (§3) excludes SRS compromise by assumption ("cannot break knowledge soundness of PLONK"), but gives no justification for why this assumption holds in deployment. A real-world deployment must specify SRS provenance. Stating the theorem "in the AGM" without specifying the ceremony is security theater.


## Persona: cu_ciso

---

### Attack 1: Breach Response Forensics — The Construction Destroys Its Own Audit Trail

- **Attack:** NCUA Part 748 Appendix B and GLBA Safeguards Rule §314.15 require me to identify *what data was accessed by whom* within my breach notification window. I run the NFCU scenario from Section 7: a member's PII leaks from the loan pipeline. My incident response team subpoenas the pipeline logs. What do they get? `finalScopeCommitment: [opaque field element]`, `narrowingHolds: 1`. The construction's privacy guarantee — "the auditor does NOT learn: how many hops, what permissions each hop had, which agents participated" — is *my forensics blackout*. I cannot answer "which tool called accessed this member's SSN at 14:32 UTC" because the circuit was explicitly designed to prevent that answer.

- **Why it works:** The construction treats "auditor" as a compliance verifier checking policy conformance. But post-incident, the NCUA examiner is a forensic investigator. These are different roles with opposite information needs. The `chainDigest` is a commitment to a structure I cannot open. The private `salt` means I cannot even correlate two audit proofs of the same chain without operator cooperation. Section 6's privacy properties are a forensics liability, not a feature.

- **In-threat-model?** **No — construction must address.** The threat model (Section 3) defines the auditor as a party learning only public outputs. It does not model the post-incident forensic auditor who needs to reconstruct events. The construction needs a credentialed-disclosure path: a separate circuit or out-of-band mechanism where the pipeline operator can selectively open the witness to regulators under subpoena, without destroying the default-private audit mode. RFC 7519 audit logs with append-only tamper evidence (something FFIEC CAT Domain 3 actually calls for) need to coexist with the ZK audit path.

---

### Attack 2: NCUA Examiner Explainability — "The Bit Is 1" Is Not Evidence

- **Attack:** I walk into my NCUA IT examination. The examiner pulls up NCUA Part 748 §748.0(b)(2) and asks me to demonstrate my information security controls over AI agent access to member data. I show them the on-chain transaction: `narrowingHolds = 1`, `policyMet = 1`. The examiner asks: "What does that mean? How do I know this is accurate? Who generated the proof? What system of record is this?" I have no answer in any language the FFIEC Cybersecurity Assessment Tool maturity model recognizes. SOC 2 Type II requires *description of controls* that a human reviewer can trace. A PLONK proof is not a control description. It is a mathematical assertion I cannot explain to my board, my examiner, or my cyber insurance underwriter.

- **Why it works:** Section 7's "audit flow" ends at step 4 with the auditor seeing opaque field elements and two bits. The construction assumes a cryptographically literate auditor. NCUA examiners are not. The FFIEC CAT expects controls mapped to documented procedures, not zero-knowledge proofs. My examiner questionnaire for third-party risk (NCUA Letter 01-CU-20) will ask: "Describe the mechanism by which you verify vendor/agent access was within authorized scope." "We have a PLONK circuit" will generate a finding, not close one.

- **Why it partially fails:** The construction does give me two concrete assertions (`narrowingHolds`, `policyMet`) that I could translate into policy language. But the gap is the *documentation layer* — there is no mapping from "PLONK output bit" to "NCUA-recognizable control evidence." Section 5's Bolyra primitive mapping helps engineers; it does not help examiners.

- **In-threat-model?** **No — construction must address.** The construction needs a Regulatory Evidence Package: a human-readable attestation signed by the prover that maps `(narrowingHolds=1, policyMet=1, auditNullifier=X)` to specific policy statements the institution can cite in examination responses. The ZK proof provides the cryptographic guarantee; the attestation provides the examiner-legible evidence. These are separate deliverables.

---

### Attack 3: EdDSA Key Custody Silence — Third-Party Risk Finding Waiting to Happen

- **Attack:** Section 2 lists `delegatorPubkeys[MAX_HOPS][2]` and `delegationSigs[MAX_HOPS][3]` as private inputs. These signatures were produced somewhere by someone's private key. Where? The construction is silent. In my NFCU scenario, each "tool" in the pipeline holds an EdDSA private key that authorizes it to sign delegation tokens. If that key lives in an AWS Lambda environment variable, I have a third-party risk finding under NCUA Letter 08-CU-09 (Vendor Management). If it lives in a browser (your attack prompt: "if it's a browser, you've lost me"), the construction's chain-integrity guarantee collapses entirely — a malicious browser extension extracts the key, forges a delegation token for an arbitrary scope, and produces a valid proof that `narrowingHolds = 1` over a fabricated chain. The circuit verifies EdDSA sigs in-circuit (G4), but if the signing key is compromised pre-circuit, the adversary constructs an honest-looking chain with any scopes they choose.

- **Why it works:** The adversary model in Section 3 assumes A2 (Baby Jubjub DL hardness) but does not model *key management failures*. Key compromise is not a cryptographic break; it's an operational one. My NCUA examiner's third-party risk questionnaire asks where credential signing keys are stored, who has access, what the rotation schedule is, and whether HSM custody applies. The construction answers none of these questions. The EdDSA signing infrastructure is entirely out of scope.

- **Why it partially fails:** Section 3 is explicit that the adversary cannot "break the discrete log assumption on Baby Jubjub." The construction correctly bounds the cryptographic threat. But key custody is an operational threat, not a cryptographic one, and the CISO toolbox is full of operational risk frameworks.

- **In-threat-model?** **No — construction must address.** A conformant deployment must specify: (a) agent signing keys are generated and stored in HSM or TEE, never exported; (b) key rotation cadence; (c) revocation mechanism when a signing key is compromised (the on-chain registry needs a key-revocation path that invalidates proofs signed by a revoked key, not just future proofs). Without this, I cannot complete my vendor management policy assessment for any AI tool vendor I plug into this pipeline.

---

### Attack 4: On-Chain Availability vs. NCUA Operational Resilience Expectations

- **Attack:** Section 7 states the audit proof "is submitted on-chain" and verified "in one on-chain call (~250K gas)." My loan pipeline runs 24/7. My NCUA-mandated Business Continuity Plan requires documented RTOs for systems involved in member-facing transactions. Base mainnet (the production target per `bolyra/CLAUDE.md`) has had periods of elevated gas prices and congestion. More concretely: if my compliance verification call fails because of a gas spike or RPC endpoint outage, does my loan pipeline halt? Or does it continue unaudited? Either answer is a regulatory finding. If it halts: I have a service availability problem. If it continues without audit verification: I have a control bypass problem. The FFIEC CAT Domain 2 (Threat Intelligence) and Domain 4 (External Dependency Management) both require me to assess dependencies on third-party networks I do not control.

- **Why it works:** The construction treats the on-chain verifier as an atomic, always-available primitive. The deployment scenario in Section 7 describes the audit flow but does not specify what happens when the verifier call reverts, times out, or is prohibitively expensive. In contrast, my core processor contract has 99.95% uptime SLA with defined remediation. "Blockchain availability" is not a contractual SLA I can show my board or my examiner.

- **Why it partially fails:** The construction's cryptographic guarantees are not weakened by on-chain unavailability — the proof is valid regardless of whether the chain is congested. The PLONK verifier could in principle run off-chain against a locally cached verification key. But the construction as written (Section 7) makes on-chain submission the audit finality mechanism, which imports all blockchain availability risks.

- **In-threat-model?** **No — construction must address.** The construction needs a defined degraded-mode path: (a) off-chain verification against the published `vkey.json` as a fallback, with the verifier's signature on the result logged to an append-only audit store; (b) explicit SLA language for what "audit finality" means when on-chain submission is delayed; (c) a gas budget and circuit-breaker policy so a gas spike does not create an unaudited production pipeline. Without this, I cannot include this system in my BCP as a controlled dependency.


## Persona: rfc7662_advocate

---

### Attack 1: AS-Side Policy Filter Already Provides Auditor-Blind Narrowing Verification

- **Attack**: RFC 7662 §2 does not require the AS to return the full token payload to the auditor. A well-configured AS enforces monotonic narrowing *at issuance time* via RFC 8693 token exchange policy — it rejects any `requested_token_type` with `scope ⊇ predecessor_scope` — and, when the auditor introspects, returns only `{"active": true, "narrowing_holds": true, "policy_met": true}`. The auditor gets the same boolean result the construction's circuit produces. Zero intermediate scopes, zero participant identities, zero chain length. Section 8's "AS-blind auditing" row claims "RFC 8693 structurally requires the AS at every hop" as if that were a privacy failure — but per-RS filtered introspection policy (§2.4 of RFC 7662) decouples what the AS *knows* from what the auditor *sees*. The AS never has to forward that knowledge.

- **Why it works / fails against the construction**: This attack is partially correct. An AS with narrow-policy enforcement at issuance and filtered introspection at audit time *does* produce auditor-blind results. The construction's genuine differentiator is not "the auditor doesn't see intermediate scopes" — a careful AS policy achieves that — but rather "the AS itself cannot reconstruct the chain even under subpoena." Section 3's adversary model includes AS compromise, but Section 8 doesn't clearly label this as the *load-bearing* gap versus the scope-visibility gap. The construction currently argues them as equivalent, when only the AS-compromise gap is cryptographically irreducible.

- **In-threat-model?** **Yes**, but the construction must tighten its claim. The section 8 comparison row "AS-blind auditing" is currently *incorrect* for a well-configured AS — it should instead read: "auditor-blind *and* AS-blind, resistant to AS subpoena." The ZK advantage is AS-compromise resistance, not auditor privacy per se. Any deployment scenario that doesn't explicitly place the AS in the subpoena-blast-radius makes the ZK claim look like overengineering.

---

### Attack 2: Signed JWT Introspection Response Removes AS from Audit Hot Path

- **Attack**: The construction's Section 8 asserts "A compromised/subpoenaed AS reconstructs the full chain." True — but `draft-ietf-oauth-jwt-introspection-response` breaks this assumption. At chain creation time, the AS signs a compact JWT: `{"sub": "<chain_digest>", "narrowing_holds": true, "policy_met": true, "iat": ..., "exp": ...}`. The AS retains no ongoing state — it can delete the internal audit record immediately after signing. The auditor verifies the AS's public key offline, with no AS hot path. The AS *was* present at issuance but need not be at audit time, and if it purges its logs, subpoena yields nothing. The construction argues RFC 8693 tokens produce "O(n) artifacts" — but a single signed JWT summary is one artifact, same as a PLONK proof.

- **Why it works / fails against the construction**: This closes the "AS from the hot path" gap the construction identifies in Section 8 row 3. However, it doesn't close the witness-authenticity gap: the AS must have seen the full chain to produce the signed JWT. If the AS is compromised *before* it purges logs, or if a court compels log retention, the signed-JWT scheme fails. More importantly, the signed JWT is unforgeable only by the AS's signing key — the auditor is trusting the AS's honesty at signing time. The PLONK proof, by contrast, is trust-free: any PPT verifier with the circuit's verifying key can check it without trusting the prover or any third party. This distinction matters for cross-org audit (Section 7, NCUA scenario): NCUA would have to trust NFCU's AS, whereas a PLONK proof is independently verifiable.

- **In-threat-model?** **Yes** (construction survives), but the construction's chain-length concealment claim in Section 8 is incorrectly attributed as baseline-impossible. A signed JWT summary conceals chain length just as well as MAX_HOPS padding. The surviving differentiator is *prover-side trust-free verification* — the PLONK proof doesn't require trusting any party's policy enforcement, only the circuit's constraint system. This needs to be surfaced explicitly; the current Section 8 conflates it with length hiding.

---

### Attack 3: Witness Authenticity Gap — The Prover Chooses the Scopes

- **Attack**: The circuit proves "there exists a witness `(scopes[], credCommitments[], delegatorPubkeys[], delegationSigs[])` such that the constraint system is satisfied." It does **not** prove "the operational pipeline actually ran with these scopes." The pipeline operator constructs the witness. Nothing in Section 2's public inputs (`auditSessionNonce`, `policyFloor`) or public outputs (`rootScopeCommitment`, `finalScopeCommitment`) binds the private `scopes[i]` values to any on-chain registry entry. An operator running a pipeline that violated monotonic narrowing can instead prove a *different*, compliant chain: set all hops to `scope = READ_DATA`, self-generate EdDSA keys not registered anywhere, produce valid signatures over those fake tokens, and submit a proof where `narrowingHolds = 1`. Gadget G4 verifies signatures against `delegatorPubkeys[i]` — but those pubkeys are private inputs; the circuit doesn't check them against the Bolyra registry. The auditor sees `narrowingHolds = 1` and is satisfied. The actual pipeline was `FINANCIAL_UNLIMITED` all the way down.

- **Why it works / fails against the construction**: This is a genuine gap not addressed anywhere in Sections 2–8. The construction assumes the delegation tokens were signed by registered agents (implying pubkeys appear in the registry), but neither Section 2 (circuit design), Section 3 (threat model), nor Section 4 (security argument) includes a constraint that `delegatorPubkeys[i]` be drawn from a committed registry. Gadget G4 verifies the signatures are internally consistent with those pubkeys, not that those pubkeys correspond to enrolled agents. This makes the proof a statement about a *hypothetical* chain, not the *operational* chain. RFC 8693 has the structural equivalent problem (the AS trusts the delegating party's request), but it also has a solution: the AS checks the delegating party's access token before issuing the exchange. The construction lacks the equivalent on-chain binding.

- **In-threat-model?** **No** — this is a gap the construction must address. A registry-membership circuit gadget (e.g., a Merkle inclusion proof that `credCommitments[i]` appears in the on-chain registered-agent tree) is required in each active hop. Without it, the proof is not a proof of operational compliance; it is a proof of a self-chosen witness. This completely undermines the NCUA audit scenario in Section 7.

---

### Attack 4: Private Salt Destroys Audit Trail Linkability — the Operator Can Generate Inconsistent Audit Proofs

- **Attack**: `chainDigest = Poseidon(salt, Poseidon-chain(scopeCommitments))` where `salt` is a **private** input chosen by the prover. The construction presents this as a privacy feature (Section 2, G6, G8). It is also an audit trail vulnerability. Because the auditor cannot link two `DelegationChainAudit` proofs to the *same* operational chain, an operator can generate two proofs: one for NCUA with `narrowingHolds = 1` (using a compliant witness), and one for internal records with a different witness. The two proofs have different `chainDigest` values (different salts), different `auditNullifier` values, and the auditor has no means to detect they were produced by the same or different chains. RFC 7662 introspection, by contrast, produces a single server-side audit record per token — there is one canonical answer to "did this chain narrow?" regardless of how many times the auditor queries. Pairwise subject identifiers (OIDC PPID) bind the AS's answer to the requesting resource server, preventing the operator from presenting inconsistent views to different auditors. The construction's private salt does the opposite: it enables inconsistent views.

- **Why it works / fails against the construction**: This is a real tension in the design. The salt's privacy property (hiding chain length by making digest pseudorandom) directly conflicts with audit trail uniqueness. The construction could address this by making the salt a public commitment (e.g., derived from a VRF over the pipeline operator's enrollment credential), but that introduces a new dependency not currently in Section 2. Alternatively, a public `chainAnchor` field — a deterministic commitment to the chain's root credential commitment — would allow two proofs to be linked to the same root without revealing intermediate structure. The current design gives the prover complete freedom to choose `salt`, which is equivalent to giving the prover the ability to generate an unlimited number of non-linkable proofs for arbitrarily chosen witnesses.

- **In-threat-model?** **No** — the construction's threat model (Section 3) defines CHAIN-PRIVACY in terms of the auditor not distinguishing two chains with the same endpoints. It does not define a game for *cross-auditor consistency*. Regulatory audit scenarios (Section 7, NCUA) require that the same pipeline produce the same audit result regardless of who asks — a property the private salt actively undermines. The construction must either add a deterministic anchor or acknowledge that each proof is a standalone attestation with no linkability to the operational chain.


## Persona: spiffe_engineer

---

### Attack 1: Unanchored Credential Commitments — The Synthetic Chain Attack

- **Attack**: The construction's `credCommitments[MAX_HOPS]` and `delegatorPubkeys[MAX_HOPS][2]` are purely private inputs with **no in-circuit or on-chain binding to enrolled agents**. G4 verifies EdDSA signatures against the private `delegatorPubkeys[i]` — but those pubkeys are never checked against a Bolyra registry root. I control a single machine. I generate 5 Baby Jubjub keypairs, sign a delegation chain between them (all under my control), set `scopes[0] ⊇ scopes[1] ⊇ ... ⊇ scopes[4]`, and produce a valid `DelegationChainAudit` proof with `narrowingHolds = 1`. The auditor sees opaque field elements and a bit flip. The chain is entirely synthetic — no real multi-party delegation occurred, no real organizational boundary was crossed, no real mandate was issued. The `rootScopeCommitment` is not pegged to any on-chain enrollment record.

  In SPIFFE terms: this is equivalent to presenting an SVID whose trust chain terminates at a self-signed root that isn't in the trust bundle. The handshake verifies; the trust is fabricated.

- **Why it works**: Section 2's public outputs include `rootScopeCommitment = Poseidon2(scopes[0], credCommitments[0])`. The construction provides no mechanism by which the auditor or verifier contract can confirm that `credCommitments[0]` corresponds to an agent registered in the Bolyra on-chain registry. Section 3's threat model states the adversary "cannot forge EdDSA signatures of honest participants" — but a Sybil adversary doesn't forge anyone's signature; they generate fresh honest-looking keys for all participants.

- **In-threat-model?**: **No.** The construction must close this gap. The fix is an additional public output: `rootEnrollmentNullifier` tied to the Bolyra registry's Merkle root for enrolled agents, proving `credCommitments[0]` corresponds to a leaf in the enrollment tree. Without this, the narrowing proof is a proof about a self-contained mathematical object, not about real agent delegation.

---

### Attack 2: Wrong Layer — SPIFFE ZK Attestor Plugin Already Solves This

- **Attack**: SPIRE's node attestation model is plugin-based. The `NodeAttestor` interface accepts arbitrary evidence bundles and returns a SPIFFE ID if the attestation succeeds. I write a `ZKDelegationAttestation` plugin that accepts a `DelegationChainAudit` PLONK proof as attestation evidence, verifies it against the on-chain verifier contract, and issues a normal X.509 SVID to the attesting workload — embedding `narrowingHolds`, `policyMet`, and `finalScopeCommitment` as X.509 extensions (OIDs are cheap). The auditor then uses standard SPIFFE bundle verification. Cross-org handoff uses trust domain federation (`spiffe://nfcu.com` ↔ `spiffe://ncua-auditor.gov`). The whistleblower scenario uses a private trust domain with no external federation endpoint — the SPIFFE model supports air-gapped trust domains natively.

  Section 8's comparison table claims the baseline "structurally requires the AS at every hop." In SPIFFE, the SPIRE server is not on the data path — it issues SVIDs at workload startup, then exits the critical path. There is no AS mediation per-request. The construction's §8 conflates RFC 8693's AS-on-critical-path behavior with SPIFFE's out-of-band attestation model.

- **Why it works**: The construction builds a parallel identity protocol (DID method, Bolyra registry, PLONK verifier contract) that replicates SPIFFE/SPIRE's function at the ZK layer. Every component has a direct SPIFFE analog: enrollment → node attestation, credential commitment → SVID SPKI hash, delegation chain → SVID path hierarchy, cross-org handoff → trust domain federation. The ZK proof adds one capability SPIFFE lacks natively: hiding intermediate scopes from the auditor. But that single capability does not justify a new protocol stack — it justifies a plugin and a `bolyra-spiffe` bridge library.

- **In-threat-model?**: **No, and it's structural.** The construction must either (a) formally specify what it does that a `ZKDelegationAttestation` SPIRE plugin + SPIFFE SVID extension cannot do, or (b) ship as a SPIFFE-compatible layer rather than a competing protocol. The current §8 baseline comparison is against RFC 8693 + BBS+ + WIMSE, conspicuously omitting SPIFFE/SPIRE — the dominant workload identity system in production.

---

### Attack 3: rootScopeCommitment Brute-Force in Service Mesh Context

- **Attack**: In any real SPIFFE deployment, the root agent's workload identity and its authorized scopes are **policy artifacts visible to the mesh**. In NFCU's scenario (§7), the root agent is "a member-facing chatbot" with `READ_DATA | WRITE_DATA | ACCESS_PII`. Service mesh policy (Envoy RBAC, OPA, or SPIRE workload authorization) records this capability set — it's not a secret; it's the policy that governs what the chatbot can do. Given: (1) the auditor knows the root agent's SPIFFE ID (public service directory), (2) the SPIFFE ID maps to a Bolyra `credCommitment` (public registry lookup), (3) the Bolyra permission model has cumulative-bit constraints that limit valid 64-bit bitmasks to a small set. I iterate: `for scope in valid_cumulative_bitmasks: if Poseidon2(scope, known_credCommitment) == rootScopeCommitment: root_scope_found`. The cumulative-bit encoding (§CLAUDE.md, §AgentPolicy constraint 6) constrains bits 4→3→2 implications, and enterprise deployments use a small number of distinct permission profiles. The "opaque field element" is not opaque when one of its two preimage components is recoverable from public registry state.

  The same attack applies to `finalScopeCommitment` when `policyFloor` is tight (e.g., `policyFloor = 0b00000001` means the final scope has bit 0 set; combined with cumulative constraints, the search space shrinks further).

- **Why it works**: Section 4's CHAIN-PRIVACY game assumes the adversary cannot distinguish chains with identical `(rootScopeCommitment, finalScopeCommitment, policyFloor)`. But in realistic deployments, `credCommitments[0]` is not hidden — it's a public registry commitment to the root agent. The Poseidon commitment `Poseidon2(scope, credCommitment)` has a 64-bit first argument, but the cumulative-bit encoding reduces the valid preimage space to O(100) values for 8-bit permissions (the CLAUDE.md model) or O(1000) for practical enterprise 64-bit profiles. The salt in `chainDigest` (G6) protects the digest but does nothing for `rootScopeCommitment` and `finalScopeCommitment`, which are un-salted (§2, public outputs table).

- **In-threat-model?**: **No.** The construction must either (a) add blinding salts to `rootScopeCommitment` and `finalScopeCommitment` (making them `Poseidon3(salt_root, scopes[0], credCommitments[0])` with private `salt_root`), accepting that the auditor can no longer correlate root commitments across audits without the prover's cooperation, or (b) document explicitly that scope values at chain endpoints are assumed public and that the privacy guarantee covers only intermediate hops.

---

### Attack 4: WIMSE Conformance Gap — The Construction Is a Parallel Standard, Not a Contribution

- **Attack**: `draft-ietf-wimse-arch` (WIMSE Architecture) defines workload identity for multi-service, multi-org pipelines. Section 5 of the current WIMSE arch draft scopes token exchange, delegation, and **selective disclosure as open work items**. The correct engineering action — per IETF norms — is to submit a `draft-bolyra-wimse-zknarrowingproof` extension that defines a new WIMSE token type carrying a `DelegationChainAudit` PLONK proof. This keeps the ZK narrowing proof interoperable with existing WIMSE infrastructure (token exchange endpoints, service mesh integration, SPIFFE ID binding) and routes the construction through standards process where the threat model gets adversarial review.

  Section 8's table claims "WIMSE binds workload identity to each hop (visible to verifier)" as a fatal flaw. But WIMSE token exchange (draft §4.3) explicitly allows opaque token formats — a WIMSE token whose body is an opaque ZK proof is valid WIMSE. The claim that WIMSE "cannot conceal chain length" is a property of current WIMSE token types, not of WIMSE architecture — the architecture is extensible by design, and the gap the construction closes is exactly the kind of gap WIMSE working group participants are supposed to address by submitting drafts.

- **Why it works**: The construction's §1 claims superiority over "RFC 8693 + BBS+ + WIMSE baseline" — but WIMSE is a draft, not a fixed baseline. The correct comparison is: does the construction add value that *cannot* be contributed to WIMSE as an extension? The answer is unclear. If `DelegationChainAudit` proofs can be wrapped in WIMSE token exchange responses (they can — WIMSE doesn't prescribe token internals), then the construction is a WIMSE extension, not a competing protocol. Building a parallel DID method, parallel registry, and parallel verifier contract imposes adoption cost on every NFCU/NCUA integrator who already runs SPIFFE/WIMSE infrastructure.

- **In-threat-model?**: **Partially.** The construction is not wrong cryptographically — but it fails the "usable beyond narrow regulatory niches" goal in its `gap_to_close` statement by creating a compatibility island. The construction must either (a) formally demonstrate that WIMSE's extensibility model cannot accommodate `DelegationChainAudit` as a token type, or (b) ship a WIMSE-compatible profile alongside the standalone construction. Absent this, NFCU's infrastructure team will route around it in favor of their existing SPIFFE mesh.
