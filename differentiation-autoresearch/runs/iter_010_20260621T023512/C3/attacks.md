# Tier 3 Adversarial — C3 Delegation audit without exposure

## Persona: auth0_pm

---

### Attack 1: The Auditor Can't Read the Proof — Regulatory Utility Is Theater

**Attack:**
The construction's §7 deployment scenario claims an NCUA examiner can verify that "PII access was confined to authorized hops." But examine what the examiner actually receives as public signals:

- `rootScopeCommitment = Poseidon3(0x87, credCommRoot, r_root)` → opaque blob
- `terminalScopeCommitment = Poseidon3(0x01, credCommUSPS, r_term)` → opaque blob
- `chainLength = 4` → okay
- `chainIntegrityDigest` → opaque fingerprint

The examiner is told: "The chain narrowed." Narrowed *from what* to *what*? Both endpoints are blinded. The construction states (§7, "What examiner learns" column): "Chain started from an enrolled agent with some scope — cannot invert." That's the point — the examiner cannot invert it. So the examiner cannot confirm the root scope was authorized to hold `ACCESS_PII` in the first place, cannot confirm PII access was stripped at hop 2, and cannot confirm the terminal scope `0x01` is actually what NFCU's policy requires for a USPS API call.

The proof proves **narrowing**, not **adequacy**. A chain that starts at `READ_DATA` and narrows to `READ_DATA` is trivially valid but tells the examiner nothing about whether the agent was authorized to start with those permissions. A chain that ends with `FINANCIAL_SMALL` is cryptographically indistinguishable from one that ends with `READ_DATA` — both are just blinded field elements.

**Why it works:** NCUA examination is about *what* permissions exist, not just *that* they narrowed. The construction answers the wrong question while claiming to answer the regulatory question. Auth0's audit logs tell the examiner exactly what scope was granted, to which client, at which timestamp, against which policy — all human-readable, all integrated into SIEM.

**In-threat-model?** No. The construction must address this: either (a) allow selective disclosure of root/terminal scope to the auditor (breaking the privacy claim for the endpoint agents), or (b) explicitly carve the adequacy question out of scope and acknowledge that Bolyra answers *compliance with narrowing policy* but not *compliance with authorization policy*. The §7 NCUA scenario is overclaimed.

---

### Attack 2: Who Generates the Proof, and When?

**Attack:**
The construction is deliberately ambiguous about the temporal model for proof generation, and that ambiguity hides a fatal operational choice.

**Option A — Proof generated at audit time.** The "prover" assembles the audit proof post-hoc from the full chain witness. This means every delegation hop must persist its full private witness (delegatorScope, delegateeCredCommitment, EdDSA signatures, Merkle paths, blinding salts) in recoverable form until an audit occurs — potentially months or years later. Who stores this? In what format? With what access controls? The construction is silent. In the NFCU scenario, this means NFCU's AI pipeline must maintain a cryptographically intact witness store for every agent-to-agent delegation. That's a new infrastructure category the construction doesn't describe.

**Option B — Proof generated inline, at each delegation hop.** Each hop adds ~5 seconds of PLONK proving latency before the next hop can proceed. A 4-hop chain serializes to ~20 seconds of wall-clock latency before the USPS API agent can respond to a member query. The construction's §6 states "< 2.5 seconds" for a 4-hop chain — this is the *proof generation* time, not the *round-trip* for an interactive delegation request. WorkOS issues a delegated OAuth token in <100ms end-to-end, including signature verification.

**Why it works:** The construction's §6 heading "Circuit cost estimate" buries the UX implication. The proving time target is asserted, not benchmarked, and the temporal model for proof generation is unspecified. A procurement team at NFCU will ask: "Does this add latency to member service interactions?" The honest answer, if proofs are inline, is "20 seconds per chain." If proofs are deferred, the answer is "we need you to run a witness archive."

**In-threat-model?** No. The construction must specify the deployment architecture for proof generation — inline vs. deferred — and quantify the operational cost of each. Claiming "<5 seconds" without stating *when in the pipeline* the 5 seconds occur is not a complete engineering claim.

---

### Attack 3: The On-Chain Verifier Is a Fantasy for Financial Regulators

**Attack:**
§7 states: "The examiner verifies the PLONK proof against the on-chain verifier contract." This sentence assumes the NCUA examiner will execute a Base Sepolia transaction or query a deployed Solidity contract. NCUA examiners do not hold Ethereum wallets. They do not submit transactions. They open laptops, connect to NFCU's examination portal, and read PDF reports, spreadsheets, and log exports pulled into SIEM systems.

The construction's verification flow requires: (1) a Base Sepolia RPC endpoint, (2) the deployed `DelegationAuditRollup` verifier contract address, (3) the PLONK proof serialized to calldata, (4) a transaction or `eth_call` to the verifier. None of this exists in any NCUA examination workflow. The `terminalMerkleRoot` check against "on-chain root history buffer" requires the examiner to independently verify the root is in the 30-entry circular buffer — which requires either trusting NFCU's claim or querying the chain themselves.

Auth0's approach: examiners receive a signed audit log export, verify it against Auth0's public key (well-known certificate, no blockchain required), and import it into their existing compliance tooling. The trust anchor is Auth0's SOC 2-certified infrastructure, not a smart contract on an L2 testnet.

**Why it works:** The construction mistakes cryptographic soundness for operational deployability. A proof is only as useful as the verifier's ability to run the verifier. For the NCUA examination use case specifically, the verifier is a human with a compliance checklist, not a smart contract runtime. The construction needs a wrapper — a verification service, a CLI tool, an API — that translates PLONK proof verification into something an examiner can consume. That wrapper doesn't exist in the spec.

**In-threat-model?** No. The construction's entire §7 scenario collapses if the NCUA examiner cannot run the on-chain verifier. This is not a cryptographic problem — it's a product problem that the construction must address before claiming the NCUA use case.

---

### Attack 4: The Procurement Question Kills the Deployment Scenario Before Cryptography Is Relevant

**Attack:**
§7 invokes Navy Federal Credit Union — a $175B institution regulated by the NCUA, subject to FFIEC IT examination procedures, and required by NCUA Letter 07-CU-13 to conduct formal vendor due diligence on any third-party technology used in member data processing. The due diligence checklist for a vendor touching PII in a member service pipeline includes:

- SOC 2 Type II report (annual)
- Penetration test results (annual)
- Business continuity and disaster recovery plan
- Legal entity with general liability insurance
- Data processing agreement meeting GLBA Safeguards Rule
- Incident response SLA (typically <4 hours for PII-related events)
- Financial stability review (audited financials or equivalent)

Bolyra is a solo-founder open-source protocol. It has none of these. The construction's response to "you are a solo founder" is implicitly: "but the cryptography is sound." That is not a procurement response. NFCU's vendor risk management team will not evaluate the Poseidon3 security reduction. They will ask for a SOC 2 report and a certificate of insurance, receive neither, and close the ticket.

The construction's baseline comparison table (§8) compares `DelegationAuditRollup` against RFC 8693 + BBS+ on cryptographic properties. The actual competition at a credit union is: Bolyra (no SOC 2, solo founder, unaudited circuit) vs. WorkOS (SOC 2 Type II, enterprise SLA, legal entity, GDPR DPA, dedicated support). The cryptographic comparison is irrelevant until the procurement comparison is won.

**Why it works:** The construction is complete as a cryptographic artifact and incomplete as a product. The gap is not addressable with more constraints or better reductions — it requires organizational infrastructure that doesn't exist. The §7 scenario is the most ambitious possible deployment context (largest US credit union, NCUA examination) and also the one least likely to adopt a solo-founder ZK library as a compliance dependency.

**In-threat-model?** No. The construction must acknowledge that the NCUA deployment scenario requires either (a) a commercial entity wrapping the protocol with compliance infrastructure, or (b) a different target customer — perhaps a developer tool used by WorkOS/Auth0 *themselves* to implement the ZK primitive, where Bolyra is an upstream library rather than a direct enterprise vendor. The claim as written implies NFCU would evaluate and adopt Bolyra directly, which will not happen at current organizational maturity.


## Persona: cryptographer

*Applied cryptographer. Stance: show me the game, the reduction, and the simulator — or it's marketing.*

---

### Attack 1: Root Delegator Never Enrolled — Enrollment Claim Is False

**Attack.**
Section 1 claims "every participant enrolled in the agent Merkle tree." Section 2 places `BinaryMerkleRoot(MAX_DEPTH=20)` checks only on `delegateeCredCommitment[h]` at each hop. The root delegator (`rootCredCommitment`, a global private input) has **no Merkle membership proof anywhere in the circuit**. No constraint in the gadget list or global constraints section ties `rootCredCommitment` to `terminalMerkleRoot` or any on-chain root.

Concrete attack: the prover creates a Baby Jubjub keypair `(sk*, pk*)` and a fabricated credential commitment `C* = Poseidon5(modelHash*, pk*_x, pk*_y, 0xFF, ∞)` — an unenrolled root agent with all 8 permission bits set. They set `rootScope = 0xFF`, sign `delegationToken[0] = Poseidon4(Poseidon2(0xFF, C*), C_1, scope_1, exp_1)` under `sk*`, and supply `C*` as `rootCredCommitment`. The scope subset and cumulative-bit constraints are trivially satisfiable from `0xFF`. Hop 1's delegatee `C_1` IS in the Merkle tree. The circuit accepts; the PLONK verifier accepts.

**Why it works / why it fails.**
The circuit's chain-consistency constraint (`delegatorCredCommitment[h] = delegateeCredCommitment[h-1]`) only propagates credential bindings *forward* — it does nothing to anchor the *first* delegator. The Merkle check is only `active[h] ⟹ BinaryMerkleRoot(delegateeCredCommitment[h])`. There is no symmetric check for the delegator at hop 0. Knowledge soundness (A1) extracts the witness, but that witness contains an unenrolled `rootCredCommitment` — no assumption prevents this.

**In-threat-model?** No. The construction must add a Merkle membership proof for `rootCredCommitment` with a corresponding public `rootMerkleRoot` signal, checked against on-chain root history. Without it, the foundational enrollment claim in §1 is false, and Game 1 (Scope Expansion Forgery) as stated is not closed: a prover fabricates a root with any scope and then "narrows" from it, producing a formally valid proof for a chain that was never issued by any enrolled agent.

---

### Attack 2: EdDSA Signing Key Is Unbound to the Enrolled Credential — Repudiation Resistance Breaks

**Attack.**
Per §2, the audit circuit takes `delegatorPubkeyAx[h], delegatorPubkeyAy[h]` as **private inputs** and verifies `EdDSAPoseidonVerifier(pubkey, delegationToken[h], sig[h])`. The credential commitment is `Poseidon5(modelHash, opAx, opAy, permBitmask, expiry)` where `opAx, opAy` are the *operator's* public key — the entity that issued the credential. The *agent's* delegation signing key does not appear in the credential commitment formula and is not constrained to match any field therein. There is no circuit constraint of the form:

```
delegatorPubkeyAx[h] === decompress(delegatorCredCommitment[h]).opAx
```

Because the prover supplies `delegatorPubkeyAx[h]` freely, any Baby Jubjub keypair `(sk', pk')` that satisfies `EdDSA.Verify(pk', delegationToken[h], sig')` is accepted. An honest agent who originally signed at hop h under key `K1` and later rotated to `K2` (updating their on-chain credential commitment) leaves a `sig_h` over the original delegation token. A prover assembling the audit proof can present `K1` as the signing key — but `K1` is no longer enrolled (the Merkle tree commits to the credential under `K2`). The circuit does not check `K1`'s enrollment. The chain is valid under the audit verifier even though the signing key corresponds to a revoked identity.

**Why it works / why it fails.**
Repudiation resistance (§8, Table row "Repudiation resistance without identity disclosure") rests on the claim that "each hop's EdDSA signature is verified inside the circuit." Verification is necessary but not sufficient: it proves *a* valid signature exists, not that the signer is the *enrolled* agent. Without `pubkey ↦ credCommitment` binding inside the circuit, a proof author can satisfy the EdDSA gadget with any key that produced a historically valid signature — including keys of departed, revoked, or rotated agents. In the whistleblower variant (§7), this means the journalistic source cannot cryptographically pin a specific enrolled agent to each hop without external evidence; the proof proves honest *chain structure*, not honest *attribution*.

**In-threat-model?** Partially. Game 1 (Scope Expansion Forgery) is not violated — the forged signing key still cannot expand scope because the scope subset constraint is independent of the signing key. But the repudiation resistance claim in §8 is overstated. The construction should constrain `delegatorPubkeyAx[h]` against a field of `delegatorCredCommitment[h]` — either by adding the agent signing key to the credential commitment hash inputs, or by computing `Poseidon2(delegatorPubkeyAx[h], delegatorPubkeyAy[h])` as a commitment and constraining it against a registered key commitment on-chain.

---

### Attack 3: Audit Session Nonce Is Prover-Controlled — `chainIntegrityDigest` Is Not a Unique Fingerprint

**Attack.**
`auditSessionNonce` is listed as **public input 3** — not a public *output* computed by the circuit, not a verifier-supplied challenge. The prover who generates the PLONK proof sets the public inputs. Therefore the prover controls `auditSessionNonce`. The `chainIntegrityDigest` is `Poseidon(delegationNullifier[0], ..., delegationNullifier[7])` where `delegationNullifier[h] = Poseidon2(delegationToken[h], auditSessionNonce)`. Since the prover chooses the nonce:

1. **Same chain, many digests.** The prover submits proof `π_1` with `nonce_1` and `π_2` with `nonce_2` for the same delegation chain — two distinct, verifier-accepted proofs with different `chainIntegrityDigest` values. The auditor cannot detect that both proofs certify the same chain.

2. **Two-chain confusion.** An adversary with two different valid delegation chains `C_A` and `C_B` (differing in an intermediate scope) submits `π_A` and `π_B` to separate regulators using the same `auditSessionNonce`. If the regulators compare digests, they see different values (because the delegation tokens differ) and conclude the chains are different — correct. But if the adversary chooses the nonce to grind toward a digest collision between `C_A` and `C_B`, they can confuse auditors into treating one proof as evidence of the other chain. A birthday bound over the Poseidon output width applies here.

3. **Absent game definition.** Game 1 (§3) does not specify who provides the nonce or whether the nonce must come from a verifiable source. The game allows A to choose any public signals including the nonce. Without a challenge-response binding (auditor sends nonce → prover generates proof), the `chainIntegrityDigest` does not bind the proof to a specific audit event. The §7 claim that "same chain always produces same digest per nonce" is tautologically true but operationally meaningless if the prover controls both the chain and the nonce.

**Why it works / why it fails.**
Under the stated game definition, there is no winning condition that requires `chainIntegrityDigest` to be audit-session-unique. But the **deployment scenario** in §7 implicitly requires it: the NCUA examiner needs a proof that is specific to *this* audit session and cannot be reused. Without a verifier-generated nonce delivered out-of-band (or committed on-chain before proof generation), a regulated entity can present the same audit proof to multiple examinations by simply regenerating with a fresh nonce, invalidating cross-examination audit trail continuity.

**In-threat-model?** No. The construction must specify that `auditSessionNonce` is a verifier challenge generated prior to proof computation (commit-then-prove), and the deployment scenario must require this nonce to be anchored to an audit session identifier (e.g., an on-chain audit registry commitment). Without this, the "fingerprint" is prover-malleable and the §8 "repudiation resistance" claim is circular.

---

### Attack 4: Subverted PLONK SRS Collapses All Security Properties Simultaneously

**Attack.**
Section 2 states PLONK is used "to avoid a per-circuit trusted setup ceremony — the universal `pot16.ptau` SRS suffices." This is correct as far as it goes, but the universal SRS is itself a trusted setup: it requires that the toxic waste `s` (the secret evaluation point of the SRS polynomial) is discarded. If `s` is known to an adversary, the algebraic group model (AGM) guarantees of PLONK collapse entirely.

**Simultaneous soundness failure (Game 1):** With knowledge of `s`, the adversary computes a PLONK proof for any witness, including one where `delegateeScope[h] & ~delegatorScope[h] ≠ 0` at some hop. The forged proof verifies on-chain. The scope expansion forgery game is won.

**Simultaneous ZK failure (Games 2 & 3):** PLONK's ZK property in the ROM assumes the adversary cannot evaluate the committed polynomials at `s`. With `s` known, the adversary evaluates the witness polynomial at `s` from the proof transcript and extracts all private inputs — including every blinding salt `r[h]`, every intermediate scope `delegatorScope[h]`, every credential commitment, and every Merkle path. The §4 argument that "the 254-bit blinding salt prevents brute-force inversion" is entirely vacated: the adversary does not need to brute-force; they read the private input directly from the polynomial evaluation.

For the **whistleblower scenario** specifically (§7): if a state actor participated in or subverted the `pot16.ptau` ceremony, they can both (a) frame sources by forging proofs of non-monotonic delegation, and (b) extract the identities of all participants in any future audit proof. Both attacks are undetectable — a forged proof is computationally indistinguishable from an honest proof without knowledge of `s`.

**Why it works / why it fails.**
The construction cites `pot16.ptau` (§2, §6) but provides no ceremony transcript, no multi-party computation (MPC) protocol reference, no mechanism to verify the SRS was honestly generated, and no key-rotation or SRS-upgrade path. A3 (discrete log on Baby Jubjub) and A2 (Poseidon collision resistance) are both irrelevant if the SRS is subverted — the attack does not require breaking either. The assumption hierarchy in §4 treats A4 (PLONK ZK) as a standalone assumption but does not state it is conditional on an honest SRS; the reduction sketch for Games 2 & 3 therefore has a hole.

**In-threat-model?** No. The threat model in §3 specifies adversary capabilities at the application layer (malicious delegators, curious auditors, repudiating participants) but says nothing about setup trust. The construction must either: (a) reference a specific verifiable MPC ceremony for `pot16.ptau` (e.g., the Hermez/Zcash Powers of Tau ceremony, whose transcript is public) and state its security is conditional on at least one honest participant; or (b) use a transparent-setup variant (e.g., Halo2 IPA or STARKs) for the whistleblower/adversarial-auditor cases where setup compromise must be explicitly excluded from the threat model. As written, the single `pot16.ptau` reference is the load-bearing trust assumption for *all* of the paper's security claims, and it is never given a game definition.


## Persona: cu_ciso

---

### Attack 1: The Examiner Has No Idea What They're Looking At

**Attack:** The construction's §7 deployment scenario tells the NCUA examiner to "verify the PLONK proof against the on-chain verifier contract." The examiner receives six public signals — two blinded commitments they cannot invert, a chain length, a nonce, a hash, and a Merkle root. The construction claims this is the audit artifact. But NCUA Part 748 Appendix B requires an audit trail that documents "what actions were taken, by whom, and when." None of the six public signals answer any of those questions in a form an examiner can read, document in a finding, or reference in a Matters Requiring Attention. The examiner cannot put `Poseidon3(0x87, credCommRoot, r_root)` in an examination report.

**Why it works:** The construction is explicit that intermediate scopes, participants, and credential commitments are hidden. That's the point. But the FFIEC CAT (Logging and Monitoring domain) requires that audit logs be reviewable by the institution's operations and compliance staff — not just mathematically verifiable by a cryptographer running an Ethereum node. The construction conflates "cryptographically verifiable" with "auditor-usable." These are different properties. A PLONK proof is not a log entry.

**In-threat-model?** No. The construction's threat model covers scope expansion forgery, scope extraction, and deanonymization. It does not address the regulatory intelligibility requirement. The construction must address how the ZK proof integrates with a human-readable audit artifact that the examiner can actually cite — otherwise the institution falls back to self-attestation (the baseline it claims to replace) for the narrative layer.

---

### Attack 2: The Prover Controls the Witness — This Is Still Self-Attestation

**Attack:** The construction says the audit proof is generated by "the entity assembling the audit proof from the full chain witness." In §7, that entity is NFCU itself (or its AI pipeline vendor). The prover has access to all private inputs: intermediate scopes, credential commitments, blinding salts, and EdDSA signatures. Nothing in the construction — no on-chain commitment, no third-party oracle, no timestamped log — ties the proof witness to the actual runtime delegation chain. An institution could generate a valid `DelegationAuditRollup` proof for a *fabricated* chain with sanitized intermediate scopes while the production runtime used a different chain with different properties. The PLONK verifier accepts both proofs equally; it only checks internal consistency of the witness, not that the witness matches what actually ran in production.

**Why it works:** The `chainIntegrityDigest` (public signal 4) is `Poseidon` over delegation nullifiers, which are `Poseidon2(delegationToken, auditSessionNonce)`. The `delegationToken` is a private input never published on-chain. The on-chain Merkle tree only confirms that each delegatee was *enrolled*, not that this specific chain *executed* at a specific time with these specific scopes. The only runtime anchor is `terminalMerkleRoot`, which is the root of the entire agent tree at some point in time — not evidence that this chain ran. GLBA Safeguards Rule §314.4(c) requires controls that demonstrate the institution can "detect, respond to, and recover from" security events. That requires evidence of what actually happened, not a proof about what *could have* been valid.

**In-threat-model?** No. The threat model assumes an honest prover ("Prover P generates a valid chain"). It does not consider an institution that generates a proof about a chain other than the one that ran. The construction must address how the runtime delegation chain is committed to an immutable, independently observable record *before* audit-proof generation time — otherwise any ZK audit proof is only as trustworthy as the institution generating it.

---

### Attack 3: NCUA Third-Party Vendor Risk Inventory Requires What the Construction Hides

**Attack:** §7 presents the cross-org handoff (USPS API Agent) as a feature: the examiner cannot see that a third-party vendor participated. But NCUA Part 748 and the 2023 Interagency Guidance on Third-Party Relationships require the CU to maintain a comprehensive inventory of all third-party relationships, perform due diligence on each vendor, and document that oversight in the examination record. If the delegation chain includes a cross-org agent from a third-party vendor (§7 explicitly includes this), and the proof hides that vendor's participation, the CU cannot satisfy its vendor management policy requirements using this proof. Worse: an examiner who suspects the institution is routing member data through undisclosed third parties will find a proof that proves nothing about *who* was in the chain — which reads as evasion, not compliance.

**Why it works:** The construction frames participant privacy as uniformly beneficial. But the CU itself is subject to disclosure obligations to its regulator. The privacy guarantee runs the wrong direction for third-party risk: the CU needs to *demonstrate to the examiner* that it knows who its vendors are and has assessed their risk. A proof that hides vendor identity protects the vendor's competitive information at the cost of the CU's vendor oversight documentation. This is a direct conflict, not a gap in the threat model — it is built into the design.

**In-threat-model?** No. The construction does not distinguish between hiding data from adversaries (correct) and hiding data from the CU's own regulator (a compliance problem). The construction must specify a disclosure mechanism that satisfies §748 vendor documentation requirements without requiring the examiner to see all chain participants — for example, a separate regulatory disclosure channel where the CU reveals vendor identities to the examiner under examination confidentiality, while the public proof remains blinded.

---

### Attack 4: Blinding Salt Custody and Proof Reproducibility Under Subpoena

**Attack:** The per-hop blinding salts are 254-bit random field elements that are private circuit inputs, never stored on-chain, and chosen at proof generation time. The security argument in §3 (Game 2) depends entirely on these salts being unknown to the auditor. But the CU faces a scenario the construction does not address: a regulatory subpoena or court order requires the CU to re-produce or extend the audit evidence. If the salts are not stored, the CU cannot regenerate the same proof (the `chainIntegrityDigest` would change with new salts, breaking the chain fingerprint claim). If the salts are stored, they become a new secret requiring custody, access controls, backup, and key rotation — a new GLBA-regulated secret management surface that the construction does not specify. If the proof generation service is a third-party (the institution's AI vendor), that vendor holds the salts and is a new critical dependency under NCUA third-party guidance.

**Why it works:** §3.3 (Game 3) claims participant deanonymization probability is `≤ 1/|enrolled agents| + negl(λ)`. This bound assumes the auditor never obtains the salts. Under a legal compelled disclosure order, the institution may be required to hand over the salts, at which point the blinded scope commitments become fully invertible. The construction offers no guidance on what the institution does when legally compelled to reveal private inputs. At 2am during an incident response, Tier 1 ops cannot re-run a PLONK proof without the original witness and salts. The construction assumes a single proof generation event; production operations require the ability to re-prove, extend, or dispute audit artifacts over time.

**In-threat-model?** No. The threat model considers a "curious auditor" but only in the context of mathematical extraction from the proof. It does not model legally compelled disclosure of the proving witness. The construction must specify a salt custody architecture, define who holds proving authority, and address the operational workflow for proof regeneration and legal hold — otherwise the privacy guarantee is fragile against exactly the regulatory mechanisms a CU CISO must plan for.


## Persona: rfc7662\_advocate

---

### Attack 1: RFC 9701 Collapses "Offline-Verifiable Without AS"

- **Attack:** Section 8's comparison table row "Offline-verifiable without AS" claims RFC 8693 requires an online AS at audit time. This is false for RFC 9701 (`draft-ietf-oauth-jwt-introspection-response`, now published). Under RFC 9701, the AS produces a **signed JWT** introspection response at delegation time. The RS caches it. An NCUA examiner receives the signed JWT response chain — one per hop — and verifies offline against the AS's public key. No live AS query needed. The construction's strongest marketing claim in §8 ("auditor needs no live AS") is therefore reachable without any ZK.

- **Why it works / why it fails:** It partially works. RFC 9701 eliminates the live AS requirement. It fails on one axis: the signed JWT response still exposes intermediate scope values *to the AS at issuance time*, and if the examiner requests those responses directly, the AS's per-requester redaction policy is the only thing hiding intermediate scopes. That redaction is an AS-trust assertion, not a proof over the actual token content. The ZK proof re-derives narrowing from the delegation token bytes themselves — if the AS lies about redaction or issues a fraudulent assertion, the ZK proof would reject while AS attestation would not. This is a real residual gap, but the construction should explicitly name it: the advantage is **trustless narrowing verification**, not merely offline verification.

- **In-threat-model?** YES — construction survives, but §8 must retract "Offline-verifiable without AS" as a differentiator and restate the claim as "trustless narrowing verification without AS attestation."

---

### Attack 2: PPID + RFC 8707 Resource Indicators Already Break Cross-RS Linkability

- **Attack:** Game 3 (Participant Deanonymization) presents hidden participant identity as a ZK-exclusive property. But OIDC Pairwise Pseudonymous Identifiers (PPIDs, §8 OIDC Core) combined with RFC 8707 audience-bound tokens already prevent cross-RS participant linkability at the RS level — no ZK required. An NCUA examiner querying each RS in the NFCU pipeline (§7) would receive a different `sub` at each hop. They cannot correlate "KYC Verification Tool at RS₁" with "Address Validation Microservice at RS₂" because each RS sees a distinct PPID. The examiner learns only what each RS discloses about its own interaction.

- **Why it works / why it fails:** It works for the RS-query model. It fails for the construction's actual deployment scenario. PPIDs break linkability *between separate RS queries*, but the audit scenario in §7 involves a **single prover generating one artifact** that any verifier can check. PPID requires the auditor to query N RSes independently, with each RS seeing its portion of the chain, and no single RS seeing the full picture. For a cross-org chain (§7, hop 2: third-party Address Validation Microservice), the NCUA examiner cannot even compel the third-party RS to respond. The ZK construction allows NFCU to generate the proof unilaterally — the third-party vendor need not participate in the audit at all. Additionally, PPID breaks RS-to-RS linkability but not AS-to-RS: the AS always sees the canonical `sub`. If the AS is subpoenaed, all PPIDs resolve.

- **In-threat-model?** YES — construction survives, but it must add a scenario-specific defense: "PPID breaks auditor-side linkability only when each RS cooperates; the single-artifact unilateral proof is the load-bearing differentiator for cross-org chains where third-party RS cooperation is unavailable."

---

### Attack 3: "Structural Gap Is Irreducible" Is an Overstatement — Bulletproofs Can Prove Bitwise Subset Over Hidden Inputs

- **Attack:** Section 8's closing paragraph states: "No composition of these standards produces a single offline-verifiable artifact proving monotonic narrowing over hidden intermediate state across organizational boundaries." And §8 claims BBS+ "cannot prove `scope_n ⊆ scope_{n-1}` over hidden bitmasks." This overstates the case. **Bulletproof inner-product arguments** (Bünz et al., 2018) can prove arbitrary boolean predicates over Pedersen-committed values, including per-bit subset constraints. A prover can commit each hop's scope bitmask as a Pedersen commitment, prove each commitment opens to a valid 8-bit value via a range proof, and prove `bit_i(scope_n) ≤ bit_i(scope_{n-1})` for all i via a per-bit inner-product argument over hidden committed values — without revealing any scope. Concatenated across N hops, this produces a single offline-verifiable artifact without any AS.

- **Why it works / why it fails:** Technically, the bitwise subset predicate over hidden Pedersen commitments is achievable in ZK generally — it is not PLONK/Circom-exclusive. The "structural gap is irreducible" claim is wrong as stated. The real gap is one of *succinctness and practical composition*: a Bulletproof multi-hop construction would have proof size O(N·log²M) (where M is the number of constraints per hop), no trusted setup per-circuit, but significantly larger proofs and slower verification than a single PLONK proof. More importantly, Bulletproofs lack the native gadget ecosystem for EdDSA-on-BabyJubjub, Poseidon hashing, and BinaryMerkleRoot that the Bolyra circuit uses — composing them correctly into a single artifact with enrollment proofs is a non-trivial open engineering problem, not just a missing standard.

- **In-threat-model?** NO — the construction must revise §8's closing claim to: "No *standardized* composition of existing OAuth/OIDC specifications produces this artifact; an ad-hoc ZK construction is required regardless of proof system choice, and the PLONK instantiation provides the only production-ready combination of succinctness, trusted-setup universality, and Poseidon/EdDSA gadget availability."

---

### Attack 4: The Prover's Trust Assumption Is Load-Bearing and Unaddressed

- **Attack:** The blinding salt construction (§2) states the prover "chooses all salts" at proof generation time and is "the entity assembling the audit proof from the full chain witness." This entity is a privileged participant: they necessarily possess all private inputs — every intermediate scope bitmask, every credential commitment, every Merkle path. The ZK property guarantees the *verifier* learns nothing from the *proof*. It makes no guarantee about what the prover learns or reveals out-of-band. In the §7 whistleblower scenario, the "source" generating the proof knows the identities of all intermediate agents. If compelled (subpoena, corporate policy, coercion), they can hand over all salts and witnesses, perfectly deanonymizing every participant. DPoP + RFC 8693 has the same weakness — the AS knows everything — but the construction's §7 claims whistleblower-level anonymity without acknowledging that the prover holds a master key to all intermediate state.

  More concretely: the construction does not specify a *distributed proof generation* protocol. A single entity assembling the proof must hold `(delegatorScope[h], delegateeCredCommitment[h], delegatorPubkeyAx[h], blindingSalt[h])` for every hop. In a true whistleblower chain, each intermediate agent would need to contribute their own witness segment without revealing it to the assembler — requiring a multi-party computation (MPC) protocol for proof generation that is entirely absent from the construction.

- **Why it works / why it fails:** The attack correctly identifies a real deployment gap. The cryptographic ZK guarantee is sound — the proof itself leaks nothing — but the prover-trust assumption is unaddressed. The comparison to RFC 8693 in §8 (row: "Journalist/whistleblower anonymity") says Bolyra provides anonymity while RFC 8693 "identifies participants" — but RFC 8693's AS is an institutional trusted party, while Bolyra's prover in the whistleblower scenario is the *source themselves*, who is not trusted by the adversary (the institution). If the source generates the proof on hardware they control and destroys the witness after proof generation, the anonymity claim holds in practice. But the construction must make this operational requirement explicit, or acknowledge that the whistleblower scenario requires an MPC proof-generation protocol outside the current construction scope.

- **In-threat-model?** NO — the construction must add a §9 "Prover Trust" section that (a) specifies who the prover is in each deployment scenario, (b) acknowledges the prover holds all intermediate state, (c) either defines a witness-destruction protocol for the whistleblower case or scopes the whistleblower claim to "single-party prover who controls all hops" and removes the multi-party implication.


## Persona: spiffe_engineer

*Staff engineer, SPIFFE/SPIRE production ops, Fortune 500, co-author WIMSE drafts. Stance: workload identity is solved at the right layer. You are reinventing at the wrong layer.*

---

### Attack 1: The Entire Construction is a SPIRE Attestor Plugin

**Attack:** In SPIFFE, node attestors are pluggable. A custom AI-model attestor can attest `modelHash`, verify an operator EdDSA signature over `(modelHash, permissionBitmask, expiry)`, and issue a JWT SVID with a `scope` claim. WIMSE token exchange (§6 of `draft-ietf-wimse-workload-identity`) already specifies delegated workload-to-workload token exchange where each hop's Authorization Server issues a narrowed-scope token, enforced at issuance. The issuance log is your audit trail. For offline audit, JWT SVIDs are signed JWTs — the auditor verifies signatures offline without an AS. The construction's §8 "offline-verifiable without AS" claim does not distinguish between "proof generated without AS" and "proof verified without AS" — WIMSE achieves the latter.

**Why it works / why it fails:** The construction's actual differentiator — the one claim §8 correctly identifies as irreducible — is *audit without revealing intermediate scope values to the auditor*. WIMSE's auditor sees all scope claims. If NCUA examiners have the right to see scope values (which they do under NCUA examination authority), the privacy property is a non-requirement at the deployment layer. The construction proves a property nobody in the GENIUS Act compliance stack can currently demand.

**In-threat-model?** No — the construction must articulate a concrete regulatory or adversarial scenario where an auditor has *legal authority to verify narrowing* but *not legal authority to see scope values*. As written, §7's NFCU scenario has an NCUA examiner who, under examination authority (12 C.F.R. Part 741), can subpoena the scope values directly. The ZK proof defends against a non-existent attacker.

---

### Attack 2: PLONK Trusted Setup is a Soundness Single Point of Failure; SPIFFE Has None

**Attack:** The soundness proof (§4, Game 1) reduces to Assumption A1: knowledge soundness of PLONK in the Algebraic Group Model + ROM. A1 requires the structured reference string (SRS) to be honestly generated — specifically, that no participant in the Powers of Tau ceremony retained toxic waste (the secret scalar used to construct the SRS). The construction uses `pot16.ptau`. If any of the ~1000+ participants in the Hermez Phase 1 ceremony (or whichever ceremony produced this SRS) retained their randomness, they can forge proofs of monotonic narrowing for chains that *expanded* scope — producing a valid accepting transcript for Game 1's forgery event. The entire enterprise of §4 "Reduction sketch: Soundness" collapses.

Compare: SPIFFE SVIDs reduce to X.509 PKI soundness — if the SPIRE server's CA key is compromised, SVIDs are forgeable. This is the same trust model (a ceremony/keygen event), but X.509 CA compromise is detectable (certificate transparency logs), revocable (CRL/OCSP), and has decades of operational playbook. A compromised `pot16.ptau` is undetectable after the fact and irrevocable for all proofs ever generated under that SRS.

**Why it works / why it fails:** The construction acknowledges PLONK universal setup in §2.3 but does not address the trusted setup ceremony as a security dependency. The §4 proof sketch says "Challenger C sets up the CRS (PLONK universal SRS)" — this silently assumes an honest CRS, which is exactly what a compromised ceremony violates. No mechanism exists to detect a forged audit proof post-hoc if the SRS is compromised.

**In-threat-model?** No — the construction's threat model (§3) defines adversary capabilities as "controls up to N-1 of N agents" and "read access to all public signals." It does not model a compromised SRS. A malicious auditor who also participated in the Powers of Tau ceremony and retained toxic waste sits outside the threat model. The construction must either (a) use a recursion-friendly accumulator scheme that eliminates trusted setup (e.g., Halo2/IPA), or (b) explicitly bound the SRS trust assumption and explain why `pot16.ptau` is acceptable for NCUA examination contexts.

---

### Attack 3: `terminalMerkleRoot` + On-Chain Enrollment History Deanonymizes the Terminal Agent

**Attack:** Public signal 5, `terminalMerkleRoot`, is the Merkle root of the agent tree at the time of the terminal delegatee's enrollment. In a sparse tree with incremental leaf insertion (the standard pattern for Semaphore-style registries), each enrollment transaction changes the root. These enrollment transactions are on-chain and timestamped. An adversary with read access to the on-chain Merkle tree (explicitly granted in Game 3, §3: "A has full read access to on-chain state including the full agent Merkle tree") can reconstruct the enrollment history: root value R_k corresponds to the state after the k-th agent enrolled. Observing `terminalMerkleRoot = R_k` identifies the terminal agent as the k-th enrollee — or, if the root is consistent with only one agent enrolled between R_{k-1} and R_k, uniquely identifies the terminal agent's leaf.

In the NFCU scenario (§7), ~50 agents are enrolled. If enrollments are sparse (one per week, typical for production), each root value corresponds to a single enrollment event. An NCUA examiner can trivially identify which of the 50 agents produced `terminalMerkleRoot` by replaying on-chain enrollment transactions.

The construction's Game 3 analysis (§3) states: "The `terminalMerkleRoot` reveals the Merkle root at the time of terminal delegatee enrollment, but this root corresponds to the entire tree — it does not identify which leaf." This claim is only correct for a continuously growing tree with many simultaneous enrollments. It fails for sparse, production-scale registries where each root value is a unique snapshot.

**Why it works / why it fails:** The ZK argument for intermediate hops is sound — blinding salts protect hops 1 through N-1. But the terminal hop is specifically chosen to expose `terminalMerkleRoot` for on-chain verification (§2, "On-chain: auditor checks terminalMerkleRoot against agent root history buffer"). This is a deliberate design choice that breaks participant anonymity at the terminal position.

**In-threat-model?** Yes, partially — the construction survives if the adversary cannot map root values to enrollment events. But this requires the construction to add a liveness assumption ("sufficiently many concurrent enrollments") that is never stated. For the journalist/whistleblower scenario (§7), terminal agent deanonymization via enrollment history correlation is a critical failure mode — the whistleblower's source is the terminal delegatee, and exposing the terminal agent identity defeats the stated anonymity claim entirely. The construction must either (a) hide `terminalMerkleRoot` and substitute a commitment to root history membership, or (b) restrict the whistleblower scenario to trees with sufficient enrollment throughput to prevent correlation.

---

### Attack 4: Deterministic Delegation Tokens Enable Cross-Audit Session Chain Linkability

**Attack:** The `chainIntegrityDigest` (public signal 4) is defined as:

```
chainIntegrityDigest = Poseidon(nullifier[0], ..., nullifier[7])
nullifier[h] = Poseidon2(delegationToken[h], auditSessionNonce)
delegationToken[h] = Poseidon4(prevScopeCommitment[h], delegateeCredCommitment[h], delegateeScope[h], delegateeExpiry[h])
```

The `delegationToken[h]` is a deterministic function of the delegation chain — it contains no per-audit randomness. Given two audit proofs for the same underlying chain with nonces `n1` and `n2`, both digests are public. Any party who knows the chain (including any chain participant) can compute `Poseidon2(token[h], n_i)` for both nonces and verify that the two digests were produced from the same set of delegation tokens. This establishes a cross-session linkability oracle: "audit session A and audit session B are about the same delegation chain."

In SPIFFE, audit trail linkability is explicit and desirable — SPIRE logs SVID issuance events with workload identity, and correlating two audit events to the same workload is intended behavior. Bolyra's construction claims to provide "repudiation resistance without identity disclosure" (§8 comparison table), but the deterministic digest means a chain participant can correlate any number of audit sessions to the same chain, then use out-of-band knowledge (e.g., "I know I delegated to the USPS agent on date X") to deanonymize the chain across sessions.

**Why it works / why it fails:** The construction's `auditSessionNonce` is intended to bind a proof to a specific audit session, but it only prevents *replay* of an old proof — it does not prevent an adversary from linking two fresh proofs of the same chain. The linkage is through `delegationToken[h]`, which is fixed for a given chain. For the whistleblower scenario specifically: if the journalist publishes an audit proof (public signals visible), and later the institution audits the same chain internally, the institution can compute whether its internal audit digest matches the journalist's published digest with a different nonce — confirming the chain identity.

**In-threat-model?** No — the construction's threat model does not define cross-session unlinkability as a security goal, but §1's claim covers "whistleblower-safe delegation chains" and §7 explicitly states the journalist use case. Cross-session linkability by chain participants directly contradicts the whistleblower safety claim. The fix is straightforward — include a prover-chosen per-audit blinding factor in the delegation nullifier: `nullifier[h] = Poseidon3(delegationToken[h], auditSessionNonce, auditBlindingFactor)` with `auditBlindingFactor` as a private input. This breaks cross-session correlation at the cost of ~8 additional Poseidon2→Poseidon3 upgrades (~800 constraints, well within the 2^17 budget).
