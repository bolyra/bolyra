# Tier 3 Adversarial — C1 Selective scope proof

## Persona: auth0_pm

---

### Attack 1: The Procurement Cliff — Solo Founder Can't Pass Credit Union Vendor Due Diligence

- **Attack:** A credit union consortium's procurement team runs vendor due diligence before any software touches member financial data. The checklist is non-negotiable: SOC 2 Type II, penetration test reports, cyber liability insurance riders, indemnification clauses, SLA guarantees with financial penalties, legal entity with audited financials, and references from three comparable institutions. WorkOS and Auth0 have all of these today and can execute a BAA equivalent within a standard procurement cycle. Bolyra is a solo-founder Apache 2.0 project. When procurement asks "who do we sue if this fails and a member's PII is exposed?" — the construction has no answer.

  The construction's Section 7 scenario explicitly targets "Columbia Credit Union — $3.4B in assets, member of the Northwest Credit Union Association." Credit unions of this size are subject to NCUA examination, and NCUA Letter to Credit Unions 24-CU-03 (cited in Section 7) requires due diligence on third-party technology vendors *including* assessment of the vendor's financial viability and support capacity. A solo founder with no revenue cannot satisfy NCUA's third-party risk management requirements, regardless of cryptographic correctness.

- **Why it works:** The construction addresses regulatory *alignment* (NCUA guidance on permissions, FFIEC API security) but not regulatory *procurement* (NCUA third-party due diligence requirements). These are different problems. You can be technically compliant and still be unacquirable by a regulated buyer. The k-of-n governor model requires 7 of 12 consortium members to run governance processes — none of them will sign the on-chain enrollment contract with a vendor that hasn't passed their vendor management program.

- **In-threat-model?** No — the construction must address this. Minimum viable answers: (a) clarify that Bolyra is a protocol, not a vendor — credit unions run their own registry contracts and have no vendor relationship with ZKProva Inc., (b) explicitly frame the procurement relationship as with the circuit auditor (e.g., Trail of Bits) and the integration systems integrator, not with the solo founder, or (c) identify a credit union CUSO or consortium operator (e.g., PSCU, Velera) as the distribution partner who absorbs vendor risk.

---

### Attack 2: Constant-Time Discipline Makes 3 Seconds Your Floor, Not Your Ceiling

- **Attack:** The construction's Section 2 "Agent-side response discipline" mandates: "The agent enforces a fixed wall-clock budget `T_prove`... If proving fails (unsatisfied predicate), the agent sleeps for the full `T_prove`." With snarkjs, `T_prove = 3 seconds`. With rapidsnark, `T_prove = 500 ms`. This is not a performance parameter — it is a **security requirement**. You cannot reduce it below actual proving time without breaking the timing side-channel defense.

  WorkOS MCP auth issues tokens in < 100ms. Cloudflare Access terminates at the edge in < 50ms. The attack is not "your proofs are slow" — the attack is: **you have made latency a cryptographic invariant**. An operator who wants 100ms response times cannot configure `T_prove = 100ms` unless rapidsnark reliably proves in < 100ms (Section 6 says < 500ms). An operator who deploys snarkjs (the common path, since rapidsnark requires a compiled native binary with `BOLYRA_RAPIDSNARK` env configuration) gets a 3-second floor on *every* resource server interaction, including rejections. At 100 agent calls per second, that's 300 concurrent hanging connections minimum — purely from legitimate traffic.

  The Section 6 acknowledgment ("Failed proofs sleep for the full `T_prove` — this is the cost of constant-time discipline") frames this as a known tradeoff. But for a buyer evaluating MCP auth, "your security model requires 3-second minimum latency on every auth check" is not a tradeoff — it is a blocking objection. The buyer compares this against Auth0 Fine-Grained Authorization at < 10ms.

- **Why it works:** The construction correctly identifies the timing side-channel and correctly addresses it via constant-time padding. But the GTM implication is unaddressed: the security model and the performance SLA are in direct tension, and the construction does not provide a path to sub-100ms response times that preserves the side-channel defense. The rapidsnark path gets you to 500ms, but only if the operator has compiled and deployed the native binary — the CLAUDE.md notes this requires `BOLYRA_RAPIDSNARK` env pointing at `circuits/build/rapidsnark_prover`, which is a non-trivial deployment step.

- **In-threat-model?** Partially — the construction acknowledges the cost (Section 6) but does not address the go-to-market implication. The construction should bound the claim: "< 500ms latency floor with rapidsnark, which requires native binary deployment" and acknowledge that snarkjs is dev/test only, not a production path for latency-sensitive deployments. A concrete rapidsnark deployment guide that gets operators to the 500ms tier is required for the claim to be credible to a buyer.

---

### Attack 3: You Replaced AS Availability with L2 Sequencer Availability — and Lost

- **Attack:** Section 7 motivation includes "AS availability: During a CrowdStrike-style outage, Columbia CU's AS goes offline for 14 hours. All consortium agents are locked out." The construction's proposed fix: agents verify against the on-chain Merkle root, eliminating AS dependency.

  But the construction's RS verification protocol (Section 2, step 1) requires: "RS reads `onChainAgentRoot` from the Bolyra on-chain registry (cached, no AS contact)." The word *cached* is doing enormous work here. The construction deploys to Base L2 (CLAUDE.md: "Deploy target chain: Base Sepolia"). Base is an OP Stack L2 with a single centralized sequencer operated by Coinbase. Base Sequencer outages have occurred. When the sequencer is down, the on-chain registry is unreadable, and the RS cannot refresh its cached root. The 30-entry root history buffer (Section 2, enrollment contract, revocation) provides a finite window before roots expire.

  Credit union regulators — specifically NCUA and the FFIEC — have issued guidance on cloud and technology concentration risk. A $3.4B credit union cannot accept availability risk tied to Coinbase's L2 sequencer infrastructure. Auth0 has a 99.99% uptime SLA with financial penalties. Base L2 has no uptime SLA with any credit union consortium. The construction replaced "trust the AS" with "trust the L2 sequencer + Coinbase" — and the latter has zero regulated financial institution credibility and no contractual availability guarantee.

  Furthermore: enrollment costs ~150K gas per credential (Section 6). Gas pricing on Base fluctuates. A surge event (e.g., an NFT mint) can price out consortium enrollment operations. The 12-member consortium's governance flow (off-chain coordination → 7 governor signatures → on-chain transaction) has a minimum latency of hours and a maximum latency of "gas is too expensive today."

- **Why it works:** The adversarial-AS claim in Section 3 is cryptographically sound — the AS is not in the proof verification path. But the operational availability claim is weaker than stated. "AS availability" risk is replaced by "L2 sequencer availability + gas market" risk, and for regulated financial institutions, the latter is *less* acceptable, not more. The CrowdStrike example is compelling until you ask "what happens during a Base outage?" and the answer is "cached root, finite history buffer, then agents fail."

- **In-threat-model?** No — the construction must address this. Minimum viable path: (a) specify a root-caching SLA (e.g., RS must refresh root every N minutes, and the root history buffer must cover M times N), or (b) deploy the registry on Ethereum mainnet with established PoS finality guarantees rather than an OP Stack L2 with a centralized sequencer, or (c) explicitly scope the deployment to use cases where L2 liveness is acceptable and exclude regulated financial institution use cases from the adversarial-AS claim.

---

### Attack 4: The k-of-n Enrollment Bootstrapping Problem — Your Trust Model Requires a Trust Model to Bootstrap

- **Attack:** The construction's adversarial-AS claim depends critically on k-of-n enrollment governance (Section 2, enrollment governance; Section 3, trust model). The security argument in Section 4 (Rogue Enrollment Forgery sub-game) reduces to ECDSA unforgeability only after the governor set is established and operating. But Section 7 shows what bootstrapping this looks like in practice: 12 credit unions, each designating one enrollment governor (typically CTO or CISO), running a consortium governance portal, reviewing credential parameters off-chain, coordinating 7-of-12 signatures, submitting on-chain transactions.

  This is not a deployment — this is a consortium formation. It requires: (a) a legal agreement between 12 institutions specifying governance rights and liabilities, (b) individual institution approval processes (board votes at each CU for participation in a novel technology consortium), (c) KYC/KYB of each governor's signing wallet, (d) HSM procurement or key management policy for governor keys (mentioned in Section 3 as a mitigation but not specified), (e) an off-chain coordination mechanism for enrollment review (the "consortium governance portal" in Section 7 — which does not exist and is not described). Before the first credential is enrolled, all of this must be in place.

  WorkOS MCP auth onboarding: create an account, configure your OAuth client, add the middleware. Time to first token: < 15 minutes. Stytch Connected Apps: similar. Auth0 MCP auth: similar. Bolyra time to first enrolled credential: weeks to months of consortium formation, assuming the credit unions agree to participate at all.

  The construction notes (Section 3): "Deployment MAY designate the same organization as both AS and enrollment governor, but this collapses the trust separation and weakens the adversarial-AS property." This means the only valid deployment for the adversarial-AS claim is multi-organization consortium governance — and that's the hardest possible deployment to bootstrap.

- **Why it works:** The construction correctly identifies that single-organization deployment collapses to "trust the operator" (Section 3). The five-property claim in Section 1 requires adversarial-AS soundness, which requires k-of-n threshold enrollment, which requires consortium governance. There is no path from "solo evaluator" to "full five-property claim" — you either deploy with weak governance (and lose property 1 and the adversarial-AS claim) or you deploy with full consortium governance (and face months of institutional coordination before writing a single line of integration code). The construction does not offer a phased adoption path that gives a single institution meaningful security improvements before the consortium is fully formed.

- **In-threat-model?** No — the construction must address this. The gap is not cryptographic; it is go-to-market. A concrete answer would specify: (a) what the minimum viable deployment looks like for a single institution (what properties are maintained without consortium governance), (b) what the minimum governor count is for meaningful adversarial-AS resistance (e.g., 3-of-5 within a single institution's infrastructure team vs. 7-of-12 across institutions), and (c) what the migration path is from single-institution deployment to full consortium governance, preserving enrolled credentials.


## Persona: cryptographer

I am an applied cryptographer with publications at CRYPTO and EUROCRYPT and reviewing experience at IEEE S&P. I accept no privacy or soundness claim without a game definition, a reduction sketch, and a concrete simulator. I have read your construction carefully. Here are four attacks.

---

### Attack 1: Trusted Setup Completeness Gap — The Adversary Model Excludes the Critical Assumption

**Attack:** The adversary model (Section 3) enumerates what the adversary controls and notably excludes "the RS's local copy of the PLONK verification key." But the verification key is derived from the structured reference string (SRS). PLONK's knowledge soundness holds in the algebraic group model conditioned on an *honestly generated* SRS — the toxic waste `τ` must be erased. If the adversary knows `τ`, she can evaluate the polynomial `Z(X)` directly, compute opening proofs for any claimed evaluation, and produce an accepting proof for a witness that does not satisfy G5. She can prove `permissionBitmask & requiredScopeMask == requiredScopeMask` for a bitmask of her choice, against a credential commitment that is a valid Merkle leaf.

**Why it works / why it fails:** The construction cites `pot16.ptau` as the universal SRS (Section 5) but provides no ceremony reference, no verifiable transcript, and no MPC ceremony record. The Groth16 phase-1 ceremony (Hermez, Aztec Ignition, Iden3) has published cryptographic transcripts. For PLONK with a universal SRS, the same multi-party ceremony transcript is required. Without naming one, the adversary in a subverted-setup scenario can forge any proof; the RS's VK is derived from the same compromised SRS and cannot detect the forgery.

**In-threat-model?** **No.** The game definition in Section 3 does not name the ceremony, does not include an SRS-compromise sub-game, and the reduction sketches in Section 4 assume honest setup without formalizing what ceremony provides this. The construction must either (a) cite a specific MPC ceremony with a verifiable transcript, (b) add a sub-game `RogueSetupForgery` analogous to `RogueEnrollmentForgery` and argue it reduces to discrete log on BN254 under the KZG opening binding property, or (c) adopt a transparent setup (STARK-based commitment) that eliminates the toxic waste entirely. The current text conflates "universal SRS avoids per-circuit ceremony" (true) with "no ceremony is needed" (false, and dangerous).

---

### Attack 2: Implication-Amplified Leakage Contradicts the 1-Bit-Per-Query Privacy Bound

**Attack:** The construction asserts (Section 3, multi-query leakage comparison) that the adversary learns "1 bit per query" — a standard Shannon entropy argument that "each binary observation carries at most 1 bit." This argument is incorrect for a bitmask that is constrained by G6. The adversary, who knows the public circuit, knows that any valid enrolled credential satisfies G6 constraints. Specifically:

```
G6:  permBits[4] * (1 - permBits[3]) === 0    ← FINANCIAL_UNLIMITED → FINANCIAL_MEDIUM
     permBits[4] * (1 - permBits[2]) === 0    ← FINANCIAL_UNLIMITED → FINANCIAL_SMALL
     permBits[3] * (1 - permBits[2]) === 0    ← FINANCIAL_MEDIUM → FINANCIAL_SMALL
```

Valid states for bits 2–4 are: `{000, 100, 110, 111}` — four states carrying `log₂(4) = 2` bits of entropy, not 3. The adversary queries `requiredScopeMask = 0x04` (bit 2, FINANCIAL_SMALL). On **failure**: the circuit rejected, so the enrolled bitmask has `permBits[2] = 0`. By G6 (FINANCIAL_MEDIUM → FINANCIAL_SMALL, and FINANCIAL_UNLIMITED → FINANCIAL_SMALL), `permBits[3] = 0` and `permBits[4] = 0` necessarily follow for any valid credential. One failed query eliminates three of four possible states and reveals the values of **three bits**, not one. The adversary's actual information gain from this single query when the outcome is failure is:

```
I = log₂(|valid states| / |states consistent with failure|) = log₂(4/1) = 2 bits
```

More generally, querying the "base" of any implication chain on failure leaks information about all higher-tier bits simultaneously. The 1-bit-per-query leakage bound, and consequently the `q_max`-bits-per-epoch claim in Section 3, is too optimistic.

**Why it works / why it fails:** The Shannon argument in Section 4 ("each binary observation carries at most 1 bit of Shannon entropy") is correct for unconstrained, uniformly distributed bits. It fails here because G6 reduces the effective entropy of the bitmask below `W` bits. The rate-limit parameter `q_max = 8` is chosen to prevent recovery of the full 64-bit bitmask in one epoch — but with implication-amplified leakage, an adversary can recover more than `q_max` bits of effective information from `q_max` queries, depending on which bits are queried and whether the outcome is a success or failure. The privacy reduction sketch in Section 4 does not account for this: it applies the Shannon argument to independent Bernoulli trials, not to trials over a constrained joint distribution.

**In-threat-model?** **No** (as a privacy claim). The ppSE-IND game is sound per-proof. The flaw is in the multi-query leakage bound, which the construction uses to justify `q_max` as a sufficient epoch defense. The construction must either (a) compute the correct per-query entropy reduction accounting for the implication structure and adjust `q_max` accordingly, or (b) weaken the multi-query leakage claim to "at most `q_max` queries, each revealing at most `log₂(|valid_states| / |states_after_outcome|)` bits, upper bounded by `log₂(W)`." The claim as written overstates the privacy guarantee.

---

### Attack 3: Blinded Nullifier Defeats RS-Side Rate Limiting — A Design Contradiction

**Attack:** The construction states two things in apparent tension. First (Section 2, G9): `agentNullifier = Poseidon3(credentialCommitment, requiredScopeMask, blindingNonce)` where `blindingNonce` is a fresh random field element per presentation. Second (Section 2, verification protocol, step 5): "RS checks `agentNullifier` against a local rate-limit table (optional)." These two statements are incompatible. Since `blindingNonce` is uniformly random per proof, every presentation by the same agent for the same predicate produces a distinct, uniformly distributed nullifier. The RS's rate-limit table is populated with values it has never seen and will never see again — it is a collection of random field elements that carries zero information about re-use. RS-side rate limiting via `agentNullifier` provides **no protection against replays or rate-limit bypasses** at the RS.

The real rate limit is agent-side (Section 2, query budget), which depends entirely on the agent SDK enforcing its own `q_max` counter in memory. The adversary model excludes adversarial control of the agent's SDK, but it does not exclude: a buggy SDK implementation, an operator-triggered agent restart (resetting the in-memory counter), a client-side vulnerability that bypasses the counter check, or a multi-agent deployment where multiple agent instances share a credential but not a counter. Under any of these scenarios, the RS has no cryptographic recourse: the nullifier table is useless, and the "rate-limited to `q_max` bits per epoch" guarantee vanishes.

**Why it works / why it fails:** This is a design-level incoherence, not a cryptographic reduction failure. A rate-limiting nullifier must be *deterministic* given the credential and epoch to allow the RS to detect reuse. The classic Semaphore nullifier `Poseidon2(secret, external_nullifier)` is deterministic — presenting the same signal twice produces the same nullifier, which the RS rejects. Here, fresh `blindingNonce` achieves unlinkability (correct) but destroys the determinism required for RS-side rate limiting (uncorrected design error). The two properties are in fundamental conflict for a single nullifier field.

**In-threat-model?** **No** (as a functional integrity claim). The multi-epoch detection window argument in Section 3 assumes the rate limit holds. If the agent SDK counter is reset (restart, crash, fresh instance), an adversarial RS can conduct unlimited single-bit probing queries across an arbitrary number of epochs. The construction must either (a) separate the unlinkability nullifier (`agentNullifier` with blinding) from a deterministic rate-limit token (epoch-keyed Poseidon commitment without blinding) with the RS checking the deterministic token, or (b) acknowledge that rate limiting is an operational, non-cryptographic control and remove the misleading rate-limit-table step from the RS verification protocol.

---

### Attack 4: Enrollment-Time Bitmask Disclosure to Governors Partially Undermines the Adversarial-AS Privacy Claim

**Attack:** The construction's adversarial-AS claim holds at *presentation time*: the AS is not in the verification path, and a compromised AS cannot forge proofs or inflate scope. But the claim is undermined at *enrollment time*. Section 2 (enrollment governance) states that governors verify: "the requested permission bitmask is consistent with Columbia CU's consortium membership tier" — meaning governors receive the **plaintext** `permissionBitmask` value during the off-chain enrollment review, before approving the EIP-712 signature over the commitment hash. The commitment is `Poseidon5(modelHash, opAx, opAy, permissionBitmask, expiryTimestamp)` — a hash. The governors must receive the preimage to meaningfully verify it; a governor who receives only the hash cannot check "is this bitmask within consortium policy."

Therefore: every enrollment governor who participated in the approval learns the plaintext `permissionBitmask` at enrollment time. In the Section 7 consortium scenario with `n=12, k=7`, up to 12 governors know the full bitmask of every enrolled Columbia CU agent. If any of those 12 governors belongs to the same organization as the AS — or if the AS operator is one of the 12 governors (a deployment the construction permits: "a deployment MAY designate the same organization as both AS and enrollment governor") — then the AS learns the full bitmask out-of-band via the enrollment review, not via breaking the ZK proof.

The construction correctly identifies this as a weakened deployment (it "collapses the trust separation"), but it does not formalize the residual privacy leak. Even in the fully separated deployment: any one of the 11 non-Columbia-CU governors now possesses the plaintext bitmask. A governor who is later compromised, or who shares information with an adversarial RS, leaks the bitmask without breaking any cryptographic assumption. The privacy game ppSE-IND says nothing about this channel — it models the adversary as interacting with proofs, not with enrollment metadata.

**Why it works / why it fails:** The flaw is that the construction's trust model table (Section 3, "Enrollment governor threat model") lists "what a compromised governor (below threshold) can do" as only able to "observe which credential commitments are proposed for enrollment — but `credentialCommitment` is a Poseidon hash, so the governor learns only the hash." This is factually incorrect: the off-chain enrollment review requires plaintext parameter disclosure for meaningful verification (as the construction itself specifies). A sub-threshold compromised governor learns not just the hash but the entire preimage — including the `permissionBitmask` that the ZK proof is designed to hide.

**In-threat-model?** **Partially no.** The adversary model allows control of "up to k-1 of n enrollment governors." The construction's own trust analysis claims a sub-threshold governor "learns only the hash." This is wrong as written: the governor learns the plaintext preimage. The construction must either (a) correct the trust model table to acknowledge that sub-threshold governors learn the plaintext bitmask at enrollment time and address what privacy guarantees remain, (b) replace the plaintext-disclosure enrollment review with a zero-knowledge enrollment proof (an agent proves to governors that its bitmask satisfies consortium policy constraints *without revealing the bitmask*, using a second ZK proof), or (c) limit the privacy claim to "presentation-time AS-blindness" and explicitly carve out enrollment-time governor disclosure as a residual trust assumption.


## Persona: cu_ciso

---

### Attack 1: The Audit Trail Is Cryptographically Blinded — My Examiner Reads English, Not Poseidon Hashes

**Attack:**
I call my NCUA examiner. She asks: "Show me every access to member financial data by your AI agents in the last 90 days. Who accessed what, when, and why?" I pull the RS access logs. They contain `scopePredicateHash = Poseidon4(requiredScopeMask, credentialCommitment, currentTimestamp, blindingNonce)` and `agentNullifier = Poseidon3(credentialCommitment, requiredScopeMask, blindingNonce)`. Both are **explicitly designed to be unlinkable across sessions** (Section 2, G9; Section 3 privacy model: "blinded per presentation, enables rate-limiting without cross-session linkage"). The `blindingNonce` is fresh per proof. I cannot correlate "which agent" across two access events. I cannot tell the examiner whether the entity that accessed member loan data at 14:15 on March 3rd is the same entity that accessed it at 09:22 on March 4th. I cannot produce a human-readable record of "Agent A held permissions X, Y, Z and used permission X to access member record 00042."

**Why it works against the construction:**
The construction's unlinkability is not a bug — it is an *intended privacy property* (ppSE-IND game, Section 3). The `agentNullifier` is scoped per-predicate and blinded per presentation precisely to prevent cross-session correlation. Section 7 claims "NCUA examiners reviewing consortium data-sharing agreements can verify that only cryptographically proven minimum-necessary permissions were exercised at each access point." This is false at the human layer: what the examiner actually receives is a sequence of valid PLONK verification results, each proving a boolean predicate satisfied — with no linkage to agent identity, no plaintext record of which permissions were in scope, and no way to reconstruct "this agent accessed this member's data." NCUA Part 748 Appendix B requires an **incident response program** that includes the ability to determine the extent of compromise. If an agent exfiltrates member PII, I cannot answer the breach notification questions under 12 CFR Part 748.1: who was affected, what was accessed, and for how long. The audit log is a sequence of cryptographic commitments I cannot explain to a regulator who expects a spreadsheet.

**In-threat-model?** No — the construction must address this. Either a separate, linkable (non-ZK) audit side-channel must be defined with explicit NCUA Part 748 / GLBA § 314.4(h) mapping, or the unlinkability property must be scoped away from the audit path. The construction cannot simultaneously claim unlinkability for privacy AND full audit defensibility for examination.

---

### Attack 2: The Operator Signing Key Is a Baby Jubjub EdDSA Key — My HSM Vendor Has Never Heard of Baby Jubjub

**Attack:**
I ask my vendor management team: where does the operator private key live? The construction defines `operatorPubkeyAx / operatorPubkeyAy` as a Baby Jubjub elliptic curve key, with the signature verified inside the circuit via `EdDSAPoseidonVerifier` (Section 2, G3; Section 5 primitive mapping). Baby Jubjub (the JubJub curve embedded in BN254) is a ZKP-specific curve. It is **not supported by any FIPS 140-2 Level 2 or Level 3 validated HSM** — not Thales Luna, not AWS CloudHSM, not Entrust nShield, not YubiHSM. The operator key that signs every agent credential commitment must therefore live in software, in a file on disk, or in a purpose-built ZK key management tool that has no NCUA-recognized security certification. GLBA Safeguards Rule (16 CFR § 314.4(c)) requires encrypted storage of customer information and appropriate access controls over systems holding sensitive keys. The FFIEC IT Examination Handbook (Information Security Booklet, Section II.C) explicitly requires HSM-backed key storage for keys that authorize access to member financial systems. The construction's entire trust chain runs through a key that cannot be stored on any device I can show my examiner a FIPS certificate for.

**Why it works against the construction:**
Section 4 (Security argument, Assumption 4) states "Unforgeability of EdDSA-Poseidon on Baby Jubjub: No PPT adversary can forge a valid signature on a new message without the signing key." That is a mathematical claim. My examiner is not asking about PPT adversaries — she is asking about my key management program (FFIEC) and whether I have dual control, split knowledge, and tamper-evident storage for this key. Section 7's deployment scenario mentions "HSM-backed governor keys" for enrollment governors (ECDSA on secp256k1, supported by standard HSMs) — but says nothing about the operator key (Baby Jubjub), which is in the hot path for every credential issuance. The operator key compromise doesn't let the adversary inflate permissions (blocked by enrollment governance) but it does let them create fraudulent credentials that will pass G3 — credentials that then require k-of-n governor approval to enroll, but where the governors are reviewing a Poseidon hash of parameters they can't independently verify without trusting the operator's key to have been used correctly. The entire enrollment governance narrative rests on governors being able to "verify the operator public key belongs to a registered Columbia CU employee" — but if the operator key lives in software, that verification is of a software-held secret with no tamper evidence.

**In-threat-model?** No — the construction must address this. A key management appendix specifying operator key custody requirements (hardware solution, dual control procedure, rotation policy) is not a cryptographic contribution but is a hard regulatory requirement. Without it, no credit union CISO can sign off on the vendor management assessment.

---

### Attack 3: Revocation Is Explicitly Marked "Future Work" — I Have a 2am Call Telling Me a Credential Was Stolen

**Attack:**
At 2:17am, my SOC alerts that the operator signing key for the consortium AI agent was compromised. I need to revoke the agent's credential immediately. Per NCUA Letter to Credit Unions 24-CU-03 (cited in Section 7), I must be able to terminate third-party agent access "promptly upon detection of unauthorized activity." I call the on-call engineer. He explains: revocation currently "operates at the Merkle root level: governors rotate the tree root by re-enrolling all valid credentials minus the revoked one, and the 30-entry root history buffer expires stale roots" (Section 2, enrollment governance, Revocation paragraph). This means: (1) I must convene 7 of 12 consortium governors at 2am to sign an enrollment transaction, (2) re-enroll every other valid credential into a new tree, (3) wait for that transaction to land on Base L2, and (4) then wait for the 30 previously-valid roots to cycle out of the history buffer. Until all 30 prior roots are evicted, a stolen credential generates valid proofs against any of them. The construction explicitly acknowledges: "enabling revocation by requiring the agent to prove non-membership in a revocation accumulator (future work, flagged as limitation)." There is no instant revocation path.

**Why it works against the construction:**
The 30-entry root history buffer (Section 5 primitive mapping, "30-entry root history buffer") exists to handle the latency between credential issuance and RS cache refresh — a legitimate operational need. But it creates a revocation window measured not in seconds but in "however long it takes for 30 new root updates to occur." In a low-enrollment-activity consortium, this could be days or weeks. During that window, a compromised credential is valid at every RS in the consortium. The construction's soundness argument (Section 4, Reduction sketch) guarantees that a forger without the private inputs cannot generate a valid proof — but a *stolen operator key* means the adversary *has* the private inputs. They can generate `credentialCommitment = Poseidon5(modelHash, opAx, opAy, permissionBitmask, expiry)` with a *new* expiry far in the future, sign it with the stolen key, and attempt enrollment. They need k-of-n governors to enroll the new commitment — but the *existing* enrolled commitment (already in the tree) continues to produce valid proofs until the root cycles out 30 times. No circuit constraint, no rate limit, and no operational control described in the construction prevents an adversary with a stolen operator key from draining proofs against existing enrolled credentials for the duration of the revocation window.

**In-threat-model?** No — the construction must address this. "Future work" is not an acceptable answer in a vendor risk assessment or an NCUA examination when the missing feature is *credential revocation*. The non-membership accumulator needs to be in-scope for Phase 1 deployment in any regulated environment.

---

### Attack 4: The Trust Root Is Base L2 — My Core Processor Has Five-Nines; Your Sequencer Has a Blog Post Saying "Temporary Downtime"

**Attack:**
The construction's verification protocol (Section 2, RS-side) begins: "RS reads `onChainAgentRoot` from the Bolyra on-chain registry (cached, no AS contact)." The registry is a smart contract on Base (Coinbase's L2, implied by `contracts/` deploy target `baseSepolia` and the Hardhat config reference). The construction trades the AS's liveness for the L2's liveness. But: (a) Base L2 had an unplanned sequencer outage in September 2023 that halted block production for several hours; (b) L2 sequencers are operated by single entities (Coinbase, in Base's case) — a regulatory single point of failure the construction does not acknowledge; (c) the "cached" root solves stale-read latency but creates a new problem: what is the RS's cache TTL? A stale cached root accepts proofs from already-revoked credentials. A cache with zero TTL requires a live L2 read on every request. The construction doesn't specify either. My NCUA vendor management policy requires third-party providers to document RTO and RPO. The construction provides no SLA for the on-chain registry, no fallback when the L2 sequencer is down, and no specification of what the RS must do when it cannot refresh the Merkle root — accept stale proofs (security risk), or reject all proofs (operational failure equivalent to the AS outage this construction was designed to avoid).

**Why it works against the construction:**
Section 7 motivates the construction in part by saying "During a CrowdStrike-style outage, Columbia CU's AS goes offline for 14 hours. All consortium agents are locked out." The construction's answer is: agents generate proofs locally, RS caches the root. But a Base L2 sequencer outage prevents *new enrollments* and *revocations* from landing on-chain. During the outage, the RS is running on a stale cached root. If the outage coincides with a credential compromise, the revocation cannot be processed until the sequencer recovers — and the compromised credential continues to generate valid proofs against the cached (pre-revocation) root. The construction's adversarial-AS resilience argument (Section 4) is that "the AS cannot lie about enrolled credentials." True — but the L2 sequencer can be unavailable, and "unavailability" at the enrollment/revocation layer during an incident is functionally equivalent to a non-responsive AS during the incident window. The construction has shifted the liveness dependency, not eliminated it.

**In-threat-model?** No — the construction must address this. A regulated deployment requires: (a) explicit L2 sequencer dependency disclosed in the vendor risk assessment, (b) defined cache TTL with documented security vs. availability tradeoff, (c) incident response procedure for sequencer outage scenarios, and (d) either a fallback mechanism (e.g., accepting proofs against any root in the 30-entry buffer during L2 unavailability, with explicit security implications) or an SLA commitment from the L2 operator that the construction's author does not control.


## Persona: rfc7662_advocate

### Attack 1: In-Memory Rate Counter Provides No Durable Privacy Guarantee

- **Attack:** The construction's multi-query leakage defense — the "multi-epoch detection window" — relies entirely on the agent SDK's in-memory `(rsIdentifier, epochId) → queryCount` map (Section 2, "Agent-side query rate limiting"). An adversarial RS (or a party who can influence the agent's runtime environment) sends `q_max - 1` probing queries per epoch, then triggers an agent restart — rolling deployment, Kubernetes pod eviction, application crash, scheduled restart, or simply starting a second SDK instance. Each restart resets the epoch counter to zero. The adversary now issues another `q_max - 1` queries. Over `ceil(W / (q_max - 1))` restart cycles, the full bitmask is recovered with no epoch-boundary detection possible, because each cycle appears as a fresh epoch from a fresh process.

- **Why it works / why it fails:** The construction explicitly states "the agent SDK enforces `q_max <= q_max < W` queries per RS per epoch" and that "the agent controls its own query budget." But the security of this claim depends on the counter persisting across all restarts within an epoch. The construction provides no durability mechanism: no on-chain counter commit, no persistent storage requirement, no cross-instance coordination. The threat model (Section 3) explicitly excludes "the honest agent's SDK rate-limit enforcement" from adversary control — but a process restart is not "bypassing the SDK," it is restarting the host process, which is entirely within the reach of a sufficiently motivated RS (e.g., one that can send malformed inputs to crash the agent). The detection window the construction promises — "operator has `ceil(W/q_max) - 1` epoch boundaries to detect anomalous query patterns" — is an epoch-level abstraction that evaporates if the epoch counters are not durable. Furthermore, the "RS sybil resistance" allowlist mitigation only prevents the adversarial RS from cycling its own identity, not from cycling the agent's.

- **In-threat-model?** Yes — construction must address. The construction must either (a) require durable, crash-safe counter storage (on-chain or persistent local store) with explicit failure semantics on unavailability, or (b) withdraw the multi-epoch detection window as a security property and reclassify rate limiting as a best-effort operational control only. The current text presents it as a formal defense that bounds per-epoch leakage, which requires durability the construction does not provide.

---

### Attack 2: RS-Supplied `currentTimestamp` Is an Adversary-Controlled Expiry Input

- **Attack:** Section 2 ("Verification protocol") specifies that the RS constructs public inputs including `currentTimestamp`, which the circuit's G7 gadget (`LessThan(64): currentTimestamp < expiryTimestamp`) uses to enforce credential expiry. The adversarial-AS threat model (Section 3) gives the adversary full AS control — but the AS is not in the expiry enforcement path. The RS is. A malicious RS submits `currentTimestamp = unix_epoch_start` (e.g., `1000`). The agent's prover sees `currentTimestamp = 1000 < expiryTimestamp = <any future date>` — G7 passes. The proof is generated and verified as fully valid, committing to the lie that the current time is the year 1970. The construction has no mechanism for the agent or any external party to detect or reject a backdated RS-supplied timestamp.

  The converse attack: an adversarial RS supplies `currentTimestamp = 9999999999` (far future). G7 fails for all currently-valid credentials (`currentTimestamp >= expiryTimestamp`). The agent returns `{"error": "scope_insufficient"}` — indistinguishable from an unsatisfied predicate, per the construction's constant-time discipline. This is a cryptographically undetectable denial-of-service the RS can apply to any agent it chooses. The baseline's RFC 7662 AS enforces expiry using its own trusted clock; the construction's adversarial-AS independence creates a new trusted-clock dependency on the RS, which is not addressed.

- **Why it works / why it fails:** The construction transfers clock trust from AS to RS without acknowledging it. The adversary model in Section 3 says the adversary "does NOT control: the honest agent's local clock beyond the public `currentTimestamp`." This phrasing reveals the issue — the agent's local clock is relevant but not used. The RS supplies the timestamp that enters the circuit. The only relevant clock for expiry enforcement is the RS's. The adversary (who controls the RS in the baseline critique scenario) therefore controls expiry enforcement. Compare: in RFC 7662, the AS's trusted clock enforces expiry. In the construction, the RS's untrusted clock enforces expiry. Neither is strictly better — they merely shift which party you must trust for time. The construction's Section 8 never acknowledges this as a traded dependency.

- **In-threat-model?** Yes — construction must address. Either (a) require the agent to also check `localTimestamp < expiryTimestamp` before generating a proof (adding a private input bound) and bound the RS-supplied timestamp to within `[localTimestamp - skew, localTimestamp + skew]`, or (b) acknowledge explicitly that expiry enforcement trusts the RS clock, which is a weaker model than claimed when the RS is adversarial.

---

### Attack 3: Threshold AS Federation Matches the Enrollment-Governance Advantage

- **Attack:** The construction's primary structural argument is that it moves from "trust the AS" (single party, every presentation) to "trust k-of-n governors" (distributed, once at enrollment). Section 3 and Section 8.1 spend considerable effort establishing that this is "categorically narrower" than AS trust. But RFC 7662's broader ecosystem is not limited to a single-AS deployment. An OAuth federation using threshold signature schemes — currently being standardized as part of cross-domain token work and implementable today with threshold-ECDSA or Schnorr multi-sig over secp256k1 — achieves structurally equivalent properties:

  1. `n` AS instances, each operated by a distinct consortium member (analogous to enrollment governors), issue JWT co-signatures.
  2. The final token carries `k` valid AS signatures and is considered active.
  3. The RS caches the signed JWT (jwt-introspection-response, RFC draft) and verifies offline — no AS roundtrip at presentation.
  4. No single AS can unilaterally assert scope, because `k-of-n` AS co-signatures are required.
  5. Enrollment authority is the same: `k-of-n` consortium members must approve a client credential.

  The construction's Table in Section 3 claims "Compromise window: Continuous (AS can lie about any token at any time)" vs. "Point-in-time (enrolled credential is immutable once in tree)." This distinction vanishes under threshold-signed JWTs with an immutable issuance log anchored to a shared ledger — the same immutability property. The construction never engages with threshold AS architectures, only with single-AS deployments.

- **Why it works / why it fails:** The construction's adversarial-AS argument is only load-bearing against a *single* AS. The construction concedes in Section 3: "A deployment MAY designate the same organization as both AS and enrollment governor" — which confirms that the governance structure is an operational choice, not a cryptographic one. A threshold AS federation makes the same operational choice: distribute AS authority across `k-of-n` consortium members. The remaining delta after acknowledging threshold federation is (a) implication closure in the circuit (G6) and (b) bitmask-level predicate ZK — but the construction should isolate these as the actual differentiators rather than claiming the entire adversarial-AS argument.

- **In-threat-model?** No — construction need not address this as a cryptographic break, but the claim in Section 8 that "no composition of RFC 7662, jwt-introspection-response, RFC 8693, RFC 8707, RFC 9449 (DPoP)" can match adversarial-AS soundness is too broad. The construction should narrow the adversarial-AS claim to precisely: "a single-AS deployment model where the AS is not threshold-governed," and acknowledge that threshold AS federation narrows the gap to G5 + G6 uniqueness.

---

### Attack 4: G6 Implication Closure Is Incomplete — the Claimed "Unconditional" Enforcement Has Gaps

- **Attack:** Section 1 states that G6 enforces "runtime-adaptive bitmask predicate with implication-closure enforcement" and Section 3's Sub-game "Implication Closure Forgery" claims G6 provides unconditional rejection of structurally invalid bitmasks. G6 encodes exactly three constraints:
  - `permBits[4] * (1 - permBits[3]) === 0` (bit 4 → bit 3)
  - `permBits[4] * (1 - permBits[2]) === 0` (bit 4 → bit 2)
  - `permBits[3] * (1 - permBits[2]) === 0` (bit 3 → bit 2)

  But the 8-bit permission model (defined in CLAUDE.md) has 8 distinct permission bits with an "8-bit cumulative encoding — higher tiers imply lower" description. The complete implication lattice includes relationships G6 does NOT enforce:
  - `SUB_DELEGATE` (bit 6) and `ACCESS_PII` (bit 7) have no implication constraints in G6.
  - `SIGN_ON_BEHALF` (bit 5) has no implication constraints in G6.
  - There is no circuit constraint that `WRITE_DATA` (bit 1) implies `READ_DATA` (bit 0), despite "higher tiers imply lower" suggesting this.

  An adversary can enroll a credential with `ACCESS_PII` (bit 7) set and `READ_DATA` (bit 0) unset. G6 does not reject this. The construction's claim that "a hardware-attested client with a structurally invalid permission set (FINANCIAL_UNLIMITED without FINANCIAL_SMALL) passes attestation but fails the R1CS constraint unconditionally" is true for the three encoded implications — but a well-configured AS enforcing the *complete* implication lattice via policy catches violations that G6 misses. RFC 7662 with AS-side policy that rejects tokens violating `ACCESS_PII → READ_DATA` is strictly more complete than G6.

- **Why it works / why it fails:** The construction's Section 3 "Sub-game: Implication Closure Forgery" game defines a win as "w.permissionBitmask violates implication closure (e.g., bit 4 = 1 but bit 3 = 0)." The "e.g." signals that the game is only illustrative — but the circuit's G6 is the authoritative definition of what's enforced, and it is incomplete relative to the permission model. The construction should either (a) extend G6 to cover the complete implication lattice for all 8 bits, or (b) explicitly specify which implications are circuit-enforced vs. operator-policy-enforced, and limit the "unconditional R1CS enforcement" claim to the three currently-encoded implications. The claim that "no baseline variant even attempts" implication closure enforcement is false for a well-configured AS: OpenID Connect Authorization Servers routinely enforce scope hierarchies via policy (`email` implies `openid`, `write:items` implies `read:items`) — this is exactly AS-side implication policy, matching the construction's claim for the subsets G6 actually covers.

- **In-threat-model?** Yes — construction must address. Specifically: extend G6 to the complete implication lattice the permission model implies, and withdraw or narrow the claim that G6 enforces "permission-structure invariants" that the baseline "does not even attempt" until the complete lattice is encoded.


## Persona: spiffe_engineer

*Workload identity at scale. You're solving at the wrong layer — again.*

---

### Attack 1: Your On-Chain Merkle Root Is a Trust Bundle With Gas Fees

- **Attack:** Section 2's G4 gadget checks `computedRoot === onChainAgentRoot`, where `onChainAgentRoot` is read from the `BolyraRegistry` on-chain. The RS caches this root and checks inclusion of `credentialCommitment` against it. The enrollment governance (k-of-n EIP-712 on `enroll()`) controls what enters the tree.

  This is architecturally identical to SPIFFE trust bundle distribution. In SPIRE, the trust bundle is a root CA certificate distributed via the Bundle Endpoint (draft-ietf-spiffe-spiffe §3.6). RSes cache the bundle and verify SVID chains against it without contacting the SPIRE server. Federation across trust domains (e.g., 12 consortium credit unions, each with their own SPIRE server) gives you exactly the k-of-n governance structure Section 2's enrollment contract provides: no single credit union's SPIRE server can mint SVIDs accepted across the consortium without bundle federation signatures from the others.

  The `BolyraRegistry`'s `enroll()` is the `POST /.well-known/spiffe/trust-bundle` call sequence, with EVM as the notary instead of X.509 and a replication quorum. Both require `k` parties to agree before new roots are accepted. The gas cost and BN254 trusted-setup assumptions are overhead you pay for a property you already have.

- **Why it works / fails against the construction:** This attack partially lands on the *enrollment governance* subsystem, but whiffs on the circuit layer. The construction survives on G5 and G6 — SPIRE trust bundles identify workloads, they do not evaluate authorization predicates over committed private state. An SVID carries no permission bitmask; OPA/Cedar evaluate policy post-SVID-verification as an assertion by the policy engine, not a proof. The RS trusting OPA's `financial_small` decision is equivalent to trusting an AS response — the adversarial-AS claim in Section 1 stands. However, the specific justification for *why the trust anchor must be an EVM Merkle tree* rather than federated SPIRE bundle endpoints is never made. The construction hasn't argued why `ecrecover` on-chain is stronger or more operationally correct than X.509 chain validation against a federated bundle.

- **In-threat-model?** Partially. The ZK predicate evaluation is not replaceable by trust bundle federation — **construction survives on Properties 1, 2, 4.** But the enrollment governance design lacks a comparative argument against SPIRE federation with multi-domain bundle signing. The construction **must address** why on-chain governance is preferable to federated bundle endpoints for the RS trust anchor — or narrow its claim to the ZK predicate evaluation property exclusively.

---

### Attack 2: WIMSE Already Separates "AS-Not-In-Hot-Path" — Your Claim Is Category Error

- **Attack:** Section 8, Property 3 ("AS-blind presentation") is claimed as a fundamental gap over the baseline. The construction's Table in Property 1 shows "AS" as absent from the verification path as a key differentiator.

  But draft-ietf-wimse-arch Section 4 already architects this separation. In WIMSE:
  - The SPIRE server issues JWT-SVIDs or X.509-SVIDs to workloads. After issuance, the SPIRE server is **not contacted during request processing**.
  - The workload uses WIMSE Workload Proof of Possession (draft-ietf-wimse-s2s-protocol) to sign requests with its SPIFFE-issued key.
  - The RS verifies the WPoP signature against the SVID's embedded public key, and verifies the SVID chain against the cached trust bundle.
  - **No AS roundtrip.** The OAuth AS, if present, issued the subject token at some prior time — it is not in the hot path.

  Your "mutual ZK handshake" maps directly onto WIMSE WPoP: the agent proves it holds the key embedded in the credential, the RS verifies without calling the AS. Sections 1 and 7 claim "AS-blind presentation" as novel, but WIMSE WPoP has been in scope since draft-ietf-wimse-s2s-protocol-01 (2024). Contributing `requiredScopeMask` as a claim type in the JWT-SVID and a WIMSE extension for predicate attestation would reach the same operational outcome.

- **Why it works / fails against the construction:** The attack forces the construction to be precise about what "AS-blind" means. WIMSE achieves AS-blind *identity verification*; it does not achieve AS-blind *authorization predicate evaluation over hidden inputs*. The WIMSE token's scope claims are plaintext strings in the JWT-SVID — a compromised SPIRE server (the WIMSE analog of enrollment governors) can mint SVIDs with arbitrary scope claims, and the RS verifies the chain but trusts the scope value. The construction's G5 — evaluating `permissionBitmask & requiredScopeMask == requiredScopeMask` over a **private** `permissionBitmask` — is not achievable with WIMSE WPoP. The scope must be public for the RS to verify it. WIMSE is AS-blind for identity; the construction is AS-blind for identity **and** authorization predicate evaluation simultaneously.

- **In-threat-model?** Construction survives on the predicate-evaluation property (G5/G6). But Section 1's phrasing — "no AS roundtrip at presentation time" presented as a differentiator — **must be tightened**. As stated, WIMSE already satisfies this for identity. The actually novel claim is the predicate evaluation over committed private state with no disclosure of the input. The construction should replace "AS-blind presentation" with "verifier-private predicate evaluation" as the named property, or a WIMSE co-author will make exactly this objection in IETF review.

---

### Attack 3: Agent-Side Rate Limiting Is a Workload-Layer Enforcement Anti-Pattern — SPIRE Puts Policy at the Agent, Not the Workload

- **Attack:** Section 2 ("Agent-side query rate limiting") and Section 3 ("The agent is the privacy-interested party. It is rational for the agent to enforce its own query budget") place rate-limit enforcement inside the agent SDK's `proveSelectiveScope()` method. The construction explicitly concedes: "a cooperative agent that disables its rate limit leaks its own bitmask, but this is equivalent to voluntary disclosure — not a protocol failure."

  This is the workload-layer enforcement anti-pattern. SPIFFE/SPIRE gets the enforcement layer right: the SPIRE **agent** (a daemon running alongside the workload, not controlled by the workload) manages SVID issuance and can refuse to deliver SVIDs based on server-pushed policy. The **workload** cannot bypass SPIRE agent enforcement — the Workload API socket is controlled by the agent, not the workload process. Policy enforcement is at a trust boundary above the workload.

  In the construction, the agent SDK is part of the workload's process. A supply-chain compromise of `@bolyra/sdk`, a runtime environment exploit (e.g., eval injection into the Node process), a misconfiguration, or a deliberate SDK fork removes the rate limit. The construction calls this "voluntary disclosure" — but in a multi-tenant consortium (Section 7: Columbia CU's agent accesses partner CU RSes), the "agent" is not a single principal making a rational privacy decision. It's a deployed process potentially under operational control of multiple teams, subject to dependency chain attacks, and running in environments the enrollment governors never audited.

  The threat model (Section 3) says "The agent is the privacy-interested party." In SPIFFE deployments, the *workload operator* is the privacy-interested party — and the SPIRE agent enforces privacy policy on behalf of the operator, not on behalf of the workload code itself. The distinction matters: SPIRE separates the enforcement point (agent, operator-controlled) from the code being attested (workload, potentially untrusted).

- **Why it works / fails against the construction:** This attack **lands**. The construction does not establish a mechanism by which the rate limit survives agent compromise. The `q_max` counter is in-process memory (`sdk/` — `proveSelectiveScope()` method per Section 5). An adversarial RS with code execution on the agent's host, a malicious SDK dependency, or a fork of the agent SDK can set `q_max = 64` or remove the check entirely. The construction's security argument for multi-query leakage (Section 3, Section 4 reduction sketch) treats the rate limit as a non-cryptographic operational control — which it is — but then relies on it as a privacy property without establishing what enforcement boundary the counter sits behind.

  The per-presentation SE-ZK property (ppSE-IND) is sound and survives independently. The **rate-limit claim** as a privacy *defense* is only as strong as the SDK's tamper resistance — which the construction does not analyze.

- **In-threat-model?** **No — the construction must address this.** Either: (a) move `q_max` enforcement to the SPIRE agent layer (or equivalent process-isolation boundary, e.g., a sidecar or TEE) so the workload code cannot bypass it, or (b) explicitly scope the multi-query leakage defense as an *operational control subject to agent integrity* and remove it from the privacy reduction sketch. As written, the reduction in Section 4 ("Agent-enforced rate limit bounds `q`") treats the SDK counter as a protocol guarantee — this is not supportable if the adversary can compromise the agent runtime.

---

### Attack 4: Implication Closure (G6) Is Three Constraints — But Your Enrollment Governance Doesn't Verify It Off-Chain, So Governors Can Approve a Structurally Invalid Credential

- **Attack:** Section 2's enrollment governance requires k-of-n governors to sign off on `credentialCommitment = Poseidon5(modelHash, opAx, opAy, permissionBitmask, expiryTimestamp)`. The governors verify "the requested permission bitmask is consistent with Columbia CU's consortium membership tier" **off-chain** before signing. But `credentialCommitment` is a Poseidon hash — the governors receive the preimage (the raw `permissionBitmask` byte) and hash it themselves to verify the commitment, or they trust the operator's disclosure.

  G6 enforces implication closure *inside the proof*: a proof with an implication-violating enrolled bitmask (bit 4 = 1, bit 3 = 0) will fail G6 at proof generation time — the prover will find no valid witness. This is correct.

  The attack is subtler: **the enrollment itself accepts structurally invalid bitmasks.** The `BolyraRegistry.enroll()` function checks k-of-n EIP-712 signatures but performs **no on-chain verification of the bitmask's structural validity.** An operator submits `credentialCommitment = Poseidon5(..., 0b00010000, ...)` — bit 4 set, bit 2 unset (`FINANCIAL_UNLIMITED` without `FINANCIAL_SMALL`). Governors review this off-chain. If they approve it (mistakenly or corruptly), the commitment enters the tree.

  Now the agent holds an enrolled credential with a structurally invalid bitmask. What happens at proof generation? G6 will reject any witness where bit 4 = 1 and bit 2 = 0 — **the agent cannot generate a valid proof**. But the agent also cannot generate a valid proof for any predicate that requires bit 2 — not because it lacks the permission, but because the enrollment captured an invalid state. The agent is cryptographically locked out of valid proof generation for any predicate that would expose the implication violation.

  This is not a forgery — it's a denial-of-service against an agent whose governors approved a structurally invalid enrollment. The construction provides no mechanism for the agent to detect or recover from this state, and the `BolyraRegistry` provides no on-chain validation that enrolled commitments correspond to implication-closed bitmasks.

  In SPIFFE terms: SPIRE's registration API validates SPIFFE ID format at registration time, server-side, before the SVID is issued. The enforcement layer that issues credentials also validates their structural correctness. The construction separates enrollment governance (contract layer, no circuit execution) from structural validation (circuit layer, proof generation) — creating a gap where governors can enroll commitments the circuit cannot prove.

- **Why it works / fails against the construction:** The construction claims in Section 3 (Sub-game: Implication Closure Forgery) that "no valid witness can satisfy the circuit with an implication-violating bitmask." This is correct for *forged proofs* — but the attack is not forging a proof with an invalid bitmask. The attack enrolls a commitment to an invalid bitmask via k-of-n governance (possibly through governor error or compromise below the k threshold for safety purposes), then the **agent** discovers at proof generation time that no valid proof exists for any predicate touching the violated implication. The construction's security argument does not address this enrollment-time structural validation gap.

- **In-threat-model?** Partially. The forgery game (Section 3) survives — no valid proof is produced. But the construction **must address** the liveness failure: add on-chain implication-closure validation to `enroll()` (decode the bitmask from the preimage, check the 3 constraints before accepting k-of-n signatures), or specify that the agent's SDK validates the enrolled bitmask locally after enrollment and flags the invalid state before committing to production. As specified, the `BolyraRegistry` is structurally blind to the bitmask — it hashes what it's given. The circuit is the only enforcement point, but the circuit only runs at proof time, after enrollment has already occurred.
