# Tier 3 Adversarial — C1 Selective scope proof

## Persona: auth0_pm

---

### Attack 1: Onboarding Gravity — The RS Integration Tax

- **Attack:** The construction requires every resource server to (a) generate and register an EdDSA Baby Jubjub keypair, (b) sign `Poseidon2(rsIdentifier, requiredScopeMask)` for each predicate (constraint 8 / RS predicate integrity fix), (c) deploy an on-chain PLONK verifier, and (d) issue and track session nonces to bound MVZ leakage. Auth0's MCP auth integration is: add the Auth0 SDK, configure a scope policy in the dashboard, done. WorkOS MCP is the same. The construction's RS onboarding is at minimum a sprint, possibly a quarter if the verifier needs legal/security review.
- **Why it works / why it fails:** The construction closes the *cryptographic* gap (EdDSA unforgeability → DL-BJJ) but ignores the *operational* gap. An RS operator who controls their own predicate signing key is now also a key-management principal. Key rotation, revocation, HSM storage — none of this is addressed. For a credit union IT team that can barely manage TLS certificates, "register a Baby Jubjub EdDSA key with the ZKP circuit registry" is a non-starter.
- **In-threat-model?** No — the construction must address RS operator onboarding complexity and key lifecycle. The claim of "constant-size proof regardless of bitmask width" is not a buyer-level reason if the buyer can't get past the integration checklist.

---

### Attack 2: The Latency Budget Is Already Spent

- **Attack:** Construction §scenarios mentions "regulated agent with 2^64 permission space." An agentic workflow hitting 10–50 RS endpoints per task (read ledger data, post transaction, query member record, etc.) needs a proof per RS per session. At ~15s PLONK proving time per proof, a 10-RS workflow takes 150s of proof generation alone, before any actual API work. WorkOS and Auth0 issue RS-scoped tokens via RFC 8693 token exchange in under 100ms. Even with proof caching keyed on `(agentSecret, rsIdentifier, scopeMask)`, the MVZ fix requires a **fresh on-chain session nonce** per query — which means either (a) proofs cannot be cached across nonces, destroying the latency argument, or (b) nonces are reused, which the construction explicitly says bounds leakage only via fresh nonce issuance.
- **Why it works / why it fails:** The MVZ fix and the latency problem are in direct tension. The construction treats nonce issuance as a policy control; procurement treats it as a latency multiplier. The construction does not address batched or precomputed proofs for predictable predicate evaluations, nor does it cite any benchmarks for the specific Poseidon2/EdDSA circuit on commodity hardware. "PLONK CZK in ROM" is not a latency argument.
- **In-threat-model?** No — the construction must either benchmark proving time, describe a precomputation strategy that doesn't conflict with MVZ nonce freshness, or scope the claim to async/offline use cases explicitly.

---

### Attack 3: The Adversarial-AS Threat Model Has No Buyer

- **Attack:** The construction replaces SECU with CU\*Answers as the scenario to justify the adversarial-AS model: "individual CUs don't fully trust the shared CUSO AS." I will ask every CU IT director this question at procurement: "Do you believe your identity provider is lying to you about scope membership?" Every single one will say no. Auth0, Okta, and WorkOS have SOC 2 Type II, contractual SLAs, cyber insurance, and NCUA examination history. The construction's adversarial-AS model is academically coherent but commercially invisible — no buyer believes they need cryptographic assurance *independent of their own IdP's cooperation*. The scenario is real only if CU\*Answers is actively malicious, which is a fraud scenario handled by NCUA enforcement, not ZK circuits.
- **Why it works / why it fails:** The gap-to-close explicitly lists "adversarial-AS model where AS cannot lie about scope membership" as a candidate differentiator. This is the construction's strongest cryptographic claim and its weakest GTM claim. The buyer's question is not "can the AS lie?" — it is "why am I paying for this instead of Auth0?" The construction provides no answer at the buyer level.
- **In-threat-model?** No — the construction must articulate a concrete buyer motivation that does not depend on the AS being adversarial. Candidates: regulatory exam independence (NCUA Part 748 audit trail, which the construction does address via constraint 12), cross-CUSO portability without data sharing, or agent delegation without AS involvement. These need to be the *primary* claim, not the adversarial-AS framing.

---

### Attack 4: SRS Ceremony Trades a Known Devil for an Unknown One

- **Attack:** The construction adds Assumption A0 (SRS integrity) as the first axiom, conditioning all four security games on it, and explicitly states "SRS compromise collapses knowledge soundness." So the enterprise's trust chain is now: solo founder → trusted setup ceremony (who ran it? how many parties? was it Powers of Tau? is it audited?) → academic construction (no third-party cryptographic audit cited) → production credit union member data. Auth0's trust chain is: Okta Inc. (public company) → SOC 2 Type II audit (annual, third-party) → contractual liability → cyber insurance → NCUA examination track record. Procurement's standard vendor risk questionnaire has a line item for "cryptographic library audit." The construction has no answer to it. Dynamic Client Registration (RFC 7591) and Client Attestation (draft-ietf-oauth-attestation-based-client-auth) are IETF-tracked, FIPS-adjacent, and auditable today.
- **Why it works / why it fails:** The construction is correct that SRS trust is a known limitation of SNARKs and documents it honestly. But documenting a risk is not mitigating it. A solo founder cannot run a sufficiently trusted ceremony, and outsourcing it (e.g., Aztec's ignition, Hermez) introduces a dependency on a third party the NCUA has never examined. The construction must either adopt a transparent/universal SRS (STARK-based, no ceremony) or provide a path to ceremony auditability that satisfies NCUA examiners — neither of which is addressed.
- **In-threat-model?** No — A0 is load-bearing for all security claims. The construction must close the ceremony trust gap or reframe to a ceremony-free proving system. This is the attack that kills the construction at the NCUA examination level, not just at procurement.


## Persona: cryptographer

---

### Attack 1: Trust Boundary Collapse — Agent-as-CUSO-Infrastructure

**Attack:**
The construction introduces `agentSecret` as "a fresh Baby Jubjub scalar generated by the agent, never shared with AS." The CRU game reduction rests entirely on this: AS sees only `Poseidon2(agentSecret, 0)` and cannot invert Poseidon2. But in the CU\*Answers deployment scenario the construction itself adopts, the *agent software runs on CUSO-managed infrastructure*. CU\*Answers operates the core processing platform. If AS controls the execution environment — the JVM, the HSM, the container runtime — then AS observes `agentSecret` at key generation time. The PRF-Poseidon reduction is then vacuous: the adversary doesn't need to break Poseidon; it already holds the key.

**Why it works / fails:**
The construction never specifies a trust boundary between the agent process and the AS operator. The game definition for CRU must include a separate *key-custody* assumption: "AS cannot observe `agentSecret` during or after generation." Without this as an explicit axiom (call it **A1: Agent Key Isolation**), the reduction has a dangling precondition. In a shared CUSO deployment, A1 is arguably false by default — CU\*Answers has root on the servers.

**In-threat-model?** No — construction must address this. Either add A1 explicitly and bound the deployment to TEE/HSM-isolated agent runtimes, or reformulate the adversarial-AS model to exclude infrastructure-level compromise (and justify why that's the right model for CU\*Answers).

---

### Attack 2: PLONK HVZK ≠ Malicious-Verifier ZK — Simulation Gap in MVZ Game

**Attack:**
The construction claims: "PLONK CZK in ROM ensures no leakage beyond the predicate bit." It then patches MVZ by rate-limiting nonces: "Full 64-bit recovery requires 64 nonces — policy-controlled nonce issuance bounds leakage." This argument conflates three distinct security notions:

1. **HVZK** (PLONK's actual security property): the simulator works given an *honest* verifier's randomness.
2. **Computational ZK under malicious verifier**: the simulator must extract the verifier's strategy and simulate without knowing the witness. In PLONK's non-interactive Fiat-Shamir instantiation in ROM, the simulator programs the random oracle — but this requires the simulator to *see* the verifier's oracle queries, which is impossible if the verifier is adaptive and withholds queries.
3. **Simulation-extractable ZK** (SE-ZK): needed if the adversary both sees proofs *and* makes proofs, which is exactly the RS scenario here.

The MVZ game as stated counts "1 bit per nonce" but this ignores *correlated* leakage across sessions: if the predicate is a threshold function over correlated permissions, the adversary can recover the full permission vector in far fewer than 64 queries via adaptive chosen-predicate attacks. The rate-limiting argument is a *policy* bound, not a cryptographic one. It has no formal reduction and collapses if nonce issuance policy is misconfigured or if the RS can obtain nonces out-of-band.

**Why it works / fails:**
PLONK achieves HVZK in ROM (Gabizon-Williamson-Ciobotaru, 2019). The transition to MVZ requires either (a) a separate simulation-extractable wrapper (e.g., the SE-SNARK transform of Groth-Maller), or (b) an explicit simulator construction in the MVZ game proof. Neither is provided. The nonce rate-limit argument is not a reduction sketch — it's an engineering heuristic dressed as a security claim.

**In-threat-model?** No — the construction must either: (a) cite and apply an SE-SNARK transform and give a reduction to SE-ZK, or (b) scope the MVZ claim to honest-but-curious RS and rename the game accordingly.

---

### Attack 3: Audit Token Breaks Unlinkability — Undefined Adversary Coalition

**Attack:**
Constraint 12 adds an in-circuit Poseidon-ECDH audit token keyed to the NCUA examiner's public key. The stated goal: "Designated NCUA examiner can reconstruct cross-RS logs from `agentSecretCommitment` + their private key." But the unlinkability game is never stated with an explicit adversary coalition. Consider:

- **Scenario A:** NCUA private key is compromised (breach, insider, compelled disclosure under 12 U.S.C. § 1786). The attacker now holds the ECDH decryption key. Every audit token across every RS becomes a deanonymization oracle. The entire cross-RS unlinkability property collapses retroactively — including for past sessions, since the tokens are on-chain and permanent.
- **Scenario B:** The unlinkability game implicitly excludes NCUA from the adversary set ("NCUA is always honest"). This is a strong trust assumption that must be stated as **A2: NCUA Key Integrity**. Without it, the game definition is incomplete, because a valid adversary strategy is "corrupt NCUA."

Furthermore, the Poseidon-ECDH construction inside the circuit uses a *static* NCUA public key. The construction gives no key rotation protocol. Old audit tokens encrypted to a rotated-out key become either unrecoverable (breaking the audit goal) or require re-encryption by the agent (breaking on-chain immutability).

**Why it works / fails:**
The construction successfully provides unlinkability against a passive AS. But the audit mechanism introduces a *designated decryptor* whose compromise is not modeled. The unlinkability game must be parameterized: `Unlink(A, S)` where `S` is the set of corrupted parties. The construction must specify whether NCUA ∈ S is allowed, and if not, why A2 is a reasonable assumption in a regulatory context where examiners are subject to subpoena.

**In-threat-model?** No — the construction must state A2 explicitly, give a key rotation protocol, and show that the unlinkability game holds when NCUA ∈ S is excluded with explicit justification.

---

### Attack 4: RS Key Registry — Missing PKI Game Breaks Predicate Integrity Reduction

**Attack:**
Constraint 8 adds: "Circuit rejects unsigned masks. Game RPI reduces to EdDSA unforgeability → DL-BJJ." The reduction assumes the RS operator's public key in the circuit is *legitimate*. But the construction never specifies who maintains the RS key registry, how keys are registered, or how the circuit learns which key to verify against.

Two concrete attacks:

**4a. AS-Controlled Registry Substitution.** In the CU\*Answers model, the CUSO AS is the natural operator of the RS key registry (it's the platform that provisions RSes). An adversarial AS can silently substitute `pk_RS_legit` with `pk_RS_evil` in the registry. The circuit verifies the signature under whatever key it's given. If the key is AS-supplied at proof generation time (passed as a witness or public input), the adversary controls the predicate entirely. The EdDSA unforgeability reduction is inapplicable — the adversary doesn't forge a signature, it substitutes the verification key.

**4b. rsIdentifier Ambiguity.** What is `rsIdentifier`? If it's an opaque AS-assigned identifier, the AS can register two `rsIdentifier` values for the same RS with different masks — one strict, one permissive — and selectively route agents to the permissive one. The predicate commitment `Poseidon2(rsIdentifier, requiredScopeMask)` binds mask to identifier, not to RS identity. There is no game proving that `rsIdentifier` uniquely and verifiably identifies the RS endpoint the agent is actually talking to.

**Why it works / fails:**
The construction needs a **Key Registration Integrity game (KRI)**: an adversary wins if it can cause a proof to verify against a predicate not authorized by the legitimate RS operator. This game requires a PKI root — either a separate registration authority (not AS), a smart-contract-based registry (on-chain, auditable), or a certificate chain from a trust anchor. None of these are specified. Without KRI, the RPI → DL-BJJ reduction proves only that *given a legitimate RS key*, forgery is hard. It says nothing about key legitimacy, which is precisely what an adversarial AS can subvert.

**In-threat-model?** No — the construction must (a) specify the key registration mechanism, (b) define and prove the KRI game separately from RPI, and (c) either remove AS from the registry trust path or show that AS-controlled registry is acceptable under the stated threat model (which it cannot be, given the adversarial-AS premise).


## Persona: cu_ciso

---

### Attack 1: Audit Token Key Lifecycle — The Examiner Who Retires

**Attack:** The construction's §audit-trail fix (constraint 12) states the designated NCUA examiner reconstructs cross-RS logs using `agentSecretCommitment + their private key`. The CISO asks: who manages that examiner key? NCUA examiners rotate, retire, and get reassigned. The examiner assigned during your 2026 exam will not be present for your 2028 exam. If the examiner's private key is destroyed on separation (as it must be under any reasonable key hygiene policy), all historical audit tokens become unrecoverable. Worse: if the examiner's public key is baked into the circuit (as it must be for constraint 12 to work), a key rotation requires a new circuit deployment — a new trusted setup ceremony under assumption A0.

**Why it works / fails:** The construction addresses *what* the audit trail proves but is silent on *how* the examiner key is provisioned, custodied, rotated, and recovered. NCUA Part 748 §748.1(b)(2) requires the security program to "ensure the security, confidentiality, integrity, and availability of member records." An audit trail that becomes unavailable on examiner turnover fails the availability prong. There is no in-construction answer; constraint 12 creates a key management dependency on NCUA as an institution — an entity the construction cannot contractually bind.

**In-threat-model?** No — construction must address. Required addition: a designated escrow mechanism (multi-sig between institution, regulator, and auditor) for examiner key recovery, plus explicit circuit versioning policy for key rotation.

---

### Attack 2: SRS Compromise Has No Incident Response Playbook

**Attack:** Assumption A0 (SRS integrity) is now explicit: "SRS compromise collapses knowledge soundness." The CISO maps this to GLBA Safeguards Rule §314.4(h) (incident response plan) and NCUA Part 748 Appendix B (response program). The question is blunt: *what is the incident response procedure when you suspect SRS compromise?* There is none expressible in operational terms. Unlike a stolen credential (revoke it) or a breached database (rotate keys, notify members), a compromised SRS means every proof ever generated may be a forgery — retroactively. You cannot tell which proofs were legitimate. Member harm cannot be bounded. Notification scope is unbounded.

**Why it works / fails:** The construction correctly discloses A0 as a precondition, but disclosure is not mitigation. SOC 2 Type II CC9.1 (risk mitigation) and FFIEC CAT Maturity Level 3 both require demonstrated response capability, not just risk acknowledgment. A vendor that says "if our root assumption is violated, all bets are off" fails the third-party vendor risk assessment at any credit union with a mature vendor management policy. The construction gives the CISO nothing to hand the examiner except "trust the ceremony."

**In-threat-model?** No — construction must address. Required addition: a concrete SRS breach scenario with (a) detection indicators, (b) bounded member impact assessment, (c) a re-keying runbook with timeline, and (d) the party responsible for declaring compromise (analogous to a CA's misissuance disclosure).

---

### Attack 3: agentSecret Is a Client-Side Key With No Recovery Path

**Attack:** The construction's CRU fix introduces `agentSecret` — "a fresh Baby Jubjub scalar generated by the agent, never shared with AS." The CISO's attack prompt fires directly: *where does the member secret live?* If the agent is browser-based or mobile, agentSecret lives in device storage. NCUA Part 748 and GLBA both require the credit union to maintain member account access under adverse conditions. When a member loses their device, who holds the recovery path? If agentSecret is never shared with the AS (by design — this is the security property), the AS cannot issue a replacement. The member's nullifiers are permanently orphaned. The construction has traded the CRU vulnerability for an unrecoverable member lockout vulnerability.

**Why it works / fails:** The construction explicitly states agentSecret is agent-held and AS-blind — this is the core security property enabling the adversarial-AS model. But it creates a key custody gap that no NCUA-compliant institution can accept without an explicit recovery path. NIST SP 800-63B §5.1.9 (recovery authenticators) and the credit union's own Account Recovery Policy both demand a documented path back. Any recovery mechanism that reconstructs agentSecret (backup phrase, encrypted vault, HSM escrow) expands the trust boundary and potentially violates the adversarial-AS assumption — the exact tension the construction does not resolve.

**In-threat-model?** No — construction must address. The adversarial-AS claim and the member recovery requirement are in direct tension. The construction must either (a) bound the adversarial-AS model to exclude recovery scenarios, (b) specify a hardware-bound key (Secure Enclave / YubiKey) that the institution can inventory under vendor management, or (c) accept that the adversarial-AS property degrades under recovery and document that tradeoff explicitly for examiners.

---

### Attack 4: On-Chain Nonce Registry SLA vs. Core Processor Availability Standard

**Attack:** The malicious-verifier ZK fix (Game MVZ) relies on "fresh on-chain session nonces" to rate-limit adaptive queries. The CISO maps this to availability. Credit union core processors (Symitar, Corelation, FiServ DNA) contractually guarantee 99.95–99.99% uptime. A blockchain-anchored nonce registry — regardless of which chain — is subject to block reorganization, gas price spikes, and network partitions that produce latency indistinguishable from outage. FFIEC CAT Domain 5 (Cyber Incident Management) and NCUA Part 748 §748.1(b)(3) require BCP/DR plans for all critical dependencies. An on-chain nonce is a critical dependency with no SLA the construction can contractually guarantee.

**Why it works / fails:** The security argument for on-chain nonces is sound — it provides rate-limiting without AS cooperation. But the construction offers no fallback mode. If the RS falls back to accepting proofs without a fresh nonce during a chain outage, the MVZ rate-limiting guarantee collapses. If the RS refuses all authentication during outage, member access is blocked — a service disruption event requiring NCUA notification under Part 748 Appendix B §III(B). Either fallback behavior is operationally unacceptable. The construction must specify the failure mode explicitly, since examiners will ask during BCP testing.

**In-threat-model?** No — construction must address. Required: (a) an explicit availability SLA claim for the nonce registry with justification, (b) a defined fallback behavior with its security degradation documented, and (c) BCP language an institution can import into its DR policy to satisfy FFIEC CAT Maturity Level 2 (Evolving) minimum.


## Persona: rfc7662_advocate

---

### Attack 1: Per-RS Filtered JWT Introspection Already Provides Selective Disclosure

- **Attack:** RFC 7662 §2.2 allows the AS to return *only* the scopes relevant to the querying RS. Combined with `draft-ietf-oauth-jwt-introspection-response`, the AS returns a signed JWT — the RS gets cryptographic assurance (signature over the filtered `scope` claim) *without* seeing the full permission set. I configure an RS-specific introspection policy table: `policy[rs_id] → {allowed_scopes}`. The RS learns exactly one bit — "does the token satisfy my required predicate?" — via a signed, offline-verifiable response. This is identical to what §2 of the construction claims as its headline property.

- **Why it works / fails against the construction:** This attack *almost* works. Where it fails is the AS-blind property: in filtered introspection, the AS learns which RS is querying and *when* the agent presents credentials there. The construction's nullifier `Poseidon2(agentSecret, rsIdentifier)` is computed entirely agent-side; the AS never sees `rsIdentifier` at presentation time. But the construction's §3 (Scenario: CU\*Answers) never explicitly states that AS-blindness to *presentation events* is the load-bearing property — it frames the adversarial-AS concern around *scope correctness*, not *AS learning the RS visit graph*. If the construction doesn't formally claim AS-blindness to presentation, this attack is not in-threat-model and the baseline matches.

- **In-threat-model?** Partially. The construction must explicitly claim and prove AS-blindness to the RS visit graph as a distinct property, or concede that per-RS filtered introspection closes this gap. As written, §3 does not do this.

---

### Attack 2: The Adversarial-AS Model Collapses at Issuance

- **Attack:** The construction's CU\*Answers scenario posits that individual CUs "don't fully trust the shared CUSO AS" and that NCUA examiners "need cryptographic assurance independent of CUSO cooperation." But the ZK proof in §4 proves membership in a scope set that was *signed and issued by the CUSO AS* (constraint 8 verifies an EdDSA signature over `Poseidon2(rsIdentifier, requiredScopeMask)` using "the RS operator's registered key"). Who registers those RS operator keys? If key registration flows through or is endorsed by the CUSO AS, a malicious AS performs a simple substitution attack: register its own key as the RS operator key, issue a scope mask asserting any permissions it wants, and the circuit accepts. The circuit cannot distinguish a legitimately registered RS key from an AS-planted one.

- **Why it works / fails against the construction:** This is a genuine gap. The construction hardens against a *runtime*-adversarial AS (AS can't forge proofs post-issuance) but does not specify a trust root for RS key registration that is *independent* of the CUSO AS. Compare: RFC 8707 resource indicators + an independent DNSSEC-anchored RS metadata discovery (RFC 9728 PRM) can establish RS identity without AS involvement. The construction's adversarial-AS claim requires an out-of-band key registration ceremony the paper does not describe.

- **In-threat-model?** Yes — this is in-threat-model and the construction does not survive it as written. §3 must specify how RS operator keys reach the circuit's trust anchor without passing through the adversarial AS.

---

### Attack 3: RFC 8693 Token Exchange Provides Runtime Predicate Restriction Without ZK

- **Attack:** The construction lists "runtime-adaptive predicate over permissions (not fixed at issuance)" as a candidate differentiator. RFC 8693 §2.1 allows an agent to exchange a broad token at runtime, specifying both `scope` (predicate restriction) and `resource` (RFC 8707 audience binding). The resulting narrow token is issued on-demand, cryptographically fresh, audience-bound, and never carries the full permission set to the RS. I can further sender-constrain it with DPoP (RFC 9449). The agent chooses *which* scopes to request at exchange time — this is runtime-adaptive. The AS roundtrip is the only asymmetry; the construction's offline capability is not stated as a formal security property.

- **Why it works / fails against the construction:** Token exchange requires AS availability and reveals to the AS that agent X is about to visit RS Y with scope Z — the AS learns the access pattern. If the construction's unlinkability claim covers AS-side access pattern leakage, token exchange fails here. However, the construction's current threat model (§3) focuses on RS-level unlinkability and NCUA audit, not AS-side pattern concealment. Unless the construction formally defines and proves AS-side access-pattern privacy, this attack correctly identifies that runtime restriction via RFC 8693 is equivalent for the stated goals.

- **In-threat-model?** No — not in the current threat model. But the construction should either add AS-side access-pattern privacy to the claimed properties or explicitly disclaim it, so readers don't over-interpret the "adversarial AS" framing.

---

### Attack 4: `agentSecretCommitment` Enables Trivial Cross-RS Linkability

- **Attack:** The construction fixes the CRU circular assumption by introducing `agentSecretCommitment = Poseidon2(agentSecret, 0)` as a *public input* to every proof — it must be public so the AS can verify the commitment at issuance and so the circuit can derive the nullifier. Every proof the agent generates across *all* RSes therefore carries the same `agentSecretCommitment` in the public inputs. Two colluding RSes — say, two credit unions both running on CU\*Answers — trivially link all proofs from the same agent by matching `agentSecretCommitment`. This is equivalent to a persistent pseudonym shared across the entire RS ecosystem, and it's *worse* than OIDC PPIDs: PPIDs are pairwise (RS₁ and RS₂ see different subject identifiers), but `agentSecretCommitment` is global. The construction's constraint 12 audit token is built on this same commitment, cementing it as a stable cross-RS identifier.

- **Why it works / fails against the construction:** This attack holds. The nullifier `Poseidon2(agentSecret, rsIdentifier)` correctly provides per-RS unlinkability *of nullifiers*, but the commitment leaks the linking handle. To close this, the circuit would need per-RS commitments (e.g., `agentSecretCommitment_rs = Poseidon2(agentSecret, rsIdentifier, 0)` kept private, with the AS seeing only a root commitment via a two-level construction). That is a material circuit change not present in the described construction.

- **In-threat-model?** Yes — if RS-level unlinkability is a claimed property (the construction's framing of "RS-level unlinkability" in the audit trail section implies it), colluding RSes break it via `agentSecretCommitment`. The construction must either (a) redesign the commitment scheme to be RS-specific, or (b) explicitly scope the unlinkability claim to *non-colluding* RSes and state that `agentSecretCommitment` is a known linking handle.


## Persona: spiffe_engineer

---

### Attack 1: Write a SPIFFE ZK Attestor, Not a New Protocol

- **Attack:** SPIFFE's node attestation model is deliberately pluggable. The SPIRE server's attestor API accepts any plugin that can produce a SPIFFE ID from workload evidence. The construction's entire ZK machinery — the circuit, the `agentSecret`, the Poseidon nullifier — could be wrapped as a custom SPIRE attestor. The attestor plugin runs the ZK verifier, and on success SPIRE issues a JWT-SVID with a minimal scope claim baked in. No new protocol. No new trust anchor. Runs in every Kubernetes cluster today.
- **Why it works / fails:** It works as a reduction argument: you are writing a ZK verifier that produces a capability token. SPIRE is a ZK-verifier-shaped hole that already exists in every enterprise stack. It fails against C1 specifically on the **adversarial-AS property** — the SPIRE server is the AS equivalent, so at SVID issuance the server learns which scopes it is attesting. The construction's distinguishing claim (§ "gap-to-close": *AS-blind presentation, agent chooses what to disclose at moment of use*) requires that the scope set is committed at issuance but only the predicate is revealed at presentation. A SPIRE attestor collapses these two steps: issuance and presentation happen together. The construction survives this attack only if it can clearly articulate that the JWT-SVID model **structurally conflates** issuance and presentation.
- **In-threat-model?** Partially. The construction must add a paragraph in §2 (or the scenario section) explaining why the issuance/presentation separation is load-bearing. Right now the paper assumes the reader agrees this matters. The SPIFFE engineer will not agree unless forced.

---

### Attack 2: WIMSE + SD-JWT Already Has Selective Disclosure — Why Are You Not Contributing There?

- **Attack:** `draft-ietf-wimse-arch` explicitly scopes token formats for workload-to-workload calls, and the working group is actively considering SD-JWT as the payload format. SD-JWT allows the AS to embed the full permission bitmask as individual selectively-disclosable claims, and the agent presents only the subset it needs. The RS verifies the AS's signature over the disclosed claims. No circuit, no trusted setup, no Baby Jubjub. The 2^64 permission space becomes 64 SD-JWT disclosure objects — large, but structurally sound. Why is the paper not a WIMSE contribution?
- **Why it works / fails:** It fails against the adversarial-AS scenario. SD-JWT's soundness reduces to the issuer's signature. If the AS (CU*Answers) is semi-trusted and the RS (a CU examiner or a peer CU) needs *cryptographic assurance independent of AS cooperation*, SD-JWT provides none: a malicious AS can issue a token with fabricated scope memberships and sign it. The construction's constraint 8 (EdDSA over `Poseidon2(rsIdentifier, requiredScopeMask)`) breaks this chain — the RS operator signs the *required mask* independently of the AS, so the circuit verifies AS-issued scope against an RS-operator-signed requirement without the AS being in the verification path. SD-JWT has no equivalent of an RS-operator-signed predicate.
- **In-threat-model?** Yes — but the paper must be explicit that constraint 8 uses a *separate RS operator key* that is not controlled by the AS. Currently this is implied. If the RS operator key is managed by CU*Answers (the adversarial AS), the whole construction collapses to SD-JWT with extra steps. The paper must state the key custody model for the RS operator key.

---

### Attack 3: Constraint 8 Is Certificate Validation — "Your Mutual ZK Handshake Is Just mTLS With SVIDs"

- **Attack:** In mTLS with X.509 SVIDs, the client presents a certificate encoding its workload identity and the server presents one encoding its service identity. Both sides verify the other's certificate chain. The construction's constraint 8 (`EdDSAPoseidonVerifier` over `Poseidon2(rsIdentifier, requiredScopeMask)`) is structurally identical: the RS operator signs a claim about what it requires, and the circuit checks it. The "ZK" part is the agent's prover — but in mTLS the server also never learns the client's full keyring, only the identity asserted in the certificate. Name one thing constraint 8 does that `tls.VerifyPeerCertificate` with an SVID encoding `requiredScopeMask` in a custom extension does not.
- **Why it works / fails:** The attack is correct that constraint 8 alone is not novel. It fails because the ZK property is not in constraint 8 — it is in the combination of constraints 1–7 (scope membership proof over the committed bitmask) plus constraint 8 (RS predicate binding). mTLS reveals the client's full identity/SVID to the server. The circuit produces a single accept/reject bit. The RS never learns which specific permissions satisfied the predicate, only that they did. This is not achievable with X.509 extensions: a custom extension encoding `requiredScopeMask` still requires the client to send a certificate encoding its full permission set, or to rely on the CA to truncate it — which brings the CA (AS) back into the path at presentation time.
- **In-threat-model?** No — the construction survives this attack, but only if it explicitly contrasts the ZK prover's output (1 bit) with mTLS's output (full SVID). The current text does not include this contrast. The paper should add it as a "non-goals / related work" paragraph.

---

### Attack 4: Adversarial Issuance Is Not Addressed — The CRU Fix Only Helps Post-Issuance

- **Attack:** The CRU fix introduces `agentSecret` — a fresh Baby Jubjub scalar the agent generates and never shares with the AS. This prevents the AS from forging nullifiers. But the AS still issues the original permission bitmask. In the CU*Answers scenario, the CUSO AS mints the token that encodes `permissionBitmask`. If the AS is adversarial, it can issue a bitmask claiming the agent has permissions it was never granted. The `agentSecretCommitment` binds the agent's secret to the AS-issued bitmask — but it cannot detect a *lying AS* that correctly signs a *false* bitmask. The circuit proves "I have a valid commitment to a bitmask that satisfies this predicate," not "this bitmask is correct." The NCUA examiner's audit token (constraint 12) uses the same AS-issued bitmask as ground truth. A malicious AS can fabricate an agent's entire permission history.
- **Why it works / fails:** This is the deepest structural gap. The construction's adversarial-AS model (§ "scenarios": *AS is semi-trusted and RS needs cryptographic assurance independent of AS cooperation*) applies at **presentation time** — the RS does not need to call the AS to verify the proof. But at **issuance time** the AS is fully trusted. The construction collapses to "semi-trusted AS at presentation, fully-trusted AS at issuance." This is a weaker adversarial model than the claim implies. The gap closes only if: (a) the bitmask is endorsed by a party other than the AS (e.g., each permission bit is co-signed by the granting CU's own key, not the CUSO), or (b) the threat model explicitly scopes adversarial-AS to presentation-time attacks and removes issuance-time AS compromise from the claim.
- **In-threat-model?** No — this is a claim mismatch. The paper's scenario names CU*Answers as the adversarial AS but then uses CU*Answers to issue the bitmask. The scenario requires either a different issuance architecture or a narrowed adversarial model.
