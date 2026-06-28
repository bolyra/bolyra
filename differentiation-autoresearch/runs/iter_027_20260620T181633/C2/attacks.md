# Tier 3 Adversarial — C2 Cross-scope unlinkability

## Persona: auth0_pm

---

### Attack 1: You Sold the Compliance Team a Blindfold

- **Attack:** Section 7's "concrete deployment scenario" proudly states: *"NFCU sees only the initial enrollment event. It has no visibility into which merchants the agent subsequently contacts, when, or how often. The merchant graph is cryptographically hidden."* A WorkOS PM reads this to a credit union's BSA/AML officer and watches them reject Bolyra on the spot. Under NCUA examination guidance, FinCEN Rule 31 CFR § 1020, and FFIEC's BSA/AML Examination Manual, the institution operating an agent-based payment system must maintain transaction monitoring capable of producing the authorization trail on demand. Removing the AS from the hot path doesn't just hide the merchant graph from the issuer — it **destroys the regulatory audit record the CU is legally required to produce.** The construction's strongest differentiator in §8 ("AS becomes an enrollment registrar, not an authorization intermediary") is the exact clause that fails NCUA IT examination. WorkOS's model, where the CU AS logs every scope grant, is not a bug — it's a compliance deliverable.

- **Why it works / why it fails:** The construction's Section 3.1 explicitly excludes the AS from post-enrollment authorization. Section 7 confirms NFCU "has no visibility." There is no mechanism to produce a compliant transaction log without re-introducing AS-side logging — which reconstructs exactly the linkable graph the construction was designed to eliminate. The paper offers no "audit mode" or selective disclosure path. The IND-UNL-AS game in §3.2 treats AS-invisibility as a win condition, not a tradeoff.

- **In-threat-model?** **No.** The construction must address it. Either (a) define a selective-disclosure audit path (e.g., operator-held blinding secret escrow that lets NFCU reconstruct its own member's graph on NCUA demand without revealing it to other parties), or (b) scope the deployment claim to non-regulated contexts and remove "credit union" from §7's lead scenario. Regulatory non-starters cannot be papered over with cryptography.

---

### Attack 2: 3 Seconds Per Tool Call Is Not a Latency Target, It's a Dealbreaker

- **Attack:** Section 6 states the PLONK proving target is "< 3s" on "commodity hardware (M1/equivalent)." Auth0, WorkOS, and Stytch issue tokens in under 100ms — measured at p99. An MCP agent making 200 tool calls across 20 resource servers in a session generates 20 proofs at 3s each: **60 seconds of blocking, CPU-bound work per session**, none of it parallelizable across sequential tool calls that depend on prior results. The construction argues PLONK proving is "constant-time for fixed circuit size" (§3.3), which is technically true but operationally irrelevant — constant 3s is still 30× slower than OAuth at p50, before network round-trips. For agentic workloads where latency compounds across chains of tool calls, this renders the protocol unusable for any interactive use case. Anthropic's own MCP examples involve agents making dozens of sequential calls. The `epochBinding` freshness mechanism (§2.4) requires a new proof per epoch boundary crossing, compounding the problem.

- **Why it works / why it fails:** The construction's §6 acknowledges the 3s target but does not compare it to incumbent latency, model realistic call volumes, or provide a caching strategy for repeated scope access within an epoch. The "< 2s with rapidsnark" alternative requires native binary deployment — a non-starter in serverless or containerized agent runtimes (Lambda, Cloud Run, Deno Deploy). The `epochBinding` determinism within a window (§2.4) could theoretically allow proof reuse within the same epoch, but this is not stated as a design intent and is not reflected in the circuit's `sessionNonce` public input, which changes per-request.

- **In-threat-model?** **No** for the interactive agentic case. The construction must either (a) specify a proof caching protocol that reuses the same proof within an epoch for the same `(scopeId, epochId)` tuple — which the public output structure already supports since `epochBinding` is deterministic — and make this explicit in the verification flow (§2.5), or (b) bound the deployment claim to batch-mode agents where per-call latency is irrelevant. Without this, the latency objection is unanswered at the buyer level.

---

### Attack 3: Your Single Point of Failure Is Worse Than Ours

- **Attack:** Section 2.3 defines the `scopeBlindingSecret` lifecycle: *"Generated once per agent credential... stored alongside the agent's credential material... never leaves the agent's local storage."* Section 2.3 further derives it as `Poseidon2(operatorPrivKey, "bolyra-scope-blind")` — meaning the blinding secret is **a deterministic function of the operator private key.** If the operator private key is compromised (stolen, leaked, rotated), two things happen simultaneously: (1) the credential commitment is compromised, AND (2) the entire history of scope-local nullifiers can be recomputed and linked retroactively. Every `scopedNullifier` the agent ever produced can be correlated post-compromise. In the OAuth model, a compromised client secret is rotated and prior tokens expire by their `exp` claim. In this construction, **there is no rotation mechanism and no forward secrecy for unlinkability.** An attacker who obtains the operator private key today can reconstruct the complete merchant graph going back to enrollment.

- **Why it works / why it fails:** Section 2.3 is silent on key rotation. Section 3.1 lists "agent's local execution environment" as outside the adversary's control, but the `scopeBlindingSecret` derivation from `operatorPrivKey` means compromise of the operator (not just the agent) breaks unlinkability. The `operatorPubkeyAx/Ay` are public inputs to the circuit (Table in §2.2) — anyone can identify which operator key a credential is associated with. A targeted attack on a specific operator compromises all agents under that operator simultaneously. The construction's §4.1 assumption A-DL (Baby Jubjub discrete log) protects the private key from being extracted from the public key, but does not address the scenario where the private key is leaked through a separate channel (HSM breach, misconfigured secrets manager, insider).

- **In-threat-model?** **Partially.** The threat model (§3.1) excludes "the agent's local execution environment" from adversary control. But the derivation `Poseidon2(operatorPrivKey, "bolyra-scope-blind")` couples unlinkability to operator key security in a way that is not disclosed in the security argument (§4). The construction must either (a) separate the `scopeBlindingSecret` from the operator key derivation — use an independently sampled field element with its own rotation protocol — and define a key rotation ceremony that issues a new credential with a new blinding secret, or (b) add a forward secrecy section to the threat model that explicitly bounds the post-compromise window.

---

### Attack 4: You Need Every RS to Ship a PLONK Verifier Before You Have One Customer

- **Attack:** Section 2.5 (verification flow) requires: *"RS verifies the PLONK proof against the on-chain `agentMerkleRoot` (via root history buffer lookup) and checks `scopedNullifier` against its local double-spend set."* This means Amazon, Costco, Quest Diagnostics, and Cedars-Sinai must each (a) deploy a PLONK verifier contract or library, (b) maintain a local nullifier double-spend store, (c) read on-chain Merkle roots from Bolyra's registry contract, and (d) define and publish `scopeId` identifiers in a well-known format. In the Auth0/WorkOS model, RSes implement one thing: Bearer token validation via `jwks_uri`. The Bolyra model requires RSes to become ZK verifiers, on-chain state readers, and nullifier store operators. **This is a classic two-sided marketplace bootstrapping problem.** No enterprise RS will implement PLONK verification until there are agent operators sending Bolyra proofs. No agent operator will generate Bolyra proofs until RSes accept them. Cloudflare's enterprise MCP product (cited in the persona toolbox) solved this by putting verification infrastructure in the network layer — operators don't change their RS code, they just put Cloudflare Access in front. Bolyra has no equivalent. WorkOS MCP auth deploys in one afternoon because RSes already trust JWTs. Bolyra's RS integration is a new engineering project with blockchain dependencies.

- **Why it works / why it fails:** Section 5 (Bolyra primitive mapping) shows the entire construction depends on RS-side on-chain root verification. Section 7 assumes Amazon and Costco have already deployed this infrastructure. There is no bootstrapping path, no RS SDK, no "Bolyra in a weekend" integration story, and no fallback for RSes that cannot or will not read from a Base Sepolia contract. The construction treats RS deployment as a solved problem when it is the central GTM obstacle.

- **In-threat-model?** **No** — this is a GTM/adoption threat, not a cryptographic one, and the construction does not address it. The construction must either define a hybrid mode where the RS delegates on-chain verification to a Bolyra-operated relay (introducing the trusted intermediary it claims to eliminate), or acknowledge that the target market is greenfield agent-native RSes (not existing OAuth-protected APIs), and bound the deployment claim accordingly. Without this, "why would enterprises adopt" has a structural answer: they cannot, because their existing RSes do not implement the required verification interface.


## Persona: cryptographer

*Applied cryptographer. Peer-reviews for CRYPTO/EUROCRYPT/S&P. If I can't find the game, there is no claim.*

---

### Attack 1: Reduction simulator gap — B cannot produce the challenge proof

**Attack:**
In the IND-UNL-AS game (§3.2), the reduction B receives oracle access to either `F_k(·) = Poseidon2(·, k)` or a random function, where `k = scopeBlindingSecret` is unknown to B. In the query phase, B has generated the real credential and therefore knows all witness material — it can compute honest PLONK proofs. But in the **challenge phase**, B queries the oracle on the challenge scope `S_b` and receives back the challenge nullifier `n*`. B must now produce a valid PLONK proof of `ScopedAgentAuth` with `scopedNullifier = n*`. The constraint in the circuit is:

```
scopedNullifier = Poseidon2(scopeId, scopeBlindingSecret)
```

B does not know `k`. It cannot satisfy this constraint with an honest witness. The proof sketch (§4.2, step 2) punts with: *"Simulates a valid PLONK proof using the PLONK simulator (exists by zero-knowledge property)."*

This is wrong. PLONK's ZK simulator exists only in the **CRS model** and requires the **structured reference string trapdoor** (the toxic waste from the universal setup). The reduction never explains how B obtains this trapdoor. In the standard model where the SRS is honestly generated and the trapdoor destroyed, B has no simulator.

**Why it fails against the construction:** The proof sketch invokes a tool (PLONK simulation) that requires setup access the reduction doesn't have. The stated bound

$$\text{Adv}^{\text{IND-UNL-AS}}_{\mathcal{A}} \leq \text{Adv}^{\text{PRF}}_{\mathcal{B}} + \text{Adv}^{\text{KS}}_{\text{PLONK}} + \text{negl}(\lambda)$$

is not supported by the proof sketch. The knowledge soundness term is added as a patch but knowledge soundness is a property of the **extractor**, not the simulator — it doesn't give B the ability to forge a proof for an unknown witness.

**Fix path:** Either (a) work in the simulation-extractable PLONK model where a simulation trapdoor is part of the CRS, explicitly modeling who holds it; or (b) restructure the reduction so that B uses the honest witness throughout and the PRF challenge is embedded only in the nullifier comparison step, never requiring proof simulation.

**In-threat-model?** No — the security reduction as written is incomplete. The claim stands informally but the concrete bound is unproven.

---

### Attack 2: `scopeCommitment` is a stable cross-scope identifier — colluding RSes trivially link the agent

**Attack:**
The circuit defines `scopeCommitment` as a **public output** (§2.2):

```
scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)
```

`credentialCommitment = Poseidon5(modelHash, opPubAx, opPubAy, permissionBitmask, expiryTimestamp)` is deterministic and agent-specific. Therefore `scopeCommitment` is **identical across every scope** for the same agent credential.

The verification flow (§2.5, step 3) sends `(proof, publicSignals)` directly to each RS. `publicSignals` includes `scopeCommitment`. Two colluding RSes — Amazon and Costco in the §7 deployment scenario — each receive a proof from the same agent. They compare `scopeCommitment` values. They match. The agent is linked across scopes with zero cryptographic work. No PRF needs to be inverted.

The collusion resistance argument (§4.3) claims: *"The `scopeCommitment` is identical across scopes for the same agent, but `scopeCommitment` is only revealed to the delegation chain verifier (on-chain), not to individual RSes in the direct-verification flow."* This directly contradicts the circuit spec in §2.2, which lists `scopeCommitment` as a public output, and §2.5, which has the agent send `publicSignals` to the RS. One of these descriptions must be wrong; in the current circuit, RSes see it.

**Why the IND-UNL-AS game misses this:** The game (§3.2) tests whether $\mathcal{A}$ can determine *which of two unused scopes* a single proof was generated for. Since both $S_a$ and $S_b$ would produce the same `scopeCommitment` for the same agent, the game is insensitive to this leakage — the game is simply measuring the wrong thing. The primary unlinkability threat is **cross-proof linkability** (can a colluding set of RSes determine that $\pi_i$ and $\pi_j$ came from the same agent?), and this is not captured by IND-UNL-AS.

**Fix path:** Remove `scopeCommitment` from the circuit's public outputs entirely and keep it only as an on-chain delegation verifier input (a separate circuit pass). Verify that the delegation extension can thread the chain without exposing a stable cross-scope identifier to leaf RSes.

**In-threat-model?** No — breaks the core unlinkability claim stated in §1 and the collusion resistance argument in §4.3. The §7 scenario ("Amazon and Costco cannot determine these came from the same agent") is false under the current circuit definition.

---

### Attack 3: IND-UNL-AS game captures the wrong adversary — the real threat is RS collusion, not AS observation

**Attack:**
The game (§3.2) places the AS as the adversary and measures scope indistinguishability: can the AS tell which of two *unused* scopes a proof was generated for? But in the stated construction, **the AS never sees any proofs** — it is removed from the authorization path entirely (§2.5: "The AS is never contacted"). The AS is reduced to an enrollment registrar. A game where the AS is the adversary and the AS never receives proofs is trivially won by the construction even if there were no ZK at all — the AS has no signal.

The actual claim in §1 is: *"unlinkability holds against collusion between AS and any subset of RSes."* The threat that matters is: colluding RSes share their received `(agentMerkleRoot, scopedNullifier, epochBinding)` tuples (and, per Attack 2, `scopeCommitment`) and attempt to reconstruct the agent's traffic graph. This is a **cross-session linkability** game, closer to the BBS+ multi-show unlinkability game or the session linkability games from anonymous credential literature. It requires:

- Multiple challenge proofs (not just one)
- Multiple RSes as adversarial parties
- A win condition of linking two sessions to the same agent (not identifying which scope was used)

The IND-UNL-AS game as written does not formalize this. The collusion resistance argument in §4.3 is a prose hand-wave: *"Linking any two requires inverting Poseidon2 on the `scopeBlindingSecret`."* No game. No reduction.

**Why it fails against the construction (partially):** Assuming Attack 2 is fixed (scopeCommitment removed from public outputs), the remaining public outputs are `(agentMerkleRoot, scopedNullifier, epochBinding)`. The `agentMerkleRoot` is a global tree state shared by many agents — it doesn't identify an individual unless the tree is sparsely populated. The `scopedNullifier` is scope-specific and PRF-pseudorandom. In this cleaned-up version, the PRF argument *does* informally support collusion resistance. But there is no formal game that captures it.

**In-threat-model?** The formal claim is not in threat model — no game definition covers the stated collusion resistance property. The informal argument is plausible (pending Attack 2 fix) but the claim of formal security with a concrete reduction is false.

---

### Attack 4: `scopeBlindingSecret` is a master tracking key with no forward secrecy

**Attack:**
Section 2.3 specifies the blinding secret lifecycle:

> `scopeBlindingSecret = Poseidon2(operatorPrivKey, "bolyra-scope-blind")`

This is a **deterministic, static derivation from the operator's private key**. Consequences:

1. **Key compromise deanonymizes all past and future authorizations.** If the operator's private key is leaked — which is the dominant failure mode in practice (phishing, HSM misconfiguration, compromised CI secrets) — an adversary can compute `scopeBlindingSecret` and then compute `Poseidon2(scopeId, scopeBlindingSecret)` for every known or guessable `scopeId`. Against any RS that stored its nullifier log, this retroactively reconstructs the full cross-scope traffic graph. The construction provides **no forward secrecy** for the blinding secret.

2. **AS-as-issuer precomputation attack.** The AS (operator) issues credentials. The operator's private key IS the operator's key, which derives `scopeBlindingSecret`. If the credential issuer IS the operator (the common case: NFCU issues agent credentials to NFCU members), the issuer can derive `scopeBlindingSecret` for every agent credential it issued, then precompute nullifiers for all known `scopeId` values. Against a cooperative RS log, the AS reconstructs the merchant graph — exactly the attack the construction claims to prevent. This is structurally identical to the "AS knows scope_id → precompute nullifiers for enrolled agents" pitfall flagged in the attack prompts.

3. **Blinding-secret-to-credential binding constraint is untested.** Constraint 10 (§2.2) binds `scopeBlindingSecret` to `credentialCommitment` via an internal commitment. But the circuit never verifies that `scopeBlindingSecret` was derived from the operator key as specified in §2.3 — it only checks that it's consistent with the credential commitment via a Poseidon hash. An agent can substitute ANY field element as `scopeBlindingSecret` (one per scope, if desired), which breaks double-spend detection: the same agent can present different blinding secrets to the same RS, generating different nullifiers and bypassing the scope-local uniqueness check.

**Why it works:** The construction conflates the operator key (authorization secret, potentially held by an institution) with the privacy secret (blinding). In a well-designed anonymous credential system, the blinding randomness is per-show or per-credential, never derived from an institutional key. The §7 NFCU scenario assumes NFCU cannot learn the merchant graph — but NFCU holds the operator private key and can derive the blinding secret for every credential it issued.

**In-threat-model?** No — the AS-as-operator precomputation attack is in-scope (the AS is explicitly in the threat model, §3.1) and trivially succeeds when AS = credential issuer. Forward secrecy failure is an explicit non-goal only for IP correlation (§3.3); `scopeBlindingSecret` lifetime is unaddressed.

---

### Summary table

| Attack | Breaks which claim | Formal severity | Fixable? |
|---|---|---|---|
| 1. Reduction simulator gap | §4.2 concrete security bound | Proof incomplete | Yes — restructure reduction or use simulation-extractable PLONK |
| 2. `scopeCommitment` stable identifier | §4.3 collusion resistance, §7 deployment | Construction broken as specified | Yes — remove from public outputs |
| 3. Wrong game / collusion not formalized | §3.2 + §1 unlinkability claim | Formal claim overstated | Yes — define cross-session linkability game |
| 4. `scopeBlindingSecret` master key | §1 + §7 AS unlinkability | Design-level failure for AS-as-issuer deployments | Requires rearchitecting blinding secret lifecycle |


## Persona: cu_ciso

### Attack 1: The Construction Destroys the Audit Trail the Examiner Requires

- **Attack:** Section 7 explicitly celebrates that "NFCU has no visibility into which merchants the agent subsequently contacted, when, or how often. The merchant graph is cryptographically hidden." I hand that sentence to my NCUA examiner verbatim. Under **NCUA Part 748 Appendix A §III.C.4** ("monitoring, detection, and response"), I must maintain audit trails of access to member financial data sufficient to reconstruct incidents. Under **GLBA Safeguards Rule 16 CFR §314.4(h)**, I must monitor activity and detect unauthorized access — which requires knowing what authorized access looked like. Under **FFIEC CAT Domain 3** (Cybersecurity Controls), logging and monitoring of transactions is a baseline maturity requirement. If my agent authorizes a $9,800 payment to a merchant and the transaction is later disputed as fraud, I cannot produce an access log tying the agent's authorization to that RS session. The construction hands me cryptographic unlinkability as a feature. My examiner calls it a missing audit log. I will fail the examination.

- **Why it works / why it fails against the construction:** The construction has no answer here. Its entire value proposition for AS-privacy IS the destruction of the correlation log. There is no opt-in audit mode described, no selective disclosure mechanism for regulators, no SIEM hook, no SAR-filing data path. The threat model (§3.1) explicitly excludes "the AS" from seeing per-scope authorizations — but NCUA doesn't care about my AS topology; it cares that I can reconstruct what happened. The construction offers zero-knowledge to all parties including the regulator.

- **In-threat-model?** No — construction must address. Possible fix: a regulator-specific disclosure circuit that produces a decryptable audit record for a supervised key (e.g., NFCU's compliance HSM) without revealing it to other RSes. This is a standard "regulatory trapdoor" pattern absent here.

---

### Attack 2: `scopeBlindingSecret` Is an Unrevocable Bearer Credential Living in Browser Storage

- **Attack:** Section 2.3 states: "stored alongside the agent's credential material. It never leaves the agent's local storage." My Vendor Management Policy requires me to classify all credential material by custody tier. Under **GLBA Safeguards Rule §314.4(c)**, I must inventory systems that access, store, or transmit customer information. The `scopeBlindingSecret` deterministically derives every nullifier for every scope this agent will ever touch. It is a permanent master key. If it leaks — malware, session hijack, insecure storage in IndexedDB or a mobile keychain — the attacker can recompute `Poseidon2(scopeId_X, scopeBlindingSecret)` for every RS the agent has ever visited, retroactively reconstructing the full merchant graph. Unlike an OAuth refresh token (revocable at the AS) or a DPoP key (bound to a session), there is no revocation mechanism described anywhere in this construction. The construction says I cannot link across scopes — the construction does not say what happens after `scopeBlindingSecret` exfiltration, because after exfiltration, I *can* link across scopes, and I have no way to know it happened.

- **Why it works / why it fails against the construction:** The construction's §3.1 "adversary does NOT control: the agent's local execution environment" is an assumption, not a control. My Tier 1 ops team cannot enforce that assumption. There is no described mechanism for `scopeBlindingSecret` rotation, revocation, or hardware binding. The credential commitment can be revoked (remove from Merkle tree), but that doesn't invalidate the blinding secret — an attacker who exfiltrated `scopeBlindingSecret` before revocation retains the ability to correlate historical proofs indefinitely.

- **In-threat-model?** No — construction must address. Required additions: (1) hardware-binding rationale (TPM, Secure Enclave) or explicit call-out that software storage is out-of-scope; (2) a `scopeBlindingSecret` rotation protocol that produces new nullifiers without re-enrollment; (3) a revocation signal that invalidates the blinding secret, not just the credential commitment.

---

### Attack 3: `scopeCommitment` Is a Stable Cross-Scope Fingerprint Sent to Every RS

- **Attack:** Section 2.2 lists `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` as a **public output** of `ScopedAgentAuth`. `credentialCommitment` is agent-specific and constant across all scopes. `permissionBitmask` is also constant for a given credential. Therefore `scopeCommitment` is the same value in every proof this agent generates, regardless of scope, regardless of RS, regardless of epoch. Section 4.3 claims "The `scopeCommitment` is identical across scopes for the same agent, but `scopeCommitment` is only revealed to the *delegation chain verifier* (on-chain), not to individual RSes in the direct-verification flow." But this directly contradicts §2.2: if `scopeCommitment` is a public output of the circuit, it is included in the `publicSignals` array sent to the RS along with the proof. The RS cannot verify the proof without the full public signal vector. Amazon and Costco both receive `scopeCommitment = 0xABCD1234`. They compare notes. They have just linked the same agent across scopes using a value the construction itself produces as a public output.

- **Why it works / why it fails against the construction:** The construction has an internal inconsistency. §4.3's collusion-resistance argument relies on RSes not seeing `scopeCommitment`, but §2.2 lists it as a public output. Either (a) `scopeCommitment` must be removed from the RS-facing proof and retained only for on-chain delegation verification, which requires circuit redesign, or (b) the collusion-resistance argument is wrong as stated. The IND-UNL-AS game in §3.2 does not include `scopeCommitment` in the adversary's observation, but the actual verification flow does include it. The game does not model the actual protocol.

- **In-threat-model?** No — construction must address. Fix: split the public output set. For direct RS verification, suppress `scopeCommitment` from the verifier-visible signal set and use a separate on-chain delegation proof path that reveals `scopeCommitment` only to the smart contract. This requires either a nested proof or a separate circuit invocation. The constraint count in §6 does not account for this.

---

### Attack 4: On-Chain Registry SLA and My Core Processor Contractual Obligations

- **Attack:** Section 2.5 step 4 requires the RS to verify the PLONK proof "against the on-chain `agentMerkleRoot` (via root history buffer lookup)." The 30-entry root history buffer (§3.3 side-channel table) means that if block production pauses, if Base Sepolia has a sequencer outage, or if the root buffer rolls over before a proof is submitted, the verification fails. My core processor (Jack Henry, Fiserv, FIS) has contractual 99.95% uptime SLAs. Base Sepolia's sequencer — operated by Coinbase — has no SLA I can sign. I cannot contractually bind a blockchain to my NCUA examination commitments. Under **NCUA Part 748 Appendix B §IV** (third-party service provider oversight), I must assess the operational risk of every vendor on the critical path of member authentication. "Smart contract correctness assumption" (§3.1) and "30-entry root history buffer" are not vendor contracts. If an agent-initiated payment fails because the on-chain root is stale during a network hiccup, my Tier 1 ops team gets the 2am call. The construction's §3.3 side-channel table documents a Merkle root staleness mitigation but does not describe the operational runbook when that mitigation is exhausted.

- **Why it works / why it fails against the construction:** The construction correctly identifies that root staleness is a risk and proposes a 30-entry buffer. But 30 entries on Base Sepolia at ~2s block time gives approximately 60 seconds of tolerance. Any sequencer pause longer than 60 seconds causes all in-flight proofs to fail verification. The construction has no described fallback mode, no degraded-operation path, and no SLA commitment. My examiner's third-party risk questionnaire has a line item for "documented availability SLA." This field cannot be filled with "blockchain liveness assumption."

- **In-threat-model?** No — construction must address. Required: (a) explicit availability SLA commitment or acknowledgment that the on-chain registry inherits L2 sequencer availability; (b) a defined fallback verification path (e.g., off-chain signed root cache operated by the CU) for sequencer outage periods; (c) a Vendor Management Policy template showing how a CU documents Base Sepolia as a third-party service provider under NCUA Part 748 Appendix B. Without these, I cannot recommend this to my board.


## Persona: rfc7662_advocate

> *OAuth Working Group veteran. Ten years of production introspection. Every ZK claim is suspect until proven not achievable by composing the toolbox. Let's see what §8 actually proves — and what it silently assumes.*

---

### Attack 1: `scopeCommitment` is a globally stable agent fingerprint visible to every RS

- **Attack:** The construction lists `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` as a **public output** of `ScopedAgentAuth` (§2.2, Public outputs table). Every RS verifying the PLONK proof receives all public outputs. Since `credentialCommitment = Poseidon5(modelHash, opPubAx, opPubAy, permBitmask, expiry)` is stable per credential, and `permissionBitmask` is fixed, `scopeCommitment` is a **globally unique, time-stable identifier** for the agent. Amazon sees it. Costco sees it. Any two colluding RSes trivially link their proofs: `scopeCommitment_Amazon == scopeCommitment_Costco` ↔ same agent.

  §4.3 attempts a rescue: "scopeCommitment is only revealed to the delegation chain verifier (on-chain), not to individual RSes in the direct-verification flow." This directly contradicts the circuit definition in §2.2. In PLONK/Groth16, all public outputs are part of the verification transcript. There is no "selective disclosure" of public outputs per verifier type — every verifier calling `verifyProof(proof, publicSignals)` receives the full `publicSignals` array, which includes `scopeCommitment`. The AS-free verification flow described in §2.5 step 4 explicitly has the RS calling the verifier against public signals.

- **Why it works:** The IND-UNL-AS reduction in §4.2 argues that the adversary learns only `(agentMerkleRoot, scopedNullifier_i, epochBinding_i, scopeCommitment)`. The reduction treats `scopeCommitment` as opaque, but it is **identical** across all scopes for the same agent. Two colluding RSes sharing their received public signals don't need to break PRF — they just compare `scopeCommitment` directly. The reduction doesn't model this because the adversary in §3.2 is defined as an AS, not a colluding RS pair. But §3.1 explicitly says the adversary controls "a coalition of up to k-1 out of k Resource Servers." The IND-UNL-AS game and reduction are inconsistent with the stated threat model.

- **In-threat-model?** **Yes — construction must address this.** Either remove `scopeCommitment` from the public outputs of `ScopedAgentAuth` (relegating it to a private intermediate used only in `ScopedDelegation`), or prove that the reduction accounts for colluding RSes observing `scopeCommitment`. The §4.3 hand-wave is not a proof.

---

### Attack 2: `agentMerkleRoot` provides a population-narrowing quasi-identifier across all RS calls

- **Attack:** The public output `agentMerkleRoot` is the same value in every proof the agent generates. The on-chain root history buffer holds 30 entries (§3.3, §7 bullet 2). The root an agent proves against is determined by the tree state at proof generation time. Two RSes receiving proofs from the same agent in the same 30-root window see the same `agentMerkleRoot`. The anonymity set is *all agents enrolled between root N and root N+29*, not *all agents ever enrolled*. In the cross-CU scenario (§7), if NFCU enrolls one new agent every few minutes, the 30-root window might cover only a handful of credentials. The root alone narrows the population to O(30) candidates. Combined with the public `epochBinding` (same epoch across same-agent calls to different RSes), the intersection attack further reduces the anonymity set.

  RFC 7662 comparisons are beside the point here — this attack applies to the Bolyra construction internally. The "structural impossibility" claim in §8 doesn't hold if RSes can already narrow the population to a small set via public outputs.

- **Why it fails partially:** The adversary still cannot *confirm* two proofs are from the same agent without linking the blinded nullifiers. For large deployments (many enrollments per 30-root window), the anonymity set is large enough to be practically protective. The construction's formal game (§3.2) doesn't model anonymity-set size, so this is a gap in the security argument, not a full break.

- **In-threat-model?** **Partial.** The construction must bound the minimum anonymity set as a deployment parameter, not just claim PRF unlinkability. For small-scale deployments (early-stage CU), the root-based narrowing is a practical linkability vector the §3 threat model does not account for. Add a concrete lower bound on tree population per root epoch.

---

### Attack 3: The suggested `scopeBlindingSecret` derivation makes the adversarial AS omniscient

- **Attack:** §2.3 derives `scopeBlindingSecret = Poseidon2(operatorPrivKey, "bolyra-scope-blind")`. The `operatorPrivKey` is the **same key used to sign all credentials issued by this operator**. In the threat model (§3.1), the adversary controls the AS — and in the credit union scenario, NFCU is the operator. NFCU knows `operatorPrivKey`. Therefore NFCU can compute `scopeBlindingSecret = Poseidon2(operatorPrivKey, "bolyra-scope-blind")` directly. Knowing `scopeBlindingSecret`, NFCU can precompute `scopedNullifier_X = Poseidon2(scopeId_X, scopeBlindingSecret)` for *every known RS scope*. When NFCU (as colluding AS) shares its precomputed table with Amazon and Costco, both RSes can deanonymize every proof immediately by table lookup.

  Furthermore, if the operator issues multiple agent credentials — all signed with the same `operatorPrivKey` — all of them share the **same** `scopeBlindingSecret`. This contradicts §2.3's claim of "once per agent credential": it is actually once per operator key, covering potentially thousands of agents. The blinding constraint (constraint 10, §2.2) only checks `Poseidon2(scopeBlindingSecret, credentialCommitment)` is consistent — it does not enforce that `scopeBlindingSecret` is distinct per credential or that it wasn't derived from a key the AS controls.

- **Why it works:** The adversarial AS in §3.1 is explicitly modeled as "full control over token issuance logic." The operator IS the AS in the stated scenarios. The derivation `Poseidon2(operatorPrivKey, "bolyra-scope-blind")` places the blinding secret derivation entirely within the AS's key material. The IND-UNL-AS game in §3.2 models `scopeBlindingSecret` as unknown to the adversary (it's a private input the challenger holds), but the suggested derivation in §2.3 hands it to the adversary by construction.

- **In-threat-model?** **Yes — construction must address this.** The `scopeBlindingSecret` MUST be derived from entropy the agent controls and the operator does NOT control. For example: `scopeBlindingSecret = Poseidon2(agentLocalSecret, credentialCommitment)` where `agentLocalSecret` is generated in the agent's local enclave. The "e.g." qualifier in §2.3 is insufficient given that the provided example is catastrophically insecure against the primary adversary in §3.1.

---

### Attack 4: RFC 8693 + signed JWT assertions already close the AS hot-path gap — the residual threat is narrower than claimed

- **Attack:** §8 claims: "AS must be contacted for every token issuance. JWT introspection response is optional and still requires initial AS contact." This overstates the baseline weakness. With RFC 9068 (JWT Profile for OAuth 2.0 Access Tokens) + RFC 8707 (Resource Indicators) + RFC 9449 (DPoP), the flow is: (1) Agent requests a long-lived token bound to `resource=amazon.com`, `scope=financial_small`, with DPoP key binding. (2) AS issues a self-contained signed JWT. (3) Agent presents the JWT + DPoP proof to Amazon on every request. **Amazon never calls the AS** — local JWT verification only. The AS is contacted *once per token lifetime* (e.g., hourly), not per request. The AS sees only: "this agent was authorized for Amazon with financial_small at T=0." It does not see per-request traffic.

  Bolyra's advantage over this baseline is not "removes AS from hot path per request" but specifically: *removes AS from the per-RS-relationship authorization decision*. With RFC 8707, the AS still sees which RS the agent requested a token for, once. The construction hides even that initial relationship. §8 should be more precise: the baseline allows AS to reconstruct the **set of RS relationships** (not the frequency of access). Bolyra hides the set itself. These are different threat scenarios and the §8 comparison collapses them.

- **Why it fails against the construction:** The construction does provide a strictly stronger property: post-enrollment, the AS cannot determine *which RSes* the agent ever contacted, not merely *how often*. RFC 8693 delegation is AS-visible at every hop; RFC 8707 token requests reveal the resource; RFC 9449 DPoP proofs are AS-visible at issuance. The categorical difference is real. But...

- **In-threat-model?** **No — the construction survives, but §8 overreaches.** The "Collusion resistance: trivially broken" row in §8's comparison table claims the baseline allows "full traffic graph reconstruction." Against the per-request baseline this is true; against the RFC 8707 + long-lived JWT baseline, the AS reconstructs only the *graph topology* (which RS, once), not the traffic frequency or timing. The construction should tighten its comparative claims to distinguish "topology-unlinkable" (the real Bolyra property) from "traffic-frequency-unlinkable" (what RFC 9449 + batching can approximate). Overstating the baseline's weakness invites this exact counterattack from a standards reviewer.


## Persona: spiffe_engineer

---

### Attack 1: `scopeBlindingSecret` is a long-lived master unlinkability key with no lifecycle management

- **Attack:** SPIFFE's core discipline is short-lived identity material — X.509 SVIDs rotate on TTLs measured in hours, SPIRE does node re-attestation continuously, compromise windows are bounded. Section 2.3 of the construction explicitly makes `scopeBlindingSecret` *persistent*: "generated once per agent credential," derived as `Poseidon2(operatorPrivKey, "bolyra-scope-blind")` and "stored alongside the agent's credential material." This is a static long-lived secret. If it leaks — exfiltrated from the agent's storage, obtained via side-channel on the Poseidon derivation, or derived after the `operatorPrivKey` is compromised — the adversary recovers the ability to compute `Poseidon2(scopeId, scopeBlindingSecret)` for every scope, destroying all cross-scope unlinkability retroactively and prospectively. The IND-UNL-AS game (§3.2) models the adversary as not controlling "the agent's local execution environment," but makes no commitment about what happens after exfiltration. Section 3.1 names this assumption without bounding the exposure window.

- **Why it works:** The reduction in §4.2 assumes `scopeBlindingSecret` is never exposed to `𝒜`. This is an environmental assumption, not a cryptographic one. The construction gives no key-rotation path, no re-enrollment ceremony that generates a fresh `scopeBlindingSecret` without re-registering a new `credentialCommitment`, and no revocation mechanism that doesn't break existing on-chain nullifiers. In SPFFE terms: you built a workload identity scheme where the "private key" never rotates. That's exactly the failure mode SPIRE was designed to prevent.

- **In-threat-model?** No. The construction must specify a `scopeBlindingSecret` rotation protocol and bound the exposure window. The current §2.3 lifecycle is insufficient for production threat models.

---

### Attack 2: `scopeId` has no global namespace authority — collision creates forced linkage

- **Attack:** Section 2.1 says the RS publishes its `scopeId` "on-chain or in a well-known endpoint," with the example `Poseidon("CU-A:merchant-read")`. The input to the Poseidon hash is a human-readable string with no assigned authority, no registry, and no uniqueness guarantee. In SPIFFE, `spiffe://trust-domain/path` is hierarchically namespaced: the trust domain is a registered DNS name, and SPIRE-issued SVIDs are cryptographically bound to it. If two distinct RSes — say, a credit union's internal accounting service and an unrelated fintech — independently choose the same scope string (or an attacker registers a resource server that mirrors an existing `scopeId`), then `Poseidon2(scopeId, scopeBlindingSecret)` produces the same `scopedNullifier`. Now double-spend detection at one RS blocks legitimate access at the other RS, and both RSes hold the same nullifier — a stable cross-RS linkage that the adversary can exploit without inverting Poseidon.

- **Why it works:** The unlinkability argument in §4.3 assumes all `scopeId` values are distinct and controlled by disjoint honest parties. The construction has no mechanism to enforce this. In the cross-credit-union deployment scenario (§7), NFCU and a competing CU independently publishing scope strings with no coordination creates collision risk. The formal game (§3.2) generates `{S₁…Sₙ}` for a single credential under Challenger control — it doesn't model adversarially crafted `scopeId` values that collide with honest ones.

- **In-threat-model?** No. The construction must specify a `scopeId` assignment authority (e.g., an on-chain registry keyed by RS's on-chain identity, or a SPIFFE-style trust-domain-prefixed naming convention). Without this, namespace collision is a live attack vector not addressed anywhere in §3.

---

### Attack 3: `scopeCommitment` is a stable cross-scope identifier exposed to every RS — the unlinkability claim contradicts the circuit's public output table

- **Attack:** Section 2.2 lists `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` as a **public output** of `ScopedAgentAuth`. `credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)` is fixed for the lifetime of the credential. `permissionBitmask` is fixed. Therefore `scopeCommitment` is a stable, constant value across every proof the agent ever generates for any RS. Any RS receiving a PLONK proof sees `scopeCommitment` in the public signals. If two RSes compare their received proofs and find matching `scopeCommitment` values, they trivially link the proofs to the same agent — with zero cryptographic work, no Poseidon inversion required.

  Section 4.3 attempts to address this: "the `scopeCommitment` is only revealed to the delegation chain verifier (on-chain), not to individual RSes in the direct-verification flow." But the circuit's public output table in §2.2 contradicts this claim — there is no circuit-level mechanism that suppresses `scopeCommitment` from being included in the proof's public signal vector. Verification of a PLONK proof requires the verifier to supply all public inputs/outputs. Every RS is a verifier. Every RS sees every public output.

- **Why it works:** This is not a protocol-layer attack — it's an internal inconsistency. The security argument in §4.3 relies on a factual claim about what RSes can observe that is directly refuted by the circuit specification two sections earlier. The IND-UNL-AS game (§3.2) has the adversary-controlled RS coalition receiving "the full public output vector" per §3.2 step 2 — which includes `scopeCommitment`. The game inadvertently models the attack: the coalition compares `scopeCommitment` values across scopes and wins immediately, regardless of nullifier separation.

- **In-threat-model?** No. The construction must either (a) remove `scopeCommitment` from `ScopedAgentAuth`'s public outputs entirely and move it to a separate on-chain-only circuit variant, or (b) apply the same scoped blinding to `scopeCommitment` — e.g., `Poseidon2(scopeId, credentialCommitment)` — making it scope-local. The current design breaks its own headline claim.

---

### Attack 4: The IND-UNL-AS game is vacuous in steady state — WIMSE's adaptive adversary exposes the gap

- **Attack:** The IND-UNL-AS game (§3.2) conditions the challenge on the adversary selecting "two *unused* scopes $S_a, S_b$" — scopes for which no proof has been generated in the query phase. This restriction is unrealistic for any production deployment. In steady state, a production agent will have proven for every RS it ever accesses. At that point, the adversary has already observed `scopedNullifier_i` for every scope the agent visits. The game says nothing about the adversary's ability to correlate *behavior patterns* given a full history of nullifier observations. For example: if the agent accesses Amazon every Tuesday at 2pm (same epoch window, same `epochBinding`), the AS observing network-layer metadata can correlate this temporal regularity with a specific `epochBinding` value at Amazon even without knowing the `scopedNullifier`. The construction's epoch mitigation (§3.3, §2.4) quantizes time into 300-second windows — this reduces timing precision but doesn't defeat an adversary who simply builds a behavioral fingerprint over weeks of access patterns.

  WIMSE's architecture draft (§4, "curious intermediary" model) requires that unlinkability hold against an adaptive adversary who has observed the full history of a workload's interactions, not just a prefix of them. The construction's game allows `𝒜` to query adaptively in phase 2 but then requires the challenge scopes to be fresh — this excludes exactly the steady-state case that WIMSE considers the primary threat.

- **Why it works:** The reduction in §4.2 is sound under the game as defined, but the game is too weak. A stronger game would allow `𝒜` to challenge on *previously observed* scopes and ask "did the agent access this scope again?" — testing temporal unlinkability. The `epochBinding` is deterministic within a 300s window, meaning repeat access within the same epoch produces the same `epochBinding` value visible to the RS. An RS (who is a potential colluder) can build an access frequency fingerprint per epoch. Section 3.3 labels this "proof generation timing" and claims PLONK is constant-time — but the side-channel here is not proving time, it's the *nullifier value itself* as a temporal access indicator, which is structural to the design.

- **In-threat-model?** Partially. The construction explicitly scopes IP correlation as out-of-scope (§3.3) and notes transport-layer anonymization as a non-goal. But temporal behavioral fingerprinting via `epochBinding` reuse is a cryptographic-layer correlation, not a transport-layer one. The formal game must be strengthened to a **repeated-access** variant, and the construction must either prove security under it or explicitly bound the residual temporal leakage.
