# Tier 3 Adversarial — C1 Selective scope proof

## Persona: auth0_pm

---

### Attack 1: The AS-Blind Property Is a Security Liability, Not a Selling Point

- **Attack:** The construction calls "AS-blind presentation" a differentiating feature (Section 1, 5th property). But every enterprise security team I've ever talked to treats AS visibility as a *control requirement*, not a limitation to route around. We sell centralized policy enforcement. SIEM integrations. Real-time scope policy updates without reissuing tokens. If the AS can't see what the agent disclosed to RS-A vs RS-B, your SOC can't correlate a breach. Your incident response team can't answer "what did the compromised agent access?" The adversarial-AS threat model assumes you distrust your own authorization server — which means you distrust your own infrastructure. No enterprise CISO signs off on that.

- **Why it works / why it fails:** The construction never addresses what the audit trail looks like at the AS level. If the AS is blind to the presentation, the AS log is empty. NCUA examiners asking for access logs for GENIUS Act compliance will get: nothing. The RS log has a proof, but regulators audit the *issuer*, not the resource server. This is a structural gap the "Why baseline fails" section skips entirely — it lists 5 impossibility axes but none of them are "auditability."

- **In-threat-model?** No — construction must address. The scenario explicitly invokes NCUA/GENIUS Act compliance (Section 7) but the AS-blind property directly undercuts the audit trail those regulations require.

---

### Attack 2: Revocation Is Impossible and the Construction Doesn't Say So

- **Attack:** RFC 7662 introspection gives me a live, real-time answer: is this token still valid *right now*? If an agent is compromised at 14:00, I call `/introspect` at 14:01 and the token is dead. With a ZK proof, what do I do? The proof was valid at issuance. The private `permissionBitmask` was committed. The EdDSA signature from the operator is baked in. If the operator revokes that agent's credentials, every proof that agent already generated and cached is still cryptographically valid — the RS has no way to know the credential was revoked. You'd need an on-chain nullifier check per-proof, which adds a blockchain round-trip to every RS verification. That's not in the construction (the nullifier in `AgentPolicy` is for replay prevention, not revocation). The construction's Section 6 quotes <0.8s proving time but doesn't quote RS verification latency with a live nullifier lookup.

- **Why it works / why it fails:** Section 3 (threat model) covers forgery and privacy games but doesn't include a revocation game. The SSF and SP games assume a static credential world. Enterprises credential-rotate constantly — key compromise, employee offboarding, M&A. The construction is silent on the lifecycle.

- **In-threat-model?** No — construction must address. Until there's a concrete revocation mechanism that doesn't require an on-chain lookup (or the construction explicitly scopes out credential revocation and justifies why), every procurement security review will kill this on this question alone.

---

### Attack 3: The 0.8s Proving Claim Assumes Hardware the Agent Doesn't Have

- **Attack:** Section 6 says "<0.8s rapidsnark proving." `rapidsnark` is a native binary. Where does it run? The construction's own architecture (`CLAUDE.md`, MCP demo) has the prover running in a Node.js subprocess bridged from a Python SDK. In practice, an MCP-connected AI agent runs in a Lambda, a container, a managed inference endpoint. None of those environments can exec a native rapidsnark binary without a sidecar. The Python SDK docs explicitly say "all proving spawns the Node `@bolyra/sdk`" — that's a subprocess fork from Python to Node to a native binary. The latency on a cold Lambda is not 0.8s. It's probably 3-8s with cold-start overhead, and it breaks entirely in sandboxed environments (Cloudflare Workers, AWS Lambda with restricted exec). WorkOS issues tokens in <100ms with a single HTTPS POST to a managed endpoint that runs anywhere.

- **Why it works / why it fails:** The construction's cost section (Section 6) is internally consistent for the stated hardware but doesn't model the deployment environment of a typical MCP agent. The "128-byte proof" and "<0.8s" figures will appear in every sales conversation as the benchmark, and the first customer to actually deploy will find neither holds in their environment.

- **In-threat-model?** No — construction must address. The GTM story requires a credible answer to "where does this run in my existing agent infrastructure?" A benchmark against an offline rapidsnark binary is not that answer.

---

### Attack 4: The 8-Bit Bitmask Scenario Doesn't Need ZK — It Needs Encryption

- **Attack:** The Pacific Federal Credit Union scenario (Section 7) uses exactly 8 permission bits across 3 agent types. The claim is that ZK is necessary because the agent "proves it satisfies a required permission predicate without revealing the full permission set." But for 8 bits, the RS already knows all 8 possible permissions exist — that's the schema. The privacy being protected is which *subset* the agent holds. I can achieve identical privacy with a standard approach: agent presents a JWT signed by the operator, RS holds a public key, JWT contains a commitment (hash) to the bitmask, and the operator provides a separate per-RS disclosure envelope signed over `(commitment, required_scope_mask, RS_id)`. That's RFC 8693 token exchange with a custom claim. No circuit. No trusted setup. No binary dependency. The ZK is doing work that a well-scoped JWT design already handles for the 8-bit case. The "2^64 permission space" scenario in the construction's gap-to-close is where ZK becomes *necessary* — but Section 7 doesn't demonstrate that scenario. It demonstrates a scenario where ZK is *sufficient* but not *necessary*.

- **Why it works / why it fails:** The "Why baseline fails" section (Section 8) lists 5 structural impossibility axes. The strongest one — adversarial-AS model — is real. But the PCFCU scenario doesn't invoke adversarial AS. The credit union controls its own AS. The construction needs a scenario where adversarial AS is actually operative, or the impossibility argument is decorative.

- **In-threat-model?** Partially. The cryptographic claim is valid in the adversarial-AS scenario. But the GTM scenario as written doesn't instantiate that scenario, leaving the buyer without a concrete reason to accept the proving overhead over a well-scoped JWT.


## Persona: cryptographer

Applied cryptographer. I've reviewed the construction document. My objections follow.

---

### Attack 1: Trusted Setup Subversion Breaks SSF Unconditionally

**Attack:** The `AgentPolicy` circuit uses Groth16 with a project-generated CRS from `pot16.ptau`. The claimed reduction is `SSF → KS-Groth16`. But KS-Groth16 (knowledge soundness of Groth16) holds only in the **Generic Group Model under an honestly generated CRS**. An adversary who controls the toxic waste from the `pot16.ptau` ceremony — or who compromises the single coordinator who ran it — can forge a valid Groth16 proof for *any* statement, including claiming arbitrary permissions (`permissionBitmask = 0xFF`) with no corresponding EdDSA credential. This is not a theoretical edge: it requires access to one ceremony participant who retains their randomness, forever.

**Why it matters here:** The threat model lists "adversarial AS" as in-scope. An adversarial AS that also ran the trusted setup ceremony (which is plausible — Bolyra as an organization would naturally run its own setup) gets the toxic waste as a side-effect of their legitimate role. The SSF game then collapses entirely: the adversary wins by producing a valid proof for a false statement, bypassing the `EUF-CMA-EdDSA` check entirely because the forgery never needs a credential at all.

**In-threat-model?** **No — the construction must address this.** The threat model states "adversarial AS" but does not scope out "AS controlled the ceremony." Either (a) use a PLONK-only construction (PLONK's universal SRS requires only one honest participant from a large ceremony — Hermez, Ethereum KZG), (b) run a verifiable MPC ceremony with public transcripts, or (c) explicitly add "honest CRS generator" to the trust model and explain why this is acceptable. The current text says "reduces to KS-Groth16" as if the premise is free — it is not.

---

### Attack 2: HVZK Does Not Imply SP-Security Against a Colluding AS + RS

**Attack:** The SP (privacy) game places the AS as the adversary who also controls a colluding set of RSes. The zero-knowledge property invoked in the security argument is Groth16's standard ZK, which is **honest-verifier ZK (HVZK)** — the simulator works because the verifier provides no challenge during proof generation. The construction correctly notes that Groth16 proofs use fresh prover randomness and the verifier is non-interactive, so HVZK extends to full ZK here.

However, the SP game claim is stronger than ZK alone: it claims the AS cannot learn *which scope was presented to which RS, nor correlate presentations across RSes*. This requires **simulation-extractability (SE)** or at minimum **proof-of-knowledge with unlinkability**, not just ZK.

Specifically: the AS issued the credential and knows `H(credential)`. The AS sees the nullifier `H(H(credential), scope_id)` at the RS (if the RS reports it, which a colluding RS will). Since `scope_id` is a public input to the RS (they choose what they accept), the AS can enumerate `H(H(credential), scope_id)` for all known `scope_id` values and match against the reported nullifier. This is an **offline linkage attack** that reveals *which agent visited which RS*, leaking usage patterns even without breaking ZK.

**Why it works:** The SP game as described focuses on bitmask privacy but does not explicitly define an unlinkability experiment. A proper SP game should include a challenge where the adversary wins if they can link proof π₁ (to RS₁) and proof π₂ (to RS₂) to the same credential. The current game definition omits this experiment.

**In-threat-model?** **No — the construction must address this.** Either define a separate unlinkability game with a formal experiment, or explain that `scope_id` is secret to the agent (but then how does the RS know to set it?), or add blinding to the nullifier scheme such that the AS cannot enumerate linkages.

---

### Attack 3: Underconstrained Circuit — Cumulative Bit Implication Not Enforced In-Circuit

**Attack:** The permission model specifies cumulative implication rules: bit 3 (`FINANCIAL_MEDIUM`) implies bit 2 (`FINANCIAL_SMALL`); bit 4 (`FINANCIAL_UNLIMITED`) implies bits 2 and 3. The CLAUDE.md notes: "`validateCumulativeBitEncoding()` enforces the implication rules; the `Delegation` circuit enforces them on-chain." The `AgentPolicy` circuit constraint is:

```
reqBits[i] * (1 - permBits[i]) === 0
```

This checks only that every required bit is set — it does **not** verify that the private `permissionBitmask` is internally consistent with the cumulative implication rules.

**Concrete exploit:** An adversarial AS issues a credential with `permissionBitmask = 0b00001000` (bit 3 set, bit 2 NOT set — violating the implication rule). The AgentPolicy circuit proves "bit 3 satisfied" to RS₁ and "bit 3 satisfied" to RS₂. The RS receiving the proof for `requiredScopeMask = 0b00001000` accepts it and grants FINANCIAL_MEDIUM. But the agent cannot prove `requiredScopeMask = 0b00000100` (bit 2) because bit 2 is not set in the malformed credential. A semantically valid credential should allow proving any implied lower permission — but this one doesn't, silently. More critically, the RS at RS₁ cannot tell whether the credential was legitimately issued or is malformed; both produce valid proofs for `reqBits[3]`.

The construction claims "adversarial-AS-resilient" — but an adversarial AS can issue bitmasks that violate the protocol's own semantic model without the RS or verifier detecting it, because the circuit does not enforce implication invariants.

**In-threat-model?** **No — the construction must address this.** Add circuit constraints that enforce implication rules: `permBits[4] * (1 - permBits[3]) === 0`, `permBits[4] * (1 - permBits[2]) === 0`, etc. This adds ~6 constraints (negligible at 38,500 total) and makes the circuit self-consistent regardless of what the AS issues.

---

### Attack 4: The "Runtime-Adaptive" Claim Has No Formal Game Definition — and May Collapse to RFC 7662

**Attack:** The construction lists "runtime-adaptive predicate" as a property that RFC 7662 + RFC 8707 + DPoP cannot express. The claim is that the agent *chooses at the moment of use* which scope predicate to prove, without a prior issuance step that fixes scope.

However, in the AgentPolicy circuit, `requiredScopeMask` is a **public input provided by the RS** (or agent), not a statement fixed at credential issuance. This is the source of "runtime adaptivity." Now consider the RFC 7662 baseline with RFC 8707 (Resource Indicators):

- RFC 8707 allows the token request to name the specific resource server and requested scope.
- The AS returns a token scoped to that RS and those permissions.
- The RS verifies offline via JWT introspection response.

The semantic difference: in RFC 7662, the AS sees which RS and which scope are being requested (at token-request time). In the ZK construction, the AS does *not* see the presentation. This is the genuine AS-blind distinction.

But the "runtime-adaptive" framing implies the agent can choose *after credential issuance* which predicate to prove. This is just standard ZK selective disclosure — it is not runtime-adaptive in any security-meaningful sense. The credential's permissions are fixed at issuance. The proof is selective at presentation time. This is definitionally the same as what a JWT with a rich claims set + RS-side policy provides: the RS checks only the claims it cares about.

**Formal objection:** There is no game definition for "runtime-adaptive predicate security." Without one, this is a UI description, not a security property. The claim must either (a) be retired as marketing, or (b) be formalized as: "the agent can prove any predicate from a family F of predicates over their credential, chosen after issuance, without re-contacting the AS" — which then requires a simulation-based definition of what F can contain and what the AS learns.

**In-threat-model?** **Ambiguous — but the claim as stated is unfalsifiable without a formal definition.** The construction should either drop "runtime-adaptive" as a named property (it falls out of the basic ZK selective disclosure argument) or provide a game `G_RA` that distinguishes it from JWT-with-offline-verification.


## Persona: cu\_ciso

---

### Attack 1: FIPS Cryptography Mandate Violation

- **Attack:** The construction is built on Poseidon hash and BabyJubjub EdDSA (Section 5, Primitive Mapping). I pull up GLBA Safeguards Rule (16 CFR Part 314.4(e)) and FFIEC CAT Domain 1, Control 1.3: all cryptographic controls protecting member information must use NIST-approved algorithms. Poseidon is not NIST SP 800-185. BabyJubjub is not an approved curve under FIPS 186-5. Neither has a FIPS 140-3 module validation. My NCUA examiner's questionnaire for third-party technology explicitly asks: "Does the solution use FIPS-validated cryptographic modules?" The answer here is **no** — and that answer ends the procurement conversation, not mine.

- **Why it works / fails:** The construction does not address this at all. It asserts ZK-soundness security reductions (Section 4) but never maps its primitives to FIPS or NIST standing. The entire differentiation claim (constant-size, AS-blind) is built on non-validated primitives. Swapping Poseidon for SHA-256 or BabyJubjub for P-256 breaks the circuit compatibility outright — `AgentPolicy.circom` would need a complete rewrite and new trusted setup.

- **In-threat-model?** No. The construction's threat model (Section 3) formalizes SSF/SP games against a cryptographic adversary. It does not model a compliance adversary who rejects the entire primitive set before the proof is even verified. **Construction must address this.**

---

### Attack 2: Incident Response — the Proof is the Black Box

- **Attack:** It's 2am. An agent authorized under this scheme transferred $47,000 above its `FINANCIAL_MEDIUM` threshold. My ops team calls me. I call my general counsel. We pull the audit log. What we find is a 128-byte Groth16 proof blob and a public `requiredScopeMask` bitmask. The *actual* `permissionBitmask` the agent held is **private by construction** (Section 2). NCUA Part 748 Appendix B, Section III.C requires the incident response program to include evidence collection adequate to support regulatory examination and potential legal action. I cannot show an examiner what permissions the agent actually claimed. The privacy guarantee — the core selling point — is also my forensic liability.

- **Why it works / fails:** The SP game (Section 3) formally guarantees that a colluding RS cannot learn the private bitmask. But the CU's own incident response team is not modeled as a trusted party with key-recovery rights. There is no mention of an escrow or audit-log mechanism that preserves the full permission set under CU-controlled keys for post-hoc inspection. The construction cannot simultaneously claim "AS-blind" privacy *and* "examiner-legible audit trail" without an explicit privileged-disclosure path — and that path is absent.

- **In-threat-model?** No. The threat model treats the CU operator as an honest participant who issues credentials. It does not model the CU as a forensic investigator needing to pierce the ZK veil under regulatory compulsion. **Construction must address this** — likely a dual-path design: ZK proof for RS-facing presentation, plaintext-signed audit record encrypted to CU's HSM key retained for 7 years per NCUA retention schedules.

---

### Attack 3: Trusted Setup Ceremony — No SOC 2 Surface

- **Attack:** My vendor management policy requires a SOC 2 Type II report for any system touching member authentication. I ask: who participated in the `pot16.ptau` ceremony and the project-specific `.zkey` generation for `AgentPolicy`? What's the ceremony transcript? What attestations exist that toxic waste was destroyed? Section 6 (Cost) tells me proving time is 0.8s but says nothing about who controls the `.zkey`. If the `.zkey` is compromised, a forger can generate valid proofs for any bitmask. There is no key-rotation path described. A SOC 2 auditor cannot scope a one-time, irrevocable ceremony with no rotation mechanism — it falls outside every control framework they know how to audit.

- **Why it works / fails:** The construction references the Semaphore v4 ceremony reuse for `HumanUniqueness` (CLAUDE.md, Circuits section), which has some public transcript. But `AgentPolicy` uses a project-specific `pot16.ptau`. Section 4's security argument reduces to KS-Groth16 — sound only if setup is honest. The construction does not address ceremony governance, transcript publication, or `.zkey` rotation policy. Without those, a SOC 2 Type II scope statement cannot be written, and FFIEC CAT Maturity Level 3 (which my board targets) cannot be certified.

- **In-threat-model?** No. The reduction in Section 4 assumes an honestly-generated CRS. The governance of who controls that CRS post-ceremony is entirely out of scope. **Construction must address this** — at minimum, cite the public ceremony transcript URL and define a `.zkey` rotation trigger (e.g., circuit change, key compromise disclosure).

---

### Attack 4: On-Chain Registry SLA vs. Core Processor SLA

- **Attack:** Section 7 (Scenario) places Pacific Federal Credit Union's agent authorization on a Merkle root committed on-chain (Base/Base Sepolia). My core processor (Fiserv/Jack Henry) SLA is 99.95% uptime with a defined RTO of 4 hours. Base mainnet has no signed SLA, no BAA, no regulatory capital backing any downtime claim. NCUA Letter to Credit Unions 01-CU-20 (Business Continuity) requires that third-party dependencies have documented SLAs incorporated into the CU's BCP. I cannot incorporate "Ethereum L2 consensus liveness" into a BCP narrative my examiner will accept. Every agent authorization that requires a live on-chain root check inherits the blockchain's availability risk — and that risk is uninsurable and uncontractable.

- **Why it works / fails:** The construction does not distinguish between *issuance-time* root commitment (one write, CU controls timing) and *presentation-time* root verification (every RS must check current root liveness). If root freshness is checked at presentation time, the on-chain dependency is on the critical path for every member-facing transaction. The construction's Section 6 measures proof latency in milliseconds but never models the latency or failure mode of the root-read path against an unavailable L2.

- **In-threat-model?** No. The threat model assumes the on-chain registry is available and live. It formalizes adversaries who forge proofs, not adversaries who are simply an L2 sequencer outage. **Construction must address this** — either by caching the root with a CU-controlled TTL (and specifying the staleness window acceptable under NCUA guidance), or by removing the live on-chain dependency from the presentation path entirely and making it an issuance-time-only write.


## Persona: rfc7662_advocate

> *Ten years shipping introspection endpoints. Every ZK deck I've seen has a "trust the token" slide that a well-tuned AS already handles. Let's see.*

---

### Attack 1: Per-RS Introspection Policy Already Achieves Selective Disclosure

- **Attack:** RFC 7662 §2.2 allows the AS to return only the scopes the requesting RS is authorized to see. Pair this with `draft-ietf-oauth-jwt-introspection-response` and the RS verifies a signed, scoped JWT offline—no hot-path AS roundtrip. For an 8-bit permission space, the AS maintains a policy table of size (RSes × permission-bits). The RS receives only the bits it is entitled to see, never the full bitmask. Your claim §1 ("reveals nothing about permissions beyond satisfying the predicate") is achieved by AS-side policy, not ZK.

- **Why it fails against the construction:** The baseline requires the AS to *decide* which bits to reveal and *cooperate at issuance time* by placing only those bits in the JWT. The construction's `AgentPolicy` circuit is evaluated entirely client-side: the agent, at runtime, selects which presentation to make against a freshly-specified `requiredScopeMask`. The AS never learns which RS is being targeted, and cannot retroactively lie about what was in the credential. The structural gap: AS-side filtering is *disclosure by proxy*; the ZK proof is *self-asserted scope satisfaction* with the AS cryptographically excluded from the presentation path.

- **In-threat-model?** Yes — construction survives, but §8 ("why baseline fails") must name the AS-cooperation assumption explicitly. As written, a reader familiar with JWT introspection caching could miss that the AS still chose the JWT's content at issuance knowing the audience.

---

### Attack 2: Audience-Bound Tokens + PPIDs Break Cross-RS Linkability Without Any ZK

- **Attack:** RFC 8707 resource indicators bind tokens to a specific RS audience. OIDC pairwise pseudonymous identifiers (PPIDs) give each RS a different `sub` claim. Combined, the RS sees a token scoped to itself with a sub that is unlinkable to other RSes—at the RS level. Your claim §3 (adversary controls "colluding RSes") is already defeated by PPIDs: even if RS-A and RS-C collude and compare tokens, `sub` values differ. Why is anything beyond this load-bearing?

- **Why it fails against the construction:** PPIDs protect the *human subject* identifier from RS-level correlation—they do not protect the *permission set* from AS-level observation. The AS computes every PPID and issues every audience-bound token; it observes which RS the agent is connecting to at each issuance event. The construction's SP game (§3) places the adversary *at the AS*—the AS itself is the entity that must learn nothing about which RS the agent is contacting at proof time. PPIDs shift correlation risk from RSes to the AS, but the AS is the adversary in the threat model. The ZK proof is generated agent-side with no AS roundtrip, so the AS never observes the `(agent, RS, timestamp)` triple at proof time.

- **In-threat-model?** Yes — but the construction must state explicitly that the AS-as-adversary model is the threat PPIDs do not cover, and that the "AS-blind" property (§1) is defined relative to an AS that has already issued the credential but must learn nothing at *presentation* time.

---

### Attack 3: The Adversarial-AS Claim Collapses if the AS Is the Credential Issuer

- **Attack:** The construction's §3 threat model says the adversary controls the AS and cannot forge valid scope proofs. But `createAgentCredential(modelHash, operatorPrivKey, permissions, expiry)` is signed by `operatorPrivKey`. In OAuth deployments, the AS *is* the operator. If the AS holds `operatorPrivKey`, it can issue a credential asserting `permissionBitmask = 0xFF` (all permissions) for an agent that was only authorized for `READ_DATA`. The ZK proof will then validly prove the predicate over a *fraudulently inflated* bitmask. The construction's security argument (§4, EUF-CMA-EdDSA reduction) proves a third party cannot forge the credential—it does not prevent the *issuer itself* from lying at issuance.

- **Why it fails against the construction / why it is a gap:** This is a real gap if the threat model conflates "AS" (OAuth authorization server) with "operator" (EdDSA key holder). If they are the same entity, adversarial-AS resilience does not hold for the issuance phase—only for the presentation phase. The construction survives only if (a) the operator/issuer is *not* the AS being adversarially modeled, or (b) the credential is anchored to an on-chain registry the AS cannot retroactively alter. The current §8 ("why baseline fails, adversarial-AS axis") makes no distinction between issuance-time and presentation-time AS trust.

- **In-threat-model?** **No — construction must address this.** Either restrict the adversarial-AS claim to presentation-time AS (with the issuer in the trusted-setup boundary), or add an on-chain credential registry that makes post-issuance tampering detectable.

---

### Attack 4: DPoP + RFC 8693 Token Exchange Covers Runtime Delegation Narrowing — Name the Delta

- **Attack:** RFC 8693 Token Exchange allows the AS to issue a new token with a narrowed scope during delegation (`scope` parameter on the exchange request). The delegated token can contain only the bits the delegatee is authorized for. RFC 9449 DPoP sender-constrains that token to the delegatee's key. Together: scoped, sender-constrained, offline-verifiable delegation without a trusted setup ceremony. Your §2 claims the `Delegation` circuit enforces one-way scope narrowing—RFC 8693 already enforces this via AS policy. What precisely does the circuit provide that the AS-mediated exchange does not?

- **Why it fails against the construction:** RFC 8693 requires the AS to be present and cooperative at every delegation event—the AS must issue the new narrowed token. The `Delegation` circuit allows the delegating agent to narrow scope *locally and offline*, committing the constraint cryptographically such that no AS roundtrip is needed and the AS never learns the delegation occurred. For multi-hop agent chains (agent delegates to sub-agent delegates to tool), RFC 8693 requires an AS roundtrip at each hop; the circuit enforces narrowing at each hop with a single proof that the verifier checks without contacting anyone. The delta: AS-free, offline, composable delegation with cryptographic proof of the narrowing invariant.

- **In-threat-model?** Yes — construction survives. But §8 should include the multi-hop delegation case as a concrete scenario where RFC 8693 breaks down operationally (latency, AS availability, AS learning the delegation graph).

---

### Summary Table

| Attack | Claim Targeted | Survives? | Action Required |
|---|---|---|---|
| 1 — Per-RS policy filtering | AS-blind, selective disclosure | Yes | Clarify AS-cooperation assumption in §8 |
| 2 — PPIDs break RS correlation | AS-adversary in SP game | Yes | State AS-as-adversary explicitly; PPIDs don't help against AS |
| 3 — AS-is-issuer collapses adversarial-AS | EUF-CMA reduction in §4 | **No** | Separate issuance-trust from presentation-trust; add registry anchor or scope the claim |
| 4 — RFC 8693 covers delegation narrowing | Delegation uniqueness in §2 | Yes | Add multi-hop offline case to §8 |


## Persona: spiffe_engineer

---

### Attack 1: The SPIRE Plugin Trap — You Built a Workload Attestor, Not a Protocol

- **Attack:** SPIRE's architecture has explicit plugin seams for node attestors and workload attestors. A ZK workload attestor plugin could accept the `AgentPolicy` Groth16 proof as attestation evidence and produce a standard X.509 SVID or JWT SVID embedding the scope commitment as a custom SAN extension. The result: SPIFFE IDs, SDS integration with Envoy/Istio, federation across trust domains, existing mTLS infrastructure — *and* the ZK selective disclosure property. The construction's Section 1 (Claim) asserts a "new protocol" is necessary, but never engages with why this couldn't be shipped as a `WorkloadAttestor` plugin against `spire-agent`'s plugin API.

- **Why it works / fails:** It works as a framing attack because the construction doesn't bound what "layering inside SPIFFE" means. It fails technically because SVIDs are cryptographically bound to the SPIRE server's CA — the proof of scope membership would be *verified by SPIRE* (the AS), not by the RS directly. The RS would receive an SVID attesting "this workload passed ZK attestation" but the SVID itself is AS-issued, destroying the AS-blind property the construction claims in Section 1. The "no AS roundtrip" claim requires the RS to hold the `vkey.json` and verify the Groth16 proof natively. An SVID wrapper re-introduces the AS as a necessary trust anchor.

- **In-threat-model?** No — the construction should explicitly state: *any SVID-based wrapper reintroduces AS issuance as a verification dependency. The AS-blind property requires the RS to verify `vkey + proof` directly, which SPIFFE's verification path (SVID chain up to SPIRE CA) structurally cannot provide.* Section 8 ("Why baseline fails") addresses OAuth but not SPIFFE SVID specifically.

---

### Attack 2: WIMSE + SD-JWT Covers "Agent Chooses at Moment of Use"

- **Attack:** `draft-ietf-wimse-arch` has token exchange in scope. SD-JWT (RFC 9449 family, now in the IETF SD-JWT spec) achieves selective disclosure where the *holder* chooses which claims to present to which verifier at presentation time — without a ZK proof. Combine: WIMSE token exchange for workload-to-workload auth, SD-JWT for selective claim disclosure, RFC 8707 resource indicators to scope the token to the RS. The agent holds an SD-JWT with all permission claims salted and individually disclosable. At runtime it discloses only the claim matching `requiredScopeMask`. This directly targets the construction's "AS-blind, agent chooses what to disclose at the moment of use" from Section 1.

- **Why it works / fails:** It works against the naive version of the claim. It fails against the SP game (Section 3) because SD-JWT disclosure reveals *which* permissions were disclosed. An RS colluding with another RS can correlate: RS-A learns agent disclosed `READ_DATA`, RS-B learns agent disclosed `FINANCIAL_SMALL` — together they reconstruct the full permission profile. The Groth16 proof of Section 2 reveals only that `requiredScopeMask` bits are satisfied; no individual claim identity leaks. The construction's SP game captures this but the claim statement in Section 1 needs to be precise: the gap is *collusion-resistant unlinkable selective disclosure*, not merely "agent chooses at moment of use."

- **In-threat-model?** Yes, but Section 1 undersells it. The distinguishing property isn't "AS-blind" (SD-JWT can be AS-blind too if issued offline) — it's that the ZK proof is *zero-knowledge about the full bitmask under collusion*. The construction should restate the primary claim as collusion-resistance across RSes, not just AS-blindness.

---

### Attack 3: Model-Identity-Binding is Weaker Than Node Attestation

- **Attack:** The construction's fifth property — "model-identity-bound" — claims the proof binds to a specific model hash. In SPIFFE, workload identity is bound to execution context via *node attestation*: TPM quotes, k8s pod identity, AWS EC2 instance identity documents. The binding is hardware-rooted. In the AgentPolicy circuit (Section 2), `modelHash` is a *private input* — it's committed to via Poseidon hash in the credential, but the RS only verifies that the proof satisfies the circuit, not which model produced it. An operator with access to the operator private key can issue a credential committing `modelHash = H(gpt-4o)` and hand it to any workload. There is no runtime attestation that the model currently executing matches the committed hash.

- **Why it works:** SPIFFE node attestation ties identity to *observable runtime state* (what is running right now). The circuit ties identity to *a credential claim* (what the operator asserted at issuance). These are categorically different. The construction's EUF-CMA-EdDSA reduction in Section 4 only proves the credential wasn't forged — it doesn't prove the model hash commitment reflects the actually-running model. An adversary who compromises the operator key issues valid credentials for any model hash.

- **In-threat-model?** No — Section 4 never addresses the issuance-time vs runtime attestation gap. The threat model (Section 3) should bound "model-identity-bound" to *credential-bound identity under honest operator*, not runtime attestation. Alternatively, the construction should pair model hash commitment with a TEE quote or a supply-chain attestation (in-toto) to make the property non-trivially stronger than an operator assertion.

---

### Attack 4: The Adversarial-AS Game Breaks at Issuance, Not Verification

- **Attack:** Section 3 defines the adversarial-AS threat game: the AS cannot forge scope membership for permissions the agent doesn't hold. But the construction's security argument (Section 4) reduces to EUF-CMA on the *operator's EdDSA key*. The operator key signs the `permissionBitmask` at credential issuance. An adversarial AS *is* the operator — it controls that key. The adversarial-AS game collapses: the AS can issue `permissionBitmask = 0xFF` (all bits set) and the ZK proof will correctly prove any required scope is satisfied. The circuit enforces `reqBits[i] * (1 - permBits[i]) === 0` — but if the AS signed a bitmask with all bits set, every predicate passes. The construction proves *consistency* (proof matches credential) not *authority* (credential reflects actual granted permissions). WIMSE addresses this via trust domain policy: the SPIRE server won't issue an SVID for a scope the workload's registered entry doesn't permit — enforcement is at issuance, not at verification.

- **Why it works:** This is a trust anchor problem. The RFC 7662 baseline actually handles it better in one axis: the AS is the policy enforcement point, and RS-side introspection catches AS-issued tokens with inflated scope if the AS has a policy violation. With the ZK construction, once the credential is issued, the RS has no recourse — a cryptographically valid proof of an inflated bitmask is indistinguishable from a valid one. The adversarial-AS game as specified in Section 3 should clarify it only bounds *forgery without the operator key*, not *fraud by the operator*.

- **In-threat-model?** Partially. The construction should split the threat model into two sub-games: (a) forgery by non-key-holders (covered), and (b) fraud by the key-holding AS (explicitly out of scope with a trust assumption). The current draft conflates "adversarial AS" with "AS cannot lie about scope" — which the construction cannot provide without a second trust anchor (e.g., on-chain permission registry that the circuit reads via Merkle proof, making AS issuance auditable and binding).
