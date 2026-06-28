# Tier 3 Adversarial — C2 Cross-scope unlinkability

## Persona: auth0_pm

### Attack 1: The Adversarial-AS Assumption Is a Self-Defeating Premise

- **Attack:** The construction's threat model (Section 3) posits an AS that actively tries to correlate per-agent traffic graphs. In every enterprise deployment I've shipped against — credit unions, healthcare, B2B SaaS — the AS *is* the enterprise. The member's own IT team runs it, or delegates it to Auth0/WorkOS. Asking an enterprise to adopt a protocol that protects the user *from the enterprise's own infrastructure* is asking them to pay to distrust themselves. The IND-UNL-AS game is formally interesting but commercially incoherent. WorkOS's MCP auth delegates scope isolation to the Resource Server audience claim — no adversarial AS assumption needed, no ceremony.

- **Why it works:** The construction explicitly defines unlinkability against a colluding AS+RS. For the two named scenarios (cross-CU member agent, healthcare referral network), the AS *is* the regulated entity that legally owns the member relationship. HIPAA and GLBA give them access to that correlation data anyway. The ZK guarantee is moot against a subpoena.

- **In-threat-model?** No — construction must address the regulatory carve-out. The adversarial AS model needs a buyer-legible justification: who exactly is the AS, why are they adversarial, and why does the enterprise have no contract-level remedy?

---

### Attack 2: Timing Side-Channel Breaks Unlinkability Before the Math Does

- **Attack:** Section 4's reduction ties uniformity of nullifiers to CSPRNG and AS-exclusion of the blindingSalt. That's the cryptographic layer. But the construction's own gap list names "timing" as an open side channel. A colluding AS+RS doesn't need to break nullifier separation — they just need to observe that proof generation requests for RS-A and RS-B arrive in the same 15-second proving window, with the same proof size, from the same TLS endpoint. ZK proof generation time is a fingerprint. Cloudflare Access + remote MCP terminates TLS at the edge and enforces per-session token freshness in <100ms; there's no 15-second window to correlate. The construction claims unlinkability "even under adversarial AS" but the timing channel exists at the network layer, not the AS layer.

- **Why it works:** The construction explicitly notes "treatment of side channels (timing, nonce freshness)" as part of the gap to close — meaning it's unaddressed at current strength 9. A proof that takes ~15s is not just slow; it's a coarse clock signal. Two proofs generated 14 seconds apart from the same device, submitted to different RS instances, are trivially linkable by a passive network observer. No cryptography is broken.

- **In-threat-model?** Partially — the gap section acknowledges timing but the construction body has no mitigations. This needs to be addressed or the claim "even under adversarial AS" is overclaimed. A concrete bound on proof generation jitter, or a batching/delay strategy, must be specified.

---

### Attack 3: BlindingSalt Lifecycle Is Enterprise Procurement Suicide

- **Attack:** Section 3.1 specifies a three-tier storage hierarchy (HSM/TPM > OS keychain > AES-256-GCM file), a rotation ceremony, and an offline Shamir backup path. Every one of those line items is a procurement blocker. Auth0's MCP auth is an API key and a redirect URI. WorkOS is a dashboard toggle. Stytch is a `curl`. The construction's "MUST NOT" rules for AS exclusion from salt provisioning mean the enterprise's secrets management team — which already owns HSM policy — now has to carve out a special-case exception for a protocol they've never heard of. No CISO approves a custom rotation ceremony for a solo-founder stack without a SOC 2 report, an enterprise SLA, and a support escalation path that doesn't end in a GitHub issue.

- **Why it works:** The construction is technically correct that AS-exclusion from salt provisioning is necessary for the unlinkability guarantee. But "technically correct" and "enterprise deployable" are different axes. The more rigorous the lifecycle spec, the higher the deployment friction. The construction has tightened the lifecycle in this iteration — which makes the cryptography stronger and the sales motion harder simultaneously.

- **In-threat-model?** No — this is a GTM gap, not a cryptographic one. The construction must specify a managed-service path where Bolyra (or a trusted third party) handles the salt lifecycle under a BAA/MSA, so the buyer's procurement question has an answer that isn't "implement HSM key management yourself."

---

### Attack 4: Nullifier Separation Per Scope Doesn't Survive Client Attestation Comparison

- **Attack:** The gap explicitly names "prototype demonstrating nullifier separation per scope" as unbuilt. Meanwhile, `draft-ietf-oauth-attestation-based-client-auth` (Client Attestation) already provides binding between a software instance and its OAuth client ID using IETF-standardized mechanisms. A colluding AS+RS under that draft can't correlate across scopes either — the client attestation is scoped to the client's own key material, and Dynamic Client Registration (RFC 7591) lets each RS maintain independent client records. The enterprise buyer's security team already knows these RFCs. The construction needs to articulate what nullifier separation provides that per-RS DCR + client attestation does not — at the cryptographic level, not the marketing level. Right now, the gap section admits the prototype doesn't exist yet.

- **Why it works:** The claim is strength 9 targeting 10, but the core differentiator (nullifier separation per scope) is described as needing a prototype. Until that prototype exists and is benchmarked against the RFC 7591 + attestation baseline, the claim is a research proposal, not a shipping construction. Auth0 and Cloudflare can point at deployed RFC conformance. Bolyra cannot yet.

- **In-threat-model?** Yes, cryptographically — but the construction must deliver the prototype and an explicit comparison to Client Attestation showing what ZK nullifiers provide that attestation JWTs cannot, or the claim is not yet falsifiable.


## Persona: cryptographer

*Applied cryptographer. Skeptical of under-specified ZK constructions. Unless I see a threat model, a game definition, and a reduction sketch, it's marketing. The blindingSalt lifecycle prose is welcome hygiene, but hygiene is not a proof.*

---

### Attack 1: Credential-Committed Nullifier — AS Precomputes the Full Nullifier Table

**Attack:**
The AgentPolicy circuit takes an agent credential as a private input. That credential was *signed by the AS's `operatorPrivKey`* (see `createAgentCredential(modelHash, operatorPrivKey, permissions, expiry)`). If the AgentPolicy nullifier is computed as anything of the form

```
nullifier_i = H(f(credential) || scope_id_i)
```

where `f(credential)` is deterministic in the credential content, then AS already knows `f(credential)` for every agent it has ever credentialed. AS also knows every `scope_id` because it issues the delegation narrowing those scopes. Result: AS can precompute the full nullifier table `{H(f(cred_j) || scope_i)}` for all `(agent j, scope i)` pairs *before any agent ever connects to an RS*. It then matches observed nullifiers to table entries, fully de-anonymizing the traffic graph.

**Why it fails / survives:**
It fails against the construction *unless* the AgentPolicy nullifier is provably routed exclusively through `blindingSalt` — a value AS is excluded from by the new §3.1. But §3.1 only specifies the lifecycle of `blindingSalt` for *human enrollment* (`HumanUniqueness`). The construction refinement is silent on whether the `AgentPolicy` nullifier also hashes through `blindingSalt` or commits instead to a value derivable from the credential. This is not a lifecycle question; it is a circuit input assignment question, and the construction must state it explicitly.

**In-threat-model?** No — the construction must prove that the `AgentPolicy` witness includes `blindingSalt` as the unlinkability randomizer, not any credential field that AS controls or can enumerate.

---

### Attack 2: Subverted Groth16 Trusted Setup — Toxic Waste Extraction of blindingSalt

**Attack:**
Groth16 security is parameterized by the CRS. Specifically: a party holding the toxic waste `τ` from the per-circuit setup ceremony can (a) simulate valid proofs for *false* statements, and (b) *extract the full witness* from any honestly-generated proof by inverting the linear combination. If AS — or any party colluding with AS — participated in the `AgentPolicy` or `Delegation` trusted setup and retained `τ_AgentPolicy`, it can extract `blindingSalt` from every proof ever submitted. Once it has `blindingSalt`, cross-scope nullifiers are trivially computable for any `scope_id`.

The §3.1 lifecycle additions are careful to exclude AS from salt *provisioning* ("AS MUST NOT generate, receive, or store `blindingSalt`"). This is correct but orthogonal. The ceremony exclusion is a *different* trust assumption that §3.1 does not address at all.

Note: the construction correctly reuses the public Semaphore v4 ceremony for `HumanUniqueness` (no project-specific toxic waste there). But `AgentPolicy` and `Delegation` use a project-specific `pot16.ptau`. Who ran that ceremony? What is the MPC transcript? Was AS excluded from the ceremony as a contributor?

**Why it fails / survives:**
Against an honest CRS, Section 4's reduction holds — knowledge soundness of Groth16 means extraction is hard for a PPT adversary. But "honest CRS" is an assumption, not a property of the construction. Under subverted setup, the reduction breaks at its first step because the extractor in the knowledge soundness proof is precisely the party that ran setup. This is the Bellare-Fuchsbauer-Scafuro subversion ZK model, and the construction says nothing about it.

**In-threat-model?** No — the construction must either (a) cite a concrete MPC ceremony log with AS exclusion, (b) use a universal SRS scheme (PLONK over BLS12-381 + KZG with a subversion-resistant accumulator), or (c) explicitly scope the threat model to "honest CRS" and acknowledge the residual trust assumption.

---

### Attack 3: IND-UNL-AS Game Undefined — The Reduction Has No Target

**Attack:**
Section 4 states the reduction ties uniformity of nullifiers to CSPRNG output, independence to AS exclusion, and secrecy to the storage hierarchy. None of this is a *reduction* until there is a game `G` such that "adversary wins `G` implies adversary breaks assumption `A`." Without the game:

1. **What does the adversary output?** A linkage bit? A graph edge `(nullifier_i, nullifier_j)` asserted same-agent? A probability over a set? Each formalization gives a different winning condition and a different reduction target.
2. **What does the adversary see?** Passive transcripts only? Active nonce-chosen transcripts? Colluding AS+RS joint view? "Colluding AS+RS" is not a single adversary role — it is a composed adversary, and composition requires a UC argument or a hybrid argument that the construction does not provide.
3. **Is the reduction tight?** The security parameter is not stated. If the reduction loses a factor of `Q` (number of queries), and `Q = 10^6` sessions per day, concrete security may be far below the claimed 128-bit level.

The refinement adds prose ("AS cannot touch the salt") but prose is not a game. A reviewer for CRYPTO would desk-reject §4 as currently described.

**In-threat-model?** No — the construction must state the IND-UNL-AS game explicitly: adversary class (PPT), oracle access (credential issuance, scope registration, nonce generation), winning condition (distinguish same-agent vs. different-agent with non-negligible advantage), and the reduction to a named hardness assumption (e.g., PRF security of H, DDH in the group).

---

### Attack 4: Nonce-Embedded Timing Side Channel — AS Correlates Without Touching Nullifiers

**Attack:**
AS issues `sessionNonce` for every handshake. Nothing in the construction constrains how AS generates nonces. Suppose AS embeds a covert timing signal:

```
sessionNonce_j = H(timestamp_j || agent_session_counter_j || covert_tag)
```

RS receives the completed handshake proof, which publicly binds to `sessionNonce_j`. RS (colluding with AS) reports to AS: "handshake with nonce `N_j` completed at time `T_RS`." AS correlates: "I issued nonce `N_j` at time `T_AS`" and "agent that connected to me at `T_AS` is the same entity that appeared at RS at `T_AS + ε`."

This attack does not touch the nullifier at all. It uses the nonce binding — which is a *feature* of the construction (§CLAUDE.md: "every handshake commits to a fresh `sessionNonce`") — as the correlation vector. The construction's nonce freshness requirement prevents replay but does not prevent the nonce from being a subliminal channel.

The gap section explicitly lists "treatment of side channels (timing, nonce freshness)" as unresolved. This attack is the concrete realization of that gap.

**Why it fails / survives:**
The attack does not fail. Nullifier domain separation provides no defense because the adversary never looks at nullifiers. The only mitigations are: (a) agent-generated nonces (AS gets a commitment, not the nonce itself), (b) nonce blinding via a commit-reveal protocol so AS cannot embed timing signals, or (c) explicit timing obfuscation (random delay, cover traffic). None of these are in the current construction.

**In-threat-model?** No — and this is the most operationally realistic attack of the four. A credit union acting as AS *already knows* when a member's agent initiates a session. If the member's agent then accesses a partner RS within milliseconds, the CU can reconstruct the referral graph with no cryptanalysis at all.

---

**Summary table:**

| # | Attack | Breaks which claim | Survives current construction? |
|---|---|---|---|
| 1 | Credential-committed nullifier precomputation | Unlinkability (nullifier separation) | Unknown — circuit input assignment unspecified |
| 2 | Subverted Groth16 setup → witness extraction | Zero-knowledge of blindingSalt | No — toxic waste exclusion not addressed |
| 3 | IND-UNL-AS game undefined | Formal security claim itself | No — no game, no reduction |
| 4 | Nonce-embedded timing side channel | Unlinkability (colluding AS+RS) | No — explicitly acknowledged gap, no mitigation |

Attacks 1 and 2 require changes to the circuit design and ceremony documentation respectively. Attack 3 requires a formal security definition before any of the other arguments can be evaluated. Attack 4 requires a protocol-level fix to nonce generation. The blindingSalt lifecycle hardening in §3.1 is correct and necessary, but it addresses none of these four issues.


## Persona: cu_ciso

### Attack 1: BSA/AML Correlation Mandate Directly Conflicts With the Core Claim

- **Attack:** Section 3's threat model names the AS — the credit union itself — as the adversary to defeat. The construction's stated goal is preventing the AS from building "per-agent traffic graphs." But under 31 U.S.C. § 5318(g) and FinCEN's SAR filing guidance, my BSA Officer is *required* to aggregate member activity across accounts and channels to detect structuring, layering, and smurfing. If the same member's delegated agent touches my loan origination RS, my bill-pay RS, and a third-party mortgage RS I host — all behind my AS — the unlinkability guarantee means my BSA program is flying blind. The IND-UNL-AS game the candidate wants to formalize is, by construction, a BSA evasion tool from my examiner's perspective.
- **Why it works:** The construction makes no distinction between "peer CU AS" (the cross-CU scenario in §3 scenarios) and "same CU AS serving multiple RS." The blindingSalt lifecycle (§3.1) explicitly excludes the AS from all salt operations — but that AS is my compliance officer's instrumentation layer.
- **In-threat-model?** No. The construction must partition the adversary model: the *peer* CU AS that must not see cross-CU merchant graphs is different from the *home* CU AS that must maintain BSA visibility. Unlinkability across peer CUs is a feature; unlinkability within my own institution's RS fleet is a regulatory liability.

---

### Attack 2: Incident Response Produces No Examiner-Legible Audit Trail

- **Attack:** NCUA Part 748, Appendix B §III.C requires the information security program to include incident response procedures that allow reconstruction of events. I have a breach: a member's compromised agent made unauthorized transfers across three RS instances I operate. My incident response team needs to answer: which authorizations did this agent present? At what times? To which RS? The nullifier-per-scope design (one of the gaps the candidate identifies) means each RS received a *different* nullifier. My SIEM sees three unlinked authorization tokens. My forensics team cannot tie them to a single agent credential without the blindingSalt — which the construction (§3.1 explicit exclusions) says I MUST NOT hold.
- **Why it works:** The "AS uninvolved" and "MUST NOT touch the salt" rules are operationally correct for privacy but mean the CU holds zero forensic linkage capability. The Shamir backup path noted in §3.1 is member-held, not CU-held. My NCUA examiner will ask for a log that demonstrates detection and containment — I cannot produce one that links events across RS instances.
- **In-threat-model?** No. The construction needs a separate, explicitly scoped "audit linkage" mechanism — e.g., a regulator-visible commitment that the CU can open under court order or examination, without AS learning it during normal operations. Zero-knowledge audit proofs or escrow-to-examiner designs exist; the construction does not address them.

---

### Attack 3: Third-Party Risk Examination — The AS Cannot Certify What It Cannot Audit

- **Attack:** Under NCUA's Supervisory Letter 07-01 and the FFIEC IT Examination Handbook (Third-Party Risk Management), my Vendor Management Policy requires me to assess and periodically audit the security controls of any third party that processes member data or participates in authentication flows. The construction's §3.1 blindingSalt lifecycle says generation is CSPRNG offline, storage is member-device (HSM/TPM/keychain/encrypted file), rotation is AS-uninvolved. From my vendor management framework, the member device *is* a third-party endpoint I cannot examine. My NCUA examiner will ask: "How do you know the salt was generated with a CSPRNG and not a weak RNG on a compromised Android device?" My answer under this construction is: "I trust the client." That is not an auditable control.
- **Why it works:** The five "MUST NOT" rules in §3.1 that correctly protect unlinkability simultaneously strip the AS of any attestation surface. There is no TPM attestation requirement, no certificate pinning, no device health check specified. The construction cites concrete OS API references for storage but does not require the client to prove those APIs were used.
- **In-threat-model?** No. The construction should address device attestation (Android StrongBox, Apple Secure Enclave attestation) as an optional but recommended layer, and specify what the AS MAY verify (device posture, FIDO2 platform authenticator presence) without learning the salt. The gap-to-close section mentions timing side channels but omits the client-device trust gap entirely.

---

### Attack 4: Rotation Ceremony SLA vs. Core Processor Availability Expectations

- **Attack:** The §3.1 rotation ceremony states it requires "no on-chain transaction." But the construction's broader design (nullifierHash as public output committed on-chain, per the Architecture in CLAUDE.md) means the *old* nullifier must remain non-revoked and the *new* nullifier must become valid. Even if rotation itself is off-chain, the RS must eventually check the on-chain registry to confirm the new nullifier's credential hasn't been revoked. My core processor (Fiserv/Jack Henry/Corelation) has a contractual 99.95% uptime SLA. My members expect the same. If the on-chain registry (Base Sepolia, per CLAUDE.md) has any degraded availability during a rotation window, the member's agent credential becomes unverifiable. The candidate's gap-to-close mentions "empirical test showing colluding AS+RS cannot de-anonymize" but has no availability SLA target, no fallback when the chain is unavailable, and no definition of what happens to in-flight agent sessions during a rotation.
- **Why it works:** "Voluntary rotation, old/new nullifiers mutually unlinkable" is stated but the race condition between old-nullifier expiry and new-nullifier on-chain confirmation is not addressed. A member's agent operating on the old nullifier while rotation is pending could be rejected by an RS that sees neither nullifier as currently active. My ops team gets a 2am call; Tier 1 has no lever to pull because the construction explicitly excludes AS from all salt/rotation operations.
- **In-threat-model?** No. The construction must specify: (a) a minimum nullifier validity window post-rotation-initiation, (b) a chain-unavailable fallback (e.g., RS caches last-known valid root with bounded staleness), and (c) an explicit SLA commitment or acknowledgment that L2 finality assumptions carry availability risk the CU must accept in its third-party risk register.


## Persona: rfc7662_advocate

> *OAuth WG veteran. A decade of production introspection. Every ZK claim is suspect until proven not achievable by RFC 7662 + its extensions.*

---

### Attack 1: PPID + Per-RS Introspection Policy Achieves the Same RS-Level Property

**Attack:**
RFC 7662 §2.2 permits the AS to filter the introspection response per RS. Layer in OIDC Pairwise Pseudonymous Identifiers (PPIDs, OIDC Core §8.1): the AS issues a distinct `sub` per `sector_identifier_uri`, so RS-A sees `sub=h(salt_A || real_sub)` and RS-B sees `sub=h(salt_B || real_sub)`. Combined with RFC 8707 Resource Indicators (audience-binding the token to exactly one RS), each RS receives a token that is (a) audience-locked and (b) carries a subject identifier that is unlinkable to any other RS's subject identifier — **without the RS ever calling back to the AS hot path** if you use the signed JWT introspection response (draft-ietf-oauth-jwt-introspection-response §4).

**Why it works / why it fails:**
The construction's claim in §3.1 is that the AS is *explicitly excluded* from the blindingSalt. But the construction does not specify how the agent *authenticates to the AS* to obtain the scope-specific proof. Under standard OAuth, the agent must present some stable credential (client_id, mTLS cert, DPoP key) to the AS token endpoint. The AS therefore observes: "client X requested scope `cu:read` at T₁ and scope `health:read` at T₂." The blindingSalt protects the *nullifier*, but the token-acquisition phase is wide open. PPID construction achieves the *same RS-level unlinkability* the construction claims, and the AS-side linkability problem is equally present in both approaches — making the ZK advantage non-differential at the RS layer.

**In-threat-model?** **No** — construction must address token-acquisition correlation. The construction's threat model in §3 names "adversarial AS that tries to correlate per-agent traffic graphs" but the lifecycle spec (§3.1) only seals the salt generation path, leaving the authentication/token-request path open.

---

### Attack 2: The "Adversarial AS" Assumption Collapses the OAuth Trust Model

**Attack:**
The construction's gap statement explicitly targets an "adversarial AS that tries to correlate per-agent traffic graphs." I challenge that premise directly. In every deployed OAuth system, the AS is a *trusted* party by definition — it is the authority issuer. RFC 6749 §1.1 is explicit: the AS issues tokens to clients it authenticates. RFC 9700 (OAuth 2.0 Security BCP) §2.1 says the AS MUST authenticate clients. If the AS is adversarial, you don't have an OAuth problem — you have a *wrong AS* problem, and the solution is not ZK, it's federation with a non-adversarial AS (e.g., the user's self-sovereign wallet AS).

More concretely: RFC 8693 Token Exchange allows the agent to obtain a narrowed token from a *resource-owned* AS without the original AS seeing scope specifics. Chain: User AS → issues base token → RS-local AS exchanges it (§2.1) for a resource-scoped token. The resource AS sees only the downstream scope request; the original AS is off the hot path entirely. This achieves the "AS cannot see merchant graph" scenario (Construction §3, CU use case) without any ZK.

**Why it works / why it fails:**
The construction does not engage with Token Exchange as a counterfactual. The IND-UNL-AS game (listed as a gap) would need to define *why* the agent must interact with a single AS that serves both RS-A and RS-B. If the game permits federation or Token Exchange, the ZK advantage shrinks to near zero.

**In-threat-model?** **No** — construction must either (a) define why Token Exchange is insufficient for the CU and healthcare scenarios, or (b) narrow the adversary definition to explicitly exclude the "replace AS" escape valve.

---

### Attack 3: DPoP (RFC 9449) + Ephemeral Keys Already Provides Sender-Constraint Unlinkability at the RS Layer

**Attack:**
The attack prompt asks: "Name the property DPoP cannot provide." I'll name the one the construction claims — then contest the claim.

DPoP (RFC 9449 §4): the agent generates a fresh DPoP key-pair per token request. The token is bound to `jkt` (JWK thumbprint of the DPoP key). If the agent generates a *new* DPoP key-pair per RS interaction, RS-A sees `jkt=K_A` and RS-B sees `jkt=K_B`. These are cryptographically unlinkable at the RS layer. The AS sees both key thumbprints at issuance, but if the construction's threat model considers the AS adversarial, then DPoP-key rotation per scope is directly analogous to nullifier separation per scope — and DPoP is already in RFC.

The construction's §3.1 blindingSalt is client-side, offline, AS-excluded. DPoP ephemeral keys are also client-side, offline, AS-excluded (the AS never sees the private key). The structural analogy is tight.

**Why it works / why it fails:**
The genuine gap: DPoP `jkt` thumbprints are **AS-observable at issuance time** (the AS sees the `DPoP` header in the token request). The AS can therefore log `(client_id, jkt_A, scope_A)` and `(client_id, jkt_B, scope_B)` and link them via `client_id`. The construction's nullifier approach — if the agent uses *different* enrollment identities per scope (i.e., scope-specific `blindingSalt`) — severs this link even at the AS. But the construction does not state whether the agent uses one enrollment identity or per-scope enrollment identities. If the agent uses one identity (one Semaphore leaf), the AS observes one registration event that it can anchor all downstream scope proofs to.

**In-threat-model?** **Yes** — but construction must explicitly document that per-scope `blindingSalt` isolation (not per-agent) is the intended design. Currently §3.1 describes a single salt lifecycle, not per-scope salt isolation.

---

### Attack 4: Timing and Nonce-Freshness Side Channel Under Colluding AS+RS

**Attack:**
The gap statement lists "treatment of side channels (timing, nonce freshness)" as open. The construction's §3.1 closes the *cryptographic* correlation path (salt generation, storage, rotation). It does not close the *traffic-analysis* path. Concretely:

1. **Timing correlation:** Agent accesses RS-A (CU-A) at T₁, RS-B (CU-B) at T₁ + 50ms. A colluding AS+RS pair observes two token-request/proof-submission events within a narrow time window. No RS sees the same nullifier, but the joint AS+RS traffic log shows `(IP=X, T₁)` and `(IP=X, T₁+50ms)`. Even with Tor-style routing, the AS sees the proof submission and can correlate session durations and nonce-request patterns.

2. **Nonce freshness leakage:** The construction's handshake commits to a `sessionNonce` (CLAUDE.md: "every handshake commits to a fresh sessionNonce"). If the nonce is AS-issued (the standard case — AS generates a fresh challenge), the AS issues nonce N_A for RS-A and nonce N_B for RS-B in rapid succession to the *same client connection*. The AS can link both nonces to the same session without ever inspecting the ZK proof.

The construction's threat model names "empirical test showing colluding AS+RS cannot de-anonymize" as a gap but §3.1 provides no answer to either sub-attack.

**Why it works / why it fails:**
This is a genuine open attack. The cryptographic unlinkability claim (IND-UNL-AS game) is purely about the proof artifacts. Traffic analysis is outside the game definition. RFC 7662 is equally vulnerable to timing correlation — so the construction does not *regress* here — but the strength-9→10 claim requires closing this gap, not just acknowledging it.

**In-threat-model?** **No** — the claim "even under adversarial AS that tries to correlate per-agent traffic graphs" explicitly includes traffic-graph correlation, which timing attacks deliver. The construction must either (a) scope the claim to *cryptographic* unlinkability only and strike "traffic graphs" from the claim, or (b) specify a nonce-blinding / request-pacing / mixnet assumption that bounds timing leakage.


## Persona: spiffe_engineer

> *"I've run SPIFFE/SPIRE across 40,000 workloads in three cloud regions. Let me show you what layer you actually live at."*

---

### Attack 1: WIMSE Token Exchange Already Provides Cross-Scope Unlinkability

- **Attack:** WIMSE `draft-ietf-wimse-arch` §6 ("Token Exchange") already defines workload-to-workload authorization token exchange where the issuer (AS) sees only the requesting workload's SVID, not the resource being accessed. The RS-specific scoped token is derived by the *workload*, not issued by the AS. The AS never sees `(agent_id, RS_target)` pairs together. This is unlinkability via token exchange semantics, not ZK. Your IND-UNL-AS game formalizes a property WIMSE is already shipping. Why are you not contributing the formal definition to the WIMSE working group and filing a ZK attestor plugin on top?

- **Why it works / fails:** The construction's C2 claim — "adversarial AS cannot correlate per-agent traffic graphs" — is operationally satisfied by WIMSE token exchange *without* the ZK layer. The gap-to-close explicitly concedes the IND-UNL-AS game is unwritten. If WIMSE closes that gap first (likely, given WG momentum), the construction's differentiator evaporates.

- **In-threat-model?** **No.** The construction must articulate what the ZK blindingSalt provides that WIMSE token exchange does not. A credible answer requires either: (a) showing a colluding AS+RS attack that WIMSE token exchange cannot prevent but the nullifier construction does, or (b) showing WIMSE relies on AS honesty while the nullifier is AS-free. The current text does neither — Section 4's reduction assumes AS exclusion as a precondition, not a proved property.

---

### Attack 2: SPIFFE Federation Is Already "Portable Cross-Scope Unlinkability"

- **Attack:** In a SPIFFE deployment, an agent workload accessing RS-A (in trust domain `spiffe://cu-a.example/`) and RS-B (in trust domain `spiffe://cu-b.example/`) presents *different X.509 SVIDs* per trust domain. Those SVIDs share no cryptographic material. The AS for domain A cannot correlate to domain B's AS without out-of-band collusion because federation uses bundle endpoints, not shared keys. The construction's healthcare/CU scenarios — "CU-as-AS must not see member merchant graph" — are already solved by assigning each CU its own SPIFFE trust domain and issuing per-domain SVIDs. Name the gap that federation does not close.

- **Why it works / fails:** This attack is strongest against the *cross-credit-union scenario* specifically. If each CU runs a SPIRE server (one SPIFFE trust domain per CU), agent workload identity federation across CUs is already cryptographically partitioned. The construction's cross-scope unlinkability is a re-derivation of SPIFFE trust domain isolation, at a higher layer, with more ceremony (ZK proving, blindingSalt storage hierarchy, rotation ceremonies).

- **In-threat-model?** **No — and it's the most serious structural gap.** The construction must explicitly scope itself to environments where SPIFFE federation is unavailable or where the AS *IS* the trust domain operator (i.e., the adversary controls the SPIRE server). Section 3 (Threat model) after the blindingSalt lifecycle addition still does not rule out a SPIRE-backed deployment. If it doesn't, SPIFFE federation dominates on simplicity and the ZK construction has no defensible wedge.

---

### Attack 3: Nonce Timing as an AS Side Channel (Gap Explicitly Unaddressed)

- **Attack:** The C2 gap-to-close list explicitly names "treatment of side channels (timing, nonce freshness)" as outstanding. Here is the concrete attack: the AS issues `sessionNonce` values to agents on request. Even if the resulting nullifiers are cryptographically unlinkable across scopes, the AS timestamps each nonce issuance. If agent X requests a nonce at T=100ms and RS-A receives a proof at T=110ms, and the same agent requests another nonce at T=200ms and RS-B receives a proof at T=210ms, the AS builds a timing graph `agent_X → {RS-A, RS-B}` purely from nonce request timestamps — no nullifier correlation needed. The Section 3.1 blindingSalt lifecycle additions do not touch nonce issuance at all. The AS is explicitly excluded from *salt* provisioning but is still the canonical *nonce* issuer per the handshake protocol.

- **Why it works / fails:** This attack *works* against the current construction because: (1) the IND-UNL-AS game is unwritten, so timing oracles are not modeled; (2) the gap-to-close acknowledges timing is unaddressed; (3) the reduction in Section 4 conditions on AS exclusion from the *salt* but not from *nonce issuance*. An adversarial AS can passively log nonce requests with sub-millisecond precision without touching any ZK primitive.

- **In-threat-model?** **No.** The IND-UNL-AS game definition must include a timing oracle adversary. The construction needs either (a) agent-generated nonces (AS never sees the request-to-proof latency), (b) nonce batching/blinding, or (c) an explicit out-of-scope declaration with a documented residual risk. None of these appear in the current iteration.

---

### Attack 4: Section 3.1 Storage Hierarchy Reinvents the SPIFFE Workload API

- **Attack:** The new Section 3.1 blindingSalt lifecycle defines a 3-tier storage hierarchy: HSM/TPM → OS keychain → AES-256-GCM encrypted file. SPIFFE's Workload API (a Unix domain socket with kernel-enforced process isolation, delivering SVIDs to attested workloads with automatic rotation) is precisely this hierarchy, already deployed, with platform-specific attestors (TPM2, AWS IID, GCP GCE, k8s SAT). Your HSM/TPM tier is a SPIRE TPM plugin. Your OS keychain tier is SPIRE's in-memory SVID cache. Your AES-GCM file tier is what SPIRE agents do when the SPIRE server is unreachable. The "explicit exclusions" (5 MUST NOT rules) are enforced in SPIFFE by the Workload API socket permission model — the AS never touches the socket. Why are you specifying a new storage hierarchy instead of mandating a SPIFFE Workload API implementation as the required blindingSalt storage backend?

- **Why it works / fails:** The attack partially fails because the blindingSalt is *not* a credential — it's a long-lived secret for nullifier derivation, not a short-lived SVID. SPIFFE Workload API rotates SVIDs (minutes to hours); the blindingSalt explicitly should *not* rotate frequently (rotation resets nullifier identity). The storage hierarchy serves a different key lifecycle than SVID delivery. However, the construction does not articulate this distinction. A reader running SPIFFE in production will read Section 3.1 and conclude the construction is reinventing SVID storage with worse tooling.

- **In-threat-model?** **Partially.** The construction survives the functional attack (different key lifecycle) but fails the *engineering credibility* attack. Section 3.1 must add a paragraph explicitly contrasting the blindingSalt lifecycle with SVID lifecycle — why the salt is *not* a Workload API secret, and why that's deliberate. Without it, the SPIFFE engineer in your customer's infrastructure team rejects the proposal in week one of the PoC.
