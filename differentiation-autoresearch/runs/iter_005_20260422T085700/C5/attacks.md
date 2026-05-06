# Tier 3 Adversarial — C5 Bolyra as MCP auth, generally

## Persona: auth0_pm

### Attack 1: Session Amortization Collapses the ZK Guarantees to a Rounding Error

- **Attack:** Section §2.8 admits cold auth is ~4s and amortizes it via a 1-hour session token. But a session token is a bearer token. During the TTL window — which covers the overwhelming majority of tool calls in any real agent workflow — Bolyra IS vanilla OAuth. The forward-secrecy guarantee (H4), the mutual identity proof (H1), and the model-binding tag (H2) are all assertions made once at session establishment and then discarded. If the session token is stolen (e.g., via MCP server compromise, prompt injection exfiltrating headers, or a memory read of the agent runtime), the attacker gets the same <1ms bearer-token access as any OAuth client. The "strict dominance" claim requires these properties to hold *across the session*, not just at the cold-start handshake.

- **Why it works:** The construction does not specify how the session token is cryptographically bound to the proof transcript. §7 says `Authorization: Bolyra` with Bearer fallback, but does not prove session token unforgeability or binding to the GGM nullifier state. An attacker who compromises the agent runtime mid-session gets a working bearer token with no ZK residue protecting them. The H4 claim ("agent secret exfiltration does not retroactively deanonymize prior sessions") is correct but irrelevant — the live session token is the attack surface, not the retrospective nullifier.

- **In-threat-model?** No. The construction must specify session token binding (e.g., DPoP-style proof-of-possession keyed to the PLONK witness, or per-tool-call proof refresh for high-value calls). Without this, the "strict dominance" claim holds only for the 4-second cold-start window, not the 3,596 seconds of the session TTL.

---

### Attack 2: The AS-Adversary Threat Model Requires Trusting a Harder-to-Audit AS

- **Attack:** §1 justifies the construction by documenting four facts showing Auth0/Okta are structurally adversarial (breach, multi-tenancy, log retention gaps, legal compulsion). The enterprise procurement question this triggers is: *Who runs Bolyra's infrastructure?* The nullifier registry must be live, globally consistent, and not adversarial. The GGM tree key state must be maintained across epochs. The PLONK verifying keys must be ceremony-derived and auditable. Today, the answer is a solo founder with no SOC 2, no published security program, no bug bounty, and no named security team. The construction proves the AS is a risk — but the alternative is trusting infrastructure that is strictly less auditable than Auth0's. For a credit union CISO, trading a known-audited risk for an unknown-founder risk is not a dominance argument.

- **Why it works:** The construction closes the cryptographic gaps (SE-NIZK, forward-secure PRF) but does not address the operational trust gap. §1's evidence motivates the threat model but does not answer: "What is Bolyra's SLA for nullifier registry availability? Who audits the ceremony parameters? What happens to my agent sessions if the founder is unavailable?" WorkOS ships with a public trust page, SOC 2 Type II, and named security contacts. The construction is silent on this entire surface.

- **In-threat-model?** No. This is a GTM-blocking objection, not a cryptographic one. The construction must address the operational trust model — either via decentralized nullifier registry (on-chain or threshold), published ceremony transcripts, or a roadmap to institutional auditability. Otherwise §1's threat evidence is self-defeating: it proves ASes are dangerous, which is an argument *against* adopting another unaudited AS.

---

### Attack 3: H3 (Zero-Config Portability) Requires an Ecosystem That Doesn't Exist and Has a Working Incumbent

- **Attack:** H3 claims "one Bolyra credential authenticates at every compliant RS without per-RS client registration." The word *compliant* is doing all the work. Today, zero RSes are Bolyra-compliant. The ~380-line middleware adapter in §7 must be adopted by every RS operator. RFC 7591 dynamic client registration — which Auth0, WorkOS, and Cloudflare Access all implement — already provides automated per-RS registration with a single roundtrip. In the Auth0 MCP product, dynamic registration is handled transparently in the SDK; the developer pastes an API key and never thinks about client registration again. Bolyra's portability claim is true in a Bolyra-native world that requires every RS to ship new middleware. The incumbent's portability is true in the world that already exists.

- **Why it works:** The construction treats RFC 7591 as friction (§ H3: "requiring Dynamic Registration roundtrip") but that roundtrip is automated and invisible in mature OAuth clients. The real adoption curve is: Bolyra requires RS operators to add a new verifier dependency, a nullifier check endpoint, and a manifest fetcher. WorkOS requires RS operators to add `npm install @workos/mcp` and set an env var. For a generic Claude agent talking to a third-party MCP server (Scenario 1), the RS operator chooses their auth stack — and they will choose the one their framework already supports. The portability advantage only materializes after critical RS-side adoption mass, which is a chicken-and-egg problem the construction does not address.

- **In-threat-model?** No. The construction must address the cold-start adoption problem: what does portability look like when RS adoption is 0%? A fallback-to-vanilla-OAuth path (§7's Bearer fallback) means H3 is inoperative by default and only activates in a future state that requires a separate GTM motion.

---

### Attack 4: Client Attestation (Draft RFC) Already Closes H2 Without the Latency Cost

- **Attack:** H2 claims Bolyra "binds {model_hash, operator_pk, permission_bitmask} to a specific RS invocation" and that "vanilla OAuth binds only client_id; runtime model identity is not authenticated." This is true of vanilla OAuth 2.1 today, but `draft-ietf-oauth-attestation-based-client-auth` (Client Attestation) — actively tracked by Auth0, Cloudflare, and the IETF OAuth WG — provides exactly this binding via a signed JWT containing arbitrary attestation claims, including model version, hardware enclave measurements, and operator identity. The attestation JWT is issued by a trusted attester and verified by the AS at token issuance. This does not require a ZK proof, adds ~5ms of verification latency, and slots into existing OAuth infrastructure with no RS-side changes.

- **Why it works:** The construction argues H2 is "outside vanilla OAuth's expressive envelope" (gap_to_close criterion). Client Attestation puts model-identity binding squarely inside that envelope, without requiring enterprises to adopt a new cryptographic primitive. The construction's §2.2 argument for SE-NIZK over attestation-based approaches is a cryptographic argument (AS cannot lie about the attested values) — but this again presupposes the AS-adversary threat model. For the 99% of enterprises who do not face a compelled-disclosure AS scenario, Client Attestation delivers H2's stated benefit with lower latency, lower integration cost, and IETF standardization trajectory. The "strict dominance in the general case" claim cannot survive if H2's differentiator is already on the OAuth roadmap.

- **In-threat-model?** No. The construction must either (a) demonstrate that Client Attestation is insufficient even under a non-adversarial AS — i.e., that the ZK binding provides value the attested JWT does not — or (b) concede that H2 is only a differentiator in the regulated/AS-adversary subset and withdraw the "general case" dominance claim.


## Persona: cryptographer

*Reviewing C5 "Bolyra as MCP auth, generally" against the stated construction. I'm taking the construction at face value and looking for gaps the author did not close.*

---

### Attack 1: Nullifier Precomputation by a Scope-Aware AS

**Attack:** The AS issues credentials and therefore knows every `scope_id` it has registered. In the GGM-tree construction (§2.3), the nullifier at epoch T is `PRF(leaf_key_T, scope_id)`. The AS observing nullifier submissions across epochs can build a dictionary: for each known `scope_id`, compute `PRF(leaf_key_T, scope_id)` for every T it can derive. Key question: does the AS ever see `leaf_key_T`? Puncturing only deletes past keys from the *holder's* state — it does not prevent the AS from logging nullifiers and inverting them if it learns any leaf key (e.g., via a subpoena on the holder, key escrow, or by corrupting the agent's TEE). Once the AS has one leaf key at depth d, it can derive all sibling leaves at that depth via the GGM construction, breaking forward secrecy for the full epoch-granularity at level d.

**Why it works / why it may fail:** The FS-NULL game (Game 2) bounds `Pr[Adv wins] ≤ 1/2 + 24·Adv^PRF(λ)`, which is tight under GGM security — *if* the adversary never sees any leaf key. But the game does not model an AS that compels leaf-key disclosure at epoch T and then retroactively deanonymizes epochs T-24 through T using the GGM sibling-derivation property. The construction says leaf keys are punctured; it does not say they are not logged before puncturing.

**In-threat-model?** **No** — the construction cites 18 U.S.C. §2703(d) and Okta 2023 as motivation for the AS-adversary, but Game 2 does not model legal compulsion or key logging prior to puncturing. A reduction to PRF security is not a reduction to "the AS never sees the key." This must be addressed with an explicit key-logging assumption or a TEE attestation binding.

---

### Attack 2: Nonce Binding Underspecification in COMPOSE-EXTRACT

**Attack:** Game 6 (COMPOSE-EXTRACT) constructs a joint extractor by running two independent SE-PLONK extractors on "same-nonce-bound proofs." The bound is `2·Adv^SE_PLONK(λ)`. But the game silently assumes the binding between the human-leg nonce and the agent-leg nonce is *cryptographically enforced in-circuit*, not merely declared as a public input equality. If the nonce is a public input `n` declared equal across both circuits but not committed inside either circuit's witness, an adversary can:

1. Execute the human-leg proof for session nonce `n_H`.
2. Execute the agent-leg proof for a different session nonce `n_A ≠ n_H`.
3. Submit both proofs to the RS with a forged public input `n_H = n_A = n_claim`.

The RS verifies both PLONK proofs independently. If neither circuit commits to the *other circuit's* nonce in its witness, the joint extractor extracts two valid witnesses for different sessions, not one joint witness for the claimed session. The "atomic" mutual identity proof (H1) fails.

**Why it works / why it may fail:** The construction says "same-nonce-bound" but does not specify whether the nonce appears as a *private witness input hash* in both circuits or merely as a shared public input. If it is only a public input, PLONK's SE property extracts knowledge of a witness satisfying the circuit for *some* public input vector — an adversary who controls the public input declaration can mix proofs across sessions. The fix is a cross-circuit commitment: each circuit must include in its witness a hash of the counterpart's public input vector.

**In-threat-model?** **No** — Game 6 assumes the extractor sees two proofs "on the same nonce" but does not model an adversary who submits proofs with mismatched witnesses and a claimed nonce equality. This is a standard cross-circuit malleability pitfall; it needs an explicit constraint in §2.1–2.2 circuit descriptions.

---

### Attack 3: Bearer Fallback as a Universal Downgrade Path

**Attack:** §7 specifies `Authorization: Bolyra` with a Bearer fallback for backward compatibility. A malicious RS (or MITM on an unauthenticated channel) responds to a Bolyra auth attempt with `401 Unauthorized: Bearer required`, stripping the Bolyra header. The client, following the fallback path, presents a Bearer token. At that point:

- Unlinkability (H3, H4): gone — the Bearer token is a persistent identifier.
- Forward secrecy (H4): gone — token compromise is retroactive.
- Model binding (H2): gone — Bearer tokens carry `client_id`, not `model_hash`.
- Mutual identity proof (H1): gone — no ZK proof presented.

The adversary does not need to break any cryptographic primitive. They only need to control the RS's `WWW-Authenticate` response.

**Why it works / why it may fail:** The construction provides no protocol-level mechanism to prevent downgrade. There is no HSTS-equivalent (a "Bolyra-Only" policy declared out-of-band), no cryptographic binding between the Bolyra credential and the Bearer token (e.g., a DPoP-style proof-of-possession that would make the Bearer token useless without the ZK witness), and no client-side enforcement that prevents fallback to Bearer when the RS requests it.

**In-threat-model?** **No** — the RS-adversary is not in the stated threat model (the AS is), but the sidecar pattern explicitly supports RS deployments that cannot verify PLONK proofs and fall back to Bearer. Any RS operator — or an attacker who has compromised an RS — can trivially strip all Bolyra guarantees. §7 needs either a mandatory Bolyra-Only mode or a cryptographic binding (e.g., DPoP-style) that makes the Bearer token non-transferable without the ZK witness.

---

### Attack 4: Model-Class Linkability Sufficient for Traffic Deanonymization

**Attack:** The construction acknowledges (§iter_003/004 closure) that `modelBindingTag` is inherently linkable to model-class (e.g., all sessions from `claude-sonnet-4-6` carry the same `model_hash`). The claim is that this is bounded to model-class, not agent-instance. But consider the adversary's position: an RS that sees `model_hash = H(claude-sonnet-4-6)` across requests can now correlate *all users of that model* against each other using timing, request structure, and tool-call patterns. In a sparse-usage RS (a niche financial API with 50 daily users, five of whom use Claude Sonnet), the model-class partition reduces the anonymity set from the full user population to ~5. If the RS is colluding with a traffic observer who knows which enterprise accounts use which model, the anonymity set collapses to 1.

**Why it works / why it may fail:** The Pedersen re-randomization closure (Game 4) addresses intra-epoch session linkability but is orthogonal to cross-session model-class linkability, which is a *design requirement* of H2 (RS must verify model hash). The construction cannot simultaneously claim (a) cryptographic model binding for RS security and (b) unlinkability across sessions for privacy — these are in direct tension when `model_hash` is a public input to the PLONK verifier and therefore visible to the RS on every call.

**In-threat-model?** **Partially** — the construction acknowledges the issue but does not quantify the anonymity-set reduction in realistic deployment scenarios, does not define a formal privacy game that covers model-class linkability, and does not propose a mitigation (e.g., a model-class commitment with RS-side zero-knowledge verification that the model is in an approved set, without revealing which member). Until a SESSION-LINK variant game covers this axis, H2 and H3 cannot simultaneously hold as stated.


## Persona: cu_ciso

---

### Attack 1: ZK Proofs Are Structurally Audit-Opaque — NCUA Part 748 Fails

**Attack:** The CISO opens the NCUA examination questionnaire to 12 CFR Part 748.2(a)(4)-(5): *"describe procedures for monitoring systems and detecting unauthorized access."* The examiner asks: "Show me the authentication log for member Jane Doe on April 15." The Bolyra nullifier log (§7 RS middleware) shows a spent nullifier `0x7a3f...` and a session token issue event. There is no member identity attached — **by construction** (that's the unlinkability guarantee). The CISO cannot produce the attributable audit trail the examiner expects.

**Why it works / why it fails:** The construction closes intra-epoch linkability (iter_003 Game 4) as a *privacy win*, but that same DDH-based unlinkability is **a GLBA Safeguards Rule failure** under 16 CFR §314.4(c)(3), which requires monitoring for unauthorized access *with attribution*. The construction has no section addressing how the RS operator reconciles unlinkability with required member-session attribution. §7's "nullifier check" middleware produces a binary (valid/invalid) with no identity binding the examiner can reference. The construction must address a *selective disclosure* or *audit-mode* path where the RS can, under specific conditions, attribute a nullifier to a member — but this is absent.

**In-threat-model?** No — construction must address. The CISO cannot defend an authentication system where "who authenticated?" has a cryptographically correct answer of "nobody, by design."

---

### Attack 2: Human Secret Key Custody Is Unspecified — NCUA Vendor Risk Disqualifies Unverifiable Key Storage

**Attack:** The CISO reads §2.1-2.2: the human leg is a simulation-extractable PLONK proof over a human secret. The attack prompt: *"Key custody: where does the member secret live?"* The construction is silent. The CISO calls Tier 1 ops at 2am: member lost their phone. The agent cannot authenticate because the human-bound PLONK credential is on the device. What's the recovery path? The construction has no §2.x covering key recovery, device migration, or HSM-backed custody for consumer members.

**Why it works / why it fails:** §2.1 introduces `human_sk` as an input to the PLONK circuit but defers the storage question entirely. NCUA's Appendix B to Part 748 (the Interagency Guidelines) requires the credit union to *maintain control* over member authentication factors, which means documented recovery procedures. GLBA Safeguards §314.4(f) requires access controls "commensurate with the sensitivity of the information." A browser-local key with no recovery path is worse than a forgotten password — it's a permanent member lockout with no helpdesk resolution path. The construction is mathematically tight but operationally undeployable until key custody is specified.

**In-threat-model?** No — construction must address. The human leg's security relies entirely on `human_sk` secrecy, but the threat model never states where `human_sk` lives, who holds it, or what happens on loss.

---

### Attack 3: Nullifier Registry SLA Is Undefined — Third-Party Risk Under Part 748 Appendix B

**Attack:** The CISO reads §2.8's latency budget and §7's RS middleware: every authentication requires a nullifier liveness check. The CISO's Vendor Management Policy requires written SLA commitments for any dependency in the authentication critical path. The construction mentions "on-chain registry" in the nullifier context (H4 forward-secure nullifiers; §2.3 GGM puncturing semantics), but never specifies: *what is the availability SLA of the nullifier registry? What is the fallback when it is unreachable?*

**Why it works / why it fails:** The construction's §7 sidecar pattern falls back to `Authorization: Bearer` for vanilla OAuth RSes, but this says nothing about what happens when the nullifier registry itself is unreachable. If the registry is on-chain, `99.9%` uptime is optimistic — Ethereum mainnet has had multi-hour degradation events. Core processors (Symitar, DNA) SLA at `99.99%`. NCUA Part 748 Appendix B §III.C requires the credit union to assess *availability* of critical service providers. A novel on-chain dependency with no documented SLA, no fallback behavior specification, and no SOC 2 Type II audit history will be flagged immediately in a third-party risk review. The construction closes the cryptographic forward-secrecy gap (Game 2, FS-NULL) but says nothing about the operational availability of the system that enforces it.

**In-threat-model?** No — construction must address. §2.8 addresses latency under happy-path conditions only. Registry unavailability is not discussed.

---

### Attack 4: No FFIEC CAT / NIST CSF Control Mapping — The Examiner Has No Framework to Assess This

**Attack:** The CISO's board presentation requires mapping every authentication control to the FFIEC Cybersecurity Assessment Tool (CAT) maturity tiers. The examiner arrives with the FFIEC CAT Domain 3 (Cybersecurity Controls) checklist. The CISO points to Bolyra. The examiner asks: *"Which FFIEC CAT baseline statement does this satisfy? Which NIST CSF function?"* The construction's vocabulary — "simulation-extractable PLONK," "GGM tree with key puncturing," "SE-NIZK under ROM" — maps to zero FFIEC CAT baseline statements and zero NIST CSF subcategories.

**Why it works / why it fails:** The construction is rigorous academic cryptography. It cites 18 U.S.C. §2703(d) (§1, production evidence) — which is actually a legal compulsion risk the AS-adversary exploits, not a regulatory control Bolyra satisfies. But the construction never inverts the argument: it never produces a table mapping {H1 mutual ZK handshake → FFIEC CAT D3.CC.1, NIST CSF PR.AC-7}, {H4 forward-secure nullifiers → NIST CSF PR.AC-1, GLBA §314.4(c)}. Without this mapping, the CISO has a cryptographic whitepaper and no examination deliverable. The construction's §7 RS integration spec is detailed but the regulatory integration spec — the document the CISO hands the examiner — is absent entirely.

**In-threat-model?** No — construction must address. The claim is "strictly dominates vanilla OAuth 2.1" but vanilla OAuth ships with Auth0/Okta SOC 2 Type II reports, FFIEC CAT-ready control narratives, and examiner-familiar vocabulary. Bolyra ships with none of these. Strict dominance requires parity on operational defensibility, not just cryptographic properties.


## Persona: rfc7662_advocate

---

### Attack 1: Trust Root Displacement — The PLONK Verifying Key is a Registration Event

**Attack:**
H3 claims "zero-config identity portability — one Bolyra credential authenticates at every compliant RS without per-RS client registration." But §7 specifies that each RS must load a PLONK verifier key (via the drop-in middleware adapter) and a manifest fetcher endpoint. That verifier key encodes the circuit's trusted setup artifacts. Before an RS can verify a single Bolyra proof, it must trust *that specific verifying key*. Who distributes it? Under what PKI? How does the RS distinguish a legitimate Bolyra verifying key from a malicious one substituted by an attacker who controls the distribution channel?

In vanilla OAuth + RFC 9728 (Protected Resource Metadata), the RS advertises its AS endpoint in `/.well-known/oauth-protected-resource`. The AS is the trust anchor, and the RS bootstraps from it via a standard HTTPS discovery roundtrip. The Bolyra construction has *displaced* client registration with verifying-key distribution — but that distribution event is structurally identical to registration: it requires an authenticated, trusted channel, it must be revocable, and it must be versioned when circuits are upgraded.

**Why it works / fails:**
The construction has no §7 content addressing verifying-key distribution trust, revocation, or upgrade lifecycle. RFC 7591 dynamic registration at least has a defined revocation path (RFC 7009). Bolyra's §7 "backward compatible sidecar" is silent on what happens when the PLONK circuit is upgraded — do all RSes simultaneously get the new verifying key? Who orchestrates that? This is not zero-config; it is configuration with extra steps and weaker tooling.

**In-threat-model?** No — the construction must address verifying-key distribution as a first-class trust operation, or retract the H3 "zero-config" claim.

---

### Attack 2: Signed JWT Introspection Response Directly Closes H1's Human-Binding Claim

**Attack:**
H1 claims vanilla MCP has "no human-in-the-loop binding." The construction points to bearer tokens and the absence of mutual identity proof. But `draft-ietf-oauth-jwt-introspection-response` (now progressing toward RFC) returns a *signed JWT* from the AS, cache-able by the RS, that includes:

- `acr` (Authentication Context Class Reference, per OIDC Core §2): attests the human authentication method (e.g., `urn:mfa:hardware-key`)
- `amr` (Authentication Methods References): enumerates step-up factors
- `sub` / PPID: identifies the human principal with pairwise pseudonymous identifiers per RS
- `client_id`: identifies the agent/client

An RS receiving this signed JWT introspection response has a cryptographically bound attestation from the AS that *human with hardware MFA bound to agent client\_id* authorized this token for *this RS's audience* (RFC 8707 `resource` indicator). This is a mutual identity proof: RS verifies human + agent, cryptographically. The AS signed it. It's off the hot path because the RS caches it for the token's lifetime.

Where does Bolyra's §2.1-2.2 mutual ZK handshake provide strictly more than this? The construction claims the AS-adversary model makes AS-issued attestations untrustworthy — but the PLONK proving key ceremony *is also run by someone*, and that someone has the same adversarial exposure as an AS operator (see §1's Okta breach argument: applies equally to ZK parameter generators).

**Why it works / fails:**
The construction's response will invoke §1's AS-adversary framing. But: the AS-adversary threat model means we cannot trust *any* AS-issued artifact — which collapses the entire OAuth threat model, not just introspection. If the AS is adversarial, the AS also controls the OIDC discovery metadata that bootstraps trust in the Bolyra verifying key (see Attack 1). The construction must either (a) scope "AS-adversary" narrowly enough that signed JWT introspection is not in scope, or (b) explain how Bolyra's trust root is AS-adversary-resistant in a way that RFC 7662 + signed responses cannot be.

**In-threat-model?** Partial — the AS-adversary framing partially addresses this, but the construction needs an explicit comparison showing where the security boundary lies relative to a well-configured signed introspection response with per-RS PPID.

---

### Attack 3: DPoP With Per-Session Ephemeral Keys Already Provides H4's Forward Secrecy Property

**Attack:**
H4 claims "agent secret exfiltration does not retroactively deanonymize prior sessions. Vanilla bearer tokens have no forward secrecy." The construction's §2.3 closes this with a depth-24 GGM punctured PRF tree (Game 2, FS-NULL bound: `1/2 + 24·Adv^PRF(λ)`).

RFC 9449 DPoP allows per-request ephemeral key pairs. If an agent generates a fresh P-256 key pair for each session (or each tool call), exfiltrating the current key state reveals nothing about prior sessions — the prior private keys are simply deleted. This is textbook forward secrecy, identical in operational effect to key puncturing. The formal difference is:

- GGM puncturing: forward secrecy even if the *key derivation state* is exfiltrated (the tree node for epoch T does not reconstruct epoch T-1 nodes)
- DPoP ephemeral keys: forward secrecy if prior private keys are deleted (no derivation state to exfiltrate)

The construction's FS-NULL game is stronger in the specific adversary model where the attacker obtains the PRF tree state at epoch T. But that adversary model requires the agent to have retained derivation state — which an agent using ephemeral DPoP keys would not have. The construction needs to demonstrate that agent implementations *will* retain GGM tree state in a way that makes the puncturing adversary realistic, rather than using per-call key generation which DPoP already supports.

**Why it works / fails:**
The attack is partially deflected if the construction argues that agents *by default* maintain long-lived identity state (to support nullifier non-reuse across sessions). If nullifiers must be globally unique across sessions, the agent must maintain state, and that state is exactly what the GGM tree protects. But the construction should make this dependency explicit — the forward secrecy argument is load-bearing *only if* nullifier uniqueness requires persistent state.

**In-threat-model?** Partial — construction survives if §2.3/§2.4 explicitly ties GGM tree state to the nullifier-uniqueness requirement. Without that linkage, a reviewer can substitute ephemeral DPoP keys and lose nothing.

---

### Attack 4: RFC 8693 Delegation Chains Do Not Require AS Roundtrip Per Hop — H5's Baseline Is Wrong

**Attack:**
H5 claims "narrow-scope delegation is a primitive (single proof per hop). Vanilla OAuth uses RFC 8693 token exchange requiring full AS roundtrip per hop." This characterization of RFC 8693 is incorrect and overstates Bolyra's advantage.

RFC 8693 §2.1 permits the AS to issue a *pre-authorized delegation token* that itself encodes the permitted delegation chain. A top-level orchestrator agent can obtain a token with `may_act` (RFC 8693 §4.4) or structured `act` claims encoding the full subagent hierarchy. Each hop validates the delegation chain *locally* against the JWT — no AS roundtrip per hop. This is exactly how SPIFFE/SPIRE handles service mesh attestation: the SVID encodes the allowed delegation path; each hop verifies the chain signature without contacting the SPIFFE server.

The Bolyra advantage in H5 reduces to: (a) the proof is computed by the *delegating agent* rather than the AS, and (b) the scope narrowing is enforced by the circuit rather than by AS policy. But for (a), a structured JWT with `act` claims signed by the delegating client achieves the same result if the RS trusts client-signed claims (standard in mTLS or DPoP-bound assertion flows). For (b), AS policy that enforces scope subset at issuance time achieves scope narrowing without ZK.

The construction's §2.8 latency analysis ("3-hop delegation at ~6s, parallel PLONK") should be compared against 3-hop RFC 8693 token exchange with a cached AS response — the AS roundtrip is ~50-100ms per hop in a co-located AS (not 2s). At 3 hops: ~150-300ms. Bolyra's 6s is 20-40x *slower* if the AS is available, and only wins when the AS is unreachable — which is not the default topology.

**Why it works / fails:**
The construction partially addresses latency in §2.8 but does not compare against RFC 8693 with `may_act` pre-authorization and local validation. The attack fails only if Bolyra can demonstrate a delegation scenario where (a) the AS is not consulted and (b) the RFC 8693 `act` chain is insufficient — e.g., dynamic scope negotiation at a leaf hop where the scope wasn't known at issuance time. The construction should identify this specific scenario rather than characterizing all RFC 8693 flows as requiring per-hop roundtrips.

**In-threat-model?** No — H5's baseline characterization is factually incorrect per RFC 8693 §4.4. The construction must either correct the baseline or find a delegation topology that RFC 8693 + pre-authorized `may_act` chains cannot handle.


## Persona: spiffe_engineer

---

### Attack 1: The ZK Attestor Plugin Gap

- **Attack:** §2 describes a "mutual ZK handshake" where H1 claims the novel property is atomically binding human (PLONK) + agent (PLONK) identity to a session nonce, versus a vanilla bearer token. But SPIRE already has a plugin architecture for custom node attestors. A ZK attestor plugin (`spire-agent/attestor/zk`) can emit an SVID whose Subject embeds `{model_hash, operator_pk}` as a SPIFFE path segment (e.g., `spiffe://acme.io/agent/claude-3-7/op-0xdeadbeef`). The session nonce can be carried as a JWT SVID claim. The "mutual" property in §1 reduces to mTLS between two SVIDs — which SPIRE natively enforces via X.509 SVID handshake. The construction's §1 does not explain why a ZK attestor *inside* SPIFFE is insufficient. The adversary submits a 50-line SPIRE attestor shim that hashes `(model_weights, operator_key)` into the SPIFFE ID path and issues a standard X.509 SVID. Where is the gap?

- **Why it works / why it fails:** It works because the construction never justifies why binding occurs *in the proof layer* rather than *in the attestation layer*. The X.509 SVID carries the same binding claims; mTLS provides the mutual property; SPIRE's rotation handles key lifecycle. It partially fails because §2.3's forward-secure PRF (GGM tree with puncturing) is not present in any SPIRE attestor — SVID rotation is coarse-grained (TTL-based), not puncture-based. But the construction must explain why coarse-grained rotation is insufficient *in the MCP threat model* before claiming puncturing is necessary.

- **In-threat-model?** No — the construction must address why a ZK attestor plugin inside SPIFFE does not satisfy H1 and H2. Without that justification, H1 is underdetermined.

---

### Attack 2: WIMSE Already Has H5 in Scope

- **Attack:** H5 claims "narrow-scope delegation is a primitive (single proof per hop)" versus RFC 8693 requiring a full AS roundtrip per hop. The adversary points to `draft-ietf-wimse-arch §5.3` (workload-to-workload token propagation) and the companion `draft-ietf-wimse-w2w` draft, which explicitly models multi-hop delegation via chained `wist` (Workload Identity Security Token) assertions. Each hop appends a signed context claim; the receiving workload verifies the chain without an AS roundtrip. The construction's §7 (`Authorization: Bolyra` header) achieves the same property. The adversary does not need to attack the crypto — they simply file a comment on the WIMSE working group list proposing a ZK-PLONK profile for the `wist` claim set, collapsing H5 into WIMSE scope. The construction becomes a profile, not a protocol.

- **Why it works / why it fails:** It works because WIMSE's token structure is deliberately extensible — the `cnf` confirmation claim and the hop-count semantics are already there. A PLONK proof is just a large opaque bytes field in a JWT. It fails as a complete dismissal because the construction's §2.3 nullifier prevents replay *across* hops in a way WIMSE does not currently model (WIMSE's anti-replay is nonce-based, not forward-secret). But this is a contribution to WIMSE, not a reason for an orthogonal protocol.

- **In-threat-model?** No — the construction must either (a) enumerate the specific WIMSE gap that cannot be closed by a PLONK profile, or (b) explicitly position Bolyra as a WIMSE profile. The current §7 treats WIMSE as nonexistent.

---

### Attack 3: Trust-Domain Federation Already Gives You H3

- **Attack:** H3 claims "one Bolyra credential authenticates at every compliant RS without per-RS client registration." The adversary points to SPIFFE federation: `spiffe://anthropic.io/...` federates with `spiffe://toolco.io/...` via a published bundle endpoint (RFC 9701-style JWK set). Any RS in `toolco.io` accepts SVIDs issued under the `anthropic.io` trust domain without per-client registration — the RS only needs the federated bundle. This is exactly H3. The construction's §7 sidecar middleware does per-RS manifest fetching, which is at minimum as much overhead as a federated bundle refresh. The adversary deploys a SPIFFE federation between two test trust domains in 20 minutes using open-source SPIRE and asks: what does Bolyra give me that this does not?

- **Why it works / why it fails:** It works strongly against H3 as stated. SPIFFE federation with JWT SVIDs already provides cross-vendor agent handoff (the second scenario: Claude → ChatGPT agent) if both operators run SPIRE with federated trust domains. It fails because the construction's human-in-the-loop binding (the PLONK human proof) has no equivalent in SPIFFE — SVIDs are workload credentials, not human credentials. The AS-adversary threat (§1's Okta/Auth0 evidence) also does not apply to SPIFFE, which is not an AS. But the construction must cleanly separate "what SPIFFE federation gives you" from "what Bolyra adds on top" — currently §3 (H3) makes no reference to SPIFFE federation and therefore cannot rebut this attack.

- **In-threat-model?** Partially. The human-leg binding survives; the portability claim (H3 as stated) does not distinguish itself from SPIFFE federation and must be revised.

---

### Attack 4: The Nullifier Is a SPIRE TTL + Rotation

- **Attack:** §2.3's forward-secure PRF via GGM tree with key puncturing (H4) is the construction's strongest novel claim. The adversary concedes the math but attacks the deployment model. SPIRE rotates SVIDs on configurable TTLs (default: 1 hour, configurable to 60 seconds). On rotation, the old SVID is revoked and the new one is issued against fresh keying material. The adversary claims this is functionally equivalent to H4: an attacker who exfiltrates the current SVID private key cannot use it after the next rotation, and cannot retroactively deanonymize prior sessions because prior sessions used prior keys. The construction's §2.3 must show that the GGM puncturing gives a *stronger* forward-secrecy guarantee than SVID rotation — specifically, that compromise at epoch T does not reveal epoch T-1 session linkage. The construction's Game 2 (FS-NULL) does prove this formally, but §2.3 never compares against SVID rotation semantics. The adversary claims that for the MCP latency budget (§2.8 targets <1ms per tool call with session token), SVID rotation at 60s TTL is operationally equivalent and eliminates the GGM tree overhead entirely.

- **Why it works / why it fails:** It works as a cost/benefit challenge — if SVID rotation achieves 99% of the forward-secrecy property at zero additional latency, the construction must justify the GGM tree overhead. It fails as a cryptographic attack because SVID rotation is *probabilistic* forward secrecy (attacker who compromises the CA during a rotation window gets all future SVIDs), while GGM puncturing is *unconditional* forward secrecy for past epochs even given full CA compromise. The §1 Okta/Auth0 evidence makes this precise: an Okta-class AS breach compromises the CA, not just one SVID. But the construction must make this argument explicitly — it is not present in §2.3 or §4.

- **In-threat-model?** Yes — the GGM construction survives the attack cryptographically, but the construction must add a paragraph to §2.3 showing why SVID rotation is insufficient under the AS-adversary threat of §1. Without that bridge, the adversary's operational equivalence claim is unanswered.
