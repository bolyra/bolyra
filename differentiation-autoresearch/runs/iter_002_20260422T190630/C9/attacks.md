# Tier 3 Adversarial — C9 Forward-secure agent delegation

## Persona: auth0_pm

---

### Attack 1: The Secure Deletion Circularity

**Attack:**
Section 8.3 of the construction attacks DPoP on the grounds that "operational deletion is not a cryptographic guarantee" — the agent promises it deleted the old key, but you can't prove it. Then Section 3 defines the adversary's capability as: "Does NOT have access to deleted epoch secrets (**secure deletion assumption for agent runtime**)." The construction's forward secrecy proof rests on the exact same operational promise it uses to disqualify DPoP.

If the compromised agent's runtime failed to zeroize `s_{e-1}` before returning `s_e` — swap file, core dump, GC heap, logging pipeline (the construction's own scenario in §7) — the adversary holds both `s_e` and `s_{e-1}`, and the Poseidon chain offers no protection. The construction gives no mechanism for a verifier to confirm deletion occurred. Section 8.3 explicitly criticizes DPoP for exactly this: "No RFC or WIMSE draft provides a mechanism for an agent to prove to any relying party that a prior key was destroyed." Bolyra provides no such mechanism either. The EpochRotation circuit (§2.4) proves chain integrity given valid inputs — it does not prove that the inputs to prior epochs were destroyed.

**Why it works / fails:**
The argument fails against the construction on a narrow reading: the construction claims the *cryptographic* guarantee is better structured (Poseidon preimage resistance vs. DPoP's per-session key ephemerality). But the security argument in §4 loads the reduction onto A1 (Poseidon preimage resistance) only *after* assuming the adversary never had `s_{e-1}`. That assumption isn't cryptographic — it's operational. The reduction is vacuously correct if the runtime deletes correctly, and completely broken if it doesn't. The construction has not closed the gap it opened.

**In-threat-model?** No — the construction must either (a) formally distinguish when the operational assumption is stronger than DPoP's equivalent assumption and justify why, or (b) specify a TEE / HSM deployment model where key destruction is enforced hardware-side, since the claim in §8.3 is currently self-defeating.

---

### Attack 2: The On-Chain Epoch Commitment Chain Is a Stable Correlator

**Attack:**
Section 2.3 stores `epochCommitment_e = Poseidon1(s_e)` on-chain at each epoch rotation, with the initial value anchored to the credential commitment at enrollment. The public on-chain state is therefore a monotonically growing sequence:

```
(credentialCommitment → epochCommitment_0 → epochCommitment_1 → ... → epochCommitment_T)
```

Every session proof in ForwardSecureAgentSession (§2.5) emits `epochCommitment` as a **public input** — visible to every verifier. An observer watching the on-chain registry sees which sessions were produced under which epoch commitment, and can cluster all sessions sharing `epochCommitment_e` into a single epoch. Across epochs, the commitment chain is publicly linked. The adversary does not need to recover any epoch secret to determine that sessions `{σ_1, σ_2, σ_3}` all belong to the same agent: they share the same epoch commitment anchor in the same chain.

The IND-FS-AGENT game (§3) defines the adversary's challenge as linking two transcripts from the **same** epoch `e*`. That game is trivially won by the epoch commitment: both transcripts carry identical `epochCommitment_{e*}` as a public input. The game as written doesn't test cross-epoch linkability, which is where the real GTM attack lives — an adversary monitoring the chain links agent activity across months by tracing the commitment chain, without compromising any key.

**Why it works / fails:**
The construction anticipates same-epoch nullifier linkability (§4, Case 1–2) but does not address the commitment chain as a cross-epoch correlator. The scope commitment is described as "linkable within the same credential set" (§4, Case 2) with a concession that "scope commitments are linkable within the same credential set" — but the epoch commitment chain is *also* a stable per-agent trace, and it's not addressed. Section 8.1 argues Bolyra "eliminates this correlator" (the AS's `sub`/`jkt` log), but replaces it with an on-chain commitment chain that is equally stable and more durable.

**In-threat-model?** No — the construction must either (a) commit to blinded epoch commitments (e.g., hiding the commitment value from non-participants), (b) use per-session derived commitments that don't form a publicly traceable chain, or (c) revise the IND-FS-AGENT game to cover cross-epoch linkability via the commitment chain and prove unlinkability there.

---

### Attack 3: Forward Secrecy Conflicts with NCUA Audit Requirements in the Flagship Scenario

**Attack:**
Section 7.1 presents SECU deploying a "30-day autonomous lending agent" as the flagship deployment scenario. Credit unions regulated by the NCUA are subject to 12 C.F.R. Part 749, which requires retention of records supporting each loan decision — including the automated decision logic and the identity of the system that processed the application. Forward-secure unlinkability of agent sessions is not a feature in this context; it is a compliance liability.

An NCUA examiner who subpoenas SECU's loan processing records and finds that the agent's session transcripts are "cryptographically unlinkable" to specific loan decisions will flag this as a record-keeping failure. The construction's §7.1 scenario explicitly celebrates that "the attacker cannot determine which sessions belong to the compromised agent" — but the NCUA examiner has exactly the same capability set as that attacker, and SECU has a legal obligation to *not* destroy that linkability.

WorkOS, Auth0, and Stytch ship MCP auth that produces auditable `sub`-bound activity logs. This is not a bug — it is the product. The construction's security argument against persistent correlators inverts the credit union's actual compliance requirement.

**Why it works / fails:**
The construction does not address regulatory audit requirements anywhere. It presents the pseudonymity guarantee as unconditional, with no escape hatch for compliance contexts. A real deployment would need a SECU-controlled audit key that can de-anonymize sessions for examination purposes — but introducing such a key partially reintroduces the correlator the construction eliminates. The construction must define a selective disclosure or auditor escrow mechanism that satisfies both the forward secrecy claim and 12 C.F.R. Part 749, or scope the claim to non-regulated contexts only.

**In-threat-model?** No — the construction must either (a) explicitly carve out regulated contexts where forward secrecy is not the right property, or (b) specify a compliant audit-escrow extension and prove it does not weaken the core unlinkability guarantee for non-escrow parties.

---

### Attack 4: No MCP Protocol Integration — The Construction Has Circuits, WorkOS Has a Product

**Attack:**
The construction's title is "Forward-secure agent delegation" for MCP auth contexts. The adversary's toolbox includes Auth0 MCP auth, WorkOS `/mcp`, Stytch Connected Apps, and Cloudflare Access for remote MCP — all of which ship today against the MCP authorization spec (which extends RFC 6749 with Dynamic Client Registration per RFC 7591 and, in the draft, client attestation per draft-ietf-oauth-attestation-based-client-auth).

The construction contains zero MCP-specific content. It does not define how an MCP server validates a Bolyra epoch nullifier in lieu of a Bearer token. It does not specify how the `ForwardSecureAgentSession` circuit output maps to MCP's `Authorization` header or resource server token introspection. It does not address Dynamic Client Registration — how does an MCP client register a Bolyra credential commitment? It does not address the MCP server's tool-call authorization flow, which today expects an OAuth access token scoped to specific tool names.

An enterprise operator evaluating this construction against WorkOS MCP auth has a concrete integration question on day one: "My MCP server calls `verify_token()` — what does that call look like with Bolyra?" The construction's answer is a PLONK verifier call against a PLONK proof with public signals, which requires the MCP server to run or call a ZK verifier. WorkOS's answer is an HTTP POST to a well-known introspection endpoint. The integration cost differential is not addressed anywhere in the construction.

**Why it works / fails:**
This is a pure GTM attack and does not touch the cryptographic claims. The cryptography in the construction may be sound. But the construction makes no argument for why an MCP server operator would instrument a ZK verifier rather than call `POST /oauth2/introspect`. The scenarios in §7 describe a "lending agent" and a "whistleblower relay" — neither of which are described as MCP tool-call flows. The construction has not demonstrated that the claimed property (forward-secure unlinkability) is a property that MCP server operators actually need, versus a property that is interesting to cryptographers. WorkOS's procurement answer is "SOC 2 Type II, shipped, 100-line integration." Bolyra's is a PLONK circuit spec.

**In-threat-model?** No — the construction must either (a) specify an MCP adapter layer that maps ZK proof verification to the MCP authorization protocol flow, or (b) explicitly scope the construction to non-MCP agent delegation contexts and retitle accordingly. Without this, the comparison to "DPoP-bound OAuth constructions" is technically valid but commercially irrelevant to the stated deployment context.


## Persona: cryptographer

*Reading the construction carefully before touching a keyboard. The claims are specific enough to attack. Let's go.*

---

### Attack 1: The Epoch Commitment IS the Next Epoch Secret — Forward Secrecy Collapses

**Attack:**

Section 2.3 defines:

```
epochCommitment_e = Poseidon1(s_e) = s_{e+1}
```

and states explicitly: *"The initial epoch commitment `epochCommitment_0 = s_1` is stored on-chain at enrollment."* The EpochRotation circuit (§2.4) publishes `newEpochCommitment = Poseidon1(s_e)` to the chain after each rotation.

The adversary does not need to invert Poseidon. The on-chain epoch commitment register at epoch `e` **is** `s_{e+1}` in the clear. Reading the chain state at enrollment and after each rotation gives the adversary `s_1, s_2, \ldots, s_T` as a sequence of public on-chain values — no preimage inversion required.

Concretely:

| Time | On-chain value | Value equals |
|------|----------------|--------------|
| Enrollment | `epochCommitment_0` | `s_1` |
| After epoch 0 rotation | `newEpochCommitment` | `s_2` |
| After epoch 1 rotation | `newEpochCommitment` | `s_3` |
| … | … | … |
| After epoch T-1 rotation | `newEpochCommitment` | `s_T` |

The adversary who compromises the agent at time T and also reads the chain (which §3 explicitly allows: *"read access to the on-chain registry"*) has all of `s_1, \ldots, s_T`. They compute `epochNullifier_e = Poseidon2(s_e, \cdot)` for any epoch `e \geq 1` and reconstruct the full pre-T activity graph.

**Confirmation from circuit inputs:** The EpochRotation circuit (§2.4) lists `previousEpochCommitment` as a public input and Constraint 1 checks `Poseidon1(s_{e-1}) == s_e`, meaning `previousEpochCommitment = s_e` is public. The verifier receives `s_e` in the clear as a public signal on every rotation.

**Why it works:** The design conflates a hash commitment with a key derivation step. A commitment `C(x) = H(x, r)` hides `x` via randomness `r`. Here there is no blinding: `epochCommitment_e = Poseidon1(s_e) = s_{e+1}` is a deterministic, publicly computable value that *is* the next key. The preimage of `epochCommitment_e` is `s_e`, which is irrelevant — the threat is that `epochCommitment_e` itself is `s_{e+1}`, which the adversary needs for the *next* epoch's nullifiers. The entire chain unravels forward.

**In-threat-model?** Yes — the adversary has on-chain read access per §3. **Construction must address this.** Fix requires a hiding commitment: `epochCommitment_e = Poseidon2(s_e, r_e)` with fresh blinding randomness `r_e` that is destroyed with `s_e`, and the circuit proves knowledge of `(s_e, r_e)` such that `Poseidon2(s_e, r_e) == publishedCommitment_e` while separately deriving `s_{e+1} = Poseidon1(s_e)` as a private intermediate never published.

---

### Attack 2: Scope Commitment is a Persistent, Cross-Epoch, Cross-Session Correlator

**Attack:**

The `ForwardSecureAgentSession` circuit (§2.5) outputs `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` as a public output. The `credentialCommitment` is defined in §4.2 (Bolyra base) as `Poseidon5(modelHash, opAx, opAy, permBitmask, expiry)` — a deterministic function of stable, per-agent values that does not rotate with epochs.

This means `scopeCommitment` is **identical** across every session the agent ever executes, for every epoch, forever (until credential revocation). It is a global, stable pseudonym for the agent, visible to every verifier that processes an `AgentSession` proof.

The adversary's strategy in IND-FS-AGENT: ignore the epoch nullifier entirely. Collect the `scopeCommitment` from pre-T transcripts. After compromise, compute `Poseidon5(modelHash, opAx, opAy, permBitmask, expiry)` from the recovered credential material and verify it matches. Every pre-T transcript that carries a matching `scopeCommitment` is immediately attributed to the compromised agent with certainty — no preimage inversion, no nullifier linking needed.

**Why the construction's own reduction fails here:** §4, Case 2 acknowledges this and dismisses it: *"scope commitments are linkable within the same credential set... The scope commitment reveals no more than the policy required."* This is precisely wrong as a security argument. The IND-FS-AGENT linkability game requires that the adversary cannot link transcripts to the compromised agent with non-negligible advantage. The scope commitment is a deterministic function of key material the adversary holds at time T. They trivially win the linkability game against any pre-T transcript: check if `scopeCommitment == Poseidon2(permBitmask, Poseidon5(modelHash, ...))`. The game is broken, not merely "relaxed."

In the whistleblower scenario (§7, Scenario 2): the seized agent's credential material lets the adversary tag every session the agent ever submitted, across all 12 epochs, via `scopeCommitment` alone. The epoch nullifier construction provides zero protection here.

**In-threat-model?** Yes — adversary holds credential key material per §3. **Construction must address this.** At minimum, the threat model must explicitly exclude linkability via `scopeCommitment` from the security claim, changing the claim from "sessions remain cryptographically unlinkable" to the weaker "session nonces are unlinkable; sessions attributed to the same credential set remain linkable by scope commitment." The IND-FS-AGENT game as written is not satisfied by the construction.

---

### Attack 3: The IND-FS-AGENT Game Does Not Formalize the Claimed Security Property

**Attack:**

The game in §3 is structurally malformed for the stated claim. Examine the challenge phase:

> *"C selects epoch e\* < T uniformly at random and two transcripts τ_0, τ_1 from epoch e\*."*

Both τ_0 and τ_1 are transcripts of the **single enrolled agent** from the **same epoch** e\*. The adversary's task is to guess which one C handed them. But:

1. The two transcripts share the same `scopeCommitment` (Attack 2), the same `epochCommitment`, and the same `agentMerkleRoot`. They differ only in `epochNullifier` (since session nonces differ) and in the PLONK proof bytes.

2. Distinguishing τ_b from the other transcript produced by the same agent in the same epoch is not the real threat. The real threat — which the claim text in §1 and §7 articulates — is whether the adversary can **attribute** a transcript to the compromised agent at all, or **replay** a prior session at a different verifier. The game does not model this.

3. A correct formalization requires a multi-agent challenger: enroll N agents (at least one of which is the target), let A see all transcripts from all agents, compromise the target at T, then challenge A to identify which transcripts belong to the target. The current game trivially leaks agent identity via scope commitment (all transcripts in the game are from the same agent), and the b-bit guess is over two transcripts where A already knows both came from the same agent.

The FS-REPLAY game (§3) has a related problem: the "Advantage" is defined as `Pr[Verify(π*) = 1 ∧ epochNullifier(π*) matches some pre-T session]`. The conjunction is strange — producing a valid proof that happens to contain a nullifier matching a prior session is exactly the replay. But if the nullifier is pseudorandom and the adversary doesn't know `s_{e*}`, they cannot construct a proof with a matching nullifier. If they can forge a proof with an *arbitrary* new nullifier that passes verification, that is a soundness break independent of the nullifier matching condition. The game conflates these two distinct failure modes.

**Why it works:** Without a simulator construction, the ZK claim is unverifiable. §4, Case 3 states: *"PLONK proofs are zero-knowledge (simulator exists in ROM). The proof reveals nothing beyond the public signals."* Standard PLONK achieves honest-verifier zero-knowledge (HVZK) in the random oracle model. This is not malicious-verifier ZK and not simulation-extractability. An on-chain smart contract verifier is a deterministic program, not an honest verifier — it can choose public inputs adversarially. No simulator is exhibited; no UC-realization is claimed. For the IND-FS-AGENT game to be meaningful, the ZK property must hold against the adversary who controls the verifier's public inputs.

**In-threat-model?** Partially — the game is in-model but does not formalize the claim in §1. **Construction must address this.** The game must be revised to model multi-agent unlinkability, or the claim must be scoped to "within a single epoch, sessions are unlinked by nullifier" — a much weaker statement that still fails against the scope commitment attack.

---

### Attack 4: Nullifier Precomputation Attack When Verifier Knows epochCommitment and sessionNonce

**Attack:**

From the forward-secure delegation nullifier construction (§2.6):

```
epochDelegationNullifier = Poseidon2(
  Poseidon4(prevScope, delegateeCC, delegateeScope, delegateeExpiry),
  Poseidon2(delegator_s_e, sessionNonce)
)
```

The inner term `Poseidon4(prevScope, delegateeCC, delegateeScope, delegateeExpiry)` depends only on public or semi-public values: `prevScope` is a public input, `delegateeCC` is registered on-chain, `delegateeScope` and `delegateeExpiry` are public inputs. This entire first argument to the outer Poseidon2 is computable by any observer who sees the delegation proof's public signals — call it `D`.

The epoch delegation nullifier therefore reduces to `Poseidon2(D, Poseidon2(delegator_s_e, sessionNonce))`. By the same Attack 1 argument, `delegator_s_e` for `e \geq 1` is recoverable from on-chain epoch commitments (since `epochCommitment_e = s_{e+1}`). Given `D`, `delegator_s_e`, and `sessionNonce` (which is a public input to the circuit), the nullifier is fully computable without any private knowledge.

More critically: in the AgentSession circuit (§2.5), `sessionNonce` is a public input. An adversary who observes a delegation during epoch `e`, reads `delegator_s_e` from the on-chain commitment register, and reads `sessionNonce` from the public signals, can compute the expected `epochDelegationNullifier` for any delegation in epoch `e \geq 1`. They can also check whether a given delegation nullifier on-chain matches their computation — linking delegation events to delegators retroactively.

**Why it works:** The nullifier construction for delegation is structurally weaker than for agent sessions because one of its two Poseidon arguments (`D`) is computable from public data, and the other (`Poseidon2(delegator_s_e, nonce)`) loses secrecy once `s_e` is leaked via the epoch commitment register. The standard Bolyra nullifier `Poseidon2(credentialCommitment, sessionNonce)` has `credentialCommitment` as a private value, providing one layer of secrecy. The forward-secure variant moves that secrecy to `s_e`, then leaks `s_e` through the commitment design.

**In-threat-model?** Yes — adversary has on-chain read access and observes public signals per §3. **Construction must address this.** At minimum, requires the blinding fix from Attack 1 to prevent `s_e` from appearing in the clear as `epochCommitment_{e-1}`, and requires that at least one input to each nullifier Poseidon call is permanently secret and never published.


## Persona: cu_ciso

---

### Attack 1: The Audit Trail Paradox

- **Attack:** The CISO presents the construction to their NCUA examiner during an IT examination under Part 748. The examiner asks for the audit trail showing what the autonomous lending agent did on a specific date when a member disputes a loan denial. The CISO turns to §7.1 (Scenario 1, SECU 30-day lending agent) and reads back the construction's own guarantee: "*The 30 days of on-chain transcripts contain epoch nullifiers that are pseudorandom values unlinkable to the compromised agent*." The examiner stops them. The construction's primary security property — that prior sessions are unlinkable — is structurally incompatible with NCUA Part 748 Appendix B's requirement for security event audit trails and GLBA's requirement that the credit union demonstrate it can reconstruct member-affecting system activity. The construction provides no secondary audit mechanism (e.g., an out-of-band encrypted log keyed to a separate audit key) that would let the institution satisfy both properties simultaneously.

- **Why it works / why it fails:** The construction addresses the *adversarial* linkability problem (attacker holds compromised key, cannot reconstruct history) but does not address the *authorized* linkability problem (regulator holds subpoena, credit union must reconstruct history). These are not the same threat. The construction's security argument is sound for its stated game, but the game definition (IND-FS-AGENT, §3) only models the adversary — not the compliance auditor who is authorized to link. No section of the construction describes a mechanism for the credit union to maintain a parallel audit log keyed to a non-epoch secret that survives the epoch rotation without defeating forward secrecy.

- **In-threat-model?** No. The construction must address this. A dual-path architecture — epoch-bound unlinkability for external observers, encrypted audit log keyed to an operator-held audit key held in escrow — is the standard answer, but it is absent here.

---

### Attack 2: Secure Deletion is an Unverifiable Operational Assumption Dressed as a Cryptographic Guarantee

- **Attack:** The CISO pulls up the threat model (§3, Adversary capabilities): "*Does NOT have access to deleted epoch secrets (secure deletion assumption for agent runtime).*" They then pull up their NCUA third-party risk examination questionnaire and ask: "Show me the evidence that `s_e` was deleted after epoch `e` ended." The answer the construction gives is: Poseidon preimage resistance means the adversary *can't use* `s_{e+1}` to recover `s_e`. But this says nothing about whether `s_e` was actually destroyed. The epoch secret lives somewhere during epoch `e` — a container memory region, a Lambda environment, a K8s secret, a TEE enclave. The construction names none of these. GLBA Safeguards Rule (16 CFR §314.4(c)) requires the credit union to demonstrate safeguards, not assume them. If the agent runtime is a standard Python process, `s_e` may persist in swap, a core dump, a memory snapshot taken by a monitoring agent, or a crash log. The construction's forward secrecy guarantee degrades from a cryptographic property to an operational hygiene promise the moment `s_e` touches non-cryptographic storage.

- **Why it works / why it fails:** The IND-FS-AGENT game explicitly excludes the deleted epoch secrets from the adversary's view by assumption, not by construction. The construction does not specify a key storage mechanism (HSM, TEE, software keystore), a deletion protocol, or any attestation mechanism that would let the credit union prove to an examiner that deletion occurred. The whistleblower scenario (§7.2) is the worst case: if the agent is seized, forensic analysis of the runtime environment may recover `s_e` values that were "deleted" only in the sense that the variable was overwritten in heap memory — a technique that fails against cold-boot attacks and memory forensics.

- **In-threat-model?** No. The construction must specify a concrete key storage and deletion mechanism and bound the adversary's forensic recovery capability. Without this, the forward secrecy claim is conditional on an assumption the credit union cannot demonstrate to its examiner.

---

### Attack 3: On-Chain Registry as Unrated Critical Infrastructure

- **Attack:** The CISO asks: "What's the SLA on the on-chain epoch commitment registry?" Every agent session (§2.5, ForwardSecureAgentSession) requires the verifier to check `epochCommitment` against on-chain state. Every epoch rotation (§2.4, EpochRotation) must write `newEpochCommitment` to the chain before the next session can proceed. For the SECU lending agent (§7.1), this means every loan application proof submission is gated on on-chain availability. The construction does not name the chain, the consensus mechanism, or the availability target. FFIEC CAT Domain 3 (Cybersecurity Controls) requires availability controls for systems processing member financial transactions. A public EVM chain with a 99% uptime SLA — industry-standard for non-enterprise deployments — yields 87 hours of agent downtime per year. No core processor operates at that availability floor. The CISO's vendor management policy requires a signed SLA for any third-party system in the critical path of member-facing operations.

- **Why it works / why it fails:** The construction makes the on-chain registry a synchronous dependency for proof verification (the verifier must read `epochCommitment_e` to validate the session proof). There is no described fallback, no cache policy, no degraded-mode operation. An epoch rotation that fails to confirm on-chain — due to gas price spikes, chain congestion, or network partition — leaves the agent unable to prove its sessions for the new epoch. The construction's deployment scenario uses a real credit union (SECU) but never addresses what happens when the chain is unavailable during a member loan application.

- **In-threat-model?** No. The construction must specify an availability architecture for the on-chain registry — either a permissioned chain with a defined SLA, a cache + re-verification pattern, or a fallback proof mode — and demonstrate it meets FFIEC availability requirements for member-facing systems.

---

### Attack 4: Scope Commitment Is a Persistent Fleet Correlator — The Construction Concedes This

- **Attack:** The CISO runs the SECU lending agent scenario with 50 parallel agents, all with identical permission bitmasks (loan origination scope) and identical credential commitments (same operator public key, same model hash). The construction's §4, Case 2 reduction sketch explicitly concedes: "*The scope commitment `Poseidon2(permissionBitmask, credentialCommitment)` is identical for all agents with the same permissions and credentials.*" Every session from every one of these 50 agents emits the same `scopeCommitment` as a public output. An on-chain observer collects all session proofs, clusters them by `scopeCommitment`, and now has a labeled bucket containing every loan-processing event ever executed by any agent in this fleet — timestamps, epoch boundaries, session counts, and behavioral cadence. This is not linkability of *individual* agents but it is linkability of the *agent class*, which in a small-fleet deployment (10 agents, not 50,000) may be sufficient to infer member access patterns and correlate with external data.

- **Why it works / why it fails:** The construction correctly notes this is "by design" — scope commitments are intentionally public for policy enforcement. But the CISO's threat is not theoretical cryptographic linkability; it is the practical inference an adversary (or the institution under investigation in a whistleblower scenario) can draw from a homogeneous fleet's behavioral metadata. The whistleblower scenario (§7.2) assumes a single agent, but the construction's primary deployment target (§7.1) is an institutional fleet. The security argument for the whistleblower case does not transfer to the fleet case because the scope commitment is a stable, public, persistent correlator that the epoch nullifier's unlinkability cannot obscure.

- **In-threat-model?** No. The construction must either (a) specify a scope commitment blinding mechanism that introduces per-agent or per-epoch entropy into the scope commitment without breaking the policy enforcement property, or (b) explicitly bound the threat model to single-agent deployments and disclaim fleet-level behavioral inference. The current text does neither.


## Persona: rfc7662_advocate

---

### Attack 1: The EpochCommitment Public Input Is a Per-Epoch Session Correlator

**Attack:**
Section 2.5 lists `epochCommitment` as a *public input* to `ForwardSecureAgentSession`. Every session proof executed in epoch `e` carries the same `epochCommitment_e` value in plaintext. On-chain, all nullifiers emitted during epoch `e` are trivially grouped by this shared public signal. Furthermore, the `EpochRotation` circuit (§2.4) chains `previousEpochCommitment → newEpochCommitment` with both values as public outputs — the full epoch chain is visible on-chain, anchored to the credential commitment stored at enrollment.

An adversary who knows the enrolled agent (e.g., from the Merkle registry or from observing the enrollment transaction) can walk the public `epochCommitment` chain forward from `epochCommitment_0`. They know exactly how many epochs ran, when each rotation occurred (from the `epochIndex` public input), and can group every session proof by epoch. This is not linkability *across* epochs — it is complete session enumeration *within* epochs, plus a public timeline of agent activity cadence.

**Why it fails against the construction (partially):**
The construction's forward secrecy claim is specifically about post-compromise retroactive unlinkability — the adversary cannot compute `s_{e*}` from `s_T`. Within a given epoch, the adversary can group sessions (same `epochCommitment`) but cannot distinguish *which* `sessionNonce` produced which `epochNullifier` without `s_{e*}`.

**Why it still lands:**
The IND-FS-AGENT game (§3) is stated over "two transcripts from epoch e*" — but the game does not account for the publicly visible `epochCommitment` grouping. An adversary who observes the on-chain transcript set can partition it into epoch buckets without any cryptographic effort. The session count, timing, and epoch rhythm of the agent's activity graph are fully reconstructible. Section 8.1's claim that "there is no `sub`, no `client_id`, no `jkt` thumbprint" is technically true but misleading: `epochCommitment_e` serves as a per-epoch correlator that is stable across all sessions in that epoch and visibly chained across the agent's lifetime. Compare: RFC 8707 Resource Indicators + per-RS token binding gives the AS per-RS activity partitions at the same granularity, without on-chain publication.

**In-threat-model?** Partially. The game definition must be strengthened to address intra-epoch grouping via public `epochCommitment`, and the construction must address what the on-chain epoch chain reveals about activity cadence.

---

### Attack 2: scopeCommitment Is a Durable Cross-Session Identity Fingerprint — Post-Compromise Graph Reconstruction Succeeds

**Attack:**
Section 2.5 lists `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` as a public output of every `ForwardSecureAgentSession` proof. The credential commitment is `Poseidon5(modelHash, opAx, opAy, permBitmask, expiry)` — deterministically derived from the agent's credential key material, which the adversary holds at time T (§3: "credential private key"). With the compromised credential, the adversary computes `credentialCommitment` and `scopeCommitment` directly, then scans the entire on-chain nullifier set for every proof bearing that `scopeCommitment`.

This is complete activity graph enumeration. Every session ever executed by the compromised agent — across all epochs, including all pre-T epochs — is identified and timestamped via the `epochIndex` and `epochCommitment` public signals. The adversary does not need to recover any `s_e`; they only need the credential commitment to reconstruct the full session list.

**Why the construction partially acknowledges this:**
Section 4, Case 2 states: "scope commitments are linkable within the same credential set... The scope commitment reveals no more than the policy required, which is a public input." This is a concession, not a defense.

**Why it breaks the stated claim:**
The abstract claim (§1) is that "sessions and delegations executed before T remain cryptographically unlinkable." If I can enumerate every session by filtering on `scopeCommitment`, the sessions are *linked to the agent* — I know the full set of when the agent acted, across all epochs. What I cannot determine is the endpoint called or the resource accessed (that's in the private witness). But the activity graph — "agent X executed N sessions across M epochs on these dates" — is fully recoverable from on-chain data using only the compromised credential commitment.

RFC 7662 with per-RS introspection filtering (§4.4 of the RFC) can be configured to return only the scopes the requesting RS needs — the AS never publishes a global activity log. Bolyra's design does the opposite: it anchors a stable `scopeCommitment` to every proof and publishes it globally.

**In-threat-model?** Yes, and the construction must address it. The IND-FS-AGENT game needs to explicitly exclude or bound what the `scopeCommitment` leaks, or the unlinkability claim must be scoped to "content unlinkability" rather than "activity graph unlinkability."

---

### Attack 3: Per-Epoch DPoP Key Rotation Is Not Analyzed — the §8.1 Critique Is Against a Strawman

**Attack (from attack_prompts seed):** "DPoP provides sender-constraint without any ZK. Name the property DPoP cannot provide."

Section 8.1's critique of DPoP addresses *per-session* ephemeral keypairs. It correctly identifies that the AS logs `(sub, jkt_i, t_i)` for each session. But the construction never analyzes the natural baseline countermeasure: **per-epoch DPoP key rotation**, which matches the construction's own granularity.

Concretely: generate one DPoP keypair `(sk_e, pk_e)` per epoch, use it for all sessions in that epoch, delete `sk_e` at epoch rotation. The AS log becomes `{(sub, jkt_e, epoch_e)}` — one entry per epoch, not per session. After deletion of `sk_e`, an adversary holding `sk_T` cannot verify prior DPoP proofs from epoch `e < T` because they lack `sk_e`. RFC 9449 §7.1 explicitly contemplates key rotation. Combine this with:

- `draft-ietf-oauth-jwt-introspection-response`: the AS issues a signed JWT introspection response, which RSes cache — AS is off the hot path for session-level logging after token issuance.
- RFC 8693 Token Exchange: per-epoch tokens bound to `pk_e` are exchanged at epoch boundaries; old tokens expire.
- Pairwise subject identifiers: the AS-side `sub` is replaced with a PPID per RP, so the AS log entry is `(ppid_e_RP, jkt_e)` — no stable global correlator.

**The residual gap:**
The AS still has `ppid_e_RP → real_sub` mapping (PPIDs are AS-computed). In a scenario where the AS is adversarial (§7, Scenario 2: institution under investigation is also the AS), this mapping survives. Bolyra's epoch nullifier has no such mapping — the verifier only sees `Poseidon2(s_e, nonce)` with no AS involvement. This is the genuine structural advantage.

**Why the construction must address this explicitly:**
Section 8.1 concludes "The baseline cannot satisfy IND-FS-AGENT" without ever analyzing per-epoch DPoP rotation. This weakens the comparative argument. The construction should quantify what per-epoch DPoP with PPID achieves and precisely identify the residual advantage: ZK removes the AS entirely, eliminating the `sub → ppid` mapping at the identity layer. As written, §8.1 proves too little against too weak a baseline.

**In-threat-model?** No — the construction survives against an adversarial AS (genuinely not achievable by DPoP+PPID). But the construction's comparative argument in §8 must be revised to address per-epoch DPoP or it overstates the gap.

---

### Attack 4: The Secure-Deletion Dependency Is an Operational Assumption — Identical in Kind to the Baseline Flaw §8.3 Criticizes

**Attack:**
Section 8.3 criticizes the baseline on the grounds that "operational deletion is not a cryptographic guarantee." It correctly notes that DPoP's forward secrecy rests on a runtime promise ("we deleted the old key") that has no verifiable proof. Then §3 lists the adversary capability exclusion: the adversary "does NOT have access to deleted epoch secrets (secure deletion assumption for agent runtime)."

This is the same assumption. The Poseidon hash chain `s_{e+1} = Poseidon1(s_e)` is one-way — but the circuit does not prove that `s_{e-1}` was destroyed. It only proves that `s_e` hashes to the stored `epochCommitment`. If the agent runtime retains all epoch secrets (a misconfiguration, a memory dump, a hypervisor snapshot, a logging bug), the adversary who obtains `s_T` *also* obtains `s_0, ..., s_{T-1}` from the same compromise. The ZK circuit's preimage resistance is irrelevant if the preimages were never deleted.

**The structural asymmetry the construction claims but doesn't deliver:**
Section 8.3, point 3 states: "With Bolyra, the verifier checks the epoch commitment on-chain: the proof is valid only if the epoch secret hashes to the stored commitment. Forward secrecy is a property of the proof system (Poseidon preimage resistance), not of the agent's operational hygiene."

This is false as stated. Forward secrecy in this construction requires both Poseidon preimage resistance *and* secure deletion of prior epoch secrets. The verifier's check (`Poseidon1(s_e) == epochCommitment`) proves knowledge of `s_e` but says nothing about whether `s_{e-1}` still exists. The cryptographic guarantee is conditional on the deletion guarantee. RFC 9449 DPoP with per-epoch keys has exactly the same conditional structure: key deletion is required for forward secrecy, and neither the DPoP verifier nor the Bolyra verifier can distinguish a runtime that faithfully deletes secrets from one that doesn't.

**The genuine advantage Bolyra has (narrowly):**
Bolyra's epoch commitment chain allows an auditor to verify that epoch *transitions* occurred at the claimed times (the on-chain record is append-only). This is not possible with DPoP key deletion. But this is an auditability property, not a forward-secrecy property, and it is not what §8.3 claims.

**In-threat-model?** Yes. The construction must either (a) acknowledge that the secure deletion assumption is load-bearing and equivalent to the baseline's operational deletion, narrowing the claimed advantage accordingly, or (b) introduce a cryptographic deletion proof mechanism — none is currently specified.


## Persona: spiffe_engineer

---

### Attack 1: The Secure-Deletion Self-Contradiction

- **Attack:** Section 8.3 opens with *"Operational deletion is not a cryptographic guarantee — and verifiers cannot distinguish them"* and lists three failure modes: no proof of deletion, memory forensics risk, and verifier ambiguity. The construction then uses this argument to dismiss the entire DPoP/WIMSE baseline. But the Poseidon hash chain's forward secrecy in §2.1 is predicated on *exactly the same assumption* it just attacked: that the agent runtime irreversibly deletes `s_e` after computing `s_{e+1}`. The circuit `EpochRotation` (§2.4) proves the chain transition is arithmetically correct — it proves nothing about whether `s_e` was actually zeroed in memory before the proof was submitted. An agent whose runtime is compromised mid-epoch (swap file, OOM dump, hypervisor snapshot) leaks `s_e` intact. SPIRE's attestation model addresses this by binding key material to the SPIRE agent's node attestation, which ties identity to hardware or cloud-provider attestation roots (TPM, AWS IID, GCP IAT). The construction has no attestation anchor — it trusts the agent process to self-delete correctly. The attack works because the construction's own critique of the baseline in §8.3 applies word-for-word to the epoch secret chain.

- **Why it works / why it fails:** It works because there is no `ProofOfEpochDeletion` circuit output and no attestation primitive mapping (§5 table) that covers it. The `epochTransitionNullifier` in `EpochRotation` proves the agent *knew* `s_e` at transition time; it does not prove `s_e` is gone. The construction cannot fail on this point at the circuit level — but the security argument in §4 inherits this gap silently, making the "forward secrecy" property dependent on the same operational hygiene the construction dismisses as insufficient in §8.3.

- **In-threat-model?** No. The construction must either (a) add a hardware attestation anchor (TPM, secure enclave) that binds epoch secret deletion to a hardware-enforced deletion event, producing an auditable deletion proof, or (b) retract the argument in §8.3 that operational deletion is not a cryptographic guarantee — it cannot use that argument against DPoP while relying on it internally.

---

### Attack 2: Scope Commitment Is a Persistent Correlator the Adversary Can Enumerate

- **Attack:** The `ForwardSecureAgentSession` circuit (§2.5) emits `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` as a public output. The construction acknowledges in §4 (Case 2) that *"scope commitments are linkable within the same credential set — this is by design."* But the adversary at time T holds the compromised credential private key, which means they can compute the `credentialCommitment = Poseidon5(modelHash, opAx, opAy, permBitmask, expiry)` directly from the known key material. They also know the `permissionBitmask` because it is public (required scope mask is a public input). Therefore, the adversary can compute the exact `scopeCommitment` value for every permission configuration the agent ever used, and scan the on-chain transcript log to identify every session that emitted a matching scope commitment. For a production agent with a stable permission set (the common case: same model, same operator, same permissions for the entire 30-day SECU deployment in §7 Scenario 1), *every pre-T session maps to the same scope commitment* and is trivially enumerable. The forward-secure epoch nullifier prevents replay and prevents the adversary from generating new valid proofs — but it does not prevent the adversary from identifying *which* on-chain sessions belong to the compromised agent and reconstructing the session count, timing distribution, and epoch boundaries.

- **Why it works / why it fails:** The construction's linkability game IND-FS-AGENT (§3) requires that the adversary *cannot link or replay pre-T sessions with non-negligible advantage.* Scope commitment linkability under the compromised credential is not excluded by assumptions A1–A4. Poseidon preimage resistance (A1) and PRF security (A2) protect the epoch nullifier; they say nothing about the scope commitment, which is computed from public inputs the adversary already knows. The reduction sketch in §4 Case 2 dismisses this with *"scope commitments reveal no more than the policy required"* — but this is not a security argument, it is a policy argument. The adversary's advantage in the linkability game is non-negligible whenever the agent's permission set is stable across epochs (which is the stated deployment target).

- **In-threat-model?** No. The IND-FS-AGENT game definition must be amended to address scope commitment enumeration, or the construction must add a blinding factor to the scope commitment: `Poseidon3(permissionBitmask, credentialCommitment, epochBlindingFactor)` where `epochBlindingFactor` is derived from `s_e`. This requires an additional Poseidon constraint (~282 constraints) and changes the scope commitment from stable to epoch-bound, eliminating the persistent correlator.

---

### Attack 3: SPIFFE ZK Attestor — Reinventing at the Wrong Layer

- **Attack:** SPIRE's node attestation plugin interface (`NodeAttestor`) and workload attestation interface accept custom attestors as gRPC plugins. The construction's epoch secret chain is, architecturally, a workload identity secret with forward-secure key derivation. Nothing in the SPIFFE specification prohibits a SVID whose `spiffe://trust-domain/path` URI encodes a commitment to an epoch chain rather than a stable workload path. A ZK attestor for SPIRE would: (a) register an initial epoch commitment as the workload identity anchor at enrollment, (b) issue a short-lived JWT-SVID whose subject claim is the epoch commitment rather than the stable path string, and (c) let the WIMSE token exchange draft (draft-ietf-wimse-s2s-protocol) handle delegation chaining. The result is forward-secure workload identity that federates across trust domains via SPIFFE federation, interoperates with existing mTLS-based service meshes, benefits from SPIRE's production-hardened node attestation (TPM, AWS IID, Azure MSI), and requires zero new on-chain infrastructure. The construction introduces an on-chain Merkle registry, three new PLONK circuits, and a novel protocol — but the distinguishing capability (epoch-bound pseudonymous nullifiers) could be contributed as a SPIRE attestor plugin and a WIMSE selective-disclosure extension rather than a new protocol.

- **Why it works / why it fails:** The construction's §8.2 argues that WIMSE SVIDs leak structural metadata through SPIFFE ID stability — which is correct for the current WIMSE spec. But this is an argument for *extending WIMSE*, not for replacing it. The WIMSE architecture draft explicitly leaves attestation mechanisms open. The attack does not break the construction's cryptographic claims; it challenges the *protocol justification*. The construction must argue why the Bolyra on-chain registry provides capabilities that a SPIRE ZK attestor plugin cannot, given that SPIRE already handles node attestation (the deletion-guarantee gap from Attack 1) and trust domain federation (the cross-domain delegation use case in §2.6).

- **In-threat-model?** No (this is a protocol-justification failure, not a cryptographic attack). The construction must add a section explaining why the on-chain nullifier registry provides properties that a short-lived SPIFFE JWT-SVID with a ZK-derived subject claim cannot. Specifically: the nullifier registry provides double-spend prevention across an open verifier set without a centralized SPIRE server — this is the genuine gap, and the construction does not articulate it as such.

---

### Attack 4: On-Chain Temporal Metadata Reconstructs the Activity Graph Epoch-by-Epoch

- **Attack:** The `EpochRotation` circuit (§2.4) publishes `newEpochCommitment` and `epochTransitionNullifier` on-chain at every epoch boundary. The `agentMerkleRoot` is a public output of `ForwardSecureAgentSession` (§2.5) and is stable across all sessions for the same enrolled agent (it is the root of the Merkle tree containing the agent's credential commitment). An adversary watching the on-chain registry observes: a sequence of `epochTransitionNullifier` events (one per epoch), each emitted at a known block timestamp; and a stream of session proofs, each containing the stable `agentMerkleRoot`. The `agentMerkleRoot` acts as a pseudonymous but stable per-agent identifier across all sessions — it does not rotate with the epoch. The adversary at time T knows the Merkle tree root for the compromised agent (computable from the credential commitment and the on-chain tree). They can therefore: (a) identify all on-chain sessions belonging to the compromised agent by matching `agentMerkleRoot`; (b) partition those sessions into epochs by correlating with `epochTransitionNullifier` timestamps; and (c) reconstruct the session volume, timing, and epoch boundaries for all pre-T activity. The epoch nullifiers remain unlinkable *within* the IND-FS-AGENT game definition, but the activity graph — *how many sessions, in which epochs, at what times* — is fully recoverable from on-chain metadata. Scenario 2 (§7, CFPB whistleblower) explicitly requires that *"all prior relay sessions are cryptographically unlinkable to the informant's identity."* A timing attack on the on-chain record reconstructs the session schedule without inverting Poseidon once.

- **Why it works / why it fails:** The IND-FS-AGENT game (§3) challenges the adversary to distinguish between two specific transcripts `τ_0, τ_1`. It does not bound the adversary's ability to enumerate the *set* of sessions belonging to the compromised agent, nor to recover temporal structure. The `agentMerkleRoot` is noted as an inherited public output in §2.5 but is never analyzed for linkability in §4 or §8. The reduction sketches in §4 address only epoch nullifier linkability (Case 1), scope commitment enumeration (Case 2, partially — see Attack 2), and PLONK proof leakage (Case 3). On-chain temporal metadata via `agentMerkleRoot` correlation is unaddressed.

- **In-threat-model?** No. The construction must either (a) rotate the `agentMerkleRoot` at each epoch by re-enrolling under a fresh Merkle leaf (expensive: one on-chain write per epoch per agent), or (b) replace the stable `agentMerkleRoot` public output with an epoch-blinded credential commitment `Poseidon2(credentialCommitment, s_e)` that changes each epoch without requiring re-enrollment. Option (b) requires the Merkle tree to contain epoch-blinded commitments rather than raw credential commitments, which changes the enrollment protocol in §2.3 and the `ForwardSecureAgentSession` constraint count. Until this is addressed, the whistleblower scenario in §7 Scenario 2 does not hold: the on-chain record is a timing-correlated activity log indexed by a stable agent identifier, regardless of epoch nullifier unlinkability.
