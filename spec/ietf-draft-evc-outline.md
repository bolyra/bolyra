# Internet-Draft Outline — External Verifier Contract (EVC)

> **This file is an OUTLINE, not the draft.** It scopes and sequences an
> individual Internet-Draft to be submitted as `draft-kondoju-evc-00`. Prose is
> deliberately compressed to bullet form; the section-by-section TODO in §14
> sizes the writing work for a first submission. The normative source of truth is
> `spec/external-verifier-contract-v1.md` (EVC v1) plus
> `spec/receipt-signer-discovery-v1.md` (RSD v1). This outline MUST NOT introduce
> requirements absent from, or in conflict with, those shipped specs; where it
> proposes anything new (e.g. an IANA registry), it is marked **[NEW — draft-only]**.

---

## Front matter (kramdown-rfc / mmark)

```
title: "An External Verifier Contract for Agent Authorization Decisions"
abbrev: "External Verifier Contract"
docname: draft-kondoju-evc-00
category: info          # informational first; std-track only if a WG adopts it
ipr: trust200902
area: Security
workgroup: (individual submission — no WG yet)
keyword: [agent, authorization, verifier, zero-knowledge, selective-disclosure]

author:
  - name: Viswanadha Pratap Kondoju
    organization: Bolyra
    email: viswa@bolyra.ai

normative:
  RFC2119:
  RFC8174:
  RFC8259:   # JSON
  RFC8126:   # IANA registration-policy guidelines (basis for §14 "Specification Required")

informative:
  I-D.klrc-aiagent-auth:            # draft-klrc-aiagent-auth-03 (2026-07-06) — complementary
  I-D.pidlisnyi-aps:                # draft-pidlisnyi-aps-02 — related (see §12)
  RFC6749:   # OAuth 2.0 (context)
  RFC7662:   # Token introspection (contrast: online vs. offline verdict)
  RFC7519:   # JWT — cited informatively (payload a classical-class verifier MAY validate)
  RFC8615:   # Well-Known URIs (RSD path, §11 relationship)
```

- **Category decision:** file **Informational** for `-00`. The contract describes
  an interoperability surface between an existing host and an existing verifier;
  it is not (yet) requesting a standards-track commitment. Revisit if a WG (SECDISPATCH
  → likely OAUTH or a new agent-auth WG) shows interest. **[decision to confirm before submit]**
- **RFC 2119 / 8174 plan:** every normative keyword lifted into the draft comes
  from EVC v1, which already uses BCP 14 correctly. The Requirements Language
  section (§2) MUST use the exact RFC 8174 boilerplate ("... only when, and only
  when, they appear in all capitals ..."). Do **not** invent new MUST/SHOULD
  obligations in the draft that are not already normative in EVC v1 — the draft is a
  faithful transcription plus IETF framing, not a redesign.

---

## Abstract (to write)

- One paragraph. Frame: a **small, testable, proof-system-agnostic contract**
  between a *host* (the program about to take a privileged action on an agent's
  behalf) and an external *verifier* (a subprocess that renders an allow/deny
  verdict on an opaque proof bundle).
- Emphasize the three properties that make it standardizable: (1) single-shot
  subprocess transport with a closed JSON verdict schema; (2) **fail-closed**
  host semantics that are independently testable via a host-conformance suite;
  (3) proof-system agnosticism — the same envelope carries classical-signature,
  zero-knowledge, and third-party verdicts, distinguished by an OPTIONAL `kind`
  self-description.
- Explicitly NOT a governance framework, NOT a delegation model, NOT a policy
  language. It is the narrow decision boundary those larger systems all need.

---

## 1. Introduction (to write)

- **Problem.** Agent frameworks (MCP hosts, orchestrators, gateways) increasingly
  need to gate a privileged tool call on "is this agent actually authorized?"
  Today each host reimplements a bespoke check and couples itself to one proof
  format. There is no interoperable, language-neutral boundary at which a host can
  ask an *external* verifier — one it did not build — for a decision.
- **What EVC standardizes.** The *transport and verdict envelope only*: how the
  host hands a request to a verifier subprocess (stdin, one JSON object), how the
  verifier answers (stdout, exactly one JSON verdict), how exit codes and timeouts
  are interpreted, and the fail-closed obligations on the host. The proof bundle
  itself is **opaque** to the host (EVC v1 §1, §10).
- **What EVC deliberately excludes.** Credential issuance, the proof format
  (`bvp/1` internals), policy authoring, delegation semantics, revocation
  infrastructure, PKI. These belong to the verifier vendor or to adjacent specs.
  Keeping the boundary this small is the design thesis — it is what makes the
  contract *testable* rather than aspirational.
- **Why now / why interoperable.** Cite the independent-maintainer validation:
  `mcp_agent_mail_rust#183` publicly matched its host requirements to EVC v1 —
  external evidence that a second implementer's needs map onto this boundary. Two
  independent reference hosts already exist (`spec/reference-host.js`,
  `spec/reference-host-rs/`), demonstrating the contract is not tied to one runtime.
- **Non-normative positioning vs. online introspection (RFC 7662).** A verdict is
  produced **offline** from a self-contained bundle plus host-supplied context and
  wall-clock; there is no round-trip to an authorization server. Contrast, do not
  compete.

### 2. Conventions and Requirements Language (to write)

- Standard BCP 14 boilerplate ({{RFC2119}} {{RFC8174}}).
- **Terminology subsection** — lift and tighten from EVC v1: *host*, *verifier*,
  *bundle* (opaque), *verdict*, *request*, *decision*, *proof-system class*
  (`classical` | `zk` | `external`), *host nonce mode* vs. *local nonce mode*,
  *reserve-before-act*, *Host-Under-Test (HUT)*.

---

## 3. Architecture and Trust Model (to write)

- The four-step boundary (EVC v1 §10): spawn → write request → read one verdict →
  decide fail-closed. Include the language-neutral pseudocode (EVC v1 §10) as a
  figure.
- **Trust boundaries.** Host trusts: (a) the *verifier command it configured*
  (which binary/argv it spawned) and (b) the *trust configuration it supplied*
  (trusted roots, capability map, signer list). The host does **not** trust the
  bundle, and MUST NOT infer trust from any self-reported field (notably `kind`,
  §5). The verifier trusts its configured roots; "no roots configured" is never
  "all roots trusted" (EVC v1 §12 — fail closed).
- **Time source.** The host owns the clock: `now_unix` is host-supplied and the
  verifier evaluates expiry against it, not its own clock (EVC v1 §2.1). State
  this as an explicit trust-model property.

---

## 4. Request and Verdict Envelopes (to write — largely transcription)

### 4.1 Host → verifier request (stdin)
- Exactly one UTF-8 JSON object, then EOF (EVC v1 §2). Field table:
  `version` (MUST be `1`), `bundle` (opaque, non-empty, host MUST NOT inspect),
  `request{agent_name, project_key, program, model, granted_capabilities}`,
  `now_unix`. Include the request JSON Schema (EVC v1 §2.2) verbatim as an appendix
  reference (§A).
- Call out the **byte-literal `project_key`** rule (no path canonicalization) — a
  subtle interop hazard worth a sentence.

### 4.2 Verifier → host verdict (stdout)
- Exactly one JSON object, nothing else (EVC v1 §3, §5). Three shapes: `allow`,
  `allow` + `consume_nonces[]`, `deny{code,message,detail?}`. Include the **closed**
  verdict JSON Schema (`additionalProperties:false`) (EVC v1 §3.4) as appendix §A.
- **Denial-code registry** (EVC v1 §9) — reproduce the 15-code table. Flag that this
  table is the candidate IANA registry (see §13).

### 4.3 stdout/stderr fd-level isolation (load-bearing)
- Summarize EVC v1 §5: stdout carries exactly one verdict; native library writes
  (snarkjs/WASM/native) can hit fd 1 directly, so a `console.log` monkeypatch is
  insufficient. Reference mechanism: worker process + private verdict channel
  (fd 3), or `dup2` redirect. If the private channel can't be established → fail
  closed. This is the single most fragile implementation point; keep it normative.

---

## 5. Proof-System Classes and the `kind` Self-Description (to write — DIFFERENTIATOR)

- **This is the section that carries Bolyra's standards differentiation.** The
  contract is proof-system-agnostic (EVC v1 §1, §3.5): the *same* wire envelope
  carries verdicts from classical-signature verifiers, zero-knowledge verifiers,
  and third-party verifiers.
- The OPTIONAL verdict field `kind ∈ {classical, zk, external}` lets a verifier
  self-describe its class. Absence MUST be read as `zk` (backward-compat with
  original v1). Reproduce the class table (EVC v1 §3.5).
- **Position selective-disclosure / ZK as a first-class-but-optional verifier class.**
  A `zk`-class verifier proves properties of a credential (scope, expiry,
  human-uniqueness nullifier, delegation narrowing) **without revealing identity or
  the underlying attributes** — the selective-disclosure capability that no
  signature-only contract can express. Make the normative point crisply: EVC does
  **not require** ZK, but it **reserves a first-class lane for it** via `kind=zk`,
  so a host that wants privacy-preserving verification and a host that wants a plain
  signature check speak the identical wire protocol and differ only in which
  verifier command they spawn.
- **Guardrails (MUST):** `kind` is *advisory provenance metadata, not an
  authorization input*. A host MUST NOT upgrade a `deny` to `allow`, relax any
  fail-closed obligation, or select trust on the basis of `kind`. Class is
  established from *configured verifier identity/policy*, never from the
  self-reported string. An unrecognized `kind` is a malformed verdict → fail closed.
- Relationship to the related APS draft (§12): draft-pidlisnyi-aps-02 does not
  define a ZK/selective-disclosure verifier class. EVC's `kind` lane is where
  privacy-preserving verification plugs into an otherwise-identical host contract,
  regardless of which framework produced the bundle.

---

## 6. Exit Codes, Timeouts, and Host Fail-Closed Obligations (to write)

- Exit `0` = a verdict was produced (allow or any policy/crypto deny). Exit
  non-zero = no trustworthy verdict; host MUST deny (EVC v1 §7.1).
- **Exit status dominates a stdout allow** (EVC v1 §16.4): a host MUST treat a
  non-zero exit as deny *even when a syntactically valid `allow` reached stdout*.
  Call this out explicitly — it is the one place implementers are tempted to trust
  stdout.
- Host owns the timeout (RECOMMENDED 10 000 ms; verifier targets <2 s p99),
  and the stdin bound (reference 1 MiB) (EVC v1 §6).
- Enumerate the fail-closed set (EVC v1 §7.2): non-zero exit, timeout, signal
  death, unparseable/empty/oversized/multi-object stdout, unknown `verdict`,
  schema failure (including unrecognized `kind`).

---

## 7. Replay Protection and Reserve-Before-Act (to write)

- Two modes (EVC v1 §8): **local** (verifier owns durable nonce store) and **host**
  (verifier returns `consume_nonces[]`, host owns durable storage).
- **Reserve-before-act** (EVC v1 §7.3): in host mode, the host MUST atomically
  reserve **every** `consume_nonces` entry with unique-insert semantics **before**
  performing the action; any conflict → reject as replay even though the verifier
  said allow. "Record after proceeding" is FORBIDDEN.
- Note the human-uniqueness nullifier as a second reserved entry for human-backed
  bundles (namespaced `human:<nullifierHash>`), and that delegation hops add no
  entry (bound to the agent session nonce). This ties the ZK-privacy story to the
  replay mechanism.

---

## 8. Host Conformance (to write — TESTABILITY as the selling point)

- The differentiator vs. a governance framework is that host obligations are
  **mechanically testable**. Describe the suite (EVC v1 §16): a runner spawns a
  **deliberately misbehaving verifier fixture** and asserts the host-under-test
  **fails closed**, with a finer-grained `failure_class` assertion for *why*.
- Reproduce the fixture inventory as a table (22 `host_behavior` vectors, confirmed
  in `spec/test-vectors.json`): positive controls, `unparseable_stdout`,
  `multiple_objects`, `schema_invalid` (full closed-schema coverage at every
  nesting level), `timeout`, `nonzero_exit`, `signal_death`, `oversize_stdout`,
  and the three reserve-before-act vectors.
- Describe the **HUT convention** (EVC v1 §16.2) so any host in any language is
  testable: env vars (`HUT_VERIFIER_CMD`, `HUT_TIMEOUT_MS`, `HUT_MAX_STDOUT_BYTES`,
  `HUT_NONCE_MODE`, `HUT_NONCE_STORE`, `HUT_ACTION_LOG`, `HUT_FIXTURE_PIDFILE`) and
  the closed decision envelope. Stress that this envelope is a **test convention,
  not part of the wire contract**.
- **Two independent reference hosts** (`spec/reference-host.js` +
  `spec/reference-host-rs/`) demonstrate portability — cite both. This is concrete
  interop evidence an IETF reader will weigh.
- Scope-and-limits paragraph (EVC v1 §16.5): the black-box suite proves the
  durable write, the gate on uniqueness, and reserve-all; it does **not** prove the
  intra-allow-path write-barrier ordering (crash-window). Be honest about this in
  the draft — it strengthens credibility.

---

## 9. Canonicalization and the Binding Signature (to write — reference, keep tight)

- The bundle carries a request-authorizing signature binding request context to
  the proven key (EVC v1 §4, **binding v2** as of 2026-07-17): canonical payload of
  **six** fields — `agent_name`, `project_key`, `program`, `model`, `capabilities`,
  and `expiry` (a positive integer, unix seconds, signature-bound as of binding v2) —
  sorted-key compact JSON, array order preserved; versioned domain-separation tag
  `bolyra.external-verifier.binding.v2` with `dsInput = DST || 0x00 || payload`;
  `digest = SHA-256(dsInput)` reduced mod BN254 field order; EdDSA-Poseidon over
  BabyJubjub. Version discrimination is structural (exact six-key set; a member
  outside the six-field set, or a non-integer/non-positive `expiry`, is rejected
  `invalid_bundle` before any version is inferred; an obsolete five-field v1 binding
  is rejected `unsupported_version`, fail-closed, no compat mode), and after the
  signature verifies the verifier requires `binding.expiry == credential.expiry`
  (else `invalid_bundle`). The expiry-binding rationale (a re-anchoring attack under
  v1) belongs in Security Considerations (§13).
- **Framing caution:** this section is *specific to Bolyra's `zk`/`classical`
  verifier* and is arguably below the interoperability boundary (a host never sees
  it). Decide before submit whether to (a) keep it as an **informative appendix**
  illustrating one verifier's internal binding, or (b) drop it entirely to keep the
  draft at the host↔verifier boundary. **Lean (a) — informative appendix §B.**

---

## 10. Wire Versioning (to write)

- Integer-major at the wire layer; embedded proofs keep semver (EVC v1 §11).
- Additive OPTIONAL fields with a defined default (the `kind` case) do not bump the
  wire major, with the stated caveat that the closed §3.4 schema means a
  *pre-revision* host rejects any verdict that actually carries `kind`. Transcribe
  the precise compatibility guarantee (omitted-`kind` interoperates both
  directions; emitted-`kind` needs a revision-aware host).

---

## 11. Relationship to Receipt Signer Discovery (to write — brief, cross-ref)

- Sibling spec `receipt-signer-discovery-v1.md`: a `.well-known/bolyra-signers.json`
  document (RFC 8615 well-known URI) lets a receipt verifier learn which ES256K
  signer address(es) to accept. Relevant to EVC because a `classical`-class verifier
  checking signed receipts consumes it.
- Pull three consumer rules into EVC's Security Considerations (§13) rather than
  restating the whole spec here: HTTPS-only, **MUST NOT follow redirects**
  (redirect → plaintext/attacker-origin downgrade), and fail-closed on any
  transport/schema failure (never "no signer restriction").

---

## 12. Relationship to Other Work (to write — POSITIONING)

### 12.1 draft-klrc-aiagent-auth-03 (complementary — cite, do not compete)
- Target the **current** revision, draft-klrc-aiagent-auth-03 (2026-07-06), not
  the -01 the earlier outreach referenced.
- The klrc draft addresses **agent authentication** (who is this agent, what
  Agent Identity Token does it carry, client-to-agent auth, delegation/impersonation
  informational). EVC addresses the **downstream decision boundary**: given a
  bundle (which MAY carry a klrc-style token inside its opaque `bundle`), how does a
  host obtain and enforce a fail-closed authorization verdict?
- Framing: **EVC is the verdict/enforcement companion to klrc's identity layer.**
  A klrc Agent Identity Token is one possible payload a `classical`-class verifier
  validates; a Bolyra ZK credential is what a `zk`-class verifier validates. The
  host contract is identical either way. Cite the -03 token-format and
  delegation/impersonation sections — **[TODO: re-read -03 and pin exact -03 section
  numbers before submit; the earlier §16 research task #17 is resolved by using -03].**

### 12.2 draft-pidlisnyi-aps-02 (related — Agent Passport System)
- APS (2026-07-04) is a broad governance framework: `did:aps` identity, a
  seven-dimensional authority-attenuation lattice, a three-signature policy chain
  (ActionIntent → PolicyDecision → PolicyReceipt), and Ed25519-signed receipts.
  Factual, citable point (verifiable against the -02 text): **draft-pidlisnyi-aps-02
  does not define a ZK/selective-disclosure verifier class** — its signed artifacts
  are EdDSA-signed and content-addressed. **[TODO: if the draft wants to characterize
  APS's disclosure model beyond "no ZK class," quote the exact -02 Security-
  Considerations sentence rather than paraphrasing.]**
- Positioning (neutral, technical): EVC and APS operate at **different altitudes**.
  APS is a full governance/passport/receipt framework; EVC is the narrow, testable
  host↔verifier decision boundary that any such framework needs at the point of
  enforcement. The complementary hook: an APS PolicyDecision engine could be wrapped
  as an `external`-class (or `classical`-class) EVC verifier; and, in the lane APS
  does not define, a **`zk`-class verifier adds selective disclosure** (prove
  authority without revealing the passport or the attributes). Do **not** disparage
  APS; state the altitude and the ZK-class gap factually.

---

## 13. Security Considerations (skeleton — expand each bullet to a paragraph)

- **Fail-closed is the whole safety property.** Every ambiguous outcome (non-zero
  exit, timeout, signal death, unparseable/oversized/multi-object stdout, schema
  failure, unrecognized `kind`) MUST deny. Reference the host-conformance suite
  (§8) as the mechanism that makes this claim *checkable* rather than asserted.
  State the §16.4 clarification: exit status dominates a stdout `allow`.
- **`kind` is unauthenticated self-report.** A host MUST establish proof-system
  class from configured verifier identity/policy, never from the `kind` string; and
  MUST NOT relax trust, verifier selection, schema validation, or nonce handling on
  its basis (EVC v1 §3.5). Threat: a hostile/buggy verifier claiming `kind=zk` to
  imply privacy guarantees it did not provide.
- **Nonce reservation / replay.** Reserve-before-act ordering (§7); "record after
  proceeding" is a replay window and FORBIDDEN. Reserve-**all** on multi-entry
  `consume_nonces` (agent + human nullifier). Local-mode store errors MUST fail
  closed. Note the black-box crash-window caveat (§8) as a residual property hosts
  SHOULD cover with an in-process test.
- **Redirect / downgrade in signer discovery.** From RSD v1: HTTPS-only, **no
  redirect following** (a redirect can move the fetch to plaintext or an
  attacker-chosen origin *after* the protocol check), fail-closed on any failure.
  Discovery is trust-in-origin, not endorsement, not PKI. When both `--signer` and
  `--signer-from` are supplied, a consumer MUST require agreement.
- **Tail truncation (hash-chained receipts) — informative note, not an EVC
  requirement.** For a hash-chained signed-receipt log a `zk`/`classical` verifier
  may consult, an attacker who can drop the newest entries mounts a **tail-truncation**
  attack (the chain still verifies as a valid prefix). This is a real property, but
  it sits **below the EVC host↔verifier boundary** (receipt-chain semantics live in
  `@bolyra/receipts`, not in EVC v1 or RSD v1), so the draft MUST NOT state a new
  normative EVC obligation here — doing so would violate the "no requirements absent
  from the shipped specs" rule at the head of this outline. Two acceptable
  treatments, pick one before submit: **(a)** phrase it informatively — a verifier
  that relies on receipt ordering *should* anchor the expected chain tip (signed
  high-water mark or monotonic counter) out of band, and treat a shorter-than-expected
  chain as a verification failure, framed as guidance a verifier vendor MAY adopt,
  not an EVC MUST; or **(b)** move the normative mitigation into a dedicated
  receipts/RSD companion draft where a MUST can be properly grounded, and reference
  it from here. Marked **[NEW — draft-only; not in shipped EVC v1 / RSD v1]**.
  **[TODO: cross-check `@bolyra/receipts` chain semantics before wording either way.]**
- **Output-bound truncation / resource exhaustion.** The stdout output bound and
  stdin bound (EVC v1 §6) bound a hostile verifier that floods or hangs; the host
  MUST enforce both and kill on breach (the `oversize-flood` / hang fixtures prove
  it). A truncated stdout is unparseable → deny, never a partial allow.
- **Domain separation.** The binding DST prevents a binding signature from being
  replayed as any other Bolyra signature and vice-versa (EVC v1 §4.2, versioned
  `.v2` as of binding v2) — include if §9/appendix §B is retained.
- **Binding of credential expiry (binding v2, 2026-07-17).** Under binding v1
  `expiry` was not signature-bound; a `classical`/`external`-class verifier that does
  not independently bind expiry could be handed a binding whose signed fields matched
  an issued mandate with a later `expiry` substituted from outside the signature,
  re-anchoring a longer lifetime onto the mandate and obtaining an `allow` past its
  intended expiry. The escalation is bounded — duration extension at the
  already-granted tier/audience only, no tier/audience/payee escalation — and a
  `zk`-class verifier that binds expiry in-circuit was not exposed. Binding v2 signs
  `expiry`, versions the DST to `.v2`, requires `binding.expiry == credential.expiry`
  after signature verification (a mismatch rejected `invalid_bundle`), and rejects a
  five-field v1 binding `unsupported_version` (fail-closed, no compat mode). State
  neutrally; below the EVC
  wire boundary, mirror the lowercase-`must` convention of appendix §B — no new host
  MUST. Cite EVC v1 §4.1/§15.
- **Privacy considerations (its own subsection).** A `zk`-class verifier lets the
  host authorize without learning the agent's identity or attribute values; the
  request context the host *does* supply (`agent_name`, `project_key`, `program`,
  `model`, `granted_capabilities`) is host-chosen and MAY itself be identifying — call out
  that EVC bounds what the *verifier* learns, not what the *host* already knows.

---

## 14. IANA Considerations (skeleton) [NEW — draft-only, not in shipped EVC v1]

- **Candidate registry: "External Verifier Denial Codes".** The 15-code
  `snake_case` vocabulary (EVC v1 §9) is a natural IANA registry so codes are
  catalogued centrally and future revisions do not collide. Proposed shape:
  - Registry name: *External Verifier Denial Codes*.
  - Registration policy: **Specification Required** (RFC 8126).
  - **Critical clarification (reconciles with EVC v1's CLOSED enum).** The wire
    denial-code set is a **closed enum** on the wire: a verifier MUST NOT add,
    remove, or rename a code without a version bump, and that change is a
    **wire-major revision** (EVC v1 §9 and §11, lines 248 & 533 of
    `external-verifier-contract-v1.md`). The IANA registry does **not** relax this
    and does **not** open the enum at runtime. It is a **catalog of the codes each
    spec version defines**: a new registration is admissible only as part of a
    published EVC wire-major/spec revision that adds the code, and each registry
    entry records the wire version that introduced it. A verifier that emits an
    unregistered code is non-conformant exactly as under EVC v1 today; the registry
    changes discoverability, not the closed-set semantics or the version-bump rule.
    Third-party (`external`-class) verifiers reuse the existing vocabulary (EVC v1
    §9) — they do not mint private codes at runtime.
  - Initial contents: the 15 EVC v1 §9 codes, each with Meaning + the wire version
    (`1`) that introduced it + reference.
  - Columns: `code` | brief description | wire version introduced | change controller | reference.
- **Candidate registry: "External Verifier Proof-System Classes".** The
  `kind` value set `{classical, zk, external}` (EVC v1 §3.5). Likely **too small /
  closed** to warrant a registry; a fixed enum in the spec may be better. **[decide:
  registry vs. closed enum — lean closed enum, note the tradeoff.]**
- **Well-known URI (defer).** RSD v1's `bolyra-signers.json` would need an RFC 8615
  well-known-URI registration, but that belongs to a *separate* RSD draft, not this
  one. Note as out-of-scope for `-00`.
- **Media type (defer/consider).** `application/vnd.bolyra.proof+json` exists for
  the proof envelope but is below the EVC boundary (bundle is opaque); EVC itself
  defines no new media type. State "no media-type registration requested."
- **Open question to resolve before submit:** does the wire request/verdict get a
  registered structured-suffix or stay an unregistered JSON object? Lean: no
  registration for `-00` (the objects are transported over a subprocess pipe, not a
  network media type). **[confirm]**

---

## 15. Appendices (plan)

- **Appendix A — JSON Schemas (normative).** Request schema (EVC v1 §2.2) + closed
  verdict schema (EVC v1 §3.4), verbatim.
- **Appendix B — Binding signature (informative).** Canonicalization + DST + digest
  reduction + EdDSA-Poseidon (EVC v1 §4), framed as *one verifier's internal binding*,
  explicitly below the interop boundary. (Keep only if §9 decision = "informative".)
- **Appendix C — Worked examples (informative).** The 8 request/verdict pairs from
  EVC v1 §13 (allow, allow+consume_nonces, the denies, classical-kind allow,
  external-kind deny). Excellent for implementers; low authoring cost (already written).
- **Appendix D — Host-conformance fixture list (informative).** The 22-vector table
  (EVC v1 §16.1) + HUT env-var table, as an implementer aid.

---

## 16. Section-by-section TODO for the `-00` submission

> Sized for a first individual submission. "Transcribe" = adapt shipped spec prose
> to I-D voice (low effort). "Write" = net-new drafting. "Decide" = a scoping call
> to lock before writing. Order roughly by dependency.

| # | Task | Type | Effort | Blocking decision? |
|---|------|------|--------|--------------------|
| 1 | Lock **category** (Informational for -00) and confirm no WG target yet | Decide | XS | yes — sets tone |
| 2 | Lock **scope line**: host↔verifier boundary only; excludes governance/policy/issuance | Decide | XS | yes — the thesis |
| 3 | Decide §9 binding-signature = **informative Appendix B** (not main-body normative) | Decide | XS | yes — affects §9/§13/§B |
| 4 | Decide `kind` = **closed enum in spec**, not IANA registry | Decide | XS | yes — affects §14 |
| 5 | Front matter + references block (incl. I-D.klrc, I-D.pidlisnyi cross-refs) | Write | S | — |
| 6 | Abstract + §1 Introduction (problem, scope, exclusions, #183 validation, two hosts) | Write | M | needs 1,2 |
| 7 | §2 Conventions + Terminology (BCP 14 boilerplate + term list) | Transcribe | S | — |
| 8 | §3 Architecture & trust model (4-step + pseudocode figure + clock ownership) | Transcribe | S | — |
| 9 | §4 Request/verdict envelopes + denial-code table + fd-isolation | Transcribe | M | — |
| 10 | §5 Proof-system classes & `kind` — **the differentiator section** | Write | M | needs 4 |
| 11 | §6 Exit codes / timeouts / fail-closed set (incl. §16.4 exit-dominates-allow) | Transcribe | S | — |
| 12 | §7 Replay modes + reserve-before-act (+ human-nullifier, delegation note) | Transcribe | S | — |
| 13 | §8 Host conformance (suite, HUT convention, 22-vector table, two ref hosts) | Write | M | — |
| 14 | §10 Wire versioning (integer-major + additive-optional caveat) | Transcribe | S | — |
| 15 | §11 RSD relationship (brief cross-ref, pull 3 rules into §13) | Write | S | — |
| 16 | §12 Relationship to klrc-**03** (complementary) + APS (altitude + ZK-class gap, factual) | Write | M | needs live re-read of klrc-03 |
| 17 | §12.1 — re-read **draft-klrc-aiagent-auth-03** (2026-07-06) live, pin exact -03 section numbers | Research | S | blocks 16 (target rev is -03, not -01) |
| 18 | §13 Security Considerations — expand bullets to paragraphs (tail-truncation stays **informative**, see task 19) | Write | L | needs 3,10,12,15 |
| 19 | §13 tail-truncation — decide **(a)** informative note vs **(b)** move MUST to receipts/RSD companion draft; cross-check `@bolyra/receipts` chain semantics. NOT an EVC MUST | Decide+Research | S | blocks 18 |
| 20 | §14 IANA — denial-code **catalog** registry (Spec Required; registry does NOT open the closed enum at runtime — additions are wire-major revisions) + defers | Write | M | needs 4 |
| 21 | Appendices A (schemas), C (examples), D (fixtures) — assemble from shipped spec | Transcribe | S | — |
| 22 | Appendix B (binding sig, informative) — only if task 3 = "informative" | Transcribe | S | needs 3 |
| 23 | Full RFC 2119/8174 keyword audit — every MUST/SHOULD traces to EVC v1 | Review | S | after body done |
| 24 | Idnits / kramdown-rfc build; fix nits; confirm datatracker-ready | Review | S | last |
| 25 | Route full draft through Codex review before any submission | Review | S | last (per workspace policy) |

**Critical path:** 1→2→3→4 (decisions) → 6/10 (thesis + differentiator) → 16/17 (positioning, needs live draft re-read) → 18/19 (security, needs receipts cross-check) → 23→24→25.

**Explicitly deferred past `-00`:** RSD as its own draft (well-known URI registration), media-type registration, standards-track upgrade, any WG-adoption request.
