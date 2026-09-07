Base-Commit: 9bf754441ab36ab93992ed5936d34c44a4128f92
Target-File: spec/external-verifier-contract-v1.md
Finding: competing-spec-author-detail-object-unbounded-and-secret-unconstrained

```diff
--- a/spec/external-verifier-contract-v1.md
+++ b/spec/external-verifier-contract-v1.md
@@ §3.3 Deny — field list @@
 - `message` (string, **REQUIRED** on deny) — a one-line, human-actionable
   reason. It **MUST NOT** contain secrets.
 - `detail` (object, **OPTIONAL**) — structured context for logs/debugging. A
   verifier **SHOULD** echo the originating internal error code here (e.g.
   `sdk_code`) so the coarse wire `code` stays stable while logs stay precise.
+  `detail` is **host-log material, not an authorization input**, and is bound
+  by the same secrecy rule as `message`: it **MUST NOT** contain secrets. In
+  particular it **MUST NOT** contain the `bundle` (in whole or in part), a
+  proof, a binding signature or any of its components (`R8`, `S`), or any
+  operator, signing, or credential key material — a deny does **not** consume
+  the presentation's nonce (§8), so a bundle echoed into `detail` is a live
+  bearer credential written into the host's logs. A verifier **SHOULD** keep
+  `detail` a flat object of short scalar values (the reference implementation
+  emits a few hundred bytes at most) and **SHOULD** prefer stable codes,
+  field *names*, and verifier-derived values (e.g. a scope bit-mask) over
+  echoed inputs. A host **MAY** truncate, redact, or drop `detail` entirely
+  without affecting the decision, and **MUST NOT** feed `detail` back into
+  any authorization input (§7.4).
 - `kind` (string, **OPTIONAL**) — the verifier's proof-system **self-description**,
   one of `classical`, `zk`, or `external` (§3.5). It **MAY** appear on either an
   `allow` or a `deny` verdict. When it is **absent**, the host **MUST** interpret
@@ §5.3 stderr @@
 All diagnostics, timing, and debug logging **MUST** go to stderr, and **SHOULD**
 be gated behind a verbose flag (`--verbose` / `BOLYRA_VERBOSE` in the reference
 implementation). The default is silent on success and a one-line reason on deny
-(also present structured in the stdout `message`/`detail`). Hosts **MUST NOT**
-parse stderr for the verdict.
+(also present structured in the stdout `message`/`detail`). The stdout
+`message` and `detail` fields **MUST NOT** contain secrets (§3.3); stderr is
+the only channel on which a verifier **MAY** emit richer diagnostics, and only
+behind the verbose gate. Hosts **MUST NOT** parse stderr for the verdict.
@@ §7.3 Reserve-before-act — end of section @@
 "Record after proceeding" is a replay window and is **FORBIDDEN**. The verifier's
 `allow` in host mode is **conditional** on every host insert being novel.
 
+### 7.4 Deny `message` / `detail` are log material, not authorization inputs
+
+On a `deny`, the fields `message` and `detail` (§3.3) exist so that a host can
+log *why* it fail-closed and so that an operator can act on the reason. They
+carry **no authorization semantics**. A host:
+
+- **MUST NOT** use any value found in `message` or `detail` as an input to a
+  subsequent authorization decision — it **MUST NOT** derive a retried
+  request, a widened `granted_capabilities` set, a trust-configuration change,
+  or a nonce-store insert or removal from them. The only fields with
+  enforcement meaning are `verdict`, `code`, and (in host nonce mode)
+  `consume_nonces` (§3.5).
+- **MAY** truncate, redact, or drop `detail` (and **MAY** truncate `message`)
+  before persisting the verdict. Doing so **MUST NOT** change the decision:
+  a `deny` with its `detail` dropped is still the same `deny`.
+- **SHOULD** treat persisted `detail` as sensitive. The verifier is required
+  by §3.3 to keep secrets out of it, but the value is **self-reported by the
+  verifier and is not authenticated**; a host cannot verify from the wire that
+  a `detail` object is secret-free. The §7.2 stdout output bound protects the
+  single-object framing (§5.2) — it is **not** a secret-containment bound, and
+  a `detail` object well under that bound can still carry a complete bundle.
+
+This mirrors the rule already stated for `kind` (§3.5): everything on the
+verdict other than `verdict`, `code`, and `consume_nonces` is advisory
+metadata for logging, never a lever a verifier can use to steer the host.
+
 ## 8. Replay protection modes
```

## Rationale

**What the pinned text permits.** §3.3 constrains `message` — "It **MUST NOT** contain secrets" — and in the very next bullet defines `detail` as "structured context for logs/debugging" that the verifier "**SHOULD** echo the originating internal error code" into, with no secrecy, size, or content rule at all. §3.4 mirrors this: `"detail": { "type": "object" }` with no `properties`, `additionalProperties`, or `maxProperties`. §7.2 lists "oversized … stdout" only as a framing condition alongside "unparseable, empty, … multi-object stdout (§5.2)". Nothing in the contract ties the output bound to secret containment, and nothing tells a host what it may or may not do with `detail` once it has it.

**The concrete divergence.** A verifier vendor can, without violating a single normative statement, echo the raw `bundle` into `detail` on every deny (a natural thing to do when "debugging context" is the stated purpose). Because §8 burns the presentation's nonce only "on an otherwise-allow", a `scope_exceeded` or `unknown_capability` deny leaves the bundle unconsumed and still valid until `expiry`. A host that persists verdicts verbatim — which is exactly what the field is designed for — now has a live bearer credential in its audit log, readable by everyone with log access (SIEM operators, third-party auditors, log-aggregation vendors). In the `classical`/`external` classes the bundle plus its binding signature (§4) is the entire mandate. The record-oriented competitors named in the finding avoid this class of leak by construction, because they specify the decision record as a third-party-readable object and therefore constrain its contents; EVC specified `detail` as the log channel and forgot the constraint.

**The second divergence.** The contract also never says a host may not *act on* `detail`. §3.5 is careful to say `kind` "is **advisory metadata about provenance**, not an authorization input" and that a host "**MUST NOT** upgrade a `deny` to an `allow`, or relax any §7 fail-closed obligation" on its basis. No equivalent sentence exists for `message`/`detail`. A host that auto-retries with `granted_capabilities` narrowed to whatever `detail.required_scope` suggests, or that seeds or purges its nonce store from a `detail.nonce` on `nonce_replayed`, is letting an unauthenticated verifier-controlled object steer its authorization inputs. New §7.4 closes that in the same shape as the existing `kind` rule.

**Why this wording.** The diff extends the *existing* secrecy sentence rather than inventing a new vocabulary, so `message` and `detail` are now governed by one rule with one reading. It names the specific artifacts that matter (`bundle`, proof, binding signature `R8`/`S`, key material) because "secrets" alone is what left `detail` open — a vendor reasonably reads a signature as public data, and the sentence about deny not consuming the nonce explains *why* it is not. §7.4 gives the host the reciprocal obligations and explicitly decouples the §7.2 output bound from secret containment, which is the mis-reading the finding identified. It also states the "self-reported, not authenticated" caveat verbatim from §3.5 so hosts do not treat the new verifier MUST NOT as something they can rely on for their own log-handling policy.

**RFC 2119 choices.**
- `detail` **MUST NOT** contain secrets: identical strength to the existing `message` rule; a weaker keyword would create exactly the asymmetry being closed.
- Verifier **SHOULD** keep `detail` small / **SHOULD** prefer derived values: size is not objectively testable at the wire level (the schema keeps `detail` an open object, §3.4) and a legitimate `internal_error` may need a longer diagnostic, so this is guidance, not a conformance gate.
- Host **MAY** truncate/redact/drop: this is a host-discretion statement whose purpose is to make explicit that doing so is *permitted* and non-decision-affecting; a MUST would force redaction policy the contract has no business dictating.
- Host **MUST NOT** feed `detail` into authorization inputs: same strength as the parallel `kind` rule in §3.5; this is the fail-closed boundary and is not discretionary.
- Host **SHOULD** treat persisted `detail` as sensitive: the host cannot verify secret-freedom from the wire, so this is a defense-in-depth recommendation rather than a testable MUST.

## Impact

**Published conformance vectors.** None of the 28 published host-behavior vectors change. Every added statement is prose; the §3.4 verdict schema is untouched (`detail` remains `{ "type": "object" }`), so no golden verdict, fixture, or expected host classification moves. No vector artifact must accompany this diff. A follow-on *verifier-side* vector ("deny `detail` must not contain the request `bundle`") is a legitimate `vector_gap` for a later iteration but is not required to land this change.

**Wire compatibility.** No change to the request or verdict envelope, the denial-code registry (§9), or the binding format (§4). Wire major stays `1`; binding stays v2. A pre-revision verifier that emits a secret-free `detail` is already conforming; a pre-revision host that ignores `detail` is already conforming. Only a verifier that was echoing bundle/proof/signature/key material into `detail` becomes non-conforming, which is the intended effect. This is the same "prose only, wire contract unchanged" class as the 2026-08-26 revision and warrants a document-revision line in the §15 changelog, which is outside the pinned excerpt and is left to the apply stage.

**-02 relevance.** The draft's Security Considerations should carry the substance of §7.4 (deny reason fields are unauthenticated log material; the output bound is a framing bound, not a secrecy bound; deny does not consume the nonce, so an echoed bundle is a live credential). The -02 text is not pinned in this artifact; mirroring it there is a companion edit, not part of this diff. The change strengthens the RFC 7942-facing position by giving hosts a normative basis for redacting persisted verdicts, which is a question skeptical implementers raise when comparing EVC to signed-receipt designs.
