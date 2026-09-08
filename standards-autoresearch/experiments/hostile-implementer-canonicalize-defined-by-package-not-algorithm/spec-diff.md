Base-Commit: 9bf754441ab36ab93992ed5936d34c44a4128f92
Target-File: spec/external-verifier-contract-v1.md
Finding: hostile-implementer-canonicalize-defined-by-package-not-algorithm

```diff
--- a/spec/external-verifier-contract-v1.md
+++ b/spec/external-verifier-contract-v1.md
@@ -3,9 +3,11 @@
 - **Status:** Stable (v1)
 - **Wire version:** `1` (integer-major; see §11)
-- **Document revision:** 2026-08-26 (registry closure and fail-closed
-  classification precedence made explicit — prose only, wire contract unchanged;
-  see the changelog in §15). Previous: 2026-07-17 (binding format **v2** —
+- **Document revision:** 2026-09-07 (§4.1 canonicalization stated inline as an
+  explicit byte-level algorithm, with a worked example and a golden vector,
+  §4.5 — prose only, wire contract and binding bytes unchanged; see the
+  changelog in §15). Previous: 2026-08-26 (registry closure and fail-closed
+  classification precedence made explicit), 2026-07-17 (binding format **v2** —
   expiry is now signature-bound), 2026-07-11 (§16 Host conformance). The wire
   request/verdict envelope major is unchanged; the **binding** sub-structure is
   versioned separately (v1 → v2, §4).
@@ -419,12 +421,111 @@
 payload = canonicalize(binding)
 ```
 
-where `canonicalize` is the sorted-key, compact (no insignificant whitespace)
-JSON serialization defined by `@bolyra/receipts` (`canonicalize`). Object keys
-**MUST** be sorted; array elements (including `capabilities`) **MUST NOT** be
-reordered. Signer and verifier therefore **MUST** agree on the array order: the
-verifier compares `capabilities` as a set for authorization, but the *signed
-bytes* are order-sensitive.
+where `canonicalize` is the deterministic serialization specified in full in
+§4.1.1. It is stated inline so that a signer or verifier built from this
+document alone — without `@bolyra/receipts` or any other Bolyra code — produces
+the same bytes; `@bolyra/receipts` (`canonicalize`) is the *reference
+implementation* of §4.1.1, not its definition. Object keys **MUST** be ordered
+as §4.1.1 specifies; array elements (including `capabilities`) **MUST NOT** be
+reordered. Signer and verifier therefore **MUST** agree on the array order: the
+verifier compares `capabilities` as a set for authorization, but the *signed
+bytes* are order-sensitive.
+
+#### 4.1.1 Canonical serialization algorithm
+
+The canonical payload is the UTF-8 encoding of the JSON text produced by the
+following rules. They are the rules of the JSON Canonicalization Scheme
+[RFC 8785], restricted to the value types a binding can contain, and are
+restated here so that no normative dependency on that document or on any
+implementation is required. A producer **MUST** apply every rule; a verifier
+**MUST** recompute the payload by these rules from the bundle's own `binding`
+and **MUST NOT** accept a self-asserted payload, digest, or `msgField`.
+
+1. **Whitespace and framing.** The text contains no whitespace outside string
+   values, no byte-order mark, and no trailing newline or other trailing bytes.
+2. **Member order.** Object members are emitted in ascending order of member
+   name, where names are compared as sequences of UTF-16 code units (the
+   comparison ECMAScript `Array.prototype.sort` applies to strings by default;
+   [RFC 8785] §3.2.3). Ordering by Unicode code point or by UTF-8 byte is
+   **NOT** conforming, even though the three orders coincide for ASCII names.
+   For the six binding-v2 members the resulting order is fixed and **MUST** be
+   exactly: `agent_name`, `capabilities`, `expiry`, `model`, `program`,
+   `project_key`.
+3. **Arrays.** Elements are emitted in the order given. They **MUST NOT** be
+   sorted, deduplicated, or otherwise reordered.
+4. **Strings.** Every string value and member name **MUST** be a sequence of
+   Unicode scalar values; a binding containing an unpaired surrogate **MUST** be
+   rejected `deny code=invalid_bundle`. A string is emitted as `"`, its escaped
+   content, `"`, where the escaped content is formed by replacing, and only
+   replacing:
+   - `"` (U+0022) with `\"`;
+   - `\` (U+005C) with `\\`;
+   - U+0008, U+0009, U+000A, U+000C, U+000D with `\b`, `\t`, `\n`, `\f`, `\r`
+     respectively;
+   - every other code point in the range U+0000–U+001F with `\u` followed by
+     four **lowercase** hexadecimal digits (e.g. U+001F → `\u001f`).
+
+   Every other code point — including `/`, `<`, `>`, `&`, U+007F, U+2028,
+   U+2029, and all code points above U+007F — **MUST** be emitted literally as
+   its UTF-8 encoding and **MUST NOT** be written as a `\uXXXX` escape.
+5. **`expiry`.** The only numeric member. Its value **MUST** be an integer in
+   the range 1 to 2⁵³−1 inclusive, emitted as its shortest decimal
+   representation: ASCII digits only, no sign, no leading zeros, no fractional
+   part, no exponent (e.g. `4102444800`, never `4102444800.0` or `4.1024448e9`).
+   A value that is not an integer, is not positive, or exceeds 2⁵³−1 **MUST**
+   be rejected `deny code=invalid_bundle` (this restates and bounds the
+   non-integer/non-positive rule above; the upper bound keeps the rendering
+   identical across IEEE 754 and arbitrary-precision runtimes).
+6. **Value types.** Each of `agent_name`, `project_key`, `program`, and `model`
+   **MUST** be a string; `capabilities` **MUST** be an array whose every
+   element is a string; `expiry` **MUST** be a number per rule 5. A binding
+   carrying `null`, a boolean, a nested object, or a non-string array element
+   in any member **MUST** be rejected `deny code=invalid_bundle`.
+
+A serializer that escapes non-ASCII characters as `\uXXXX` (for example
+Python's `json.dumps` with its default `ensure_ascii=True`), escapes `/`, sorts
+names by code point or by UTF-8 byte, or renders `expiry` with a fraction or
+exponent produces different bytes, a different SHA-256 digest, and therefore a
+different `msgField`; its signatures fail on a conforming verifier
+(`deny code=invalid_signature`) and it wrongly rejects conforming bundles. Such
+a serializer is not conforming even though its output is "sorted, compact
+JSON".
+
+#### 4.1.2 Worked example
+
+For the binding
+
+```json
+{
+  "agent_name": "research-bot",
+  "project_key": "/work/acmé",
+  "program": "crewai",
+  "model": "opus-4.1",
+  "capabilities": ["fetch_inbox", "send/message"],
+  "expiry": 4102444800
+}
+```
+
+the canonical payload text is the single line
+
+```
+{"agent_name":"research-bot","capabilities":["fetch_inbox","send/message"],"expiry":4102444800,"model":"opus-4.1","program":"crewai","project_key":"/work/acmé"}
+```
+
+and `payload` is its UTF-8 encoding: every byte is ASCII except `é`, which is
+the two bytes `c3 a9`, so the payload ends with the bytes
+`2f 77 6f 72 6b 2f 61 63 6d c3 a9 22 7d` (`/work/acmé"}`). The `/` characters
+are unescaped. A serializer emitting `\u00e9` (bytes `5c 75 30 30 65 39`) in
+place of `c3 a9`, or `\/` in place of `/`, has produced a non-conforming
+payload. The complete `payload` hex, the SHA-256 digest of `dsInput` (§4.2,
+§4.3), and the reduced `msgField` for this exact binding are published as the
+canonicalization golden vector (§4.5).
 
 `expiry` is part of the signed binding as of **binding v2** (this revision).
 A verifier **MUST** reject a binding that omits `expiry` with
@@ -467,6 +568,29 @@
   a signing key disjoint from the credential **MUST** be rejected
   (`deny code=invalid_signature`). This closes the cross-signer replay class.
 
+### 4.5 Canonicalization golden vector
+
+Because the signed bytes are order-, escape-, and number-format-sensitive, an
+implementer in any language **MUST** be able to check its `canonicalize` and
+digest pipeline without executing Bolyra code. The repository publishes a
+**canonicalization golden vector** at
+`spec/fixtures/binding-canonical/binding-v2-canonical-golden.json`, generated
+by the reference implementation from the §4.1.2 binding, carrying:
+
+- `binding` — the input object exactly as in §4.1.2;
+- `payload` — the canonical payload as a JSON string;
+- `payload_hex` — the UTF-8 bytes of `payload`, lowercase hex;
+- `ds_input_sha256_hex` — `SHA-256(DST || 0x00 || payload)` (§4.2, §4.3);
+- `msg_field` — the reduced `msgField` (§4.3) as a decimal string.
+
+A conforming producer or verifier **MUST** reproduce `payload_hex`
+byte-for-byte and `msg_field` exactly for this input. This vector exercises a
+non-ASCII `project_key`, a `/`-bearing capability, and an integer `expiry`; a
+pass demonstrates that rules 2, 4, and 5 of §4.1.1 are implemented. It is a
+**serialization** vector, distinct from the host-behavior conformance vectors
+described in `spec/CONFORMANCE.md`, and does not exercise the request/verdict
+envelope.
+
 ## 5. stdout / stderr / fd-level isolation (load-bearing)
 
 The whole contract depends on stdout carrying **exactly one** JSON object and
```

## Rationale

**The divergence the pinned text permits.** §4 states that "Any implementer that produces or verifies a bundle **MUST** reproduce these exact bytes," but §4.1 defines those bytes only as "the sorted-key, compact (no insignificant whitespace) JSON serialization defined by `@bolyra/receipts` (`canonicalize`)." The normative definition of the signed bytes therefore lives in an npm package, not in the contract, which contradicts §1's promise that "a host in any ecosystem MAY implement or consume the contract without depending on Bolyra internals" and §3.5's `external` class, which implements the contract "with its own proof system." An implementer working from the text alone has three underdetermined choices, each of which changes `SHA-256(dsInput)` and hence `msgField`:

- **String escaping.** "Compact JSON" does not say whether non-ASCII is emitted raw or as `\uXXXX`, nor whether `/` is escaped. The finding's runnable divergence is real on its face: a default-configured Python serializer emits `\u00e9` where a default ECMAScript serializer emits the raw UTF-8 `é`. Both are "sorted, compact JSON"; they sign different bytes.
- **Key collation.** "Object keys **MUST** be sorted" does not name the collation. UTF-16 code-unit order, code-point order, and UTF-8 byte order agree on ASCII but diverge once a name contains a supplementary-plane character or a code point in U+E000–U+FFFF. The six v2 names are ASCII, so nothing breaks today, but the rule as written is not future-proof and gives an implementer no way to know which order the reference uses.
- **Number rendering.** `expiry` is "a positive integer, unix seconds," but nothing forbids a float-typed serializer from emitting `4102444800.0` or an exponent form.

Nothing in the shipped conformance surface catches any of these: per the vector index supplied with the finding, every published vector is `host_behavior`, so a signer or verifier with a divergent `canonicalize` passes the suite and then fails (or wrongly accepts) in the field with `deny code=invalid_signature`. The failure is silent at conformance time and only appears as interop breakage between two independently "conforming" parties.

**Why this wording closes it.** §4.1.1 replaces the by-reference definition with the complete rule set: framing (no BOM, no trailing bytes), member collation named explicitly as UTF-16 code units with the fixed six-name order spelled out, array order preserved, the exact escape table with minimal escaping and lowercase hex, and integer-only rendering of `expiry` with an explicit range. These are the JCS rules of RFC 8785 restricted to the types a binding can hold, and they are also the rules ECMAScript `JSON.stringify` applies to an object whose members have been pre-sorted with the default string comparison, which is the natural implementation of a "sorted, compact" serializer in the reference language. The demoted sentence keeps `@bolyra/receipts` as the *reference implementation* so existing pointers stay meaningful while the *definition* moves into the contract. §4.1.2 gives a worked example that an implementer can compare by eye, including the two byte sequences that distinguish a conforming from a non-conforming serializer at the exact point where the finding's Python/Node divergence occurs. §4.5 adds a published golden (payload hex, digest, `msgField`) so the check is mechanical and language-independent.

**Behavior-preservation constraint (the judge's condition).** This diff is written so that the canonical bytes for every binding a conforming signer emits today are unchanged: it asserts the rules a default sorted-key `JSON.stringify` already follows. Whether the pinned `@bolyra/receipts` `canonicalize` is byte-identical to §4.1.1 for all six-field bindings requires maintainer verification against `integrations/receipts` (`canonicalize`): specifically that (a) keys are sorted with the default string comparison, (b) no additional escaping of `/`, U+2028/U+2029, or non-ASCII is applied, and (c) the serializer emits `expiry` through the runtime's integer rendering. If any of these differ, the spec text in this diff **must be revised to match the observed reference bytes**, not the other way round, because changing the bytes would invalidate signatures on bundles already issued under binding v2. The golden vector in §4.5 makes this verification objective: generating it from the reference implementation and checking it against a hand-derived §4.1.1 serialization of the §4.1.2 binding either confirms equivalence or exposes the exact divergence.

**RFC 2119 keyword choices.** Every serialization rule is **MUST** because the bytes are signature inputs; a **SHOULD** anywhere in the pipeline would re-open the divergence the finding describes. "**NOT** conforming" for the alternative collations and the `\uXXXX`/`\/` escapes is stated positively so a hostile or lazy implementer cannot read "sorted" as permitting a different sort. The three new rejections (unpaired surrogate, out-of-range `expiry`, wrong value type) are **MUST** reject `invalid_bundle` for consistency with the existing §4.1 rule that "a binding carrying a non-integer/non-positive `expiry`, or any field beyond the six, **MUST** be rejected `deny code=invalid_bundle`"; they are fail-closed tightenings on inputs no conforming signer produces. §4.5's reproduction requirement is **MUST** because a golden that an implementer may skip provides no interop assurance. The reference to RFC 8785 is deliberately informative (the rules are restated inline), because RFC 8785 is an Informational RFC and a normative dependency on it would be a downref for an eventual Standards-Track draft (see Impact).

## Impact

**Published conformance vectors.** No change to any published host-behavior vector. Per the vector index supplied with the finding, every vector in set 0.7.0 is `host_behavior` and none exercises the binding bytes; confirming that no fixture in `spec/fixtures/host-conformance/` embeds a binding whose canonical form would change requires maintainer verification against that directory. The vendored `@bolyra/evc-conformance` snapshot is unaffected unless the maintainer chooses to ship the new golden through it.

**Accompanying artifact (required).** This diff introduces a reference to a file that does not exist at the base commit and **must not** be staged without it: `spec/fixtures/binding-canonical/binding-v2-canonical-golden.json`, containing the five fields named in §4.5 for the exact §4.1.2 binding. The `payload_hex`, `ds_input_sha256_hex`, and `msg_field` values **must be generated by the reference implementation** at the base commit, not hand-authored; no digest is asserted in this artifact for that reason. If the generated `payload_hex` does not end in `2f 77 6f 72 6b 2f 61 63 6d c3 a9 22 7d` or does not begin with the ASCII bytes of `{"agent_name":"research-bot","capabilities":["fetch_inbox","send/message"],"expiry":4102444800,`, the reference `canonicalize` diverges from §4.1.1 and the diff must be revised to the reference behavior before staging (see Rationale). The path is a proposal; if the maintainer places the golden elsewhere, the two path references in §4.1.2 and §4.5 must be updated together. `spec/CONFORMANCE.md` should gain a one-line pointer distinguishing this serialization golden from the host-behavior vectors; that file is not quoted here and its edit requires maintainer verification.

**Wire compatibility.** Wire version `1` is unchanged. Binding v2 bytes are unchanged for every binding whose strings are well-formed Unicode and whose `expiry` is below 2⁵³, which covers every binding a conforming signer emits; the DST, digest, and `msgField` derivation in §4.2–§4.4 are untouched. The three new `invalid_bundle` rejections apply only to inputs (unpaired surrogates, `expiry` ≥ 2⁵³, non-string members) that no existing signer produces and that the current text already implicitly disallows via "a positive integer" and the six-field shape; they are prose tightenings in the fail-closed direction, not a binding-version bump. This revision is prose-only, matching the precedent of the 2026-08-26 revision line.

**Changelog and references.** §15 (changelog) and the references list are not quoted in this prompt; a §15 entry dated 2026-09-07 mirroring the new "Document revision" line, and a `[RFC 8785]` entry in the references list, should accompany this diff, and their exact placement requires maintainer verification against those sections. Hunk line offsets in the diff above were authored without tool access and are approximate; context lines are verbatim from the pinned file so the hunks apply on context.

**-02 relevance.** High. A specification that defines its signed bytes by reference to a package cannot survive IETF review: an implementer reading only the draft cannot produce a conforming signature, which is a "not implementable from the text" blocker regardless of stream. The -02 draft should carry §4.1.1 verbatim (or an equivalent self-contained restatement) rather than cite RFC 8785 normatively, because RFC 8785 is Informational and a normative reference from a Standards-Track document would require a downref call-out. §4.5's golden vector also supplies the first interop-evidence artifact that an independent implementation can pass **without** running any Bolyra code, which strengthens an RFC 7942 implementation-status section and directly addresses the `external`-class positioning in §3.5.
