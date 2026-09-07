Base-Commit: 9bf754441ab36ab93992ed5936d34c44a4128f92
Target-File: spec/external-verifier-contract-v1.md
Finding: hostile-implementer-stdout-framing-whitespace-newline-contradiction

```diff
--- a/spec/external-verifier-contract-v1.md
+++ b/spec/external-verifier-contract-v1.md
@@ -415,8 +415,12 @@
 ### 5.1 Verifier obligations
 
-- The verifier **MUST** write exactly one `JSON.stringify(verdict)` to the
-  host-facing stdout, at the very end. A single trailing newline is **OPTIONAL**.
+- The verifier **MUST** write exactly one `JSON.stringify(verdict)` to the
+  host-facing stdout, at the very end, framed exactly as §5.4 specifies: the
+  serialized object, then at most one line terminator (a single `LF` or a
+  single `CRLF` — the terminator itself is **OPTIONAL**), then nothing. The
+  verifier **MUST NOT** write a UTF-8 byte order mark, any byte (including
+  whitespace) before the object, a bare `CR`, or a second line terminator.
 - **No other code path may write to the host-facing stdout.** Proof-verification
   libraries (snarkjs / circomlibjs / WASM / native bindings) can write to file
   descriptor 1 directly — progress bars, warnings, debug spew — bypassing any
@@ -445,16 +449,23 @@
 ### 5.2 Host obligations (single-object parse)
 
-The host **MUST** parse the verifier's stdout as **exactly one** JSON object with
-**no trailing bytes**, and **MUST** reject (treat as deny, §7) any of:
+The host **MUST** parse the verifier's stdout as **exactly one** JSON object
+framed per the grammar in §5.4 — no bytes before the object, at most one line
+terminator after it — and **MUST** reject (treat as deny, §7) any of:
 
-- stdout that is empty, not valid JSON, or contains a leading/trailing prefix or
-  suffix around the object;
+- stdout that is empty, not valid JSON, or contains any byte before the object
+  or after its optional single line terminator (§5.4) — this includes leading
+  or trailing whitespace, a UTF-8 byte order mark, a bare `CR`, and a second
+  line terminator. A host **MUST NOT** strip leading or trailing whitespace (or
+  a byte order mark) before parsing; tolerance of that kind is exactly the
+  parser-defined behavior this section exists to remove;
 - **multiple** concatenated JSON values (a lenient parser that reads only the
   first object **MUST NOT** be used — two objects is a fail-closed condition);
 - a verdict whose `verdict` field is neither `"allow"` nor `"deny"`, or a `deny`
   missing `code`/`message`.
 
+A framing violation is a transport failure, not a verdict: the host classifies
+it `unparseable_stdout` (§16.3) and never relays it as a verifier `deny` code.
+
 ### 5.3 stderr
 
 All diagnostics, timing, and debug logging **MUST** go to stderr, and **SHOULD**
@@ -464,6 +475,51 @@
 (also present structured in the stdout `message`/`detail`). Hosts **MUST NOT**
 parse stderr for the verdict.
 
+### 5.4 stdout framing grammar (normative)
+
+The complete set of bytes a verifier writes to the host-facing stdout, and the
+complete set a host accepts, is (ABNF, [RFC 5234]):
+
+```
+verifier-stdout = verdict-object [ line-terminator ]
+line-terminator = LF / CRLF          ; at most one
+LF              = %x0A
+CRLF            = %x0D.0A
+verdict-object  = <one UTF-8 JSON object per RFC 8259 §4, with no byte order mark>
+```
+
+Rules:
+
+- The **only** bytes permitted outside `verdict-object` are the single optional
+  `line-terminator`. This is a deliberate **profile** of [RFC 8259]: §2 of that
+  RFC permits insignificant whitespace around a JSON text, and §8.1 permits a
+  parser to ignore a byte order mark; this contract grants **neither** latitude
+  at the stdout boundary. Whitespace *inside* `verdict-object` (between tokens)
+  remains governed by RFC 8259 and is accepted; `JSON.stringify` emits none.
+- `CRLF` is accepted so that verifiers whose platform text streams translate
+  `\n` to `\r\n` (Windows console and text-mode stdio) remain conforming. A bare
+  `CR` (`%x0D`) is **not** a line terminator under this grammar.
+- A host **MUST** check framing before validating the object against the §3.4
+  verdict schema. A framing violation is therefore classified
+  `unparseable_stdout`, never `schema_invalid` (§16.3), even when the bytes
+  between the illegal prefix/suffix would parse as a valid verdict.
+- The §6 stdout output bound and the §7.2 precedence (output bound, then
+  timeout, then signal death, then non-zero exit, then framing/parse, then
+  schema) are unchanged.
+
+Illustrative cases (`␣` = 0x20, `BOM` = `EF BB BF`, `{…}` = a valid verdict):
+
+| stdout bytes | Host outcome |
+|---|---|
+| `{…}` | accept — parse the verdict |
+| `{…}LF` · `{…}CRLF` | accept — parse the verdict |
+| `{…}LF LF` · `{…}CR` · `{…}CRLF LF` · `{…}␣` · `{…}LF␣` | deny, `unparseable_stdout` |
+| `LF{…}` · `␣{…}` · `BOM{…}` · `BOM{…}LF` | deny, `unparseable_stdout` |
+
+The host-behavior conformance vectors named in `spec/CONFORMANCE.md` under
+"stdout framing" exercise both directions of this grammar.
+
 ## 6. Timeout and input bounds
 
 - **Timeout.** The **host owns the timeout**. The verifier does not implement its
@@ -527,7 +583,7 @@
 - timeout (§6) — the host **MUST** kill the process and deny;
 - death by signal / crash;
-- unparseable, empty, oversized, or multi-object stdout (§5.2);
+- unparseable, empty, oversized, mis-framed (§5.4), or multi-object stdout (§5.2);
 - an unknown `verdict` value or a `deny` missing required fields;
 - a verdict that otherwise fails the §3.4 verdict schema — including an
   unrecognized `kind` value (outside `classical` | `zk` | `external`, §3.5), a
```

## Rationale

**The divergence the pinned text permits.** §5.1 tells the verifier:

> The verifier **MUST** write exactly one `JSON.stringify(verdict)` to the host-facing stdout, at the very end. A single trailing newline is **OPTIONAL**.

§5.2 tells the host:

> The host **MUST** parse the verifier's stdout as **exactly one** JSON object with **no trailing bytes**, and **MUST** reject (treat as deny, §7) any of: stdout that is empty, not valid JSON, or contains a leading/trailing prefix or suffix around the object

A newline is a trailing byte. Read literally, a host that denies `{"verdict":"allow"}\n` satisfies §5.2 while a verifier that emits it satisfies §5.1, so a conforming host can deny every verdict from a conforming verifier. The text then says nothing at all about the cases that arise in practice:

- `\r\n` from a verifier whose text-mode stdout translates newlines (.NET `Console.WriteLine`, Python `print` on Windows, PowerShell pipelines).
- A UTF-8 byte order mark before the object, which PowerShell and several .NET stream defaults prepend. RFC 8259 §8.1 makes BOM handling explicitly parser-defined ("implementations that parse JSON texts **MAY** ignore the presence of a byte order mark"), so two hosts using different JSON libraries diverge on the same bytes.
- Two newlines, a leading newline, or a leading space. RFC 8259 §2 calls this insignificant whitespace, so a host built as `JSON.parse(stdout.trim())` accepts all of it and a host built as a strict single-object reader rejects all of it. Both hosts pass the published vector set, because every published fixture emits the bare object, exactly one `\n`, or non-whitespace garbage.

The section that introduces this text calls itself "the single most fragile part of the implementation" and "normative for both sides", but the framing grammar it depends on is never written down. That is the finding: the contract's most fragile boundary is specified by two contradictory sentences and an unstated parser default.

**Why this matters beyond interop.** The extra-newline and BOM cases are not cosmetic. A second line terminator after the verdict is the fingerprint of a second writer on fd 1 (a leaked `console.log('')`, a library's progress-bar teardown), which is precisely the class of write §5.1's fd-isolation rules exist to keep off stdout. A host that trims silently hides that a second writer reached the verdict channel, and the next thing that writer emits may not be whitespace. A BOM before the object means the verifier's output stream is not the one it was configured to write; tolerating it means the host has stopped verifying the transport it depends on. §5.2 already refuses the lenient-parser posture for the multi-object case ("a lenient parser that reads only the first object **MUST NOT** be used"); the diff extends the same posture to whitespace and BOM so the rule is consistent rather than exploitable at the edges.

**Why this wording closes it.** §5.4 states the full byte set as ABNF: the object, then at most one `LF` or `CRLF`, then nothing. Every case the finding lists is now decided in exactly one direction, and the illustrative table makes each decision checkable against a fixture. §5.1 and §5.2 are rewritten only in the sentences that contradicted each other, and both now point at §5.4 as the single source of the grammar. The RFC 8259 relationship is stated explicitly as a profile so a reviewer cannot argue the generic "insignificant whitespace" rule back in. The classification rule (`unparseable_stdout`, never `schema_invalid`, framing checked before schema) follows the Tier-1 judgment that framing vectors should reuse the existing §16.3 transport classification rather than introduce a new one, and it keeps the host's fail-closed report honest: a BOM-prefixed but otherwise valid verdict is a transport failure, not a schema failure.

**Design choices.**

- **`CRLF` accepted.** The cost to hosts is one extra byte to recognize; the benefit is that verifiers on Windows text streams are conforming without special-casing their output. Rejecting `CRLF` would make the contract silently Unix-only.
- **Bare `CR` rejected.** No mainstream platform emits a lone `CR` as a line terminator; accepting it would only widen the grammar for no producer.
- **Leading whitespace and BOM rejected rather than tolerated.** Tolerance is the parser-defined behavior that produced the divergence, and no correct verifier emits either. Rejecting them costs nothing for a correct verifier and removes the ambiguity entirely. Tolerating them would require enumerating which whitespace, how much, and which BOMs, and would still leave RFC 8259 §8.1's MAY on the table.
- **Second terminator rejected.** Same reasoning as leading whitespace, plus the second-writer signal described above.

**RFC 2119 keyword choices.**

- **MUST** for the framing on both sides (§5.1 verifier emission, §5.2 host acceptance, §5.4 grammar). Framing is interop-critical; any weaker keyword reintroduces the two-conforming-hosts problem.
- **OPTIONAL** retained for the line terminator. Existing verifiers emit either the bare object or object plus `\n`; both remain conforming without change, so the terminator must stay optional to avoid a wire-visible tightening on verifiers.
- **MUST NOT** for verifier emission of BOM / leading bytes / second terminator, and for host-side stripping before parse. These are the exact behaviors that produce the divergence; a SHOULD NOT would leave the ambiguity in place for any host that chose the lenient reading.
- **MUST** for framing-before-schema ordering. Without it, two hosts could classify the same BOM-prefixed verdict differently (`unparseable_stdout` vs `schema_invalid`), which is the §16.3 classification-precedence problem in miniature.

## Impact

**Published conformance vectors (set 0.7.0).** No existing vector changes outcome or classification. Every published host-behavior fixture emits the bare object, the object plus exactly one `LF`, or non-whitespace non-JSON bytes, all of which fall on the same side of the new grammar as before. (The task brief refers to 28 vectors; the index at the pinned commit lists 29 after the `host-deny-signal-death-after-allow` addition. Either way, none is affected.)

**Vector artifact that must accompany this diff.** The finding is closed only when both directions of §5.4 are exercised, so this diff is incomplete without a companion `vector_gap` artifact adding host-behavior vectors to `spec/fixtures/host-conformance/`, with each fixture reading stdin to EOF before writing (the pattern the existing fixtures use):

| Vector | Fixture stdout | Expected |
|---|---|---|
| `host-allow-well-behaved-crlf-newline` | `{"verdict":"allow"}\r\n` | allow (positive control) |
| `host-deny-leading-bom-before-allow` | `EF BB BF` + `{"verdict":"allow"}\n` | deny, `unparseable_stdout` |
| `host-deny-leading-whitespace-before-allow` | `\n{"verdict":"allow"}` | deny, `unparseable_stdout` |
| `host-deny-double-newline-after-allow` | `{"verdict":"allow"}\n\n` | deny, `unparseable_stdout` |

The positive control matters as much as the denies: it is the only thing that stops a host from "passing" by rejecting all terminators. The vector-set version, `spec/CONFORMANCE.md` ("stdout framing" heading referenced by §5.4), and the vendored `@bolyra/evc-conformance` snapshot move together with that artifact, not with this diff alone.

**Reference-host consequence to verify.** The Tier-1 judgment states that both reference parsers (the Rust host and the JS conformance runner) trim whitespace before parsing. That claim is not verified here against the pinned source. If it holds, both reference hosts will fail the leading-whitespace and leading-BOM vectors until their parse path is tightened to §5.4, and the published `@bolyra/evc-conformance` self-check would go red on the same vectors. That host-side change is outside this artifact's scope and is a separate staged item; the spec diff and the vectors should not be applied without it, or the repository's own hosts become non-conforming to the repository's own spec.

**Wire compatibility.** The request and verdict envelopes are byte-for-byte unchanged; wire version stays `1` and no `code` is added, removed, or renamed. For verifiers this is a no-op: the bare object and object-plus-`LF` outputs that every existing verifier produces remain conforming, and object-plus-`CRLF` becomes explicitly conforming where it was previously undefined. For hosts this is a tightening: a host that trims or ignores a BOM before parsing was arguably conforming under the ambiguous text and is non-conforming under §5.4. Because no correct verifier ever emitted the bytes such a host tolerated, no correct verifier/host pair changes behavior; only a host's handling of malformed output changes, and it changes toward deny. The document revision line and the §15 changelog should record this as a prose-only clarification of the fail-closed boundary (same category as the 2026-08-26 revision), not a wire change.

**-02 relevance.** An IETF transport section that says "exactly one JSON object and nothing else" without a grammar draws the first review comment, and the whitespace/BOM question is the standard second one. §5.4 supplies the ABNF and the explicit RFC 8259 profile statement in the form a datatracker reviewer expects, and the framing-before-schema classification rule closes the precedence gap that the 2026-08-26 revision opened for the rest of §7.2. RFC 7942 status is unaffected: the framing tightening does not invalidate any pinned independent implementation run, though the companion vectors will need to be re-run against `khandrew1/mcp-use-evc-example` before its pass count is re-cited at a new vector-set version.
