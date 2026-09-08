Base-Commit: 9bf754441ab36ab93992ed5936d34c44a4128f92
Target-File: spec/external-verifier-contract-v1.md
Finding: hostile-implementer-stdout-whitespace-grammar-single-lf-vs-no-trailing-bytes

## Staged diff

```diff
--- a/spec/external-verifier-contract-v1.md
+++ b/spec/external-verifier-contract-v1.md
@@ -150,6 +150,7 @@
 ## 3. Verifier → host verdict (stdout)
 
-The verifier **MUST** write exactly one JSON object to stdout and nothing else
-(§5 governs this strictly). The verdict is one of three shapes.
+The verifier **MUST** write exactly one JSON object to stdout and nothing else
+apart from the trailing whitespace §5.1 permits (§5 governs the framing
+strictly). The verdict is one of three shapes.
 
 ### 3.1 Allow
@@ -430,8 +431,16 @@
 ### 5.1 Verifier obligations
 
-- The verifier **MUST** write exactly one `JSON.stringify(verdict)` to the
-  host-facing stdout, at the very end. A single trailing newline is **OPTIONAL**.
+- The verifier **MUST** write exactly one `JSON.stringify(verdict)` to the
+  host-facing stdout, at the very end. Trailing JSON whitespace after the object
+  is **OPTIONAL**: the verifier **MAY** append a single line terminator (`LF`,
+  or `CRLF` on a platform whose stdout is text-mode) and **SHOULD NOT** append
+  any other whitespace. The verifier **MUST NOT** write any byte before the
+  object and **MUST NOT** write any non-whitespace byte after it — including a
+  NUL, a UTF-8 byte-order mark, or a second JSON value. A conforming verifier's
+  stdout is therefore always a valid `verdict-text` (§5.2) whose leading
+  whitespace is empty, which keeps it readable by pre-revision hosts that
+  tolerate only a bare object plus an optional newline.
 - **No other code path may write to the host-facing stdout.** Proof-verification
   libraries (snarkjs / circomlibjs / WASM / native bindings) can write to file
   descriptor 1 directly — progress bars, warnings, debug spew — bypassing any
@@ -462,12 +471,49 @@
 ### 5.2 Host obligations (single-object parse)
 
-The host **MUST** parse the verifier's stdout as **exactly one** JSON object with
-**no trailing bytes**, and **MUST** reject (treat as deny, §7) any of:
+The host **MUST** read the verifier's stdout to EOF and **MUST** accept it only
+if the **complete** captured byte sequence matches the following framing
+grammar (ABNF, RFC 5234):
+
+```
+verdict-text = *ws object *ws
+ws           = %x20 / %x09 / %x0A / %x0D   ; SP, HT, LF, CR
+object       = <the "object" production of RFC 8259 section 4, UTF-8 encoded>
+```
+
+`ws` is **exactly** the RFC 8259 §2 insignificant-whitespace set and nothing
+else. Any other byte outside the object — a NUL (`%x00`), a UTF-8 byte-order
+mark (`EF BB BF`; RFC 8259 §8.1 forbids a producer from adding one), a
+non-ASCII space such as U+00A0, a comment, or any byte of a second JSON value —
+is a **prefix** or **suffix** and **MUST** cause rejection. Consequently:
+
+- the host **MUST** accept `{"verdict":"allow"}` with no trailing byte, with a
+  trailing `LF`, with a trailing `CRLF`, or surrounded by any run of `ws`
+  (leading whitespace included). A host that rejects a trailing newline as "a
+  trailing byte" is **non-conforming**.
+- the host **MUST** reject `{"verdict":"allow"}` followed by `LF` and then a
+  NUL or any other non-`ws` byte. A host built on a parser that stops at the
+  first complete value, or that trims whitespace and ignores whatever follows,
+  is **non-conforming**.
+
+A general-purpose JSON parser that accepts `ws value ws` and rejects everything
+else, applied to the **entire** stdout capture (never to the first line or to
+the first value only), satisfies this grammar; a parser that tolerates content
+after the first value, or that silently skips a byte-order mark, does not. The
+top-level value **MUST** be a JSON object: an array, string, number, literal,
+or an empty `verdict-text` is rejected. Rejection under this grammar is a
+§7.2 fail-closed deny and is classified by the host's own stdout-parse cause
+(§16.3), never relayed as a verifier decision.
+
+The host **MUST** therefore reject (treat as deny, §7) any of:
 
-- stdout that is empty, not valid JSON, or contains a leading/trailing prefix or
-  suffix around the object;
+- stdout that is empty, does not match `verdict-text`, is not valid JSON, or
+  contains a non-`ws` prefix or suffix around the object;
 - **multiple** concatenated JSON values (a lenient parser that reads only the
   first object **MUST NOT** be used — two objects is a fail-closed condition);
 - a verdict whose `verdict` field is neither `"allow"` nor `"deny"`, or a `deny`
   missing `code`/`message`.
@@ -511,7 +557,8 @@
 - non-zero exit code;
 - timeout (§6) — the host **MUST** kill the process and deny;
 - death by signal / crash;
-- unparseable, empty, oversized, or multi-object stdout (§5.2);
+- unparseable, empty, oversized, or multi-object stdout, or stdout that
+  otherwise falls outside the §5.2 `verdict-text` framing grammar;
 - an unknown `verdict` value or a `deny` missing required fields;
```

## Rationale

**The divergence the pinned text permits.** §5.1 tells the verifier that "A
single trailing newline is **OPTIONAL**", while §5.2 tells the host to parse
stdout "as **exactly one** JSON object with **no trailing bytes**" and to
reject "a leading/trailing prefix or suffix around the object". Read literally,
a newline *is* a trailing byte, so the two sections license opposite host
behaviours on the verifier's own permitted output:

- A byte-literal host rejects `{"verdict":"allow"}\n` — a verdict the spec
  explicitly allows a verifier to emit. That is a spurious fail-closed deny on
  every run against a newline-terminating verifier, and it is invisible to the
  published suite because no vector emits whitespace after the object.
- A host built on an off-the-shelf parser (RFC 8259 §2 defines
  `JSON-text = ws value ws`, and `JSON.parse`, `serde_json::from_str`, and
  most standard-library parsers implement exactly that) accepts
  `\n\n\t{"verdict":"allow"}\r\n\n`. The same host may also accept a
  byte-order mark, or — if it uses a streaming/first-value API — a second
  value after the newline, which the "multiple concatenated JSON values" bullet
  forbids.

The pinned text never says whether `CRLF` is "a single newline", whether
leading whitespace is a "prefix", or whether two `LF`s are one trailing
newline or a suffix. The two published framing vectors named in the candidate
evidence (`host-deny-allow-trailing-garbage`, "followed by trailing garbage",
and `host-deny-leading-garbage`, "a non-JSON PREFIX") both use non-whitespace
bytes, so an over-strict host and an over-lenient host pass identically. A
hostile or lazy implementer can therefore ship either, cite the suite, and be
interoperable with only a subset of conforming verifiers.

**Why this wording closes it.** The diff replaces two prose descriptions of
"one object, nothing else" with a single normative ABNF production,
`verdict-text = *ws object *ws`, whose `ws` alternative is enumerated by code
point and pinned to the RFC 8259 §2 set. Every case the finding lists now has
one answer:

| Input | Verdict-text? | Host obligation |
|---|---|---|
| `{…}` | yes | accept |
| `{…}\n`, `{…}\r\n`, `{…}\n\n` | yes | accept |
| `\n\t{…}` | yes | accept |
| `{…}\n\x00` | no (NUL is not `ws`) | reject |
| `\xEF\xBB\xBF{…}` | no (BOM is not `ws`) | reject |
| `{…}\n{…}` | no (second value) | reject |
| `[…]`, `"…"`, empty | no (not `object`) | reject |

The grammar is asymmetric on purpose. The **host** is required to accept the
full `ws` set because that is what standards-conformant JSON parsers already
do, so the cheapest correct host implementation is also the conforming one.
The **verifier** is held to the *narrowest* output — no leading bytes, at most
one line terminator — so a verifier that follows §5.1 remains readable by a
pre-revision host that only tolerated a bare object plus an optional newline;
tightening the verifier side is what makes the change backward-compatible for
deployed hosts. The §3 intro sentence ("nothing else") and the §7.2 bullet are
adjusted only so no remaining sentence contradicts the grammar.

**RFC 2119 choices.**

- `MUST` for the host acceptance and rejection rules: interoperability is the
  entire point of the framing, and the two behaviours the finding exhibits are
  mutually incompatible; a `SHOULD` would leave the same fork open.
- `MUST NOT` for verifier leading bytes and non-whitespace trailing bytes: these
  are exactly the outputs the host is required to reject, so any weaker keyword
  would describe a verifier that conforming hosts must deny.
- `MAY` for the single line terminator and `SHOULD NOT` for other trailing
  whitespace: the host accepts all of `*ws`, so extra whitespace is harmless
  to a revised host; `SHOULD NOT` records that it needlessly narrows
  compatibility with older strict hosts without making a working verifier
  non-conforming on that ground alone.
- `CRLF` is named explicitly as a permitted terminator so a Windows text-mode
  stdout is not left to interpretation.

## Impact

**Published vectors.** No existing vector's stdout, expected verdict, or
expected host classification changes. The two existing framing vectors
referenced in the candidate evidence use non-whitespace prefix/suffix bytes,
which remain rejections under the new grammar. Whether any existing vector's
verifier fixture already emits a trailing `LF` — and therefore whether a
byte-strict reference host is silently over-strict today — requires
maintainer verification against `spec/fixtures/host-conformance/` and the two
reference hosts (`spec/reference-host-rs`, `spec/conformance-runner.js`).

**Accompanying vector artifact (required).** This diff must ship with new
host-behavior vectors so the suite pins both edges of the grammar:

- `host-allow-trailing-crlf-and-leading-whitespace` — positive control:
  verifier stdout is `\n\t{"verdict":"allow"}\r\n`, exit 0; expected host
  outcome is allow. This is the vector that fails an over-strict host.
- `host-deny-trailing-nul-after-newline` — negative control: verifier stdout
  is `{"verdict":"allow"}\n\x00`, exit 0; expected host outcome is the host's
  own fail-closed stdout-parse classification. This is the vector that fails an
  over-lenient first-value or trim-and-ignore host.
- Optionally `host-deny-leading-bom` (`\xEF\xBB\xBF{"verdict":"allow"}`), which
  catches parsers that silently skip a byte-order mark.

The exact fixture schema, the vector-set version bump policy, and the
`schema_invalid`-style classification token the negative vectors should expect
require maintainer verification against `spec/CONFORMANCE.md` and §16.3 of the
contract (not in the pinned excerpt). Because vectors change, the vendored
`@bolyra/evc-conformance` snapshot must be re-synced from `spec/` under the
repo's existing sync procedure.

**Wire compatibility.** No change to the request envelope (§2), the verdict
schema (§3.4), the denial-code registry (§9), or exit-code semantics (§7.1).
Wire version stays `1`; binding version stays v2. A conforming pre-revision
verifier (bare object plus optional `LF`) is conforming after this change. A
pre-revision host is affected in one direction only: a host that rejected a
trailing newline was already rejecting spec-permitted verifier output and is
now explicitly non-conforming; a host that accepted arbitrary trailing content
was already violating the multi-value rule and is now caught by a vector. This
is a prose/normative-clarification revision: the document revision line and
the §15 changelog need a matching entry, and neither is in the pinned excerpt.

**-02 relevance.** High. An ABNF-defined framing grammar with an enumerated
whitespace set is the form an IETF reviewer expects for a stdio transport, and
it removes an RFC 2119 self-contradiction (`OPTIONAL` newline vs `MUST` reject
trailing bytes) that would be flagged as a blocking nit. The candidate states
that the IETF draft mirrors this stdout framing in its §4.4; that text is not
in the pinned excerpt, so a companion diff to
`spec/draft-bolyra-mutual-zkp-auth-01.md` requires maintainer verification
before the two documents are considered aligned.
