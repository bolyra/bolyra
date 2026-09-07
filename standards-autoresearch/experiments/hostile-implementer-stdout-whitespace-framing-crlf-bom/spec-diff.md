```markdown
Base-Commit: a4f546f3279706a2b28a0c15569c0040425e84c7
Target-File: spec/external-verifier-contract-v1.md
Finding: hostile-implementer-stdout-whitespace-framing-crlf-bom
Artifact-Kind: spec_finding → staged spec diff (prose only, wire contract unchanged)
Staged: 2026-09-07 (standards-autoresearch, iteration 2)

# Staged diff: define stdout framing whitespace, line terminators, and BOM handling in §5

This is a staged proposal. It is pinned to the base commit above and is not
applied by the loop. Hunk line offsets are approximate (the pinned text was read
as prose, not as numbered lines); the founder should apply with
`git apply --recount` or a 3-way apply and confirm the context lines match.

```diff
diff --git a/spec/external-verifier-contract-v1.md b/spec/external-verifier-contract-v1.md
--- a/spec/external-verifier-contract-v1.md
+++ b/spec/external-verifier-contract-v1.md
@@ -3,9 +3,11 @@
 - **Status:** Stable (v1)
 - **Wire version:** `1` (integer-major; see §11)
-- **Document revision:** 2026-08-26 (registry closure and fail-closed
-  classification precedence made explicit — prose only, wire contract unchanged;
-  see the changelog in §15). Previous: 2026-07-17 (binding format **v2** —
+- **Document revision:** 2026-09-07 (stdout framing made normative — framing
+  whitespace set, line terminators, byte-order-mark prefix; prose only, wire
+  contract unchanged; see the changelog in §15). Previous: 2026-08-26 (registry
+  closure and fail-closed classification precedence made explicit),
+  2026-07-17 (binding format **v2** —
   expiry is now signature-bound), 2026-07-11 (§16 Host conformance). The wire
   request/verdict envelope major is unchanged; the **binding** sub-structure is
   versioned separately (v1 → v2, §4).
@@ -335,8 +337,20 @@ normative for both sides.
 ### 5.1 Verifier obligations
 
 - The verifier **MUST** write exactly one `JSON.stringify(verdict)` to the
-  host-facing stdout, at the very end. A single trailing newline is **OPTIONAL**.
+  host-facing stdout, at the very end. The verifier **MUST NOT** write any byte
+  before the object; in particular it **MUST NOT** emit a UTF-8 byte order mark
+  (bytes `EF BB BF`, U+FEFF), which this contract treats as a non-whitespace
+  prefix (§5.2), not as framing. After the object the verifier **MAY** write a
+  single line terminator, either LF (`0x0A`) or CRLF (`0x0D 0x0A`). It
+  **SHOULD NOT** write any other trailing bytes, and it **MUST NOT** write any
+  trailing byte outside the framing-whitespace set defined in §5.2. The
+  platform line terminator appended by a language's default line-oriented
+  print (Rust `println!`, Python text-mode `print`, PowerShell `Write-Output`)
+  is therefore conforming on every platform; a verifier does not need to
+  suppress it.
 - **No other code path may write to the host-facing stdout.** Proof-verification
   libraries (snarkjs / circomlibjs / WASM / native bindings) can write to file
   descriptor 1 directly — progress bars, warnings, debug spew — bypassing any
@@ -365,13 +379,39 @@ normative for both sides.
 ### 5.2 Host obligations (single-object parse)
 
-The host **MUST** parse the verifier's stdout as **exactly one** JSON object with
-**no trailing bytes**, and **MUST** reject (treat as deny, §7) any of:
+The host **MUST** parse the verifier's stdout as **exactly one** JSON object,
+optionally surrounded by **framing whitespace**, and nothing else.
+
+*Framing whitespace* is exactly the [RFC 8259] §2 `ws` set — the four bytes
+`0x20` (space), `0x09` (horizontal tab), `0x0A` (LF), and `0x0D` (CR) — in any
+count and any order, including none. Concretely, the complete stdout **MUST**
+match
+
+```
+stdout = ws object ws
+```
+
+where `object` is one JSON object and each `ws` is zero or more
+framing-whitespace bytes. The host **MUST** accept a well-formed verdict framed
+this way: a trailing LF, a trailing CRLF, and leading or trailing runs of
+framing whitespace **MUST NOT** by themselves cause a deny. Every byte before or
+after the object that is **not** in the framing-whitespace set is a prefix or
+suffix and **MUST** cause a deny. A UTF-8 byte order mark (`EF BB BF`) is such a
+prefix: the host **MUST** deny stdout that begins with it and **MUST NOT** strip
+or ignore it before parsing, even though [RFC 8259] §8.1 permits generic JSON
+parsers to ignore one. A host whose runtime removes U+FEFF while decoding or
+trimming text (for example, JavaScript `String.prototype.trim` strips U+FEFF)
+**MUST** perform the prefix check on the raw bytes before that step. Trailing
+framing whitespace is bounded only by the host's output bound (§7.2, §16.3);
+the host **MUST NOT** treat the count of framing-whitespace bytes as a
+conformance signal in either direction.
+
+The host **MUST** reject (treat as deny, §7) any of:
 
-- stdout that is empty, not valid JSON, or contains a leading/trailing prefix or
-  suffix around the object;
+- stdout that is empty or consists only of framing whitespace, is not valid
+  JSON, contains a leading or trailing prefix or suffix (any non-framing byte,
+  including a byte order mark) around the object, or whose single JSON value is
+  not an object;
 - **multiple** concatenated JSON values (a lenient parser that reads only the
   first object **MUST NOT** be used — two objects is a fail-closed condition);
 - a verdict whose `verdict` field is neither `"allow"` nor `"deny"`, or a `deny`
   missing `code`/`message`.
```

## Rationale

### The divergence the pinned text permits

§5.1 and §5.2 make contradictory statements about the same bytes, and neither
defines which bytes count as framing:

> §5.1: "The verifier **MUST** write exactly one `JSON.stringify(verdict)` to the
> host-facing stdout, at the very end. A single trailing newline is **OPTIONAL**."

> §5.2: "The host **MUST** parse the verifier's stdout as **exactly one** JSON
> object with **no trailing bytes**, and **MUST** reject (treat as deny, §7) any
> of: stdout that is empty, not valid JSON, or contains a leading/trailing prefix
> or suffix around the object;"

Read literally, `\n` is a trailing byte, so a host that enforces §5.2 as written
denies a verifier that exercised its §5.1 option. Nothing says whether "newline"
means LF, CRLF, or either. Nothing says whether leading whitespace is a "prefix".
Nothing says what a UTF-8 BOM is. Two hosts can therefore both claim conformance
and return opposite verdicts on the same well-behaved verifier:

| Verifier stdout | Strict host (`exactly one 0x0A`) | Trim-then-parse host |
|---|---|---|
| `{"verdict":"allow"}\r\n` (Rust `println!` on Windows, Python text mode, PowerShell) | deny | allow |
| ` {"verdict":"allow"}` (leading space from a shell wrapper) | deny | allow |
| `{"verdict":"allow"}\n\n` | deny | allow |
| `EF BB BF {"verdict":"allow"}` (BOM from a text-mode redirect) | deny | parser-dependent: Node `JSON.parse` throws; JS `trim()` strips U+FEFF and then accepts; Python `json.loads(str)` rejects while `json.loads(bytes)` accepts |

None of these rows is a fail-open. Every deny is safe. But the contract's stated
product is that a host "adopts the contract by learning four steps, not the
proof format" and gets identical behavior from any conforming verifier. Spurious
denies between conforming parties are an interop defect in exactly the layer the
contract exists to fix, and the published vector set does not pin either
direction: `host-deny-leading-garbage` and `host-deny-allow-trailing-garbage`
use non-whitespace bytes, and `host-allow-well-behaved` has no CRLF or
leading-whitespace variant.

### Why this wording closes it

The diff resolves the ambiguity by naming the framing set rather than by
picking one line terminator:

- **Framing whitespace is defined by reference to RFC 8259 §2 `ws`.** That is
  the set every JSON parser already treats as insignificant around a value, so
  the rule matches what compliant parsers do by default and needs no new
  tokenizer. It is a closed four-byte set, so "tolerant" cannot be stretched to
  admit any other byte.
- **Host acceptance is a MUST, not a MAY.** If accepting CRLF were merely
  permitted, the strict host in the table above would remain conforming and the
  divergence would survive. The finding is only closed if one direction is
  mandatory. Accepting is the safe direction to mandate: it never converts a
  deny into an allow on the verdict content, only on the framing around it.
- **Verifier emission is layered MAY / SHOULD NOT / MUST NOT.** A verifier MAY
  emit one LF or one CRLF, so Windows-native and line-oriented-print
  implementations are conforming as written. It SHOULD NOT emit other trailing
  whitespace, which keeps well-behaved output tight. It MUST NOT emit any
  non-framing trailing byte, which is the load-bearing prohibition and is what
  §5.1 already meant. The emit rule is strictly narrower than the accept rule,
  so a conforming verifier always parses on a conforming host, while a host
  remains obligated to tolerate the full `ws` set from verifiers it did not
  write.
- **BOM is a MUST-deny, on both sides.** RFC 8259 §8.1 says a producer MUST NOT
  add a BOM and a parser MAY ignore one. The contract adopts the producer MUST
  NOT and resolves the parser MAY to "deny" for two reasons. First, a BOM on the
  verdict channel is evidence that a text-mode layer rewrote the verifier's
  bytes between the `fs.writeSync` and the host's read, which is precisely the
  interposition §5's fd-level isolation exists to exclude; fail-closed is the
  consistent posture. Second, "MAY ignore" is the origin of the parser-dependent
  row in the table, so leaving it as MAY would preserve the divergence. Denying
  is always RFC 8259-conforming because ignoring was never required.
- **The raw-bytes clause is there because `trim()` is the common
  implementation.** The Tier-1 judgment recorded that the reference hosts use
  trim-based parsing. JavaScript's `String.prototype.trim` removes U+FEFF; Rust's
  `str::trim` does not, since U+FEFF is not Unicode `White_Space`. Without the
  clause, two reference hosts written idiomatically would already disagree on
  the BOM row. Stating that the check happens on raw bytes before decoding makes
  the obligation implementable in one line in any language.
- **Unbounded trailing whitespace is explicitly bounded by the existing output
  bound**, which §7.2 already names first in the fail-closed precedence. No new
  resource exposure is introduced, and the clause forbids a host from inventing
  its own "too much whitespace" heuristic, which would recreate the divergence.
- **"whose single JSON value is not an object"** is added to the first bullet
  because the new framing grammar names `object`, and a bare `"allow"`, `[]`, or
  `null` would otherwise satisfy `ws value ws` while failing the intent of
  "exactly one JSON object". It restates what the section already required.

### RFC 2119 keyword choices

| Clause | Keyword | Justification |
|---|---|---|
| Verifier writes no byte before the object | MUST NOT | Any prefix is a deny on a conforming host; a permissive keyword would license spurious denies. |
| Verifier emits no BOM | MUST NOT | Mirrors RFC 8259 §8.1 producer rule; a BOM is a guaranteed deny under §5.2. |
| Verifier may emit one LF or one CRLF | MAY | Both are inside the accept set; forcing LF-only would make Windows-native verifiers non-conforming with no security gain. |
| Verifier emits no other trailing bytes | SHOULD NOT | Interoperable either way inside the `ws` set; tight output is best practice, not a correctness condition. |
| Verifier emits no non-framing trailing byte | MUST NOT | This is the original §5.1 intent and a guaranteed deny under §5.2. |
| Host accepts `ws object ws` | MUST | The only keyword that eliminates the strict-host divergence; accepting framing is never fail-open. |
| Host denies any non-framing prefix or suffix | MUST | Unchanged strength from pinned §5.2. |
| Host denies a BOM and does not strip it | MUST / MUST NOT | Resolves the RFC 8259 §8.1 parser MAY to a single direction; the strip prohibition is what makes the rule testable. |
| Host checks raw bytes before decode when the runtime strips U+FEFF | MUST | Without it the BOM rule is unimplementable in JavaScript via the idiomatic path. |
| Host does not treat whitespace count as a signal | MUST NOT | Prevents a host from re-introducing an out-of-spec heuristic that a strict verifier would trip. |

## Impact

### Published vectors (set 0.6.0, 28 host-behavior vectors)

No published vector changes meaning or expected outcome:

- `host-deny-leading-garbage` and `host-deny-allow-trailing-garbage` use
  non-whitespace bytes, which remain prefix or suffix under the new definition.
  Expected verdict unchanged.
- `host-allow-well-behaved` and every other allow vector emit either no trailing
  bytes or a single LF, both inside the new accept set. Expected verdict
  unchanged.
- No vector emits CRLF, leading whitespace, or a BOM, so no golden flips.

This diff MUST be accompanied by a vector artifact adding three `host_behavior`
vectors in the same format as `host-deny-leading-garbage`, with the vector set
bumped additively (0.6.0 → 0.7.0) and the `spec/CONFORMANCE.md` index updated:

| Vector id | Verifier stdout (bytes) | Expected host outcome |
|---|---|---|
| `host-allow-trailing-crlf` | `{"verdict":"allow"}` + `0D 0A` | allow (positive control) |
| `host-allow-leading-whitespace` | `20 09 0A` + `{"verdict":"allow"}` + `0A` | allow (positive control) |
| `host-deny-utf8-bom-prefix` | `EF BB BF` + `{"verdict":"allow"}` + `0A` | deny; host classification `parse_invalid` under the §16.3 precedence (the founder should confirm the exact classification token against the pinned §16.3 when authoring the golden) |

The two positive controls are what the current set lacks: today a host that
rejects CRLF passes all 28 vectors. After this change it fails one. The
published `@bolyra/evc-conformance` suite is a vendored snapshot, so the vector
artifact must be followed by `node integrations/evc-conformance/scripts/sync.js`
and a `sync:check` run; both are founder-side steps recorded in APPLY.md.

Total published host-behavior vectors after apply: 31. The independent
implementation listed in `spec/IMPLEMENTER.md` §9 (`khandrew1/mcp-use-evc-example`,
27/27 at its pinned commit) remains a valid RFC 7942 entry at that pin; its
listing does not need to change, and a re-run against 0.7.0 would be a new
ledger event, not an edit to the old one.

### Reference host impact (flag, not asserted)

The Tier-1 judgment recorded that the reference hosts parse with a trim-based
approach. If the JS conformance runner (`spec/conformance-runner.js`) or the MPP
gate decodes stdout to a string and calls `trim()` before `JSON.parse`, it will
strip U+FEFF and **accept** the BOM vector, failing `host-deny-utf8-bom-prefix`.
The Rust reference host (`spec/reference-host-rs`) is expected to fail closed on
a BOM because `str::trim` does not remove U+FEFF and `serde_json` rejects it,
but this has not been verified against the pinned source and must be confirmed
by running the new vector. Any resulting host fix lands in CODEOWNERS-gated
paths and is a separate founder-side change; this staged diff does not modify
any code. The loop's own writes stay inside `standards-autoresearch/`.

### Wire compatibility

Prose only. The request and verdict envelopes, the §3.4 schemas, the §9 code
registry, and wire version `1` are unchanged. No verifier that conforms to the
pinned text becomes non-conforming: the pinned text already forbade non-JSON
trailing bytes and already permitted one trailing newline, and every
already-conforming verifier output lies inside the new accept grammar. The only
behavior that changes is on hosts that were stricter than the spec intended, and
those hosts were already producing spurious denies against conforming verifiers.

### -02 relevance

- The finding proposes mirroring this text into the IETF-style draft at §4.4.
  The draft's pinned text was not part of this artifact's input, so no hunk is
  staged for it; the founder should port the §5.2 framing grammar and the BOM
  rule verbatim and add [RFC 8259] to the draft's normative references if it is
  not already there. Undefined framing on a stdio transport is a routine IETF
  review comment, so closing it before -02 removes a predictable blocker.
- A §15 changelog entry should accompany the revision-line hunk above. Proposed
  text: "2026-09-07 — §5.1/§5.2: stdout framing made normative. Framing
  whitespace defined as RFC 8259 §2 `ws`; hosts MUST accept LF, CRLF, and
  leading/trailing framing whitespace; a UTF-8 BOM is a prefix and MUST be
  denied. Prose only; wire contract unchanged. Vectors
  `host-allow-trailing-crlf`, `host-allow-leading-whitespace`,
  `host-deny-utf8-bom-prefix` added (set 0.7.0)." The §15 text was not in the
  pinned input, so it is given here rather than as a diff hunk.
- Standard-ness effect: closes one CONFIRMED spec finding (SPEC HARDNESS) and
  adds two positive-control vectors covering a MUST that previously had none
  (coverage map), with no IMPLEMENTATIONS regression because existing pins are
  preserved.
```
