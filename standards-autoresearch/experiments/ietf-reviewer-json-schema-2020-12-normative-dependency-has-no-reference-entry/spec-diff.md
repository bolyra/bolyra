Base-Commit: 9bf754441ab36ab93992ed5936d34c44a4128f92
Target-File: spec/draft-kondoju-evc-01.md
Finding: ietf-reviewer-json-schema-2020-12-normative-dependency-has-no-reference-entry

```diff
--- a/spec/draft-kondoju-evc-01.md
+++ b/spec/draft-kondoju-evc-01.md
@@ front matter: references @@
 normative:
   RFC2119:
   RFC8174:
   RFC8259:
+  I-D.bhutton-json-schema-01:
+  I-D.bhutton-json-schema-validation-01:
 informative:
   RFC6749:
   RFC7519:
   RFC7662:
   RFC7942:
   RFC8126:
   RFC8615:
   I-D.klrc-aiagent-auth:
   I-D.pidlisnyi-aps:
@@ section 4, opening paragraph @@
-This section transcribes the wire envelopes. The full JSON Schemas appear normatively in {{schemas}}.
+This section transcribes the wire envelopes. The full JSON Schemas appear normatively in {{schemas}}.
+Both schemas are written in the JSON Schema 2020-12 dialect: the core vocabulary
+(`$schema`, `$id`, `oneOf`, `properties`, `additionalProperties`) is defined in
+{{I-D.bhutton-json-schema-01}}, and the validation vocabulary this document
+relies on (`const`, `enum`, `required`, `minLength`, `minItems`, and the numeric
+form of `exclusiveMinimum`) is defined in
+{{I-D.bhutton-json-schema-validation-01}}. A host or verifier that validates a
+request or verdict against these schemas MUST evaluate them under that dialect.
```

Hunk placement note: the two hunks are anchored on text quoted in the candidate evidence (the exact `normative:` / `informative:` key lists and the first two sentences of Section 4). The surrounding front-matter indentation, the presence of any other keys between the reference lists, and the exact paragraph boundary in Section 4 require maintainer verification against `spec/draft-kondoju-evc-01.md` at the base commit before the hunks are positioned; the `@@` headers above carry no line numbers for that reason.

## Rationale

**The gap the current text leaves open.** The pinned draft makes the schemas load-bearing in two places. Section 4 states that "The full JSON Schemas appear normatively in {{schemas}}", and Section 4.2 defines the fail-closed rule in terms of the schema itself: "the deny schema ({{schemas}}) enumerates exactly these codes, so a verdict carrying any other `code` fails the verdict schema and the host MUST fail closed." The companion contract text transcribed into the draft (`spec/external-verifier-contract-v1.md` §2.2 and §3.4, quoted above) opens both schemas with `"$schema": "https://json-schema.org/draft/2020-12/schema"` and uses `"exclusiveMinimum": 0`, `"const"`, `"oneOf"`, `"minItems": 1`, and `"additionalProperties": false`. Those keywords have dialect-specific meaning: `exclusiveMinimum` in particular is a number in 2020-12 but was a boolean modifier on `minimum` in draft-04, so a reader who resolves the schema under the wrong dialect either rejects `now_unix: 5` as ill-formed or accepts `now_unix: 0`. The draft's normative references, per the quoted front matter, are exactly `RFC2119`, `RFC8174`, and `RFC8259`; there is no JSON Schema entry in either list. An IETF reviewer therefore cannot resolve the dependency that the MUST in Section 4.2 rests on, and the draft asserts a normative behavior ("fails the verdict schema") whose meaning is defined nowhere the draft cites.

**Why this wording closes it.** Adding `I-D.bhutton-json-schema-01` and `I-D.bhutton-json-schema-validation-01` under `normative:` gives the reviewer a resolvable target for every keyword the schemas use, and splitting core from validation matches how the JSON Schema documents themselves are structured (the core draft defines `$schema`, `$id`, applicators such as `oneOf` and `properties`, and `additionalProperties`; the validation draft defines `const`, `enum`, `required`, `minLength`, `minItems`, and `exclusiveMinimum`). The `-01` revision pin is deliberate: the `$schema` URI in the transcribed schemas is the 2020-12 dialect, and pinning the revision that defines 2020-12 prevents the reference from silently drifting if a later revision of the I-D introduces a different dialect. Whether `-01` is the current datatracker revision requires maintainer verification against https://datatracker.ietf.org/doc/draft-bhutton-json-schema/ and https://datatracker.ietf.org/doc/draft-bhutton-json-schema-validation/ at staging time.

A reference entry that is never cited in the body is itself a reviewer finding, so the diff adds one citing sentence in Section 4 immediately after the sentence that declares the schemas normative. That sentence names the dialect, cites both documents, and lists which keywords come from which document, so the citation is substantive rather than decorative.

**RFC 2119 keyword choice.** The added sentence uses a single **MUST** ("MUST evaluate them under that dialect"). This is the minimum strength that makes the existing Section 4.2 rule well-defined: that rule already says a verdict "fails the verdict schema and the host MUST fail closed", and failing a schema is only a determinate event once the evaluation dialect is fixed. A **SHOULD** would leave two conforming hosts free to reach opposite verdicts on the same bytes (one under 2020-12, one under draft-04), which reintroduces exactly the ambiguity the finding identifies. No new keyword is applied to verifiers; the sentence binds whoever validates, which is the same population the existing Section 4.2 MUST already binds.

**What is deliberately not staged.** The candidate also proposed a "prose controls over schema" precedence clause and an alternative that demotes the schemas to informative. The Tier 1 verdict promoted the reference additions on their own and called the precedence clause unnecessary, and this diff follows that: it changes no normative relationship between prose and schema, so it cannot create a new divergence between the draft and the host-conformance suite, which already exercises schema-derived behavior. Whether the two new references constitute a downref to expired Internet-Drafts is an IESG process question that requires maintainer verification against the datatracker status of both documents; if they are expired, the reference is still the correct one for the dialect and the downref would be handled in the shepherd write-up, not by weakening the draft's text.

## Impact

**Published conformance vectors.** None. The change touches only the reference lists and one prose paragraph of the Internet-Draft. It does not alter either schema, any request or verdict field, any denial code, or any host-behavior rule that a vector in the published host-conformance set exercises, so no vector artifact needs to accompany this diff and no golden regeneration is implied.

**Wire compatibility.** Unchanged. Wire version `1` and binding v2 are untouched; the diff only names the dialect the already-published schemas already declare via their `$schema` URI. A host or verifier that was evaluating the schemas under 2020-12, which is the only reading consistent with the transcribed `"$schema"` line, conforms before and after this change with no code modification.

**-02 relevance.** This removes an unreferenced-normative-dependency blocker for draft-kondoju-evc-02. After this diff the draft cites a resolvable definition for every schema keyword its fail-closed rule depends on, and the citation appears in body text rather than only in the reference list. Whether idnits raises a downref warning for the two I-D references requires maintainer verification by running idnits on the rendered -02 text; that warning, if present, is a process note for the write-up and not a further text change.
