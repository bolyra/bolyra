Base-Commit: a4f546f3279706a2b28a0c15569c0040425e84c7
Target-File: spec/external-verifier-contract-v1.md
Also-Touches: spec/draft-kondoju-evc-01.md (-02 material; source `.md` only — `.xml`/`.txt` are rendered artifacts)
Finding: ietf-reviewer-stdout-bound-unspecified
Artifact-Type: spec_finding → staged prose diff (no wire change, no vector change)

## Summary

§6 of the v1 contract (and §6.3 of the -01 draft) defines the **timeout** and the **stdin bound** but never the **stdout output bound** — yet §7.2 ("oversized … stdout"), §16.2 (`HUT_MAX_STDOUT_BYTES` "the stdout output bound the host **MUST** enforce (§6)"), the §16.3 `oversize_stdout` row ("exceeded the host output bound (§6)"), and the draft's Security Considerations ("the host MUST enforce both and kill on breach") all point at a quantity §6 does not contain. The only number lives in code: `spec/reference-host.js:42` and `spec/reference-host-rs/src/lib.rs:125-132` both default to `1048576`, and `spec/conformance-runner.js:630` injects that default when a vector does not pin one.

This diff adds a third bullet to §6 — **stdout bound** — that (1) makes the host the owner of the bound, parallel to the timeout; (2) states the enforce-and-kill obligation at its definition site with cross-references to §7.2 and §16.3, and forbids parsing a truncated prefix; and (3) sets a **RECOMMENDED** value of 1 MiB matching both reference hosts and the runner default. It fixes one dangling cross-reference in §7.2 and records the revision in the header and §15. The draft gets the same paragraph under a new `{#bounds}` anchor, and the three places that already depend on the bound now resolve to it. It deliberately says nothing about verdict size or a minimum bound: neither is stated anywhere in the pinned text or exercised by a vector, so neither belongs in a clarification.

## Diff 1 — `spec/external-verifier-contract-v1.md`

```diff
--- a/spec/external-verifier-contract-v1.md
+++ b/spec/external-verifier-contract-v1.md
@@ -2,9 +2,10 @@
 
 - **Status:** Stable (v1)
 - **Wire version:** `1` (integer-major; see §11)
-- **Document revision:** 2026-08-26 (registry closure and fail-closed
-  classification precedence made explicit — prose only, wire contract unchanged;
-  see the changelog in §15). Previous: 2026-07-17 (binding format **v2** —
+- **Document revision:** 2026-09-07 (stdout output bound defined in §6 —
+  prose only, wire contract unchanged; see the changelog in §15). Previous:
+  2026-08-26 (registry closure and fail-closed classification precedence made
+  explicit), 2026-07-17 (binding format **v2** —
   expiry is now signature-bound), 2026-07-11 (§16 Host conformance). The wire
   request/verdict envelope major is unchanged; the **binding** sub-structure is
   versioned separately (v1 → v2, §4).
@@ -474,6 +475,16 @@ parse stderr for the verdict.
   reference limit is **1 MiB** (1 048 576 bytes). A request over the bound **MUST**
   yield `deny code=malformed_input`; the verifier **MUST NOT** buffer an unbounded
   request.
+- **stdout bound.** The **host owns the stdout bound**, exactly as it owns the
+  timeout. The host **MUST** bound the number of bytes it accepts from the
+  verifier's stdout, and on breach **MUST** kill the process and deny (§7.2); a
+  host that reports a failure class classifies this as `oversize_stdout`
+  (§16.3). The host **MUST NOT** buffer unbounded verifier output and **MUST
+  NOT** parse a truncated prefix as a verdict — a breach is a fail-closed
+  condition, never a partial verdict. The **RECOMMENDED** bound is **1 MiB**
+  (1 048 576 bytes): the default of both reference hosts, and the value the
+  conformance runner applies when a vector does not pin one
+  (`HUT_MAX_STDOUT_BYTES`, §16.2).
 
 ## 7. Exit codes and host fail-closed obligations
 
@@ -496,7 +507,9 @@ The host **MUST** treat **all** of the following as **deny**, regardless of what
 - non-zero exit code;
 - timeout (§6) — the host **MUST** kill the process and deny;
 - death by signal / crash;
-- unparseable, empty, oversized, or multi-object stdout (§5.2);
+- stdout over the host output bound (§6) — the host **MUST** kill the process
+  and deny;
+- unparseable, empty, or multi-object stdout (§5.2);
 - an unknown `verdict` value or a `deny` missing required fields;
 - a verdict that otherwise fails the §3.4 verdict schema — including an
   unrecognized `kind` value (outside `classical` | `zk` | `external`, §3.5), a
@@ -838,6 +851,15 @@ wire `version`. A wire-`1` verifier that predates an entry below — necessarily
 are read as `zk` (§3.3); a verifier that implements a revision as a non-`zk` class
 adopts that revision's obligations (e.g. it **MUST** set `kind`, §3.5).
 
+- **2026-09-07 (wire version `1`, prose only).** Defined the **stdout output
+  bound** in §6, which §7.2, §16.2 (`HUT_MAX_STDOUT_BYTES`), and the §16.3
+  `oversize_stdout` failure class already depended on but no section stated:
+  the host owns it, **MUST** enforce it and kill-and-deny on breach, and the
+  **RECOMMENDED** value is 1 MiB (the default both reference hosts and the
+  conformance runner already used). §7.2 now cross-references §6 for the
+  oversized-stdout condition instead of §5.2, which never defined a size. No
+  vector, fixture, golden, or reference-host change: both hosts already
+  implement exactly this behavior at the recommended default.
 - **2026-08-26 (wire version `1`, prose + conformance only).** Made two
   behaviors the §3.4 schema and reference hosts already had explicit in prose,
   after the first independent external host implementation missed both: §7.2 now
```

## Diff 2 — `spec/draft-kondoju-evc-01.md` (source for -02)

```diff
--- a/spec/draft-kondoju-evc-01.md
+++ b/spec/draft-kondoju-evc-01.md
@@ -546,7 +546,7 @@ an implementer may be tempted to trust stdout, and it is stated explicitly to cl
 that temptation. No non-zero exit -- including "internal_error" -- ever yields an
 allow.
 
-## Timeout and Input Bounds
+## Timeout and Input Bounds {#bounds}
 
 The host owns the timeout; the verifier does not implement its own. The host MUST
 enforce a wall-clock timeout on the spawned process and treat expiry as deny. The
@@ -556,6 +556,16 @@ request read from stdin; the reference limit is 1 MiB (1 048 576 bytes). A reque
 over the bound MUST yield "deny code=malformed_input"; the verifier MUST NOT buffer
 an unbounded request.
 
+The host owns the stdout output bound, exactly as it owns the timeout. The host
+MUST bound the number of bytes it accepts from the verifier's stdout, and on breach
+MUST kill the process and deny ({{fail-closed}}); a host that reports a failure
+class classifies this as "oversize_stdout" ({{failure-classes}}). The host MUST NOT
+buffer unbounded verifier output and MUST NOT parse a truncated prefix as a
+verdict: a breach is a fail-closed condition, never a partial verdict. The
+RECOMMENDED bound is 1 MiB (1 048 576 bytes), the default of both reference hosts
+and the value the conformance runner applies when a vector does not pin one
+("HUT_MAX_STDOUT_BYTES").
+
 ## The Fail-Closed Set {#fail-closed}
 
 The host MUST treat ALL of the following as deny, regardless of what (if anything)
@@ -564,7 +574,9 @@ reached stdout:
 - non-zero exit code;
 - timeout -- the host MUST kill the process and deny;
 - death by signal / crash;
-- unparseable, empty, oversized, or multi-object stdout ({{fd-isolation}});
+- stdout over the host output bound ({{bounds}}) -- the host MUST kill the
+  process and deny;
+- unparseable, empty, or multi-object stdout ({{fd-isolation}});
 - an unknown "verdict" value or a "deny" missing required fields;
 - a verdict that otherwise fails the verdict schema ({{schemas}}) -- including an
   unrecognized "kind" value, a "code" outside the denial-code registry
@@ -746,7 +758,7 @@ deny; the failure class is the finer-grained assertion.
 | signal_death | verifier died by an unsolicited signal |
 | unparseable_stdout | stdout empty, not JSON, or with trailing bytes |
 | multiple_objects | stdout carried more than one JSON value |
-| oversize_stdout | stdout exceeded the host output bound |
+| oversize_stdout | stdout exceeded the host output bound ({{bounds}}) |
 | schema_invalid | a parsed verdict failed the verdict schema |
 | replay | a "consume_nonces" entry was already reserved |
 | spawn_error | the host could not spawn or drive the verifier at all |
@@ -998,7 +1010,7 @@ agree.
 
 ## Output-Bound Truncation and Resource Exhaustion
 
-The stdout output bound and the stdin bound (Section 6.3) bound a hostile verifier
+The stdout output bound and the stdin bound ({{bounds}}) bound a hostile verifier
 that floods or hangs; the host MUST enforce both and kill on breach. The
 "oversize-flood" and hang fixtures (Section 8.1) prove this. A truncated stdout is
 unparseable and MUST deny, never yield a partial allow.
```

The "Changes Since draft-kondoju-evc-00" appendix is -01's and is not edited; the -02 working copy needs a bullet in its own "Changes Since -01" appendix reading: *Defined the stdout output bound (Section 6.3) that the fail-closed set, the HUT convention, the `oversize_stdout` failure class, and Security Considerations already depended on; host-owned, kill-and-deny on breach, RECOMMENDED 1 MiB. No wire change.*

## Rationale

**The divergence the pinned text permits.** Four places impose an obligation on a quantity that is never defined:

> §7.2: "unparseable, empty, **oversized**, or multi-object stdout (§5.2)" — §5.2 contains no size.
> §16.2: "`HUT_MAX_STDOUT_BYTES` — the stdout output bound the host **MUST** enforce (§6)" — §6 has no stdout bullet.
> §16.3: "`oversize_stdout` | stdout exceeded the host output bound (§6)".
> Draft §13.5: "The stdout output bound and the stdin bound (Section 6.3) bound a hostile verifier … the host MUST enforce both and kill on breach."

A hostile implementer reads §6 alone and sees only a timeout and a stdin bound. The literal reading of §7.2's "oversized" against §5.2 is that a bound is not a distinct obligation at all. Two concrete behaviors are therefore defensible today and both are wrong:

1. **No bound at all.** A host buffers stdout to completion and relies on the timeout. Against a verifier that streams at pipe speed for 9.9 s, the host holds hundreds of MiB before the timeout fires. The `oversize-flood.js` fixture is deliberately built to expose exactly this (it bursts 8 MiB then hangs), but a host author reading only the draft has no normative text telling them a bound is a distinct obligation from the timeout.
2. **Truncate-and-parse.** A host that stops reading at its bound and parses what it has could, with a lenient parser, read a valid `{"verdict":"allow"}` prefix from a verdict the verifier then continued writing. §5.2 already forbids lenient multi-object parsing, but the truncation case is a different path and only the draft's Security Considerations — not the normative body — say "never yield a partial allow."

**Why this wording closes it.** The new bullet lives where the reader looks — beside the timeout and stdin bound — and answers the three questions the finding raises: *whose* bound (the host's, parallel to the timeout, so a verifier never has to implement it), *what happens on breach* (kill and deny, classified `oversize_stdout`, and never parse a truncated prefix — closing divergence 2), and *what value* (RECOMMENDED 1 MiB, exactly the number the reference hosts and runner already use, so the document now states what the code does rather than the code being the only source). The bound-as-distinct-obligation language closes divergence 1.

**What is deliberately left out.** An earlier revision of this artifact also asserted a maximum conforming-verdict size and a 64 KiB "SHOULD NOT go below" floor. Both are withdrawn. The pinned text nowhere bounds verdict size (a `deny` `message`/`detail` and the `consume_nonces` array have no stated length limits in §3 or the §3.4 schema), so a "few kilobytes" claim would be a new, unsupported normative-adjacent statement. The 64 KiB figure is a per-vector test input (`max_stdout_bytes: 65536` on `host-deny-oversize-stdout`), chosen so the kill fires before the fixture's 8 MiB burst completes; it says nothing about what a production host should choose, and no vector drives a below-floor host, so a SHOULD NOT there would be an untested recommendation. A clarification should state only what the contract already relies on.

**RFC 2119 choices.**
- **MUST bound / MUST kill and deny**: already normative by implication (§7.2 lists oversized stdout as a fail-closed condition; §16.2 says the host MUST enforce it). This diff states the obligation where it is defined; it introduces no new MUST that a conforming reference host does not already satisfy, and the obligation is already covered by a vector (`host-deny-oversize-stdout`, with `assert_verifier_killed: true`).
- **MUST NOT parse a truncated prefix**: lifts the draft's Security Considerations sentence ("never yield a partial allow") into the normative body. Same behavior as both reference hosts.
- **RECOMMENDED 1 MiB**: RECOMMENDED rather than MUST because the bound is a host resource limit, not a wire parameter, and the timeout in the same section uses RECOMMENDED for the same reason.

## Impact

**Published vectors (28).** None change. `host-deny-oversize-stdout` already exercises the kill-on-breach obligation at `max_stdout_bytes: 65536` with `assert_verifier_killed: true`; this diff is the normative text that vector was testing against. No new fixture, no golden regeneration, and `integrations/evc-conformance/scripts/sync.js` does not vendor spec prose (it copies `conformance-runner.js`, `reference-host.js`, the trimmed `test-vectors.json`, and `fixtures/host-conformance/`), so `sync:check` stays green without a run. Vector set stays 0.6.0.

**Reference hosts.** No change. `spec/reference-host.js:42` and `spec/reference-host-rs/src/lib.rs:125-132` already default to 1 048 576 and already kill on breach; `spec/conformance-runner.js:630` already injects that default. The diff documents existing behavior.

**Wire compatibility.** Wire version `1` unchanged. The request (§2) and verdict (§3) envelopes, the §3.4 schema, the §9 registry, and the binding v2 format are untouched. No conforming verifier is affected in any way — the bound is host-side. No conforming host is affected: a host with a bound that kills on breach was and remains conformant; a host with no bound was already non-conformant under §7.2/§16.2 and now has the text that says so.

**Independent implementation.** `khandrew1/mcp-use-evc-example` (27/27 pinned, IMPLEMENTER.md §9) already passes `host-deny-oversize-stdout`, so it satisfies the new text as written; no re-run is required, though the founder may re-pin as evidence at their discretion.

**Coverage map (SPEC HARDNESS).** Closes one CONFIRMED spec finding. Net MUST count: +2 at the definition site (bound, kill-and-deny) and +1 (no truncated-prefix parse), all three already covered by the existing vector; the §7.2 bullet is a cross-reference repair, not a new obligation. No uncovered MUST or SHOULD is introduced.

**-02 relevance.** This is an IESG DISCUSS-class gap (a MUST referencing an undefined quantity) and belongs in -02. The draft hunk above applies to the -01 source as the base for -02; regenerate `.xml`/`.txt` with the kramdown-rfc pipeline as part of the -02 build, not as part of landing this diff. The new `{#bounds}` anchor is used by three existing cross-references, replacing one hard-coded "Section 6.3" so section renumbering in -02 cannot dangle it.

**Verification performed.** Both diffs were generated by `git diff` against a checkout of the two files at `a4f546f3279706a2b28a0c15569c0040425e84c7` and pass `git apply --check` against that base; they also apply cleanly on the current `main` worktree HEAD (`da3a4ac`). Neither diff contains the strings "64 KiB", "65 536", "4 KiB", or "few kilobytes".

**APPLY.md must carry.** Base commit `a4f546f3279706a2b28a0c15569c0040425e84c7`; re-validation command `node spec/conformance-runner.js --host "node spec/reference-host.js"` (expects 28/28) plus `cd integrations/evc-conformance && npm run sync:check`; `git apply` of Diff 1 then Diff 2; `git commit -s` for DCO; note that `spec/` is a CODEOWNERS-gated path.
