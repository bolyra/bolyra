# Evidence record: coverage delta of the external implementation `khandrew1/mcp-use-evc-example` against vector set 0.7.0

**Kind:** implementation (RFC 7942 implementation-status material)
**Bolyra base pin:** `9bf7544` (`spec: host-deny-signal-death-after-allow vector — set 0.7.0, evc-conformance 0.3.0 (#126)`)
**Subject:** `https://github.com/khandrew1/mcp-use-evc-example`

## 1. Claim

The external implementation `khandrew1/mcp-use-evc-example` is recorded in the pinned repository as passing 27 of 27 vectors, and the shipped suite at the same pin contains 29 vectors, so the two vectors added after that record have no recorded pass or fail result for this implementation.

## 2. What this record does and does not assert

This record asserts a **coverage delta**, not a failure. It does not infer that the external host passes or fails either delta vector. Its output is:

- the enumerated list of vectors added after the 27-vector record,
- for each, a coverage status of `UNTESTED` unless a third party produces a pinned run result,
- an RFC 7942-format status stanza that states coverage as N-of-29 with the untested ids named.

## 3. Source facts this record depends on

Facts quoted from the pinned `CLAUDE.md` at `9bf7544`:

- "First independent external implementation: `khandrew1/mcp-use-evc-example` (27/27 pinned, listed in IMPLEMENTER.md §9)."
- "`@bolyra/evc-conformance` … v0.3.0 — the published conformance suite (vector set 0.7.0, 29 host-behavior vectors, zero runtime deps)."

Fact quoted from the commit subject of `9bf7544`:

- "spec: host-deny-signal-death-after-allow vector — set 0.7.0, evc-conformance 0.3.0 (#126)"

From these three quotations alone, the following is established: the recorded external pass count is 27, the shipped count at the pin is 29, and `host-deny-signal-death-after-allow` is a vector introduced at the pin commit. Therefore at least one of the two delta vectors is `host-deny-signal-death-after-allow`.

The following are **not** established by quoted text and are marked accordingly throughout:

- The identity of the second delta vector. The candidate names `host-deny-unknown-denial-code`. **Requires maintainer verification against `spec/fixtures/host-conformance/`** via Procedure A below.
- The external repository's pinned SHA and the Bolyra commit at which the 27/27 record was made. **Requires maintainer verification against `spec/IMPLEMENTER.md` §9.**
- Whether the external host's source, at its pinned SHA, exhibits the behavior the two delta vectors require. **Requires maintainer verification against the external repository's pinned source.** This record does not assert either outcome.

## 4. Reproduce procedure

All steps are read-only against the Bolyra repository. Only Procedure C uses a workspace, and that workspace is a single fresh temporary directory that is discarded afterward. Nothing below writes to `spec/`, `integrations/`, or any repository tree. This section describes a procedure for a founder or third party to execute; it does not report an execution.

### Procedure A — enumerate the delta vectors (repository, read-only, no network)

Run from the Bolyra repository root with the working tree at `9bf7544`.

**A1. Confirm the vector introduced at the pin commit.**

```sh
git show 9bf7544 --stat -- spec/fixtures/host-conformance/
```

Expected output: a stat listing whose added paths include a fixture whose id is `host-deny-signal-death-after-allow`. Any additional fixture paths in this listing are also delta vectors, because they postdate a 27-vector record by construction.

**A2. Locate the Bolyra commit at which the 27/27 record was written.**

```sh
git log --format='%H %s' -S 'mcp-use-evc-example' -- spec/IMPLEMENTER.md
```

Expected output: one or more commit lines. The oldest line is the commit that introduced the listing; call its hash `RECORD_COMMIT`. If this returns no lines, the record was introduced under a different path and the remaining steps cannot be completed until a maintainer locates it.

**A3. Read the pinned SHA of the external implementation from the record.**

```sh
git show 9bf7544:spec/IMPLEMENTER.md | sed -n '/§9\|## 9/,/^## /p'
```

Expected output: the §9 text including a 40-hex or 7-hex SHA for `khandrew1/mcp-use-evc-example`. Call it `EXTERNAL_SHA`. If no SHA appears, the record is not pinned and `rfc7942_ready` must remain `false` for this entry regardless of any other result.

**A4. List vectors added between the record and the pin.**

```sh
git diff --name-status RECORD_COMMIT..9bf7544 -- spec/fixtures/host-conformance/ | grep '^A'
```

Expected output: added fixture paths. Their count is expected to be exactly 2 if the 27/27 record was made at a 27-vector suite and no vectors were removed in between. If the count is not 2, record the actual count and the actual ids; the stanza in §5 must use the observed values, not the expected ones.

**A5. Confirm the total at the pin.**

```sh
ls spec/fixtures/host-conformance/ | wc -l
```

Expected output: `29`, or a count consistent with the fixture directory layout. If the directory nests vectors under subdirectories, substitute the index file the runner consumes; the exact index path **requires maintainer verification against `spec/conformance-runner.js`**.

### Procedure B — per-vector coverage status from the external source (read-only, no live run)

For each delta id from A4, the coverage status is determined by inspection of the external source at `EXTERNAL_SHA`, obtained from a local clone made in Procedure C's scratch workspace. The determination rule:

- `UNTESTED` — no run record exists at `EXTERNAL_SHA` for this vector. This is the default and the only status this record assigns without a run result.
- `PASS@<sha>` / `FAIL@<sha>` — assigned only if Procedure C produces a result at a named external SHA.

This record assigns `UNTESTED` to both delta vectors. It does not infer a pass from source reading, because a source-level judgment of a fail-closed obligation is not a run and would not be third-party reproducible.

### Procedure C — optional isolated-scratch rerun (third party's action, one temporary workspace)

This procedure clones an external repository and therefore contacts the network to fetch it. It is not part of the loop's execution and is not required for this record; it is the step a skeptical third party would run to convert `UNTESTED` into a result. It uses one fresh temporary directory and touches no repository tree.

```sh
WS="$(mktemp -d)"
git clone https://github.com/khandrew1/mcp-use-evc-example "$WS/impl"
cd "$WS/impl"
git checkout EXTERNAL_SHA
npx @bolyra/evc-conformance@0.3.0 --host "HOST_CMD"
```

`HOST_CMD` is the external repository's documented host invocation; it **requires verification against that repository's README at `EXTERNAL_SHA`**.

Expected output: either a summary line reporting `29/29`, or a summary reporting fewer than 29 together with the ids of failing vectors. Either outcome is a valid result to record. If `@bolyra/evc-conformance@0.3.0` reports its vector set version, the expected value is `0.7.0`; a different value means the wrong suite was resolved and the result must not be recorded.

After recording, `rm -rf "$WS"`.

## 5. RFC 7942 implementation-status stanza (proposed text)

The following is proposed text for the Implementation Status section of the EVC draft. Bracketed values are to be filled from Procedure A results; the defaults shown are the values supported by the quoted facts alone.

```
Implementation: mcp-use-evc-example
  Organization:  independent (repository owner: khandrew1)
  Source:        https://github.com/khandrew1/mcp-use-evc-example
  Pinned commit: [EXTERNAL_SHA from Procedure A3]
  Maturity:      example integration; independently written against
                 the External Verifier Contract v1 text and the
                 published conformance suite.
  Coverage:      27 of 29 host-behavior vectors (vector set 0.7.0,
                 suite @bolyra/evc-conformance 0.3.0). The 27 recorded
                 passes were produced against an earlier vector set.
                 No result is recorded for the following vectors,
                 which were added after that record:
                   - host-deny-signal-death-after-allow
                   - [second id from Procedure A4]
  Licensing:     [requires verification against the repository's
                 LICENSE at EXTERNAL_SHA]
  Contact:       repository issue tracker
  Last verified: [date Procedure A was executed]
```

This stanza states coverage honestly as a count over the current suite rather than as a fraction of the suite that existed when the passes were recorded. It becomes `29 of 29` only if Procedure C yields that result at a named SHA, in which case the pinned commit line changes to that SHA.

## 6. Ledger entry

The `pinned_commit` field carries the Bolyra pin. The external pinned SHA is placed in `subject` once Procedure A3 supplies it; until then the placeholder remains and `rfc7942_ready` is `false` because the record's coverage of two vectors is unevidenced.

```json
{
  "id": "impl-khandrew1-mcp-use-evc-example-coverage-delta-set-0.7.0",
  "kind": "implementation",
  "subject": "khandrew1/mcp-use-evc-example@<EXTERNAL_SHA per spec/IMPLEMENTER.md §9 at 9bf7544>; coverage 27-of-29 vs vector set 0.7.0; UNTESTED: host-deny-signal-death-after-allow, <second delta id per Procedure A4>",
  "pinned_commit": "9bf7544",
  "reproduce_cmd": "git show 9bf7544 --stat -- spec/fixtures/host-conformance/ && git log --format='%H %s' -S 'mcp-use-evc-example' -- spec/IMPLEMENTER.md && git diff --name-status <RECORD_COMMIT>..9bf7544 -- spec/fixtures/host-conformance/ | grep '^A'",
  "urls": [
    "https://github.com/khandrew1/mcp-use-evc-example",
    "https://github.com/bolyra/bolyra/commit/9bf7544"
  ],
  "rfc7942_ready": false
}
```
