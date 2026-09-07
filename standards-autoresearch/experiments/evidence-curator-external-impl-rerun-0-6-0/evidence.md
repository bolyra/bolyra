# Interop run record: khandrew1/mcp-use-evc-example @17642a5 vs vector set 0.6.0

**Claim substantiated:** At commit `17642a5efd5e1c42991ab8aa399cd6138f64f635`, the host boundary of `khandrew1/mcp-use-evc-example` passes 27 of 28 `host_behavior` vectors of vector set 0.6.0 as published in `@bolyra/evc-conformance@0.2.0`, failing only `host-deny-unknown-denial-code`, and passes 27 of 27 vectors of vector set 0.5.0 (bolyra commit `441de46`) under the same test adapter.

Runs: 2026-09-06 (first) and 2026-09-07 (re-run, identical totals). Run by: Bolyra maintainers, not a third party. Outbound contact: none. The procedure performs a read-only `git clone` of a public repo and read-only npm registry fetches; it posts, comments, and publishes nothing.

## 1. What is being tested, exactly

The pinned external repo ships the EVC host boundary as a library function, `askExternalVerifier()` in `src/evc-host.ts`, wired into an mcp-use `mcp:tools/call` middleware in `src/demo.ts`. It ships **no Host-Under-Test (HUT) entrypoint**: nothing in the repo at `17642a5` reads `HUT_*` variables or emits the harness decision envelope (`spec/IMPLEMENTER.md` §3, `spec/conformance-runner.js` HUT convention §16.2). The repo's own `npm test` (vitest) does not run the conformance suite.

Consequently every conformance run of this implementation, including the 27/27 run recorded in `spec/IMPLEMENTER.md` §9 (line 182 at `a4f546f`) and `spec/draft-kondoju-evc-01.md` {#impl-status}, requires a test adapter that is pinned in neither repo. This record pins one: `run/hut.ts`, SHA-256 `8e57afa3dd8e19414642b70816ec84e90d4489424d299311994afde885206b99`, alongside this file. The adapter:

- reads the harness request from stdin and passes it to `askExternalVerifier()` unchanged;
- spawns exactly the argv in `HUT_VERIFIER_CMD`; forwards `HUT_TIMEOUT_MS` and `HUT_MAX_STDOUT_BYTES` as the function's `timeoutMs` / `maxStdoutBytes`;
- implements the `consumeNonces` callback against `HUT_NONCE_STORE` (host mode) or memory (local mode), reserving nothing if any offered nonce is already present;
- appends to `HUT_ACTION_LOG` only after the function resolves with `allow`;
- maps the implementation's `EvcHostError` message strings 1:1 onto §16.3 failure classes (`timeout`, `spawn_error`, `oversize_stdout`, `signal_death`, `nonzero_exit`, `unparseable_stdout`, `schema_invalid`, `replay`);
- relays a verifier `deny` as `{"decision":"deny","code":<verifier code unchanged>}`.

It adds no contract logic. Every timeout, output-bound, schema, exit-status, and replay decision is the implementation's own. The 0.5.0 control in §5 is the check on this: with the same adapter the pinned commit reproduces the listed 27/27, so the adapter neither inflates nor deflates the result.

## 2. Environment

| Item | Value |
|---|---|
| OS | macOS 15.6 (Darwin 24.6.0), arm64 |
| node | v24.13.0 |
| npm | 11.6.2 |
| External repo | https://github.com/khandrew1/mcp-use-evc-example |
| External commit | `17642a5efd5e1c42991ab8aa399cd6138f64f635` (2026-08-26 10:37:04 -0700, "Merge pull request #1 from saneGuy/fix-signal-exit-distinction") |
| External deps | `npm ci --ignore-scripts` from the repo's committed `package-lock.json` (105 packages); `tsx` from that tree runs the adapter |
| Suite under test | `@bolyra/evc-conformance@0.2.0`; `dist.integrity` `sha512-6taKERfvC2M65p2HkpfN79jrYoIkOHxmMXUjmwW7mz86WG9oeWnzsB8sQB++SVwuiXZYnT8bDpNtASmi4RzgRA==`; `dist.shasum` `6dcdc2e12b005545c95af7d7f13070e1de613e82`; attestation https://registry.npmjs.org/-/npm/v1/attestations/@bolyra%2fevc-conformance@0.2.0 |
| Vector set (from `--json`) | version `0.6.0`, 28 `host_behavior` vectors, SHA-256 `1472cc1765059833f91a24e575655d97bb667c7bc6412af3e7a1edb58b1059c1` (equals `integrations/evc-conformance/MANIFEST.json` entry for `vendor/test-vectors.json` at bolyra `da3a4ac`) |
| Bolyra checkout used for cross-checks | `da3a4ac9299f96e9af559f3ce65513a6f6481174`; last `spec/` commit `a4f546f3279706a2b28a0c15569c0040425e84c7` (2026-08-27) |

## 3. Reproduce (pinned, read-only)

```sh
# 1. External implementation at the pinned commit
git clone https://github.com/khandrew1/mcp-use-evc-example /tmp/evc-ext
git -C /tmp/evc-ext checkout 17642a5efd5e1c42991ab8aa399cd6138f64f635
(cd /tmp/evc-ext && npm ci --ignore-scripts)

# 2. Test adapter (from this experiment directory in a bolyra/bolyra clone)
mkdir -p /tmp/evc-ext-hut /tmp/evc-empty
cp standards-autoresearch/experiments/evidence-curator-external-impl-rerun-0-6-0/run/hut.ts /tmp/evc-ext-hut/hut.ts
shasum -a 256 /tmp/evc-ext-hut/hut.ts   # 8e57afa3dd8e19414642b70816ec84e90d4489424d299311994afde885206b99

# 3. Published suite, from an empty directory
cd /tmp/evc-empty
npx -y @bolyra/evc-conformance@0.2.0 \
  --host "$(command -v node) /tmp/evc-ext/node_modules/tsx/dist/cli.mjs /tmp/evc-ext-hut/hut.ts" --json
echo "exit=$?"
```

Expected stdout (`--json`, top-level fields; per-vector array elided):

```json
{"runner":"bolyra-conformance","spec":"external-verifier-contract-v1",
 "vector_set":{"version":"0.6.0","total":28,"selected":28,
   "sha256":"1472cc1765059833f91a24e575655d97bb667c7bc6412af3e7a1edb58b1059c1"},
 "totals":{"passed":27,"failed":1,"skipped":0}}
```

Expected exit code: `1`. Expected stderr (failing line and tail):

```
  host-deny-unknown-denial-code: FAIL -- failure_class mismatch: got 'undefined', want one of ["schema_invalid"]
  ...
27 passed, 1 failed, 0 skipped
```

Cross-check from a bolyra clone at `da3a4ac` (identical vector bytes, no install):

```sh
HOST_CMD="$(command -v node) /tmp/evc-ext/node_modules/tsx/dist/cli.mjs /tmp/evc-ext-hut/hut.ts" \
  node spec/conformance-runner.js --type host_behavior
# -> 27 passed, 1 failed, 0 skipped
```

Captured outputs alongside this file: `run/result-npm-0.2.0.json`, `run/result-npm-0.2.0.log` (2026-09-06); `run/rerun-2026-09-07-npm-0.2.0.json`, `run/rerun-2026-09-07-npm-0.2.0.log` (2026-09-07). Both report `"totals":{"passed":27,"failed":1,"skipped":0}` and the same vector-set SHA-256.

## 4. Per-vector result, vector set 0.6.0

| # | Vector | Result |
|---|---|---|
| 1 | host-allow-well-behaved | PASS |
| 2 | host-relay-well-behaved-deny | PASS |
| 3 | host-deny-non-json-stdout | PASS |
| 4 | host-deny-multiple-objects | PASS (as `unparseable_stdout`, accepted by the vector) |
| 5 | host-deny-schema-invalid-verdict | PASS |
| 6 | host-deny-unknown-denial-code | **FAIL** |
| 7 | host-deny-deny-missing-fields | PASS |
| 8 | host-deny-allow-trailing-garbage | PASS |
| 9 | host-deny-no-output-timeout | PASS |
| 10 | host-deny-partial-json-timeout | PASS |
| 11 | host-deny-nonzero-exit-after-allow | PASS |
| 12 | host-deny-killed-by-signal | PASS |
| 13 | host-deny-oversize-stdout | PASS |
| 14 | host-nonce-reserve-novel-allow | PASS |
| 15 | host-nonce-reserve-replay-deny | PASS |
| 16 | host-nonce-reserve-all-any-conflict-deny | PASS |
| 17 | host-deny-allow-extra-property | PASS |
| 18 | host-deny-bad-kind | PASS |
| 19 | host-deny-empty-consume-nonces | PASS |
| 20 | host-deny-malformed-consume-nonce | PASS |
| 21 | host-deny-deny-extra-property | PASS |
| 22 | host-deny-nonce-entry-extra-property | PASS |
| 23 | host-deny-nonce-entry-wrong-type | PASS |
| 24 | host-deny-binary-garbage-stdout | PASS |
| 25 | host-deny-leading-garbage | PASS |
| 26 | host-deny-slow-allow-past-deadline | PASS |
| 27 | host-allow-well-behaved-kind-classical | PASS |
| 28 | host-allow-well-behaved-kind-external | PASS |

**The one failure, precisely.** Fixture `unknown-denial-code.js` emits `{"verdict":"deny","code":"quantum_flux_error","message":"not a registry code"}` and exits 0. The implementation's `isClosedVerdict()` (`src/evc-host.ts`) checks that `code` is a string but does not close it over the §9 registry, so it resolves the verdict and the host relays it. Observed host decision when the adapter is driven directly with that fixture as `HUT_VERIFIER_CMD`:

```
{"decision":"deny","code":"quantum_flux_error"}
```

The vector requires `{"decision":"deny","failure_class":"schema_invalid"}`. This is the obligation the vector was added to test (registry closure, bolyra commit `030884b`, 2026-08-26, "close the §9 denial-code registry — vector set 0.6.0"), merged the same day as the implementation's pinned commit. The pinned commit predates the closed registry; the result is not a regression of the implementation.

## 5. Control: the listed 0.5.0 result reproduces with the same adapter

`spec/IMPLEMENTER.md` §9 lists this commit at "27/27 host_behavior, vector set 0.5.0". No published package carries vector set 0.5.0: `npm view @bolyra/evc-conformance versions` returns `["0.1.0","0.2.0"]`; `0.1.0` reports vector set 0.4.0 (27 vectors) and `0.2.0` reports 0.6.0 (28 vectors). Vector set 0.5.0 exists only in the bolyra repo between commits `37b3fa6` (2026-08-25, introduces 0.5.0 with 27 `host_behavior` vectors) and `441de46` (2026-08-25, the parent of `030884b`).

```sh
# from a bolyra clone
mkdir -p /tmp/evc-spec-050 && git archive 441de467a12ade34677999749e37b199e94975c9 spec/ | tar -x -C /tmp/evc-spec-050
HOST_CMD="$(command -v node) /tmp/evc-ext/node_modules/tsx/dist/cli.mjs /tmp/evc-ext-hut/hut.ts" \
  node /tmp/evc-spec-050/spec/conformance-runner.js --type host_behavior --json
echo "exit=$?"
```

Expected: `"vector_set":{"version":"0.5.0","total":111,"selected":27,"sha256":"879d1cf9647f4f42e0815e34eeb5587633dff28e8fa8ceab25c139f470bb629c"}`, `"totals":{"passed":27,"failed":0,"skipped":0}`, exit 0. Observed on both run dates: identical (`run/result-repo-441de46-0.5.0.json`, `run/rerun-2026-09-07-repo-441de46-0.5.0.json`).

Also observed, for completeness: `npx -y @bolyra/evc-conformance@0.1.0 --host ... --json` (vector set 0.4.0, 27 vectors, SHA-256 `153eba4c4e9afd413f2f1496ae6eb44dd0aa816bd02eb259e9d13ee6fee1f13a`) gives 27 passed, 0 failed (`run/result-npm-0.1.0.json`).

## 6. What this changes in our documents (staged text, not applied)

Pinned to `spec/` commit `a4f546f3279706a2b28a0c15569c0040425e84c7`. The existing row is true and stays; the 0.6.0 result is added so the listing states what the pinned commit does under the current set.

`spec/IMPLEMENTER.md` §9 (line 182), replace the single table row with:

```
| [`khandrew1/mcp-use-evc-example`](https://github.com/khandrew1/mcp-use-evc-example) | TypeScript, behind mcp-use's `mcp:tools/call` middleware | commit `17642a5`, 2026-08-26 | 27/27 `host_behavior`, vector set 0.5.0 (bolyra `441de46`); 27/28 on vector set 0.6.0 (`@bolyra/evc-conformance@0.2.0`), failing `host-deny-unknown-denial-code`: relays an out-of-registry denial code; the registry was closed after this commit |
```

`spec/draft-kondoju-evc-01.md` {#impl-status} (lines 926-928), after `it passes 27 of 27 "host_behavior" vectors of vector set 0.5.0`, insert:

```
Against vector set 0.6.0 the same commit passes 27 of 28; the one failing
vector is the registry-closure vector added in this revision, which
postdates the commit.
```

Re-validation before applying: the §3 command must still print `"passed":27,"failed":1` with exit 1, and the §5 command `"passed":27,"failed":0` with exit 0. If the implementation is updated and re-pinned upstream, the row gets a new commit and a new run record; this one is not edited. The edit touches `spec/`, which CODEOWNERS gates; commit with `git commit -s`.

## 7. Findings for the next Tier 1 (not staged here)

- **Listing reproducibility gap (IMPLEMENTER.md §9).** The listed 27/27 depends on a HUT adapter that is pinned in neither repo. §9 says rows are "listed ... after a harness-green run at a pinned public commit" but does not require the adapter to be pinned. Candidate: require a harness-entrypoint column (path plus commit, or an adapter checksum) so a third party can reproduce a row without writing code.
- **Vector set 0.5.0 has no published artifact.** A row citing 0.5.0 can only be reproduced from a bolyra git commit. Candidate: cite the bolyra commit in the row (done in the §6 text above), or pin rows to published suite versions only.
- **Implementation-side gap (upstream, not ours).** `isClosedVerdict()` at `17642a5` does not close `code` over the §9 registry. This is the implementer's to fix; rule 2c means this loop does not propose contacting them.

## 8. Ledger entry

```json
{"id": "interop-run-2026-09-07-mcp-use-evc-example-17642a5-vs-0.6.0",
 "kind": "interop_run",
 "subject": "khandrew1/mcp-use-evc-example host boundary vs @bolyra/evc-conformance@0.2.0 (vector set 0.6.0, 28 host_behavior vectors): 27 passed, 1 failed (host-deny-unknown-denial-code); control: 27/27 on vector set 0.5.0 (bolyra 441de46) with the same adapter; reproduced on 2026-09-06 and 2026-09-07",
 "pinned_commit": "17642a5efd5e1c42991ab8aa399cd6138f64f635",
 "reproduce_cmd": "git clone https://github.com/khandrew1/mcp-use-evc-example /tmp/evc-ext && git -C /tmp/evc-ext checkout 17642a5efd5e1c42991ab8aa399cd6138f64f635 && (cd /tmp/evc-ext && npm ci --ignore-scripts) && mkdir -p /tmp/evc-ext-hut /tmp/evc-empty && cp standards-autoresearch/experiments/evidence-curator-external-impl-rerun-0-6-0/run/hut.ts /tmp/evc-ext-hut/hut.ts && cd /tmp/evc-empty && npx -y @bolyra/evc-conformance@0.2.0 --host \"$(command -v node) /tmp/evc-ext/node_modules/tsx/dist/cli.mjs /tmp/evc-ext-hut/hut.ts\" --json   # expect totals passed=27 failed=1, exit 1",
 "urls": ["https://github.com/khandrew1/mcp-use-evc-example/commit/17642a5efd5e1c42991ab8aa399cd6138f64f635", "https://www.npmjs.com/package/@bolyra/evc-conformance/v/0.2.0", "https://registry.npmjs.org/-/npm/v1/attestations/@bolyra%2fevc-conformance@0.2.0"],
 "rfc7942_ready": false}
```

`rfc7942_ready` is false because the run was performed by the specification's authors and the test adapter is not pinned in the implementer's public repository; the row in §6 is listable as maintainer-run evidence only.
