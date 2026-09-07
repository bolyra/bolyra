All verification is done. Writing the artifact now.

# RFC 7942 implementation-status material: independent host at vector set 0.6.0, plus per-entry template fields

**Claim substantiated (one sentence):** At commit `17642a5efd5e1c42991ab8aa399cd6138f64f635`, the host boundary of `khandrew1/mcp-use-evc-example` passes 27 of 28 `host_behavior` vectors of vector set 0.6.0 (`@bolyra/evc-conformance@0.2.0`), failing only `host-deny-unknown-denial-code`, and the five entries in draft-kondoju-evc-01 §11 can each be stated with the RFC 7942 §2 fields (URL, maturity, coverage, version compatibility, licensing, contact, last-updated) using only facts checked against pinned sources on 2026-09-07.

Run date: 2026-09-07. Run by: Bolyra maintainers, not a third party. Outbound: none. The run performs read-only `git clone`, `gh api` reads, and npm registry fetches only; no comment, issue, PR, or message was created anywhere. Both implementers named below are under engagement-graph holds; this record proposes contacting neither.

Pinned bolyra checkout: `da3a4ac9299f96e9af559f3ce65513a6f6481174` (branch `fix/sar-template-render`). Last `spec/` change to the §11 text: `a4f546f3279706a2b28a0c15569c0040425e84c7` (2026-08-27).

## 1. Ground truth checked, and what the candidate got right and wrong

| Candidate assertion | Checked against | Result |
|---|---|---|
| §11.3 records 27/27 at vector set 0.5.0, commit 17642a5 | `spec/draft-kondoju-evc-01.md:923-928`; `spec/IMPLEMENTER.md:182` | Confirmed verbatim |
| §11.2 says the published suite is 0.2.0 / vector set 0.6.0 / 28 vectors | `spec/draft-kondoju-evc-01.md` §11.2; `integrations/evc-conformance/package.json` (`0.2.0`); `MANIFEST.json` (`vector_set.version` `0.6.0`, `host_behavior_count` 28) | Confirmed |
| The 28th vector is `host-deny-unknown-denial-code` | `vendor/test-vectors.json` (28 `host_behavior` ids listed in §4 below); bolyra commit `030884b` (2026-08-26, "close the §9 denial-code registry — vector set 0.6.0") | Confirmed |
| No run record shows the independent implementation passing it | This record: it does **not** pass it (§3) | Confirmed, and resolved with a run rather than prose |
| No §11 entry states licensing or contact | `grep -n -i "licens\|contact" spec/draft-kondoju-evc-01.md` returns no lines inside §11 | Confirmed |
| §11.4 and §11.5 give no URL and no coverage statement | §11 text | Confirmed |
| Reproduce command: `npx @bolyra/evc-conformance@0.2.0 --host "<host cmd from that repo's README>"` | The repo's README at 17642a5 | **Not runnable as written.** The README has no host command; the pinned commit has no Host-Under-Test entry point at all (no file reads `HUT_*`, nothing emits the harness decision envelope). A test adapter is required; §2 pins one. |
| `@bolyra/evc-conformance@0.1.0` ships vector set 0.5.0 | `npm view`; `git show c76536c:integrations/evc-conformance/MANIFEST.json` | **No.** 0.1.0 ships vector set **0.4.0** (27 vectors). Vector set 0.5.0 (commit `37b3fa6`, 2026-08-25) was never published to npm. The listed 0.5.0 result is reproducible only from a bolyra git commit. |

Published suite facts (npm registry, read 2026-09-07):

| Version | Published | Vector set | `dist.integrity` |
|---|---|---|---|
| 0.1.0 | 2026-08-22T23:51:08Z | 0.4.0, 27 vectors | `sha512-kWnDmrKMRgNngR78Wevo8IAJsa+490DnlWstxiNfUPN2RCSTdrT30LJhUehj+BodZdfEnshLDuWw+Wq4i9uCDA==` |
| 0.2.0 (latest) | 2026-08-26T18:16:21Z | 0.6.0, 28 vectors, SHA-256 `1472cc1765059833f91a24e575655d97bb667c7bc6412af3e7a1edb58b1059c1` | `sha512-6taKERfvC2M65p2HkpfN79jrYoIkOHxmMXUjmwW7mz86WG9oeWnzsB8sQB++SVwuiXZYnT8bDpNtASmi4RzgRA==` |

Attestation for 0.2.0: `https://registry.npmjs.org/-/npm/v1/attestations/@bolyra%2fevc-conformance@0.2.0`. Annotated tag `@bolyra/evc-conformance@0.2.0` points at bolyra `030884b9f48d39770f779e6eeb6174a59ff75247`, whose `MANIFEST.json` says vector set 0.6.0; the vendored vector SHA-256 at `da3a4ac` is identical to the one the published package reports at run time.

## 2. The test adapter (pinned alongside this record)

File: `standards-autoresearch/experiments/ietf-reviewer-rfc7942-listing-stale-and-incomplete/runs/hut-shim.mjs`
SHA-256: `6fa7a50a1cf3ebe18a0bca5a2e673f55f869e732af69e6e977e1918442488b8d`

What it does, and what it does not do:

- Imports `askExternalVerifier` and `EvcHostError` from the clone's `src/evc-host.ts`, unmodified. Node 24 strips the file's type-only syntax natively, so no build step is needed.
- Maps `HUT_VERIFIER_CMD` (argv array) to `command`/`args`, `HUT_TIMEOUT_MS` to `timeoutMs`, `HUT_MAX_STDOUT_BYTES` to `maxStdoutBytes`. Passes the stdin request object through unchanged.
- In `HUT_NONCE_MODE=host`, supplies a `consumeNonces` callback backed by the `HUT_NONCE_STORE` file with the same any-conflict-rejects rule the repo's own `src/demo.ts` applies to its in-memory `Set`.
- Appends to `HUT_ACTION_LOG` only after the function resolves `allow`.
- Maps the implementation's `EvcHostError` message strings one-to-one onto §16.3 failure classes (`spawn_error`, `timeout`, `oversize_stdout`, `signal_death`, `nonzero_exit`, `unparseable_stdout`, `schema_invalid`, `replay`).
- Relays a verifier `deny` as `{"decision":"deny","code":<verifier code unchanged>}`.

Every timeout, output-bound, framing, exit-status, verdict-schema, and replay decision is made inside `src/evc-host.ts`. The adapter contains no registry table and no verdict validation of its own, so the one failure in §3 is attributable to the implementation, not to the adapter. Control: the same adapter reproduces the listed 27/27 on the older vector set (§3, run C).

An equivalent adapter (`run/hut.ts`, SHA-256 `8e57afa3dd8e19414642b70816ec84e90d4489424d299311994afde885206b99`) in the sibling experiment `evidence-curator-external-impl-rerun-0-6-0` produced the same per-vector results on 2026-09-06; the two records corroborate each other.

## 3. Reproduce (pinned, read-only, no outbound writes)

Environment used: macOS 15.6 (Darwin 24.6.0) arm64, node v24.13.0, npm 11.x, cargo 1.97.1.

```sh
# A. External implementation at the pinned commit
W=/tmp/evc-rfc7942 && mkdir -p "$W" && cd "$W"
git clone https://github.com/khandrew1/mcp-use-evc-example
git -C mcp-use-evc-example checkout 17642a5efd5e1c42991ab8aa399cd6138f64f635
(cd mcp-use-evc-example && npm ci --ignore-scripts)     # 105 packages from the committed lockfile

# B. Adapter (from a bolyra checkout at da3a4ac or later), placed NEXT TO the clone
cp <bolyra>/standards-autoresearch/experiments/ietf-reviewer-rfc7942-listing-stale-and-incomplete/runs/hut-shim.mjs "$W/hut-shim.mjs"
shasum -a 256 "$W/hut-shim.mjs"   # 6fa7a50a1cf3ebe18a0bca5a2e673f55f869e732af69e6e977e1918442488b8d

# C. Published suite 0.2.0 (vector set 0.6.0), from an empty directory
mkdir -p "$W/empty" && cd "$W/empty"
npx -y @bolyra/evc-conformance@0.2.0 --host "$(command -v node) $W/hut-shim.mjs" --json > run.json 2> run.stderr
echo "exit=$?"
```

Expected: `exit=1`. Expected `run.json` top-level fields:

```json
{"runner":"bolyra-conformance","spec":"external-verifier-contract-v1",
 "vector_set":{"version":"0.6.0","total":28,"selected":28,
   "sha256":"1472cc1765059833f91a24e575655d97bb667c7bc6412af3e7a1edb58b1059c1"},
 "totals":{"passed":27,"failed":1,"skipped":0}}
```

Expected `run.stderr` lines that differ from PASS:

```
Bolyra Conformance Test Runner v0.6.0
28 test vectors loaded
  host-deny-unknown-denial-code: FAIL -- failure_class mismatch: got 'undefined', want one of ["schema_invalid"]
27 passed, 1 failed, 0 skipped
```

Observed 2026-09-07: identical. Saved as `runs/run-npx-0.2.0.json` and `runs/run-npx-0.2.0.stderr`. The per-vector `results` array is byte-identical to the vendored-runner run from the bolyra checkout (`runs/run-vendored-da3a4ac-0.6.0.json`, command below) and to the prior attempt's `runs/run-0.2.0.json`.

```sh
# C'. Same vectors from a bolyra checkout, no npm install
node <bolyra>/integrations/evc-conformance/bin.js --host "$(command -v node) $W/hut-shim.mjs" --json
# → totals passed=27 failed=1, exit 1
```

Control run on the older set (reproduces the listed result with the same adapter):

```sh
# D. Vector set 0.4.0 via the only other published version
cd "$W/empty" && npx -y @bolyra/evc-conformance@0.1.0 --host "$(command -v node) $W/hut-shim.mjs" --json
# → "vector_set":{"version":"0.4.0","total":27,"selected":27,"sha256":"153eba4c4e9afd413f2f1496ae6eb44dd0aa816bd02eb259e9d13ee6fee1f13a"},"totals":{"passed":27,"failed":0,"skipped":0}, exit 0
```

Observed (prior attempt, same adapter, `runs/run-0.1.0.json`): identical. For vector set 0.5.0 itself, which has no published artifact, the sibling record ran `spec/conformance-runner.js` from bolyra commit `441de467a12ade34677999749e37b199e94975c9` and observed 27/27 (`experiments/evidence-curator-external-impl-rerun-0-6-0/run/result-repo-441de46-0.5.0.json`).

Reference-host runs on the same suite, same day, same machine, for the §11.2 entry:

```sh
# E. Bundled JS reference host (self-test)
node <bolyra>/integrations/evc-conformance/bin.js --json        # → passed=28 failed=0
# F. Rust reference host, built out of tree
cargo build --release --manifest-path <bolyra>/spec/reference-host-rs/Cargo.toml --target-dir "$W/rs-target"
node <bolyra>/integrations/evc-conformance/bin.js --host "$W/rs-target/release/evc-reference-host" --json   # → passed=28 failed=0
```

Observed: 28/28 and 28/28. Saved as `runs/run-js-reference-host-da3a4ac-0.6.0.json` and `runs/run-rust-reference-host-da3a4ac-0.6.0.json`.

## 4. Per-vector result for the independent host, vector set 0.6.0

| # | Vector | Result |
|---|---|---|
| 1 | host-allow-well-behaved | PASS |
| 2 | host-relay-well-behaved-deny | PASS |
| 3 | host-deny-non-json-stdout | PASS |
| 4 | host-deny-multiple-objects | PASS |
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

**The failure, mechanically.** Fixture `unknown-denial-code.js` writes `{"verdict":"deny","code":"quantum_flux_error","message":"not a registry code"}` and exits 0. In `src/evc-host.ts` at 17642a5, `isClosedVerdict()` requires `code` to be a string but does not close it over the §9 registry, so the verdict is accepted and relayed. Direct observation with a one-line fake verifier:

```
$ echo '<§2.1 request>' | HUT_VERIFIER_CMD='["node","-e","process.stdout.write(JSON.stringify({verdict:\"deny\",code:\"totally_made_up\",message:\"m\"}))"]' node hut-shim.mjs
{"decision":"deny","code":"totally_made_up"}
```

The vector requires `{"decision":"deny","failure_class":"schema_invalid"}`. The registry was closed in bolyra `030884b` on 2026-08-26, the same day the implementation's final commit (`17642a5`, 2026-08-26 17:37Z) merged; the pinned commit predates the obligation it fails. The repository's default branch (`main`) still points at `17642a5` as of 2026-09-07, so no later upstream commit exists to re-pin to.

## 5. RFC 7942 §2 field coverage for every §11 entry (verified facts only)

RFC 7942 §2 lists, per implementation: organization; name and/or URL; description; maturity; coverage; version compatibility; licensing; implementation experience; contact; date last updated. Below, each §11 entry with the fields the current text omits, filled only where a pinned source supports the value. "Not stated" marks a field the founder must supply or leave out; nothing here is inferred.

**§11.1 Verifier: `bolyra verify`**
- URL: `https://www.npmjs.com/package/@bolyra/cli` (npm reports version `0.9.0`, license `Apache-2.0`, read 2026-09-07; matches `integrations/cli/package.json` at `da3a4ac`).
- Coverage: verifier side of the contract (§2 request, §3 verdict, §5 stdio framing, §7.1 exit semantics, §9 registry), `zk` and `classical` classes. The verifier-side vector class (`external_verifier`, 10 vectors in set 0.6.0) is exercised in `.github/workflows/ci.yml`; this record did not re-run it.
- Version compatibility: draft-kondoju-evc-01; wire version 1; binding v2.
- Licensing: Apache-2.0.
- Contact: the document author (`viswa@bolyra.ai`, already in the draft header).
- Last updated: 2026-09-07.

**§11.2 Reference hosts (JS and Rust)**
- URL: `https://github.com/bolyra/bolyra/tree/main/spec` (`reference-host.js`, `reference-host-rs/`).
- Coverage: host obligations only (§5.2, §6, §7.2, §7.3, §16); no cryptography. Both pass 28/28 `host_behavior` vectors of set 0.6.0 (runs E and F above, 2026-09-07).
- Version compatibility: draft-kondoju-evc-01, vector set 0.6.0.
- Licensing: Apache-2.0 (repo `LICENSE`; `reference-host-rs/Cargo.toml` `license = "Apache-2.0"`, `publish = false`).
- Contact: the document author.
- Last updated: 2026-09-07.

**§11.3 Independent host: `khandrew1/mcp-use-evc-example`**
- URL: `https://github.com/khandrew1/mcp-use-evc-example`, commit `17642a5efd5e1c42991ab8aa399cd6138f64f635`.
- Organization: individual maintainer; none stated in the repository.
- Coverage: host boundary only, as a library function behind an mcp-use `mcp:tools/call` middleware. 27/27 on vector set 0.5.0 (as listed); **27/28 on vector set 0.6.0, failing `host-deny-unknown-denial-code`** (this record). Requires the adapter in §2 to be driven by the harness; the repository ships no harness entry point.
- Version compatibility: built to the -00 text; predates the -01 registry closure.
- Licensing: **no `LICENSE` file at the pinned commit; `package.json` is `"private": true` with no `license` field; GitHub reports `license: null`.** The RFC 7942 field cannot be filled from the repository. The maintainer's written permission to use the example ("Feel free to use the example repo however you want", mcp-use#1835, cited in `spec/IMPLEMENTER.md` §9) covers listing, not a license grant; state that literally.
- Contact: the repository URL. No email is published in the repository; do not add one.
- Last updated: 2026-09-07.

**§11.4 Hosted verifier (preview)**
- URL: none publishable; the endpoint is access-controlled and named per design partner (`integrations/hosted-verify/README.md`). RFC 7942 permits omitting the URL; the entry should say "no public URL; access-controlled preview" rather than stay silent.
- Coverage: verifier side, `classical` class only; does not verify zero-knowledge proofs (README, "What kind of verifier it is"). This record did not run it.
- Version compatibility: draft-kondoju-evc-01; binding v2.
- Licensing: not applicable to a hosted preview; state "hosted service, no license grant".
- Contact: the document author.
- Last updated: 2026-09-07.

**§11.5 Implementation experience: `mcp_agent_mail_rust`**
- URL: `https://github.com/Dicklesworthstone/mcp_agent_mail_rust`; the relevant file is `crates/mcp-agent-mail-tools/src/proof_gate.rs` (blob `409734ae8424d592eb092398838b48835b22a7bb`, 37,400 bytes, read 2026-09-07); the design thread is issue #183, closed as completed 2026-07-18T14:51:40Z.
- Coverage: an in-process `ProofVerifier` trait with an Ed25519 trust-anchor implementation designed to the v1 boundary; **not a spawned external verifier, and not run against `host_behavior` vectors.** The §11 heading "Implementation experience" is the correct RFC 7942 category; the entry should say explicitly that no conformance run exists.
- Licensing: repository `LICENSE` reads "MIT License (with OpenAI/Anthropic Rider)", copyright Jeffrey Emanuel 2026; GitHub reports SPDX `NOASSERTION`. Quote the file's own header; do not normalize to plain MIT.
- Contact: the repository URL.
- Last updated: 2026-09-07.

## 6. Staged text for §11 (pinned to `spec/` commit `a4f546f`, not applied)

`spec/IMPLEMENTER.md` §9, replace the single table row with:

```
| [`khandrew1/mcp-use-evc-example`](https://github.com/khandrew1/mcp-use-evc-example) | TypeScript, behind mcp-use's `mcp:tools/call` middleware | commit `17642a5`, 2026-08-26; re-run 2026-09-07 | 27/27 `host_behavior`, vector set 0.5.0 (bolyra `441de46`); 27/28 on vector set 0.6.0 (`@bolyra/evc-conformance@0.2.0`), failing `host-deny-unknown-denial-code`: relays an out-of-registry denial code; the registry was closed after this commit. Harness adapter: `standards-autoresearch/experiments/ietf-reviewer-rfc7942-listing-stale-and-incomplete/runs/hut-shim.mjs` (SHA-256 `6fa7a50a…88b8d`). License: none published at the pinned commit. |
```

`spec/draft-kondoju-evc-01.md` §11.3, after "it passes 27 of 27 "host_behavior" vectors of vector set 0.5.0", insert:

```
Against vector set 0.6.0 (published as "@bolyra/evc-conformance" 0.2.0) the same
commit passes 27 of 28; the failing vector is the registry-closure vector added in
this revision, which postdates the commit. Coverage: host boundary only. Licensing:
no license is published at the pinned commit. Contact: the repository URL. Last
updated: 2026-09-07.
```

Each of §11.1, §11.2, §11.4, §11.5: append one sentence per RFC 7942 field from §5 above, using the "Not stated" wording where the source is silent. Apply as a normal spec edit (`git commit -s`; CODEOWNERS gates `spec/`). Re-validation before applying: run C above must still print `"passed":27,"failed":1`.

## 7. Findings not staged here (input to the next Tier 1)

- **Listing reproducibility.** `spec/IMPLEMENTER.md` §9 requires "a harness-green run at a pinned public commit" but not a pinned harness entry point. Every reproduction of the §11.3 row depends on an adapter that lives in neither the implementer's repository nor `spec/`. Candidate: a required "harness entrypoint" column (path plus commit, or adapter checksum).
- **Vector set 0.5.0 has no published artifact.** The row cites a set reachable only from a bolyra git commit. Candidate: cite the bolyra commit in the row, or pin rows to published suite versions only.
- **Implementation-side gap, upstream.** `isClosedVerdict()` at 17642a5 accepts any string as a denial code. This is the implementer's to change; the entity is under an engagement-graph hold and rule 2c applies, so this loop proposes no contact.
- **§11.5 category.** The entry is implementation experience, not a conformant implementation. Counting it toward RFC 7942 "implementations" would overstate; the text should keep it under its current heading and say no run exists.

## 8. Ledger entry

```json
{"id": "interop-run-2026-09-07-mcp-use-evc-example-17642a5-vs-0.6.0-rfc7942-fields",
 "kind": "interop_run",
 "subject": "khandrew1/mcp-use-evc-example host boundary vs @bolyra/evc-conformance@0.2.0 (vector set 0.6.0, 28 host_behavior vectors): 27 passed, 1 failed (host-deny-unknown-denial-code, relays out-of-registry code); control 27/27 on @bolyra/evc-conformance@0.1.0 (vector set 0.4.0) with the same adapter; JS and Rust reference hosts 28/28 same day; RFC 7942 field values for all five draft-kondoju-evc-01 §11 entries checked against pinned sources",
 "pinned_commit": "17642a5efd5e1c42991ab8aa399cd6138f64f635",
 "reproduce_cmd": "W=/tmp/evc-rfc7942 && mkdir -p $W && cd $W && git clone https://github.com/khandrew1/mcp-use-evc-example && git -C mcp-use-evc-example checkout 17642a5efd5e1c42991ab8aa399cd6138f64f635 && (cd mcp-use-evc-example && npm ci --ignore-scripts) && cp <bolyra@da3a4ac>/standards-autoresearch/experiments/ietf-reviewer-rfc7942-listing-stale-and-incomplete/runs/hut-shim.mjs $W/hut-shim.mjs && mkdir -p $W/empty && cd $W/empty && npx -y @bolyra/evc-conformance@0.2.0 --host \"$(command -v node) $W/hut-shim.mjs\" --json   # expect totals passed=27 failed=1, exit 1; adapter sha256 6fa7a50a1cf3ebe18a0bca5a2e673f55f869e732af69e6e977e1918442488b8d",
 "urls": ["https://github.com/khandrew1/mcp-use-evc-example/commit/17642a5efd5e1c42991ab8aa399cd6138f64f635", "https://www.npmjs.com/package/@bolyra/evc-conformance/v/0.2.0", "https://registry.npmjs.org/-/npm/v1/attestations/@bolyra%2fevc-conformance@0.2.0", "https://github.com/bolyra/bolyra/commit/030884b9f48d39770f779e6eeb6174a59ff75247", "https://github.com/Dicklesworthstone/mcp_agent_mail_rust/issues/183", "https://www.rfc-editor.org/rfc/rfc7942#section-2"],
 "rfc7942_ready": false}
```

`rfc7942_ready` is false because the run was performed by the specification's authors, the adapter is pinned in the authors' repository rather than the implementer's, and the §11.3 licensing field cannot be filled from the implementer's repository. The staged text in §6 is listable as maintainer-run evidence with those three facts stated.
