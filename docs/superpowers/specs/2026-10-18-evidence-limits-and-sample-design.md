# Evidence-limits table and published simulated sample

Date: 2026-10-18. Ruling: Codex build-next pick A (cap 3 hours, both halves, table first). Completes the collateral authorized on 2026-10-10; not a product build. No new viewer, adapter, generator feature or redesign.

## Goal

A reviewer who reads the acceptance-exercise offer on bolyra.ai can, without cloning or installing anything, (1) read what the evidence report establishes and what it never establishes, and (2) open the actual deliverable rendered from the committed dry-run fixture, labeled SIMULATED, with its JSON and exact input bundle and a copy-paste way to reproduce it.

## 1. Evidence-limits table (landing/index.html)

Placement: inside `#acceptance-exercise`, after the deliverable paragraph. Markup: a `<table class="limits-table">` with three columns and a short input-scope paragraph under it. New CSS class (`.limits-table`, ~10 lines) because `.comparison-table` colors its last column green, which would read as endorsement.

Columns: **The report marks a finding** · **That establishes** · **It does not establish**. Rows map to the statuses the tool emits (`examples/operator-trial/src/report/claims.ts`); every positive claim corresponds to a check the tool performs on the fixture today:

| Status | Establishes | Does not establish |
|---|---|---|
| SIGNED (decision, reason, simulated subject identifiers, permission mask, nonce, proof hashes: claims A2, A3, A5, A6, A8a, A9a) | an authenticated assertion by whoever holds the anchored signing key | that the assertion is true; who holds the key (the signer anchor is reviewer-supplied, the bundle cannot prove it); that any subject was authenticated |
| DERIVED (signature recovery and payload hash, intact hash chain, count and head against the supplied anchors, recorded action vs signed descriptor, replayed nonce denied: B1, B1a, B2, B3a, B3b, B4, A1, A4b, A4c, A7b, A8b) | the receipts are one unaltered chain, internally consistent, matching the anchors the reviewer typed | completeness beyond those anchors; that the decision was signed before dispatch (A12 is ABSENT in this tool); that authorization preceded whatever the endpoint did |
| OBSERVED (host-recorded action, dispatch attempt, upstream status, dry-run and ephemeral-signer flags, host counts: A4a, A10, A11, B4b, B6, B7, B8a, B8b) | what the trial host wrote down, signed by nothing | that the endpoint executed anything; that the recorded configuration was the enforced one |
| ABSENT (always: execution A13, human consent A14, mandate or spend limit A15, who receives funds or controls a settlement address A16, production credentials or registry A17, proof verification A9b/B5, required permission A7a) | nothing; the row is printed so the gap is visible instead of omitted | anything |
| FAILED (a check failed or two sources contradict) | shown in place, never filtered; an altered receipt line fails signature verification | — |

Input-scope paragraph (verbatim intent, final wording in the PR): the report reads exactly one input today, an operator-trial bundle (`receipts.jsonl`, `summary.json`, `signer.json`, `VERIFY.txt`). A separate verifier in `examples/audit-log-evidence` checks one approval bound to one exact action through an audit-log-shaped export (JSONL in the WorkOS Audit Logs metadata shape; CSV export fidelity tested in a WorkOS staging environment for seven values). Neither reads an arbitrary audit export; an exercise on another export shape starts with the feasibility check, which is why feasibility is agreed before signing.

Offer-block changes: the existing "Simulated sample" paragraph now points at the published sample first and the README second; a secondary button "View the simulated sample report" (`/evidence-report-sample`) sits next to the mailto CTA. The three existing `verify.sh` root needles stay intact.

## 2. Published simulated sample

Generator `landing/evidence-sample/build.mjs` (Node 20, no dependencies):

1. Reads anchors from the committed fixture `examples/operator-trial/test/report-fixtures/dry-run`: signer from `signer.json`, head from `summary.json`, count = number of receipt lines (3). These are the same values the fixture's `VERIFY.txt` carries; the banner says they were copied from the bundle, so they establish consistency only.
2. Runs the shipped report tool unchanged: `npm run report --silent -- --bundle <fixture> --signer … --expect-count 3 --expect-head … --out <tmp>` in `examples/operator-trial` (fails with a clear message if `node_modules` is missing).
3. Writes `landing/evidence-report-sample.html` = a SIMULATED banner injected immediately after `<body>` plus the generated report byte-for-byte (asserted: the original report HTML is a suffix of the output; `<title>` prefixed with "SIMULATED sample: "). Banner: label SIMULATED SAMPLE; one paragraph (generated from the committed dry-run fixture by `@bolyra/operator-trial report 0.1.0` with `@bolyra/receipts 0.11.0`, CLI pin 0.9.0; simulated credentials, ephemeral signer, no proof verification, no real endpoint; shows the deliverable's form and limits, not a customer run; anchors copied from the bundle); links to `report.json`, the four bundle files, the fixture directory on GitHub, the offer block; the fixture pin as `sha256(receipts.jsonl)`; the regenerate command. Inline `<style>` only, no scripts (live CSP permits inline styles, forbids nothing we need).
4. Writes `landing/evidence-report-sample/report.json` and copies the four fixture files to `landing/evidence-report-sample/bundle/`.
5. `--check`: regenerates into a temp dir and compares against the committed files after normalizing the `generatedAt` ISO timestamp in both HTML and JSON; exit 1 naming each drifting file.

Deploy (`landing/deploy.sh`): existence checks for the new files; pre-upload gate `npm ci` in `examples/operator-trial` then `node landing/evidence-sample/build.mjs --check`; index must contain `href="/evidence-report-sample"`. Uploads: the page at `evidence-report-sample.html` and `evidence-report-sample`; `evidence-report-sample/report.json` as `application/json`; `evidence-report-sample/bundle/{receipts.jsonl,VERIFY.txt}` as `text/plain; charset=utf-8` and `{summary.json,signer.json}` as `application/json`; cache-control 300 like the rest; the CloudFront invalidation path list gains the six new paths (invalidation is an explicit list, not `/*`).

Verify (`landing/verify.sh`): `/evidence-report-sample` returns 200 and contains `SIMULATED SAMPLE`, `Reviewer evidence report`, `FAILED: 0` and `npx @bolyra/cli@`; `/evidence-report-sample/report.json` returns 200 and parses, with `findings` non-empty and zero `FAILED`; `/evidence-report-sample/bundle/receipts.jsonl` returns 200 with three lines; root needles add `href="/evidence-report-sample"` and `authorization preceded`.

CI (`.github/workflows/ci.yml`, operator-trial job): after `npm ci`, run `node ../../landing/evidence-sample/build.mjs --check` so the committed sample cannot drift from the tool.

README (`examples/operator-trial/README.md`): one sentence under "Produce a reviewer report" pointing at the published sample and stating it is simulated.

## Acceptance (Codex, 2026-10-18)

- Table distinguishes authenticated assertion from established fact, and chain validity from proof that authorization preceded execution; explicitly excludes execution, human consent, payee control and production authorization enforcement; positive claims correspond to checks the tool performs.
- Input scope names the operator-trial bundle and the tested #209 export shape with their own verification paths; never implies arbitrary export ingestion.
- One click from the offer opens the #207 HTML report, no login or install, labeled SIMULATED prominently; JSON and exact input bundle alongside; missing and failed checks visible.
- Pinned source (fixture hash + tool versions), setup instructions and a copy-paste re-verification command that reproduces the published findings (`--check` proves it on every deploy and in CI).
- Stop after the static publication. No new features. Traffic is not a criterion.

## Codex spec review (2026-10-18): APPROVE WITH EDITS, all applied

1. DERIVED narrowed to "the named check passed over its stated inputs"; A7b is the parsed required mask, A8b is a repeated nonce met by a signed deny; production replay/permission enforcement explicitly excluded.
2. A12 added to the always-ABSENT list; FAILED row says changing `payload.decision.allowed` without re-signing fails signature verification and an id-only edit fails the report-local id check; banner and offer copy say "built-in localhost echo endpoint, no customer endpoint".
3. Input scope says "one supported bundle format"; #209 described as a separate verifier over synthetic JSONL plus retained receipt and action artifacts; its staging test preserved seven metadata string occurrences through CSV, provides no CSV ingestion and establishes no human consent.
4. HTML invariant restated and enforced in `compose()`: stripping the banner block and the title prefix restores the original report bytes exactly.
5. Reproduction pins commit `93239a88` (last commit touching the operator-trial sources, lockfile and fixture; `deploy.sh` refuses to ship if any of those paths changed since; the README is prose and not pinned), a sha256 manifest over the report sources and fixture, Node 20 setup, `npm ci`, and the literal report command with anchors; the banner says the CLI verify-chain command does not reproduce the report's findings; versions come from report metadata.
6. `--check` compares all committed artifacts, normalizes only `generatedAt`, asserts the baseline SIGNED 18 / OBSERVED 12 / DERIVED 21 / ABSENT 27 / FAILED 0, the CLI pin against `VERIFY.txt`, and `VERIFY.txt` signer/count/head against the other bundle files.
7. Seven upload and invalidation paths; root-absolute download links; `verify.sh` byte-compares both HTML aliases and the five downloads against the committed files and checks the JSON has findings and zero FAILED.

## Out of scope

Viewer or generator features, an export adapter, redesign, navigation changes, analytics, any hosted service.
