# Reviewer evidence report for an operator-trial bundle

**Status:** design, 2026-10-10. Founder override of the same-day "build nothing" ruling
(`.viswa/decisions/2026-10-10-founder-override-build-evidence-report.md`, private). Time cap: 8 hours.

## 1. Purpose

An operator runs `examples/operator-trial` and hands the bundle directory to a reviewer at their
own company (security, compliance, a customer's vendor-risk team). That reviewer needs to answer
one question: **which of the claims they care about are supported by this bundle, by what, and
which are not.** Today the bundle gives them `receipts.jsonl`, `summary.json`, `signer.json`, a
verify command, and a README paragraph. It does not give them a per-claim answer.

The report is a single printable HTML page (plus a JSON twin with the same findings) generated
from a bundle, using only the published `@bolyra/receipts` verifier and anchors the reviewer
supplies. It is the narrowed candidate A from the 2026-10-03 ruling with the smallest part of C
(claim-to-evidence classification) folded in.

## 2. What the report must and must not do

Acceptance (Codex, 2026-10-10; binding):

1. Every conclusion names its artifact and field (`receipts.jsonl` line n, `payload.decision.allowed`;
   `summary.json` `attempts[1].dispatched`). Absent evidence is reported as absent, never inferred.
2. Signed assertions, unsigned observations, and derived interpretations are visibly distinct.
3. Altered signed payloads fail: a modified receipt line produces FAILED rows, not a softer status.
4. Signer and completeness anchors (expected signer, count, head hash) are **reviewer-established**:
   taken from command-line flags, never silently from `signer.json` or `summary.json`. When an
   anchor is not supplied, the report says which checks are therefore not closed (tail truncation,
   signer identity) rather than filling it in from the bundle.
5. The reviewer can re-verify independently: the report prints the exact `@bolyra/cli` command
   with the anchors it used, and states what altering a receipt will do to that command's output.
6. No claim of endpoint execution, human consent, payee or settlement control, spend limit, or
   production authentication. The trial runs the gateway in dev mode with simulated credentials
   and an ephemeral signer; the report states this on its first screen.

Non-goals: no new receipt schema or field; no change to the trial's bundle format; no hosted
anything; no scoring or grading; no verdict word like "compliant" or "certified"; no network access.

## 3. Inputs

```
npm run report -- --bundle <dir> --signer <0xaddr> [--expect-count <n>] [--expect-head <0xhash>] [--out <dir>]
```

- `--bundle`: a trial bundle directory. Required files: `receipts.jsonl`, `summary.json`.
  `signer.json` and `VERIFY.txt` are read only to be **compared** against the anchors (a mismatch
  is reported; the bundle's own values are never used as anchors).
- `--signer`: required. The address every signature must recover to. If the reviewer has no
  independent source, they pass the value from `signer.json` themselves and the report records
  "anchor source: command line (reviewer-supplied)"; the report cannot tell where they got it and
  says so.
- `--expect-count`, `--expect-head`: optional. Absent → the tail-truncation check is reported as
  **not closed** (status `ABSENT`, note names the missing flag).
- `--out`: output directory; default `./report-out/<bundle basename>/`. The bundle directory is
  never written to.

Exit code: 0 when the report was written, regardless of findings; 2 on unreadable input. The
findings live in the report, not in the exit code, so a FAILED bundle still gets a report.

## 4. Classification

Each finding has exactly one status:

| Status | Meaning | Source allowed |
|---|---|---|
| `SIGNED` | The value is inside a receipt payload whose ES256K signature recovered to the anchored signer and whose payload hash and id recomputed. | `receipts.jsonl` only, and only after the receipt's own verification passed |
| `OBSERVED` | The value is recorded by the trial host but not signed by anything. | `summary.json`, `VERIFY.txt`, `signer.json` |
| `DERIVED` | A conclusion the report computes from SIGNED or OBSERVED values; the row names the inputs and the rule. | computed |
| `ABSENT` | The bundle holds no evidence for this claim. The row says what would be needed. | none |
| `FAILED` | Evidence is present and verification of it failed, or two sources contradict. | any |

A receipt that fails signature, hash, or id verification contributes **no** `SIGNED` rows; every
claim that would have come from it is `FAILED` with the issue code.

## 5. The claim list (fixed in code; v1)

Bundle-level:

| # | Claim | Expected status on a clean dry-run bundle | Evidence |
|---|---|---|---|
| B1 | Each receipt's signature recovers to the anchored signer; payload hash and id recompute | `SIGNED` per receipt | `receipts.jsonl` line n, `signature.{signer,payloadHash,value}`, `id` |
| B2 | Receipts form one intact hash chain (genesis, seq, prevReceiptHash, receiptHash) | `SIGNED` | `verifyReceiptChain` result, issue codes on failure |
| B3 | Chain is complete (count and head match reviewer anchors) | `SIGNED` with anchors; `ABSENT` without | `--expect-count`, `--expect-head`; `summary.json` `receiptCount`/`headReceiptHash` shown as `OBSERVED` for comparison only |
| B4 | Signer in `signer.json` equals the anchor | `OBSERVED` (match) / `FAILED` (mismatch) | `signer.json` `signer` |
| B5 | Proof verification mode | `ABSENT`: the bundle does not record it; operator-trial 0.1.0 runs the gateway with `devMode: true` and static simulated credentials (source: `examples/operator-trial/src/gateway-config.ts`) | note only |
| B6 | Signer key is ephemeral to this run | `OBSERVED` | `signer.json` `ephemeral`, `summary.json` `note` |

Per attempt n (1, 2, 3), each row linked by `summary.json` `attempts[n].receiptId` ↔ receipt `id`:

| # | Claim | Expected on clean dry-run | Evidence |
|---|---|---|---|
| A1 | The summary's receipt id names a receipt in the log | `DERIVED` (link holds) / `FAILED` | `attempts[n].receiptId` vs `id` |
| A2 | Decision (allow / deny) | `SIGNED` | `payload.decision.allowed` |
| A3 | Decision reason text | `SIGNED` (text) | `payload.decision.reasonCode` |
| A4 | Action name, method, host, path | `DERIVED` from the ` | action=` suffix convention in `reasonCode` (operator-trial convention, not a receipt schema field); `OBSERVED` from `summary.json` `action`; `FAILED` if they disagree | both |
| A5 | Acting subject (DID, commitments) | `SIGNED`; note: dev DID from a simulated credential; cryptographic identity, not a person or legal entity | `payload.subject.*` |
| A6 | Permission bitmask the decision evaluated | `SIGNED` | `payload.decision.permissionBitmask` |
| A7 | Permission the action required | `ABSENT` from receipts (host configuration, unsigned); the denial reason text may state it (`SIGNED` text, `DERIVED` meaning) | note |
| A8 | Nonce; replay relation to attempt 1 | `SIGNED` nonce; attempt 3: `DERIVED` "same nonce as attempt 1 and denied" | `payload.proof.nonce` |
| A9 | Human/agent proofs verified | `ABSENT` (hashes are signed; verification disabled in dev mode; see B5) | `payload.proof.*Hash` listed as `SIGNED` hashes only |
| A10 | Request dispatched to the endpoint | `OBSERVED` | `attempts[n].dispatched` |
| A11 | Upstream HTTP status | `OBSERVED` | `attempts[n].upstreamStatus` |
| A12 | Decision was signed before dispatch | `ABSENT` (no ordering evidence in the bundle; the host's code verifies the persisted receipt before dispatching, but the bundle does not record that) | note |
| A13 | The endpoint executed the action | `ABSENT` | note: never claimed |
| A14 | A human consented to this action | `ABSENT` | note |
| A15 | A mandate or spend limit bounded this action | `ABSENT` (tier mask only; no cumulative budget; auth receipt, not commerce) | note |
| A16 | Who receives funds / controls a settlement address | `ABSENT` | note |
| A17 | Production credentials or registry were used | `ABSENT`; see B5 | note |

Expected statuses are what the tests assert against the committed dry-run fixture.

## 6. Output

- `report.html`: self-contained (inline CSS, no scripts, no external resources), prints to A4/Letter.
  Order: (1) what this report is and is not, dev-mode disclosure; (2) anchors used and their source;
  (3) verification results B1–B6; (4) per-attempt tables A1–A17; (5) "re-verify yourself": the exact
  CLI command, and "change any byte of a receipt line and re-run: expect `FAIL [signature-invalid]`";
  (6) legend for the five statuses.
- `report.json`: `{ tool, generatedAt, bundle, anchors, findings: [{id, claim, status, evidence:[{file, path, line?}], note}] }`.
  The HTML is rendered from this object; tests assert on the JSON.

Nothing from the bundle is copied into the report except the fields named in §5; header values,
bodies, and credentials are not in the bundle to begin with, and the report never reads `trial.yaml`.

## 7. Placement and files

Inside `examples/operator-trial` (shares `@bolyra/receipts 0.11.0`, the CI job, and the README):

- `src/report/classify.ts`: bundle → findings (pure; no I/O beyond what it is handed).
- `src/report/render.ts`: findings → HTML string.
- `src/report/cli.ts`: flags, file reads, writes.
- `test/report-fixtures/dry-run/`: a committed dry-run bundle (its signer is ephemeral and public by
  construction; nothing secret).
- `test/report.classify.test.ts`, `test/report.render.test.ts`, `test/report.cli.test.ts`.
- README: a "Produce a reviewer report" section after "The bundle"; CI job runs the report on the
  fresh dry-run bundle.

## 8. Tests (written first)

1. Clean fixture + correct anchors → every expected status in §5 matches.
2. One receipt line altered (one hex digit in `signature.value`) → that receipt's B1 `FAILED`
   `signature-invalid`, B2 `FAILED`, all A-rows for that attempt `FAILED`, other attempts unchanged.
3. Tail-truncated log (3 → 2 lines) with anchors → B3 `FAILED` `count-mismatch`/`head-hash-mismatch`;
   without anchors → B2 `SIGNED`, B3 `ABSENT`, note names the flags.
4. `summary.json` `attempts[0].receiptId` edited → A1 `FAILED`, A2–A9 for that attempt still `SIGNED`
   from the receipt the log actually holds, labelled as unlinked.
5. `signer.json` edited → B4 `FAILED`; B1 unchanged (anchor wins).
6. Wrong `--signer` → every B1 `FAILED`, no `SIGNED` row anywhere.
7. Render: HTML contains no `<script`, no `http://`/`https://` other than in the verify command's
   package name, every finding id appears once, status legend present.
8. CLI: missing `--signer` exits 2 with usage; bundle dir untouched after a run (mtime/listing equal).

## 9. Out of scope, explicitly

Scoring; a hosted viewer; reading real (non-dry-run) bundles differently from dry-run ones (same
code path; `dryRun` is shown as `OBSERVED`); any change to `@bolyra/receipts`, `@bolyra/cli`, or the
trial's bundle writer; conformance vectors; the G1–G6 gap note.
