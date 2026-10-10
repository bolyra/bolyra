# Reviewer evidence report for an operator-trial bundle

**Status:** design, 2026-10-10, Codex plan review R1 APPROVE WITH EDITS (9) and R2 APPROVE WITH EDITS (5), R3 APPROVE WITH EDITS (1), all applied. Founder
override of the same-day "build nothing" ruling (private decision record). Time cap: 8 hours.

## 1. Purpose

An operator runs `examples/operator-trial` and hands the bundle directory to a reviewer at their
own company (security, compliance, a customer's vendor-risk team). That reviewer needs to answer
one question: **which of the claims they care about are supported by this bundle, by what, and
which are not.** Today the bundle gives them `receipts.jsonl`, `summary.json`, `signer.json`, a
verify command, and a README paragraph. It does not give them a per-claim answer.

The report is a single printable HTML page (plus a JSON twin with the same findings) generated
from a bundle, using only the published `@bolyra/receipts` verifier plus one report-local check,
and anchors the reviewer supplies. It is the narrowed candidate A from the 2026-10-03 ruling with
the smallest part of C (claim-to-evidence classification) folded in.

## 2. What the report must and must not do

Acceptance (Codex, 2026-10-10; binding):

1. Every conclusion names its artifact and field (`receipts.jsonl` line n, `payload.decision.allowed`;
   `summary.json` `attempts[1].dispatched`). Absent evidence is reported as absent, never inferred.
2. Signed assertions, unsigned observations, and derived interpretations are visibly distinct.
3. Altered signed payloads fail: a modified payload produces FAILED rows, not a softer status.
4. Signer and completeness anchors (expected signer, count, head hash) are **reviewer-supplied**:
   taken from command-line flags, never silently from `signer.json` or `summary.json`. The report
   states, verbatim: *"Values were supplied through command-line flags. Their independence from
   this bundle is unknown. Copying signer/count/head from bundle files establishes consistency with
   those supplied values; it does not establish signer identity or independently establish
   completeness. External assurance requires a separately trusted signer reference and checkpoint."*
5. The reviewer can re-verify independently: the report prints the exact `@bolyra/cli` command
   built from the validated flags (shell-quoted paths; `VERIFY.txt` is never executed or parsed as
   a command), and states exactly what altering a payload field does to that command's output.
6. No claim of endpoint execution, human consent, payee or settlement control, spend limit,
   subject authentication, or production authentication. The shipped operator-trial 0.1.0 runs
   the gateway in dev mode with simulated credentials and an ephemeral signer; the report states
   this on its first screen **as a property of the shipped implementation**, not as something this
   bundle proves about itself.

Non-goals: no new receipt schema or field; no change to the trial's bundle writer, to
`@bolyra/receipts`, or to `@bolyra/cli`; no hosted anything; no scoring or grading; no verdict
word like "compliant" or "certified"; no network access; no new example directory or package.

## 3. Inputs

```
npm run report -- --bundle <dir> --signer <0xaddr> [--expect-count <n>] [--expect-head <0xhash>] [--out <dir>]
```

- `--bundle`: a trial bundle directory. Required files: `receipts.jsonl`, `summary.json`.
  `signer.json` and `VERIFY.txt` are read only to be **compared** against the anchors (a mismatch
  is reported; the bundle's own values are never used as anchors). `VERIFY.txt` is treated as
  text: the report shows whether it contains the anchored signer string; it is not parsed further.
- `--signer`: required. The address every signature must recover to.
- `--expect-count`, `--expect-head`: optional and **independent**. Each supplied anchor closes its
  own check (either one detects simple tail truncation; count alone does not bind content). A
  missing flag makes only that check `ABSENT`, with the flag named.
- `--out`: output directory; default `./report-out/<bundle basename>/`. Must not resolve inside
  the bundle directory (rejected, exit 2). The bundle directory is never written to.

Exit code: 0 when the report was written, regardless of findings; 2 on unreadable or rejected
input. Findings live in the report, not in the exit code, so a FAILED bundle still gets a report.

Malformed input (a receipt line that is not JSON, or not a receipt) is a `FAILED` finding naming
the **physical line number**; the remaining lines are still processed.

## 4. Classification

Each finding has exactly one status:

| Status | Meaning | Source allowed |
|---|---|---|
| `SIGNED` | An **authenticated signer assertion, not independently established truth**: the value is inside a receipt payload whose ES256K signature recovered to the anchored signer and whose payload hash recomputed. | `receipts.jsonl` only, and only after that receipt's signature + payload-hash check passed |
| `OBSERVED` | An **unsigned host assertion**: recorded by the trial host, signed by nothing. | `summary.json`, `VERIFY.txt`, `signer.json` |
| `DERIVED` | A conclusion the report computes from SIGNED or OBSERVED values, reviewer anchors, or a named check; the row names its inputs and the rule. | computed |
| `ABSENT` | No supporting evidence for this claim in the bundle. The row says what would be needed. | none |
| `FAILED` | Evidence is present and a named check on it failed, or two sources contradict. | any |

Failure propagation:

- A receipt whose **signature or payload hash** fails contributes no `SIGNED` rows; every claim
  that would have come from its payload is `FAILED` with the issue code.
- A **chain** failure (`prev-hash-mismatch`, `seq-mismatch`, `genesis-mismatch`, `chain-restart`),
  an **id** failure, or a **convenience-hash** failure (`receipt-hash-mismatch`) can coexist with an
  authentic payload: the payload's `SIGNED` rows stay `SIGNED`; the chain/id/hash finding is
  `FAILED`; and every `DERIVED` finding that depends on the failed check is `FAILED`.
- A cross-receipt `DERIVED` finding (for example, A8 replay) is `FAILED` when either dependency
  is `FAILED`.
- Independent `OBSERVED` and `ABSENT` findings keep their status whatever happens to receipts.

Report-local id check (outside `@bolyra/receipts` and `@bolyra/cli` coverage, stated as such in
the report): after the payload-hash check, `id` must equal `signature.payloadHash.slice(0, 18)`.
The published verifier does not check `id` and the chain hash excludes it, so an id-only edit
passes anchored verification; the report therefore checks it itself. Attempt linking (A1)
requires a valid **and unique** id.

## 5. The claim list (fixed in code; v1)

Expected statuses are what the tests assert against the committed dry-run fixture.

Bundle-level:

| # | Claim | Expected on a clean dry-run bundle | Evidence |
|---|---|---|---|
| B1 | Each receipt's signature recovers to the anchored signer and its payload hash recomputes | `DERIVED` per receipt (named check: `verifyReceipt(receipt, anchor)`); `FAILED` with code | `receipts.jsonl` line n, `signature.{signer,payloadHash,value}` |
| B1a | Each receipt's `id` equals the first 18 characters of its payload hash and is unique in the log | `DERIVED` (report-local check) / `FAILED` | `id`, `signature.payloadHash` |
| B2 | Receipts form one intact hash chain (genesis, seq, prevReceiptHash, stored receiptHash) | `DERIVED` (named check: `verifyReceiptChain`); `FAILED` with codes | chain issue list |
| B3a | Receipt count matches the supplied count checkpoint | `DERIVED` with `--expect-count`; `ABSENT` without | flag; `summary.json` `receiptCount` shown `OBSERVED` for comparison only |
| B3b | Head hash matches the supplied head checkpoint | `DERIVED` with `--expect-head`; `ABSENT` without | flag; `summary.json` `headReceiptHash` shown `OBSERVED` for comparison only |
| B4 | Signer in `signer.json` equals the supplied signer anchor | `DERIVED` (match) / `FAILED` (mismatch) | `signer.json` `signer` |
| B5 | Proof verification mode | `ABSENT`: the bundle does not record it. Note: the shipped operator-trial 0.1.0 runs the gateway with `devMode: true` and static simulated credentials (`examples/operator-trial/src/gateway-config.ts`); this is a property of the implementation, not authenticated provenance of this bundle | note only |
| B6 | Host reports an ephemeral signer | `OBSERVED` (no key-destruction claim follows) | `signer.json` `ephemeral`, `summary.json` `note` |
| B7 | Host-reported dry-run flag (the actual boolean is displayed; the built-in-echo explanation appears only when `true`; the same renderer accepts non-dry-run bundles) | `OBSERVED` | `summary.json` `dryRun` |

Per attempt n (1, 2, 3; the record is `summary.json` `attempts[n-1]`). Attribution (A1) holds
only when `attempts[n-1].receiptId` equals exactly one receipt's valid id (B1a) **and no other
attempt references that receipt**. A failed A1 makes that attempt's receipt-backed findings (A2,
A3, A4b, A4c, A5, A6, A8a, A9a, and A7b/A8b where emitted) `FAILED` without assigning payload
values; A8b additionally depends on successful A1 for attempts 1 and 3. **Receipts that no
attempt links to keep their own B1/B1a findings and their authentic payload findings under an
"unattributed receipt" heading; a link is never inferred by position.**

| # | Claim | Expected on clean dry-run | Evidence |
|---|---|---|---|
| A1 | The summary's receipt id names exactly one valid receipt in the log | `DERIVED` / `FAILED` (no match, duplicate, or invalid id) | `attempts[n-1].receiptId` vs `id` |
| A2 | Decision (allow / deny) | `SIGNED` | `payload.decision.allowed` |
| A3 | Decision reason text | `SIGNED` (text) | `payload.decision.reasonCode` |
| A4a | Action name, method, host, path as the host recorded them | `OBSERVED` | `summary.json` `action` |
| A4b | Action descriptor parsed from the signed reason text (` \| action=` suffix: an operator-trial convention, not a receipt schema field) | `DERIVED` from A3 | `reasonCode` |
| A4c | A4a and A4b agree | `DERIVED` / `FAILED` | both |
| A5 | Signer-asserted simulated subject identifiers; subject authentication is not established | `SIGNED` (identifiers only) | `payload.subject.*` |
| A6 | Recorded permission bitmask | `SIGNED`. Note on attempt 3: the signed `0` is the gateway's failure default (replay is rejected before tool policy runs), not evidence that permissions were evaluated | `payload.decision.permissionBitmask` |
| A7a | Permission the host configured as required | `ABSENT` from the bundle (host configuration, unsigned) | note |
| A7b | Required mask as reported in the denial text. **Emitted for attempt 2 only** | `DERIVED` from A3 (reported, not the enforced configuration); `ABSENT` if the text carries no mask | `reasonCode` |
| A8a | Nonce | `SIGNED` | `payload.proof.nonce` |
| A8b | Attempt 3 presented attempt 1's nonce and was denied. **Emitted for attempt 3 only** | `DERIVED` from A8a of attempts 1 and 3 plus A2 of attempt 3; `FAILED` if any dependency (including A1 of attempt 1 or 3) failed | both receipts |
| A9a | Proof hashes | `SIGNED` (hashes only) | `payload.proof.*Hash`, `publicSignalsHash` |
| A9b | Human/agent proofs were verified | `ABSENT` (verification disabled in dev mode; see B5) | note |
| A10 | Host reports invoking fetch toward the endpoint; delivery and execution unproven | `OBSERVED` | `attempts[n-1].dispatched` |
| A11 | Upstream HTTP status | `OBSERVED` when a status is recorded (attempt 1); `ABSENT` when `null` (attempts 2, 3) | `attempts[n-1].upstreamStatus` |
| A12 | Decision was signed before dispatch | `ABSENT` (no ordering evidence in the bundle; the host's code verifies the persisted receipt before dispatching, but the bundle does not record that) | note |
| A13 | The endpoint executed the action | `ABSENT` | note: never claimed |
| A14 | A human consented to this action | `ABSENT` | note |
| A15 | A mandate or spend limit bounded this action | `ABSENT` (tier mask only; no cumulative budget; auth receipt, not commerce) | note |
| A16 | Who receives funds / controls a settlement address | `ABSENT` | note |
| A17 | Production credentials or registry were used | `ABSENT`; see B5 | note |

## 6. Output

- `report.html`: self-contained (inline CSS, no scripts, no external resource loads: no `<script>`,
  no `<link>`, no `<img src>`, no `@import`, no `url(`), prints across as many pages as needed;
  plain styling. Every value copied from the bundle is HTML-escaped. Order: (1) what this report
  is and is not, dev-mode disclosure as in §2.6; (2) anchors used, with the §2.4 wording verbatim;
  (3) verification results B1–B7; (4) per-attempt tables A1–A17, then unattributed receipts if any;
  (5) "re-verify yourself": the exact CLI command built from the validated flags, always pinned to
  the trial's `CLI_VERSION` (`npx @bolyra/cli@0.9.0 …`, never an unversioned package), and *"Change
  `payload.decision.allowed` in any receipt line without re-signing and re-run: expect
  `FAIL line <n>: [signature-invalid]` for that line, possibly with additional chain failures. The
  report's id check (B1a) is not part of the CLI's output."*; (6) legend for the five statuses.
- `report.json`: `{ tool, generatedAt, bundle, anchors, findings: [{id, attempt?, claim, status, evidence:[{file, path, line?}], note, inputs?}] }`.
  The HTML is rendered from this object; tests assert on the JSON.

Nothing from the bundle is copied into the report except the fields named in §5; header values,
bodies, and credentials are not in the bundle to begin with, and the report never reads `trial.yaml`.

## 7. Placement and files

Inside `examples/operator-trial` (shares `@bolyra/receipts 0.11.0`, the CI job, and the README):

- `src/report/classify.ts`: parsed bundle + anchors → findings (pure).
- `src/report/render.ts`: findings → HTML string (one renderer over the JSON).
- `src/report/cli.ts`: flags, file reads, writes, `--out` rejection.
- `test/report-fixtures/dry-run/`: a committed dry-run bundle (its signer is ephemeral and public by
  construction; nothing secret).
- `test/report.classify.test.ts`, `test/report.render.test.ts`, `test/report.cli.test.ts`.
- README: a "Produce a reviewer report" section after "The bundle"; CI job runs the report on the
  fresh dry-run bundle after `npm run trial -- --dry-run`.

## 8. Tests (written first)

1. Clean fixture + all anchors → every expected status in §5 matches.
2. Signed-payload mutation (`payload.decision.allowed` flipped, line 1) → B1 `FAILED`
   `signature-invalid` for that receipt; receipt 1's A2, A3, A4b, A4c, A5, A6, A8a and A9a are
   `FAILED`; attempt 3's A8b is `FAILED`; B2 `FAILED`; other receipts' payload rows unchanged;
   independent `OBSERVED` and `ABSENT` rows (A4a, A7a, A9b, A10, A11, A12–A17) remain unchanged.
3. Id-only mutation (one hex digit of `id`, line 2) → B1 `DERIVED` (still verifies), B1a `FAILED`,
   A1 for attempt 2 `FAILED`, attempt 2's receipt-backed rows `FAILED` with no values, that receipt
   listed as unattributed with its payload rows `SIGNED`.
4. Convenience-hash mutation (`receiptHash`, line 3) → B1 `DERIVED`, B2 `FAILED`
   `receipt-hash-mismatch`, payload rows `SIGNED`.
5. Tail-truncated log (3 → 2 lines): with both anchors → B3a and B3b `FAILED`; with only
   `--expect-count` → B3a `FAILED`, B3b `ABSENT`; with only `--expect-head` → B3a `ABSENT`, B3b
   `FAILED`; without either → B2 `DERIVED`, B3a/B3b `ABSENT` naming the flags; attempt 3's A1 and
   receipt-backed rows `FAILED`, A8b `FAILED`.
6. `summary.json` `attempts[0].receiptId` pointing at a nonexistent id → A1 `FAILED`; attempt 1's
   receipt-backed rows `FAILED` with no values; A8b `FAILED`; the real receipt 1 appears as
   unattributed with `SIGNED` payload rows; no positional re-link.
7. Duplicate link (two attempts naming the same receipt id) → both A1 `FAILED`, both attempts'
   receipt-backed rows `FAILED`, both receipts unattributed with `SIGNED` payload rows.
8. `signer.json` edited → B4 `FAILED`; B1 unchanged.
9. Wrong `--signer` → every B1 `FAILED`; no `SIGNED` row anywhere.
10. Malformed line (non-JSON at physical line 2) → a `FAILED` finding naming line 2; lines 1 and 3
    still classified.
11. Render: no executable markup or external resource loads (assert on `<script`, `<link`, `<img`,
    `@import`, `url(`, `on[a-z]+=` attributes); a bundle value containing `<img onerror=…>` is
    escaped; every finding id appears exactly once; §2.4 wording present verbatim; legend present.
12. CLI: missing `--signer` → exit 2 and usage; `--out` inside the bundle → exit 2; bundle listing
    and mtimes identical after a run; both output files written.

## 9. Cut order if the 8-hour cap is hit

Cut, in this order: print styling beyond page breaks; `VERIFY.txt` comparison (B4 keeps
`signer.json`); decorative formatting or explanatory prose in the unattributed-receipt section
(its findings, including `SIGNED` payload rows, stay). Never cut: tests 1–10, the id check, the
§2.4 wording, the escaping.

## 10. Out of scope, explicitly

Scoring; a hosted viewer; treating real (non-dry-run) bundles differently from dry-run ones (same
code path; `dryRun` is B7); any change to `@bolyra/receipts`, `@bolyra/cli`, or the trial's bundle
writer; conformance vectors; the G1–G6 gap note.
