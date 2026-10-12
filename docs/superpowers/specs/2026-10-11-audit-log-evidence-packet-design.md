# Preserving approval-to-action evidence through an audit-log export

**Status:** design, 2026-10-11 (one-day scope). Synthetic and reproducible; nothing here is a customer
deployment or a claim about any vendor's product.

## 1. Question

A B2B SaaS vendor records that a human approved an AI-agent tool call, then the agent executes it. The
vendor's audit-log product exports events as rows (action, occurred_at, actor, targets, context, metadata).
A customer's reviewer receives the export. What in that export can the reviewer verify *without trusting
the exporter*, and what can they not?

This packet shows one approval bound to one exact action, carried through an audit-log-shaped export, and
verified offline with published Bolyra tooling. It then alters the executed arguments and shows the check
fail. It is written for a reviewer and for an audit-log product team; it names no vendor's internals.

## 2. Artifacts (all committed under `examples/audit-log-evidence/fixtures/`, regenerable byte-for-byte)

| File | Signed? | Content |
|---|---|---|
| `approval-receipt.json` | **signed** (ES256K, `@bolyra/receipts`) | one `bolyra.auth` receipt with signed `decision.allowed === true` whose `decision.reasonCode` carries exactly `approved \| action_digest=<64 hex> \| tool=<server>.<tool>` (an **example-specific convention** in the free-text reason field, not a receipt schema field; the verifier rejects a missing, malformed, or duplicate digest entry) |
| `action.json` | unsigned | the synthetic call the signer asserts was approved: `{ tenant, server, tool, resource: { type, id }, arguments }`; `action_digest = sha256(canonicalize(action))` using the receipts package's JCS canonicalizer. Tenant and resource are inside the digested action and mapped to the export's actor/target fields |
| `execution.json` | unsigned | the host's record of the dispatched call: same `action`, `receipt_id`, `executed_at`, `status` |
| `export.jsonl` | unsigned | synthetic audit-log-shaped JSONL with fields mapped to WorkOS's public documentation (not a tested WorkOS export): two events: `tool.approval_resolved` (actor = approver; targets = tool, ticket; metadata = `action_digest`, `receipt_id`, `receipt_hash`, `signer`) and `tool.executed` (actor = agent; metadata = `action_digest`, `receipt_id`) |
| `signer.json` | unsigned | the synthetic signer address and the fixed, published synthetic private key (labelled synthetic; never reuse) |
| `tampered/execution-altered-args.json` | unsigned | same as `execution.json` with the reply body changed |

The export event shape follows the public documentation of WorkOS Audit Log events (action, occurred_at,
actor{type,id,name}, targets[{type,id,name}], context, metadata). WorkOS documents metadata limits of 50
keys, 40-character key names and 500-character values (workos.com/docs/audit-logs/metadata-schema), which
is why the export carries the digest, receipt id, receipt hash and signer (each under 500 characters) and
the signed receipt itself is a retained artifact joined by id and hash. Verification therefore needs the
export **plus** the retained receipt and action artifacts.

## 3. Verification procedure (offline; `npm run verify`)

Inputs: the fixtures directory and `--signer <address>` (reviewer-supplied; `signer.json` is compared, not
used as the anchor). Checks, each reported with the five statuses from the reviewer evidence report:

| # | Check | Status on clean fixtures | Tool |
|---|---|---|---|
| V1 | receipt signature recovers to the anchored signer; payload hash recomputes; signed `decision.allowed` is true | DERIVED | `verifyReceipt` (`@bolyra/receipts`), also `npx -p @bolyra/receipts bolyra-receipt-verify approval-receipt.json --signer … --max-age 315360000` |
| V2 | join consistency only: both events' `receipt_id` and `execution.receipt_id` equal the receipt's `id`; `id` equals the recomputed first 18 characters of `signature.payloadHash` (`computeReceiptHash` excludes `id`); both events' `receipt_hash` equal `computeReceiptHash(receipt)` | DERIVED | `computeReceiptHash`, `hashPayload` |
| V3 | recorded action matches the digest in the verified approval assertion: `sha256(canonicalize(action.json))` equals `sha256(canonicalize(execution.json.action))`, the digest in the signed reason text, and the digest in both events. Establishes neither execution nor enforcement. If V1 failed: FAILED (verification dependency failed) | DERIVED | `canonicalize` + sha256 |
| V4 | approval `occurred_at` precedes `executed_at`: a comparison of unsigned timestamps; actual chronology unproven. The timestamps themselves are OBSERVED | DERIVED | none |
| V5 | the action executed as recorded | ABSENT (independently established execution; `execution.json` is an unsigned host assertion) | none |
| V6 | the approver is the authenticated person named | ABSENT (authenticated approver identity; the export's actor is an unsigned host assertion; the receipt's `subject` is a simulated agent credential) | none |

Altered arguments (`tampered/execution-altered-args.json`): V3 FAILED (digest mismatch), V1/V2 unchanged.
Altered receipt (mutated in a test, not committed: `decision.allowed` flipped without re-signing): V1 FAILED
(signature-invalid), V2 FAILED, V3 FAILED (verification dependency failed).

## 4. Trust assumptions (printed by the verifier, verbatim in the README)

A signature authenticates the signer's assertion; it does not establish that the assertion is true. The
digest binds the approval to one exact call; it does not establish enforcement (that no other call ran) or
execution (that this call ran). Timestamps and actor identities in the export are unsigned. Completeness is
unproven; a trusted external checkpoint covering the relevant scope and sequence would be required. The
signing key here is synthetic and published: because the demo private key is public, anyone can forge
replacement receipts; this packet demonstrates verification mechanics, not a trust anchor. In a deployment
the vendor controls the key and the reviewer must obtain the expected signer out of band.

## 5. Placement, tests, cap

`examples/audit-log-evidence/`: `src/digest.ts`, `src/generate.ts` (pinned `issuedAt`, fixed key →
byte-identical fixtures; a test asserts regeneration equals the committed files), `src/verify.ts` (CLI:
`--fixtures <dir> --signer <addr>`, prints the table, exit 0 with a report / 2 on unreadable input),
`test/*.test.ts` (clean = V1–V4 DERIVED, V5–V6 ABSENT; altered args → V3 FAILED only; altered
receipt → V1+V2 FAILED; regeneration byte-equality; wrong signer → V1 FAILED). README = the packet.
CI job mirrors gov-stats-portal (clean checkout: generate, diff against fixtures, verify, test); deferred if
the cap is hit. Depends on `@bolyra/receipts@0.11.0` only (pinned; installation is separate from offline
verification). Cap: one day. No changes to `@bolyra/receipts`; no new receipt field; no live vendor
integration, export adapter, new schema, or completeness mechanism.

## 6. The compatibility question, answered (2026-10-12)

The question whether `action_digest`, `receipt_id`, `receipt_hash` and `signer` survive a CSV export
losslessly was answered by a staging reproduction (`examples/audit-log-evidence/tools/
workos-csv-reproduction.mjs`): in the 2026-10-12 staging run, parsing the CSV's `metadata` JSON cell
recovered all seven tested string occurrences exactly (`action_digest`, `receipt_id`, `receipt_hash` on both
events, `signer` on the approval event; the execution fixture has no `signer`). "Lossless" refers only to
these values in this run. Setup observations: unconfigured action/version pairs were rejected
(`invalid_audit_log`) until a schema was registered (actions are environment-scoped), and with the schemas
used, validation required `actor.metadata`. Per the stop rule, no
public question is asked; the packet carries the verified mapping instead.
