# Preserving approval-to-action evidence through an audit-log export

**Status:** design, 2026-10-11. Codex-ruled move (one-day cap) under the design-partner track. Synthetic
and reproducible; nothing here is a customer deployment or a claim about any vendor's product.

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
| `approval-receipt.json` | **signed** (ES256K, `@bolyra/receipts`) | one `bolyra.auth` receipt whose `decision.reasonCode` carries `approved | action_digest=<sha256>` and `tool=zendesk.post_reply` (a **convention** in the free-text reason field, not a receipt schema field; stated as such) |
| `action.json` | unsigned | the exact call the approver saw: `{ server, tool, arguments }`; `action_digest = sha256(canonicalize(action))` using the receipts package's JCS canonicalizer |
| `execution.json` | unsigned | the host's record of the dispatched call: same `action`, `receipt_id`, `executed_at`, `status` |
| `export.jsonl` | unsigned | two audit-log-shaped events: `tool.approval_resolved` (actor = approver; targets = tool, ticket; metadata = `action_digest`, `receipt_id`, `receipt_hash`, `signer`) and `tool.executed` (actor = agent; metadata = `action_digest`, `receipt_id`) |
| `signer.json` | unsigned | the synthetic signer address and the fixed, published synthetic private key (labelled synthetic; never reuse) |
| `tampered/execution-altered-args.json` | unsigned | same as `execution.json` with the reply body changed |
| `tampered/approval-receipt-altered.json` | signed-then-edited | `decision.allowed` flipped without re-signing |

The export event shape follows the documented public fields of a generic audit-log event (action,
occurred_at, actor{type,id,name}, targets[{type,id,name}], context, metadata). Metadata size limits and
export format fidelity (CSV vs JSON) are **not documented** on the pages checked; the packet treats
metadata as opaque JSON and lists this as an open question (§6).

## 3. Verification procedure (offline; `npm run verify`)

Inputs: the fixtures directory and `--signer <address>` (reviewer-supplied; `signer.json` is compared, not
used as the anchor). Checks, each reported with the five statuses from the reviewer evidence report:

| # | Check | Status on clean fixtures | Tool |
|---|---|---|---|
| V1 | receipt signature recovers to the anchored signer; payload hash recomputes | DERIVED | `verifyReceipt` (`@bolyra/receipts`), also `npx -p @bolyra/receipts bolyra-receipt-verify approval-receipt.json --signer … --max-age 315360000` |
| V2 | `export.metadata.receipt_hash` equals `computeReceiptHash(receipt)`; `receipt_id` equals `id` | DERIVED (join integrity) | `computeReceiptHash` |
| V3 | `action_digest` recomputed from `execution.json.action` equals the digest in the signed reason text and in both export events | DERIVED | `canonicalize` + sha256 |
| V4 | approval event `occurred_at` precedes execution `executed_at` | OBSERVED (unsigned timestamps; ordering is not proven) | none |
| V5 | the action executed as recorded | ABSENT (no evidence in the packet) | none |
| V6 | the approver is the authenticated person named | ABSENT (the receipt's `subject` is a simulated agent credential; approver identity is an unsigned actor field) | none |

Altered arguments (`tampered/execution-altered-args.json`): V3 FAILED (digest mismatch), V1/V2 unchanged.
Altered receipt (`tampered/approval-receipt-altered.json`): V1 FAILED (signature-invalid), V2 FAILED, V3 not evaluated.

## 4. Trust assumptions (printed by the verifier, verbatim in the README)

A signature authenticates the signer's assertion; it does not establish that the assertion is true. The
digest binds the approval to one exact call; it does not establish enforcement (that no other call ran) or
execution (that this call ran). Timestamps and actor identities in the export are unsigned. Completeness
of the export is not established by anything inside it; a separately retained count or head hash would be
needed. The signing key here is synthetic and published; in a deployment the vendor controls it and the
reviewer must obtain the expected signer out of band.

## 5. Placement, tests, cap

`examples/audit-log-evidence/`: `src/digest.ts`, `src/generate.ts` (pinned `issuedAt`, fixed key →
byte-identical fixtures; a test asserts regeneration equals the committed files), `src/verify.ts` (CLI:
`--fixtures <dir> --signer <addr>`, prints the table, exit 0 with a report / 2 on unreadable input),
`test/*.test.ts` (clean = V1–V3 DERIVED, V4 OBSERVED, V5–V6 ABSENT; altered args → V3 FAILED only; altered
receipt → V1+V2 FAILED; regeneration byte-equality; wrong signer → V1 FAILED). README = the packet.
CI job mirrors gov-stats-portal (clean checkout: generate, diff against fixtures, verify, test). Depends on
`@bolyra/receipts@0.11.0` only. Cap: one day. No changes to `@bolyra/receipts`; no new receipt field.

## 6. Open questions the packet surfaces for an audit-log product (candidates for ONE public question)

1. Metadata limits: can a ~1.5 KB signed record be carried in `metadata`, or only its hash and signer, with
   the record retained elsewhere and joined by id?
2. Export fidelity: does CSV export preserve `metadata` byte-for-byte (key order, nesting) so a digest
   recomputed from the export matches one computed at event time?
3. Does an export carry anything a reviewer can use to detect tail truncation (count, head hash)?
Only a question backed by the reproduction gets asked; otherwise the packet stops at the artifact.
