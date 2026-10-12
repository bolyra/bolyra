# Preserving approval-to-action evidence through an audit-log export

A synthetic, reproducible packet. One human approval is bound to one exact AI-agent action, carried
through an audit-log-shaped export, and verified offline with published Bolyra tooling. Then the executed
arguments are altered and the check fails. Nothing here is a customer deployment, a tested export from any
vendor, or a claim about any vendor's internals.

**What it is for.** A B2B SaaS vendor records that a person approved an agent tool call, then the agent
executes it. The vendor's audit-log product exports events as rows: `action`, `occurred_at`, `actor`,
`targets`, `context`, `metadata`. A customer's reviewer receives the export. This packet shows what in that
export the reviewer can verify *without trusting the exporter*, and what they cannot.

## Run it

```bash
cd examples/audit-log-evidence
npm ci
# 0x7a2d…681d is the SYNTHETIC demo signer from fixtures/signer.json. For this public-key fixture reading
# it from the packet is fine; in a deployment the reviewer obtains the expected signer out of band.
npm run verify -- --fixtures ./fixtures --signer 0x7a2d4e540e813ea0b14c44793d7dc9868d5d681d
npm run verify -- --fixtures ./fixtures --signer 0x7a2d4e540e813ea0b14c44793d7dc9868d5d681d --execution ./fixtures/tampered/execution-altered-args.json
npm test                      # regeneration is byte-identical; statuses; the two failure cases
npm run generate -- --out /tmp/regen && diff -r /tmp/regen ./fixtures && echo identical
```

Node 20 or newer. Installation needs the network (`npm ci`); verification itself reads only the files.
Exit code 0 means a report was produced, including reports that contain FAILED rows; exit code 2 means the
arguments or the input could not be read.
The receipt alone can also be checked with the published standalone verifier, no repository needed:

```bash
npx -y -p @bolyra/receipts@0.11.0 bolyra-receipt-verify fixtures/approval-receipt.json \
  --signer 0x7a2d4e540e813ea0b14c44793d7dc9868d5d681d --max-age 315360000
```

## The artifacts (`fixtures/`, regenerable byte-for-byte with `npm run generate`)

| File | Signed? | What it is |
|---|---|---|
| `action.json` | no | the synthetic call the signer asserts was approved: `tenant`, `server`, `tool`, `resource`, `arguments`. `action_digest = sha256(canonicalize(action))`, JCS canonical form via `@bolyra/receipts` |
| `approval-receipt.json` | **yes** (ES256K, `@bolyra/receipts`) | one `bolyra.auth` receipt with signed `decision.allowed: true`; its free-text `decision.reasonCode` carries exactly `approved \| action_digest=<64 hex> \| tool=<server>.<tool>`. That placement is a convention of this example, not a receipt schema field |
| `execution.json` | no | the host's record of the dispatched call: the same action, the digest, the receipt id, `executed_at`, HTTP status |
| `export.jsonl` | no | synthetic audit-log-shaped JSONL, fields mapped to WorkOS's public Audit Logs documentation (not a tested WorkOS export): `tool.approval_resolved` then `tool.executed` |
| `signer.json` | no | the synthetic signer address and the **published** private key. Anyone can forge receipts under it; it is compared against your `--signer` flag, never used as the anchor |
| `tampered/execution-altered-args.json` | no | `execution.json` with the reply body changed; the digest it carries is the original one the host claims |

### Field mapping

| Export field | Carries | Why there |
|---|---|---|
| `action` | `tool.approval_resolved`, `tool.executed` | the two events a reviewer must join |
| `occurred_at` | approval time; execution time | unsigned; compared, not trusted |
| `actor` | `user_approver_01`; `agent_support_01` | unsigned host assertions of who acted |
| `targets` | `tool`, `ticket`, `organization` | tenant and resource, which are also inside the digested action |
| `metadata.action_digest` | 64 hex | the join to the exact approved call |
| `metadata.receipt_id`, `metadata.receipt_hash`, `metadata.signer` | 18, 66, 42 chars | the join to the retained signed receipt. WorkOS documents metadata limits of 50 keys, 40-character names and 500-character values ([metadata schema](https://workos.com/docs/audit-logs/metadata-schema)), so the receipt itself (about 1.4 KB) is a retained artifact joined by id and hash, not embedded |

Verification therefore needs the export **plus** the retained receipt and action artifacts.

## What the verifier reports

| # | Check | Clean | Altered arguments | Altered receipt |
|---|---|---|---|---|
| V1 | signature recovers to the anchored signer; payload hash recomputes; signed `allowed` is true | DERIVED | DERIVED | **FAILED** (signature-invalid) |
| V2 | join consistency: both events and the execution record reference the recomputed receipt id; both events carry the recomputed receipt hash | DERIVED | DERIVED | **FAILED** |
| V3 | recorded action matches the digest in the verified approval assertion (action.json, execution.json, the signed reason text, both events). Establishes neither execution nor enforcement | DERIVED | **FAILED** (digest mismatch) | FAILED (dependency) |
| V4 | approval `occurred_at` precedes `executed_at`: a comparison of unsigned timestamps; chronology unproven | DERIVED | DERIVED | DERIVED |
| V5 | the action executed as recorded | ABSENT | ABSENT | ABSENT |
| V6 | the approver is the authenticated person named | ABSENT | ABSENT | ABSENT |

Statuses follow the reviewer evidence report in `examples/operator-trial`: SIGNED (an authenticated signer
assertion), OBSERVED (an unsigned host assertion), DERIVED (a named check over stated inputs), ABSENT (no
evidence), FAILED (a check failed).

## Trust assumptions (the verifier prints these)

- A signature authenticates the signer's assertion; it does not establish that the assertion is true.
- The digest binds the approval to one exact call; it does not establish enforcement (that no other call ran) or execution (that this call ran).
- Timestamps and actor identities in the export are unsigned host assertions.
- Completeness is unproven; a trusted external checkpoint covering the relevant scope and sequence would be required.
- The demo private key is public, so anyone can forge replacement receipts under it; this packet demonstrates verification mechanics, not a trust anchor.
- In a deployment the vendor controls the signing key and the reviewer must obtain the expected signer out of band; reading it from the packet establishes consistency only.

## One open compatibility question

WorkOS documents [CSV exports](https://workos.com/docs/audit-logs/exporting-events); this packet exercises
synthetic JSONL, so the question is untested here. For this fixture's `action_digest`, `receipt_id`,
`receipt_hash` and `signer` metadata, how are values represented in a CSV export, and can their original
string values be recovered losslessly? JCS does not
require preservation of JSON key order or serialization bytes, so the digest recomputed from an export
must come from the retained `action.json`, not from re-serialized rows. This is a compatibility question,
not an allegation of a defect in any product.

Design note: `docs/superpowers/specs/2026-10-11-audit-log-evidence-packet-design.md`.
