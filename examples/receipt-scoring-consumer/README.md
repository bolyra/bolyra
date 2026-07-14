# Receipt scoring consumer (reference)

The demand-side twin of [`examples/receipt-scoring-kit`](../receipt-scoring-kit):
what an **indexer or counterparty-risk scoring system** does with Bolyra
receipt logs. Built entirely on the published `@bolyra/receipts@0.9.0` — no
local source, no private APIs.

The pipeline is two steps, in a fixed order:

1. **Verify first, fail closed.** Accepted signers come from a Receipt Signer
   Discovery v1 document ([spec](../../spec/receipt-signer-discovery-v1.md)),
   every signature and the hash chain are checked with `verifyReceiptChain`,
   and the count + head hash are pinned externally. A log that fails ANY of
   this contributes **nothing** to scoring — there is no "partial credit" for
   unverified history.
2. **Extract per-actor features.** Group verified receipts by
   `credentialCommitment` and emit the columns a risk engine ingests.

## Run it against the public corpus

```bash
npm install
npm run score -- ../receipt-scoring-kit/corpus/receipts.jsonl \
  --signers ../receipt-scoring-kit/corpus/bolyra-signers.json \
  --expect-count 8 \
  --expect-head 0x8150d2464e2f17dd1bfa921283ae8622d912160bfa7e24ffefd930fc06e31d92
```

Output:

```
| actor (credentialCommitment) | actions | allow | deny | deny rate | top deny reason | max tier | max depth | commerce allowed | first→last |
|---|---|---|---|---|---|---|---|---|---|
| 18446744073709551617 | 8 | 5 | 3 | 0.375 | credential_mismatch | FINANCIAL_SMALL | 2 | 42.5 USDC | 1783900800→1783901220 |
```

`--signers` also accepts an `https://` discovery URL (same rules as the CLI:
no plain http except loopback, no redirects). `--expect-count` and
`--expect-head` are **mandatory** — without external pins, a tail-truncated
log is internally consistent and would score, so the pipeline refuses to run
rather than offering an unpinned mode. `--json` emits the full feature
objects instead of the table.

## The features

| Column | Scoring meaning |
|---|---|
| `denyRate` + `denyReasons` histogram | How often, and why, this actor gets refused — `credential_mismatch` (forgery attempts) reads very differently from `request_mismatch` (tier overreach) |
| `maxFinancialTier` | The largest spend scope this actor has been granted (cumulative 8-bit mask) |
| `maxDelegationDepth` | Whether the actor operates directly or through delegation chains |
| `commerceVolumeAllowed` / `commerceDenied` | Authorized payment volume by currency, and blocked payment attempts |
| `firstSeen` / `lastSeen` | History depth — thin histories score differently from deep ones |

## What fail-closed means here (tested)

- The **tampered** corpus log → verification failure → scoring aborted.
- Operator B's log under operator A's discovery document → unknown signer →
  aborted.
- A wrong pinned head hash (tail-truncation guard) → aborted.

An unverifiable history is not a weak signal; it is no signal.

## Caveats (same as everywhere in this stack)

Discovery is not endorsement — trusting the discovery origin is still the
consumer's decision. And receipts here prove **authorization** (and the
approved→paid pair on commerce receipts), not delivery: fulfillment remains
an unsigned leg.
