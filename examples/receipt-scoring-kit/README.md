# Receipt scoring test kit

A committed, deterministic corpus of signed, hash-chained Bolyra receipts for
**third-party consumers** — counterparty scoring systems, auditors, indexers —
to test verification against, without talking to the issuer.

Every receipt is ES256K-signed. Chain fields (`seq`, `prevReceiptHash`) live
**inside the signed payload**, so edits, deletes, inserts, reorders, and
head truncation break chain verification; **tail truncation** is the one
manipulation that stays internally valid, which is why you pin the expected
count and head hash from `manifest.json` (see caveats). Verification is fully
offline: all you need is the corpus and the signer's public address
(`signer.json`).

## Verify it yourself (5 commands, nothing installed but Node)

```bash
# 1. Fetch the corpus (two operators' logs, signer anchors, a standalone receipt, a tampered log)
base=https://raw.githubusercontent.com/bolyra/bolyra/main/examples/receipt-scoring-kit/corpus; curl -sO "$base/receipts.jsonl" -sO "$base/signer.json" -sO "$base/allow.json" -sO "$base/tampered.jsonl" -sO "$base/operator-b.jsonl" -sO "$base/signer-b.json" -sO "$base/manifest.json"

# 2. Verify the whole chain: every signature + linkage + count + head
npx -y -p @bolyra/cli@0.5.0 bolyra receipt verify-chain receipts.jsonl \
  --signer 0x17c5185167401ed00cf5f5b2fc97d9bbfdb7d025 \
  --expect-count 8 \
  --expect-head 0x8150d2464e2f17dd1bfa921283ae8622d912160bfa7e24ffefd930fc06e31d92
# -> PASS: all signatures valid, chain intact

# 3. Verify one receipt standalone (schema, hash, id, signature, signer)
npx -y -p @bolyra/receipts@0.8.0 bolyra-receipt-verify allow.json \
  --signer 0x17c5185167401ed00cf5f5b2fc97d9bbfdb7d025 --max-age 315360000
# -> PASS — receipt is valid

# 4. Prove tampering is detectable: this log has one edited line
npx -y -p @bolyra/cli@0.5.0 bolyra receipt verify-chain tampered.jsonl \
  --signer 0x17c5185167401ed00cf5f5b2fc97d9bbfdb7d025
# -> FAIL line 3: [receipt-hash-mismatch] ... (the edit)
# -> FAIL line 4: [prev-hash-mismatch] ...    (the chain break it causes)

# 5. A second, independent operator's log verifies under ITS signer only
npx -y -p @bolyra/cli@0.5.0 bolyra receipt verify-chain operator-b.jsonl \
  --signer 0xae72a48c1a36bd18af168541c53037965d26e4a8 --expect-count 3 \
  --expect-head 0x4f1e6808ba5d49ce6e502ec5aa39cc177a4d3a44747e3366b4c9aba1d68d01d0
```

Expected counts and head hashes for all files live in
[`corpus/manifest.json`](corpus/manifest.json).

## What's in the corpus

| File | Contents |
|---|---|
| `receipts.jsonl` | 8-receipt chained log, one operator: allows, denies (with reason codes), a depth-2 delegated action, and two `bolyra.commerce` receipts (x402-style payment gate, allow + tier-exceeded deny) |
| `operator-b.jsonl` | 3-receipt log from an independent operator (different signer) — multi-operator consumption |
| `tampered.jsonl` | `receipts.jsonl` with line 3's decision flipped **after** signing — intentionally fails |
| `allow.json`, `deny.json` | Single receipts for standalone verification |
| `signer.json`, `signer-b.json` | Public trust anchors: `{ issuer, keyId, alg, signer }` — address only, no key material |
| `manifest.json` | Counts + head hashes to pin with `--expect-count` / `--expect-head` |

## Receipt fields a scoring system can consume

| Field | Scoring input |
|---|---|
| `payload.subject.rootDid` / `actingDid` | Who acted: root credential holder vs the (possibly delegated) acting agent |
| `payload.subject.credentialCommitment` / `effectiveCommitment` | Stable identity keys to aggregate history per credential |
| `payload.decision.allowed` | Allow/deny outcome |
| `payload.decision.reasonCode` | Why a deny happened (`credential_mismatch`, `credential_expired`, `nonce_replayed`, `request_mismatch`, …) |
| `payload.decision.permissionBitmask` | Authorized scope at decision time (8-bit cumulative mask, decimal string) |
| `payload.decision.chainDepth` | Delegation depth (0 = root credential acted directly) |
| `payload.decision.score` | Issuer-side verification score at decision time |
| `payload.kind` + `payload.commerce.*` | Payment context: rail (e.g. `x402`), amount, currency, merchant, intent hash |
| `payload.issuedAt`, `payload.issuer`, `signature.signer` | When, by whom, attributable to which key |
| `payload.chain.seq` + `receiptHash` linkage | Completeness of the history you are scoring over |

## Known caveats (stated plainly)

1. **Signer key distribution is operator-pinned today.** You get the signer
   address from `signer.json` (or any out-of-band channel you trust) — there
   is no key discovery/registry mechanism yet. Verification proves the log is
   internally consistent and signed by *that* key; binding the key to a
   real-world operator is currently a manual trust decision.
2. **Tail truncation is only detectable externally.** Deleting receipts from
   the *end* of a log leaves a shorter but internally valid chain. Pin
   `--expect-count` / `--expect-head` from a source you trust (this kit's
   `manifest.json` plays that role here).

## Regenerating

```bash
npm install && npm test   # builds, regenerates corpus deterministically, runs 7 invariant tests
```

The signing keys in `src/generate.ts` are **test keys, published on purpose**
so the corpus is reproducible. Never reuse them: production signers keep
`receipts.privateKey` private and publish only the derived address.
