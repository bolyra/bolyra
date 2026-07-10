# @bolyra/receipts

Tamper-evident signed receipts for Bolyra ZKP verification decisions — secp256k1 / ES256K signatures, canonical JSON, EVM-compatible r‖s‖v encoding.

## Install

```bash
npm install @bolyra/receipts
```

## Usage

```typescript
import { createAuthReceipt, signReceipt, verifyReceipt } from '@bolyra/receipts';

// 1. Build a receipt from a verification result
const payload = createAuthReceipt(
  {
    rootDid: 'did:bolyra:0xabc…',
    actingDid: 'did:bolyra:0xdef…',
    credentialCommitment: '0x1234…',
    effectiveCommitment: '0x1234…',
    humanProof: verifiedBundle.humanProof,
    agentProof: verifiedBundle.agentProof,
    humanPublicSignals: verifiedBundle.humanPublicSignals,
    agentPublicSignals: verifiedBundle.agentPublicSignals,
    allowed: true,
    score: 95,
    permissionBitmask: 3n,
    chainDepth: 0,
    bundleVersion: 1,
    nonce: '0xdeadbeef',
  },
  { issuer: 'https://gateway.example.com', keyId: 'k1' },
);

// 2. Sign it with your secp256k1 private key
const signed = signReceipt(payload, {
  privateKey: process.env.RECEIPT_SIGNING_KEY!,
  keyId: 'k1',
});

// 3. Verify later (or on another service)
const ok = verifyReceipt(signed, '0xYourExpectedSignerAddress');
console.log(ok); // true
```

The `signed` object is JSON-serializable and can be stored in a database, forwarded to an audit log, or returned to the caller as proof of the verification decision.

## Hash-chained logs (v0.8.0+)

A signature makes each *receipt* tamper-evident; it does not make a *log* of
receipts tamper-evident — deleting or reordering whole entries leaves every
remaining signature valid. `ReceiptChain` closes that gap:

```typescript
import { ReceiptChain, verifyReceiptChain, GENESIS_PREV_RECEIPT_HASH } from '@bolyra/receipts';

// Writer side: one chain per log. Each signed payload gains
// chain: { seq, prevReceiptHash } — the fields are INSIDE the signed payload,
// so they cannot be rewritten without breaking the signature.
const chain = new ReceiptChain();
const first = chain.sign(payload1, signerConfig);  // seq 0, prevReceiptHash = genesis sentinel
const second = chain.sign(payload2, signerConfig); // seq 1, prevReceiptHash = first.receiptHash

// Verifier side: every signature AND the chain links.
const result = verifyReceiptChain([first, second], { expectedSigner: '0x…' });
result.ok;       // true
result.headHash; // pin this externally to detect tail truncation later
```

Details:

- **Genesis sentinel:** the first receipt in a log has `seq: 0` and
  `prevReceiptHash: GENESIS_PREV_RECEIPT_HASH` (`0x` + 64 zeros).
- **`receiptHash`** (envelope field) is `computeReceiptHash(receipt)`:
  keccak256 over the canonical `{ payload, signature }` — it commits to the
  exact signature bytes and excludes `id` and itself. Verifiers recompute it;
  the stored copy is a convenience for linking and anchoring.
- **Backward compatible:** all fields are additive. Chain-less receipts keep
  verifying, chained receipts still pass the plain `verifyReceipt()`, and
  chain verification is a separate step. Logs that START with pre-chaining
  receipts verify with `{ allowUnchained: true }` (deletions among that
  unchained prefix are, unavoidably, not detectable). Only a prefix is
  tolerated: a chain-less receipt after any chained receipt always fails
  (`unchained-after-chained`) — otherwise a validly signed chain-less receipt
  could be spliced in undetected.
- **What chain verification detects from the log alone:** edited receipts,
  deleted lines, reordered lines, inserted lines, head truncation (missing
  genesis), and a second chain spliced into the file.
- **What it provably cannot detect from the log alone:** truncation from the
  **tail** — a chain cut after any receipt is still internally consistent.
  Detecting it requires an external expectation: pass `expectedCount` and/or
  `expectedHeadHash` (e.g. from a periodically anchored checkpoint). The
  anchoring mechanism and checkpoint cadence are deployment policy —
  enterprise-configurable, not fixed by this library.

CLI: `bolyra receipt verify-chain audit-log.jsonl` (from
[`@bolyra/cli`](../cli/README.md)) runs the same verification over a JSONL
file, with `--signer`, `--expect-count`, `--expect-head`, and
`--allow-unchained`.

## License

Apache-2.0
