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

## Approval-to-execution binding

Gateways that hold an agent's tool call for human approval usually scope the resulting grant to the
requester, the server and the tool. This module binds an approval to the **exact arguments** and links
the execution back to it, with evidence a reviewer can verify offline. No Bolyra gateway is needed in
the request path; the operator keeps its approval UI, policy, runtime, keys and storage.

Three steps:

```typescript
import {
  createApprovalReceipt, executeApproved, verifyApprovalExecutionLink, ApprovedExecutionError,
} from '@bolyra/receipts';

// 1. When the approval source reports a decision, bind it to the reviewed action.
const argumentsJson = JSON.stringify({ orderId: 'o-1001', amount: 40 });
const context = { requester: 'agent:refunds-bot', audience: 'crm.example', tool: 'refund.issue', operationId: 'op-7f3a' };
const approval = createApprovalReceipt(
  {
    binding: context,
    approval: {
      approver: 'ops-lead@example', source: 'gateway:acme', decision: 'approved',
      decidedAt: '2026-10-25T18:00:00.000Z', validity: { kind: 'once' },
    },
    argumentsJson,
  },
  { issuer: 'https://approvals.example', keyId: 'k1', privateKey: process.env.APPROVAL_KEY! },
);

// 2. Immediately before dispatch, re-verify and dispatch only the checked snapshot.
const result = await executeApproved(
  {
    receipt: approval,
    expectedSigner: '0xApprovalSignerAddress',   // obtained out of band, never read from the receipt
    context,
    argumentsJson,                                // the arguments you are about to send
    attemptId: 'attempt-1',
    consume: (claim) => replayStore.consumeOnce(claim),   // operator-owned, atomic, durable
    observer: { issuer: 'https://executor.example', keyId: 'x1', privateKey: process.env.EXEC_KEY! },
  },
  (snapshot, checkedContext) => crm.issueRefund(checkedContext.audience, snapshot),
);
// result.outcome: 'blocked' (dispatch never called; result.code says why)
//              or 'returned' (result.value + result.observation)
// A throwing dispatch rejects with ApprovedExecutionError { cause, observation? }.

// 3. Later, a reviewer verifies the pair offline.
if (result.outcome === 'returned' && result.observation) {
  const link = verifyApprovalExecutionLink({
    approval,
    observation: result.observation,
    expectedApprovalSigner: '0xApprovalSignerAddress',
    expectedExecutionSigner: '0xExecutionSignerAddress',
  });
  // link.ok, link.checks (A1..L4), link.statement
}
```

What a blocked result means: the approval receipt failed closed on one of the typed codes
(`signature_invalid`, `untrusted_signer`, `decision_not_approved`, `expired`, `future_decision`,
`context_mismatch`, `arguments_mismatch`, `consume_required`, `consume_rejected`, …) and `dispatch`
was never called.

**Argument domain (`bab1`).** Arguments enter only as immutable JSON text (`argumentsJson`); there is no
API that accepts an arbitrary JavaScript value. The text is parsed once, validated and deep-frozen, and
that frozen tree is what is digested and what `dispatch` receives. The digest is `sha256(utf8("bolyra.approval.arguments/1") || 0x00 || utf8(canonicalize(value)))`
over a JSON object whose values are objects, arrays, strings, finite numbers, booleans or null. Keys named
`__proto__`, `constructor` or `prototype`, negative zero, and non-finite numbers (`1e400` parses to
`Infinity`) are rejected by the validator; cycles, sparse arrays, accessors, proxies, symbols and custom
prototypes are unrepresentable through JSON ingress rather than detected at runtime. Limits: text and
canonical form at most 1 MiB each, depth at most 64. Numbers and non-ASCII strings follow `JSON.stringify`, not RFC 8785; both
sides must use this library's `computeArgumentsDigest`. The receipt carries the digest only, never the
arguments.

**Ordered checks and limits.** `executeApproved` captures every parameter once at entry (receipt,
context and arguments are cloned, parsed and deep-frozen; the observer config is cloned; callbacks are
captured as bare functions, never re-read), preflights the observer key before anything is consumed, validates the receipt's closed schema
and signature against `expectedSigner`, compares the full context and the argument digest, samples the
clock (`t0`: the decision must not be in the future, an `until` receipt must not have expired), consumes
(`once` only, synchronously), samples the clock again (`td`, same checks) and only then calls `dispatch`
with the frozen snapshot, awaiting settlement. Arguments: JSON text at most 1 MiB, canonical form at
most 1 MiB, nesting depth at most 64. Duplicate JSON keys collapse last-wins before digesting: the
binding covers the parsed JavaScript value, so an approval display must render that same interpretation.
Observations are optional (`observer`); a signing failure after dispatch is returned as
`observationError` beside the `returned` value (or inside `ApprovedExecutionError`) and never retries the
dispatch.

**Operator-owned interfaces.** `consume({ signer, payloadHash, operationId })` must store the claim
atomically and durably, namespaced by the recovered signer, across every executor; only the literal
`true` permits dispatch, and a consumed-then-blocked operation is never released. `until` receipts permit
repeats; reconciling repeated operations is the operator's job. Business-state checks (is the order still
refundable?) belong to the operator and must be made atomically with the mutation: the receipt cannot
know whether the approved operation already produced its effect.

**What this does not claim.** Universal compatibility with any gateway; verified human identity because
a name was signed; authorization correctness; downstream commitment from dispatch; exactly-once
execution; protection against bypassing the hook; complete logs without completeness anchors; live
vendor integration; compliance certification. Imported approval metadata cannot establish which
arguments a human actually reviewed; the receipt records what the operator asserted was reviewed. An
offline PASS establishes signed assertions and their linkage only: not human review, actual dispatch,
consumption, response success, business-state freshness or committed effect.

TypeScript compatibility: ordinary legacy calls, the default `SignedReceipt`
payload, and legacy `ReturnType`/`Parameters` inference are preserved. Added
overloads can require changes to legacy-only mocks or wrappers annotated with
`typeof verifyReceipt`. Type those wrappers explicitly as
`(receipt: SignedReceipt, expectedSigner?: string) => boolean`.
Legacy receipt, hash and signature bytes are unchanged.

Runnable [synthetic-key example](https://github.com/bolyra/bolyra/blob/2e505cdc/integrations/receipts/examples/approval-binding.ts):
from a repository checkout, run `npm ci` and then
`npx tsx examples/approval-binding.ts` in `integrations/receipts/`.
The example is not included in the npm package.
[Design](https://github.com/bolyra/bolyra/blob/2e505cdc/docs/superpowers/specs/2026-10-25-approval-binding-design.md).

## License

Apache-2.0
