# Approval-to-execution binding primitive — design (2026-10-25)

Status: revision 6 (R6 APPROVE WITH EDITS doc fixes; argument ingress narrowed to JSON text only after code review R5; creation contract recorded after R1) after Codex spec review R1 (REJECT, 10 findings, all applied) and R2 (APPROVE WITH EDITS, 5 edits, all applied). Founder override
2026-10-25 lifts BUILD NOTHING for this one item. Cap (Codex): 12 hours total including spec,
implementation, tests, docs, review; stop at the cap with findings. Spec re-review precedes
implementation; code review precedes push; publishing is a separate ruling. Scope excludes vendor
adapters, new packages, OCSF/FINOS schema work, hosted services, default telemetry.

## 1. Problem

TrueFoundry documents approval grants scoped to requester, server and tool. Its
[September 19, 2026 post](https://www.truefoundry.com/blog/mcp-tool-approvals-explained), updated
October 15, recommends application-level binding of material arguments and business state for
high-impact applications. Operators therefore need, without a Bolyra gateway in the request path:

1. a signed approval receipt that binds the reviewed action and its exact arguments;
2. a dispatch path that verifies that receipt immediately before dispatch and dispatches only the
   checked argument snapshot;
3. a signed execution observation that links to the approval receipt and verifies offline.

## 2. Non-goals and must-not-claim

Not built: vendor adapters (gateway `_meta` fields, MCP elicitation), OCSF/SIEM profiles, FINOS/JFrog event
shapes, any hosted service, any CLI change, any telemetry. The primitive does not claim: universal
compatibility; verified human identity because a name was signed; authorization correctness; downstream
commitment from dispatch; exactly-once execution; protection against bypassing the hook; complete logs
without completeness anchors; live vendor integration; compliance certification. Imported approval
metadata cannot establish which arguments a human actually reviewed; the receipt records what the
operator asserted was reviewed. The README states each of these.

## 3. Where it lives

`@bolyra/receipts` (no new package): new module `src/approval.ts` exported from `src/index.ts`, a runnable
example `examples/approval-binding.ts` inside the package (run with `tsx`, already a devDependency), and
tests. The example must use the unpublished module, and a sibling `file:` dependency in CI is a house-rule
violation, so the example stays inside the package.

Signing reuses the existing ES256K machinery. `SignedReceipt` becomes `SignedReceipt<T = ReceiptPayload>`.
`signReceipt`, `verifyReceipt`, `hashPayload` and `computeReceiptHash` gain legacy-first overloads: the
existing `ReceiptPayload` signatures stay first and unchanged, and a second overload accepts the new
payload types (`ApprovalReceiptPayload | ExecutionReceiptPayload`). Runtime behavior, hashes and signature
bytes for legacy receipts do not change. The existing auth, commerce, chain, instance and CLI tests stay as
regression fixtures; a new compile-time assertion file exercises legacy call sites without type arguments.
No change to `ReceiptPayload`, the chain, the instance binding, the CLI, or signer discovery.

## 4. Data model (all inside the signed payload)

### 4.1 Approval receipt — `kind: 'bolyra.approval'`, `v: 1`

```
{
  v: 1, kind: 'bolyra.approval', issuedAt: <unix s>, issuer: <string>, keyId: <string>,
  binding: {
    scheme: 'bab1',
    requester: <id>,            // identity that requested the action, as asserted by the operator
    audience: <id>,             // execution audience: the server / system that will execute
    tool: <id>,                 // action / tool name
    operationId: <id>,          // operator-assigned, unique per operation
    argumentsDigest: <64 lowercase hex>   // §4.3
  },
  approval: {
    approver: <printable ASCII 1..256>,   // exactly as the approval source asserted it
    source: <id>,                          // provenance label of the approval source
    decision: 'approved' | 'denied',       // closed enum; anything else (incl. "pending") is rejected
    decidedAt: <RFC 3339 UTC, exactly 3-digit ms, Z>,
    validity: { kind: 'once' } | { kind: 'until', notAfter: <RFC 3339 ms Z> },
    requestId?: <id>                       // external approval-request identifier, verbatim
  }
}
```

`<id>` = printable ASCII excluding space (0x21..0x7E), 1..256 chars. Closed schemas: unknown members at
any level are rejected. Every member except `requestId` is required; `createApprovalReceipt` throws naming
the first offending member. Provenance (`approver`, `source`) is never defaulted. The envelope `keyId`
must equal the payload `keyId`.

### 4.2 Execution observation — `kind: 'bolyra.execution'`, `v: 1`

```
{
  v: 1, kind: 'bolyra.execution', issuedAt, issuer, keyId,
  execution: {
    scheme: 'beo1',
    approvalReceiptHash: <0x keccak hex>,  // computeReceiptHash(approval receipt); verifiers recompute
    approvalReceiptId: <string>,           // approval envelope id; verifiers re-derive from payloadHash
    operationId: <id>, attemptId: <id>,    // attemptId operator-assigned per dispatch attempt
    requester, audience, tool: <id>,       // the checked context actually passed to dispatch
    actionDigest: <64 lowercase hex>,      // same canonical-bytes + DST hash (§4.3) over the dispatched snapshot
    dispatchedAt: <RFC 3339 ms Z>,         // captured immediately before invoking dispatch
    outcome: 'returned' | 'threw'          // what the dispatch promise did; NOT a confirmed effect
  }
}
```

No `responseDigest` in v1.

### 4.3 Arguments digest

`argumentsDigest = sha256hex( utf8("bolyra.approval.arguments/1") || 0x00 || utf8(canonicalize(value)) )`
where `value` is the tree produced by `JSON.parse(argumentsJson)` after validation.

**Ingress is JSON text only.** There is no public API that accepts an arbitrary JavaScript value: every
entry point (`validateArgumentsJson`, `computeArgumentsDigest`, `createApprovalReceipt`,
`executeApproved`) takes `argumentsJson: string`. The shared analysis parses it exactly once (no
reviver), validates the parsed tree, canonicalizes it and checks the canonical size. `validateArgumentsJson`
stops there: it returns a verdict and freezes nothing. `computeArgumentsDigest` hashes the canonical
bytes. `executeApproved` deep-freezes the parsed tree after analysis and uses that frozen tree for the
digest comparison and for dispatch. `JSON.parse` output contains only own enumerable string-keyed data
properties, plain objects, arrays, strings, numbers, booleans and null, so proxies, accessors, exotic
objects, symbols and custom prototypes cannot enter; `JSON.parse` can still yield `Infinity` (for
example from `1e400`), and the validator supplies the finite-number rule.
(Revision 5: an earlier direct-value validator was removed after review found that no brand-probing
strategy could both avoid executing caller code and reject every exotic object.)

Domain (bab1) on the parsed tree, fail closed: root must be a non-array object; any key equal to
`__proto__`, `constructor` or `prototype` at any depth is rejected (`JSON.parse` creates `__proto__` as
an own property); negative zero (`-0`, `-0.0`, `-0e0`) is rejected; nesting depth is capped at 64;
raw text and canonical form are each capped at 1 MiB; duplicate keys collapse last-wins per
`JSON.parse`, so the binding covers the parsed value and an approval display must render that same
interpretation. The existing `canonicalize` is not changed (wire compatibility); within this domain
its output is deterministic. Golden tests pin canonical bytes and digests for fixtures with numeric keys,
Unicode strings, nested arrays and numbers with exponents. `actionDigest` in the observation is computed
by the same canonical-bytes + DST hashing algorithm over the dispatched snapshot (the public function
accepts text; the internal hash step is shared). The receipt carries the digest only, never
the arguments.

## 5. Functions

### 5.1 `validateArgumentsJson(argumentsJson: string)` and `computeArgumentsDigest(argumentsJson: string): string`

`validateArgumentsJson` parses the immutable JSON text once and validates the bab1 domain, returning
`{ ok: true } | { ok: false, detail }`. `computeArgumentsDigest` does the same and returns the digest;
it throws on invalid JSON or out-of-domain values.

### 5.2 `createApprovalReceipt(input, signerConfig): SignedReceipt<ApprovalReceiptPayload>`

`input` = `{ v?, kind?, issuedAt?, binding: { scheme?, requester, audience, tool, operationId },
approval: { approver, source, decision, decidedAt, validity, requestId? }, argumentsJson }`. `v`, `kind`
and `scheme` default to their fixed values and any other value throws; `issuedAt` defaults to now;
`issuer` and `keyId` come from `signerConfig`; a caller-supplied `argumentsDigest` is rejected. Provenance
members are never defaulted. Validates every member and the domain, computes the digest, builds the
payload, signs. Throws on any invalid input. (Creation contract as implemented; Codex code review R1
accepted.)

### 5.3 `executeApproved(params, dispatch): Promise<ApprovedExecution<R>>`

The only path that dispatches. There is no exported standalone guard: a check result that is not
immediately followed by dispatch inside this function authorizes nothing.

Params: `receipt`, `expectedSigner` (non-empty, required), `context: { requester, audience, tool,
operationId }`, `argumentsJson` (string), `attemptId`, `consume?` (§5.4), `observer?: ReceiptSignerConfig`,
`clock?: () => Date` (default `() => new Date()`).

Order of operations:

1. Snapshot once, before first read: `structuredClone` of `receipt`, `context`, `observer` and
   `expectedSigner`; parse `argumentsJson` once, validate the domain, deep-freeze the parsed value.
   Callbacks (`consume`, `dispatch`, `clock`) are not cloned. All later steps read only the snapshots.
   Capture `argumentsJson`, `attemptId`, `consume`, `dispatch` and `clock` exactly once at entry. Validate
   primitive strings and callback types before consumption. Deep-freeze the cloned context. Never reread
   caller-owned params.
2. Preflight the observer configuration (private key parses, keyId and issuer non-empty) before anything
   is consumed, so a post-dispatch signing failure cannot be caused by a known-bad config.
3. Validate the receipt: closed schema, `kind`, `v`, `scheme`, envelope/payload `keyId` agreement,
   signature `alg` and byte lengths, derived id (for both new receipt kinds,
   `id === '0x' + signature.payloadHash.slice(2, 18)`),
   `verifyReceipt(snapshot, expectedSigner)` true. Decision must be `approved`. Compare `requester`,
   `audience`, `tool`, `operationId` with the context snapshot. Compare `argumentsDigest` with the digest
   of the parsed snapshot. `attemptId` is a valid id.
4. Clock: sample `t0` by calling the captured clock and immediately extracting epoch milliseconds with
   `Date.prototype.getTime.call`. Throws or nonfinite results block with `invalid_clock`. Reject
   `decidedAt > t0` as `future_decision`; for `until`, reject `t0 >= notAfter` as `expired`.
5. Consumption (`once` only): call `consume({ signer, payloadHash, operationId })` exactly once, after all
   validation; only the literal `true` permits dispatch; `false`, any other value, a thrown error, or a
   Promise blocks. A consumed-then-blocked operation is never released by this function. `until` receipts
   permit repeats; reconciling repeated operations is operator-owned.
6. Sample `td` using the same validation. Repeat both temporal checks against `td`. Capture
   `dispatchedAt` as an immutable UTC timestamp string, then immediately invoke the captured
   `dispatch(snapshot, checkedContext)` without awaiting anything between validation and invocation.
   Await settlement. `checkedContext` is the frozen context snapshot; the operator routes the call by it,
   never by anything outside the snapshot.
7. Observation: when `observer` is present, build and sign the §4.2 payload from the retained snapshots
   with `outcome` set from settlement. A signing failure after dispatch is reported as `observationError`
   and never as blocked, and never triggers a retry of dispatch.

Results:

- Blocked (any failure in steps 1–5, or the step 6 clock re-check): resolves
  `{ outcome: 'blocked', code, detail }` with codes `malformed_input`, `malformed_receipt`, `wrong_kind`,
  `keyid_mismatch`, `signature_invalid`, `untrusted_signer`, `decision_not_approved`,
  `future_decision`, `expired`, `context_mismatch`, `arguments_out_of_domain`, `arguments_mismatch`,
  `consume_required`, `consume_rejected`, `observer_invalid`, `invalid_clock`. `dispatch` is never called.
- Dispatched and returned: resolves `{ outcome: 'returned', value, observation?, observationError? }`.
- Dispatched and threw: rejects with `ApprovedExecutionError { cause, observation?, observationError? }`.

### 5.4 Consumption interface

`consume: (claim: { signer: string; payloadHash: string; operationId: string }) => boolean`.
The operator stores the claim atomically and durably, namespaced by the recovered signer, across all
executors; the full `payloadHash` (not the truncated id) is the replay identity. The README documents that
the guard cannot know whether the approved operation already produced its effect; business-state checks
belong to the operator and must be made atomically with the mutation.

### 5.5 `verifyApprovalExecutionLink({ approval, observation, expectedApprovalSigner, expectedExecutionSigner })`

Offline, pure. Returns `{ ok, checks: [{ id, status: 'PASS' | 'FAIL', detail }], statement }`. Checks:
A1 approval closed schema, kind, scheme, keyId agreement, derived id; A2 approval signature valid and
signer equals the expected approval signer (non-empty); A3 decision approved; E1 observation closed
schema, kind, scheme, keyId agreement, derived id; E2 observation signature valid and signer equals the
expected execution signer; L1 `approvalReceiptHash` equals recomputed `computeReceiptHash(approval)` and
`approvalReceiptId` equals the approval's derived id; L2 `operationId`, `requester`, `audience`, `tool`
equal; L3 `actionDigest` equals `argumentsDigest`; L4 `decidedAt <= dispatchedAt`, and for `until`,
`dispatchedAt < notAfter`. `statement` is fixed text: a PASS establishes signed assertions and their
linkage only; it does not establish human review, actual dispatch, consumption, response success,
business-state freshness or committed effect.

## 6. Error handling

All public functions fail closed. Creation throws; execution resolves to a typed blocked result or
rejects with `ApprovedExecutionError`; verification returns typed checks. No function logs, writes files,
or makes network calls.

## 7. Testing

`test/approval.test.ts` (Jest, under the package's existing config) plus `test/types.test-d.ts` compiled by
typecheck. A new `tsconfig.test.json` (noEmit, includes `src/`, `test/`, `examples/`) is run by
`npm run typecheck` so tests and the example are type-checked even though Jest runs with diagnostics off.

Coverage:

- digest: golden canonical bytes and digests (numeric keys, Unicode, nested arrays, exponent numbers);
  rejection of `__proto__`/`constructor`/`prototype` keys at depth, negative zero in every spelling,
  depth and size caps, invalid JSON; duplicate keys bind last-wins; no test targets a direct-value API
  because none exists.
- creation: valid input signs and verifies; each missing, unknown or out-of-domain member throws naming
  it; `decision: 'pending'` and unknown `scheme`/`v` throw.
- execute, every rejected case asserts zero `dispatch` calls: changed arguments; changed
  requester/audience/tool/operationId; denied decision; expired `until` at the boundary (`t0 == notAfter`
  rejects, `t0 == notAfter - 1 ms` passes the first check); future `decidedAt`; missing `consume` on
  `once`; `consume` returning `false`, a string, a Promise, or throwing; concurrent and re-entrant calls
  with a shared in-memory consume map (exactly one dispatch); wrong expected signer; forged envelope id;
  tampered payload; keyId mismatch; malformed inputs (null, string, array, missing fields); invalid
  observer config blocks before consumption (consume map untouched); invalid clock.
- execute, success: dispatch called once with a frozen snapshot and the checked context; mutating the
  caller's objects during `consume` or `dispatch` changes nothing; observation signs, verifies and links;
  a throwing dispatch rejects with `ApprovedExecutionError` carrying the `threw` observation; a dispatch
  returning a business error value is `returned` (the primitive does not interpret values); a failing
  observer key at signing time (simulated) yields `observationError`, not blocked.
- link verification: full PASS; each tampered field fails the matching check; re-signed semantic
  negatives (a validly signed observation whose `actionDigest` differs) fail L3; a blocked execution
  produces no observation, so the L3 negative is a separately signed mismatching observation.
- example: `test/example.test.ts` runs the example and asserts its two outcomes (match dispatched once;
  changed argument blocked with zero dispatches and no observation).
- clock boundaries: second clock samples that throw, return invalid Dates, precede `decidedAt`, or equal
  `notAfter` each block with zero dispatches. Mutating a clock-returned Date during dispatch must not
  alter the observation. Mutating params during consumption must not replace captured callbacks or
  `attemptId`. Exercise validly re-signed negatives for every linkage check L1–L4.

Run: `npm run typecheck` and `npm test` in `integrations/receipts`; the full receipts suite in a node:20
container before push (house rule). CI today builds `integrations/receipts` inside the mcp and gateway
jobs but never runs its Jest suite; this PR adds a `receipts-tests` job (checkout, node 20, `npm ci`,
`npm run typecheck`, `npm test`) so the new tests gate merges.

## 8. Documentation

README section "Approval-to-execution binding (Unreleased)" with the three steps, the data model, the
bab1 domain, the operator-owned interfaces (consumption, business-state checks), the ordering guarantees
and their limits, and the must-not-claim list verbatim. CHANGELOG entry under Unreleased. No version bump
in this PR. House rules: clean node:20 validation before push, no `file:` sibling CI dependencies, DCO
sign-off on every commit, no telemetry.

## 9. Acceptance (from Codex 2026-10-25)

Versioned canonical representation binds requester, audience, tool, exact reviewed arguments, approval
identity and source, decision, validity, operation id; unsupported inputs fail closed and provenance is
never invented; verification checks an explicitly trusted signer and the full context; changed
arguments, target, tool or requester, invalid signature, expired, pending or denied decisions cause zero
dispatches; the wrapper dispatches the same immutable snapshot it checked; replay consumption and
business-state checks are operator-owned interfaces with documented limits; signed execution observations
reference the approval receipt hash, operation and attempt id, and actual action digest; offline
verification detects tampering and broken links; tests distinguish approval, dispatch, response and
confirmed effect; one reproducible example demonstrates matching execution and changed-argument
rejection; no default telemetry; no raw sensitive arguments in exported evidence.
