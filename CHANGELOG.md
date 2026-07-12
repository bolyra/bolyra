# Changelog

All notable changes to Bolyra are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Bolyra is a **monorepo** — this changelog covers all published packages
released together as a cohort:

- `@bolyra/sdk` (npm — TypeScript SDK)
- `@bolyra/mcp` (npm — MCP authentication middleware)
- `@bolyra/payment-protocols` (npm — Stripe ACP / Visa TAP / AP2 adapters)
- `@bolyra/openclaw` (npm — OpenClaw trust verification adapter)
- `bolyra` (PyPI — Python SDK)

Contract verifier addresses and circuit artifacts are versioned separately
under `contracts/deployments/` and `circuits/build/`.

## [Unreleased]

### Added

#### Hosted verify endpoint (`integrations/hosted-verify` — private, not published)

- **Observability for the design-partner preview.** Workers Logs enabled
  (`observability.enabled: true`, `head_sampling_rate: 1`) and a Workers
  Analytics Engine dataset (`bolyra_hosted_verify_usage`, binding `USAGE`)
  receiving exactly **one structured data point per request**: route, partner
  label, verdict (`allow`/`deny`/`error`), deny/error code, proof kind,
  latency_ms, HTTP status, and request id — **nothing else: no request
  bodies, no proofs, no credentials, no bearer tokens, no IPs**. Writes are
  fire-and-forget after the verdict is decided; an Analytics Engine outage
  never affects verdicts.
- **Labeled partner tokens.** New `PARTNER_TOKENS` secret (JSON object
  mapping partner label → bearer token) with constant-time comparison per
  token; the legacy `PREVIEW_TOKEN` keeps working as label `preview`, and
  auth failures are recorded under the reserved label `unauthenticated`.
  Named bearer tokens only — not multi-tenant admin.
- **Usage report script** (`scripts/usage.mjs`, `npm run usage`): last-24h/7d
  requests by partner label, verdict breakdown, top deny codes, and p50/p95
  verify latency via the Analytics Engine SQL API (token scope: Account →
  Account Analytics → Read). 16 new tests (55 total in the package).

#### Spec (`spec/reference-host-rs` — reference only, not published)

- **Rust reference host for the External Verifier Contract v1**
  (`spec/reference-host-rs/`, binary `evc-reference-host`): a second,
  independent implementation of the §16.2 host-under-test convention —
  verifier spawn + strict single-object stdin/stdout framing (§5.2), wall-clock
  timeout and stdout byte bound with kill + reap (§6), fail-closed exit /
  signal / parse / closed-schema handling (§3.4, §7.1–§7.2, §16.4), and
  reserve-before-act durable nonce consumption (§7.3, §16.5). The verifier
  runs in its own process group and classification happens at stdout EOF
  (bounded by the wall-clock budget), so a descendant flooding the inherited
  pipe after a non-zero exit is still `oversize_stdout` (Codex round 1) and a
  quiet pipe-holder past the budget is `timeout`, beating signal/non-zero
  precedence exactly like the JS reference (Codex round 2). Passes all 22
  `host_behavior` conformance vectors (and the full runner with `HOST_CMD`
  pointed at it), matching `spec/reference-host.js`. 52 Rust unit tests.
  Dependency tree is `serde_json` + `libc` (Unix, for the process-group kill)
  + std (no async runtime). Not a supported SDK, not on crates.io,
  deliberately not wired into CI (see its README).

## [0.7.9] — 2026-07-11

### Added

#### Hosted verify endpoint (`integrations/hosted-verify` — new, private, not published)

- **DESIGN PARTNER PREVIEW: External Verifier Contract v1 over HTTP** on
  Cloudflare Workers. `POST /v1/verify` accepts the exact spec §2.1 request
  object `bolyra verify` reads on stdin and returns exactly one strict §3.4
  verdict object, always `kind: "classical"` (spec §3.5) — this is a
  **classical (Bolyra Core) verifier**: no zk verification (explicit
  `kind: "zk"` requests and human/delegation-slot bundles are denied with a
  clear reason).
  - Trust model (honest, disclosed live on `GET /health`): because the proof
    is NOT verified, every public signal and credential field is
    self-asserted. The load-bearing anchor is the set of trusted OPERATOR keys
    (`TRUSTED_OPERATORS`, fail-closed when unset) plus the EdDSA-Poseidon
    binding signature (spec §4) over the request binding — an `allow` means a
    trusted operator signed a binding authorizing this exact
    {agent_name, project_key, program, model, capabilities} and the request
    matches it. Signature-authenticated checks: trusted-operator gate, binding
    signature, request↔binding match, granted ⊆ signed capabilities.
    Consistency-only checks over the (unsigned) revealed credential: schema +
    bvp/1 shape, Poseidon scope anchor, model-hash, capability→scope subset,
    strict expiry — sound scope/expiry enforcement needs the zk-class CLI. NOT
    performed: Groth16 verification + vkey pinning, Merkle-root inclusion,
    human/delegation proofs, local replay state.
  - workerd cannot compile circomlibjs' runtime WASM, so Poseidon/EdDSA run
    on pure-JS `poseidon-lite` + `@zk-kit/eddsa-poseidon` (same
    circomlibjs-derived constants), pinned to the SDK's outputs by the
    conformance fixtures; the SDK's pure Core modules (`validateEnvelope`,
    `Permission`, `validateCumulativeBitEncoding`) are reused via deep
    imports with circuit libs aliased to a fail-loud stub.
  - Fail-closed everywhere: malformed/oversized (1 MiB bound, spec §6)
    bodies, wrong versions, undecodable bundles → explicit §9 denials;
    `internal_error` → HTTP 500 (the CLI's non-zero-exit analog); bearer
    auth (constant-time compare) on `/v1/verify`.
  - Host nonce mode only (stateless): every allow carries `consume_nonces`
    for the caller to reserve-before-act (spec §7.3).
  - Optional ES256K signed receipts (`@bolyra/receipts`) on every decision
    via the `X-Bolyra-Receipt` response header (body stays a pure closed-
    schema verdict).
  - Conformance: the 10 `external_verifier` vectors from
    `spec/test-vectors.json` pass — 5 driven end-to-end over HTTP against the
    Worker in workerd (`@cloudflare/vitest-pool-workers`) and 5 `static_verdict`
    schema vectors against the executable spec §3.4 schema; 39 tests total,
    including a regression that a forged bundle signed by an attacker-generated
    operator key is denied.

## [0.7.8] — 2026-07-10

### Added

#### Receipts (`@bolyra/receipts` 0.7.0 → 0.8.0)

- **Receipt hash-chaining — whole-log integrity.** Signatures made each
  receipt tamper-evident; the LOG was not — deleting or reordering lines was
  undetectable. New additive, backward-compatible chain fields:
  - `payload.chain: { seq, prevReceiptHash }` — lives INSIDE the signed
    payload, so chain fields cannot be rewritten without breaking the ES256K
    signature. `seq` is 0-based and monotonic per log; genesis links to the
    documented sentinel `GENESIS_PREV_RECEIPT_HASH` (32 zero bytes).
  - envelope `receiptHash` — `computeReceiptHash(receipt)`: keccak256 over
    the canonical `{ payload, signature }` (commits to the exact signature
    bytes; excludes `id` and itself). The next receipt's `prevReceiptHash`
    equals it. Verifiers recompute it — the stored copy is convenience.
  - New exports: `ReceiptChain` (stateful writer-side chain),
    `verifyReceiptChain(receipts, options)` (every signature AND the chain:
    shape guard for foreign/corrupted log lines (`malformed-receipt` —
    Codex round 2), seq continuity, prev-hash links, genesis, chain restarts, plus
    `expectedSigner` / `expectedCount` / `expectedHeadHash` /
    `allowUnchained`), `computeReceiptHash`, `GENESIS_PREV_RECEIPT_HASH`,
    and the `ReceiptChainFields` / `ChainVerifyOptions` / `ChainVerifyResult`
    / `ReceiptChainIssue` types.
  - Backward compatible: chain-less receipts keep signing/verifying, chained
    receipts still pass the existing per-receipt `verifyReceipt()`, and chain
    verification is a separate step. `allowUnchained` tolerates only a
    pre-chaining PREFIX — a chain-less receipt after any chained receipt is
    always flagged (`unchained-after-chained`), closing the splice-a-valid-
    chainless-receipt-into-the-log hole (Codex review round 1, P1).
  - Precision on limits (docs + verifier output): deletions, reorderings,
    insertions, edits, and head truncation are detectable from the log alone;
    truncation from the TAIL is provably not — it requires an externally
    pinned head hash or count. Anchoring mechanism and checkpoint cadence are
    enterprise-configurable deployment policy, not library behavior.

#### CLI (`@bolyra/cli` 0.4.0 → 0.5.0)

- **`bolyra receipt verify-chain <file>`** — verifies a JSONL receipt log:
  every ES256K signature AND the hash chain. Reports seq gaps, prev-hash
  mismatches (deleted/reordered/inserted lines), head truncation
  (genesis-mismatch), mid-file chain restarts, and tampered receipts, each
  with the original file line number (blank-line safe). Flags: `--signer`,
  `--expect-count` (strict non-negative integer), `--expect-head` (the only
  way to detect tail truncation — PASS output says so explicitly and prints
  the head hash to pin), `--allow-unchained` (pre-chaining PREFIX only).
  Exit codes: 0 pass, 1 verification failure, 2 usage error.

#### Gateway (`@bolyra/gateway` 0.4.0 → 0.5.0)

- **Every signed gateway receipt is now hash-chained** (allow, deny, and
  anonymous deny alike): one `ReceiptChain` per gateway process, startup
  probe excluded so the first written receipt is genesis (seq 0). A restart
  starts a new chain — rotate collected logs per process run to verify each
  as a single chain (README documents this and the tail-truncation caveat).

#### Verified-actions demo (`examples/verified-actions-demo`)

- Audit log receipts are hash-chained via the same `ReceiptChain`; the demo
  gains a whole-log tamper section that DELETES a line and REORDERS two lines
  and shows chain verification failing both times while every remaining
  individual signature stays valid. `npm run verify` (standalone
  verify-audit) now chain-verifies too and prints the head hash to pin.
  README's "whole-log integrity is a production add-on" paragraph replaced
  with the shipped chaining semantics, anchoring/checkpoint cadence
  explicitly enterprise-configurable (buyer-specified).

## [0.7.7] — 2026-07-10

### Added

#### Gateway (`@bolyra/gateway` 0.3.0 → 0.4.0)

- **Credential binding in packaged Core mode (`--dev`)** — closes the
  self-asserted-claims gap. Previously the packaged gateway trusted the
  permission mask inside a dev bundle; the registered-credential check lived
  only in `examples/verified-actions-demo`'s host code. Now a `credentials`
  section in `gateway.yaml` (or a `--credentials <path>` file: bare
  commitment → `{ permissionBitmask, expiryTimestamp? }` map, YAML/JSON)
  registers credentials with the gateway, and every verified claim must
  match the registry:
  - unknown commitment → 401 fail-closed + signed deny receipt
    (`credential_unknown`)
  - claimed mask ≠ registered grant (forged bundle) → 401 + signed deny
    receipt (`credential_mismatch`)
  - delegation chains are held to the Delegation circuit's production
    semantics: permissions may only narrow at EVERY hop
    (`credential_mismatch`), expiry may never outlive the delegator's
    (`delegateeExpiry <= delegatorExpiry`), expired hops are rejected
    against the gateway clock (`credential_expired` — the bundle's own
    `currentTimestamp` is caller-supplied and never trusted), and hop
    fields use the same strict decimal wire format, uint64 range, and
    cumulative-bit mask encoding production enforces
  - config validation enforces circuit semantics on registered credentials
    too: masks/expiries must fit uint64 and masks must satisfy the
    cumulative-bit encoding (a grant the circuits could never accept would
    make production binding permanently unsatisfiable); commitment keys
    must be canonical decimal (no leading zeros), numeric values must be
    safe integers (larger values as decimal strings)
  - registered expiry passed → 401 + signed deny receipt
    (`credential_expired`)
- **Unconfigured Core mode stays tutorial-friendly but loud**: behavior is
  unchanged (any claim passes), the CLI warns at startup, the banner shows
  `Binding: NONE — permission claims self-asserted`, and every allow receipt
  is flagged `[credential-binding: none — permission claims self-asserted]`
  (same visibility pattern as 0.3.0's ephemeral-signer marking).
- **Production mode gains a packaged credential resolver**: the same static
  `credentials` section is compiled into a `resolveCredential`
  implementation, engaging `verifyBundle`'s Poseidon3 `scopeCommitment`
  binding (the CLI previously could not run production verification at all —
  every request failed closed with "resolveCredential is required").
  `expiryTimestamp` is required per entry in production (it is a binding
  input), and expired registrations resolve to `null` — fail closed, not
  score-docked. An explicit library `resolveCredential` still takes
  precedence.
- New exports: `loadCredentialsFile`, `hasStaticCredentials`,
  `buildCredentialRegistry`, `checkCredentialBinding`,
  `createStaticCredentialResolver`, `StaticCredentialEntry` type, and a
  `credential_binding_failed` stage on `GatewayDenial`.

### Changed

- `credentials.type: registry` (documented but never implemented) now fails
  gateway config validation with a clear "not supported yet" error instead
  of being silently ignored — a security-relevant config section must never
  no-op.
- README caveats updated (gateway, root, verified-actions demo): the
  "credential permission claims are self-asserted and not cryptographically
  bound" caveat is now conditional on running Core mode without registered
  credentials.

## [0.7.6] — 2026-07-10

### Changed

#### SDK (`@bolyra/sdk` 0.6.0 → 0.6.1)

- snarkjs is now lazy-loaded at Groth16 prove/verify call sites (`src/zk.ts`
  cached loader). Bolyra Core paths — dev identities, receipts, gateway
  middleware, JWT delegation — never import it; module load cost and any
  snarkjs resolution problems no longer affect classical usage. No API changes.

## [0.7.5] — 2026-07-10

### Added

#### Gateway (`@bolyra/gateway` 0.2.1 → 0.3.0)

- **ES256K-signed receipts for EVERY decision** — allow and deny, dev mode
  and production. This makes the landing-page claim ("ES256K-signed receipt
  for every decision. Allow or deny.") true for the packaged proxy, not just
  the verified-actions demo it was lifted from. Previously dev mode emitted
  no receipts at all (`verifyDevBundle` never attaches one) and production
  denials were written as unsigned raw JSON.
  - Denials now carry full context: verdict, reason (which tool, required
    vs. held permissions), agent DID/score when known, proof-material hashes.
  - Requests with a missing or malformed proof bundle get a signed
    **anonymous deny receipt** — no unsigned gaps in the audit trail.
  - Same schema and crypto as `examples/verified-actions-demo`:
    `createAuthReceipt` + `signReceipt` from `@bolyra/receipts`; every
    receipt verifies independently via `verifyReceipt()` and is
    tamper-evident.
- **Signing key resolution**: explicit `receiptSigner` option →
  `receipts.privateKey` from config (now validated at startup: 32-byte hex)
  → ephemeral key generated at startup. The CLI prints the signer address in
  the banner, warns when running production on an ephemeral key, and (file
  output) persists `signer.json` to the receipt dir as the pinnable trust
  anchor — the same pattern as the demo's audit log.
- New exports: `createGatewayReceiptSigner`, receipt-input builders, and the
  `GatewayDenial` type (middleware now records why it denied a request on
  `req.bolyraDenial` so embedders can sign their own deny receipts).
- Receipts record the gateway's FINAL decision: the proxy signs its own
  receipts and deliberately does not forward a `receiptSigner` to the
  verification middleware, because a verification-step receipt says
  `allowed: true` for an authenticated agent that then fails tool policy
  (Codex review P1). Delegated calls attribute `actingDid` to the
  delegation-chain leaf. In the exceptional case that runtime signing fails
  (the key is probe-validated at startup), the fallback raw record is
  explicitly tagged `unsigned: true` so audit consumers can detect the gap.

### Fixed

- `X-Bolyra-Receipt-ID` header now actually carries the signed receipt id —
  it previously read a nonexistent `payload.receiptId` field and was never
  set. File-mode receipt filenames now use the receipt id instead of
  `unknown-{timestamp}`.
- A bundle that parses as JSON but carries no proof material made
  `verifyBundle` throw, surfacing as an unaudited 502. The middleware now
  fails closed: HTTP 401 plus a signed anonymous deny receipt (Codex review
  P1).

## [0.7.4] — 2026-07-09

### Added

#### External verifier CLI (`@bolyra/cli` 0.3.1 → 0.4.0)

- New `bolyra verify` subcommand: a spawnable external verifier for MCP hosts
  and agent-coordination servers. Reads one JSON request on stdin (an opaque
  proof bundle + the action to authorize + `now_unix`) and writes exactly one
  allow/deny verdict on stdout, fail-closed on everything else. Verifies the
  Bolyra proof envelope, delegation-chain non-expansion, scope/capability
  binding, model binding, strict expiry, trusted Merkle roots, and nonce replay
  — all anchored to the proof's public commitments — with fd-level stdout
  isolation so native prover writes can never corrupt the verdict.
- Host-agnostic contract published at `spec/external-verifier-contract-v1.md`;
  an `external_verifier` conformance vector type added to the conformance runner.
- First integration target: `mcp_agent_mail_rust#183` (see
  `docs/integrations/mcp-agent-mail-verifier.md`).
- Raises the `@bolyra/sdk` dependency floor to `^0.6.0`.

#### SDK primitives (`@bolyra/sdk` 0.5.3 → 0.6.0)

- New public exports (additive minor bump): `eddsaVerify` (BabyJubjub
  EdDSA-Poseidon signature verification — the inverse of `eddsaSign`), plus
  `poseidon5`, `eddsaSign`, and `derivePublicKey`. Previously internal; now
  public so the external verifier and third-party hosts can recompute
  credential/scope commitments and verify binding signatures.

### Fixed

- Conformance `proof_envelope` vectors: `content_type` corrected from the stale
  `application/bolyra-proof+json` to the canonical
  `application/vnd.bolyra.proof+json` (matches `sdk/src/envelope.ts`).

## [0.7.3] — 2026-07-08

### Fixed

#### Delegation (`@bolyra/delegation` 0.2.3)

- Repo reconciled with the published 0.2.2: the 0.2.1/0.2.2 hotfixes
  (published 2026-05-13) were cut from a working tree that was never
  committed — canonical `audience`/`trustedIssuers` option docs in
  `types.ts`, and the F2 fix in `verify.ts` (an expired receipt reports
  `EXPIRED` instead of being masked as `INVALID_SIGNATURE` by jose's
  generic error). Sources restored from the published tarball with
  regression tests added.
- New in 0.2.3: the F2 pre-check now uses `<=` so a receipt expiring
  exactly on the skew boundary also reports `EXPIRED` — published 0.2.2
  still returns `INVALID_SIGNATURE` in that one case (found by Codex
  review, confirmed with a frozen-clock regression test).
- New in 0.2.3: `jose.errors.JWTExpired` is caught distinctly, so a
  receipt that crosses expiry while a slow async issuer resolver is in
  flight (network DID/JWKS lookup) also reports `EXPIRED` fail-closed
  instead of `INVALID_SIGNATURE` (Codex round 2; clock-advancing-resolver
  regression test).
- New in 0.2.3 (**security**): `checkIssuerClaims` expiry comparison now
  uses `<=` to match jose's boundary — previously a receipt at exactly
  `exp + skew === now` could be *accepted* when the clock ticked between
  `jwtVerify` and the claim check (Codex round 3). This bug also exists
  in published 0.2.2.
- `release.yml` now covers `@bolyra/delegation@*` tags for future OIDC
  releases (Trusted Publisher config on npmjs.com still required first).

### Added

#### MCP Shield (`@bolyra/shield` 0.2.0)

- **Learn mode** — `bolyra-shield --learn --server "<cmd>"` spawns the target
  MCP server, performs the handshake (`initialize` →
  `notifications/initialized` → `tools/list` with cursor pagination), and
  generates a `shield.yaml` with `defaultDeny: true` and every discovered tool
  at `requireBitmask: 1` (READ_DATA). Hardened per 3-reviewer consensus:
  quote-aware spawn splitting (shared with the proxy), `_generated` provenance
  marker, 50-page pagination cap, 30s handshake timeout, guaranteed child
  cleanup, `O_EXCL` write (never overwrites an existing config), `yaml`
  serializer output.
- LICENSE and NOTICE now ship in the npm tarball (they were listed in `files`
  but missing from the package directory in 0.1.0).

## [0.7.2] — 2026-07-04

### Fixed

#### TypeScript SDK (`@bolyra/sdk` 0.5.3)

- **Fresh install was broken** — `snarkjs` and `ethers` were optional
  peerDependencies but are eagerly imported by `dist/index.js`, so
  `npm install @bolyra/sdk` followed by `require('@bolyra/sdk')` threw
  `Cannot find module 'snarkjs'` (the documented quickstart path, caught by
  the CI fresh-install smoke test). Both are now regular `dependencies`.
- Removed the unused `@semaphore-protocol/core` peer/dev dependency —
  nothing in the SDK imports it (the HumanUniqueness circuit reuses the
  Semaphore v4 *ceremony*, not the JS package).

## [0.7.1] — 2026-06-21

### Added

#### CrewAI Integration (`bolyra-crewai` 0.1.0) — NEW PACKAGE

- **`BolyraAuthTool`** — CrewAI BaseTool subclass for mutual ZKP handshake
  authentication. Dev mode and production mode with operator key.
- **`BolyraDelegateTool`** — scoped permission delegation with cryptographic
  narrowing. Comma-separated permission input for LLM reliability.
- **`BolyraSDJWTTool`** — lightweight SD-JWT delegation (pure Python, no
  Node.js). Receipt vaulting prevents bearer credentials from leaking into
  LLM context.
- **`BolyraGuard`** — pre-execution tool wrapper (`guard_tools()`) and
  post-execution step callback. Three failure modes: raise, warn, skip.
  Session TTL support.
- **`BolyraSession`** — thread-safe session management chaining handshake,
  delegation, and SD-JWT flows with auto-injected nonce/commitment.
- 88 tests covering metadata, behavior, E2E, guard, session, and types.
- Security hardening: 3 critical + 4 informational fixes from pre-landing
  review (operator key enforcement, verify_delegation check, PrivateAttr
  vault, case-normalized escalation check).



The **commerce receipts** release. Every commerce authorization
decision can produce a cryptographically signed receipt.

### Cohort version state after this release

| Package | npm / PyPI version | Notes |
|---|---|---|
| `@bolyra/receipts` | 0.7.0 | commerce receipt kind + createCommerceReceipt |
| `@bolyra/payment-protocols` | 0.7.0 | signed commerce receipts |
| `@bolyra/mcp` | 0.6.0 | unchanged |
| `@bolyra/sdk` | 0.4.0 | unchanged |
| `@bolyra/openclaw` | 0.3.1 | unchanged |
| `bolyra` (PyPI) | 0.4.0 | unchanged |

### Added

#### Receipts (`@bolyra/receipts` 0.6.0 → 0.7.0)

- **`createCommerceReceipt()`** — builds a `ReceiptPayload` with
  `kind: 'bolyra.commerce'` and commerce fields (rail, amount,
  currency, merchant, intentHash).
- **CLI** accepts `bolyra.commerce` receipts and validates commerce
  fields. Rejects `commerce` fields on `bolyra.auth` receipts.
- `createAuthReceipt()` now accepts optional `issuedAt` for timestamp
  alignment with upstream authorization decisions.

#### Payment Protocols (`@bolyra/payment-protocols` 0.5.0 → 0.7.0)

- **`signedReceipt`** on `CommerceAuthorizationDecision` — when
  `receiptSigner` and `receiptEvidence` are provided in options,
  `authorizeCommerceIntent()` produces a `SignedReceipt` with
  commerce-specific fields.

## [0.6.0] — 2026-06-13

The **signed receipts** release. Every MCP verification decision
produces a cryptographically signed, auditable receipt.

### Cohort version state after this release

| Package | npm / PyPI version | Notes |
|---|---|---|
| `@bolyra/receipts` | 0.6.0 | NEW — signed receipt primitives |
| `@bolyra/mcp` | 0.6.0 | receipt integration |
| `@bolyra/sdk` | 0.4.0 | unchanged |
| `@bolyra/payment-protocols` | 0.5.0 | unchanged |
| `@bolyra/openclaw` | 0.3.0 | unchanged |
| `bolyra` (PyPI) | 0.4.0 | unchanged |

### Added

#### Receipts (`@bolyra/receipts` — NEW)

- **`@bolyra/receipts`** — new package for signed authorization receipts
- `createAuthReceipt()` — builds a `ReceiptPayload` from verification context
- `signReceipt()` — secp256k1 signature with keccak256 hash, EVM-compatible 65-byte `r||s||v`
- `verifyReceipt()` — recovers signer address, validates payload hash and claimed signer
- `hashPayload()` — canonical JSON with sorted keys → keccak256
- `canonicalize()` — deterministic JSON serialization

#### MCP (`@bolyra/mcp` 0.4.0 → 0.6.0)

- **`receiptSigner`** config option — when set, `verifyBundle()` attaches a
  `SignedReceipt` to `BolyraAuthContext`. Covers production verification
  decisions (both allow and deny). Skipped in dev mode.

### Security

- `verifyReceipt()` checks recovered address matches the claimed
  `receipt.signature.signer`. Prevents forged signer metadata.

## [0.5.0] — 2026-06-11

The **unified commerce authorization** release. One API answers whether
a commerce intent is authorized across all payment rails.

### Cohort version state after this release

| Package | npm / PyPI version | Notes |
|---|---|---|
| `@bolyra/sdk` | 0.4.0 | unchanged |
| `@bolyra/mcp` | 0.4.0 | unchanged |
| `@bolyra/payment-protocols` | 0.5.0 | commerce authorization layer, x402 hardening |
| `@bolyra/openclaw` | 0.3.0 | unchanged |
| `bolyra` (PyPI) | 0.3.0 | unchanged |

### Added

#### Payment Protocols (`@bolyra/payment-protocols` 0.3.1 → 0.5.0)

- **`authorizeCommerceIntent(input)`** — unified commerce authorization
  across all payment rails. Accepts a `CommerceIntent` (amount, currency,
  merchant, rail, operation) plus the rail-specific adapter result. Returns
  a uniform `CommerceAuthorizationDecision` with `allowed`, `did`, `score`,
  `grade`, `warnings`, and an unsigned `CommerceAuthorizationReceipt`.
- **Stripe ACP** and **x402** fully wired. **Visa TAP** and **Google AP2**
  stubbed fail-closed with clear reason string.
- `CommerceAuthorizationReceipt` — deterministic unsigned receipt for
  logging and audit (signed receipts deferred to v0.6.0).

### Fixed

- **x402: credential resolution is now a hard gate.** Previously an
  unresolved credential scored 80/100 and passed the default minScore:70
  threshold. Now `credentialResolved` must be `true` for `verified` to be
  `true`. This is a **breaking change** for consumers that relied on the
  old behavior.
- **x402: currency match is now checked.** `verifyX402Authorization()`
  now compares `requirements.asset` against `bundle.spendPolicy.currency`
  (case-insensitive). Mismatches deny with a clear warning.
- `X402VerifyDecision` gains `credentialResolved: boolean` and
  `currency: string` fields.

### Migration

- `@bolyra/sdk` dep bumped from `^0.3.0` to `^0.4.0`.
- `X402VerifyDecision` has 2 new required fields — update any code that
  constructs or destructures this type.

## [0.4.0] — 2026-06-10

The **dev-mode release**. Adds a complete zero-friction developer path — no circuit artifacts, no trusted setup, instant local iteration — while tightening several correctness issues found during the v0.3 integration work.

### Cohort version state after this release

| Package | npm / PyPI version | Notes |
|---|---|---|
| `@bolyra/sdk` | 0.4.0 | dev mode, signal alignment, nonce fix |
| `@bolyra/mcp` | 0.4.0 | dev mode server/client, HTTP auth context fix |
| `@bolyra/payment-protocols` | 0.3.1 | unchanged |
| `@bolyra/openclaw` | 0.3.0 | unchanged |
| `bolyra` (PyPI) | 0.3.0 | unchanged |

### Added

#### SDK (`@bolyra/sdk` 0.3.1 → 0.4.0)

- **`createDevIdentities(options?)`** — returns fixed-seed `{ human, agent, operatorKey }` without requiring circuit artifacts. All values are deterministic. Logs a one-time `console.warn` on first call. Options: `permissionBitmask` (default 0b11111111), `expiryTimestamp` (default 2099-12-31). (#42)
- **Mock proving in `attachBolyraProof`** — pass `devMode: true` to skip real Groth16 proving and emit a mock bundle (`_dev: true`). The bundle carries the commitment so server-side policy checks still fire. (#42)

#### MCP (`@bolyra/mcp` 0.3.0 → 0.4.0)

- **`devMode` config flag** — when set, `withBolyraAuthStdio` and `bolyraAuthMiddleware` accept mock bundles (`_dev: true`) and skip ZKP verification. `resolveCredential` is also optional in dev mode. Safe to leave on in local development; never enable in production. (#42)
- **Protected file server example** (`integrations/mcp/examples/protected-file-server/`) — complete stdio server + client pair using dev mode. Demonstrates per-tool `READ_DATA` / `WRITE_DATA` gating with `createDevIdentities`. (#43)
- **Integration test** (`integrations/mcp/test/dev-mode-e2e.test.ts`) — subprocess end-to-end: spawns the protected-file-server process, exercises tool calls with valid and permission-denied bundles, asserts correct pass/reject behavior. (#44)

### Fixed

#### SDK (`@bolyra/sdk`)

- **Nonce unit mismatch** — `proveHandshake` was passing `Date.now()` (milliseconds) as the session nonce into the circuit, but `verifyHandshake` compared it against a seconds-based freshness window. The nonce is now `BigInt(Math.floor(Date.now() / 1000))` — unix seconds — matching the circuit's `currentTimestamp` input and the verifier's `maxProofAge` window. Handshakes generated before this fix will fail the freshness check. (#45)
- **Signal layout alignment** — `verifyHandshake` public-signal index constants updated to match the hardened circuit layout shipped in v0.3.0 (`currentTimestamp` at index 5 for Agent, `sessionNonce` at index 4 for Human). Previous indexing was off by one after the UC3.2 constraint was added. (#46)
- **Spec alignment: Groth16 REQUIRED** — `formatPlonkProof` removed from the public API. The AgentPolicy and Delegation circuits ship both `.zkey` artifacts, but the on-chain `IdentityRegistry` and the IETF spec (§4.2, draft-bolyra-mutual-zkp-auth-01) mandate Groth16 for all on-chain verification. `formatGroth16Proof` is the only exported formatter. Callers using `formatPlonkProof` must migrate. (#47)

#### MCP (`@bolyra/mcp`)

- **HTTP auth context not attached on success** — `bolyraAuthMiddleware` was calling `next()` after a successful verification but not writing `req.bolyra` before yielding, so downstream handlers saw `undefined`. Fixed by attaching `req.bolyra = ctx` before `next()`. (#48)

### Documentation

- **`sdk/QUICKSTART.md`** — `formatPlonkProof` → `formatGroth16Proof` in the on-chain example; verifier names updated to match `contracts/deployments/base-sepolia.json` (`HumanGroth16Verifier`, `AgentGroth16Verifier`, `DelegationGroth16Verifier`); spec link updated to `-01.md`.
- **`integrations/mcp/README.md`** — full rewrite leading with the dev-mode quickstart, API reference for all exports, production configuration guide, transport comparison table, and link to the protected-file-server example.

### Migration notes

- **`formatPlonkProof` removed**: use `formatGroth16Proof` for both the human and agent proofs in `registry.verifyHandshake()` calls.
- **Nonce unit change**: any stored or cached nonces from `proveHandshake` before 0.4.0 are in milliseconds and will fail the freshness check. Regenerate — do not cache nonces across versions.
- **Verifier contract name change** (docs only): the deployed contracts are unchanged. The names `PlonkVerifier` and `Groth16Verifier` in older docs referred to `AgentGroth16Verifier` and `HumanGroth16Verifier` respectively — now corrected in all documentation.

## [@bolyra/sdk 0.3.1] — 2026-06-02

Single-package hotfix; cohort otherwise unchanged.

### Cohort version state after this release

| Package | npm version | Notes |
|---|---|---|
| `@bolyra/sdk` | 0.3.1 | this release |
| `@bolyra/payment-protocols` | 0.3.1 | hotfix shipped 2026-05-30 (X402 helpers missing from 0.3.0 tarball) |
| `@bolyra/mcp` | 0.3.0 | unchanged |
| `@bolyra/openclaw` | 0.3.0 | unchanged |
| `bolyra` (PyPI) | 0.3.0 | unchanged |

**Versioning policy:** the cohort moves together on minor/major bumps (0.x.0,
1.x.0). Patch releases (0.x.N) are per-package — only the affected package
bumps, others stay at the cohort base. The cohort base is the highest minor
across published packages — currently 0.3. Tag scheme matches: cohort
releases use `v0.x.0` (e.g., `v0.3.0`); per-package patches use
`@bolyra/<pkg>@0.x.N` (e.g., `@bolyra/sdk@0.3.1`). The
`@bolyra/payment-protocols@0.3.1` release of 2026-05-30 was published before
this policy was written and has no git tag — gap acknowledged, not backfilled.

### Fixed

#### SDK (`@bolyra/sdk` 0.3.0 → 0.3.1)

- **`verifyHandshake(humanProof, agentProof, nonce, config?)`** — the `nonce`
  argument is now bound to the proof's committed `sessionNonce`. Previously
  decorative: snarkjs verified against the proof's embedded public signals
  regardless of the caller-passed value, so a mismatched nonce silently
  passed. Now compares `BigInt(humanProof.publicSignals[4]) === nonce` and
  `BigInt(agentProof.publicSignals[5]) === nonce`; short-circuits
  `verified: false` on drift before any vkey lookup. (#41)
- **Fail-closed parse on malformed public signals.** `BigInt(string)` throws
  on non-numeric input; the nonce check now goes through a `tryBigInt()`
  helper that returns `null` on parse failure, with `?? 0n` fallback for
  the returned nullifier/scope fields. Malformed signals now return
  `verified: false` instead of throwing. (#41, codex review fix)
- **Relative `circuitDir` paths.** `verifyHandshake({ circuitDir: './demo' })`
  now resolves via `path.resolve()`. Previously broke when the caller's cwd
  wasn't the SDK root. (#41)
- **Structural length floor** tightened to 5 / 6 public signals
  (Human / Agent) — proofs generated by incompatible circuit versions now
  throw a clear `VerificationError` instead of returning garbage.

### Tooling

- **`landing/verify.sh`** — runtime tamper-rejection gate added. `npm install`
  the published packages, `require()` every advertised symbol, run
  `snarkjs.groth16.verify` against pinned proof fixtures, then flip the last
  decimal digit of `agentProof.pi_a[0]` and re-verify; strict assertion that
  `verified === false`. Motivated by the 2026-05-30 X402 outage where the
  string-match-only verify.sh stayed green for 14h while the published
  tarball was missing the advertised functions. (#40)
- **`/402` page** — Quickstart code blocks now labelled as TypeScript with
  `npx tsx server.ts` run hint (Node 22.6+ also supported via
  `--experimental-strip-types`). (#38) Landing page SDK snippets are
  self-contained — fixture preambles, no dangling references. (#39)

## [0.3.0] — 2026-05-30

The **delegation release**. Phase 1 (mutual handshake) was 0.2; Phase 2 adds
one-way scope-narrowing delegation with on-chain replay protection, an
end-to-end MCP delegation chain, and the first agentic-commerce wedge
(Stripe Agent Commerce Protocol).

### Added

#### SDK (`@bolyra/sdk` 0.2.1 → 0.3.0)

- **`delegate(rootCred, hops[])`** — Groth16 single-hop delegation proofs,
  identity-bound via `Poseidon3(scope, credCommitment, expiry)` chain and
  `Poseidon4` delegation tokens. Pre-flight scope / expiry / chain-link
  rejections fire before paying for proving. (#7)
- **`verifyDelegation(proof)`** — verifies a single delegation hop.
- **`attachDelegatedBolyraProof(human, rootCred, hops[])`** — client helper
  that runs handshake once and walks `delegate()` per hop, returning a
  complete v=2 bundle. (#10)
- Re-exported `poseidon2 / poseidon3 / poseidon4` for consumers that need to
  reconstruct binding commitments.

#### MCP (`@bolyra/mcp` 0.1.0 → 0.3.0)

- **`BolyraProofBundle` v=2** — optional `delegationChain:
  BolyraDelegationLink[]` so authority can flow root → agent A → agent B
  end-to-end. v=1 single-credential handshake still accepted. (#10)
- **`BolyraAuthContext.chainDepth` + `effectiveCommitment`** — visible to
  per-tool policies.
- **`permissionBitmask` now reflects the leaf delegatee's scope** when a
  chain is present, so per-tool policies see what the calling agent can
  actually do, not what the root granted.
- **`verifyBundle` walks the chain** — per hop runs `verifyDelegation`,
  recomputes `Poseidon3(scope, commitment, expiry)`, matches against
  `publicSignals[0]`, rejects expired hops.
- Standalone off-chain delegation demo (`npm run demo:delegation`) and
  proxy delegation mode (`BOLYRA_DELEGATION_MODE=1`) in
  `examples/mcp-demo`. (#11)

#### Contracts

- **`IdentityRegistry.verifyDelegation`** — accepts the canonical 6-public-
  signal Delegation layout `[newScope, nullifier, delegateeRoot, prevScope,
  sessionNonce, currentTimestamp]`. (#12)
- **On-chain 2-hop delegation demo** (`npm run demo:delegation:onchain`):
  handshake 538k gas, hop1 311k gas, hop2 294k gas, replay correctly
  reverts `ScopeChainMismatch`. (#12)
- **Public layout-version constants** — `HUMAN_PUBSIG_LAYOUT_VERSION`,
  `AGENT_PUBSIG_LAYOUT_VERSION`, `DELEGATION_PUBSIG_LAYOUT_VERSION` — and
  explicit `*_PUBSIG_LEN` length checks with a typed
  `PubSignalsLengthMismatch` revert. (#15)

#### Payment protocols (`@bolyra/payment-protocols` 0.1.0 → 0.3.0)

- **Stripe Agent Commerce Protocol (ACP) wedge** — pure mapping over
  `BolyraVerifiedContext`. Three exports: (#13)
  - `bitmaskToStripeSpendingLimits(bitmask, currency?)` — collapses
    cumulative bits 2/3/4 into Stripe spending tiers.
  - `authContextToStripeACPContext(ctx, rootCommitment, network?, currency?)`
    — maps leaf delegatee → `actingAgentDid`, root credential →
    `rootAgentDid`, `chainDepth` → `delegationDepth`.
  - `verifyStripeACPSpend(ctx, amount, currency, operation?)` — per-
    PaymentIntent gate. `operation: 'authorize' | 'confirm'` (#15, P1-6).
- LICENSE + NOTICE now ship in the published tarball (PR #6 patent-grant
  audit fix-forward). (#15)

#### Python SDK (`bolyra` 0.1.1 → 0.3.0)

- **`delegate()` + `verify_delegation()`** via the existing subprocess
  bridge to `@bolyra/sdk`. Python owns types + pre-flight; Node owns
  proving. New `DelegateeMerkleProof` dataclass +
  `delegatee_merkle_root` field on `DelegationResult`. 10 new tests,
  65/65 total green. (#8)

#### Spec

- **11 v0.3 delegation conformance vectors** in `spec/test-vectors.json`
  (vector format `0.2.0 → 0.3.0`, corpus 37 → 48): 2-hop chain, forged-
  token EdDSA, nullifier-per-nonce, Poseidon3/4 binding formulas with
  per-field sensitivity assertions, LeanIMT single- and two-leaf root
  edges, canonical 6-element public-signals layout, financial scope
  narrowing, cumulative-invariant FAIL on delegatee. (#9)

### Changed

- **Permission bitmask in `BolyraAuthContext` reflects the leaf** when a
  delegation chain is present (was: root). Consumers that previously read
  this field as "what authority the root granted" will see narrower bits
  on delegated calls. v=1 bundles are unaffected. (#10)

### Security

The codex adversarial review surfaced 18 findings. All BLOCK + HARDEN
buckets shipped in 0.3.0; DEFER bucket (P2-1 LeanIMT proof shape, P2-2
Merkle proof builder, P2-7 correlation surface) is deferred to a
follow-up release with no consumer impact.

- **BLOCK bucket (#14)** — 4 P1 holes closed before any 0.3.0 surface
  shipped.
- **HARDEN bucket (#15)** — 8 defense-in-depth fixes:
  - **P1-2** `IdentityRegistry`: explicit pubsig-length revert + public
    layout-version constants at the ABI boundary.
  - **P1-5** `bitmaskToStripeSpendingLimits` enforces cumulative-bit
    shape — non-cumulative bitmasks (e.g. bit 4 without 2+3) collapse to
    `tier='none'` instead of silently picking a tier.
  - **P1-6** Stripe ACP `confirm` operation fails closed without
    `SIGN_ON_BEHALF` (bit 5); `authorize` stays open.
  - **P1-9** Stripe ACP boundary uses `>= cap` matching CLAUDE.md strict
    `< $100` / `< $10K` semantics. `$100` exact and `$10K` exact reject.
  - **P1-10** Bundle round-trip drift detection (string bitmask reject,
    missing warnings reject) against a fixture pinned to
    `@bolyra/mcp/src/types.ts`.
  - **P2-3** Nullifier-replay test with matching `prevScope` proves the
    `DelegationNullifierReused` guard fires and state rolls back.
  - **P2-4** 4th-hop boundary test proves `MaxDelegationHopsExceeded`
    fires at `hopCount == MAX (3)` and state rolls back.
  - **P2-6** Stripe ACP amount integer-minor-units guard — rejects
    non-finite, fractional, non-safe-integer, and non-positive amounts
    before tier comparison.

### Fixed

- **Circuit unit tests** (`circuits/test/Delegation.test.js`) were silently
  failing on `main` after the `68b7266` circuit hardening commit added the
  UC3.1 (Poseidon5 delegator credential binding) and UC3.2 (Poseidon3
  expiry-bound scope commitment) constraints plus `currentTimestamp`
  liveness. The witness builder still constructed inputs against the
  pre-hardening signal list and pre-hardening commitment formulas.
  Updated the `createDelegation` helper to compute `delegatorCredCommitment`
  via Poseidon5, `previousScopeCommitment` via Poseidon3, and to pass
  `delegatorModelHash` + `currentTimestamp`. Chain test now derives
  agent A's commitment from Poseidon5 so the hop-2 binding holds. CI
  did not catch this regression because circuit unit tests aren't part
  of the PR pipeline; contracts integration tests (which exercise the
  same `.wasm` / `.zkey` artifacts) were always green and remain so.

### Test infrastructure

- New `contracts/contracts/test/TestableIdentityRegistry.sol` (owner-gated
  test-only setters: `__test_setLastScopeCommitment`,
  `__test_setDelegationHopCount`, `__test_setUsedDelegationNullifier`)
  isolates guards that the production replay test can't reach because
  `ScopeChainMismatch` fires first. Excluded from production deploy
  scripts.

### Migration notes

- **MCP consumers**: bundle v=2 is a superset of v=1. If you store
  `BolyraAuthContext.permissionBitmask` somewhere and use it for
  authorization, audit: on a v=2 chain, this is now the **leaf**
  bitmask, not the root. If you need the root, use
  `effectiveCommitment` + the on-chain registry.
- **Contract integrators**: `IdentityRegistry.verifyDelegation` and
  `IDelegationGroth16Verifier.verifyProof` now take `uint[6]` pubSignals
  (was `uint[5]`). Regenerate ABIs and pass the canonical layout
  `[newScope, nullifier, delegateeRoot, prevScope, sessionNonce,
  currentTimestamp]`.
- **Integration peer deps**: `@bolyra/mcp`, `@bolyra/payment-protocols`,
  and `@bolyra/openclaw` now require `@bolyra/sdk >=0.3.0`. Cohort
  released together.

## [0.2.x] — pre-2026-05-30

Phase 1 — mutual handshake. See git history for per-PR detail; this
file's release log starts at 0.3.0.

[0.3.0]: https://github.com/bolyra/bolyra/releases/tag/v0.3.0
