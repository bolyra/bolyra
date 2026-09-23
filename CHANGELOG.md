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

## @bolyra/mpp 0.6.0 (2026-09-22)

Bounded nonce retention, honest spend-mandate naming.

### Changed (BREAKING)

#### `@bolyra/mpp`

- `IssueMandateInput.maxUsd` is removed and replaced by `coversAmountUsd`. The old
  name asserted a ceiling the value never had: it selects a **tier**, so
  `maxUsd: 25` authorized any amount under $100 and `maxUsd: 100` authorized any
  amount under $10,000. Passing `maxUsd` now throws `MandateIssueError` naming the
  replacement rather than silently authorizing a bucket.
- `IssuedMandate` gains `authorizedMaxUsd` (the tier's exclusive USD ceiling, or
  `null` for `unlimited`) and `authorizedRange` (the same in words). Read these for
  what was actually authorized; the amount you passed in is only a tier selector.
- `bolyra mandate issue` renames `--max-usd` to `--covers-amount`. The old flag
  exits 2 with the migration message. The summary now prints an `authorizes:` line.

### Migration

- Replace `maxUsd:` with `coversAmountUsd:` in every `issueMandate` call.
- Replace `--max-usd` with `--covers-amount` in every `bolyra mandate issue` invocation.
- Where you meant a real ceiling, pass `tier` directly instead of an amount.
- Read `authorizedMaxUsd` (not your input amount) wherever you log or display the limit.
- **Release ordering — `@bolyra/cli` is NOT releasable from this commit.** Its source
  now calls `coversAmountUsd`, but its dependency range is still `@bolyra/mpp ^0.4.0`
  and its committed lockfile resolves 0.4.0. The range cannot be bumped here because
  `scripts/verify-lockfiles.sh` runs a clean `npm ci` on every committed lockfile and
  `0.6.0` is not published yet. Publish `@bolyra/mpp` 0.6.0 first, then bump the CLI's
  range and regenerate its lockfile in a follow-up, then release the CLI. CI is
  unaffected: the CLI's `tsconfig` paths and its jest `moduleNameMapper` both resolve
  `@bolyra/mpp` to the workspace package, so the job typechecks and tests against
  0.6.0 regardless of the published range in `package.json`.

### Fixed

#### `@bolyra/mpp`

- The reserve-before-act nonce store's cleanup is no longer quadratic.
  `NonceStore.evict()` previously walked the entire retained map on every
  `reserve()` while `retain_until` was the raw credential expiry (every shipped
  fixture expires in 2100), so nothing was ever evicted: 10,000 retained
  reservations cost 49,995,000 cleanup iterations. Sweeping is now amortized against
  a bounded per-call budget AND resumes from a persistent cursor, so long-lived
  entries at the front can no longer hide expired ones behind them. A lookup whose
  retention has elapsed is treated as free, so a lagging sweep can never produce a
  false `nonce_replayed`.
- The store **honours `retain_until` exactly as stated** and never silently shortens
  it: EVC §3.2 makes retaining through that instant a host obligation, and quietly
  retaining less would surface as a replay being accepted. The new
  `maxRetentionSeconds` option instead REFUSES a requirement the store will not
  honour (`NonceRetentionTooLongError`, fail closed). It is unset by default, because
  a verifier deployed before this release still emits the raw credential expiry and
  defaulting to refusal would fail every request against it.
- The memory bound is therefore the capacity ceiling: at `DEFAULT_MAX_ENTRIES`
  (1,000,000 live) the store refuses new reservations rather than evicting live ones,
  because evicting a live reservation re-opens the replay it exists to prevent. A
  full sweep can run at most once per distinct clock value, so repeated refusals at
  capacity cannot be used to trigger repeated full scans. The gate reports the
  refusal as a fail-closed `internal_error`, never as `nonce_replayed` — the
  presentation was not reused. This path mattered because `enforce: 'always'`
  reserves on the 402 discovery request, **before** payment, so an unpaid caller
  could drive reservations.
- The gate no longer echoes an injected nonce store's raw exception text in the
  denial detail, which reaches the HTTP response; a Redis or SQL client puts
  connection and query information in `message`. Our own refusals keep their
  operator-facing text; anything else is logged and reported generically.

#### Verifier cores (`bolyra verify` and hosted-verify)

- Both verifiers now clamp the `retain_until` they emit to at most 30 days past the
  caller's clock, instead of asking a host to retain a nonce until the credential
  expires. EVC constrains what a host **must** retain, never what a verifier **may**
  ask for, so a bounded statement is conformant. The clamp is a ceiling, not a
  floor: a credential expiring inside the window keeps its own expiry.
- Stated plainly, because it is a real reduction in guarantee: once a reservation
  ages out at 30 days, **the same unmodified presentation can be presented again**
  and will be accepted, establishing another 30-day reservation, repeatedly until the
  credential itself expires. Host mode previously protected a presentation for the
  credential's whole life. Lifetime protection now requires a credential expiry
  inside the retention window, enforced presentation freshness, or a durable store
  configured for longer retention — pointing a durable store at the newly shortened
  `retain_until` does not restore it. Local nonce mode has always had this same
  30-day bound; host mode now agrees with it.
- The `MAX_NONCE_TTL` constant's "spec §5.2" citation was wrong — §5.2 is the
  single-object stdout parse rule — and is corrected.

## Unreleased — hosted verify endpoint

### Changed (BREAKING)

#### Hosted verify endpoint (`integrations/hosted-verify` — private, not published)

- `PREVIEW_TOKEN`, `PARTNER_TOKENS` and `TRUSTED_OPERATORS` are removed. One `TENANTS` secret replaces all three: a JSON object mapping an org id to that tenant's admin token, verifier token and trusted operator keys. Trust is now per tenant — an allow requires the credential's operator key to be in the *calling* tenant's `trusted_operators`. **Migration:** set `TENANTS` before deploying; every existing token stops working the instant it lands; afterwards `npx wrangler secret delete PREVIEW_TOKEN` and `npx wrangler secret delete PARTNER_TOKENS`.
- A token with the wrong role is `403 {"error":"forbidden"}`. `POST /v1/verify` accepts a tenant's verifier token only; an admin token is rejected there.
- Configuration defects are the 500 `internal_error` verdict: an unset, malformed or oversize `TENANTS`, an entry with an empty `trusted_operators` list, or a tenant quarantined with `"disabled": true`. The map is validated as a whole on every request, so one invalid entry fails closed for every tenant. Consequence: a malformed request body sent to a deployment whose configuration is broken is now `500 internal_error`, where it used to be `200 malformed_input`.
- Usage analytics attribute every request to `<org_id>:<role>` instead of a bare partner label; the reserved label `unauthenticated` is unchanged. Tokens are still never recorded.
- `/health` reports `tenants: "ok" | "invalid"` — whether the `TENANTS` secret parses. It is a parseability signal, not per-tenant availability: a quarantined (`disabled`) tenant still reports `ok`.
- `POST /v1/verify` now requires the presented signed binding to be ACTIVE in the tenant's managed credential registry: an unregistered or revoked binding is `deny untrusted_root` with `detail: { reason: "credential_not_active", credential_id }` (one reason for both; revoked-vs-unregistered is admin-only); a registry failure or the 2,000 ms read deadline is the `500 internal_error` verdict. An allow carries `x-bolyra-credential-id` (unsigned correlation). `/health` reports `registry_enforced: true` and the trust-policy amendment under `trust_policy`. One structured log line per authenticated decision and per authenticated registry request (`request_id, org_id, role, route, verdict, code, credential_id?, latency_ms`); a `401`, a wrong-role `403`, a quarantined tenant and a configuration defect are decided before that line and carry no decision line (analytics records them, and a configuration defect also logs at `error` level, a quarantined tenant at `warn`). Migration: register every binding a tenant expects to verify BEFORE deploying this build; a deployment that verified without the registry must never be rolled back to. The README quickstart examples are now the v2 conformance fixtures (the shipped copies carried a v1 binding and denied `unsupported_version`) plus `examples/registration.allow.json` for the register step.

### Added

#### Hosted verify endpoint (`integrations/hosted-verify` — private, not published)

- A managed credential registry per tenant (a SQLite-backed Durable Object named by `org_id`) and three admin-token routes: `POST /v1/credentials` registers an operator-signed binding (checks: trusted operator → signature → expiry; `201`, or `200` with the original `registered_at`, or `409` once revoked), `GET /v1/credentials/{id}` returns the record with its history, `POST /v1/credentials/{id}/revoke` is idempotent (`204`). `credential_id` is derived from the canonical operator key id and the signed binding — never from a presentation. Revoked records are retained indefinitely; a quarantined tenant gets `503 tenant_disabled` on these routes. `/health` reports `registry` and `credential_id_version`. The README's storage disclosure now states exactly what the registry persists.
- Provisioning: `pilot/tenant.sh` (`add`, `rotate`, `disable`, `enable --keys-retired`, `remove`, `sync [--dry-run]`, `show`) keeps the two tokens per tenant in the macOS keychain, the tenant records in `pilot/tenants/`, assembles `TENANTS` in memory, validates it with `pilot/tenants-check.mjs` — the Worker's own rules, proven against its loader by a test — and streams it into `wrangler secret put` through a guard that starts wrangler only once a non-empty validated map has arrived (a pipeline whose last stage is `wrangler secret put` would put an EMPTY secret on a validator refusal); a map the Worker would reject is never pushed and no token is ever printed. A staging environment (`env.staging` in `wrangler.jsonc`, deployed as `bolyra-hosted-verify-staging`) redeclares the bindings Wrangler does not inherit, with its own secrets, Durable Object namespace, and analytics dataset; `CAPABILITY_MAP` now carries `@bolyra/mpp`'s spend-mandate vocabulary (the `0.5.0` snapshot in the mandate fixture) in both environments, pinned by a test. `pilot/RUNBOOK.md` and `pilot/INTEGRATION.md` are rewritten for the registry: registration is part of onboarding and of the partner smoke test, quarantine is described per route family (500 verdict on verify, 503 on the registry routes), the deny table names both `untrusted_root` causes, and the deploy section is staging first, the example's 20 checks against staging as the gate, then a one-step 100% cutover whose version id is the rollback floor. No deployment is made by this change; the rollback-floor table is empty until one is.
- A scheduled GitHub Actions probe of production `/health` (every 15 minutes, best effort) that fails when the tenant map or registry enforcement is not healthy; the runbook's alarm instruction now points at it.

#### Managed revocation example (`examples/managed-revocation` — new, not published)

- The runnable revocation demonstration: issue a spend mandate with the published `@bolyra/mpp@0.5.0`, register it with the hosted verifier, spend through an mppx gate (real 402→pay handshake, two fresh presentations per paid action), revoke, and the next fresh presentation is denied `untrusted_root` / `credential_not_active` before the paid action runs; an independent credential under the same operator still allows. Runs in CI against `wrangler dev` (job `managed-revocation-example`, Node 22) with a generated `.dev.vars` that is never printed.

### Changed

#### Hosted verify endpoint (`integrations/hosted-verify` — private, not published)

- Production receipt key id is `preview-2` (signer key rotated at the registry cutover; `/.well-known/bolyra-signers.json` publishes the new key). Staging is `staging-1`.

### Fixed

#### Hosted verify endpoint (`integrations/hosted-verify` — private, not published)

- `REGISTRY_DEADLINE_MS` moved from the Worker entry module to `src/deadlines.ts`. The Workers runtime accepts only handlers, classes and functions as entry-module exports and refuses to instantiate otherwise (`not of type 'function or ExportedHandler'`), so `wrangler dev` would not start and a deploy would be rejected when the runtime instantiated the module — while the vitest pool, which does not enforce that rule, stayed green. A test now pins what the entry module may export.

## @bolyra/mpp 0.5.0 (2026-09-19)

### Changed (BREAKING)

- Denials are **thrown** as `BolyraDeniedError` from the gate's `preflight`/`verify` hooks instead of being returned as a `Response`. mppx converts a returned non-402 preflight `Response` into an outer `status: 200`, which let the documented handler run the protected action after a denial. **Migration:** wrap Fetch-style handlers with `handleDenials` (or catch `BolyraDeniedError` and return `err.response`); Express/Node handlers use `sendDenial(err, res)` — e.g. in an error middleware (a returned `Response` does not complete an Express request).
- `onReceipt` must be **synchronous**. A sink that returns a Promise is treated as a sink failure and the request is denied `internal_error` (an async sink's rejection could otherwise never fail the decision). **Migration:** hand off to a queue synchronously inside the sink.
- `enforce: 'payment'` combined with a method `authorize` hook is refused at construction (`BolyraGateConfigError`); credential-less discovery under `enforce: 'payment'` may only yield `undefined` or a 402 from the method's own `preflight` — anything else is denied. **Migration:** use `enforce: 'always'` (the default) or remove the hook.
- The stashed authorization decision is consumed one-use: a second `verify` against the same captured request fails closed; a failed payment rail means the client retries with a fresh presentation.
- A receipt sink failure (throw or Promise) now denies the request `internal_error` on every path instead of escaping; on the allow path this consumes the presentation's nonce.
- `issueMandate` now mints a fresh, random nullifier (`publicSignals[1]`) per issuance. Previously it was a constant, which made every standing mandate single-use against a hosted verifier that reserves the nullifier. Presentations minted by 0.4.0 keep working; re-issue rather than re-present.
- `mppx` peer dependency is pinned exactly to `0.8.13`, the version the real-mppx action-counter suite runs against; the range widens only when that suite passes on a newer mppx. Consequence: with npm 7+, a consumer whose tree already resolves a different `mppx` version gets an `ERESOLVE` install failure (optional peers are validated when present); pnpm/yarn warn. Escape hatch at the consumer's own risk: `--legacy-peer-deps`.

### Added

- `handleDenials`, `sendDenial`, `BolyraDeniedError`, `BolyraGateConfigError`, `isBolyraDeniedError`, `isBolyraGateConfigError` exports.
- `test-integration/`: the gate driven through real `Mppx.create()` (mppx pinned 0.8.13), with an application-owned execution counter; runs in CI alongside `typecheck:integration`.
- `MppxServerMethodLike` hook typing accepts a real mppx `Method.Server` under strict settings (method syntax; optional `realm`/`secretKey`/`credential`/`request` fields).
- The shipped `demo` CLI and `examples/mandate-demo` migrated to the new contract.

## @bolyra/evc-conformance 0.7.0

### Added

- **`verifier_config_fault` class** (vector set **0.10.0 → 0.11.0**, 125 → 126
  vectors), one vector: `verifier-config-fault-internal-error-exits-non-zero`.

  §7.1 and the §9 registry row bind `internal_error` to a **non-zero exit**, and
  it is the only code in the registry that does. `verifier_envelope` could not
  test that rule, so a verifier could violate §7.1 on every `internal_error`
  path and still score 11/11 — and one real external verifier did.

  The assertion was never missing; the runner already flagged a deny with
  `code=internal_error` at exit 0. What was missing is an **input that reaches
  it**. The only such probe was `null` on stdin (added in 0.6.0), which worked
  by accident of `typeof null === 'object'`; once implementers classify `null`
  correctly it is gone.

  No *request* portably induces `internal_error` in a correct verifier — a
  request that does is almost always a misclassification the implementer should
  fix. That is an empirical finding, not a proof of impossibility. The portable
  inducer is a **config fault**: corrupt the verifier's own trust configuration,
  then send a request it would otherwise answer. Mechanism contributed by
  `stillmarcus24` on `stillmarcus24/x402-authority-verifier-kit#1`.

  Setup is implementation-specific and supplied by env (`VERIFIER_FAULT_CMD`,
  `VERIFIER_FAULT_UNDO_CMD`, `VERIFIER_VALID_REQUEST`); the suite cannot supply
  a valid request, because the trust check runs after root recovery and the
  bundle is opaque per spec.

  Deliberately **not** failures: missing hooks SKIP, and a deny carrying some
  other code SKIPs — nothing obliges every verifier to classify a config fault
  as `internal_error`, so it is neither a failure nor exercised coverage. An
  `allow` under the fault always FAILS: a trust source that is present but
  unusable must never silently disable trust enforcement.

  Red-green through the package entry point against two commits of one real
  external verifier: `660902f6` FAILS (the corrupt store silently became "not
  enforced" and the request was allowed) and `1aa9d88` PASSES (`deny
  code=internal_error`, exit 1). At `660902f6` the fail-open **masks** the
  exit-code path, so that red run does not itself exercise `internal_error` at
  exit 0; that defect is separately supported by source review at that pin.

### Fixed

- **An explicitly selected vector now runs through `bin.js`.** The launcher
  prepends `--type` for its two default modes and the runner ANDs that with
  `--vector`, so selecting a vector outside the default class matched nothing
  and **exited 0** — a vendored vector no implementer could run, reporting
  success while testing nothing. An explicit `--vector` now stands the injected
  `--type` down. Both default modes are unchanged: `--verifier` still selects
  exactly the 11 `verifier_envelope` vectors, and a regression in `npm test`
  asserts that count so it cannot silently move.
- `verifier_config_fault` added to the vendoring filter; without it the vector
  would have lived in `spec/` and never shipped.

### Note

Previous entries for 0.2.0 and 0.6.0 were marked `(UNRELEASED)` although both
are live on npm with attestations. Corrected here.

## @bolyra/evc-conformance 0.6.0

### Added

- `verifier-envelope-deny-json-null-request` (vector set **0.9.0 → 0.10.0**,
  124 → 125 vectors): stdin is the JSON literal `null`. `null` is valid JSON
  but is not a JSON object, so §2.1's "not a JSON object" trigger binds it to
  deny `code=malformed_input`.

  It is deliberately distinct from `verifier-envelope-deny-request-not-object`
  (which sends `[1,2,3]`). In JavaScript `typeof null === 'object'`, so the
  obvious guard `typeof req !== 'object'` admits `null`, and the next property
  read throws. A verifier that catches that throw and reports
  `deny code=internal_error` still fails the vector: the code is wrong. If it
  also exits 0 it violates §9 as well, which binds `internal_error` to a
  non-zero exit.

  Found by probing rather than by review, against the first external
  verifier-side implementation
  (`stillmarcus24/x402-authority-verifier-kit` @ `35e209d`), and acknowledged
  to that implementer as a coverage gap on our side. Red-green proved against
  two real verifiers: the unpatched kit 8/11, the same kit with the check-order
  fix 11/11, and an always-allow negative control 0/11.

## @bolyra/evc-conformance 0.5.0

### Added

- New vector class `verifier_envelope` (vector set **0.8.0 → 0.9.0**, 114 →
  124 vectors): 10 domain-agnostic wire-envelope vectors for the VERIFIER
  side of the contract — the universal §2.1/§2.2 negatives (malformed stdin,
  structural violations, wrong envelope version) plus §3.4/§5.1/§7.1
  envelope assertions on every response (exactly one closed verdict object
  on stdout, exit 0). No vector assumes anything about `bundle` semantics,
  so a verifier for any proof domain can run the class unmodified. Two
  vectors (empty bundle, non-positive now_unix) assert only the deny — the
  contract fixes the rejection but not its code there — while the
  wrong-version vector asserts `unsupported_version` exactly; the envelope
  check itself closes deny codes over the §9 registry, so an invented code
  fails every vector.
- Runner: `--verifier "<cmd>"` flag / `VERIFIER_CMD` env (verifier-under-test
  convention, mirroring `--host`); falls back to the built reference CLI,
  else skips with a build hint.
- `evc-conformance --verifier "<cmd>"` runs the new class from the published
  package; the vendored vector subset now includes both dependency-free wire
  classes (host_behavior + verifier_envelope).

### Validation

- Reference CLI (`bolyra verify`): 10/10.
- First external data point, StillOS `x402-authority-verifier-kit` @
  `35e209d` (network-isolated): 8/10 — two genuine §2.1 code-classification
  gaps (non-object stdin classified `unsupported_version`; missing REQUIRED
  `bundle` classified `invalid_bundle`), queued for an upstream report.

## @bolyra/evc-conformance 0.2.0

**Release gate:** held until `khandrew1/mcp-use-evc-example` (an independent
external host implementation) is harness-green on vector set 0.5.0 — do not
tag before then. Moving the conformance target while an external implementer
is one fix away from green would invalidate their in-flight run.

**Gate satisfied 2026-08-26:** fix merged upstream and verified at clean
merged-main commit `17642a5` — 27/27 `host_behavior` on vector set 0.5.0
(sha256 `879d1cf9647f4f42e0815e34eeb5587633dff28e8fa8ceab25c139f470bb629c`).
Clear to tag.

### Added

- New host-behavior vector `host-deny-unknown-denial-code` (vector set
  **0.5.0 → 0.6.0**, 111 → 112 vectors, host_behavior 27 → 28): a verifier
  returns an otherwise well-formed `deny` whose `code` is outside the §9
  registry. The §3.4 deny schema closes `code` over the registry enum, so a
  conforming host MUST fail closed with `schema_invalid` and MUST NOT relay
  the unknown code. Previously no vector exercised this, so a host that
  relays arbitrary denial codes could pass the suite. Both reference hosts
  (JS and Rust) already enforce the registry and pass unchanged, 28/28.

### Changed

- Spec (`external-verifier-contract-v1.md`): §7.2 now states the fail-closed
  classification precedence explicitly (own kills → signal death → non-zero
  exit → parse/schema) and that `signal_death` vs `nonzero_exit` are distinct
  classes a host must not collapse; §9 now states the registry is closed
  within wire version 1 and reconciles the old "treat an unrecognized future
  `code` as deny" sentence — the deny is the host's `schema_invalid`
  fail-closed override, never a relayed verdict. Both edits tighten prose
  around behavior the reference hosts and §3.4 schema already had; the wire
  contract is unchanged.

## @bolyra/cli 0.9.0 (2026-08-25)

### Added

- `bolyra receipt verify` / `verify-chain` run `verifyInstanceBinding`
  whenever a receipt carries an `instance` block — a new failure mode
  (`FAIL: instance binding invalid [code]`); `receipt verify`'s PASS output
  additionally reports the ref.

### Changed

- Dependencies: `@bolyra/receipts@~0.11.0`, `@bolyra/mpp@^0.4.0`.

## @bolyra/payment-protocols 0.8.0 (2026-08-25)

### Changed

- x402 EVC profile: the 402 challenge nonce is documented as the receipt
  instance discriminator (profile spec §4.1; `X402EvcContext.nonce` jsdoc) —
  profile hosts recording receipts set `requestNonce` to it when building
  the instance block.
- Dependencies: `@bolyra/mpp@^0.4.0`, `@bolyra/receipts@^0.11.0`.

## @bolyra/receipts 0.11.0 (2026-08-25)

### Changed

- `verifyInstanceBinding()` no longer throws on non-receipt input (missing or
  invalid `payload`): new `malformed_receipt` result code. This widens the
  published `InstanceBindingCode`/`InstanceBindingResult` union — a minor
  bump, not a patch.
- The `bolyra-receipt-verify` bin (the golden-corpus verifier) now runs the
  instance-binding check after the signature check — a signer-issued receipt
  with a forged `instance.ref` passes the signature check and must still
  fail.
- `tsx` is now a declared devDependency (the verify-cli tests shell out to it;
  previously resolved from cache/network only).

## @bolyra/receipts 0.10.0 (2026-08-25)

### Added

- **Receipt instance binding** (`spec/receipt-instance-binding-v1.md`): optional
  signed `instance` block on commerce receipts — a `birv1:`-prefixed,
  domain-separated ref plus its full preimage, third-party-recomputable from
  the action's own facts. New public API: `verifyInstanceBinding()`,
  `computeInstanceRef()`, `validateInstancePreimage()`,
  `INSTANCE_BINDING_DST`, `INSTANCE_REF_PREFIX`. Signature validity and
  instance-binding validity are different claims. Externally design-reviewed
  on x402-foundation/x402#3230.
- §3.1.1 audience identifier syntax is part of the verifier domain:
  `audience` MUST match `^[\x21-\x7E]{1,256}$`; a display-name audience is
  `out_of_domain`.

## @bolyra/mpp 0.4.0 (2026-08-25)

### Changed (BREAKING)

- `DecisionFacts` renamed to `DecisionReceiptFacts` (deprecated alias kept)
  and gains a required `decisionAt` (RFC 3339 UTC, 3-digit ms) plus optional
  `requestNonce`. New `DecisionInstanceFacts` carries the pure spec-§3
  preimage facts; `buildDecisionInstance()` takes it (helper:
  `instanceFactsFrom()`).
- `bolyraGate` validates `audience` against the §3.1.1 identifier syntax and
  `program` as non-empty ASCII at construction (as does `issueMandate`) —
  display-name audiences and empty discriminators are rejected before
  anything signs.

### Added

- Every gate decision receipt carries a signed `instance` block whenever the
  spend facts are resolved and the clock is valid; early denials
  (`missing_authorization`) are honestly instance-less. Emission is
  fail-closed: a failed instance build denies `internal_error` and can never
  throw out of the gate or burn a nonce.
- `nowMs` gate option (epoch-ms clock; exactly one of `now`/`nowMs`). The
  sample is validated (finite, Date-representable, derived unix seconds ≥ 1);
  `now_unix` and nonce-reservation timestamps derive from the same sampled
  instant.
- `GateReceiptSigner.sign(input, instance?)` attaches the block before
  signing, so the ES256K signature covers it.

## @bolyra/cli 0.8.0 (tagged 2026-07-24 — never published to npm)

> The 0.8.0 release workflow failed at its test gate (sibling-source jest
> mappers unresolvable on the release runner) and the failure went
> unnoticed; the registry stayed at 0.7.0. The changes below first reached
> npm in 0.9.0.

### Fixed

- **The bundled `@bolyra/circuits` vkey fallback never worked.** `resolveVkeyPath`
  looked for `@bolyra/circuits/build/<vkey>`, but the package ships
  `artifacts/<Circuit>/<Circuit>_groth16_vkey.json` — a different directory, an
  extra level of nesting, and (for `HumanUniqueness`) a different filename than
  the flat `circuits/build` layout uses. Installing `@bolyra/cli` alongside
  `@bolyra/circuits` without setting `BOLYRA_CIRCUITS_DIR` therefore produced
  `internal_error` instead of the documented fallback. The fallback now resolves
  the package root and applies that package's own layout.

### Changed

- **`--circuits-dir` is now authoritative.** When the operator names a circuits
  directory and the verification key is not there, `bolyra verify` fails with
  `internal_error` instead of falling back to `BOLYRA_CIRCUITS_DIR` or the
  bundled package. Silently verifying against a key the operator did not choose
  is a trust surprise in a verifier. `BOLYRA_CIRCUITS_DIR` is ambient config and
  still falls through to the bundled package.

### Added

- CI now typechecks and runs the full CLI suite (299 tests, including real
  Groth16 proof generation) on every push. Artifacts come from the published
  `@bolyra/circuits` via `scripts/circuits-build-from-package.js`, so no Circom
  toolchain is needed. Previously the CLI was the only published package with no
  CI test job.

## @bolyra/mpp 0.3.1 (2026-07-18)

- Fix: gate decision receipts now emit a bare 64-hex commerce.intentHash
  (no 0x prefix), matching the @bolyra/receipts verify-CLI validator and the
  golden corpus. Previously mpp-emitted receipts failed `receipt verify` with
  "commerce.intentHash must be a 64-char hex string" even though they verified
  programmatically. Found via the stripe-ai-mandate demo build.

## @bolyra/mpp 0.3.0 (2026-07-17)

### Added

- **One-command runnable demo: `npx @bolyra/mpp demo`.** New `bolyra-mpp` bin
  (the package's single bin, so `npx @bolyra/mpp` resolves it) runs the full
  mandate flow in-process with zero setup — no network, no wallet, no mppx
  install: the operator issues a small-tier spend mandate via the package's
  own `issueMandate`, an agent presents it to a route gated by `bolyraGate`,
  a $25 spend allows, a $500 spend denies with the RFC 9457 problem body
  before any payment logic runs, a mandate-less request denies fail-closed,
  and the ES256K hash-chained authorization receipt is printed and
  signature-verified. The verification path is the real shipped code
  (`issueMandate` → classical verify → `@bolyra/receipts`); only the route is
  a clearly labeled stub standing in for an mppx method (`bolyraGate` wraps
  `Method.Server` structurally, so the demo needs no mppx import). Narrated
  stdout explains each step and the one-line why; a jest smoke test runs the
  demo programmatically and asserts all six outcomes. README Quickstart now
  leads with the demo command; `examples/mandate-demo` remains the
  real-mppx deeper path. Minor bump: new bin, no API changes.

## @bolyra/mpp 0.2.1 (2026-07-17)

- Test suite now pinned against mppx 0.8.12 (the release carrying our upstream
  session/channel fix, wevm/mppx#632); README states the tested version.
- No code changes from 0.2.0. First release published via npm Trusted
  Publisher (OIDC) for this package.

## [Unreleased]

### Security

#### Classical binding v2 — `expiry` is now signature-bound (EVC binding v1 → v2)

- **Closed a re-anchored-expiry gap in classical verification.** In classical
  mode (the in-process `@bolyra/mpp` gate, `bolyra verify`'s classical trust
  core, and the hosted-verify preview) the operator's EdDSA binding signature
  covered `{agent_name, project_key, program, model, capabilities}` but **not**
  `expiry`. Because the scope-commitment public signal is recomputable from the
  revealed credential preimage, a presenter holding an expired mandate could
  re-anchor a later `expiry` and still obtain `allow`, extending duration at the
  granted tier (bounded: no tier/audience/payee escalation). A `zk`-class
  verifier was never affected — `AgentPolicy.circom` binds `expiry` into the
  in-circuit EdDSA-signed `credentialCommitment` and enforces expiry in-circuit.
- **Binding v2.** The operator-signed binding now has **six** fields — the prior
  five plus `expiry` — under a versioned domain-separation tag
  `bolyra.external-verifier.binding.v2`. After the signature verifies, all three
  classical verifiers require `binding.expiry == credential.expiry`. The
  obsolete five-field **v1** binding is rejected `unsupported_version`
  (fail-closed, no advisory-expiry mode or compatibility flag); a
  non-integer/non-positive `expiry` or any extra binding field is
  `invalid_bundle`. Byte-compatible across the three implementations (pinned
  cross-implementation digest conformance vector). Spec: EVC
  `external-verifier-contract-v1.md` §4 + §15 changelog. `issueMandate` /
  `bolyra mandate issue` emit v2 only. Committed `bolyra verify` goldens
  re-signed to v2 (proofs byte-identical — the binding is outside the proof).

### Added

#### MPP authorization gate (`integrations/mpp-payments` — new, `@bolyra/mpp` 0.1.0, not yet published)

- **Verify an agent's delegated spend mandate before accepting an MPP payment
  credential.** A small authorization middleware for the Machine Payments
  Protocol ecosystem ([mppx](https://github.com/wevm/mppx) servers):
  `bolyraGate(method, options)` wraps an mppx `Method.Server` (the same
  integration shape as other mppx extensions) and composes into the method's
  `preflight` hook, so the mandate check runs **before** the challenge /
  payment path — denials are RFC 9457 Problem Details with stable EVC §9
  codes, fail-closed on every error path, and no payment logic ever runs.
  Implements the `docs/mpp-authorization-companion.md` mapping.
- **Amount → tier mapping.** Route amounts resolve to USD (exact-decimal
  comparison, never float; `amountToUsd` hook for token base units) and map
  to the cumulative `FINANCIAL_SMALL` (< $100) / `FINANCIAL_MEDIUM`
  (< $10,000) / `FINANCIAL_UNLIMITED` Permission tiers via the
  `mpp:financial:*` capability vocabulary (`MPP_CAPABILITY_MAP`, round-trips
  through `bolyra verify --capability-map`).
- **Three verifier backends, classical default.** In-process classical
  verification (the hosted-verify pipeline: trusted-operator gate, EdDSA-
  Poseidon binding signature, byte-literal audience binding, capability
  subset, scope anchoring, strict expiry — **no ZK dependency**); or delegate
  the decision to an External Verifier Contract v1 command spawn or a hosted
  verifier URL, with the full host obligations (timeout → SIGKILL, output
  caps, strict single-object closed-schema verdict parsing, non-zero-exit
  fail-closed, reserve-before-act `consume_nonces`).
- **Authorization receipts.** Every decision (allow AND deny) signs an
  ES256K, hash-chained `bolyra.commerce` receipt via `@bolyra/receipts`
  (gateway 0.5.0 receipt-signer pattern; ephemeral key by default, pinnable);
  on allow the mppx receipt gains a `bolyraAuthorization` extension field
  that rides into MPP's `Payment-Receipt` header — the approved → paid audit
  pair.
- **Operator-side mandate issuance (`issueMandate`).** The minting counterpart
  to `verifyClassical`: given an operator key the caller already holds, resolve
  a financial tier (from `tier` or a `maxUsd` amount, cumulative capability
  tokens) and emit the signed `bvp/1` presentation the gate consumes. This
  closes the "how do I mint the header value?" gap — the demo and test fixtures
  no longer hand-assemble bundles inline; `issueMandate` (and its internal
  `mintPresentation` assembler) is the single issuance code path. Issuance
  only: no key generation/storage/rotation, no custody, no settlement,
  classical EdDSA-binding (no ZK proof), matching the default verifier.
  Fail-closed on bad input (`MandateIssueError`).
- **Tests + example.** 79 jest tests (was 62; +17 for issuance: tier
  round-trips through classical verify, over-tier / expired / wrong-audience /
  tampered / untrusted-operator denials, `maxUsd`→tier mapping, Buffer key
  shape, fail-closed input validation) and a self-contained runnable demo
  (`examples/mandate-demo`) that now issues its mandate with the real
  `bolyra mandate issue` CLI, then drives the real `mppx` request lifecycle:
  $25 allowed within a small-tier mandate, $500 denied `request_mismatch`
  before payment, missing mandate denied 401.

#### CLI — `bolyra mandate issue` (`@bolyra/cli` — not yet published, founder-gated)

- **New `bolyra mandate issue` subcommand.** Issues a delegated spend mandate
  for an agent and prints the `bvp/1` presentation `@bolyra/mpp` consumes.
  Inputs: `--operator-key` (the key file from `bolyra key generate`, same
  `parseKeyFile` shape as `cred create` — issuance reuses the existing operator
  key mechanism, no new key handling), `--agent`, `--audience`, `--model`,
  `--tier` **or** `--max-usd` (amount → smallest covering tier), `--expiry`
  (future-only duration/timestamp via the shared `parseExpiry`), optional
  `--program`, `--nonce` (opaque audit id, not a replay nonce), `--encoding`,
  `--out`. Presentation goes to stdout (pipe-clean); a summary + the operator
  public key to trust goes to stderr. Fail-closed: missing/invalid inputs
  refuse to emit and exit non-zero. Thin wrapper over `@bolyra/mpp`'s
  `issueMandate` — one issuance code path shared with the demo and fixtures.
  12 new jest tests (277 → 289); round-trips through the same `verifyClassical`
  the gate runs.
- **Release note (founder-gated).** This wires a new `@bolyra/cli` →
  `@bolyra/mpp` dependency (currently `file:../mpp-payments` for local dev).
  Publishing the CLI requires **(1)** publishing `@bolyra/mpp` at a new minor
  (it must carry `issueMandate`; the source is `0.1.0`, not yet published) and
  **(2)** switching the CLI dependency from `file:` to that published semver.
  No versions were bumped or published here.

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

#### Receipt scoring test kit (`examples/receipt-scoring-kit` — new, not published)

- **A committed, deterministic corpus of signed, hash-chained receipts for
  third-party consumers** (counterparty scoring systems, auditors, indexers)
  to test verification against with zero contact with the issuer: an
  8-receipt chained log (allows, denies with reason codes, a depth-2
  delegated action, x402-style commerce allow + tier-exceeded deny), a
  3-receipt log from an independent second operator, an intentionally
  tampered variant that fails with `receipt-hash-mismatch` +
  `prev-hash-mismatch`, standalone allow/deny receipts, public signer
  anchors, and a manifest with pinned counts + head hashes. Verification is
  5 documented commands against the *published* packages
  (`@bolyra/cli@0.5.0` `receipt verify-chain`, `@bolyra/receipts@0.8.0`
  `bolyra-receipt-verify`). Fixed test keys (published on purpose) + fixed
  timestamps + RFC 6979 signatures make regeneration byte-reproducible;
  8 invariant tests pin golden signer/count/head values against drift. The
  README maps every receipt field to a scoring input and states the two
  standing caveats plainly (operator-pinned signer keys; tail truncation
  requires externally pinned count/head).

#### Receipt scoring consumer (`examples/receipt-scoring-consumer` — new, not published)

- **Reference receipts CONSUMER** — the demand-side twin of the scoring kit:
  what an indexer/counterparty-risk engine does with receipt logs. Verify
  FIRST and fail closed (signer set via a Receipt Signer Discovery v1
  document, `verifyReceiptChain`, externally pinned count/head — an
  unverifiable log contributes nothing), then extract per-actor features:
  deny rate + reason-code histogram, max financial tier from the cumulative
  mask, max delegation depth, commerce volume by currency + denied payment
  attempts, first/last seen. Built entirely on the PUBLISHED
  `@bolyra/receipts@0.9.0`. 5 tests against the kit's golden corpus,
  including the fail-closed paths (tampered log, foreign signer, wrong
  pinned head). States the delivery caveat plainly: receipts prove
  authorization and approved→paid, not fulfillment.

#### Receipt Signer Discovery v1 (spec + `@bolyra/receipts` 0.9.0 + `@bolyra/cli` 0.6.0 + `@bolyra/gateway` 0.6.0 — all published 2026-07-13)

- **Fetchable signer trust anchors** (`spec/receipt-signer-discovery-v1.md`):
  a minimal `/.well-known/bolyra-signers.json` document (version, issuer,
  updatedAt, signers[{keyId, alg: ES256K, signer, label?}]) that replaces
  manual signer-key exchange for third-party receipt verification.
  Explicitly NOT a PKI: discovery moves the trust decision from "trust this
  key" to "trust this origin" — the spec says so in plain language, and when
  `--signer` and `--signer-from` are both supplied they must agree.
- **`@bolyra/receipts` 0.9.0**: canonical `parseSignerDiscovery` /
  `acceptedSigners` / `SignerDiscoveryError` exports — strict validation
  (closed `alg` set, address regex, duplicate-keyId conflict rejection,
  unknown fields ignored for forward compat). 24 new tests.
- **`@bolyra/cli` 0.6.0**: `--signer-from <url>` on `receipt verify` and
  `receipt verify-chain`. Fail-closed on every path: bad URL, plain http to
  non-loopback hosts, non-200, malformed document, signer not listed. 10 new
  tests against a live local HTTP fixture.
- **`@bolyra/gateway` 0.6.0**: serves the document for its active receipt
  signer (404 when receipts are disabled; ephemeral keys are labeled as
  rotating). The hosted-verify preview serves the same route for its pinned
  signer.
- **Scoring kit**: the corpus now ships `corpus/bolyra-signers.json` for
  operator A (operator B deliberately stays manual-pin-only, so the corpus
  demonstrates both trust modes).
- **RELEASE ORDERING (steps 1-2 executed 2026-07-13):** `@bolyra/receipts`
  0.9.0 published first (OIDC, attestation verified), then the cli's
  `@bolyra/receipts` range raised `~0.8.0` → `~0.9.0` with the lockfile
  resolving the registry release (`--signer-from` calls
  `parseSignerDiscovery` at runtime, so a cli built against 0.8.x would
  crash on the new flag). cli 0.6.0 and gateway 0.6.0 published same day (attested).

### Changed

#### CLI (`@bolyra/cli` 0.5.1 — published 2026-07-13)

- **`bolyra receipt verify` now works on real receipts** (found by the
  scoring-kit build): the command read `receipt.signer` at the top level and
  `payload.timestamp`, but the `SignedReceipt` schema carries
  `signature.signer` and `payload.issuedAt` (Unix seconds) — so `--signer`
  always failed on real receipts ("Got: unknown") and `--max-age` silently
  never applied. Both now read the schema fields (signer compare is
  case-insensitive); 4 regression tests generate real signed receipts and
  cover signer pass/fail and stale/fresh age handling. `verify-chain` and
  the receipts-package verifier were never affected.

#### Gateway (`@bolyra/gateway` 0.5.1 — published 2026-07-13)

- **`@bolyra/sdk` floor raised from `>=0.5.0` to `^0.6.1`** (dependencies and
  peerDependencies). The old floor admitted pre-0.6.1 SDKs that eagerly
  import snarkjs at module load, which is why the credential-binding module
  kept a local copy of the cumulative-bit mask validator instead of importing
  the SDK's. With the floor at 0.6.1 (lazy snarkjs), that local mirror is
  deleted: `cumulativeMaskError` now delegates to the SDK's canonical
  `validateCumulativeBitEncoding`, so gateway mask semantics can never drift
  from the SDK/circuits. A new out-of-process test
  (`test/sdk-canonical-validator.test.ts`) proves the emitted package runs
  classical credential binding with snarkjs resolution blocked — the Core
  guarantee now holds for the gateway's installed dependency tree, not just
  for jest's source mapping.
- **`underscore` override pinned to 1.13.8** (same pattern as sdk/cli/mcp
  manifests) — the sdk 0.6.1 install surfaced the known
  snarkjs→bfj→jsonpath→underscore advisory chain in the gateway lockfile;
  `npm audit --omit=dev --audit-level=high` gate is green again (the
  remaining elliptic chain is the documented no-patch residual in
  SECURITY.md).
- **No nested pre-0.6.1 sdk on the verification path** (Codex review
  finding): every published `@bolyra/mcp` (≤0.6.4) declares
  `@bolyra/sdk ^0.5.0`, so npm nests a second, pre-lazy-ZK
  `@bolyra/sdk@0.5.3` under `@bolyra/mcp` — and `verifyBundle` resolves
  `@bolyra/sdk` relative to itself, putting the old SDK on the gateway's
  production verification path regardless of the top-level floor. Fixed
  twice over: `@bolyra/mcp` 0.6.5 raises its own dependency to `^0.6.1`
  (see below), and the gateway's `@bolyra/mcp` range is raised from
  `~0.6.0` to `~0.6.5` so consumers can never resolve an mcp that
  reintroduces the pre-0.6.1 sdk. A tree-scan test fails the gateway suite
  if any pre-0.6.1 `@bolyra/sdk` appears anywhere under `node_modules`.
  (During review a temporary nested override pinned mcp's sdk in this
  repo's tree; it was removed once the `~0.6.5` range made it redundant.)
- **RELEASE ORDERING (executed 2026-07-13):** `@bolyra/mcp` 0.6.5 published
  first (OIDC, attestation verified), then the gateway range bump + lockfile
  refresh in the gateway 0.5.1 release commit, then `@bolyra/gateway` 0.5.1
  published. Same lockstep pattern as the sdk 0.6.0 → cli 0.4.0 release
  (caret-trap lesson).

#### MCP (`@bolyra/mcp` 0.6.5 — published 2026-07-13)

- **`@bolyra/sdk` dependency raised from `^0.5.0` to `^0.6.1`** so consumers
  installing `@bolyra/mcp` resolve the lazy-snarkjs SDK instead of nesting a
  pre-0.6.1 copy (see the gateway entry above). The peer range stays
  `>=0.4.0` pending a deliberate compatibility decision at release time.

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
