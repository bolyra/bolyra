# Operator authorization trial — design

**Date:** 2026-09-13
**Status:** design, Codex-ruled (session 01a098bb), founder-accepted
**Location:** `examples/operator-trial/` (private example, not published)
**Budget:** 20 hours across two weeks of evenings. If it runs long, narrow the supported environments; do not extend the schedule.

## 1. Purpose

Give an operator who owns one consequential HTTP action a ten-minute path to put that action behind a Bolyra authorization rule, attempt it three ways, and see for each attempt the decision, whether the request reached their endpoint, and the signed receipt. The operator is an accept/reject owner, not an EVC implementer. They should never need to read the External Verifier Contract to finish.

This exists to produce the first externally owned usage. It is not a product, a hosted service, or a certification.

**Success metric (30 days after shipping):** at least one distinct external workflow owner voluntarily emails a valid result bundle to hello@bolyra.ai and confirms it exercised their own endpoint, including the expected allowed outcome. Dry-runs and vendor fixture experiments do not count. One qualifying submission is trial adoption, not production adoption or buyer pull. Zero within 30 days means the build missed its metric; it does not prove nobody ran it.

## 2. What the operator sees

```
git clone https://github.com/bolyra/bolyra
cd bolyra/examples/operator-trial
npm ci
npm run trial -- --dry-run          # built-in echo endpoint, no secrets
THEIR_TOKEN=... npm run trial -- --config ./trial.yaml
```

`trial.yaml` (the only file they write):

```yaml
action: refund                     # the name Bolyra gates; appears in receipts
method: POST
url: https://staging.example.com/v1/refunds
bodyFile: ./refund.json            # optional, literal body, sent as-is
headers:
  Authorization: "Bearer ${THEIR_TOKEN}"   # ${ENV} substitution only
requiredPermission: WRITE_DATA     # READ_DATA | WRITE_DATA | FINANCIAL_SMALL ...
```

The run narrates three attempts and ends with the bundle path and the ask:

```
Attempt 1  authorized credential (WRITE_DATA)  -> ALLOW   forwarded: yes  upstream 201  receipt a1b2…
Attempt 2  credential without WRITE_DATA       -> DENY    forwarded: no   receipt c3d4…
Attempt 3  replay of attempt 1's bundle        -> DENY    forwarded: no   receipt e5f6…

dispatches to your endpoint: 1 / 0 / 0
bundle: ./trial-out/2026-09-13T15-40-12Z/
verify offline: npx @bolyra/cli receipt verify-chain ./trial-out/.../receipts.jsonl \
  --signer 0x… --expect-count 3 --expect-head 0x…

If this ran against an endpoint you own, email the bundle directory to
hello@bolyra.ai. Nothing is sent automatically.
```

The entry page (`landing/operator-trial.html`) shows exactly this, states that the target must be staging or a reversible action, and states that the trial protects traffic routed through the local Bolyra host, not direct access to the endpoint.

## 3. Architecture

Four modules, each testable alone. All reuse published packages at pinned versions: `@bolyra/gateway 0.6.0`, `@bolyra/mcp 0.6.5`, `@bolyra/receipts 0.11.0`. No package in this repo is modified.

```
trial.ts  ──config──▶  host.ts  ──middleware──▶  @bolyra/gateway createGatewayMiddleware
   │                      │                          (bundle parse, nonce replay,
   │ three attempts       │ on allow only             dev credential binding,
   │ (fetch to host)      ▼                           tool policy)
   │                 dispatch()  ──HTTP──▶  operator endpoint  (or echo.ts in dry-run)
   │                      │
   └──────────────▶  audit.ts  (ReceiptChain, JSONL, signer.json, summary, verify cmd)
```

### 3.1 `host.ts` — the boundary

A loopback-only `node:http` server. It accepts `POST /action/<name>` where `<name>` must equal the configured action. Anything else returns 404 and is neither verified nor receipted (a route-bypass test covers this).

Per request:

1. Read the body (the trial client sends `{}`; the body is ignored, the operator's literal body file is what gets dispatched).
2. Decode the `Authorization: Bolyra <base64>` bundle for receipt input, as the verified-actions demo does.
3. Call `createGatewayMiddleware({ config })(req, res, actionName)`. The gateway config has `devMode: true`, a static `credentials` map, and `tools: { [actionName]: { requireBitmask } }`. The middleware performs bundle verification, nonce replay (in-memory store), dev credential binding, and tool policy, and it writes the 401/403 response itself. The host does not duplicate any of those checks.
4. If the middleware returned `false`: sign a deny receipt with the middleware's `req.bolyraDenial.reason`, plus the action descriptor, and return. Dispatch count stays 0.
5. If `true`: sign the allow receipt and persist it **before** dispatch. If the write or its immediate re-verification fails, respond 500 and abort the run. Then dispatch exactly once.
6. Dispatch: one `fetch` to the configured URL with the configured method, headers (after `${ENV}` substitution), and literal body. `redirect: 'manual'` and no retries. A 3xx is reported as `upstream 3xx (not followed)`. A timeout is reported as `dispatched, outcome unknown`. The response status is recorded; the response body and headers are discarded.
7. Respond to the trial client with `{ decision, forwarded, upstreamStatus?, receiptId }`.

The host keeps a per-attempt dispatch counter. The trial asserts `1 / 0 / 0` and fails the run otherwise.

### 3.2 `trial.ts` — the operator's three attempts

- Loads `trial.yaml` (or `--dry-run`, which synthesizes a config pointing at `echo.ts`). Rejects unknown keys. Resolves `${ENV}` references literally; a missing variable fails the run before any server starts.
- Mints two registered credentials with the demo's `createDemoAgent` pattern: `granted` holds `requiredPermission`; `withheld` holds the highest cumulative tier below it (or `READ_DATA` when the requirement is `READ_DATA`, in which case `withheld` gets bitmask 0 and the deny comes from policy on an empty grant). Both commitments go into the gateway config's static credential map, so attempt 2 is a credential-bound policy deny, not a self-asserted one.
- Starts `host.ts` on `127.0.0.1:0`.
- Attempt 1: fresh dev bundle for `granted`, expect ALLOW + forwarded.
- Attempt 2: fresh dev bundle for `withheld`, expect DENY (403 policy) + not forwarded.
- Attempt 3: resend attempt 1's exact `Authorization` header, expect DENY (401 nonce replay) + not forwarded.
- Any unexpected outcome sets `process.exitCode = 1` after the bundle is still written, so a failed run is inspectable.
- Prints the narration, the dispatch counters, the bundle path, the verify command, and the email ask. Labels the run as a controlled trial with simulated credentials and ZK verification disabled.

### 3.3 `audit.ts` — receipts and the bundle

Copied in shape from `examples/verified-actions-demo/src/audit.ts`, trimmed to what the trial needs:

- Ephemeral ES256K key per run; `signer.json` written with `{ issuer, keyId, alg, signer, ephemeral: true }`.
- `ReceiptChain` hash-chains the three receipts; each is `createAuthReceipt` + `chain.sign`.
- Action identity travels in the existing `decision.reasonCode` string: the middleware's reason (or `allowed`) followed by ` | action=<name> <METHOD> <host><path>`. Query string and body never appear. This is signed descriptive context, not request instance binding. No schema change.
- Output directory: `trial-out/<ISO timestamp>/`, fresh per run, never overwritten. Contents:
  - `receipts.jsonl` — three receipts, pre-verified with `verifyReceiptChain` before the summary is written; failure aborts.
  - `signer.json`
  - `summary.json` — `{ trialVersion, packages, action: { name, method, host, path }, attempts: [{ n, credential, decision, forwarded, upstreamStatus?, receiptId }], dispatchCounts, dryRun, startedAt, finishedAt, note: "unsigned observations; signer is ephemeral" }`.
  - `VERIFY.txt` — the exact `npx @bolyra/cli receipt verify-chain` command with `--signer`, `--expect-count 3`, `--expect-head`.
- Secret exclusion: the bundle writer runs a scan over every file it wrote for each resolved header value and each `${ENV}` value, and fails the run on a hit. It prints that this scan covers only values the trial itself resolved.

### 3.4 `echo.ts` — dry-run endpoint

A loopback `node:http` server that counts requests, returns 200 with `{ echoed: true }`, and exposes the count to the test. Dry-run is the CI path and the operator's first run. It proves the mechanics without secrets. Dry-run bundles are labeled `dryRun: true` and do not count toward the metric.

## 4. Configuration and secrets

- Config is YAML or JSON, parsed with the same `${ENV}` substitution rule the gateway uses: literal replacement of `${NAME}` from `process.env`, no shell evaluation, fail on unset.
- Resolved header values, body content, credentials, and raw upstream error bodies are never written to receipts, `summary.json`, logs, or the console. The console shows only the header *names* being sent.
- `bodyFile` is read once and sent byte-for-byte. No templating.
- Redirects are not followed. There are no retries. Timeout is 15 seconds.

## 5. Error handling

| Condition | Behavior |
|---|---|
| Missing `${ENV}` variable | Exit 2 before starting any server, naming the variable |
| Unknown config key | Exit 2, naming the key |
| Request to any route other than the configured action | 404, no verification, no receipt |
| Middleware deny | Deny receipt signed and persisted; no dispatch |
| Allow receipt write or re-verify fails | 500 to the client, run aborts with exit 1, no dispatch |
| Upstream timeout | Attempt recorded as `forwarded: true, upstreamStatus: null, outcome: "unknown"`; run continues; exit code unaffected |
| Upstream 3xx | Recorded as not followed; treated as a completed dispatch |
| Dispatch counters not `1/0/0` | Exit 1 after the bundle is written |
| Chain pre-verification fails | Exit 1, bundle directory kept for inspection, `summary.json` not written |
| Secret scan hit | Exit 1, bundle directory deleted, message names the file |

## 6. Testing

`node:test`, matching the other examples. `test/trial.test.ts` runs the full dry-run in-process against `echo.ts` and asserts:

1. Three attempts produce ALLOW, DENY (policy), DENY (replay) with HTTP 200, 403, 401 from the host.
2. Echo server observed exactly one request; host dispatch counters are `1/0/0`.
3. Three receipts verify individually and as a chain; head hash and count in `VERIFY.txt` match `receipts.jsonl`.
4. Route bypass: `POST /action/other` and `GET /action/<name>` return 404 and add no receipt.
5. Credential mismatch: a bundle claiming `granted`'s commitment with a higher bitmask than registered is denied 401 `credential_mismatch` and receipted.
6. Redirect handling: an echo variant returning 302 is recorded as not followed, dispatch count 1.
7. Secret exclusion: with a header value `Bearer sekrit-…`, no file in the bundle contains it; the console capture does not contain it.
8. Missing env var exits 2 before listening.

CI: a new job `operator-trial` copied from `verified-actions-demo` (Node 20, `npm ci --no-audit --no-fund`, `npm run trial -- --dry-run`, `npm test`). The package is added to the `dependency-audit` directory list. `scripts/verify-lockfiles.sh` picks up tracked lockfiles automatically; the new lockfile must `npm ci` cleanly on Linux (regenerate on Linux or in Docker if the `@emnapi/*` optional subtree goes missing, per `tasks/lessons.md`).

## 7. Files

```
examples/operator-trial/
  README.md              # the operator path, verbatim from §2, plus the honesty labels
  package.json           # private, scripts: trial, build, test; deps pinned to published versions
  package-lock.json
  tsconfig.json
  trial.example.yaml
  .gitignore             # trial-out/, dist/
  src/
    trial.ts
    host.ts
    audit.ts
    echo.ts
    agents.ts            # createDemoAgent / buildDevBundle, copied from verified-actions-demo
    config.ts            # yaml/json load, ${ENV} substitution, strict keys
  test/
    trial.test.ts
landing/operator-trial.html
.github/workflows/ci.yml   # operator-trial job + dependency-audit list entry
```

## 8. Explicitly out of scope

MCP targets. Bring-your-own-agent. Body templates. Arbitrary proxying or path passthrough. Hosted services, telemetry, or any phone-home. New npm packages or new `@bolyra/cli` dependencies. Receipt schema changes or instance binding for auth receipts. Persistent nonce storage. Production deployment claims. Publishing as a package is not promised; revisit only if installation blocks an operator.

## 9. Honesty labels (must appear in README, console output, and the entry page)

- Controlled trial: credentials are simulated and registered locally; ZK proof verification is disabled (dev mode). Production uses real proofs and a credential registry.
- The trial protects traffic routed through the local Bolyra host. It does not stop anyone from calling the endpoint directly.
- `summary.json` is unsigned observation. The signer key is ephemeral. Neither establishes independent provenance; the receipts and chain do, for the run they describe.
- Use a staging endpoint or a reversible action. Attempt 1 really executes.
