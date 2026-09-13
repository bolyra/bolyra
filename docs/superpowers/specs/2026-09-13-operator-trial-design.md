# Operator authorization trial — design

**Date:** 2026-09-13
**Status:** design, Codex-ruled (session 01a098bb), founder-accepted; revision 3 after two spec-review rounds
**Location:** `examples/operator-trial/` (private example, not published)
**Budget:** 20 hours across two weeks of evenings. If it runs long, narrow the supported environments; do not extend the schedule.
**Supported environment (initial):** macOS and Linux, Node 20 or newer. Windows is untested and not claimed.

## 1. Purpose

Give an operator who owns one consequential HTTP action a ten-minute path to put that action behind a Bolyra authorization rule, attempt it three ways, and see for each attempt the decision, whether a request was dispatched to their endpoint, and the signed receipt. The operator is an accept/reject owner, not an EVC implementer. They should never need to read the External Verifier Contract to finish.

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

`trial.yaml` (the only file they write; full contract in §4):

```yaml
action: refund                     # the name Bolyra gates; appears in receipts
method: POST
url: https://staging.example.com/v1/refunds
bodyFile: ./refund.json            # optional, literal body, sent as-is
headers:
  Authorization: "Bearer ${THEIR_TOKEN}"   # ${ENV} substitution only
requiredPermission: WRITE_DATA     # one name from the table in §3.2
```

The run narrates three attempts and ends with the bundle path and the ask:

```
Attempt 1  credential granted WRITE_DATA       -> ALLOW   dispatched: yes  upstream 201  receipt a1b2…
Attempt 2  credential granted READ_DATA only   -> DENY    dispatched: no   receipt c3d4…
Attempt 3  replay of attempt 1's bundle        -> DENY    dispatched: no   receipt e5f6…

dispatches to your endpoint: 1 / 0 / 0
bundle: ./trial-out/2026-09-13T15-40-12Z/
verify independently (needs @bolyra/cli 0.9.0 installed):
  npx @bolyra/cli@0.9.0 receipt verify-chain ./trial-out/.../receipts.jsonl \
    --signer 0x… --expect-count 3 --expect-head 0x…

If this ran against an endpoint you own, email the bundle directory to
hello@bolyra.ai. Nothing is sent automatically.
```

The entry page (`landing/operator-trial.html`) shows exactly this, states that the target must be staging or a reversible action, and states that the trial protects traffic routed through the local Bolyra host, not direct access to the endpoint.

## 3. Architecture

Four runtime modules plus config and credential helpers, each testable alone. All reuse published packages at pinned versions: `@bolyra/gateway 0.6.0`, `@bolyra/mcp 0.6.5`, `@bolyra/receipts 0.11.0`. No package in this repo is modified.

```
trial.ts  ──config──▶  host.ts  ──middleware (created once)──▶  @bolyra/gateway createGatewayMiddleware
   │                      │                                       (bundle parse, nonce replay,
   │ three attempts       │ on allow only                          dev credential binding,
   │ (fetch to host)      ▼                                        tool policy, writes 401/403)
   │                 dispatch()  ──HTTP──▶  operator endpoint  (or echo.ts in dry-run)
   │                      │
   │◀── in-process AttemptResult per request ──┘
   └──────────────▶  audit.ts  (ReceiptChain, JSONL, signer.json, summary, verify cmd)
```

### 3.1 `host.ts` — the boundary

A loopback-only `node:http` server bound to `127.0.0.1:0`. It accepts `POST /action/<name>` where `<name>` must equal the configured action. Anything else returns 404 and is neither verified nor receipted.

**Construction (once per host):**

```ts
const middleware = createGatewayMiddleware({ config: gatewayConfig });
```

`createGatewayMiddleware` builds its in-memory nonce store when called, so it is created exactly once at host startup and the returned function is reused per request. Creating it per request would give every attempt a fresh nonce store and attempt 3's replay would be allowed.

**`gatewayConfig`** is the complete `GatewayConfig` object the middleware needs. Nothing is loaded from a gateway YAML; the trial constructs it:

```ts
const gatewayConfig: GatewayConfig = {
  target: 'http://127.0.0.1:1/unused',   // required by the type; the host never proxies MCP
  port: 0,
  network: 'base-sepolia',
  devMode: true,
  credentials: { type: 'static', map: {
    [granted.commitment.toString()]:  { permissionBitmask: granted.permissionBitmask.toString() },
    [withheld.commitment.toString()]: { permissionBitmask: withheld.permissionBitmask.toString() },
  } },
  tools: { [actionName]: { requireBitmask: Number(requiredMask) } },
  nonce: { store: 'memory', maxProofAge: 300 },   // middleware dereferences nonce.maxProofAge
  receipts: { enabled: false, output: 'stdout' },  // the trial signs its own receipts (audit.ts)
  health: { enabled: false, path: '/healthz' },
};
```

Notes on this object: `DemoAgent` (copied from the demo's `agents.ts`) exposes `permissionBitmask`, not `mask`. `port: 0` and the placeholder `target` are acceptable because the middleware is embedded directly; they would not pass the gateway's `validateConfig`, which the trial does not call. `buildCredentialRegistry` parses the static map but does not validate cumulative closure; closure is guaranteed by the table in §3.2, which is the only source of masks.

**Per request:**

1. Route check. Method must be `POST` and path must be `/action/<configured name>`; otherwise 404, no verification, no receipt, no `AttemptResult`.
2. Read and discard the body. The middleware does not need `req.rawBody` or `req.jsonRpcBody`; it reads only `req.jsonRpcBody?.id` through optional chaining.
3. `const ok = await middleware(req, res, actionName)`. With `actionName` passed, the middleware itself performs bundle verification, nonce replay (401), dev credential binding against the static map (401 `credential_unknown` / `credential_mismatch`), and tool policy (403). On deny it has already written a JSON-RPC error response. The host duplicates none of these checks.
4. If `ok === false`: build the deny receipt input from `req.bolyraDenial` (`stage`, `reason`, `authCtx?`, `bundle?`). `stage` is one of `missing_auth | malformed_bundle | verification_failed | credential_binding_failed | policy_denied`. Input shape, copied from the demo host:
   - `stage` is `credential_binding_failed` or `policy_denied` (verification succeeded, so `authCtx.verified === true` and its DID is populated) → `decisionInput(bundle, authCtx, false, reason)`.
   - `stage` is `verification_failed` with a `bundle` (including attempt 3's replay; the middleware's `authCtx` here is a failure context whose `did` and `effectiveCommitment` are empty strings) → `authFailInput(bundle, reason)`, which derives the DID from `bundle.credentialCommitment`.
   - no `bundle` (`missing_auth`, `malformed_bundle`) → `anonymousDenyInput(reason)`.
   `reasonCode = req.bolyraDenial.reason + descriptor` (see §3.3). Sign and persist. Push an `AttemptResult` with `dispatched: false`. If persistence fails, record `receiptError` in the result and mark the run failed; the HTTP response was already sent by the middleware.
5. If `ok === true`: build the allow receipt input from `req.bolyra` and `req.bolyraBundle` with `reasonCode = 'allowed' + descriptor`. Sign and persist **before** dispatch, then immediately re-verify the persisted receipt with `verifyReceipt`. If either fails, respond 500, push an `AttemptResult` with `dispatched: false, receiptError`, and mark the run failed. No dispatch.
6. Dispatch exactly once: `fetch(url, { method, headers, body, redirect: 'manual', signal: AbortSignal.timeout(15_000) })`. Record `upstreamStatus` and discard the response body and headers. Outcome mapping:
   - 2xx/4xx/5xx → `outcome: 'completed'`
   - 3xx → `outcome: 'not_followed'` (redirect not followed)
   - abort → `outcome: 'timeout'`, `upstreamStatus: null`
   - any other fetch rejection → `outcome: 'network_error'`, `upstreamStatus: null`
   In every case the dispatch counter increments and `dispatched: true`. `dispatched` means the host invoked `fetch` for this attempt; it does not prove bytes left the machine, or that the endpoint received or executed anything.
7. Respond to the trial client with `{ decision: 'allow', dispatched: true, upstreamStatus, outcome, receiptId }` and push the same `AttemptResult`.

**In-process result channel.** The host exposes `results: AttemptResult[]` and `nextResult(): Promise<AttemptResult>` which resolves after the receipt for the current request has been persisted (or its persistence failure recorded). `trial.ts` awaits `nextResult()` after each attempt's `fetch` settles, so it never reads a deny's receipt id from the HTTP body (the middleware's JSON-RPC error body carries none).

```ts
interface AttemptResult {
  n: 1 | 2 | 3;
  credential: 'granted' | 'withheld' | 'replay';
  decision: 'allow' | 'deny';
  stage?: 'missing_auth' | 'malformed_bundle' | 'verification_failed' | 'credential_binding_failed' | 'policy_denied';
  reason: string;                // middleware reason or 'allowed'
  httpStatus: number;            // what the client saw from the host
  dispatched: boolean;           // the host invoked fetch for this attempt
  upstreamStatus: number | null;
  outcome: 'completed' | 'not_followed' | 'timeout' | 'network_error' | 'not_dispatched';
  receiptId: string | null;
  receiptError?: string;
}
```

The host keeps `dispatchCount` and a per-attempt count. The trial asserts `1 / 0 / 0`.

### 3.2 `trial.ts` and `agents.ts` — the operator's three attempts

**Permission table** (`agents.ts`). Bit positions follow `@bolyra/sdk`'s `Permission` enum; masks are cumulative-closed (they satisfy `validateCumulativeBitEncoding`, though the embedded middleware does not itself call `validateConfig`):

| Name | Bit | Closed mask | Withheld credential gets |
|---|---|---|---|
| `READ_DATA` | 0 | `1` | `0` |
| `WRITE_DATA` | 1 | `2` | `1` (READ_DATA) |
| `FINANCIAL_SMALL` | 2 | `4` | `2` (WRITE_DATA) |
| `FINANCIAL_MEDIUM` | 3 | `12` (8 implies 4) | `4` (FINANCIAL_SMALL) |
| `FINANCIAL_UNLIMITED` | 4 | `28` (16 implies 8, 4) | `12` (FINANCIAL_MEDIUM) |
| `SIGN_ON_BEHALF` | 5 | `32` | `28` (FINANCIAL_UNLIMITED) |
| `SUB_DELEGATE` | 6 | `64` | `32` (SIGN_ON_BEHALF) |
| `ACCESS_PII` | 7 | `128` | `64` (SUB_DELEGATE) |

`requiredPermission` must be one of these names. The policy's `requireBitmask` is the required name's closed mask. The withheld credential's mask is the closed mask of the previous row (`0` for `READ_DATA`). Soundness: `checkToolPolicy` denies unless `(mask & required) === required`, and a lower row's mask never contains the required row's own bit, so the withheld credential fails policy for every row. Dev-mode verification still passes for the withheld credential: a fresh bundle scores 40 + 20 + 10 (fresh nonce) + 10, plus 20 when either bit 0 or bit 1 is set. So masks containing READ or WRITE score 100; the zero mask and every financial-only or higher-bit-only mask score 80. All are above the default `minScore` of 70, so the deny is a 403 `policy_denied`, never a 401.

`agents.ts` is copied from `examples/verified-actions-demo/src/agents.ts` (`createDemoAgent`, `buildDevBundle`, fresh production-layout nonce per bundle) with the table above added.

**`runTrial(opts): Promise<TrialSummary>`** is the in-process entry point the CLI and the tests both call:

```ts
interface RunTrialOptions {
  config: TrialConfig;               // already loaded and validated (see config.ts)
  outDir: string;                    // parent of the per-run directory
  dryRun: boolean;
  echo?: { status: number };         // dry-run only; test 6 sets 302
  log?: (line: string) => void;      // narration sink; default console.log
}
```

Sequence:

1. Mint `granted` (required closed mask) and `withheld` (previous row) with `createDemoAgent`.
2. In dry-run, start `echo.ts` and point the action at it (`POST http://127.0.0.1:<port>/echo`, `requiredPermission: WRITE_DATA`, no headers, no body).
3. Start `host.ts` with the gateway config from §3.1 and an `audit.ts` instance for a fresh run directory.
4. Attempt 1: fresh dev bundle for `granted`. Expect host 200, `decision: 'allow'`, `dispatched: true`.
5. Attempt 2: fresh dev bundle for `withheld`. Expect host 403, `stage: 'policy_denied'`, `dispatched: false`.
6. Attempt 3: resend attempt 1's exact `Authorization` header. Expect host 401, `stage: 'verification_failed'`, reason containing `Nonce already used`, `dispatched: false`.
7. After each attempt, `await host.nextResult()`.
8. Close servers. Ask `audit.ts` to finalize the bundle (§3.3).
9. Compare results against expectations and the `1 / 0 / 0` counters. Any mismatch, any `receiptError`, or a finalize failure sets `summary.ok = false`.
10. Print narration, counters, bundle path, verify command, honesty labels (§9), and the email ask. Return the summary.

The CLI wrapper (`npm run trial`) maps outcomes to exit codes: config errors (`TrialConfigError`) exit 2 before any server starts; `summary.ok === false` exits 1; otherwise 0. Tests call `runTrial` directly and assert on the returned summary and thrown `TrialConfigError`, never on process exit.

### 3.3 `audit.ts` — receipts and the bundle

Copied in shape from `examples/verified-actions-demo/src/audit.ts`, trimmed to what the trial needs:

- Ephemeral ES256K key per run; `signer.json` written at construction with `{ issuer: 'operator-trial', keyId: 'trial-k1', alg: 'ES256K', signer, ephemeral: true }`.
- `ReceiptChain` hash-chains the receipts; each is `createAuthReceipt(input, { issuer, keyId })` then `chain.sign(payload, signerConfig)`, appended to `receipts.jsonl` synchronously.
- **Write-failure rule.** `ReceiptChain.sign` advances `seq` and `prevReceiptHash` before the append happens, so a receipt that was signed but not written leaves a gap that every later receipt would chain past. On the first append failure `audit.ts` marks itself `broken` and refuses to sign further receipts; each later attempt gets `receiptError: 'chain broken by earlier write failure'` and no receipt. The file therefore always holds an intact prefix, and that prefix is what `finalize` verifies and what `VERIFY.txt` describes. The partial-run promise is limited to this intact prefix.
- **Action descriptor.** Every `reasonCode` is `<middleware reason or 'allowed'> | action=<name> <METHOD> <host><path>`. Query string, headers, and body never appear. This is signed descriptive context, not request instance binding. No receipt schema change.
- Run directory `trial-out/<ISO timestamp, colons replaced>/`, created fresh; the run refuses to start if it already exists.
- `finalize(results, meta)`:
  0. Secret scan first, on whatever has been written so far (see step 4). It runs on every path that retains artifacts, including a chain-verification failure in step 1, so a kept directory is never an unscanned directory.
  1. Read back `receipts.jsonl`, run `verifyReceiptChain(receipts, { expectedSigner, expectedCount: receipts.length })`. On failure, write nothing else, keep the directory, and return a failure.
  2. Write `summary.json`:
     ```
     { trialVersion, packages: { gateway, mcp, receipts }, dryRun, ok,
       action: { name, method, host, path },
       attempts: AttemptResult[], dispatchCounts: [n1, n2, n3],
       receiptCount, headReceiptHash /* verifyReceiptChain(...).headHash */, startedAt, finishedAt,
       note: "unsigned observations; signer key is ephemeral" }
     ```
     `path` is operator-visible content and is written as-is.
  3. Write `VERIFY.txt` with `npx @bolyra/cli@0.9.0 receipt verify-chain ./receipts.jsonl --signer <signer> --expect-count <receiptCount> --expect-head <headReceiptHash>`. The count is the actual number of receipts, so a partial run still produces a verifiable bundle and `summary.ok` records that it was partial.
  4. Secret scan (also run as step 0 and again after `summary.json` and `VERIFY.txt` are written): for every resolved header value and every `${ENV}` value the trial substituted, search every file in the run directory. On a hit, delete the directory and return a failure naming the file. The console states that this scan covers only values the trial itself resolved.

### 3.4 `echo.ts` — dry-run endpoint

A loopback `node:http` server with `{ status?: number }` options (default 200). It counts requests, responds with the configured status and `{ echoed: true }`, and exposes `requestCount` to the test. Dry-run is the CI path and the operator's first run. Dry-run bundles are labeled `dryRun: true` and do not count toward the metric.

### 3.5 `config.ts` — the trial config contract

Loads YAML or JSON (`yaml` package, already a gateway dependency). Every violation throws `TrialConfigError` with the key name. Contract:

| Key | Type | Rule |
|---|---|---|
| `action` | string | required; matches `^[a-z][a-z0-9_-]{0,63}$` |
| `method` | string | required; one of `GET HEAD POST PUT PATCH DELETE` |
| `url` | string | required; parses as a URL with scheme `http` or `https`; no credentials in the URL |
| `headers` | map of string → string | optional; header names must be valid tokens; values are substituted |
| `bodyFile` | string | optional; resolved relative to the config file's directory; read once as bytes; rejected when `method` is `GET`, `HEAD`, or `DELETE` |
| `requiredPermission` | string | required; a name from the §3.2 table |
| any other key | — | rejected |

`${NAME}` substitution applies to `headers` values only. It is literal replacement from `process.env`, no shell evaluation. An unset variable throws `TrialConfigError` before any server starts. This is stricter than the gateway's own `substituteEnvVars`, which leaves unset references in place; the trial implements its own substitution.

## 4. Secrets

- Resolved header values, body content, credentials, and upstream response bodies are never written to receipts, `summary.json`, `VERIFY.txt`, logs, or the console. The console shows header names only.
- `bodyFile` is sent byte-for-byte. No templating.
- Redirects are not followed. There are no retries. Timeout is 15 seconds.
- The secret scan in §3.3 is a backstop for the trial's own resolved values, not a general redaction guarantee.

## 5. Error handling

| Condition | Behavior |
|---|---|
| Config violation, including unset `${ENV}` | `TrialConfigError`; CLI exits 2 before any server starts |
| Run directory already exists | `TrialConfigError` |
| Request to any route other than `POST /action/<name>` | 404; no verification, no receipt, no result |
| Middleware deny | Deny receipt persisted; `dispatched: false`; result pushed |
| Deny receipt persistence fails | Result carries `receiptError`; `summary.ok = false`; the chain is marked broken and no further receipts are signed; run continues so remaining attempts are still observable |
| Allow receipt persistence or re-verify fails | 500 to the client; no dispatch; `receiptError`; `summary.ok = false` |
| Dispatch 3xx | `outcome: 'not_followed'`; counts as dispatched |
| Dispatch timeout or network error | `outcome: 'timeout'` or `'network_error'`, `upstreamStatus: null`; counts as dispatched; `summary.ok` unaffected by the upstream outcome alone |
| Dispatch counters not `1/0/0` | `summary.ok = false` |
| Chain pre-verification fails | `summary.ok = false`; directory kept; `summary.json` and `VERIFY.txt` not written |
| Secret scan hit | Directory deleted; `summary.ok = false`; message names the file |

## 6. Testing

`node:test`, matching the other examples (`tsc && node --test dist/test/*.test.js`). Tests call `runTrial` in-process with a temp `outDir` and a capturing `log`.

1. Dry-run produces attempts with host status 200, 403, 401; decisions allow, deny (`policy_denied`), deny (`verification_failed` with `Nonce already used`); `summary.ok === true`.
2. Echo `requestCount === 1`; `dispatchCounts` deep-equals `[1, 0, 0]`.
3. Receipts in `receipts.jsonl` verify individually with `verifyReceipt(r, signer)` and as a chain; `VERIFY.txt` names the same count and head hash as the file.
4. Route bypass: while the host is up, `POST /action/other` and `GET /action/<name>` return 404 and the receipt count does not change.
5. Credential mismatch: with `requiredPermission: WRITE_DATA` pinned, a **fresh** bundle built as `buildDevBundle({ ...granted, permissionBitmask: granted.permissionBitmask | 128n })` (mask `130`, new nonce) scores 100, reaches credential binding, returns 401 with reason starting `credential_mismatch`, is receipted, and is not dispatched. The test pins WRITE_DATA because for `ACCESS_PII` the forged mask would equal the registered one.
6. Redirect: `echo: { status: 302 }` gives attempt 1 `outcome: 'not_followed'`, `dispatched: true`, `dispatchCounts[0] === 1`.
7. Permission matrix: for every row in §3.2, `granted` passes policy and `withheld` fails with `policy_denied` (host-level test, no dispatch needed).
8. Secret exclusion: with `headers: { Authorization: 'Bearer ${T}' }` and `T=sekrit-…`, no file in the run directory and no captured log line contains the value.
9. Missing env var: `loadTrialConfig` throws `TrialConfigError` naming `T`, and no server was started.
10. Allow-receipt write failure: the audit's append is made to throw on attempt 1 (an injectable `appendLine` in `audit.ts`, defaulting to `fs.appendFileSync`). Expect host 500, `dispatched: false`, `receiptError` on attempt 1, `receiptError` on attempts 2 and 3 naming the broken chain, zero receipts in the file, `summary.ok === false`, and `VERIFY.txt` not written.
11. Deny-receipt write failure: the append throws on attempt 2 only. Expect attempt 1 allowed and receipted, attempt 2 denied with `receiptError`, attempt 3 denied with `receiptError` naming the broken chain, exactly one receipt in the file, chain verification of that prefix passing, `summary.ok === false`.

CI: a new job `operator-trial` copied from `verified-actions-demo` (Node 20, `npm ci --no-audit --no-fund`, `npm run trial -- --dry-run`, `npm test`). `scripts/verify-lockfiles.sh` picks up the tracked lockfile automatically; it must `npm ci` cleanly on Linux (regenerate on Linux or in Docker if the `@emnapi/*` optional subtree goes missing, per `tasks/lessons.md`). The `dependency-audit` job lists published packages plus hosted-verify and does not include `verified-actions-demo`; this example follows the same convention and is not added.

## 7. Files

```
examples/operator-trial/
  README.md              # the operator path from §2, the config contract, the honesty labels
  package.json           # private; scripts: trial, build, test; deps pinned to published versions
  package-lock.json
  tsconfig.json
  trial.example.yaml
  .gitignore             # trial-out/, dist/
  src/
    cli.ts               # arg parsing, exit-code mapping, calls runTrial
    trial.ts             # runTrial
    host.ts
    audit.ts
    echo.ts
    agents.ts            # createDemoAgent / buildDevBundle + permission table
    config.ts            # loadTrialConfig, TrialConfigError
  test/
    trial.test.ts
landing/operator-trial.html
.github/workflows/ci.yml   # operator-trial job
```

## 8. Explicitly out of scope

MCP targets. Bring-your-own-agent. Body templates. Arbitrary proxying or path passthrough. Hosted services, telemetry, or any phone-home. New npm packages or new `@bolyra/cli` dependencies. Receipt schema changes or instance binding for auth receipts. Persistent nonce storage. Production deployment claims. Windows support. Publishing as a package is not promised; revisit only if installation blocks an operator.

## 9. Honesty labels (must appear in README, console output, and the entry page)

- Controlled trial: credentials are simulated and registered locally; ZK proof verification is disabled (dev mode). Production uses real proofs and a credential registry.
- The trial protects traffic routed through the local Bolyra host. It does not stop anyone from calling the endpoint directly.
- Receipts verify signed claims and chain integrity against the supplied signer, which is ephemeral to this run. Endpoint execution remains an unsigned observation in `summary.json`.
- Use a staging endpoint or a reversible action. Attempt 1 really executes.

## Appendix A — mapping to the Codex ruling (session 01a098bb, 2026-09-13)

| Fork | Ruling | Where in this spec |
|---|---|---|
| F1 target | (a) plain HTTP, one fixed action, loopback adapter, no MCP exemptions | §3.1, §3.5, §8 |
| F2 agent | trial-as-agent, two registered credentials, replay of the exact bundle, labeled controlled trial | §3.2, §9 |
| F3 distribution | (a) private example, published deps, committed lockfile, no publish promise | §2, §7, §8 |
| F4 secrets | env-only literal substitution, fail on unset, no redirects/retries, scoped scan | §3.5, §4 |
| F5 bundle | local, pre-verified JSONL, public signer, unsigned summary, verify command; email only | §3.3, §1 |
| F6 receipts | existing reason string + descriptor; not instance binding | §3.3 |
| F7 non-forwarding | dispatch counters `1/0/0`, echo observes one request, timeout still counts as dispatched | §3.1, §3.4, §6 |
| Scope cuts | as listed | §8 |
| Extra rulings | allow receipt persisted before dispatch; fail on receipt-write or verification failure; fresh output dir per run; tests for bypass, mismatch, replay, redirect, secret exclusion | §3.1, §3.3, §6 |
