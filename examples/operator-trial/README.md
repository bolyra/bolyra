# Bolyra operator trial

Put one HTTP action you own behind a Bolyra authorization rule. Attempt it three ways. See, for each attempt, the decision, whether a request was dispatched to your endpoint, and the signed receipt. About ten minutes once you have endpoint credentials.

**Use a staging endpoint or a reversible action. Attempt 1 really executes.**

## Run it

```bash
git clone https://github.com/bolyra/bolyra
cd bolyra/examples/operator-trial
npm ci
npm run trial -- --dry-run            # built-in echo endpoint, no secrets, see the mechanics
cp trial.example.yaml trial.yaml      # edit: your endpoint, method, header, permission
THEIR_TOKEN=... npm run trial -- --config ./trial.yaml
```

Requires Node 20 or newer on macOS or Linux. Windows is untested.

## What happens

1. The trial mints two simulated credentials and registers them with a local Bolyra host: one granted the permission your action requires, one granted only the next lower tier (or nothing, for `READ_DATA`).
2. **Attempt 1** presents the granted credential. The host verifies it, signs an allow receipt, then dispatches your configured request once. You see the upstream status.
3. **Attempt 2** presents the withheld credential. Policy denies it (403). Nothing is dispatched. A deny receipt is signed.
4. **Attempt 3** replays attempt 1's exact proof bundle. Nonce replay protection denies it (401). Nothing is dispatched. A deny receipt is signed.
5. The run ends with `dispatches to your endpoint: 1 / 0 / 0`, a bundle directory, and the command to verify the receipt chain independently.

## The config (`trial.yaml`)

| Key | Required | Rule |
|---|---|---|
| `action` | yes | `^[a-z][a-z0-9_-]{0,63}$`; the name Bolyra gates, recorded in every receipt |
| `method` | yes | `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, or `DELETE` |
| `url` | yes | `http` or `https`; no credentials in the URL. The host and path are recorded in every receipt and in `summary.json` (the query string is not), so do not use an endpoint whose path embeds a secret, such as a webhook URL; put secrets in headers via `${ENV}` |
| `headers` | no | map of header name to value; `${NAME}` is replaced from the environment, unset is an error |
| `bodyFile` | no | path relative to the config file, sent byte for byte; not allowed with `GET`, `HEAD`, `DELETE` |
| `requiredPermission` | yes | `READ_DATA`, `WRITE_DATA`, `FINANCIAL_SMALL`, `FINANCIAL_MEDIUM`, `FINANCIAL_UNLIMITED`, `SIGN_ON_BEHALF`, `SUB_DELEGATE`, `ACCESS_PII` |

Unknown keys are rejected. Redirects are not followed. There are no retries. The upstream timeout is 15 seconds.

`--dry-run --config ./trial.yaml` keeps your headers and permission but replaces the URL with the built-in echo endpoint, so your resolved `${ENV}` values are still sent, to loopback only. `--out-dir <dir>` changes where bundles go (default `./trial-out`).

## The bundle

`trial-out/<timestamp>/` (the timestamp includes milliseconds, e.g. `2026-09-13T15-40-12-345Z`):

- `receipts.jsonl`: three ES256K-signed, hash-chained receipts (allow and both denies).
- `signer.json`: the ephemeral signer for this run.
- `summary.json`: unsigned observations: the action (method, host, path), each attempt's decision, dispatch flag, upstream status, and receipt id.
- `VERIFY.txt`: the exact command to verify the chain with `@bolyra/cli`.

Verify independently (the first `npx` run downloads the CLI):

```bash
cd trial-out/<timestamp>
npx @bolyra/cli@0.9.0 receipt verify-chain ./receipts.jsonl --signer <signer> --expect-count 3 --expect-head <hash>
```

Run the verify command from inside the bundle directory (`VERIFY.txt` is written with that working directory in mind).

Header values, body content, credentials, and upstream response bodies are never written to the bundle or the console. The trial scans the bundle for every value it substituted from the environment and every header value that contained one, and deletes the directory on a hit. That scan covers only values the trial itself resolved; nothing else is redacted.

Receipts are signed by the `@bolyra/receipts` bundled inside `@bolyra/gateway 0.6.0` (receipts 0.8.0) and verified with `@bolyra/receipts` 0.11.0 here and by `@bolyra/cli` 0.9.0, which bundles receipts 0.11.0; the formats interoperate. `summary.json` records the verifier versions. The bundle's `summary.json` and every receipt name the action's host and path; see the `url` row above.

**If this ran against an endpoint you own, email the bundle directory to hello@bolyra.ai.** Nothing is sent automatically. `dispatched: true` means this host invoked the request; delivery and execution at your endpoint are not proven by the receipts.

## Produce a reviewer report

Hand a bundle to someone who has to decide what it proves. The report lists, for each claim a reviewer might make, whether this bundle supports it, by which file and field, and with which kind of evidence:

```bash
npm run report -- --bundle trial-out/<timestamp> --signer <signer> --expect-count 3 --expect-head <hash>
```

It writes `report-out/<timestamp>/report.html` (self-contained, printable) and `report.json` (the same findings). The anchors come from the flags only: `signer.json` and `summary.json` are compared against them, never used as anchors. Copying the values out of the bundle makes the report consistent with the bundle; it does not establish signer identity or completeness, and the report says so.

Five statuses: **SIGNED** (inside a receipt payload whose signature recovered to the anchored signer), **OBSERVED** (recorded by the host, signed by nothing), **DERIVED** (computed by a named check), **ABSENT** (no evidence in the bundle), **FAILED** (a check failed or two sources contradict). Execution, consent, payee control, spend limits, subject authentication and production credentials are always ABSENT: the trial never produces evidence for them. One check is report-local: the receipt `id` is neither signed nor hashed by the published verifier, so the report checks it itself (B1a) and says the CLI does not.

## What this is, and is not

- A controlled trial. Credentials are simulated and registered locally; ZK proof verification is disabled (dev mode). Production Bolyra uses real proofs and a credential registry.
- It protects traffic routed through the local Bolyra host. It does not stop anyone from calling your endpoint directly.
- Receipts verify signed claims and chain integrity against the signer in `signer.json`, which is ephemeral to this run. Endpoint execution is an unsigned observation in `summary.json`.
- Not a hosted service, not a certification, not a production deployment.

## Under the hood

The host embeds `createGatewayMiddleware` from the published `@bolyra/gateway` (bundle verification, nonce replay, dev credential binding, tool policy) and signs receipts with `@bolyra/receipts`. See `src/host.ts`. Spec: `docs/superpowers/specs/2026-09-13-operator-trial-design.md`.
