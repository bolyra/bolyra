# Managed revocation

An operator delegates a spend mandate to an agent by signing a Bolyra request
binding. This example registers that signed binding with a **hosted** Bolyra
verifier, spends under it through an mppx payment gate, **revokes** it, and
shows the very next presentation denied before the paid action runs — while an
independent credential under the same operator keeps working. The paid action
is an in-memory counter; the counter is the evidence.

This is the revocation demonstration. `examples/operator-trial` verifies
locally and is not revocation evidence.

## Run it

```bash
# from the repo root
# 1. the hosted verifier (built from this repo — it is not published)
cd integrations/hosted-verify && npm ci --no-audit --no-fund && cd ../..
# 2. the example (published @bolyra/mpp 0.5.0 + mppx 0.8.13 from the registry)
cd examples/managed-revocation && npm ci --no-audit --no-fund
npm run demo:local
```

`demo:local` writes `integrations/hosted-verify/.dev.vars` (the repo's
documented placeholder tenant, the mpp capability vocabulary read from the
installed `@bolyra/mpp`, and a throwaway receipt signing key — none of it
secret, none of it printed), starts `wrangler dev` on `127.0.0.1:8787`
(`HOSTED_VERIFY_PORT` picks another port; a busy 8787 is an error, not a
fallback), waits for `/health`, runs the sequence, and stops the Worker. Node 22
(wrangler's requirement), on macOS or Linux — `demo:local` is a bash script and
uses `lsof` and `curl`. Windows is untested. The generated `.dev.vars` is
removed on exit; an existing `.dev.vars` this script did not write blocks the
run rather than being overwritten.
Measured from a fresh clone with a warm npm cache: the two installs about
10 seconds together, `npm run demo:local` about 4 seconds, of which the Worker
start is about one; a cold CI cache adds to the installs, not the run.

Against a verifier you already run: `VERIFY_URL=… ADMIN_TOKEN=… VERIFIER_TOKEN=… npm run demo`.
The tenant must trust the example's operator key (the repo's documented
test-only scalar, `42`) and its `CAPABILITY_MAP` must carry the mpp vocabulary.
The deployment must also have receipts on (`RECEIPT_SIGNER_KEY`) and serve
`/.well-known/bolyra-signers.json` — rows 0 and 3 check both, and the run exits
non-zero without them.

## What happens

| # | step | evidence | result |
|---|------|----------|--------|
| 0 | `GET /health` | verifier | `registry_enforced: true`, `tenants: "ok"`, `receipts_enabled: true` |
| 1 | issue a `mpp:financial:small` mandate; `POST /v1/credentials` | verifier | `201` + `credential_id`, equal to the id derived in-process from the mandate (the installed `@bolyra/mpp` `bindingDigest` + `src/credential-id.ts`, a `node:crypto` mirror of the Worker's derivation); a second presentation of the same binding → `200`, same id |
| 2 | 402→pay handshake with two fresh presentations | gate | **ALLOWED**, counter **1**; `Payment-Receipt.bolyraAuthorization.verifier = "url"` |
| 3 | `POST /v1/verify` with a fresh presentation | verifier | `x-bolyra-credential-id` = the registered id; `x-bolyra-receipt` passes `bolyra receipt verify --signer-from` |
| 4 | handshake again, fresh presentations | gate | **ALLOWED**, counter **2** |
| 5 | `POST /v1/credentials/{id}/revoke` | verifier | `204`; again `204` (idempotent); re-register → `409 credential_revoked` (terminal) |
| 6 | handshake with a fresh presentation of the revoked binding | gate | **DENIED** `401` `code: untrusted_root` before any 402; counter still **2**; the verdict the gate threw carries `detail.reason: credential_not_active` and the id |
| 7 | `POST /v1/verify` with another fresh presentation | verifier | `200` `deny untrusted_root`, `detail: { reason: "credential_not_active", credential_id }`, no id header |
| 8 | an independent mandate under the same operator: register, handshake | both | `201`, a different id; **ALLOWED**, counter **3** |

The run exits non-zero if any row comes out differently.

Row 1's second presentation maps to the same id because the run computes its
absolute expiry once and reuses it: `expiry` is inside the signed binding, so
a re-issue with a relative `--expiry 30d` is a new binding and a new id that
must be registered on its own — see
[Renewal](../../pilot/INTEGRATION.md#renewal).

## Two evidence sources

- **`[gate]`** — what the published `@bolyra/mpp` gate proves on its own: the
  counter, the Problem Details `code`, and the payment receipt's
  `bolyraAuthorization` field. The gate's hosted-verifier client keeps only the
  verdict body, so response headers never reach it, and its Problem Details
  `detail` is the verdict's message; the structured `detail` object is
  available in-process on the thrown `BolyraDeniedError`, which is where row 6
  reads it.
- **`[verifier]`** — what only the hosted verifier shows, read by calling
  `POST /v1/verify` directly with the verifier token: the
  `x-bolyra-credential-id` header on an allow (unsigned correlation, not an
  authorization input), the signed `x-bolyra-receipt` (decoded and checked with
  `bolyra receipt verify --signer-from <verifier>/.well-known/bolyra-signers.json`),
  and the deny `detail`.

## Two presentations per paid action

The gate runs the Bolyra decision on **every** request (`enforce: 'always'`, the
default), including the credential-less discovery request that mppx answers
with a 402. That discovery attempt already reserves the presentation's
nullifier, so the paid retry must present a **fresh** one — re-sending the
discovery presentation is denied `403 nonce_replayed`, and a request with no
presentation at all is `401 missing_authorization` before any 402.
`test/server.test.ts` proves all three against a stubbed verifier, without the
Worker.

## Not shown here

- Money. The payment method is mppx's mock shape; nothing settles.
- A production verifier. `wrangler dev` runs the Worker locally with a
  placeholder tenant; the same sequence against a deployed instance needs a
  tenant that trusts your operator key and carries `CAPABILITY_MAP`.
- ZK proofs. The hosted verifier is classical-only — Bolyra Core: the
  operator's EdDSA signature over the binding, checked against the tenant's
  trusted operator keys. See
  [`integrations/hosted-verify`](../../integrations/hosted-verify/README.md).
- Revocation reaching the gate by any path other than the verifier's verdict.
  Revocation is a registry-status change at the verifier — the operator key
  stays trusted (row 8); the gate learns it on the next presentation.

## Tests

```bash
npm test   # typecheck + test/server.test.ts (4 cases against a stubbed verifier) + test/versions.test.ts (pins, incl. the installed @bolyra/mpp) + test/credential-id.test.ts
```

`test/credential-id.test.ts` checks `src/credential-id.ts` against every committed
credential id in `integrations/hosted-verify/test/fixtures/registrations.json`, read from
the repo checkout: unlike `npm run demo`, `npm test` needs the repo checkout.
