# Pilot Harness — Operator Runbook

Operational steps to take a design partner from "yes" to "pilot running this
week", using only existing pieces: the hosted-verify preview
(`integrations/hosted-verify/`), `@bolyra/cli` (`bolyra verify`,
`receipt verify-chain`), `@bolyra/mpp`, and the pilot docs in `docs/pilot/`.

**Hard scope:** this is a pilot harness, not a hosted platform. No dashboard,
no billing, no self-serve signup, no tenant model, no SLA. See
[Out of scope](#out-of-scope--waits-for-a-real-pilot).

Partner-facing integration doc: [`INTEGRATION.md`](INTEGRATION.md).
Commercials + success criteria: `docs/pilot/design-partner-brief.md` and
`docs/pilot/design-partner-agreement-template.md`.

## Fixed facts (where things live)

| Thing | Where |
|---|---|
| Hosted verify Worker | `integrations/hosted-verify/` → `https://bolyra-hosted-verify.<account>.workers.dev` (workers.dev preview only) |
| Partner bearer tokens | macOS keychain, service `bolyra-hosted-verify`, account `partner-token-<label>` (legacy shared token: account `preview-token`) |
| Live token map | wrangler secret `PARTNER_TOKENS` (JSON label→token; **replaced whole** on every put — only ever update it via `partner-token.sh sync`) |
| Partner registry | `pilot/partners/<label>.json` (gitignored; template `pilot/partner-config.example.json`) |
| Policy record | `pilot/partners/<label>.policy.json` (template `pilot/policy-config.example.json`) |
| Trust anchor | `TRUSTED_OPERATORS` var in `integrations/hosted-verify/wrangler.jsonc` — changing it requires `npm run deploy` |
| Usage data | Analytics Engine dataset `bolyra_hosted_verify_usage` (counts + labels only, never payloads) |
| CF analytics token | keychain service `bolyra-hosted-verify`, account `cf-analytics-token` |
| Receipts | `X-Bolyra-Receipt` response header (hosted, signed, unchained) / gateway-shield receipt logs (signed, hash-chained) |

## 0. One-time prereqs

```bash
cd integrations/hosted-verify && npm install && npx wrangler login  # founder account
# confirm the worker is live:
curl -s https://bolyra-hosted-verify.<account>.workers.dev/health | jq .status
```

## 1. Onboard a partner

```bash
cd integrations/hosted-verify

# 1. Mint a labeled token (keychain) + registry file + push PARTNER_TOKENS:
./pilot/partner-token.sh add <label>

# 2. Fill in the registry + policy records (contacts, operator keys, tier cap):
#      pilot/partners/<label>.json          (from pilot/partner-config.example.json)
#      pilot/partners/<label>.policy.json   (from pilot/policy-config.example.json)

# 3. Pin the partner's operator key(s) — REQUIRED before their own
#    presentations verify (without this they can only run the fixture examples):
#    append their x:y decimal pair(s) to TRUSTED_OPERATORS in wrangler.jsonc, then
npm test && npm run deploy

# 4. Send the partner: the base URL, their token (secure channel — read it with
#    the command partner-token.sh printed), and pilot/INTEGRATION.md.

# 5. Smoke it as them:
TOKEN=$(security find-generic-password -s bolyra-hosted-verify -a partner-token-<label> -w)
curl -s -X POST https://bolyra-hosted-verify.<account>.workers.dev/v1/verify \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  --data @examples/request.allow.json | jq .verdict     # → "allow"

# 6. Confirm attribution (row shows under their label):
CF_API_TOKEN=$(security find-generic-password -s bolyra-hosted-verify -a cf-analytics-token -w) \
  node pilot/usage-partner.mjs <label> 1
```

Partner needs mandates / spend tiers (`@bolyra/mpp`)? Their credential's
permission bits bound the tier (small <$100 / medium <$10k / unlimited);
`bolyra mandate issue --help` for delegated spend mandates. Record the agreed
cap in `tierCaps` in the registry file.

## 2. Rotate a token

```bash
cd integrations/hosted-verify
./pilot/partner-token.sh rotate <label>   # mints new, pushes map — old token dead immediately
# send the new token over a secure channel (command is printed)
```

## 3. Disable / re-enable / revoke a partner

```bash
cd integrations/hosted-verify
./pilot/partner-token.sh disable <label>  # off the Worker, token kept in keychain
./pilot/partner-token.sh enable <label>   # back on
./pilot/partner-token.sh revoke <label>   # off the Worker AND deleted from keychain
./pilot/partner-token.sh show             # sanity: labels, status, keychain presence
```

Notes:
- Secrets take effect immediately; no redeploy.
- Revoking the **last** active partner pushes an effectively-empty map (the
  reserved `unauthenticated` label) — but the legacy shared `PREVIEW_TOKEN`
  is a separate secret and stays live until
  `npx wrangler secret delete PREVIEW_TOKEN`.
- Disabling a partner does **not** un-pin their operator keys. If trust itself
  is the problem (not just the token), also remove their keys from
  `TRUSTED_OPERATORS` in `wrangler.jsonc` and `npm run deploy`.

## 4. Check a partner's usage

```bash
cd integrations/hosted-verify
CF_API_TOKEN=$(security find-generic-password -s bolyra-hosted-verify -a cf-analytics-token -w) \
  node pilot/usage-partner.mjs <label> [days]   # default 7
# all partners at once: npm run usage  (scripts/usage.mjs)
```

Counts only — requests by route, allow/deny/error, deny codes, transport
errors, HTTP statuses, p50/p95 latency. Never payloads, tokens, or IPs.

## 5. Export audit receipts (JSONL)

One export per source (chained and unchained receipts must not share a file):

Always pass `--signer` with the expected receipt-signer address from the
pilot's policy record (`pilot/partners/<label>.policy.json` →
`receipts.signer`) — that is what proves the receipts were signed by *your*
key, not just self-consistently signed:

```bash
SIGNER=0x<receipts.signer from the policy record>

# Gateway/middleware receipt dir (hash-chained per gateway instance):
node pilot/scripts/export-receipts.mjs --gateway-dir <partner-receipts-dir> --signer $SIGNER --out pilot/acme-audit.jsonl

# An NDJSON log (bolyra run --receipt-file …, or gateway stdout mode):
node pilot/scripts/export-receipts.mjs --jsonl receipts.ndjson --signer $SIGNER --out pilot/acme-audit.jsonl

# Hosted-verify receipts the partner captured (one X-Bolyra-Receipt
# base64url header value per line; signed but NOT chained — stateless Worker):
node pilot/scripts/export-receipts.mjs --headers headers.txt --signer $SIGNER --out pilot/acme-audit.jsonl
```

The script pre-verifies the export with the real `@bolyra/receipts` verifier
(fails closed — an export that would fail the partner's check is never
written; with `--signer`, that includes signer identity), then prints the
exact `bolyra receipt verify-chain` command with `--expect-count` /
`--expect-head` / `--signer` filled in, plus the file's sha256 digest. **Run the printed command yourself, then give the partner the
same command** and pin the count + head hash + digest in the pilot status
email — tail truncation (chained) and same-count substitution (unchained) are
not detectable from the log alone.

## 6. Debug deny / error codes

First: `200` means a decision — **branch on `verdict`, not HTTP status.**
Full registry: `spec/external-verifier-contract-v1.md` §9.

| Code | HTTP | Likely cause in a pilot | Do |
|---|---|---|---|
| *(401 body `{"error":…}`)* | 401 | Missing/wrong bearer token | `partner-token.sh show`; re-send token; check they hit the right deployment |
| `malformed_input` | 200 | Body not JSON, >1 MiB, or missing/ill-typed request field | Diff their request against `examples/request.allow.json` (spec §2.1: `version`, `bundle`, `request`, `now_unix`) |
| `unsupported_version` | 200 | `version` ≠ 1, or obsolete v1 (five-field) binding | They must re-issue the binding (binding v2 includes `expiry`) |
| `invalid_bundle` | 200 | `bundle` undecodable / structurally wrong | Regenerate the bundle with a current SDK |
| `invalid_proof` | 200 | Envelope validation failed; also `kind:"zk"` requested | Hosted endpoint is classical-only — zk goes through `bolyra verify` CLI |
| `untrusted_root` | 200 | (zk-class; rare here) root not in trusted set | CLI-path config issue |
| `invalid_signature` | 200 | Binding signature doesn't verify against a **trusted** operator key | Most common onboarding failure: their operator key isn't pinned yet → step 1.3. Or they signed with a different key than they sent you |
| `request_mismatch` | 200 | Request fields ≠ signed binding, or capabilities not covered | Byte-literal match required on `agent_name`/`project_key`/`program`/`model` |
| `model_mismatch` | 200 | Proof committed to a different model string | `sha256(model) mod p` must equal revealed `modelHash` — check exact model string |
| `unknown_capability` | 200 | Capability has no scope mapping | Fail-closed by design; add it to the capability map (Worker `CAPABILITY_MAP` var + policy record) or fix the capability name |
| `scope_exceeded` | 200 | Requested bits ⊄ credential's permission bits | Tier cap working as intended, or credential issued too narrow |
| `expired` | 200 | `now_unix >= expiry` (strict — equality is expired) | Check their clock / `now_unix`; re-issue credential |
| `nonce_missing` | 200 | No usable nullifier signal | Regenerate the bundle |
| `nonce_replayed` | 200 | (local mode only — not hosted) | Hosted is host-mode: THEY must reserve `consume_nonces` before acting |
| `internal_error` | 500 | Worker misconfig (e.g. no trusted operators) or bug | Fail-closed. `npx wrangler tail` in `integrations/hosted-verify/`; check `TRUSTED_OPERATORS` is set; check `/health` |
| *(404/405 `{"error":…}`)* | 404/405 | Wrong path or method | `POST /v1/verify`, `GET /health` — nothing else exists |

Live logs while a partner is testing:

```bash
cd integrations/hosted-verify && npx wrangler tail
```

## Out of scope — waits for a real pilot

Deliberately not built until a paying pilot shapes the need: dashboard,
billing/metering, self-serve signup, policy-builder UI, compliance portal,
tenant model / per-partner operator scoping on the Worker, SSO/RBAC, SIEM
export beyond JSONL, self-host installer, SLA/status page, hosted ZK flows.
If a pilot task seems to need one of these, the answer is a manual step in
this runbook, not new product surface.
