# Pilot Harness — Operator Runbook

Operational steps to take a design partner from "yes" to "pilot running this
week", using only existing pieces: the hosted-verify preview
(`integrations/hosted-verify/`), `@bolyra/cli` (`bolyra verify`,
`receipt verify-chain`), `@bolyra/mpp`, and the pilot docs in `docs/pilot/`.

**Hard scope:** this is a pilot harness, not a hosted platform. No dashboard,
no billing, no self-serve signup, no tenant self-service, no SLA. See
[Out of scope](#out-of-scope--waits-for-a-real-pilot).

Partner-facing integration doc: [`INTEGRATION.md`](INTEGRATION.md).
Commercials + success criteria: `docs/pilot/design-partner-brief.md` and
`docs/pilot/design-partner-agreement-template.md`.

## Fixed facts (where things live)

| Thing | Where |
|---|---|
| Hosted verify Worker | `integrations/hosted-verify/` → `https://bolyra-hosted-verify.<account>.workers.dev` (workers.dev preview only) |
| Tenant tokens | wrangler secret `TENANTS`, two per tenant: `verifier_token` (`POST /v1/verify`) and `admin_token` (tenant administration) |
| Live tenant map | wrangler secret `TENANTS` (JSON `org_id` → tokens, `trusted_operators`, `disabled`; **replaced whole** on every put — always edit your complete copy and re-put it) |
| Partner registry | `pilot/partners/<label>.json` (gitignored; template `pilot/partner-config.example.json`) |
| Policy record | `pilot/partners/<label>.policy.json` (template `pilot/policy-config.example.json`) |
| Trust anchor | each tenant's `trusted_operators` list inside the `TENANTS` secret — changing it takes effect on the next request, no redeploy |
| Usage data | Analytics Engine dataset `bolyra_hosted_verify_usage` (counts + labels only, never payloads) |
| CF analytics token | keychain service `bolyra-hosted-verify`, account `cf-analytics-token` |
| Receipts | `X-Bolyra-Receipt` response header (hosted, signed, unchained) / gateway-shield receipt logs (signed, hash-chained) |

## The `TENANTS` secret (read before editing it)

The Worker re-parses `TENANTS` on **every** request and validates the map as a
whole. Any defect in any entry invalidates the whole map, and then **every**
tenant fails closed — `POST /v1/verify` returns `500` `internal_error` and
`/health` reports `tenants: "invalid"` — until a valid map is put. Defects:

- an empty `trusted_operators` list (never "trust everyone"), or an entry that
  is not an `x:y` decimal pair;
- an unknown field on an entry (a typo in `disabled` must not silently leave a
  tenant live);
- a token shorter than 32 or longer than 256 characters, or containing anything
  outside `[A-Za-z0-9._~+/-]`;
- the same token value used twice anywhere in the map (it then grants nothing);
- an `org_id` outside `^[a-z0-9][a-z0-9-]{1,62}$`;
- an empty map (`{}`), invalid JSON, or a serialized map of 4,096 bytes or more.

So every recipe below is **one atomic put of a complete, valid map**. Never
push a placeholder entry meant to be filled in later.

**Your plaintext copy.** `wrangler secret put` is write-only — the live map
cannot be read back — so keep one authoritative copy of the whole map: a
1Password (or macOS keychain) item, or a `chmod 600` file outside every repo
checkout, e.g. `~/.bolyra/tenants.json`. Lose it and there is no recovery but
re-keying: new tokens for every tenant, re-sent over secure channels.

**Seeded fixture key.** Each pilot tenant's `trusted_operators` carries the
partner's operator key(s) **and** the repo conformance fixture key (the one in
`integrations/hosted-verify/.dev.vars.example`). That is deliberate: the
fixture key is what makes the quickstart in `integrations/hosted-verify/`
and the smoke step below work for them before their own key issues anything.

## 0. One-time prereqs

```bash
cd integrations/hosted-verify && npm install && npx wrangler login  # founder account
# confirm the worker is live:
curl -s https://bolyra-hosted-verify.<account>.workers.dev/health | jq .status
```

## 1. Onboard a partner

```bash
cd integrations/hosted-verify

# 1. Collect the partner's operator public key(s) FIRST (x:y decimal pairs).
#    Without them there is no valid entry to push — an empty trusted_operators
#    list 500s EVERY tenant — so until you have a key, push nothing.
#    Then ONE atomic put of the complete map, the new entry carrying their
#    key(s) AND the seeded fixture key:
#      "<org_id>": {"admin_token": "<openssl rand -hex 32>",
#                   "verifier_token": "<a different openssl rand -hex 32>",
#                   "trusted_operators": ["<their x:y>", "<fixture x:y>"]}
#    (the put REPLACES the whole map — anything you leave out is revoked):
npx wrangler secret put TENANTS

# 2. Fill in the registry + policy records (contacts, operator keys, tier cap):
#      pilot/partners/<label>.json          (from pilot/partner-config.example.json)
#      pilot/partners/<label>.policy.json   (from pilot/policy-config.example.json)

# 3. Adding or replacing an operator key later (a second key, a re-issue):
#    edit that tenant's trusted_operators in your copy of the map and re-put
#    the whole map — takes effect on the next request, no redeploy. Their own
#    presentations verify only once their key is in that list; never empty the
#    list to revoke a key (see "3. Disable / re-enable / revoke a partner"):
npx wrangler secret put TENANTS

# 4. Send the partner: the base URL, their verifier token (secure channel —
#    from your own copy of the TENANTS map), and pilot/INTEGRATION.md.

# 5. Smoke it as them. examples/request.allow.json is signed by the repo
#    fixture key, so an "allow" here proves their token plus the seeded
#    fixture key — a request signed by THEIR operator key is the real proof:
TOKEN=<their verifier token>
curl -s -X POST https://bolyra-hosted-verify.<account>.workers.dev/v1/verify \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  --data @examples/request.allow.json | jq .verdict     # → "allow"

# 6. Confirm attribution (row shows under their <org_id>:<role> label):
CF_API_TOKEN=$(security find-generic-password -s bolyra-hosted-verify -a cf-analytics-token -w) \
  node pilot/usage-partner.mjs <org_id>:verifier 1
```

Partner needs mandates / spend tiers (`@bolyra/mpp`)? Their credential's
permission bits bound the tier (small <$100 / medium <$10k / unlimited);
`bolyra mandate issue --help` for delegated spend mandates. Record the agreed
cap in `tierCaps` in the registry file.

## 2. Rotate a token

```bash
cd integrations/hosted-verify
# Replace that tenant's verifier_token (or admin_token) in your copy of the
# map and re-put the whole map — the old token dies the instant it lands:
npx wrangler secret put TENANTS
# send the new token over a secure channel
```

## 3. Disable / re-enable / revoke a partner

```bash
cd integrations/hosted-verify
# Each of these is an edit to your complete copy of the map followed by one
# `npx wrangler secret put TENANTS` (the put REPLACES the whole map):
#   quarantine  set "disabled": true on the tenant's entry — entry, keys and
#               label all stay, but every route answers 500 internal_error,
#               which the partner cannot tell apart from a config defect on
#               our side; tell them it is deliberate, or they will report a
#               broken deployment
#   re-enable   set "disabled": false (or drop the field)
#   revoke      delete the tenant's entry from the map
#
# To de-trust an operator key, delete the entry or quarantine it. NEVER clear
# a tenant's trusted_operators to [] — an empty list is a defect that 500s
# every OTHER tenant too.
npx wrangler secret put TENANTS
# sanity: the map parses (it does not list tenants):
curl -s https://bolyra-hosted-verify.<account>.workers.dev/health | jq .tenants
```

Notes:
- Secrets take effect immediately; no redeploy.
- `wrangler secret put TENANTS` replaces the WHOLE map: always start from your
  complete copy, or every tenant you left out is revoked by accident.
- Removing the **last** tenant leaves `{}`, which the loader rejects: every
  request is then `500` `internal_error` and `/health` reports
  `tenants: "invalid"` — not `401`. To stand the deployment down with no
  active partners, quarantine the remaining tenants instead.
- Quarantining a tenant does **not** un-pin their operator keys, and that is
  fine: a quarantined tenant is served on no route. If trust itself is the
  problem, delete the whole entry — never leave the entry with an empty
  `trusted_operators`.

## 4. Check a partner's usage

```bash
cd integrations/hosted-verify
CF_API_TOKEN=$(security find-generic-password -s bolyra-hosted-verify -a cf-analytics-token -w) \
  node pilot/usage-partner.mjs <org_id>:<role> [days]   # default 7
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
| *(401 body `{"error":…}`)* | 401 | Missing/wrong bearer token | Check the tenant's entry in `TENANTS`; re-send token; check they hit the right deployment |
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
| `internal_error` | 500 | Worker misconfig (an unset/malformed `TENANTS`, a quarantined tenant, or a tenant with no trusted operators) or bug | Fail-closed. `npx wrangler tail` in `integrations/hosted-verify/`; check `/health` reports `tenants: "ok"`; check that tenant's entry |
| *(404/405 `{"error":…}`)* | 404/405 | Wrong path or method | `POST /v1/verify`, `GET /health` — nothing else exists |

Live logs while a partner is testing:

```bash
cd integrations/hosted-verify && npx wrangler tail
```

## Out of scope — waits for a real pilot

Deliberately not built until a paying pilot shapes the need: dashboard,
billing/metering, self-serve signup, policy-builder UI, compliance portal,
tenant self-service, SSO/RBAC, SIEM export beyond JSONL, self-host installer,
SLA/status page, hosted ZK flows.
If a pilot task seems to need one of these, the answer is a manual step in
this runbook, not new product surface.
