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
| Staging Worker | `bolyra-hosted-verify-staging.<account>.workers.dev` — `wrangler … --env staging`; its own secrets, its own Durable Object namespace, its own analytics dataset (`bolyra_hosted_verify_usage_staging`); configured as `env.staging` in `wrangler.jsonc` |
| Tenant tokens | macOS keychain, service `bolyra-hosted-verify` (`-staging` for staging), accounts `tenant-<org_id>-admin` and `tenant-<org_id>-verifier`; written and read only by `integrations/hosted-verify/pilot/tenant.sh` |
| Live tenant map | wrangler secret `TENANTS` (JSON `org_id` → tokens, `trusted_operators`, `disabled`; **replaced whole** on every put) — only ever written by `tenant.sh sync`, which validates the map first |
| Tenant registry | `pilot/tenants/<org_id>.json` (gitignored; template `pilot/partner-config.example.json`; no secrets — org id, status, operator keys, contacts) |
| Policy record | `pilot/tenants/<org_id>.policy.json` (template `pilot/policy-config.example.json`) |
| Trust anchor | each tenant's `trusted_operators` **plus** that tenant's managed credential registry: an allow needs a trusted key **and** a registered, unrevoked binding |
| Managed credential registry | one SQLite Durable Object per tenant (`TENANT` binding, class `TenantRegistry`), reachable only through `POST /v1/credentials`, `GET /v1/credentials/{id}`, `POST /v1/credentials/{id}/revoke` with the tenant's **admin** token. Persists the signed binding, operator key, credential id, status, and timestamps; never presentations, proofs, nonces, tokens, or IPs. Revoked records are kept forever |
| Capability map | `CAPABILITY_MAP` var in `wrangler.jsonc` (both environments): `@bolyra/mpp`'s `mpp:financial:*` vocabulary merged over the built-in messaging default. Global, not per tenant; a change needs a deploy (`wrangler deploy` re-sets vars from the file) |
| Usage data | Analytics Engine dataset `bolyra_hosted_verify_usage` (counts + `<org_id>:<role>` labels only, never payloads or credential ids) |
| CF analytics token | keychain service `bolyra-hosted-verify`, account `cf-analytics-token` |
| Receipts | `X-Bolyra-Receipt` response header (hosted, signed, unchained; signer published at `/.well-known/bolyra-signers.json`) / gateway-shield receipt logs (signed, hash-chained) |
| Rollback floor | the version id recorded in [7. Deploy](#7-deploy-staging-first-then-the-managed-cutover) — never deploy below it |

## The `TENANTS` secret (read before touching it)

The Worker re-parses `TENANTS` on **every** request and validates the map as a
whole. Any defect in any entry invalidates the whole map, and then **every**
tenant fails closed — `POST /v1/verify` returns `500` `internal_error`, the
registry routes return `500`, and `/health` reports `tenants: "invalid"` —
until a valid map is put. Defects:

- an empty `trusted_operators` list (never "trust everyone"), or an entry that
  is not an `x:y` decimal pair;
- an unknown field on an entry (a typo in `disabled` must not silently leave a
  tenant live), or a mistyped VALUE — `"disabled": "true"` is a string, not a
  boolean, and is a defect;
- a token shorter than 32 or longer than 256 characters, or containing anything
  outside `[A-Za-z0-9._~+/-]`;
- the same token value used twice anywhere in the map (it then grants nothing);
- an `org_id` outside `^[a-z0-9][a-z0-9-]{1,62}$`;
- an empty map (`{}`), invalid JSON, a repeated JSON key, or a serialized map
  of 4,096 bytes or more.

That is why the map is never edited by hand: `tenant.sh sync` rebuilds it from
the registry files and the keychain, runs it through
`pilot/tenants-check.mjs` — the same rules, proven against the Worker's own
loader by `test/tenants-check.spec.ts` — and refuses to push anything that
would fail. `wrangler secret put` is write-only (the live map cannot be read
back), so the keychain items plus the registry files **are** the authoritative
copy. Back the keychain up; lose it and the only recovery is re-keying every
tenant. Every command except `show` holds a per-environment lock for its whole
run, so two operators cannot interleave a quarantine and a sync. An interrupt
takes effect only after the in-flight put has finished, and the lock is
released only once wrangler confirms the upload. A lock that is kept names its
own directory: run `tenant.sh sync --dry-run` to see what is live, then `sync`,
then remove that directory by hand.

**Seeded fixture key.** `tenant.sh add … --with-fixture-key` trusts the partner's
key(s) **and** the repo conformance fixture key; without the flag only the keys
you give are trusted. Seed it deliberately during onboarding: the fixture key is
what makes the quickstart in `integrations/hosted-verify/` and
`examples/managed-revocation` work for them before their own key issues
anything. Its private half is in the public repo
(`integrations/cli/test/fixtures/verify/generate.ts`), so anyone can sign a
fixture-key presentation: a fixture-signed `allow` proves transport, the bearer
token, and the registry — nothing about who the caller is. The seeding is
preview-only and must never survive into a real deployment: once their own key
has passed step 5, edit the fixture key out of `trustedOperators` and re-sync.

## 0. One-time prereqs

```bash
cd integrations/hosted-verify && npm ci && npx wrangler login  # founder account
# macOS keychain + openssl are assumed (tenant.sh). Confirm the Worker is live and enforcing:
curl -s https://bolyra-hosted-verify.<account>.workers.dev/health | jq '{status, tenants, registry_enforced, receipts_enabled}'
# Cloudflare notification (once, in the dashboard): Notifications → add "Workers — error rate"
# for this Worker, email to the founder. A configuration defect 500s every tenant at once;
# this is the only alarm that would fire.
```

## 1. Onboard a partner

```bash
cd integrations/hosted-verify

# 1. Collect the partner's operator public key(s) FIRST (x:y decimal pairs). Without a key
#    there is no valid entry, and an empty trusted_operators list 500s EVERY tenant.
#    Then ONE command: mints both tokens into the keychain, writes the registry file,
#    seeds the fixture key (opt-in; needed for steps 5 and 6), validates the whole map,
#    and re-puts TENANTS:
pilot/tenant.sh add <org_id> <their-x>:<their-y>[,<second-x>:<second-y>] --with-fixture-key

# 2. Fill in the human fields of the registry + policy records (contacts, tier cap) — these
#    live at the REPO ROOT, not under integrations/hosted-verify:
#      <repo root>/pilot/tenants/<org_id>.json          (created by add; template <repo root>/pilot/partner-config.example.json)
#      <repo root>/pilot/tenants/<org_id>.policy.json   (copy <repo root>/pilot/policy-config.example.json)

# 3. A second key later, or a re-issued one: edit trustedOperators in the registry file
#    and re-sync — takes effect on the next request, no redeploy. Never empty the list;
#    to de-trust a key, edit it out (their registered bindings under that key stay ACTIVE:
#    revoke them too if that is the intent — step 3 below).
pilot/tenant.sh sync

# 4. Send the partner over a secure channel: the base URL; BOTH tokens (read them yourself,
#    deliberately — the script never prints them):
#      security find-generic-password -s bolyra-hosted-verify -a tenant-<org_id>-admin -w
#      security find-generic-password -s bolyra-hosted-verify -a tenant-<org_id>-verifier -w
#    and pilot/INTEGRATION.md. Tell them the capability vocabulary the deployment carries
#    (mpp:financial:small|medium|unlimited plus the messaging default).

# 5. Smoke it as them — registration is part of the smoke: an allow needs a REGISTERED
#    binding, not just a trusted key. The fixture registration + request prove their
#    tokens, the seeded fixture key, and the registry; a binding signed by THEIR key,
#    registered with THEIR admin token, is the real proof:
BASE=https://bolyra-hosted-verify.<account>.workers.dev
ADMIN=<their admin token>; TOKEN=<their verifier token>
curl -s -X POST $BASE/v1/credentials -H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json" \
  --data @examples/registration.allow.json | jq                  # → 201 { credential_id, status: "ACTIVE", … }
curl -s -X POST $BASE/v1/verify -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  --data @examples/request.allow.json | jq .verdict               # → "allow"

# 6. The end-to-end acceptance test is the example, pointed at the deployment:
#    register → allow → allow → revoke → deny credential_not_active → an independent
#    credential still allows (20 checks; exits non-zero on any miss):
(cd ../../examples/managed-revocation && npm ci && VERIFY_URL=$BASE ADMIN_TOKEN=$ADMIN VERIFIER_TOKEN=$TOKEN npm run demo)

# 7. Confirm attribution (rows under their <org_id>:verifier label; repeat with :admin for the registry calls):
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
pilot/tenant.sh rotate <org_id> verifier     # or admin
# The old token dies when the sync lands (next request). Send the new one over a
# secure channel (security find-generic-password … -w, as in 1.4).
```

## 3. Quarantine, re-enable, remove; revoke a credential

```bash
cd integrations/hosted-verify

# quarantine — entry, keys, label and registry all stay; the tenant is served on NO route:
#   /v1/verify answers 500 internal_error (a verdict; logged at warn, not error, so the
#   configuration alarm stays quiet) and the registry routes answer 503 tenant_disabled.
#   The partner cannot tell the 500 from a defect on our side: tell them it is deliberate.
pilot/tenant.sh disable <org_id>

# re-enable — refuses without the flag; the flag records that whatever the quarantine
# was about (a key, a token) has been retired or re-issued:
pilot/tenant.sh enable <org_id> --keys-retired

# remove — deletes both tokens from the keychain and the entry from the map. The registry
# file stays (status=removed) and so does the tenant's Durable Object with its history;
# nothing about a removed tenant is served. To bring the same org_id back, `add` refuses
# because the file exists: run `rotate <org_id> admin` and `rotate <org_id> verifier`
# to re-mint both tokens first — a removed tenant is skipped by sync, so both pass
# cleanly — then set "status": "active" in the registry file by hand and run `sync`;
# the Durable Object resumes as it was — revoked credentials stay revoked:
pilot/tenant.sh remove <org_id>

# revoke ONE credential (not the tenant): the partner does this with their admin token,
# or you do it for them. Terminal — a revoked binding can never be re-registered:
# BASE and ADMIN as in step 1.5 (their base URL and admin token).
curl -s -o /dev/null -w '%{http_code}\n' -X POST $BASE/v1/credentials/<credential_id>/revoke \
  -H "Authorization: Bearer $ADMIN"                              # → 204 (204 again if already revoked)

# sanity after any change: the map parses (it does not list tenants):
curl -s $BASE/health | jq .tenants                              # → "ok"
```

Notes:
- Secrets take effect on the next request; no redeploy.
- `sync` replaces the WHOLE map from the registry directory: a file you delete
  by hand is a tenant you revoked by accident — use `remove`.
- Removing the **last** tenant would leave `{}`, which the loader rejects
  (every request `500`, `/health` `tenants: "invalid"`, not `401`), so `sync`
  refuses to push an empty map. To stand the deployment down with no active
  partners, quarantine the remaining tenants instead.
- Quarantining does **not** un-pin operator keys or revoke credentials, and
  that is fine: a quarantined tenant is served on no route. If trust in a key is
  the problem, edit it out of `trustedOperators` **and** revoke the credentials
  registered under it — the registry read does not consult the key list.

## 4. Check a partner's usage

```bash
cd integrations/hosted-verify
CF_API_TOKEN=$(security find-generic-password -s bolyra-hosted-verify -a cf-analytics-token -w) \
  node pilot/usage-partner.mjs <org_id>:<role> [days]   # default 7
# all tenants at once: npm run usage  (scripts/usage.mjs; staging: USAGE_DATASET=bolyra_hosted_verify_usage_staging npm run usage)
```

Counts only — requests by route, allow/deny/error, deny codes, transport
errors, HTTP statuses, p50/p95 latency. Never payloads, tokens, IPs, or
credential ids.

## 5. Export audit receipts (JSONL)

One export per source (chained and unchained receipts must not share a file).
Run these from the **repo root** (`pilot/scripts/` lives there).

Always pass `--signer` with the expected receipt-signer address from the
pilot's policy record (`pilot/tenants/<org_id>.policy.json` →
`receipts.signer`; the live value is at
`https://bolyra-hosted-verify.<account>.workers.dev/.well-known/bolyra-signers.json`) —
that is what proves the receipts were signed by *your* key, not just
self-consistently signed:

```bash
cd "$(git rev-parse --show-toplevel)"
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
`--expect-head` / `--signer` filled in, plus the file's sha256 digest. **Run
the printed command yourself, then give the partner the same command** and
pin the count + head hash + digest in the pilot status email — tail truncation
(chained) and same-count substitution (unchained) are not detectable from the
log alone.

## 6. Debug deny / error codes

First: `200` means a decision — **branch on `verdict`, not HTTP status.**
Full registry: `spec/external-verifier-contract-v1.md` §9.

| Code | HTTP | Likely cause in a pilot | Do |
|---|---|---|---|
| *(401 `{"error":"unauthorized"}`)* | 401 | Missing/wrong bearer token | `tenant.sh show`; re-send the token; check they hit the right deployment (staging vs production) |
| *(403 `{"error":"forbidden"}`)* | 403 | Right tenant, wrong role: an admin token on `/v1/verify`, or a verifier token on a registry route | Two tokens per tenant — send them the other one |
| *(503 `{"error":"tenant_disabled"}`)* | 503 | Their tenant is quarantined (registry routes; `/v1/verify` answers 500 instead) | Deliberate — see step 3 |
| `untrusted_root` | 200 | **The most common deny.** Either the operator key that signed the binding is not in the tenant's `trusted_operators` (`detail.operator_key` names the key), or the binding is not an ACTIVE credential in that tenant's registry — never registered, or revoked (`detail.reason: "credential_not_active"`, `detail.credential_id`) | Unpinned key → step 1.3. Not registered → they `POST /v1/credentials` with the admin token. Revoked → intended; revocation is terminal |
| `invalid_signature` | 200 | The binding signature does not verify against a key that **is** pinned | They signed with a different key than the one they sent you; or a corrupted bundle |
| `malformed_input` | 200 | Body not JSON, >1 MiB, or missing/ill-typed request field | Diff their request against `examples/request.allow.json` (spec §2.1: `version`, `bundle`, `request`, `now_unix`) |
| `unsupported_version` | 200 | `version` ≠ 1, or an obsolete five-field v1 binding | They must re-issue the binding (binding v2 includes `expiry`) |
| `invalid_bundle` | 200 | `bundle` undecodable / structurally wrong | Regenerate the bundle with a current SDK |
| `invalid_proof` | 200 | Envelope validation failed; also `kind:"zk"` requested | Hosted endpoint is classical-only — zk goes through the `bolyra verify` CLI |
| `request_mismatch` | 200 | Request fields ≠ signed binding, or capabilities not covered | Byte-literal match required on `agent_name`/`project_key`/`program`/`model` |
| `model_mismatch` | 200 | Proof committed to a different model string | `sha256(model) mod p` must equal the revealed `modelHash` — check the exact model string |
| `unknown_capability` | 200 | The capability has no scope mapping | Fail-closed by design. The map is `CAPABILITY_MAP` in `wrangler.jsonc` (global; a change is a deploy) — add the capability there and in the policy record, or fix the name |
| `scope_exceeded` | 200 | Requested bits ⊄ credential's permission bits | Tier cap working as intended, or credential issued too narrow |
| `expired` | 200 | `now_unix >= expiry` (strict — equality is expired) | Check their clock / `now_unix`; re-issue the credential |
| `nonce_missing` | 200 | No usable nullifier signal | Regenerate the bundle |
| `nonce_replayed` | 200 | (local mode only — not hosted) | Hosted is host-mode: THEY reserve `consume_nonces` before acting; `@bolyra/mpp`'s gate does this |
| `internal_error` | 500 | Fail-closed: `TENANTS` unset or malformed, or `CAPABILITY_MAP` malformed (every tenant; an *unset* `CAPABILITY_MAP` is not a defect — it falls back to the messaging default and mpp capabilities then deny `unknown_capability`), a quarantined tenant, a registry RPC failure or its 2,000 ms deadline, a missing `TENANT` Durable Object binding (a deploy from an environment that did not redeclare it), or a bug | `npx wrangler tail --env=`; `/health` → `tenants` must be `"ok"`; `tenant.sh sync --dry-run` validates the map; check the deploy came from `wrangler.jsonc` with the `TENANT` binding |
| *(409 `{"error":"credential_revoked"}`)* | 409 | Re-registering a revoked binding | Terminal by design; the partner must issue a new binding |
| *(404 `{"error":"not_found"}`)* | 404 | Unknown credential id, a malformed id (not 64 lowercase hex), a wrong path, or **another tenant's** credential (never 403 — tenants cannot probe each other) | Routes: `GET /health`, `POST /v1/verify`, `POST /v1/credentials`, `GET /v1/credentials/{id}`, `POST /v1/credentials/{id}/revoke`, `GET /.well-known/bolyra-signers.json` |

`/health` reports `tenants: "invalid"` → the map on the Worker is defective and
every tenant is down: `tenant.sh sync --dry-run` from the registry, fix what it
names, `tenant.sh sync`.

Live logs while a partner is testing:

```bash
cd integrations/hosted-verify && npx wrangler tail --env=            # --env=staging for staging
```

One structured line per authenticated decision and per authenticated registry
request: `request_id, org_id, role, route, verdict, code, credential_id?,
latency_ms`. A registry write that fails with `registry storage failure` means
the tenant's Durable Object could not persist: check the Workers dashboard →
Durable Objects → storage and errors for `TenantRegistry`. The registry is
tiny (a few KiB per credential), so a storage error is an outage, not a quota.

## 7. Deploy: staging first, then the managed cutover

Two Workers, one config. `wrangler.jsonc`'s `env.staging` deploys
`bolyra-hosted-verify-staging` with its own secrets, Durable Object
namespace, and analytics dataset. Both environments carry `CAPABILITY_MAP`.
Cloudflare's `wrangler deploy` is a one-step 100% deployment that prints
`Current Version ID:`; gradual rollouts are opt-in (`wrangler versions`) and
are **not** used for this Worker. Production is the top-level environment:
`npm run deploy:prod` passes `--env=""` explicitly (a bare `npm run deploy`
refuses and names the two targets), `tenant.sh` does the same, and `npm run dev`
is pinned the same way (`npm run dev:staging` for staging), because a
`CLOUDFLARE_ENV` variable in the shell would otherwise redirect a command with
no `--env` to whatever it names — check `env | grep CLOUDFLARE_ENV` before any
production step.

**Local dev against either shape.** `npm run dev:staging` reads
`.dev.vars.staging` *instead of* `.dev.vars` — no merge, so the file must be
complete (a missing `TENANTS` fails every request closed with a 500 verdict and
no hint why); only when `.dev.vars.staging` is absent does it fall back to
`.dev.vars`. `npx wrangler types --env staging` rewrites the gitignored
`worker-configuration.d.ts` with staging literals — run plain `npx wrangler types`
afterwards. Usage reports read production's dataset unless told otherwise:
`USAGE_DATASET=bolyra_hosted_verify_usage_staging npm run usage`.

```bash
cd integrations/hosted-verify
npm ci && npm test && npm run typecheck

# ── Staging ─────────────────────────────────────────────────────────────────
# Deploy FIRST: a `secret put` against a Worker that does not exist yet makes wrangler
# create a stub Worker (non-interactively it answers its own prompt with yes).
npm run deploy:staging                                        # note the printed Current Version ID
npx wrangler secret put RECEIPT_SIGNER_KEY --env staging      # a fresh 0x-hex secp256k1 key
HOSTED_VERIFY_ENV=staging pilot/tenant.sh add <org_id> <x:y> --with-fixture-key  # staging keychain + <repo root>/pilot/tenants-staging/; the example below signs with the fixture key
curl -s https://bolyra-hosted-verify-staging.<account>.workers.dev/health | jq '{tenants, registry_enforced, receipts_enabled}'

# The gate for production: the example must pass against staging.
(cd ../../examples/managed-revocation && npm ci && \
  VERIFY_URL=https://bolyra-hosted-verify-staging.<account>.workers.dev \
  ADMIN_TOKEN="$(security find-generic-password -s bolyra-hosted-verify-staging -a tenant-<org_id>-admin -w)" \
  VERIFIER_TOKEN="$(security find-generic-password -s bolyra-hosted-verify-staging -a tenant-<org_id>-verifier -w)" \
  npm run demo)                                               # → 20/20 checks passed
# Record the run (date, commit, version id, "20/20") in the table below.

# ── Production: the first managed cutover ───────────────────────────────────
# Zero consumers are on record, so a maintenance window is a courtesy, not a risk.
# 1. Deploy the build (100%, one step). The moment it lands, the Worker requires a
#    REGISTERED binding for every allow — legacy tokens and unregistered bindings stop.
npm run deploy:prod                                           # note the printed Current Version ID
# 2. Retire the legacy secrets if they are still set (they are read by nothing):
npx wrangler secret list --env=
npx wrangler secret delete PREVIEW_TOKEN --env=; npx wrangler secret delete PARTNER_TOKENS --env=
# 3. Provision: RECEIPT_SIGNER_KEY (if not yet), then every tenant through tenant.sh
#    (step 1), then REGISTER each binding a tenant expects to verify (step 1.5/1.6).
# 4. Hand out verifier + admin tokens and the capability vocabulary (step 1.4).
# 5. Record the version id below as the ROLLBACK FLOOR.
```

**Rollback floor.** The first version that reports `registry_enforced: true`
on `/health` is the floor. Never deploy a build below it, and never deploy a
build that verifies without the registry: a deployment that allows unregistered
bindings while tenants hold registrations is a storage-incident-class event.
If a rollback below the floor is ever unavoidable: quarantine every tenant
first (`tenant.sh disable …` for each), deploy, and treat every registration
as unverified until the floor is restored.

| Environment | Version id | Deployed (UTC) | Commit | Example run |
|---|---|---|---|---|
| staging | *(not yet deployed)* | — | — | — |
| production | *(not yet deployed — the floor is unset)* | — | — | — |

## Out of scope — waits for a real pilot

Deliberately not built until a paying pilot shapes the need: dashboard,
billing/metering, self-serve signup, policy-builder UI, compliance portal,
tenant self-service, SSO/RBAC, SIEM export beyond JSONL, self-host installer,
SLA/status page, hosted ZK flows.
If a pilot task seems to need one of these, the answer is a manual step in
this runbook, not new product surface.
