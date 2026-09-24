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
| Tenant registry | `$HOME/.bolyra/tenants-production/<org_id>.json` (staging: `$HOME/.bolyra/tenants-staging/`; `TENANTS_DIR` overrides) — **off the git checkout**, usable only once initialized (see [Initializing or migrating the registry](#initializing-or-migrating-the-registry)); template `pilot/partner-config.example.json`; no secrets — org id, status, operator keys, contacts. The old in-checkout `pilot/tenants/` and `pilot/tenants-staging/` are the legacy location (still gitignored) |
| Policy record | `$HOME/.bolyra/tenants-production/<org_id>.policy.json` beside the tenant record (template `pilot/policy-config.example.json`) |
| Registry lock | `$HOME/.bolyra/tenants-<env>/.lock` (`<env>` = `production` or `staging`; `$TENANTS_DIR/.lock` under an override) |
| Trust anchor | each tenant's `trusted_operators` **plus** that tenant's managed credential registry: an allow needs a trusted key **and** a registered, unrevoked binding |
| Managed credential registry | one SQLite Durable Object per tenant (`TENANT` binding, class `TenantRegistry`), reachable only through `POST /v1/credentials`, `GET /v1/credentials/{id}`, `POST /v1/credentials/{id}/revoke`, `POST /v1/credentials/{id}/repair-history` with the tenant's **admin** token. Persists the signed binding, operator key, credential id, status, and timestamps; never presentations, proofs, nonces, tokens, or IPs. Revoked records are kept forever |
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
- a missing (unset or empty) secret, invalid JSON, a repeated JSON key, or a
  serialized map of 4,096 bytes or more.

An empty **map** (`{}`) is NOT a defect: it is what removing the last tenant
leaves (see "Removing the last tenant" in section 3). It loads as zero tenants,
so every authenticated request is `401` and `/health` stays `200` with
`tenants: "ok"`, `tenant_count: 0`.

That is why the map is never edited by hand: `tenant.sh sync` rebuilds it from
the registry files and the keychain, runs it through
`pilot/tenants-check.mjs` — the same rules, proven against the Worker's own
loader by `test/tenants-check.spec.ts` — and refuses to push anything that
would fail. `wrangler secret put` is write-only (the live map cannot be read
back), so the keychain items plus the registry files **are** the authoritative
copy. Back the keychain up; lose it and the only recovery is re-keying every
tenant. Every command except `show` holds a per-environment lock
(`$HOME/.bolyra/tenants-<env>/.lock`) for its whole run, so two operators — or
two git worktrees — cannot interleave a quarantine and a sync; an interrupt
takes effect only after the in-flight put has finished.

### Initializing or migrating the registry

The registry is one directory per environment, **outside** any git checkout:
`$HOME/.bolyra/tenants-production` and `$HOME/.bolyra/tenants-staging`
(`TENANTS_DIR=<dir>` overrides it; the lock is always `<dir>/.lock`). It used
to live in the checkout (`pilot/tenants`, `pilot/tenants-<env>`), where a
removed worktree took the real records with it and two worktrees took two
different locks while writing the one Worker.

Nothing mutates a registry until it carries the `.initialized` marker: `add`,
`rotate`, `disable`, `enable`, `remove` and `sync` (dry runs included) refuse
with `registry <dir> is not initialized` and create nothing. `show` works
either way and says which. There are exactly two ways to initialize one:

```bash
cd integrations/hosted-verify

# A NEW environment (no records anywhere yet): writes the marker into an empty directory.
pilot/tenant.sh init
HOSTED_VERIFY_ENV=staging pilot/tenant.sh init

# EXISTING records (the legacy checkout location, or a backup): copies every <org_id>.json and
# <org_id>.policy.json into <registry>/.candidate/, validates the COMPLETE candidate (each
# status; both keychain tokens of every active/disabled record; the assembled map through the
# same validator as `sync --dry-run`), then renames each file into the registry and writes the
# marker LAST. --from must be an absolute path. The source is never modified.
pilot/tenant.sh migrate --from /absolute/path/to/old/tenants
pilot/tenant.sh show                      # confirm; THEN delete the source by hand
```

Both take the lock. Both refuse a registry that is already initialized, and
one that holds records or a `.candidate/` without the marker — `init` cannot
bless a partial migration and `migrate` never merges. A migrate whose
validation fails commits nothing (no records, no marker, the candidate
removed) and names the source file to fix.

**Interrupted migrate.** A Ctrl-C or TERM aimed at the tenant.sh shell during
the commit is deferred until the marker is written. A SIGKILL, a crash, or a
terminal Ctrl-C (which reaches the whole foreground process group, so it can
also kill the in-flight `mv`) can still stop a migrate between its first
rename and the marker. Every one of these leaves the same recoverable state:
records (and possibly a `.candidate/`) without a marker. Every command — `init` and `migrate`
included — then refuses with `has records but no marker: it looks like an
interrupted migrate`; there is no automatic repair. If the lock was retained,
remove it first as in "Recovering a retained lock" (no migrate can be
running). Then delete the partially migrated `*.json` files and `.candidate/`
from the NEW registry directory (never the source — it was not touched) and
re-run the same `migrate --from`.

**A legacy record whose keychain token is missing.** `migrate` refuses the
WHOLE candidate if any active or disabled record lacks either token, and
`rotate` cannot mint the missing one because the destination is not
initialized yet. The escape hatch: in the SOURCE directory, set that record's
`"status"` to `"removed"` by hand; migrate; then bring the tenant back with
the removed-tenant path in the new registry — `rotate <org_id> admin
--confirm` and `rotate <org_id> verifier --confirm` (for a removed tenant these
store the token and skip the sync), set `"status": "active"` in the migrated
record, and `sync`. The partner then needs both new tokens (schedule it: see
"2. Rotate a token").

**One-time move of the founder's existing records (do this BEFORE any other
provisioning mutation).** Until then the real production and staging records
are still in the founder's checkout, under `pilot/tenants` and
`pilot/tenants-staging`, and every mutating command refuses the new, empty
default location:

```bash
cd ~/Projects/bolyra/integrations/hosted-verify
pilot/tenant.sh migrate --from ~/Projects/bolyra/pilot/tenants
HOSTED_VERIFY_ENV=staging pilot/tenant.sh migrate --from ~/Projects/bolyra/pilot/tenants-staging
pilot/tenant.sh show && HOSTED_VERIFY_ENV=staging pilot/tenant.sh show
# every tenant listed with its status and both tokens "yes"; then delete the two old
# directories by hand. Do NOT `init` either environment instead: that would start an empty
# registry beside the real records, and the next sync would push a map without them.
```

### Recovering a retained lock

A retained per-environment lock means "outcome unknown"; TENANTS is
write-only and cannot be read back. There is no automatic unlock or
stale-lock removal.

Before removing the lock, ensure no tenant.sh or tenants-put.mjs invocation
remains running or can launch another uploader, and prevent concurrent
invocations throughout recovery. Run `pgrep -fl wrangler`, inspect any
matches, and confirm that no Wrangler uploader remains on this machine; if
you cannot establish local quiescence, leave the lock in place.

Once local quiescence is established, remove only the retained lock
directory for the affected environment — `$HOME/.bolyra/tenants-<env>/.lock`
(`<env>` = `production` or `staging`; `$TENANTS_DIR/.lock` under an override;
the refusal message prints the exact path) — then run `sync` for that same
environment to re-put the intended, validated map (add `--allow-empty` only
when the intended map is the deliberate empty one, every record removed). Removing the
lock does not cancel or roll back any request. Local process checks cannot
establish completion or ordering of an already-submitted request, and an
earlier request may take effect after the recovery sync. A SIGKILL before
stdin is delivered can leave an empty secret, causing verification to fail
closed until a successful re-sync restores the intended map.

If the retained lock came from `remove`, the tenant is half-removed: its
registry file says `status=removed` but both keychain tokens were kept,
because the old map (with the tenant in it) may still be live. Once the lock
is removed as above, finish it with `pilot/tenant.sh remove <org_id>` instead
of `sync`: it re-puts the map without the tenant and deletes the tokens only
when that upload is confirmed. To keep the tenant after all, set its
`"status"` back by hand and run `sync`; its tokens are still there.

After sync, check the affected Worker's `/health` endpoint and the expected
authenticated behaviour, including successful authentication for intended
active tenants and rejection for quarantined or removed tenants. A healthy
`/health` response alone does not verify the tenant configuration. Failed
behavioural checks mean recovery has not been verified; passing checks
establish behaviour at the time checked and do not prove that an earlier
submitted request cannot take effect later.

### Seeded fixture key

`tenant.sh add … --with-fixture-key` trusts the partner's
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
curl -s https://bolyra-hosted-verify.<account>.workers.dev/health | jq '{status, tenants, capability_map, registry, registry_enforced, receipts_enabled}'
# Alarm: .github/workflows/hosted-verify-health.yml probes /health every 15 minutes (best effort)
# and fails the run on any non-200 (a degraded Worker answers 503 `status: "degraded"`; the run
# prints a one-line diagnostic of the failing component) or unless status/tenants are "ok" and
# registry_enforced is true. GitHub sends
# scheduled-run failure notifications to the account that last edited the `cron` line in the
# workflow file (not whoever last touched the file); a manual dispatch notifies the dispatcher.
# That account needs "Actions: failed workflows only" (or all) email notifications enabled in its
# GitHub notification settings. Verify the scheduled route once at setup: set the repository
# variable HOSTED_VERIFY_HEALTH_URL to the production URL with `/nope` appended, wait for the next
# scheduled run (≤15 minutes) to fail, confirm the failure email arrived, restore the variable to
# the real `/health` URL, and confirm the following scheduled run passes. A manual dispatch
# (url=…/nope) tests the workflow logic but not the scheduled notification route. While a real
# failure is being fixed, the probe fails every 15 minutes (up to 96 runs a day); disable the
# workflow from the Actions tab during remediation if the noise matters. The probed URL is the
# HOSTED_VERIFY_HEALTH_URL repository variable. Cloudflare offers no per-Worker error-rate
# notification on this account (the only Workers type, "Workers Observability: Real-Time Issue",
# could not be enabled). A TENANTS defect (unset or invalid) or the Worker being down trips this
# probe. `/health` also probes the registry Durable Object (a status read under the 2 s verify
# deadline) and parses CAPABILITY_MAP, and answers 503 `status: "degraded"` (with `registry:
# "unavailable"|"timeout"` or `capability_map: "invalid"`) when either fails, so on a build that
# emits those fields a registry outage or a malformed CAPABILITY_MAP trips the probe too. While
# the registry is HEALTHY, the probe runs at most once per Worker isolate per 10 s (single-flight;
# a healthy result is cached for 10 s, so the registry signal may be up to 10 s stale), which
# bounds what a /health flood can put on the `__health__` object. While the registry is FAILING
# there is no such bound: a failed result is dropped as soon as it settles, so each /health call
# may probe again, and an RPC that hit the 2 s deadline stays outstanding until it settles.
# `registry_enforced` is a build marker, not a registry liveness check (`registry` is the liveness).
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
#    live OFF the checkout, in the registry directory (`pilot/tenant.sh show` prints it):
#      $HOME/.bolyra/tenants-production/<org_id>.json          (created by add; template <repo root>/pilot/partner-config.example.json)
#      $HOME/.bolyra/tenants-production/<org_id>.policy.json   (copy <repo root>/pilot/policy-config.example.json)

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
#    credential still allows (21 checks; exits non-zero on any miss):
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

A rotation is a partner-visible outage for that role unless it is scheduled.
There is **no overlap window**: the `TENANTS` schema holds exactly one token
per role, so the old token stops working the moment the sync lands, and every
request the partner sends under it is `401` until they have deployed the new
one. Overlapping old/new tokens are deliberately not supported (deferred).

1. Agree a switch-over time with the partner, and how they will receive the
   new token.
2. At that time, rotate — `rotate` refuses without `--confirm`, which records
   that step 1 happened:

```bash
cd integrations/hosted-verify
pilot/tenant.sh rotate <org_id> verifier --confirm     # or admin
# prints: warning: requests under the verifier token return 401 from the next sync until
# the partner deploys the new token — the sync is part of this command, so that is now.
# Send the new one over a secure channel (security find-generic-password … -w, as in 1.4),
# and confirm with the partner that their calls authenticate again.
```

A compromised token is the exception: rotate at once (`--confirm` still
required) and tell the partner afterwards — the 401s are the point.

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

# remove — drops the entry from the map (status=removed, then sync) and deletes both tokens
# from the keychain only AFTER wrangler has confirmed that upload. If no upload started (a
# keychain, assembler or validator refusal, or a Ctrl-C before the put began) the status is
# restored and the tokens are kept — nothing changed. If the outcome is unknown the lock,
# the tokens and status=removed all stay: the tokens are what re-syncs the old map if it
# is still live (see "Recovering a retained lock"). A token delete that fails after a
# confirmed upload is reported by account and exits non-zero; delete it by hand. If `show`
# says `removed` with both tokens present and there is no lock, nothing was uploaded (the run
# was stopped while it wrote the registry file): re-run `remove`, or set "status" back by hand.
# A refused or cancelled remove otherwise leaves the registry file byte-identical. The registry
# file stays (status=removed) and so does the tenant's Durable Object with its history;
# nothing about a removed tenant is served. To bring the same org_id back, `add` refuses
# because the file exists: run `rotate <org_id> admin --confirm` and `rotate <org_id> verifier --confirm`
# to re-mint both tokens first — for a removed tenant rotate stores the token and SKIPS
# the sync (the map would not change; it says so and exits 0), which also works when every
# tenant is removed — then set "status": "active" in the registry file by hand and run `sync`;
# the Durable Object resumes as it was — revoked credentials stay revoked:
pilot/tenant.sh remove <org_id>

# the LAST tenant (no other record is active or disabled — a quarantined tenant still
# occupies the map) is refused without --last: its removal pushes the EMPTY map {}, and
# every request is then denied (401). Everything above about confirmation, tokens and
# unknown outcomes applies unchanged:
pilot/tenant.sh remove <org_id> --last

# re-push the empty map on purpose (every record is removed; plain sync refuses it):
pilot/tenant.sh sync --allow-empty

# revoke ONE credential (not the tenant): the partner does this with their admin token,
# or you do it for them. Terminal — a revoked binding can never be re-registered:
# BASE and ADMIN as in step 1.5 (their base URL and admin token).
curl -s -o /dev/null -w '%{http_code}\n' -X POST $BASE/v1/credentials/<credential_id>/revoke \
  -H "Authorization: Bearer $ADMIN"                              # → 204 (204 again if already revoked)

# sanity after any change: the map parses, and how many tenants it holds (it does not list them):
curl -s $BASE/health | jq '{tenants, tenant_count}'            # → {"tenants":"ok","tenant_count":<n>}
```

### Recovering a revocation whose audit row failed

Symptom: a revoke answered `204` **with** `x-bolyra-audit: history_write_failed`,
or the request log (`npx wrangler tail --env=`) shows `code: "revoke_history_failed"`
on a `hosted-verify registry request` line. The credential **is revoked** — verify
already denies it `credential_not_active`, and a `GET` shows `"status": "REVOKED"`
with `"pending_history": true`. Only its `revoked` history row is missing; the
timestamp and request id it owes are stored with the credential.

```bash
# BASE and ADMIN as in step 1.5. Idempotent — safe to repeat:
curl -s -X POST $BASE/v1/credentials/<credential_id>/repair-history \
  -H "Authorization: Bearer $ADMIN"
# → 200 {"credential_id":…,"audit":"repaired"}  the row is written from the stored metadata
# → 200 {…,"audit":"clean"}                     nothing was owed
# → 409 {"error":"history_conflict",…}          see below
```

The two audit headers ask for different things:
- `x-bolyra-audit: history_write_failed` (code `revoke_history_failed`): the first
  write failed → retry the revoke or run `repair-history`.
- `x-bolyra-audit: history_conflict` (code `revoke_history_conflict`): a retry
  found rows that do not agree → a human looks at the rows; retrying will not help.

A retry of the same `revoke` also attempts the repair. It answers a plain `204`
once the repair succeeds. If the repair fails again, it answers the same `204` with
`x-bolyra-audit: history_write_failed`, never a `500`, and the metadata stays.
`repair-history` is an explicit admin action, so it reports that failure as a
`500`. `history_conflict` means a **different** `revoked` event is
already recorded for that credential (its `ts` or `request_id` does not match the
metadata), or the stored recovery metadata is itself incomplete (null ts / request
id): the log shows `stored: null`; fix the row by hand. The repair never overwrites
a stored event or clears the metadata: the Worker logs `hosted-verify history
conflict` with both values — compare them and decide by hand. The credential stays
revoked whatever you decide.

Notes:
- Secrets take effect on the next request; no redeploy.
- `sync` replaces the WHOLE map from the registry directory: a file you delete
  by hand is a tenant you revoked by accident — use `remove`.
- **Removing the last tenant** leaves the empty map `{}`. That is valid
  configuration, not a defect: every authenticated request is denied with `401`
  (no bearer resolves to a tenant) and `/health` answers `200` with
  `tenants: "ok"` and `tenant_count: 0`. Because it denies everyone, every
  step that can produce it asks for a deliberate flag: `remove <org_id>
  --last` (refused without it, before anything changes), `sync --allow-empty`
  (a plain `sync` over an all-removed registry refuses and uploads nothing),
  and `tenants-put.mjs --allow-empty` (the put stage refuses `{}` on its own
  without it). Active **and** disabled records count as tenants. A registry
  directory with **no** record files is refused whatever the flags say; that
  is a wrong `TENANTS_DIR` / `HOSTED_VERIFY_ENV` far more often than intent.
  A removal can also end with `--last` given for a tenant that turns out not
  to be the last one: that is noted and runs a plain sync (the map stays
  non-empty). Bring a tenant back with `add` (a new org) or, for a removed
  one, the path above: `rotate <org_id> admin --confirm` and `rotate <org_id> verifier --confirm`
  store fresh tokens and skip the sync (the tenant is removed, so the map would
  not change — this holds even when every tenant is removed), then set
  `"status": "active"` and run `sync`.
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
pilot's policy record (`$HOME/.bolyra/tenants-production/<org_id>.policy.json` →
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
| `internal_error` | 500 | Fail-closed: `TENANTS` unset or malformed, or `CAPABILITY_MAP` malformed (every tenant; an *unset* `CAPABILITY_MAP` is not a defect — it falls back to the messaging default and mpp capabilities then deny `unknown_capability`), a quarantined tenant, a registry RPC failure or its 2,000 ms deadline, a missing `TENANT` Durable Object binding (a deploy from an environment that did not redeclare it), or a bug | `npx wrangler tail --env=`; `/health` → `tenants`, `capability_map` and `registry` must all be `"ok"` (`registry: "unavailable"`/`"timeout"` = registry outage or missing `TENANT` binding); `tenant.sh sync --dry-run` validates the map; check the deploy came from `wrangler.jsonc` with the `TENANT` binding |
| *(409 `{"error":"credential_revoked"}`)* | 409 | Re-registering a revoked binding | Terminal by design; the partner must issue a new binding |
| *(413 `{"error":"payload_too_large"}`)* | 413 | The canonical binding is over 16,384 UTF-8 bytes (a body over 64 KiB is `400 malformed_input` instead) | They shorten the binding (long `agent_name`/`capabilities`) and re-sign it |
| *(429 `{"error":"quota_exceeded"}`)* | 429 | The tenant already holds 1,000 ACTIVE credentials (expired-but-unrevoked ones count) | Not time-based (no `Retry-After`): they revoke credentials they no longer use, then register again |
| *(409 `{"error":"history_conflict"}`)* | 409 | `repair-history` found a different `revoked` event already recorded for the credential, or its recovery metadata is itself incomplete (the log shows `stored: null`) | Needs a human look — see "Recovering a revocation whose audit row failed" in step 3. The credential is revoked either way |
| *(404 `{"error":"not_found"}`)* | 404 | Unknown credential id, a malformed id (not 64 lowercase hex), a wrong path, or **another tenant's** credential (never 403 — tenants cannot probe each other) | Routes: `GET /health`, `POST /v1/verify`, `POST /v1/credentials`, `GET /v1/credentials/{id}`, `POST /v1/credentials/{id}/revoke`, `POST /v1/credentials/{id}/repair-history`, `GET /.well-known/bolyra-signers.json` |

`/health` reports `tenants: "invalid"` → the map on the Worker is defective and
every tenant is down: `tenant.sh sync --dry-run` from the registry, fix what it
names, `tenant.sh sync`.

Live logs while a partner is testing:

```bash
cd integrations/hosted-verify && npx wrangler tail --env=            # --env=staging for staging
```

One structured line per authenticated decision and per authenticated registry
request: `request_id, cf_ray?, org_id, role, route, verdict, code, credential_id?,
latency_ms`. `request_id` is the server-generated UUID the caller sees as the
`x-bolyra-request-id` response header (search the tail for it); `cf_ray` is the
edge ray id, present only when well-formed. A registry write that fails with `registry storage failure` means
the tenant's Durable Object could not persist: check the Workers dashboard →
Durable Objects → storage and errors for `TenantRegistry`. A `registry storage
failure` is an outage, never the credential cap: the cap is the separate
`429 quota_exceeded` in the table above.

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
npm run deploy:staging                                        # deploys, then verifies it (see "Post-deploy verification"); note the Current Version ID
npx wrangler secret put RECEIPT_SIGNER_KEY --env staging      # a fresh 0x-hex secp256k1 key
HOSTED_VERIFY_ENV=staging pilot/tenant.sh add <org_id> <x:y> --with-fixture-key  # staging keychain + $HOME/.bolyra/tenants-staging/ (initialized or migrated first); the example below signs with the fixture key
curl -s https://bolyra-hosted-verify-staging.<account>.workers.dev/health | jq '{status, tenants, capability_map, registry, registry_enforced, receipts_enabled}'
# A secret put takes a few seconds to reach every isolate: /health can still say tenants "invalid" right after the put; re-check after ~10 s before reading anything into it.

# The gate for production: the example must pass against staging.
(cd ../../examples/managed-revocation && npm ci && \
  VERIFY_URL=https://bolyra-hosted-verify-staging.<account>.workers.dev \
  ADMIN_TOKEN="$(security find-generic-password -s bolyra-hosted-verify-staging -a tenant-<org_id>-admin -w)" \
  VERIFIER_TOKEN="$(security find-generic-password -s bolyra-hosted-verify-staging -a tenant-<org_id>-verifier -w)" \
  npm run demo)                                               # → 21/21 checks passed
# Record the run (date, commit, version id, "21/21") in the table below.

# ── Production: the first managed cutover ───────────────────────────────────
# Zero consumers are on record, so a maintenance window is a courtesy, not a risk.
# 1. Deploy the build (100%, one step). The moment it lands, the Worker requires a
#    REGISTERED binding for every allow — legacy tokens and unregistered bindings stop.
npm run deploy:prod                                           # deploys, then verifies it (auth boundary; the canary leg once
                                                              # bolyra-canary exists); note the Current Version ID
# 2. Retire the legacy secrets if they are still set (they are read by nothing):
npx wrangler secret list --env=
npx wrangler secret delete PREVIEW_TOKEN --env=; npx wrangler secret delete PARTNER_TOKENS --env=
# 3. Provision: RECEIPT_SIGNER_KEY (if not yet), then every tenant through tenant.sh
#    (step 1), then REGISTER each binding a tenant expects to verify (step 1.5/1.6).
# 4. Hand out verifier + admin tokens and the capability vocabulary (step 1.4).
# 5. Record the version id below as the ROLLBACK FLOOR.
# 6. Post-cutover: harden the /health alarm. After the FIRST production deploy whose /health
#    answers `registry: "ok"` and carries `capability_map` (check with the step 0 curl), edit
#    .github/workflows/hosted-verify-health.yml: replace the two TEMPORARY soft clauses
#        (if (.[0] | has("registry_kind")) then .[0].registry == "ok" else true end)
#        ((.[0].capability_map // "ok") == "ok")
#    with the strict
#        .[0].registry == "ok" and .[0].capability_map == "ok"
#    (and the matching registry_ok / capability_map_ok diagnostic lines), and drop
#    "durable-object" from the `registry` enum in diag(). Open it as its own PR.
```

### Post-deploy verification

`npm run deploy:staging` and `npm run deploy:prod` pipe `wrangler deploy` through
`tee` into `scripts/verify-deploy.mjs --from-wrangler`, so every deploy is checked
against the version it just produced. The script reads `Current Version ID: <uuid>`
from wrangler's output and fails when it is absent. npm runs scripts without
`pipefail`, so this check is what turns a failed `wrangler deploy` into a failed
command. Run it by hand against any target:

```bash
cd integrations/hosted-verify
node scripts/verify-deploy.mjs https://bolyra-hosted-verify-staging.kondojuviswanadha.workers.dev \
  --version <id> --env staging --tenant bolyra-staging
```

**What it proves.**
- *Auth boundary (always).* `GET /health` answers 200 with `status`, `registry`,
  `capability_map` and `tenants` all `"ok"`, `registry_enforced: true`, and
  `version.id` equal to the deployed id. `POST /v1/verify` with no token and with a
  well-formed bogus token both answer 401. `GET /v1/credentials/<64 zeros>` with no
  token answers 401.
- *Enforcement (with `--tenant <org>`).* A fresh canary binding (agent
  `verify-deploy-<8 hex>`, signed by the tenant's canary operator key) goes through
  the full registry lifecycle, all on one credential id. The script derives that id
  locally (`scripts/lib/credential-id.mjs`) before sending anything:
  1. presented unregistered: deny `credential_not_active` (ABSENT)
  2. registered: 201
  3. presented: allow, with `x-bolyra-credential-id` set to the id (ACTIVE)
  4. revoked: 204
  5. presented: deny `credential_not_active` (REVOKED)

  A 204 carrying `x-bolyra-audit: history_write_failed` is reported but does not
  fail the check; run `repair-history` for that id (step 3). Output is limited to
  status codes, verdict codes, 64-hex ids and the version id. Response bodies and
  tokens are never printed.

**Keychain accounts** (service `bolyra-hosted-verify`, or `bolyra-hosted-verify-staging`
with `--env staging`):

| Account | Holds | Created by |
|---|---|---|
| `tenant-<org>-admin` | the tenant's admin token | `tenant.sh add` |
| `tenant-<org>-verifier` | the tenant's verifier token | `tenant.sh add` |
| `operator-<org>-scalar` | the canary operator's EdDSA private scalar, decimal or `0x`-hex; its public key must be in the tenant's `trusted_operators` | by hand, once (below) |

Create these items with `security` (as `tenant.sh` and the command below do). A
generic-password item created another way, such as in Keychain Access, can raise a GUI
access prompt when `security` reads it. That prompt stalls the chained deploy until
someone answers it.

```bash
# Create the scalar entry (prompts for the value; nothing lands in shell history):
security add-generic-password -s bolyra-hosted-verify-staging -a operator-bolyra-staging-scalar -w
```

`bolyra-staging` trusts the fixture key (`--with-fixture-key`), so its scalar is the
repo's documented test scalar `42`. Production's `bolyra-canary` gets its own key:
generate a scalar, add its public key when running `tenant.sh add bolyra-canary <x:y>`,
store the scalar as `operator-bolyra-canary-scalar`, then delete
`--allow-missing-tenant` from `deploy:prod` in `package.json`. Until then production
is verified only up to the auth boundary, and the output says so: `enforcement NOT
verified on this target (tenant bolyra-canary has no keychain entries)`. Without
`--allow-missing-tenant`, a missing account fails the run and the message names it.

**The pending directory.** Before the registration request, the script creates
`~/.bolyra/canary-pending-<env>/<credential_id>.pending` (override the directory with
`--pending-dir`). The file holds one line, `<iso-time> <env> <org> <credential_id>
pending`. There is one file per canary, created atomically and never rewritten, so
concurrent runs cannot lose each other's records. After any registration attempt,
including a timeout or a lost response, the script revokes the id again in cleanup:

| Cleanup revoke | Registration was | Result | Record |
|---|---|---|---|
| 204 | anything | `cleaned` | removed |
| 404 | a parsed 4xx (never committed) | `nothing_committed` | removed |
| 404 | timed out / lost / 5xx / unparseable | `unconfirmed`: it may still commit | **kept**; exit non-zero |
| anything else, or a network error | anything | `unconfirmed` | **kept**; exit non-zero |

`CANARY CLEANUP UNCONFIRMED credential_id=<id>` on stderr means a record was kept.
To resolve the kept records, `ls ~/.bolyra/canary-pending-<env>/` and handle each id
with that tenant's admin token:

- **Revoke it** (step 3's revoke). A `204` confirms it is revoked, so delete its
  `.pending` file.
- A `404` on the revoke is harmless: nothing is registered under that id right now.
  It does **not** prove the registration will never commit, because a timed-out
  registration can still land later, and elapsed time proves nothing. So keep the
  file and revoke again later.
- Delete the file without a `204` only when `GET /v1/credentials/{id}` (admin token)
  returns `404` **and** you know from another source that the registration request
  was never sent or never committed. For example, the run's output shows the
  registration step failed before sending, or it got a parsed `4xx`. Record that
  reason when you delete it.

Otherwise, keep revoking until you get a `204`.

**Growth.** Each successful enforcement run leaves one REVOKED row and its history
in the canary tenant's registry object (revocation is terminal and rows are never
deleted). Rotate the canary org id (`tenant.sh add bolyra-canary-2 …`, then update
`deploy:prod`/`deploy:staging`) once it holds more than ~1000 revoked rows.

**Right after a deploy.** A new version can take a few seconds to reach every
isolate. When a version id is expected (`--version` or `--from-wrangler`), the script
first polls `/health` every 5 s, up to 12 times (about 60 s once the host answers; each
poll gives up after 5 s, so a host that never answers costs about 2 min), until
`version.id` matches. Each miss prints `--  waiting for version <id> (n/12)`. If the version never
appears, the run fails on the `/health version.id` mismatch, and no canary is written.
During propagation, `/health` and `/v1/verify` can be served by different isolates.
A match therefore means at least one isolate reports the new version, not that every
isolate runs it.

**Locally.** `npm run verify:dev` boots the Worker under `wrangler dev`
(`scripts/with-worker.sh`) and runs both legs against it. The enforcement leg uses the
placeholder tenant `local`, its tokens from `.dev.vars.example`, and scalar `42`.
`--secrets-from-dev-vars` is accepted only with `--env local` and a loopback URL. CI
runs the same command. Extra arguments pass through after `--`, for example
`npm run verify:dev -- --pending-dir /tmp/pending`. The URL defaults to `$VERIFY_URL`,
which `with-worker.sh` exports. To pass it yourself, quote it inside `sh -c` so that
the wrapper's value is used, not your shell's:

```bash
bash scripts/with-worker.sh sh -c 'node scripts/verify-deploy.mjs "$VERIFY_URL" --env local --tenant local --allow-missing-tenant'
```

`--from-wrangler` refuses to run when stdin is a terminal: pipe a deploy into it.

**Rollback floor.** The first version that reports `registry_enforced: true`
on `/health` is the floor. Never deploy a build below it, and never deploy a
build that verifies without the registry: a deployment that allows unregistered
bindings while tenants hold registrations is a storage-incident-class event.
If a rollback below the floor is ever unavoidable: quarantine every tenant
first (`tenant.sh disable …` for each), deploy, and treat every registration
as unverified until the floor is restored.

**Rolling back to the floor across the schema_meta change.** The floor build
(`4a4e83fc`, commit e7cb720) pre-dates `schema_meta` and ignores it. It runs
safely on a v2 database: every statement it issues names its columns, and the
added `pending_history` column defaults to 0. It cannot see or repair a
revocation whose audit row is still owed (`pending_history = 1`): it answers
such a revoke `204` with no header. That metadata is left untouched. Before
rolling back, list the credential ids that logged `revoke_history_failed` (or
`revoke_history_conflict`). After restoring this build or a newer one, run
`repair-history` for each (step 3). Once this build is deployed, its version id
becomes the new floor (recorded at the OPS step, in the table below).

| Environment | Version id | Deployed (UTC) | Commit | Example run |
|---|---|---|---|---|
| staging | 1c4eaa83-2b5f-4c98-9f41-9f4e980bcf32 | 2026-09-21 | e7cb720 | 20/20 (2026-09-21, tenant bolyra-staging, fixture key) |
| production | **4a4e83fc-6e53-4287-8f92-c5d03a6fbc6f — the rollback floor** | 2026-09-21 | e7cb720 | 20/20 (2026-09-21, tenant bolyra-smoke, fixture key; quarantined afterwards) |

## Out of scope — waits for a real pilot

Deliberately not built until a paying pilot shapes the need: dashboard,
billing/metering, self-serve signup, policy-builder UI, compliance portal,
tenant self-service, SSO/RBAC, SIEM export beyond JSONL, self-host installer,
SLA/status page, hosted ZK flows.
If a pilot task seems to need one of these, the answer is a manual step in
this runbook, not new product surface.
