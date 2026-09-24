# Pilot Integration Guide (for the partner's engineer)

You are integrating a verifier for Bolyra's [External Verifier Contract
v1](../spec/external-verifier-contract-v1.md): your host sends one JSON
request describing an agent's presentation + the action it wants, and gets
back exactly one verdict object — `allow` or `deny` with a stable reason
code. Every decision can carry an independently verifiable signed receipt.

The hosted option is an experimental service for registering operator-signed
agent authorizations and revoking them on an integrated action path.

Two ways to run the verifier. They speak the same request/verdict contract,
so you can start hosted and move local without changing your host code's
decision handling.

| | A. Hosted `POST /v1/verify` | B. Local `bolyra verify` CLI |
|---|---|---|
| Setup | none (curl in 5 minutes) | `npm i -g @bolyra/cli` + circuit artifacts |
| Verifier class | `classical` — **no ZK proof verification** | `zk` — full Groth16 + vkey pinning |
| Trust anchor | your tenant's pinned operator keys **plus** your tenant's credential registry | proof + trusted roots + vkey pin |
| Revocation | register a signed binding, revoke it later; the next presentation denies | none (re-issue with a shorter expiry) |
| Replay | host nonce mode (you reserve nonces) | local or host mode |
| Status | **design-partner preview** — no SLA, may be reset | your infrastructure, your uptime |

## A. Hosted endpoint

> **Preview honesty (read once, it's load-bearing):** the hosted endpoint is a
> **DESIGN PARTNER PREVIEW** and a **classical** verifier — it does **not**
> verify zero-knowledge proofs, so public signals in the bundle are
> self-asserted. An `allow` means exactly this: a **trusted operator key**
> (pinned for your tenant) signed a binding authorizing this exact
> `{agent_name, project_key, program, model, capabilities, expiry}`, the
> request matches that signed binding, the granted capabilities are a subset
> of it, **and that signed binding is ACTIVE in your tenant's credential
> registry** — registered with your admin token and not revoked. Scope-bitmask
> checks are consistency-only; expiry IS signature-bound (binding v2).
> `GET /health` discloses the live `checks_authenticated` /
> `checks_consistency_only` / `checks_not_performed` lists — machine-readable,
> no auth. Sound scope enforcement and ZK-class guarantees are Option B.
>
> Verifier tokens belong to trusted enforcement hosts. Expiry is evaluated
> against host-supplied time; this endpoint does not establish that the
> supplied time is current wall-clock time. Classical verification
> authenticates the signed authorization, not possession of an agent identity
> secret. Replay reservations are host-owned; the default MPP nonce store does
> not survive restarts or coordinate multiple instances. Revocation covers
> registered credentials on this path — it does not stop an agent everywhere,
> cancel in-flight actions, or undo completed ones. The deployment may be
> reset; a reset clears the registry, and every binding must be registered
> again.

You'll receive from us: the base URL; **two** bearer tokens — a *verifier*
token for `POST /v1/verify` and an *admin* token for the registry routes —
labelled with your org id (usage analytics record only `<org_id>:<role>`,
counts and latency — never request bodies, proofs, credentials, tokens, or
IPs; our per-request server log additionally records the request id, and the
credential id on any request that names or creates one); confirmation that
**your operator public key is pinned** for your tenant; and the capability
vocabulary the deployment carries (`mpp:financial:small|medium|unlimited`
plus the messaging default). Until your key is pinned, only bindings signed
by the repo's fixture key (if we seeded it for your tenant) can be registered
— and nothing verifies until it is registered.

## Try managed revocation in ten minutes

**Step 0 — the ask.** Send your operator's BabyJubjub **public key**,
corresponding to the private key you use with `bolyra mandate issue` or the
SDK, to hello@bolyra.ai as an `x:y` decimal pair. With the Bolyra CLI
installed, `bolyra key generate --out operator.key` creates the private key
and writes decimal-string `x`/`y` coordinates to `operator.key.pub`; send
only the `.pub` contents and retain the private key locally. We reply same
day, over a secure channel, with the base URL and two bearer tokens — admin,
verifier. The ten minutes start once you have those.

### 1. Run the example

```bash
git clone https://github.com/bolyra/bolyra
cd bolyra/examples/managed-revocation && npm ci
VERIFY_URL='<base URL>' ADMIN_TOKEN='<admin token>' VERIFIER_TOKEN='<verifier token>' npm run demo
```

Node 22+. Your pilot is configured for the example's signing key, MPP
capabilities, and receipt checks; expect `21/21 checks passed`.

**Read once — load-bearing.** The example signs its bindings with the
repository's conformance fixture key, whose private half is public. To make
it pass, we seed that key into your trial tenant alongside your own (that's
what `--with-fixture-key` means on our side). An allow from a fixture-signed
binding proves transport, your tokens, and the registry — not who signed.
Ask us to remove the fixture key from your tenant before anything real runs
on it.

### 2. Register a binding signed by your own key

```bash
bolyra mandate issue \
  --operator-key '/absolute/path/to/operator.key' \
  --agent '<agent-name>' --audience '<project-key>' --model '<model>' \
  --tier small --expiry 30d --encoding json --out mandate.json
```

Replace the placeholders with your values and use the private key
corresponding to the public key you sent. From `mandate.json`, create the
registration body with `version: 1`, `binding` from `.binding`, `signature`
from `.sig`, and `operator_pubkey` from `.agent.credential.operator_pubkey`.
Create a separate verification request with `version: 1`, the presentation
serialized as the `bundle` string, matching request identity fields,
`granted_capabilities: ["mpp:financial:small"]`, and current Unix seconds in
`now_unix`. Substitute these files in curl steps 2 and 3, and use step 2's
returned ID in step 5; capture response headers separately to inspect
`x-bolyra-credential-id`.

Expect: step 2 → `201` + `credential_id`; step 3 → allow with
`x-bolyra-credential-id`; step 5 revoke → `204`, verify again → `deny
untrusted_root`/`credential_not_active`; re-register → `409
credential_revoked`.

When it works, there's nothing to send us. From here: the rest of this
guide, or `bolyra verify` for the zk-class path.

### Curl test

```bash
BASE=https://bolyra-hosted-verify.<account>.workers.dev
ADMIN=<your admin token>; TOKEN=<your verifier token>

# 1. Health + capability disclosure (no auth):
curl -s $BASE/health | jq

# 2. Register the fixture binding (admin token; 201, then 200 with the same id on repeat):
curl -s -X POST $BASE/v1/credentials \
  -H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json" \
  --data @integrations/hosted-verify/examples/registration.allow.json | jq

# 3. Known-good presentation of that binding (verifier token) → allow:
curl -s -X POST $BASE/v1/verify \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  --data @integrations/hosted-verify/examples/request.allow.json | jq

# 4. Insufficient scope (fixture) → deny scope_exceeded:
curl -s -X POST $BASE/v1/verify \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  --data @integrations/hosted-verify/examples/request.deny-scope.json | jq

# 5. Revoke it (admin token; 204, idempotent) — step 3 now answers
#    deny untrusted_root with detail.reason "credential_not_active":
curl -s -o /dev/null -w '%{http_code}\n' -X POST $BASE/v1/credentials/<credential_id from step 2>/revoke \
  -H "Authorization: Bearer $ADMIN"
```

(The three example files live in the repo at
`integrations/hosted-verify/examples/` — we can send them directly if you're
not working from a checkout.) The runnable end-to-end version of this flow,
through the published `@bolyra/mpp` payment gate, is
[`examples/managed-revocation`](../examples/managed-revocation/README.md);
the operator trial (`examples/operator-trial`) verifies locally and is not
revocation evidence.

### Registering your own bindings

Your operator issues a binding (for spend mandates, `bolyra mandate issue`;
for anything else, the SDK's signed request binding). Registration is the
signed binding lifted out of a presentation: `{ "version": 1, "binding": {…},
"signature": { "R8": { "x", "y" }, "S" }, "operator_pubkey": { "x", "y" } }`,
decimal digit strings only, at most 64 KiB, posted with the admin token. The
response's `credential_id` (64 hex) is a pure function of your operator key
and the signed binding: every presentation of that binding maps to it, so
revoking the id denies all of them, including presentations minted after the
revocation. Revocation is terminal — re-registering a revoked binding is
`409 credential_revoked`; issue a new binding instead.

### Handling responses — the rules that matter

1. **Branch on `verdict`, never on HTTP status.** `200` means "a decision was
   produced" — that includes every policy/crypto `deny`. The `code` field is
   the stable reason vocabulary (spec §9).
2. **Fail closed.** Malformed JSON, oversized bodies (>1 MiB), wrong
   versions, undecodable bundles — all explicit `deny`s, never a silent
   allow. `500` + `code=internal_error` means the verifier could not produce
   a trustworthy verdict (including a registry outage or its 2,000 ms
   deadline): treat as deny.
3. **Reserve nonces before acting.** The verify path is stateless with respect
   to replay (host nonce mode): an `allow` carries `consume_nonces`, and you
   **must** record every entry in your own durable storage before performing
   the action. If an entry was already recorded → treat as replay and reject,
   even though the verdict said `allow`. `@bolyra/mpp`'s gate does exactly
   this. (Classical caveat: this stops replay of the identical bundle; sound
   one-time nullifier enforcement is Option B.)
4. **Transport errors are not verdicts.** `401` (bad/missing token), `403`
   (right tenant, wrong token role), `404`, `405`, and `503`
   (`tenant_disabled` — your tenant is quarantined) return `{ "error": … }`,
   not a verdict object.
5. **The `x-bolyra-credential-id` header on an allow is correlation, not
   evidence.** It is the registered credential id, unsigned, outside the
   receipt; use it to join your logs to ours, never as an authorization input.

### Failure modes (what you'll actually see)

| Symptom | Meaning | Fix |
|---|---|---|
| `401 {"error":…}` | token missing/wrong | check the `Authorization: Bearer` header and which of the two tokens you used |
| `403 {"error":"forbidden"}` | wrong role: admin token on `/v1/verify`, or verifier token on `/v1/credentials…` | swap tokens |
| `deny untrusted_root` with `detail.reason: "credential_not_active"` | the binding is not registered, or it was revoked | register it with the admin token; if revoked, that is the intent |
| `deny untrusted_root` with `detail.operator_key` | the operator key that signed the binding is not pinned for your tenant | most common during onboarding — ping us with the key's `x:y` |
| `deny invalid_signature` | the signature does not verify against a pinned key | you signed with a different key than the one you sent us, or the bundle is corrupt |
| `deny request_mismatch` | request fields ≠ the signed binding | `agent_name`/`project_key`/`program`/`model` must match byte-for-byte |
| `deny scope_exceeded` | capability needs bits your credential lacks | working as intended (tier cap), or re-issue the credential |
| `deny expired` | `now_unix >= expiry` (equality = expired) | check the `now_unix` you send; re-issue if actually expired |
| `deny unknown_capability` | capability has no mapping | unmapped is never silently allowed — ask us to map it |
| `409 {"error":"credential_revoked"}` | re-registering a revoked binding | terminal; issue a new binding |
| `413 {"error":"payload_too_large"}` on `POST /v1/credentials` | the canonical binding is over 16,384 UTF-8 bytes | shorten the binding and re-sign it |
| `429 {"error":"quota_exceeded"}` on `POST /v1/credentials` | your tenant already holds 1,000 ACTIVE credentials (expired-but-unrevoked ones count) | revoke credentials you no longer use, then register again; waiting does not help |
| `404 {"error":"not_found"}` on `/v1/credentials/{id}` | unknown or malformed id — or an id that belongs to another tenant (never 403) | check the id you stored from registration |
| `500 deny internal_error` | verifier-side failure (configuration, registry, or a quarantined tenant) | fail closed on your side; tell us, we check logs |

Full code registry: spec §9 (`../spec/external-verifier-contract-v1.md`).

## B. Local CLI (`bolyra verify`)

The zk-class verifier: full Groth16 proof verification, vkey pinning,
trusted-root checks, local replay state. Same stdin request / stdout verdict
contract (spec §2/§3), so your decision handling is unchanged:

```bash
npm i -g @bolyra/cli
bolyra verify --help        # trusted roots, capability map, nonce mode flags
cat request.json | bolyra verify [flags]   # → one verdict JSON on stdout
```

Spawn it per decision (or keep a worker pool) and parse the single JSON
object on stdout; exit codes follow spec §7. There is no registry on this
path: revocation is a shorter expiry and a re-issue. We'll pair on
flags/artifacts during integration week.

## Verifying your receipts (your independent audit trail)

Every `/v1/verify` response (allow **and** deny) carries an `X-Bolyra-Receipt`
header when receipts are on: a base64url-encoded ES256K-signed receipt over
the decision. Verify one receipt yourself, offline, against the signer set we
publish:

```bash
# decode the header value (base64url → JSON) into receipt.json, then:
bolyra receipt verify receipt.json --signer-from $BASE/.well-known/bolyra-signers.json
```

Capture the raw header values (one per line in a file) — they're your
evidence, independent of us. Receipts attest to decisions, not to execution
or to complete audit coverage.

During the pilot we'll send you consolidated **JSONL audit exports** (one
signed receipt per line; enforcement-point receipts are hash-chained).
Verify the whole log — every signature plus chain integrity (edits,
deletions, reordering, head truncation):

```bash
bolyra receipt verify-chain export.jsonl --signer <addr> \
  --expect-count <N> --expect-head <hash>
```

We give you `<N>` and `<hash>` out-of-band with each export; pinning them is
what makes tail truncation detectable. If the log predates chaining or
contains hosted (unchained) receipts, the command we send includes
`--allow-unchained` — signatures are still verified per receipt.

## Questions / stuck

Viswa Kondoju — kondojuviswanadha@gmail.com. Include the request id
(the `x-bolyra-request-id` response header) for hosted issues; we can see per-request outcome codes
and latency (never your payloads).
