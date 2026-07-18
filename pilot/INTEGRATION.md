# Pilot Integration Guide (for the partner's engineer)

You are integrating a verifier for Bolyra's [External Verifier Contract
v1](../spec/external-verifier-contract-v1.md): your host sends one JSON
request describing an agent's presentation + the action it wants, and gets
back exactly one verdict object — `allow` or `deny` with a stable reason
code. Every decision can carry an independently verifiable signed receipt.

Two ways to run the verifier. They speak the same request/verdict contract,
so you can start hosted and move local without changing your host code's
decision handling.

| | A. Hosted `POST /v1/verify` | B. Local `bolyra verify` CLI |
|---|---|---|
| Setup | none (curl in 5 minutes) | `npm i -g @bolyra/cli` + circuit artifacts |
| Verifier class | `classical` — **no ZK proof verification** | `zk` — full Groth16 + vkey pinning |
| Trust anchor | operator key set pinned in the deployment | proof + trusted roots + vkey pin |
| Replay | host nonce mode (you reserve nonces) | local or host mode |
| Status | **design-partner preview** — no SLA, may be reset | your infrastructure, your uptime |

## A. Hosted endpoint

> **Preview honesty (read once, it's load-bearing):** the hosted endpoint is a
> **DESIGN PARTNER PREVIEW** and a **classical** verifier — it does **not**
> verify zero-knowledge proofs, so public signals in the bundle are
> self-asserted. An `allow` means exactly this: a **trusted operator key**
> (pinned server-side) signed a binding authorizing this exact
> `{agent_name, project_key, program, model, capabilities, expiry}`, the
> request matches that signed binding, and the granted capabilities are a
> subset of it. Scope-bitmask checks are consistency-only; expiry IS
> signature-bound (binding v2). `GET /health` discloses the live
> `checks_authenticated` / `checks_consistency_only` / `checks_not_performed`
> lists — machine-readable, no auth. Sound scope enforcement and ZK-class
> guarantees are Option B.

You'll receive from us: the base URL, a bearer token labeled with your
partner name (usage is attributed to the label — we never log request
bodies, proofs, credentials, tokens, or IPs; counts and latency only), and
confirmation that **your operator public key is pinned**. Until your key is
pinned, only the repo's fixture examples will verify.

### Curl test

```bash
BASE=https://bolyra-hosted-verify.<account>.workers.dev
TOKEN=<your token>

# 1. Health + capability disclosure (no auth):
curl -s $BASE/health | jq

# 2. Known-good presentation (fixture) → allow:
curl -s -X POST $BASE/v1/verify \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  --data @integrations/hosted-verify/examples/request.allow.json | jq

# 3. Insufficient scope (fixture) → deny scope_exceeded:
curl -s -X POST $BASE/v1/verify \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  --data @integrations/hosted-verify/examples/request.deny-scope.json | jq
```

(The two fixture files live in the repo at
`integrations/hosted-verify/examples/` — we can send them directly if you're
not working from a checkout.)

### Handling responses — the rules that matter

1. **Branch on `verdict`, never on HTTP status.** `200` means "a decision was
   produced" — that includes every policy/crypto `deny`. The `code` field is
   the stable reason vocabulary (spec §9).
2. **Fail closed.** Malformed JSON, oversized bodies (>1 MiB), wrong
   versions, undecodable bundles — all explicit `deny`s, never a silent
   allow. `500` + `code=internal_error` means the verifier could not produce
   a trustworthy verdict: treat as deny.
3. **Reserve nonces before acting.** The Worker is stateless (host nonce
   mode): an `allow` carries `consume_nonces`, and you **must** record every
   entry in your own durable storage before performing the action. If an
   entry was already recorded → treat as replay and reject, even though the
   verdict said `allow`. (Classical caveat: this stops replay of the
   identical bundle; sound one-time nullifier enforcement is Option B.)
4. **Transport errors are not verdicts.** `401` (bad/missing token), `404`,
   `405` return `{ "error": … }`, not a verdict object.

### Failure modes (what you'll actually see)

| Symptom | Meaning | Fix |
|---|---|---|
| `401 {"error":…}` | token missing/wrong | check the `Authorization: Bearer` header and the token we sent |
| `deny invalid_signature` | binding not signed by a pinned operator key | most common during onboarding: your operator key isn't pinned yet, or you signed with a different key — ping us |
| `deny request_mismatch` | request fields ≠ the signed binding | `agent_name`/`project_key`/`program`/`model` must match byte-for-byte |
| `deny scope_exceeded` | capability needs bits your credential lacks | working as intended (tier cap), or re-issue the credential |
| `deny expired` | `now_unix >= expiry` (equality = expired) | check the `now_unix` you send; re-issue if actually expired |
| `deny unknown_capability` | capability has no mapping | unmapped is never silently allowed — ask us to map it |
| `500 deny internal_error` | verifier-side failure | fail closed on your side; tell us, we check logs |

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
object on stdout; exit codes follow spec §7. We'll pair on flags/artifacts
during integration week — this is the recommended endpoint by pilot end.

## Verifying your receipts (your independent audit trail)

Every hosted response (allow **and** deny) can carry an `X-Bolyra-Receipt`
header: a base64url-encoded ES256K-signed receipt over the decision. Verify
one receipt yourself, offline:

```bash
# decode the header value, then:
bolyra receipt verify receipt.json --signer <signer-address-we-give-you>
```

Capture the raw header values (one per line in a file) — they're your
evidence, independent of us.

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
(`cf-ray` header) for hosted issues; we can see per-request outcome codes
and latency (never your payloads).
