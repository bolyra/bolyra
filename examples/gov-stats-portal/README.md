# gov-stats-portal — a mock relying party that verifies Bolyra proofs

A mock "government statistics portal" asks the published `bolyra verify` one question per request:
**did an operator-signed binding authorize THIS agent, for THIS capability, at THIS audience?**
Public data is served only after an `allow`. Everything runs on loopback.

## Disclosure (read this before the results)

- The verifier is the published `@bolyra/cli@0.9.0` (`bolyra verify`), doing **real Groth16
  verification** against the fixture trusted roots copied from the repository.
- The Groth16 proof is the repository test vector
  `integrations/cli/test/fixtures/verify/allow-agent-only`, reused **unchanged**.
- The operator-signed bindings are **re-signed with the publicly known test private key `42n`**,
  the same technique the CLI's own e2e fixtures use (`deny-mutations.ts`). Anyone can reproduce
  these signatures. The golden proof attests the public key of `42n`, which is why the re-signed
  binding still verifies.
- Therefore this demonstrates **enforcement by a relying party** (what the published verifier does
  with a request), **not** genuine operator identity and **not** production issuance.
- Proof-bound and unchangeable without re-proving: `model` (`opus-4.1`), `expiry` (4102444800),
  and the credential bitmask `3` (READ_DATA|WRITE_DATA). Changed by re-signing only: `agent_name`,
  `project_key`, `program`, `capabilities`.
- The "domains" (`https://stats.example.gov`, `https://internal.example.gov`) are configured
  audience strings on two loopback servers. No DNS, no TLS, no real hosts. The data is invented.
- No claim is made about any real incident.

## Run

```bash
npm ci
npm run demo     # two portal processes, six scenes, exits 1 on any deviation
npm test         # unit + integration tests (spawns portals and the published verifier)
```

## Decision origin

Every response carries `origin`:

| origin | meaning |
|---|---|
| `cli` | a verdict returned by the published verifier (including a CLI-emitted `internal_error`, which the runner passes through) |
| `runner` | `@bolyra/mpp`'s `runCommandVerifier` synthesized a fail-closed `internal_error` on a transport/process/output failure (timeout, oversize, signal, unparseable output, non-zero exit without a verdict) |
| `portal` | decided here without consulting the verifier: `401 missing_authorization`, `404`, `405`, and `500` for an allow carrying host-nonce obligations this example does not honor |

The runner exposes no provenance, so `runner` is recognised by its closed set of synthesized
messages; a verifier that emitted one of those exact strings would be labelled `runner`.

## The six scenes

P1 = binding `capabilities: ["read:public-stats"]`. P2 = binding
`["read:public-stats", "read:internal-files"]`. Both name `agent_name stats-research-agent`,
`project_key https://stats.example.gov`, `program demo`. The portal's route policy is
`/public/stats → read:public-stats`, `/internal/files → read:internal-files`, and its capability
map is `capability-map.json` (`read:public-stats → READ_DATA`, `read:internal-files →
READ_DATA, ACCESS_PII`). "allow" below is a verdict (presentation shorthand), not a code.

| # | Portal · path · presentation | Decider | Result | origin |
|---|---|---|---|---|
| 1 | A `/public/stats` · P1 | `read:public-stats → READ_DATA` ⊆ proven bitmask 3; fresh nullifier burned | 200, allow | cli |
| 2 | A `/internal/files` · P1 | **binding-capability rejection**: the signed binding does not cover `read:internal-files` | 403 `request_mismatch` `{field: granted_capabilities, capability}` | cli |
| 3 | B `/public/stats` · P1 | **literal audience rejection**: portal B put its own audience in `request.project_key`; compared byte-for-byte to the signed binding | 403 `request_mismatch` `{field: project_key, request, binding}` | cli |
| 4 | A `/public/stats` · P1 again | nullifier burned by scene 1 in A's local store | 403 `nonce_replayed` | cli |
| 5 | A `/public/stats` · no header | portal-local | 401 `missing_authorization` | portal |
| 6 | A `/internal/files` · P2 | **subset check against the proof-anchored bitmask**: the operator signed a binding naming `read:internal-files`, but the proven bitmask `3` lacks `ACCESS_PII` (bit 7) | 403 `scope_exceeded` `{required_scope: 129, effective_scope: 3, excess_bits: 128}` | cli |

Verifier messages, verbatim: scene 2 `granted capability "read:internal-files" is not covered by
the signed binding`; scene 3 `request project_key does not match the signed binding`; scene 4
`agent nullifier replayed`; scene 6 `required scope exceeds the credential effective scope`.

What the proof does and does not say: the golden proof's `requiredScopeMask` is `0`; it attests
the credential (operator key, bitmask 3, expiry, model hash), not this HTTP request's capability.
The portal supplies the route → capability → permission policy; the READ|WRITE proof becomes
public-stats-only through P1's signed binding. Scene 6 is the one place the proof's own scope
limits what a signature can grant.

## Mechanics worth knowing

- **Audience is an exact byte comparison** (EVC §2.1): `https://stats.example.gov/` with a
  trailing slash is a different audience (tested). No URL normalization.
- **Nonces.** The agent-only policy denials shown here (scenes 2, 3, 6) occur before the agent
  nullifier is consumed, so a denial does not spend the nonce (tested: deny → allow → replay on a
  fresh store). The local store under `$HOME/.bolyra/` retains nullifiers for 30 days; each demo
  portal runs with its own temporary `HOME`, so replay state resets per run. This is not a general
  statement: delegation consumption happens earlier in the verifier pipeline, and human replay
  rejection can follow agent consumption.
- **Verifier process.** The portal runs `node <@bolyra/cli>/dist/main.js verify --circuits-dir
  fixtures/vkeys --roots-file fixtures/roots.json --capability-map capability-map.json --nonce-mode
  local` through `@bolyra/mpp`'s fail-closed runner with a 30 s host bound; the CLI worker has its
  own 10 s watchdog, which the host bound does not extend. The capability map is merged over the
  verifier's built-in default map (`fetch_inbox`, `send_message`, `read_message`, `broadcast`,
  `list_agents` stay mapped); harmless here because the demo bindings never name them, so they
  would fail `request_mismatch` first.
- **Problem responses.** `status`, `title` and `type` come verbatim from `@bolyra/mpp`'s published
  `denyProblem` table (its titles are payment-flavoured, e.g. "Spend Exceeds Delegated Tier");
  `verifier_detail` is an RFC 9457 §3.2 extension member carrying only the documented scene fields
  (`field`, `capability`, `request`, `binding`, `required_scope`, `effective_scope`,
  `excess_bits`), never the raw detail object.
- **HTTP boundary.** GET only, exact route lookup; other methods get 405 with `Allow: GET`;
  unknown paths 404; neither consults the verifier. Only the `x-bolyra-authorization` header is
  read (a presentation in `Authorization` is not seen). Denials never carry table data. The
  presentation is never logged or echoed.
- **Fixtures.** `fixtures/` holds byte copies of the CLI's vkeys, roots and golden request;
  `test/fixtures.test.ts` fails if they drift from `integrations/cli/test/fixtures/verify/`.

## Limits

Only a relying party that verifies gets any of this; unauthenticated endpoints check nothing. The
routes and data are mock. Not shown: revocation, delegation, human proofs, host-nonce mode
(reserve-before-act). Versions: `@bolyra/cli 0.9.0`, `@bolyra/mpp 0.7.0`, `@bolyra/sdk 0.6.1`,
Node 20.
