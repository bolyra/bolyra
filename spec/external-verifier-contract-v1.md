# External Verifier Contract v1

- **Status:** Stable (v1)
- **Wire version:** `1` (integer-major; see §11)
- **Reference implementation:** `bolyra verify` in `@bolyra/cli` (`integrations/cli`)
- **Companion documents:** `spec/CONFORMANCE.md` (conformance vectors), design spec
  `docs/superpowers/specs/2026-07-08-external-verifier-cli-design.md`

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**,
**SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this
document are to be interpreted as described in [RFC 2119] and [RFC 8174] when,
and only when, they appear in all capitals.

## 1. Overview

An **external verifier** is a program a host spawns to decide whether an agent's
Bolyra proof bundle authorizes a privileged action. The host↔verifier boundary is
a single-shot subprocess protocol:

1. The host **spawns** the verifier command.
2. The host writes **exactly one** JSON request object to the verifier's **stdin**,
   then closes stdin.
3. The verifier writes **exactly one** JSON verdict object to its **stdout** and
   exits.
4. The host reads that one verdict and enforces it **fail-closed** (§7).

This document is host-agnostic and language-agnostic: a host in any ecosystem MAY
implement or consume the contract without depending on Bolyra internals. The
`bundle` field of the request is **opaque** to the host; only a verifier vendor
needs to understand its internal `bvp/1` structure. A host adopts the contract by
learning four steps (§10), not the proof format.

This contract governs the *transport and verdict envelope*. The reference
verifier's internal verification algorithm (envelope validation, Groth16
verification, trusted-root checks, scope/expiry/replay binding) is specified in
the design document; a conforming verifier MAY implement any algorithm so long as
it honors the input schema (§2), the verdict schema (§3), the exit-code semantics
(§6), and the stdout discipline (§5).

## 2. Host → verifier request (stdin)

The host **MUST** write exactly one JSON object, UTF-8 encoded, to the verifier's
stdin and then **MUST** close (EOF) stdin. The host **MUST NOT** write more than
one object, trailing bytes, or a stream of objects.

### 2.1 Request shape

```json
{
  "version": 1,
  "bundle": "<opaque proof string>",
  "request": {
    "agent_name": "research-bot",
    "project_key": "/work/acme/research",
    "program": "crewai",
    "model": "opus-4.1",
    "granted_capabilities": ["fetch_inbox", "send_message"]
  },
  "now_unix": 1751990400
}
```

Field requirements:

- `version` (integer, **REQUIRED**) — envelope version of the *host request*.
  A verifier that implements this contract **MUST** support `1` and **MUST**
  reject any other value with `deny code=unsupported_version` (§4). Negotiation is
  by major only (§11).
- `bundle` (string, **REQUIRED**, non-empty) — opaque to the host. The verifier
  owns its internal structure. The host **MUST NOT** inspect, rewrite, or
  normalize it.
- `request` (object, **REQUIRED**) — the privileged action the host is about to
  authorize. It **MUST** contain:
  - `agent_name` (string, **REQUIRED**)
  - `project_key` (string, **REQUIRED**) — compared **literally**, byte-for-byte,
    against the bundle's signed binding. The verifier **MUST NOT** apply path
    canonicalization (no `..` resolution, no symlink resolution): `a/../b` and `b`
    are distinct keys.
  - `program` (string, **REQUIRED**)
  - `model` (string, **REQUIRED**)
  - `granted_capabilities` (array of strings, **REQUIRED**) — host-defined
    capability tokens the host intends to grant. They are opaque strings that the
    verifier maps to its internal permission model (see the capability map in the
    design spec §6). An empty array is permitted.
- `now_unix` (integer, **REQUIRED**, positive) — the host's current wall-clock
  time in seconds since the Unix epoch. The verifier **MUST** evaluate credential
  expiry against **this** value, not against its own clock, so the host owns the
  time source.

A request that is not a JSON object, is missing a **REQUIRED** field, or has a
field of the wrong type **MUST** yield `deny code=malformed_input` (§4). A
well-formed request whose `version` is not `1` **MUST** yield
`deny code=unsupported_version`.

### 2.2 Request JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://bolyra.ai/spec/external-verifier-request-v1.json",
  "title": "External Verifier Request v1",
  "type": "object",
  "required": ["version", "bundle", "request", "now_unix"],
  "additionalProperties": true,
  "properties": {
    "version": { "type": "integer", "const": 1 },
    "bundle": { "type": "string", "minLength": 1 },
    "request": {
      "type": "object",
      "required": [
        "agent_name",
        "project_key",
        "program",
        "model",
        "granted_capabilities"
      ],
      "additionalProperties": true,
      "properties": {
        "agent_name": { "type": "string" },
        "project_key": { "type": "string" },
        "program": { "type": "string" },
        "model": { "type": "string" },
        "granted_capabilities": {
          "type": "array",
          "items": { "type": "string" }
        }
      }
    },
    "now_unix": { "type": "integer", "exclusiveMinimum": 0 }
  }
}
```

## 3. Verifier → host verdict (stdout)

The verifier **MUST** write exactly one JSON object to stdout and nothing else
(§5 governs this strictly). The verdict is one of three shapes.

### 3.1 Allow

```json
{ "verdict": "allow" }
```

### 3.2 Allow with host-owned nonce consumption

Emitted only in host nonce mode (§8). Instructs the host to durably record each
one-time nonce so the same proof cannot be replayed. A presentation can carry
more than one nonce to reserve — e.g. the agent nullifier **plus** a
human-uniqueness nullifier when the bundle is human-backed (the human entry's
`nonce` is namespaced `human:<nullifierHash>`).

```json
{
  "verdict": "allow",
  "consume_nonces": [
    {
      "issuer_key": "15617329...:20201653...",
      "nonce": "12616665119450508255185458876855962314592339945640375882344193391684757282246",
      "retain_until": 4102444800
    }
  ]
}
```

- `consume_nonces` (array of objects, **OPTIONAL**, allow-only). When present it
  is a **non-empty** list (the key is omitted entirely when there is nothing to
  burn). The host **MUST** reserve-before-act **EACH** entry (§7.3). Each entry:
  - `issuer_key` (string, **REQUIRED**) — the issuer/operator key that scopes the
    nonce namespace. For host bookkeeping only; the `nonce` is already globally
    unique (§8).
  - `nonce` (string, **REQUIRED**) — the one-time value the host **MUST** record.
  - `retain_until` (integer, **REQUIRED**) — Unix seconds until which the host
    **MUST** retain the consumed nonce.

### 3.3 Deny

```json
{
  "verdict": "deny",
  "code": "scope_exceeded",
  "message": "required scope exceeds the credential effective scope",
  "detail": { "required_scope": "2", "effective_scope": "1", "excess_bits": "2" }
}
```

- `verdict` (string, **REQUIRED**) — `"allow"` or `"deny"`.
- `code` (string, **REQUIRED** on deny) — a stable machine token from the
  registry in §9. The host **MAY** branch on it.
- `message` (string, **REQUIRED** on deny) — a one-line, human-actionable
  reason. It **MUST NOT** contain secrets.
- `detail` (object, **OPTIONAL**) — structured context for logs/debugging. A
  verifier **SHOULD** echo the originating internal error code here (e.g.
  `sdk_code`) so the coarse wire `code` stays stable while logs stay precise.

### 3.4 Verdict JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://bolyra.ai/spec/external-verifier-verdict-v1.json",
  "title": "External Verifier Verdict v1",
  "oneOf": [
    {
      "type": "object",
      "required": ["verdict"],
      "additionalProperties": false,
      "properties": {
        "verdict": { "const": "allow" },
        "consume_nonces": {
          "type": "array",
          "minItems": 1,
          "items": {
            "type": "object",
            "required": ["issuer_key", "nonce", "retain_until"],
            "additionalProperties": false,
            "properties": {
              "issuer_key": { "type": "string" },
              "nonce": { "type": "string" },
              "retain_until": { "type": "integer" }
            }
          }
        }
      }
    },
    {
      "type": "object",
      "required": ["verdict", "code", "message"],
      "additionalProperties": false,
      "properties": {
        "verdict": { "const": "deny" },
        "code": {
          "type": "string",
          "enum": [
            "malformed_input",
            "unsupported_version",
            "invalid_bundle",
            "invalid_proof",
            "untrusted_root",
            "delegation_invalid",
            "invalid_signature",
            "request_mismatch",
            "model_mismatch",
            "unknown_capability",
            "scope_exceeded",
            "expired",
            "nonce_missing",
            "nonce_replayed",
            "internal_error"
          ]
        },
        "message": { "type": "string" },
        "detail": { "type": "object" }
      }
    }
  ]
}
```

## 4. Canonicalization, domain separation, and the binding signature

The bundle carries a **request-authorizing signature** that binds the request
context to the cryptographic key the proof commits to. Any implementer that
produces or verifies a bundle **MUST** reproduce these exact bytes. A verifier
consuming a foreign bundle **MUST** recompute the digest from the bundle's own
`binding` bytes; it **MUST NOT** trust a self-asserted digest.

### 4.1 Canonical payload

Let `binding` be the object with exactly the five fields `agent_name`,
`project_key`, `program`, `model`, `capabilities` (a string array). The canonical
payload is

```
payload = canonicalize(binding)
```

where `canonicalize` is the sorted-key, compact (no insignificant whitespace)
JSON serialization defined by `@bolyra/receipts` (`canonicalize`). Object keys
**MUST** be sorted; array elements (including `capabilities`) **MUST NOT** be
reordered. Signer and verifier therefore **MUST** agree on the array order: the
verifier compares `capabilities` as a set for authorization, but the *signed
bytes* are order-sensitive.

### 4.2 Domain separation

A domain-separation tag (DST) prevents a binding signature from being replayed as
any other Bolyra signature (delegation token, receipt, handshake) and vice-versa:

```
DST     = utf8("bolyra.external-verifier.binding.v1")
dsInput = DST || 0x00 || payload
```

The single `0x00` byte separates the ASCII domain tag from the canonical binding
bytes so no binding payload can be crafted to collide with a differently-tagged
message.

### 4.3 Digest → field element

```
digest   = SHA-256(dsInput)                              // 32 bytes
msgField  = BigInt("0x" || hex(digest)) mod BN254_FIELD_ORDER
```

`BN254_FIELD_ORDER` is the BN254 scalar field order
`21888242871839275222246405745257275088548364400416034343698204186575808495617`.
The modular reduction maps the 256-bit digest into the scalar field the
Poseidon/EdDSA primitives operate over (BN254 order ≈ 2²⁵⁴, so the reduction bias
is negligible for this use).

### 4.4 Sign / verify

- **Sign:** `sig = eddsaSign(operatorPrivateKey, msgField)` → `{ R8: { x, y }, S }`
  where each of `R8.x`, `R8.y`, `S` is a decimal-string field element (BabyJubjub
  EdDSA-Poseidon).
- **Verify:** recompute `msgField` from the bundle's own `binding` bytes, then
  EdDSA-Poseidon-verify `sig` against the operator public key that the proof
  commits to. The signing key **MUST** be the same operator key the proof binds;
  a signing key disjoint from the credential **MUST** be rejected
  (`deny code=invalid_signature`). This closes the cross-signer replay class.

## 5. stdout / stderr / fd-level isolation (load-bearing)

The whole contract depends on stdout carrying **exactly one** JSON object and
nothing else. This is the single most fragile part of the implementation and is
normative for both sides.

### 5.1 Verifier obligations

- The verifier **MUST** write exactly one `JSON.stringify(verdict)` to the
  host-facing stdout, at the very end. A single trailing newline is **OPTIONAL**.
- **No other code path may write to the host-facing stdout.** Proof-verification
  libraries (snarkjs / circomlibjs / WASM / native bindings) can write to file
  descriptor 1 directly — progress bars, warnings, debug spew — bypassing any
  language-level stdout wrapper. A `console.log`-style monkeypatch is therefore
  **insufficient**: it misses native writes.
- A conforming verifier **MUST** separate verification from verdict-emission at
  the **file-descriptor level**. The reference mechanism is **process isolation
  with a private verdict channel**:
  - the command **spawns a worker** process that performs the entire
    verification;
  - the worker's stdio binds fd 0 = request in, **fd 1 = captured** (everything
    native writes here), fd 2 = inherited parent stderr, **fd 3 = the private
    verdict channel**;
  - any raw fd-1 writes *inside the worker* **MUST** be captured by the parent and
    forwarded to the parent's **stderr** — they **MUST NOT** reach the host-facing
    stdout;
  - the worker emits the single verdict object **only** on fd 3 (`fs.writeSync(3,
    …)`); the parent reads fd 3 and performs the sole `process.stdout.write` on
    fd 1.
  - If the private verdict channel cannot be established on the platform, the
    verifier **MUST** fail closed (`deny code=internal_error`, non-zero exit) —
    it **MUST NOT** silently fall back to sharing fd 1.
- An in-process `dup2`-style redirect (duplicate fd 1, point fd 1 at stderr during
  verification, write the verdict via the duplicate) is an equally acceptable
  realization where the platform exposes the primitive. The process-isolation form
  is the reference implementation and is strictly stronger (it also captures native
  writes).

### 5.2 Host obligations (single-object parse)

The host **MUST** parse the verifier's stdout as **exactly one** JSON object with
**no trailing bytes**, and **MUST** reject (treat as deny, §7) any of:

- stdout that is empty, not valid JSON, or contains a leading/trailing prefix or
  suffix around the object;
- **multiple** concatenated JSON values (a lenient parser that reads only the
  first object **MUST NOT** be used — two objects is a fail-closed condition);
- a verdict whose `verdict` field is neither `"allow"` nor `"deny"`, or a `deny`
  missing `code`/`message`.

### 5.3 stderr

All diagnostics, timing, and debug logging **MUST** go to stderr, and **SHOULD**
be gated behind a verbose flag (`--verbose` / `BOLYRA_VERBOSE` in the reference
implementation). The default is silent on success and a one-line reason on deny
(also present structured in the stdout `message`/`detail`). Hosts **MUST NOT**
parse stderr for the verdict.

## 6. Timeout and input bounds

- **Timeout.** The **host owns the timeout**. The verifier does not implement its
  own. The host **MUST** enforce a wall-clock timeout on the spawned process and
  treat expiry as deny (§7). The **RECOMMENDED** timeout is **10 000 ms** (10 s):
  the verifier targets < 2 s p99 (cold start + library load + a handful of Groth16
  verifies), and 10 s leaves ample headroom.
- **stdin bound.** The verifier **MUST** bound the request read from stdin. The
  reference limit is **1 MiB** (1 048 576 bytes). A request over the bound **MUST**
  yield `deny code=malformed_input`; the verifier **MUST NOT** buffer an unbounded
  request.

## 7. Exit codes and host fail-closed obligations

### 7.1 Exit-code semantics (verifier)

- **Exit `0`** — a verdict object was produced (`allow` *or* any policy/crypto
  `deny`). The host reads stdout for the decision.
- **Exit non-zero** — the verifier could not produce a trustworthy verdict at all
  (could not read stdin, could not load required artifacts or trust configuration,
  catastrophic internal failure). Decision-level outcomes (invalid proof, expired,
  replay, mismatch, …) are **NOT** errors: they exit `0` with `verdict=deny`.
- The one nuance: `internal_error` is emitted as `deny code=internal_error`
  **and** exits non-zero, so the host both sees a machine reason and fail-closes.

### 7.2 Host fail-closed obligations (informative for the verifier, normative for the host)

The host **MUST** treat **all** of the following as **deny**, regardless of what
(if anything) reached stdout:

- non-zero exit code;
- timeout (§6) — the host **MUST** kill the process and deny;
- death by signal / crash;
- unparseable, empty, oversized, or multi-object stdout (§5.2);
- an unknown `verdict` value or a `deny` missing required fields.

The verifier is designed so these are the *only* ways it fails ambiguously; every
outcome it can reason about is an explicit `deny` with a `code` (§9).

### 7.3 Reserve-before-act (host nonce mode)

When the host runs the verifier in **host nonce mode** (§8) and receives
`allow` with `consume_nonces`, the host **MUST** reserve **every** entry in the
list **before** performing the privileged action:

1. For **each** `entry` in `consume_nonces`, atomically insert `entry.nonce` into
   durable storage with a unique-insert / "on conflict reject" semantic,
   retaining it until `entry.retain_until`.
2. If **all** inserts are **novel**, proceed with the action.
3. If **any** insert **conflicts** (that nonce was already recorded), the host
   **MUST** reject the action as a replay — even though the verifier returned
   `allow`.

"Record after proceeding" is a replay window and is **FORBIDDEN**. The verifier's
`allow` in host mode is **conditional** on every host insert being novel.

## 8. Replay protection modes

A verifier supports one of two replay modes, selected by the host at spawn time
(`--nonce-mode` in the reference implementation):

- **local (default).** The verifier owns durable replay state (file-backed under
  `~/.bolyra/nonces/`, or an injectable store). On an otherwise-allow it burns the
  proof's one-time nonce locally; a second presentation of the same proof yields
  `deny code=nonce_replayed`. Suitable for a single-host deployment. If the store
  errors, the verifier **MUST** fail closed (`deny code=internal_error`, non-zero
  exit).
- **host.** The verifier does **not** persist nonces. On an otherwise-allow it
  returns `consume_nonces` (§3.2) — one entry per one-time nullifier the
  presentation carries (the agent nullifier, plus the human-uniqueness nullifier
  for a human-backed bundle) — and the host owns durable storage under the
  reserve-before-act rule (§7.3). Delegation hops add **no** entry: each per-hop
  delegation nullifier is bound to the agent's session nonce, so reserving the
  agent nullifier already covers delegation replay. This is the mode for
  multi-host / clustered deployments where the host already owns a database.

The agent nonce value is globally unique per (credential, session-nonce), so no
separate operator namespacing is needed; `consume_nonces[].issuer_key` is provided
for host-side bookkeeping only.

## 9. Denial-code registry

The stable, lowercase `snake_case` vocabulary for the verdict `code` field. This
table is the single normative source; hosts **MAY** branch on these tokens and
**MUST** treat an unrecognized future `code` as deny. Verifiers **MUST NOT** add,
remove, or rename a code without a version bump (§11).

| `code` | Meaning |
|---|---|
| `malformed_input` | stdin missing / oversized (> 1 MiB) / not JSON, or a required request field is missing or ill-typed. |
| `unsupported_version` | host request `version` is not `1`, or the bundle's internal version is unsupported. |
| `invalid_bundle` | the opaque `bundle` is undecodable, not an object, or structurally wrong. |
| `invalid_proof` | envelope validation or Groth16 verification failed, the mandatory vkey pin is absent/mismatched, or the credential-to-proof anchoring (signer / scope / expiry bind) failed. |
| `untrusted_root` | a proof's Merkle root (agent, human, or delegatee) is not in the configured trusted-root source. |
| `delegation_invalid` | a delegation chain break, hop-cap overflow (> 3 hops), scope expansion, or expiry expansion. |
| `invalid_signature` | the BabyJubjub EdDSA-Poseidon binding signature (§4) did not verify against the proven operator key. |
| `request_mismatch` | a host `request` field does not match the signed binding, or `granted_capabilities` are not covered by the binding's capabilities. |
| `model_mismatch` | the proof's committed `model_hash` does not equal `sha256(request.model) mod BN254_FIELD_ORDER` — the proof is for a different model. |
| `unknown_capability` | a requested capability has no scope mapping (fail-closed; unmapped is never silently allowed). |
| `scope_exceeded` | the capability-required permission bits are not a cumulative-bit subset of the proven effective scope. |
| `expired` | proof-anchored `now_unix >= effective_expiry` — a **strict** comparison; the equality boundary is rejected. |
| `nonce_missing` | the proof lacks a usable `nullifierHash` / `sessionNonce` signal. |
| `nonce_replayed` | the proof's one-time nonce was already seen (local mode). |
| `internal_error` | unexpected failure, missing circuit artifacts, or missing trust configuration. Emitted as a deny **and** with a non-zero exit code. |

All rows are terminal `deny`s. Only `internal_error` additionally sets a non-zero
exit code (§7).

## 10. Adopt this verifier

A host in any language adopts the contract in four steps. The `bundle` stays
opaque throughout; the host never parses proofs.

1. **Spawn** the verifier command (e.g. `bolyra verify` — see §12 for flags).
2. **Write** the §2.1 request object to the child's stdin (the host fills in its
   own capability tokens in `granted_capabilities` and its wall clock in
   `now_unix`), then close stdin.
3. **Read** exactly one JSON verdict from the child's stdout under the strict
   single-object rule (§5.2), enforcing the host timeout (§6).
4. **Decide, fail-closed** (§7): `allow` → proceed (and, in host nonce mode,
   reserve-before-act EVERY `consume_nonces` entry, §7.3); anything else — `deny`, non-zero
   exit, timeout, signal death, unparseable/oversized/multi-object stdout, unknown
   verdict — → reject.

Language-neutral pseudocode:

```
child   = spawn(verifier_cmd, timeout = 10_000ms)
write(child.stdin, json(request)); close(child.stdin)
status, out, err = wait(child)                 // out = stdout, err = stderr

if status != 0 and status != INTERNAL_ALLOWED: reject("non-zero exit")   // §7.2
if timed_out(child):                          reject("timeout")          // §6
verdict = parse_single_json_object(out)        // §5.2; on any failure → reject
if verdict is null:                            reject("unparseable stdout")

switch verdict.verdict:
  case "allow":
    for entry in (verdict.consume_nonces or []):                         // §8 host mode
      if not reserve_nonce_atomically(entry): reject("replay")           // §7.3 (reserve ALL)
    proceed()
  case "deny":
    reject(verdict.code)                        // branch on §9 registry if desired
  default:
    reject("unknown verdict")                   // §7.2
```

Because the bundle is opaque, only Bolyra (or another verifier vendor) needs to
understand its internal `bvp/1` structure; the host only needs the four steps
above.

## 11. Wire versioning

Two version tokens live at different layers, with **deliberately different**
versioning rules:

- **Wire-facing envelopes are integer-major.** The host request `version` (§2.1)
  and the internal bundle version are single integers, negotiated **by major
  only**. A verifier supports a fixed set of wire majors; an unsupported major is
  `deny code=unsupported_version`. There is no minor/patch at the wire layer: any
  breaking change to the request or verdict envelope increments the integer.
- **Embedded proofs keep semver.** The `ProofEnvelope`s carried inside the opaque
  bundle keep their semantic-version string (e.g. `"1.0.0"`) and the SDK's
  existing major-only compatibility rule.

This split — *wire envelopes integer-major, embedded proofs semver* — is
intentional and is stated here so it does not read as accidental. The denial-code
registry (§9) is part of the wire contract and is therefore also governed by the
integer-major rule: adding, removing, or renaming a code is a wire-major change.

## 12. Reference implementation flags (informative)

The `bolyra verify` reference verifier accepts:

| Flag | Meaning |
|---|---|
| `--nonce-mode <local\|host>` | replay-protection mode (§8); default `local`. |
| `--roots-file <path>` | trusted-roots JSON file (optionally namespaced `{ "agent": [...], "human": [...], "delegatee": [...] }`). |
| `--root <decimal>` | inline trusted root, repeatable (also `BOLYRA_TRUSTED_ROOTS`, comma-separated). |
| `--capability-map <path>` | capability → permission-bit map JSON. |
| `--circuits-dir <path>` | circuit vkey/artifact directory (also `BOLYRA_CIRCUITS_DIR`). |
| `--verbose` | verbose diagnostics on stderr (§5.3). |

If **no** trusted-root source is configured, the reference verifier fails closed
(`deny code=internal_error`, non-zero exit): "no roots configured" is never
treated as "all roots trusted".

## 13. Worked examples

Each example is a real `(stdin request, stdout verdict)` pair against the
reference verifier. Requests are abbreviated (`bundle` elided).

### 13.1 Allow (local nonce mode)

Request:

```json
{ "version": 1, "bundle": "…", "request": {
    "agent_name": "research-bot", "project_key": "/work/acme/research",
    "program": "crewai", "model": "opus-4.1",
    "granted_capabilities": ["fetch_inbox", "send_message"] },
  "now_unix": 1751990400 }
```

Verdict (exit 0):

```json
{ "verdict": "allow" }
```

### 13.2 Allow with `consume_nonces` (host nonce mode)

Same request, verifier spawned with `--nonce-mode host`. This agent-only bundle
yields a single entry; a human-backed bundle would add a second
`human:<nullifierHash>` entry. Verdict (exit 0):

```json
{
  "verdict": "allow",
  "consume_nonces": [
    {
      "issuer_key": "15617329766995256858590222302430068383949745072531974464084158078905448850943:20201653676552407165606319978171745645181779505176156736762229713293662347780",
      "nonce": "12616665119450508255185458876855962314592339945640375882344193391684757282246",
      "retain_until": 4102444800
    }
  ]
}
```

The host **MUST** reserve every entry's `nonce` atomically before acting (§7.3).

### 13.3 Deny — `scope_exceeded`

Request whose credential proves only `READ_DATA` but whose `send_message`
capability requires `WRITE_DATA`. Verdict (exit 0):

```json
{
  "verdict": "deny",
  "code": "scope_exceeded",
  "message": "required scope exceeds the credential effective scope",
  "detail": { "required_scope": "2", "effective_scope": "1", "excess_bits": "2" }
}
```

### 13.4 Deny — `model_mismatch`

Request whose `model` differs from the model the proof commits to. Verdict
(exit 0):

```json
{
  "verdict": "deny",
  "code": "model_mismatch",
  "message": "proven model hash does not match the requested model",
  "detail": { "requestModel": "model-beta" }
}
```

### 13.5 Deny — `malformed_input`

Truncated JSON on stdin (`{"version":1,"bun`). Verdict (exit 0):

```json
{ "verdict": "deny", "code": "malformed_input", "message": "request stdin is not valid JSON" }
```

### 13.6 Deny — `internal_error` (fail-closed, non-zero exit)

No trusted-root source configured. Verdict on stdout **and** a non-zero exit
code, so the host fail-closes on either signal:

```json
{ "verdict": "deny", "code": "internal_error", "message": "no trusted root source configured" }
```

## 14. References

- Denial-code registry and IO-contract framing: `spec/CONFORMANCE.md`.
- Design and verification algorithm:
  `docs/superpowers/specs/2026-07-08-external-verifier-cli-design.md`.
- Host integration guide (mcp_agent_mail):
  `docs/integrations/mcp-agent-mail-verifier.md`.

[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119
[RFC 8174]: https://www.rfc-editor.org/rfc/rfc8174
