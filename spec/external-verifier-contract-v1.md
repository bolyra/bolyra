# External Verifier Contract v1

- **Status:** Stable (v1)
- **Wire version:** `1` (integer-major; see §11)
- **Document revision:** 2026-07-11 (additive, backward-compatible; wire major
  unchanged — see the changelog in §15). Adds §16 Host conformance.
- **Reference implementation:** `bolyra verify` in `@bolyra/cli`
  (`integrations/cli`) — a `zk`-class verifier (§3.5)
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

This contract governs the *transport and verdict envelope* and is
**proof-system-agnostic**: the request (§2) and verdict (§3) envelopes are
identical whether the verifier checks Groth16 zero-knowledge proofs, classical
signatures (ES256K receipts, JWT delegation, policy/nonce checks), or a third
party's own scheme. A verifier **SHOULD** announce which proof-system class it
implements via the verdict's `kind` self-description (§3.5), and a host **MAY**
route to, or branch on, verifiers of a given class. The reference `bolyra verify`
verifier is a `zk`-class verifier; its internal algorithm (envelope validation,
Groth16 verification, trusted-root checks, scope/expiry/replay binding) is
specified in the design document. A conforming verifier of **any** class **MAY**
implement any algorithm so long as it honors the input schema (§2), the verdict
schema (§3), the exit-code semantics (§6), and the stdout discipline (§5).

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
- `kind` (string, **OPTIONAL**) — the verifier's proof-system **self-description**,
  one of `classical`, `zk`, or `external` (§3.5). It **MAY** appear on either an
  `allow` or a `deny` verdict. When it is **absent**, the host **MUST** interpret
  the verdict as `zk`. A verifier whose class is **not** `zk` (i.e. `classical` or
  `external`) **MUST** set `kind` explicitly, because omission is read as `zk`.

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
        "kind": { "type": "string", "enum": ["classical", "zk", "external"] },
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
        "kind": { "type": "string", "enum": ["classical", "zk", "external"] },
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

### 3.5 Verifier self-description (`kind`) and proof-system class

Because the contract is proof-system-agnostic (§1), the same wire envelope carries
verdicts from verifiers built on different cryptographic foundations. The
**OPTIONAL** verdict field `kind` lets a verifier declare which class it
implements, so a host that spawns a verifier it did not build — or that fans a
request across several verifiers — can record and, if it chooses, branch on the
class of proof that produced the decision.

`kind` takes exactly one of three values:

| `kind` | Proof-system class | Bolyra product line | Examples |
|---|---|---|---|
| `classical` | Classical public-key crypto — signatures, tokens, policy/nonce checks, no zero-knowledge. | **Bolyra Core** | ES256K-signed receipts, JWT delegation tokens, capability/scope and replay-nonce checks. |
| `zk` | Zero-knowledge circuit proofs. | **Bolyra ZK** | Groth16 proofs for private delegation, credential predicates, human-uniqueness nullifiers. |
| `external` | A third-party verifier implementing this contract with its own proof system. | — (third party) | A vendor verifier the host adopts without depending on Bolyra internals. |

Normative rules:

- A verifier **SHOULD** set `kind` to the class it implements.
- A verifier that implements this revision as a `classical`- or `external`-class
  verifier **MUST** set `kind` explicitly (such verifiers are introduced by the
  2026-07-10 revision, §15; no non-`zk` verifier existed under the original v1). A
  verifier **MUST NOT** emit a `kind` value outside the three-member set above; a
  host **MUST** treat an unrecognized `kind` as a malformed verdict and fail closed
  (§7.2).
- The reference `bolyra verify` verifier is `zk`-class. For backward
  compatibility with wire version `1` verifiers that predate this field, a verdict
  **without** `kind` **MUST** be interpreted by the host as `zk` (§3.3). A
  `zk`-class verifier **MAY** therefore omit the field; emitting `"kind":"zk"`
  explicitly is equivalent for a revision-aware host. Because a host validating
  against the *original* (pre-revision) closed v1 schema rejects **any**
  `kind`-bearing verdict (§11), a `zk`-class verifier that must remain
  interoperable with such a host **SHOULD** omit `kind` rather than emit
  `"kind":"zk"`.
- `kind` is **advisory metadata about provenance**, not an authorization input.
  The `verdict`, `code`, and (in host nonce mode) `consume_nonces` fields are the
  sole enforcement surface; a host **MUST NOT** upgrade a `deny` to an `allow`, or
  relax any §7 fail-closed obligation, on the basis of `kind`.
- The value is **self-reported by the verifier and is not authenticated**. A host
  that requires a proof of a particular class **MUST** establish the verifier's
  class from its **configured verifier identity or policy** (which command it
  spawned, and the trust configuration it supplied) — never from the `kind` string
  alone. A host **MAY** use `kind` for logging, or to deny more strictly on a
  mismatch between the expected and reported class, but **MUST NOT** use it to
  relax trust, verifier selection, schema validation, nonce handling, or any §7
  fail-closed obligation.

The denial-code registry (§9) is shared across all three classes; a `classical`-
or `external`-`kind` verifier reuses the same vocabulary (§9).

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
- an unknown `verdict` value or a `deny` missing required fields;
- a verdict that otherwise fails the §3.4 verdict schema — including an
  unrecognized `kind` value (outside `classical` | `zk` | `external`, §3.5) or any
  disallowed additional property.

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
remove, or rename a code without a version bump (§11). The registry is
**proof-system-agnostic** (§3.5): a `classical`- or `external`-`kind` verifier
reuses the same codes — e.g. `invalid_proof` covers a failed classical signature
or token check as well as a failed Groth16 verification, and the Groth16-specific
wording in a row's *Meaning* is illustrative of the `zk` class, not exclusive.

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
   verdict, or a verdict that fails §3.4 schema validation (e.g. an unrecognized
   `kind`) — → reject.

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

**Additive optional fields do not bump the wire major.** The verdict `kind` field
(§3.5) is **OPTIONAL** and its absence has a defined meaning (`zk`, §3.3). Adding
it is compatible in the two directions that occur in practice: (i) a verifier that
omits `kind` — which includes **every** wire-`1` verifier predating this revision,
all of them `zk`-class — produces verdicts that both pre-revision and
revision-aware hosts accept; and (ii) a revision-aware host accepts those older
no-`kind` verdicts unchanged, reading them as `zk`.

The one caveat, stated plainly: the §3.4 verdict schema is **closed**
(`additionalProperties: false`), so a host validating against the *original* v1
schema will reject any verdict that actually *carries* `kind` — including a `zk`
verifier's explicit `"kind":"zk"`. The compatibility guarantee is therefore
precise rather than absolute: **omitted**-`kind` verdicts interoperate in both
directions (§3.3 reads their absence as `zk`), but any verdict that **emits**
`kind` requires a revision-aware host. This does not force a wire-major bump,
because the two classes of verifier that would emit `kind` are already paired with
revision-aware hosts: a `zk`-class verifier that must remain interoperable with a
strict pre-revision host **SHOULD** simply omit the field (§3.5), and a
`classical`- or `external`-class verifier — which **MUST** emit `kind` (§3.5) — did
not exist under the original v1 (the reference verifier was `zk`-only and emitted
no `kind`), so it is introduced by this revision and consumed only by
revision-aware hosts. Because the change adds only a named **OPTIONAL** property
with a defined default and introduces no new required field, it is recorded in the
document changelog (§15) rather than by incrementing the wire `version`. A field
that is **REQUIRED**, or whose omission would change how an existing verdict is
interpreted, would instead remain a wire-major change.

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

### 13.7 Allow — `classical`-kind verifier (Bolyra Core)

A `classical`-class verifier (§3.5) — e.g. one that checks an ES256K-signed
receipt and a JWT delegation token rather than a Groth16 proof — returns the same
`allow` envelope, tagged with its `kind`. Verdict (exit 0):

```json
{ "verdict": "allow", "kind": "classical" }
```

### 13.8 Deny — `external`-kind verifier

A third-party verifier (§3.5) denies with the shared registry (§9) and its own
`kind`. Verdict (exit 0):

```json
{ "verdict": "deny", "kind": "external", "code": "expired", "message": "credential expired" }
```

An agent-only `zk` verdict (§13.1) carries no `kind`; the host reads its absence
as `zk` (§3.3).

## 14. References

- Denial-code registry and IO-contract framing: `spec/CONFORMANCE.md`.
- Design and verification algorithm:
  `docs/superpowers/specs/2026-07-08-external-verifier-cli-design.md`.
- Host integration guide (mcp_agent_mail):
  `docs/integrations/mcp-agent-mail-verifier.md`.

## 15. Changelog

The wire contract is versioned integer-major (§11); this changelog records
**additive, backward-compatible** document revisions that do **not** increment the
wire `version`. A wire-`1` verifier that predates an entry below — necessarily
`zk`-class and emitting no `kind` — remains conformant, and its no-`kind` verdicts
are read as `zk` (§3.3); a verifier that implements a revision as a non-`zk` class
adopts that revision's obligations (e.g. it **MUST** set `kind`, §3.5).

- **2026-07-10 (wire version `1`, additive).** Made proof-system-agnosticism
  explicit. Added the **OPTIONAL** verdict field `kind` (`classical` | `zk` |
  `external`) as a verifier self-description (§3.3, §3.5) and to the §3.4 verdict
  schema; defined its absence as `zk` for backward compatibility. Stated in §1 and
  §9 that the transport, verdict envelope, and denial-code registry are shared
  across proof-system classes, and recorded in §11 that adding an optional field
  with a defined default does not bump the wire major. Motivated by the split of
  Bolyra into **Bolyra Core** (`classical`) and **Bolyra ZK** (`zk`), alongside
  third-party (`external`) verifiers.
- **2026-07-11 (wire version `1`, additive; documentation + conformance only).**
  Added §16 **Host conformance** — a fixture-and-vector suite that tests a *host*
  (not a verifier) against the §7.2 fail-closed and §7.3 reserve-before-act
  obligations, covering the five cases the project offered publicly: malformed
  stdout, timeout / no output, nonzero exit / killed-by-signal, oversize output,
  and reserve-before-act nonce consumption. Added the Host-Under-Test (HUT)
  convention (§16.2) the conformance runner drives — including the durable
  nonce-store, action-log, and fixture-pidfile side channels that make
  reserve-before-act ordering (§16.5) and the verifier-kill obligation (§16.3)
  observable — the misbehaving-verifier fixtures (`spec/fixtures/host-conformance/`,
  covering the full closed §3.4 verdict schema), the `host_behavior` vector type in
  `spec/test-vectors.json` / `spec/conformance-schema.json`, and a reference host
  (`spec/reference-host.js`). Added one clarifying normative sentence (§16.4)
  resolving a latent ambiguity: a non-zero exit is a deny **even when** a
  syntactically valid `allow` reached stdout. No wire envelope, verdict schema, or
  denial-code change; the verifier-facing contract is untouched.

## 16. Host conformance

Sections 5–7 place the load-bearing obligations on the **host**: it owns the
timeout (§6), the single-object stdout parse (§5.2), the exit-code interpretation
(§7.1–§7.2), and reserve-before-act nonce consumption (§7.3). A verifier that
follows the contract is not enough — a host that trusts a *misbehaving* verifier
is the actual vulnerability. This section makes those host obligations testable.

The suite inverts the `external_verifier` conformance class (§13, which spawns the
real verifier and checks its verdict): here the runner spawns a **deliberately
misbehaving verifier fixture** in place of a real one and asserts that the
**host-under-test fails closed**. A conforming host **MUST** deny in every case
below.

### 16.1 Misbehaving-verifier fixtures

The fixtures live in `spec/fixtures/host-conformance/` as small, dependency-free
Node scripts. Each violates exactly one contract obligation. The `Required host
outcome` column is the normative behavior a conforming host **MUST** produce; the
`Class` column is the reference host's canonical §16.3 classification.

| Fixture | Violates | Required host outcome | Class |
|---|---|---|---|
| `well-behaved-allow.js` | — (positive control) | relay `allow` | — |
| `well-behaved-deny.js` | — (positive control) | relay `deny code=expired` | — |
| `non-json-stdout.js` | §5.2 stdout not valid JSON | **deny** | `unparseable_stdout` |
| `multiple-objects.js` | §5.2 two concatenated verdicts (single-object framing) | **deny** | `multiple_objects` |
| `schema-invalid-verdict.js` | §3.4 `verdict` is neither `allow` nor `deny` | **deny** | `schema_invalid` |
| `deny-missing-fields.js` | §3.3/§3.4 `deny` missing `code`/`message` | **deny** | `schema_invalid` |
| `allow-trailing-garbage.js` | §5.2 valid `allow` then trailing bytes | **deny** | `unparseable_stdout` |
| `allow-extra-property.js` | §3.4 closed schema — disallowed additional property | **deny** | `schema_invalid` |
| `bad-kind.js` | §3.5 `kind` outside `classical`\|`zk`\|`external` | **deny** | `schema_invalid` |
| `empty-consume-nonces.js` | §3.2/§3.4 `consume_nonces` violates `minItems:1` | **deny** | `schema_invalid` |
| `malformed-consume-nonce.js` | §3.2/§3.4 nonce entry missing `issuer_key`/`retain_until` | **deny** | `schema_invalid` |
| `deny-extra-property.js` | §3.4 closed `deny` — disallowed additional property | **deny** | `schema_invalid` |
| `nonce-entry-extra-property.js` | §3.2/§3.4 nonce entry has an extra property | **deny** | `schema_invalid` |
| `nonce-entry-wrong-type.js` | §3.2/§3.4 nonce entry `retain_until` is not an integer | **deny** | `schema_invalid` |
| `no-output-hang.js` | §6 no output, never exits | **deny** (kill on timeout) | `timeout` |
| `partial-json-hang.js` | §6 partial verdict then hangs | **deny** (kill on timeout) | `timeout` |
| `nonzero-exit-after-allow.js` | §7.1 valid `allow` on stdout **but** non-zero exit | **deny** (§16.4) | `nonzero_exit` |
| `killed-by-signal.js` | §7.2 death by signal, no verdict | **deny** | `signal_death` \| `unparseable_stdout` |
| `oversize-flood.js` | §6 floods stdout past the output bound | **deny** (bound + kill) | `oversize_stdout` |
| `allow-consume-nonces.js` | — (drives §7.3 reserve-before-act) | reserve then allow, or deny on replay | `replay` on conflict |
| `allow-consume-nonces-multi.js` | — (drives §7.3 reserve-**all**) | deny if **any** entry conflicts | `replay` on conflict |

The `schema_invalid` fixtures collectively exercise the **closed** §3.4 verdict
schema at every level: an unknown `verdict`, a `deny` missing `code`/`message`,
additional properties on **both** the `allow` and `deny` objects, a bad `kind`,
and — for `consume_nonces` — an empty array, a missing required entry field, an
**extra** entry property, and a wrong-typed entry field. A host that validates
only the outer object, or only a subset of the nonce-entry schema, is therefore
caught.

The fixtures that flood or hang are **bounded**: `oversize-flood.js` streams only
to the stdout pipe (never to disk) and, after an 8 MiB burst, **hangs** rather than
exiting — so a host that never enforces the output bound cannot "buffer everything
then observe a clean exit"; it is instead caught by its own or the runner's
timeout. The hang fixtures perform no I/O beyond an optional partial write. The
three "kill-proof" fixtures (`no-output-hang.js`, `partial-json-hang.js`,
`oversize-flood.js`) record their PID (§16.2 `HUT_FIXTURE_PIDFILE`) so the runner
can verify the host **actually killed** the verifier rather than leaking an orphan
(§16.3).

### 16.2 Host-Under-Test (HUT) convention

The runner drives any host through a thin, language-neutral convention so a host
in any ecosystem can be tested against the same fixtures. By default the runner
tests the in-repo reference host (`spec/reference-host.js`); set the `HOST_CMD`
environment variable to a shell command to test a different host.

The runner spawns the host once per vector and communicates as follows:

- **Environment** — the runner sets, and the host **MUST** honor:
  - `HUT_VERIFIER_CMD` — a JSON array (`argv`) the host **MUST** spawn as its
    verifier. The host **MUST NOT** substitute a different command.
  - `HUT_TIMEOUT_MS` — the wall-clock timeout the host **MUST** enforce (§6).
  - `HUT_MAX_STDOUT_BYTES` — the stdout output bound the host **MUST** enforce
    (§6); exceeding it is a fail-closed condition (§7.2).
  - `HUT_NONCE_MODE` — `local` or `host` (§8).
  - `HUT_NONCE_STORE` — a filesystem path the host uses as its durable nonce
    store when in host nonce mode (§7.3). **For the harness only**, the store
    format is the simplest possible: **newline-delimited decimal nonce strings,
    UTF-8**. The runner pre-seeds it to stage replay scenarios and inspects it
    afterward to confirm reservation. A production host with a different store
    (SQLite, a KV, issuer-scoped keys, expiry columns) tests against this suite by
    pointing a thin test adapter at this file format; the format is a test
    convention, not part of the wire contract.
  - `HUT_ACTION_LOG` — a filesystem path. The host **MUST** append a non-empty
    marker here at the moment it **authorizes the action** — i.e. after every
    §7.3 reservation succeeds and immediately before returning `allow` — and
    **MUST NOT** write on any deny. This is the observable proxy for the "act" in
    reserve-before-act (§16.5).
  - `HUT_FIXTURE_PIDFILE` — a filesystem path. The host **MUST** propagate this
    variable to the spawned verifier so the kill-proof fixtures can record their
    PID; the runner then confirms the host killed the verifier on timeout/oversize
    (§16.3). For kill-proof vectors a **missing** pidfile is itself a failure — a
    host that scrubs its environment to the verifier must still forward this one
    test-only variable, otherwise the kill cannot be proven and a leaked orphan
    could hide. (This is a harness requirement, not a production one.)
- **stdin** — the runner writes exactly one §2.1 request object to the host's
  stdin and closes it. The host forwards this to the verifier per §2.
- **stdout** — the host **MUST** write exactly one **decision** object and exit
  `0`. The fail-closed signal is the decision object, **not** the host's own exit
  code; a host that itself exits non-zero fails the convention. The runner
  **enforces** that the decision is **exactly one** of these three closed shapes
  (any additional or mutually-exclusive field fails the vector):
  - `{"decision":"allow"}` — the verifier allowed (and, in host nonce mode, every
    nonce was reserved as novel, §7.3); no other key is permitted;
  - `{"decision":"deny","code":"<§9 code>"}` — a schema-valid verifier `deny`,
    relayed unchanged; the host **MUST NOT** attach a `failure_class` to a genuine
    verifier deny;
  - `{"decision":"deny","failure_class":"<§16.3 class>"}` — the host itself
    fail-closed (§7.2) or rejected a replay (§7.3); it **MUST NOT** also carry a
    `code`.

This decision envelope exists only for the conformance harness; it is **not** part
of the wire contract (§2–§9) and imposes nothing on a production host's internal
API. It merely makes the host's allow/deny decision, its *reason* for a
fail-closed deny, and whether it authorized the action, observable to the runner.

### 16.3 Host failure classes

When a host fails closed, the runner asserts *why*, using the classification the
host reports in `decision.failure_class`. This proves the host detected the
specific violation rather than denying by accident. The normative requirement is
always **deny**; the failure class is the finer-grained assertion.

| `failure_class` | Fail-closed condition (§7.2 unless noted) |
|---|---|
| `nonzero_exit` | verifier exited non-zero (§7.1/§16.4) |
| `timeout` | host timeout fired; host killed the process (§6) |
| `signal_death` | verifier died by an unsolicited signal |
| `unparseable_stdout` | stdout empty, not JSON, or with trailing bytes (§5.2) |
| `multiple_objects` | stdout carried more than one JSON value (§5.2) |
| `oversize_stdout` | stdout exceeded the host output bound (§6) |
| `schema_invalid` | a parsed verdict failed the §3.4 verdict schema |
| `replay` | a `consume_nonces` entry was already reserved (§7.3) |
| `spawn_error` | the host could not spawn or drive the verifier at all |

Because several §7.2 conditions can co-occur for one input, a vector **MAY** admit
more than one acceptable class. For example, a verifier killed by a signal both
dies by signal **and** leaves stdout empty, so `host-deny-killed-by-signal`
accepts `signal_death` or `unparseable_stdout` depending on the order a
conforming host checks. Where a fixture triggers a single unambiguous condition,
the vector pins the single class — a host that denies but misclassifies it
(e.g. calling an unbounded flood `unparseable_stdout` instead of enforcing the
`oversize_stdout` bound) is flagged, because the misclassification reveals a real
gap. The `well-behaved-*` positive controls assert that the suite is not
vacuously always-deny: a conforming host **MUST** relay their `allow` / `deny`.

### 16.4 Exit status dominates a stdout allow (clarification)

§7.1 defines a non-zero exit as "the verifier could not produce a trustworthy
verdict at all," and §7.2 requires the host to treat a non-zero exit as deny. This
section states the interaction explicitly, because it is the one place an
implementer may be tempted to trust stdout: a host **MUST** treat a non-zero exit
as **deny even when a syntactically valid `allow` was written to stdout**. Exit
status is part of the contract; whenever it is non-zero the host **MUST** ignore
stdout for the purpose of the decision. `nonzero-exit-after-allow.js` exercises
exactly this. (The reference §10 pseudocode's `INTERNAL_ALLOWED` token is **not**
an exception to this rule: no non-zero exit — including `internal_error`, §7.1 —
ever yields an allow.)

### 16.5 Reserve-before-act, made observable

The reserve-before-act rule (§7.3) is an *ordering* obligation: the host **MUST**
durably reserve every nonce **before** it authorizes the action. The suite makes
the observable parts of this testable with two side channels — the durable nonce
store (`HUT_NONCE_STORE`, proving the reservation was written) and the **action
log** (`HUT_ACTION_LOG`, the observable proxy for "the action": the host appends a
marker only when it authorizes, §16.2). Three vectors drive the
`allow-consume-nonces*` fixtures in host nonce mode:

- **`host-nonce-reserve-novel-allow`** — the store starts empty. The verifier
  returns `allow` with `consume_nonces`. *Observable assertion:* the decision is
  `allow`, the nonce is durably present in the store afterward, **and** the
  action-log marker is present (`action_taken: true`). This shows the reservation
  was actually written and the action was authorized.
- **`host-nonce-reserve-replay-deny`** — the store is pre-seeded with the nonce
  the verifier will emit. The verifier still returns `allow`, but a conforming host
  **MUST** deny (`replay`) **and MUST NOT authorize** — the action log stays empty
  (`action_taken: false`). *Observable assertion:* an `allow` from the verifier is
  flipped to a host `deny` by pre-existing durable state, with **no** action
  marker written. This is the load-bearing check: it proves authorization is
  **gated on the durable uniqueness check**, and it catches any host that
  authorizes a replayed presentation.
- **`host-nonce-reserve-all-any-conflict-deny`** — the verifier emits **two**
  nonces; only the second is pre-seeded. Because §7.3 requires reserving **every**
  entry and rejecting on **any** conflict, a conforming host **MUST** deny
  (`replay`) with no action taken, proving it reserves the whole list rather than
  short-circuiting on the first novel entry.

**Scope and limits.** As a black-box harness the suite proves three things: the
reservation is durably written (novel case), authorization is gated on the durable
uniqueness check (replay case, the primary guarantee), and every entry is checked
(reserve-all case). It does **not** prove the fine-grained *intra-allow-path*
ordering — that within a single `allow` the durable write is committed strictly
**before** the action marker — because distinguishing "reserve then act" from "act
then reserve, both before returning `allow`" would require fault injection (a crash
between the two steps), which a portable black-box runner cannot induce. That
crash-safety property remains a §7.3 obligation on the host; this suite asserts the
observable gate, not the write barrier. Implementers **SHOULD** additionally
cover the crash-window ordering with an in-process test in their own codebase.

### 16.6 Running the suite

```bash
# Against the in-repo reference host (default):
node spec/conformance-runner.js --type host_behavior

# Against your own host (any language), via the HUT convention (§16.2):
HOST_CMD="/path/to/your-host --flags" node spec/conformance-runner.js --type host_behavior
```

The `host_behavior` vectors also run as part of the full suite
(`node spec/conformance-runner.js --validate-schema`). A conforming host passes
every vector; the reference host is validated end-to-end as the suite's own
self-test.

[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119
[RFC 8174]: https://www.rfc-editor.org/rfc/rfc8174
