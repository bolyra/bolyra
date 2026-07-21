---
title: "An External Verifier Contract for Agent Authorization Decisions"
abbrev: "External Verifier Contract"
docname: draft-kondoju-evc-00
category: info
ipr: trust200902
area: Security
workgroup: Individual Submission
keyword:
  - agent
  - authorization
  - verifier
  - zero-knowledge
  - selective-disclosure
submissiontype: IETF
stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
  - name: Viswanadha Pratap Kondoju
    organization: Bolyra
    email: viswa@bolyra.ai

normative:
  RFC2119:
  RFC8174:
  RFC8259:

informative:
  RFC6749:
  RFC7519:
  RFC7662:
  RFC7942:
  RFC8126:
  RFC8615:
  I-D.klrc-aiagent-auth:
    title: "AI Agent Authentication and Authorization"
    docname: draft-klrc-aiagent-auth-03
    date: 2026-07-06
    author:
      - name: P. Kasselman
      - name: D. Lombardo
      - name: Y. Rosomakho
      - name: B. Campbell
      - name: A. Steele
  I-D.pidlisnyi-aps:
    title: "Agent Passport System"
    docname: draft-pidlisnyi-aps-02
    date: 2026-07-04
    author:
      - name: Pidlisnyi

--- abstract

This document specifies the External Verifier Contract (EVC): a small, testable,
proof-system-agnostic boundary between a host (the program about to take a
privileged action on an agent's behalf) and an external verifier (a subprocess
that renders an allow/deny verdict on an opaque proof bundle). The contract
governs only the transport and verdict envelope: how the host hands a single JSON
request to a verifier subprocess over stdin, how the verifier answers with exactly
one JSON verdict on stdout, and how the host interprets exit codes, timeouts, and
malformed output under a fail-closed rule. Three properties make the boundary
standardizable: (1) a single-shot subprocess transport with a closed JSON verdict
schema; (2) fail-closed host semantics that are independently testable by a
host-conformance suite; and (3) proof-system agnosticism, so the same envelope
carries classical-signature, zero-knowledge, and third-party verdicts,
distinguished only by an OPTIONAL self-description field. EVC is deliberately not a
governance framework, not a delegation model, and not a policy language. It is the
narrow decision boundary those larger systems all require at the point of
enforcement.

--- middle

# Introduction

## Problem

Agent frameworks -- Model Context Protocol (MCP) hosts, orchestrators, and
gateways -- increasingly need to gate a privileged tool call on a single question:
is this agent actually authorized to take this action right now? Today each host
reimplements a bespoke check and couples itself to one proof format. There is no
interoperable, language-neutral boundary at which a host can ask an external
verifier -- one the host did not build -- for a decision.

## What EVC Standardizes

EVC standardizes the transport and verdict envelope only. Specifically: how the
host hands a request to a verifier subprocess (one JSON object on stdin, then EOF),
how the verifier answers (exactly one JSON verdict on stdout), how exit codes and
timeouts are interpreted, and the fail-closed obligations that bind the host. The
proof bundle itself is opaque to the host: only a verifier vendor needs to
understand its internal structure. A host adopts the contract by learning four
steps (Section 3), not a proof format.

## What EVC Deliberately Excludes

EVC does not define credential issuance, the internal proof format, policy
authoring, delegation semantics, revocation infrastructure, or any PKI. These
belong to the verifier vendor or to adjacent specifications. Keeping the boundary
this small is the design thesis: it is what makes the contract testable rather
than aspirational. Every normative obligation in this document is placed either on
the host or on a conforming verifier at the wire boundary, and nothing below it.

## Why Interoperable, Why Now

The contract is not tied to one runtime. Two independent reference hosts already
exist -- one in JavaScript ("spec/reference-host.js") and one in Rust
("spec/reference-host-rs/") -- demonstrating that the host obligations can be
implemented and tested in more than one language. The maintainer of a separate
MCP project (mcp_agent_mail_rust) built an off-by-default Ed25519
registration-proof gate designed to this contract's v1 boundary (issue #183
defines the corresponding spawnable-verifier slot shape); that gate exercises
the contract's request/verdict surface without depending on any Bolyra
component. The host obligations are mechanically testable by a conformance
suite (Section 8), so a host's fail-closed behavior is a checkable property
rather than an assertion. See also the Implementation Status section
({{impl-status}}).

## Positioning Versus Online Introspection (Non-Normative)

A verdict is produced offline from a self-contained bundle plus host-supplied
context and the host's wall-clock; there is no round-trip to an authorization
server. This is a deliberate contrast with, not a competitor to, OAuth 2.0 token
introspection {{RFC7662}}, which resolves a token's state through an online request
to an introspection endpoint. EVC and online introspection can coexist: a bundle
can carry a token that a classical-class verifier (Section 5) validates by
whatever means it chooses, including an out-of-band introspection call, but the
host↔verifier decision boundary itself is a single local subprocess exchange.

# Conventions and Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 {{RFC2119}} {{RFC8174}} when,
and only when, they appear in all capitals, as shown here.

The wire representations in this document are JSON {{RFC8259}}.

## Terminology

host:
: The program about to take a privileged action on an agent's behalf. The host
  spawns the verifier, supplies the request, and enforces the verdict fail-closed.

verifier:
: A program the host spawns as a subprocess to decide whether a bundle authorizes a
  privileged action. It reads one request on stdin and writes one verdict on
  stdout.

bundle:
: An opaque proof string carried in the request. It is opaque to the host: the host
  MUST NOT inspect, rewrite, or normalize it. Only a verifier vendor understands its
  internal structure.

verdict:
: The single JSON object the verifier writes to stdout: an allow, an allow with
  host-owned nonce consumption, or a deny with a code and message.

request:
: The single JSON object the host writes to the verifier's stdin, describing the
  privileged action it is about to authorize.

decision:
: The host's enforced outcome (proceed or reject) after applying the verdict and all
  fail-closed obligations.

proof-system class:
: The cryptographic family a verifier implements, one of "classical", "zk", or
  "external" (Section 5). Self-described by the OPTIONAL verdict field "kind".

host nonce mode / local nonce mode:
: The two replay-protection modes (Section 7). In local mode the verifier owns the
  durable nonce store; in host mode the verifier returns nonces for the host to
  reserve.

reserve-before-act:
: The host obligation, in host nonce mode, to durably reserve every returned nonce
  with unique-insert semantics before performing the privileged action (Section 7).

Host-Under-Test (HUT):
: A host driven by the conformance runner through the environment convention of
  Section 8, so hosts in any language can be tested against the same fixtures.

# Architecture and Trust Model

The host↔verifier boundary is a single-shot subprocess protocol of four steps:

1. The host spawns the verifier command.
2. The host writes exactly one JSON request object to the verifier's stdin, then
   closes (EOF) stdin.
3. The verifier writes exactly one JSON verdict object to its stdout and exits.
4. The host reads that one verdict and enforces it fail-closed (Section 6).

Language-neutral pseudocode for the host side:

~~~
child   = spawn(verifier_cmd, timeout = 10_000ms)
write(child.stdin, json(request)); close(child.stdin)
status, out, err = wait(child)                 // out = stdout, err = stderr

if status != 0:                               reject("non-zero exit")   // Sec 6
if timed_out(child):                          reject("timeout")         // Sec 6
verdict = parse_single_json_object(out)        // Sec 4; on any failure -> reject
if verdict is null:                            reject("unparseable stdout")

switch verdict.verdict:
  case "allow":
    for entry in (verdict.consume_nonces or []):        // Sec 7 host mode
      if not reserve_nonce_atomically(entry): reject("replay")   // reserve ALL
    proceed()
  case "deny":
    reject(verdict.code)                        // branch on Sec 4.2 registry
  default:
    reject("unknown verdict")
~~~

The contract is host-agnostic and language-agnostic: a host in any ecosystem MAY
implement or consume the contract without depending on any verifier's internals.

## Trust Boundaries

The host trusts exactly two things: (a) the verifier command it configured -- which
binary and argument vector it spawned -- and (b) the trust configuration it supplied
to that verifier, such as trusted roots, a capability map, or a signer list. The
host does NOT trust the bundle, and it MUST NOT infer trust from any self-reported
field in the verdict, notably the "kind" self-description (Section 5).

The verifier trusts its configured roots and policy. "No roots configured" is never
"all roots trusted": a verifier that has no trust source configured MUST fail
closed rather than accept anything.

## Time Source

The host owns the clock. The request field "now_unix" is host-supplied, and the
verifier MUST evaluate credential expiry against that value rather than its own
clock. This is an explicit trust-model property: expiry is judged against the
host's wall-clock, so the host, not the verifier, is authoritative about the
current time.

# Request and Verdict Envelopes

This section transcribes the wire envelopes. The full JSON Schemas appear
normatively in {{schemas}}.

## Host to Verifier Request (stdin) {#request}

The host MUST write exactly one JSON object, UTF-8 encoded, to the verifier's
stdin, and then MUST close (EOF) stdin. The host MUST NOT write more than one
object, trailing bytes, or a stream of objects.

~~~ json
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
~~~

Field requirements:

- "version" (integer, REQUIRED) -- envelope version of the host request. A verifier
  that implements this contract MUST support "1" and MUST reject any other value
  with "deny code=unsupported_version" (Section 4.2). Negotiation is by major only
  (Section 10).
- "bundle" (string, REQUIRED, non-empty) -- opaque to the host. The verifier owns
  its internal structure. The host MUST NOT inspect, rewrite, or normalize it.
- "request" (object, REQUIRED) -- the privileged action the host is about to
  authorize. It MUST contain:
  - "agent_name" (string, REQUIRED).
  - "project_key" (string, REQUIRED) -- compared literally, byte-for-byte, against
    the bundle's signed binding. The verifier MUST NOT apply path canonicalization
    (no ".." resolution, no symlink resolution): "a/../b" and "b" are distinct
    keys. This byte-literal rule is a subtle interoperability hazard and is stated
    explicitly to prevent a verifier from silently normalizing a project key.
  - "program" (string, REQUIRED).
  - "model" (string, REQUIRED).
  - "granted_capabilities" (array of strings, REQUIRED) -- host-defined capability
    tokens the host intends to grant. They are opaque strings that the verifier
    maps to its internal permission model. An empty array is permitted.
- "now_unix" (integer, REQUIRED, positive) -- the host's current wall-clock time in
  seconds since the Unix epoch. The verifier MUST evaluate credential expiry
  against this value, not against its own clock.

A request that is not a JSON object, is missing a REQUIRED field, or has a field of
the wrong type MUST yield "deny code=malformed_input". A well-formed request whose
"version" is not "1" MUST yield "deny code=unsupported_version".

## Verifier to Host Verdict (stdout) {#verdict}

The verifier MUST write exactly one JSON object to stdout and nothing else
(Section 4.3 governs this strictly). The verdict is one of three shapes.

### Allow

~~~ json
{ "verdict": "allow" }
~~~

### Allow With Host-Owned Nonce Consumption

Emitted only in host nonce mode (Section 7). It instructs the host to durably
record each one-time nonce so the same proof cannot be replayed. A presentation can
carry more than one nonce to reserve -- for example the agent nullifier plus a
human-uniqueness nullifier when the bundle is human-backed (the human entry's
"nonce" is namespaced "human:NULLIFIER-HASH").

~~~ json
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
~~~

"consume_nonces" (array of objects, OPTIONAL, allow-only). When present it is a
non-empty list (the key is omitted entirely when there is nothing to burn). The
host MUST reserve-before-act EACH entry (Section 7). Each entry:

- "issuer_key" (string, REQUIRED) -- the issuer/operator key that scopes the nonce
  namespace, for host bookkeeping only; the "nonce" is already globally unique
  (Section 7).
- "nonce" (string, REQUIRED) -- the one-time value the host MUST record.
- "retain_until" (integer, REQUIRED) -- Unix seconds until which the host MUST
  retain the consumed nonce.

### Deny

~~~ json
{
  "verdict": "deny",
  "code": "scope_exceeded",
  "message": "required scope exceeds the credential effective scope",
  "detail": { "required_scope": "2", "effective_scope": "1", "excess_bits": "2" }
}
~~~

- "verdict" (string, REQUIRED) -- "allow" or "deny".
- "code" (string, REQUIRED on deny) -- a stable machine token from the registry in
  Section 4.2. The host MAY branch on it.
- "message" (string, REQUIRED on deny) -- a one-line, human-actionable reason. It
  MUST NOT contain secrets.
- "detail" (object, OPTIONAL) -- structured context for logs/debugging. A verifier
  SHOULD echo the originating internal error code here so the coarse wire "code"
  stays stable while logs stay precise.
- "kind" (string, OPTIONAL) -- the verifier's proof-system self-description, one of
  "classical", "zk", or "external" (Section 5). It MAY appear on either an "allow"
  or a "deny" verdict. When absent, the host MUST interpret the verdict as "zk". A
  verifier whose class is not "zk" MUST set "kind" explicitly, because omission is
  read as "zk".

## Denial-Code Registry {#denial-codes}

The stable, lowercase snake_case vocabulary for the verdict "code" field. This
table is the single normative source; hosts MAY branch on these tokens and MUST
treat an unrecognized future "code" as deny. Verifiers MUST NOT add, remove, or
rename a code without a wire-major version bump (Section 10). The registry is
proof-system-agnostic (Section 5): a "classical"- or "external"-kind verifier
reuses the same codes -- for example "invalid_proof" covers a failed classical
signature or token check as well as a failed zero-knowledge verification.

| code | Meaning |
|---|---|
| malformed_input | stdin missing / oversized (> 1 MiB) / not JSON, or a required request field is missing or ill-typed. |
| unsupported_version | host request "version" is not "1", or the bundle's internal version is unsupported. |
| invalid_bundle | the opaque "bundle" is undecodable, not an object, or structurally wrong. |
| invalid_proof | envelope validation or proof verification failed, the mandatory verification-key pin is absent/mismatched, or the credential-to-proof anchoring failed. |
| untrusted_root | a proof's trust anchor (agent, human, or delegatee) is not in the configured trusted-root source. |
| delegation_invalid | a delegation chain break, hop-cap overflow, scope expansion, or expiry expansion. |
| invalid_signature | the request-binding signature (Appendix B) did not verify against the proven operator key. |
| request_mismatch | a host "request" field does not match the signed binding, or "granted_capabilities" are not covered by the binding's capabilities. |
| model_mismatch | the proof's committed model does not equal the requested model -- the proof is for a different model. |
| unknown_capability | a requested capability has no scope mapping (fail-closed; unmapped is never silently allowed). |
| scope_exceeded | the capability-required permission bits are not a cumulative-bit subset of the proven effective scope. |
| expired | proof-anchored "now_unix >= effective_expiry" -- a strict comparison; the equality boundary is rejected. |
| nonce_missing | the proof lacks a usable nullifier / session-nonce signal. |
| nonce_replayed | the proof's one-time nonce was already seen (local mode). |
| internal_error | unexpected failure, missing artifacts, or missing trust configuration. Emitted as a deny AND with a non-zero exit code. |

All rows are terminal denies. Only "internal_error" additionally sets a non-zero
exit code (Section 6). This 15-code table is the candidate IANA registry
(Section 13).

## stdout / stderr / fd-Level Isolation (Load-Bearing) {#fd-isolation}

The whole contract depends on stdout carrying exactly one JSON object and nothing
else. This is the single most fragile part of the implementation and is normative
for both sides.

Verifier obligations:

- The verifier MUST write exactly one serialized verdict to the host-facing stdout,
  at the very end. A single trailing newline is OPTIONAL.
- No other code path may write to the host-facing stdout. Proof-verification
  libraries (native, WASM, or otherwise) can write to file descriptor 1 directly --
  progress bars, warnings, debug output -- bypassing any language-level stdout
  wrapper. A "console.log"-style monkeypatch is therefore insufficient: it misses
  native writes.
- A conforming verifier MUST separate verification from verdict-emission at the
  file-descriptor level. The reference mechanism is process isolation with a private
  verdict channel: the command spawns a worker whose stdio binds fd 0 = request in,
  fd 1 = captured (everything native writes here), fd 2 = inherited parent stderr,
  and fd 3 = the private verdict channel. Any raw fd-1 writes inside the worker MUST
  be captured by the parent and forwarded to the parent's stderr, and MUST NOT reach
  the host-facing stdout. The worker emits the single verdict only on fd 3; the
  parent performs the sole write to fd 1.
- If the private verdict channel cannot be established on the platform, the verifier
  MUST fail closed ("deny code=internal_error", non-zero exit). It MUST NOT silently
  fall back to sharing fd 1. An in-process fd-redirect realization is equally
  acceptable where the platform exposes the primitive; the process-isolation form is
  the reference implementation and is strictly stronger.

Host obligations (single-object parse):

The host MUST parse the verifier's stdout as exactly one JSON object with no
trailing bytes, and MUST reject (treat as deny, Section 6) any of:

- stdout that is empty, not valid JSON, or contains a leading/trailing prefix or
  suffix around the object;
- multiple concatenated JSON values (a lenient parser that reads only the first
  object MUST NOT be used -- two objects is a fail-closed condition);
- a verdict whose "verdict" field is neither "allow" nor "deny", or a "deny" missing
  "code"/"message".

All diagnostics, timing, and debug logging MUST go to stderr. Hosts MUST NOT parse
stderr for the verdict.

# Proof-System Classes and the `kind` Self-Description {#kind}

Because the contract is proof-system-agnostic (Section 1), the same wire envelope
carries verdicts from verifiers built on different cryptographic foundations: a
classical-signature verifier, a zero-knowledge verifier, and a third-party verifier
all speak the identical request and verdict schema and differ only in which command
the host spawns. This is the property that lets a host adopt privacy-preserving
verification without changing its wire contract.

The OPTIONAL verdict field "kind" lets a verifier declare which class it implements,
so a host that spawns a verifier it did not build -- or that fans a request across
several verifiers -- can record and, if it chooses, branch on the class of proof
that produced the decision. "kind" takes exactly one of three values:

| kind | Proof-system class | Examples |
|---|---|---|
| classical | Classical public-key crypto -- signatures, tokens, policy/nonce checks, no zero-knowledge. | ES256K-signed receipts, JWT delegation tokens, capability/scope and replay-nonce checks. |
| zk | Zero-knowledge circuit proofs. | Zero-knowledge proofs for private delegation, credential predicates, human-uniqueness nullifiers. |
| external | A third-party verifier implementing this contract with its own proof system. | A vendor verifier the host adopts without depending on any specific internals. |

## Selective Disclosure as a First-Class, Optional Lane

A "zk"-class verifier proves properties of a credential -- scope, expiry, a
human-uniqueness nullifier, delegation narrowing -- without revealing the agent's
identity or the underlying attribute values. This selective-disclosure capability
is one that no signature-only contract can express, because a classical signature
necessarily discloses the signed content it authenticates.

The normative point is deliberately narrow: EVC does NOT require zero-knowledge
verification, but it reserves a first-class lane for it via "kind=zk". A host that
wants privacy-preserving verification and a host that wants a plain signature check
speak the identical wire protocol and differ only in which verifier command they
spawn. The privacy property is a property of the verifier the host configures, not
of the wire contract.

## Normative Rules for `kind`

- A verifier SHOULD set "kind" to the class it implements.
- A verifier that implements this contract as a "classical"- or "external"-class
  verifier MUST set "kind" explicitly, because omission is read as "zk". A verifier
  MUST NOT emit a "kind" value outside the three-member set above; a host MUST treat
  an unrecognized "kind" as a malformed verdict and fail closed (Section 6).
- For backward compatibility, a verdict without "kind" MUST be interpreted by the
  host as "zk". A "zk"-class verifier MAY therefore omit the field. Because a host
  validating against the original closed verdict schema rejects any "kind"-bearing
  verdict (Section 10), a "zk"-class verifier that must remain interoperable with
  such a host SHOULD omit "kind" rather than emit "kind":"zk".

## Guardrails (Advisory Metadata, Not an Authorization Input)

"kind" is advisory metadata about provenance, and it is self-reported by the
verifier and NOT authenticated. The "verdict", "code", and (in host nonce mode)
"consume_nonces" fields are the sole enforcement surface. A host:

- MUST NOT upgrade a "deny" to an "allow" on the basis of "kind";
- MUST NOT relax any Section 6 fail-closed obligation, schema validation, verifier
  selection, or nonce handling on the basis of "kind";
- MUST establish a verifier's proof-system class from its configured verifier
  identity or policy -- which command it spawned and the trust configuration it
  supplied -- never from the self-reported "kind" string alone.

A host MAY use "kind" for logging, or to deny more strictly on a mismatch between
the expected and reported class. An unrecognized "kind" is a malformed verdict and
MUST fail closed (Section 6). The threat guarded against is a hostile or buggy
verifier claiming "kind=zk" to imply privacy guarantees it did not provide.

## Relationship to the Related APS Draft

The related draft {{I-D.pidlisnyi-aps}} does not define a zero-knowledge or
selective-disclosure verifier class (Section 12.2). EVC's "kind" lane is where
privacy-preserving verification plugs into an otherwise-identical host contract,
regardless of which framework produced the bundle.

# Exit Codes, Timeouts, and Host Fail-Closed Obligations

## Exit-Code Semantics (Verifier)

- Exit "0" -- a verdict object was produced ("allow" or any policy/crypto "deny").
  The host reads stdout for the decision.
- Exit non-zero -- the verifier could not produce a trustworthy verdict at all
  (could not read stdin, could not load required artifacts or trust configuration,
  catastrophic internal failure). Decision-level outcomes (invalid proof, expired,
  replay, mismatch) are NOT errors: they exit "0" with "verdict=deny".
- The one nuance: "internal_error" is emitted as "deny code=internal_error" AND
  exits non-zero, so the host both sees a machine reason and fail-closes.

## Exit Status Dominates a stdout Allow

A host MUST treat a non-zero exit as deny even when a syntactically valid "allow"
was written to stdout. Exit status is part of the contract; whenever it is non-zero
the host MUST ignore stdout for the purpose of the decision. This is the one place
an implementer may be tempted to trust stdout, and it is stated explicitly to close
that temptation. No non-zero exit -- including "internal_error" -- ever yields an
allow.

## Timeout and Input Bounds

The host owns the timeout; the verifier does not implement its own. The host MUST
enforce a wall-clock timeout on the spawned process and treat expiry as deny. The
RECOMMENDED timeout is 10 000 ms (10 s); a conforming verifier targets under 2 s at
the 99th percentile, so 10 s leaves ample headroom. The verifier MUST bound the
request read from stdin; the reference limit is 1 MiB (1 048 576 bytes). A request
over the bound MUST yield "deny code=malformed_input"; the verifier MUST NOT buffer
an unbounded request.

## The Fail-Closed Set

The host MUST treat ALL of the following as deny, regardless of what (if anything)
reached stdout:

- non-zero exit code;
- timeout -- the host MUST kill the process and deny;
- death by signal / crash;
- unparseable, empty, oversized, or multi-object stdout (Section 4.3);
- an unknown "verdict" value or a "deny" missing required fields;
- a verdict that otherwise fails the verdict schema ({{schemas}}) -- including an
  unrecognized "kind" value or any disallowed additional property.

The verifier is designed so these are the only ways it fails ambiguously; every
outcome it can reason about is an explicit "deny" with a "code" (Section 4.2).

# Replay Protection and Reserve-Before-Act

A verifier supports one of two replay modes, selected by the host at spawn time.

- local (default). The verifier owns durable replay state. On an otherwise-allow it
  burns the proof's one-time nonce locally; a second presentation of the same proof
  yields "deny code=nonce_replayed". Suitable for a single-host deployment. If the
  store errors, the verifier MUST fail closed ("deny code=internal_error", non-zero
  exit).
- host. The verifier does not persist nonces. On an otherwise-allow it returns
  "consume_nonces" (Section 4.2), one entry per one-time nullifier the presentation
  carries (the agent nullifier, plus the human-uniqueness nullifier for a
  human-backed bundle), and the host owns durable storage under the
  reserve-before-act rule. This is the mode for multi-host or clustered deployments
  where the host already owns a database.

The agent nonce value is globally unique per (credential, session-nonce), so no
separate operator namespacing is needed; "consume_nonces[].issuer_key" is provided
for host-side bookkeeping only. Delegation hops add no entry: each per-hop
delegation nullifier is bound to the agent's session nonce, so reserving the agent
nullifier already covers delegation replay. The human-uniqueness nullifier for a
human-backed bundle is carried as a second reserved entry, namespaced
"human:NULLIFIER-HASH".

## Reserve-Before-Act (Host Nonce Mode)

When the host runs the verifier in host nonce mode and receives "allow" with
"consume_nonces", the host MUST reserve every entry in the list before performing
the privileged action:

1. For each entry in "consume_nonces", atomically insert "entry.nonce" into durable
   storage with a unique-insert / "on conflict reject" semantic, retaining it until
   "entry.retain_until".
2. If all inserts are novel, proceed with the action.
3. If any insert conflicts (that nonce was already recorded), the host MUST reject
   the action as a replay -- even though the verifier returned "allow".

"Record after proceeding" is a replay window and is FORBIDDEN. The verifier's
"allow" in host mode is conditional on every host insert being novel.

# Host Conformance {#conformance}

The differentiator between this contract and a governance framework is that the
host obligations are mechanically testable. Sections 4, 6, and 7 place the
load-bearing obligations on the host: it owns the timeout, the single-object stdout
parse, the exit-code interpretation, and reserve-before-act nonce consumption. A
verifier that follows the contract is not enough -- a host that trusts a
misbehaving verifier is the actual vulnerability. This section makes those host
obligations testable.

The suite spawns a deliberately misbehaving verifier fixture in place of a real
verifier and asserts that the host-under-test fails closed. A conforming host MUST
deny in every non-positive case below.

## Misbehaving-Verifier Fixtures

The fixtures are small, dependency-free scripts, each violating exactly one contract
obligation. The "Required host outcome" column is the normative behavior a
conforming host MUST produce; the "Class" column is the reference host's canonical
failure classification (Section 8.3). The inventory below is 26 fixtures that drive
27 "host_behavior" vectors, confirmed in "spec/test-vectors.json": the
"allow-consume-nonces.js" fixture drives two vectors (a novel-reserve allow and a
replay deny), so the fixture count is one fewer than the vector count.

| Fixture | Violates | Required host outcome | Class |
|---|---|---|---|
| well-behaved-allow | -- (positive control) | relay allow | -- |
| well-behaved-deny | -- (positive control) | relay deny code=expired | -- |
| well-behaved-allow-kind-classical | -- (positive control, "kind") | relay allow | -- |
| well-behaved-allow-kind-external | -- (positive control, "kind") | relay allow | -- |
| non-json-stdout | stdout not valid JSON | deny | unparseable_stdout |
| multiple-objects | two concatenated verdicts | deny | multiple_objects \| unparseable_stdout |
| schema-invalid-verdict | "verdict" neither allow nor deny | deny | schema_invalid |
| deny-missing-fields | "deny" missing code/message | deny | schema_invalid |
| allow-trailing-garbage | valid allow then trailing bytes | deny | unparseable_stdout |
| binary-garbage-stdout | raw non-UTF-8 bytes on stdout | deny | unparseable_stdout |
| leading-garbage | non-JSON prefix before a valid allow | deny | unparseable_stdout |
| allow-extra-property | closed schema -- disallowed additional property | deny | schema_invalid |
| bad-kind | "kind" outside classical/zk/external | deny | schema_invalid |
| empty-consume-nonces | "consume_nonces" violates minItems:1 | deny | schema_invalid |
| malformed-consume-nonce | nonce entry missing issuer_key/retain_until | deny | schema_invalid |
| deny-extra-property | closed "deny" -- disallowed additional property | deny | schema_invalid |
| nonce-entry-extra-property | nonce entry has an extra property | deny | schema_invalid |
| nonce-entry-wrong-type | nonce entry retain_until not an integer | deny | schema_invalid |
| no-output-hang | no output, never exits | deny (kill on timeout) | timeout |
| partial-json-hang | partial verdict then hangs | deny (kill on timeout) | timeout |
| slow-allow-past-deadline | valid allow, but only after the deadline | deny (kill on timeout) | timeout |
| nonzero-exit-after-allow | valid allow on stdout but non-zero exit | deny (Section 6.2) | nonzero_exit |
| killed-by-signal | death by signal, no verdict | deny | signal_death \| unparseable_stdout |
| oversize-flood | floods stdout past the output bound | deny (bound + kill) | oversize_stdout |
| allow-consume-nonces | -- (drives reserve-before-act) | reserve then allow, or deny on replay | replay on conflict |
| allow-consume-nonces-multi | -- (drives reserve-all) | deny if any entry conflicts | replay on conflict |

The "schema_invalid" fixtures collectively exercise the closed verdict schema at
every level: an unknown "verdict", a "deny" missing "code"/"message", additional
properties on both the "allow" and "deny" objects, a bad "kind", and -- for
"consume_nonces" -- an empty array, a missing required entry field, an extra entry
property, and a wrong-typed entry field. A host that validates only the outer
object, or only a subset of the nonce-entry schema, is therefore caught.

## Host-Under-Test (HUT) Convention

The runner drives any host through a thin, language-neutral convention so a host in
any ecosystem can be tested against the same fixtures. The runner spawns the host
once per vector and communicates as follows.

Environment -- the runner sets, and the host MUST honor:

- "HUT_VERIFIER_CMD" -- a JSON array (argv) the host MUST spawn as its verifier. The
  host MUST NOT substitute a different command.
- "HUT_TIMEOUT_MS" -- the wall-clock timeout the host MUST enforce.
- "HUT_MAX_STDOUT_BYTES" -- the stdout output bound the host MUST enforce; exceeding
  it is a fail-closed condition.
- "HUT_NONCE_MODE" -- "local" or "host".
- "HUT_NONCE_STORE" -- a filesystem path the host uses as its durable nonce store in
  host nonce mode. For the harness only, the store format is newline-delimited
  decimal nonce strings, UTF-8. A production host with a different store tests
  against this suite by pointing a thin test adapter at this file format; the format
  is a test convention, not part of the wire contract.
- "HUT_ACTION_LOG" -- a filesystem path. The host MUST append a non-empty marker at
  the moment it authorizes the action -- after every reservation succeeds and
  immediately before returning "allow" -- and MUST NOT write on any deny. This is
  the observable proxy for the "act" in reserve-before-act.
- "HUT_FIXTURE_PIDFILE" -- a filesystem path the host MUST propagate to the spawned
  verifier so the kill-proof fixtures can record their PID; the runner then confirms
  the host killed the verifier on timeout/oversize. For kill-proof vectors a missing
  pidfile is itself a failure.

stdin -- the runner writes exactly one request object (Section 4.1) to the host's
stdin and closes it. The host forwards this to the verifier.

stdout -- the host MUST write exactly one decision object and exit "0". The
fail-closed signal is the decision object, NOT the host's own exit code; a host
that itself exits non-zero fails the convention. The decision is exactly one of
three closed shapes:

- {"decision":"allow"} -- the verifier allowed (and, in host nonce mode, every nonce
  was reserved as novel); no other key is permitted;
- {"decision":"deny","code":"CODE"} -- a schema-valid verifier "deny", relayed
  unchanged; the host MUST NOT attach a "failure_class" to a genuine verifier deny;
- {"decision":"deny","failure_class":"CLASS"} -- the host itself fail-closed or
  rejected a replay; it MUST NOT also carry a "code".

This decision envelope exists only for the conformance harness; it is NOT part of
the wire contract and imposes nothing on a production host's internal API.

## Host Failure Classes

When a host fails closed, the runner asserts why, using the classification the host
reports in "decision.failure_class". This proves the host detected the specific
violation rather than denying by accident. The normative requirement is always
deny; the failure class is the finer-grained assertion.

| failure_class | Fail-closed condition |
|---|---|
| nonzero_exit | verifier exited non-zero |
| timeout | host timeout fired; host killed the process |
| signal_death | verifier died by an unsolicited signal |
| unparseable_stdout | stdout empty, not JSON, or with trailing bytes |
| multiple_objects | stdout carried more than one JSON value |
| oversize_stdout | stdout exceeded the host output bound |
| schema_invalid | a parsed verdict failed the verdict schema |
| replay | a "consume_nonces" entry was already reserved |
| spawn_error | the host could not spawn or drive the verifier at all |

Because several fail-closed conditions can co-occur for one input, a vector MAY
admit more than one acceptable class. For example, a verifier killed by a signal
both dies by signal and leaves stdout empty. Where a fixture triggers a single
unambiguous condition, the vector pins the single class: a host that denies but
misclassifies it (for example calling an unbounded flood "unparseable_stdout"
instead of enforcing the "oversize_stdout" bound) is flagged, because the
misclassification reveals a real gap.

## Two Independent Reference Hosts and Scope Limits

Two independent reference hosts demonstrate portability: one in JavaScript
("spec/reference-host.js") and one in Rust ("spec/reference-host-rs/", producing an
"evc-reference-host" binary). Both pass the full suite; each is concrete interop
evidence that the host obligations are implementable and testable in more than one
language.

As a black-box harness the suite proves three things about reserve-before-act: the
reservation is durably written (novel case), authorization is gated on the durable
uniqueness check (replay case, the primary guarantee), and every entry is checked
(reserve-all case). It does NOT prove the fine-grained intra-allow-path ordering --
that within a single "allow" the durable write is committed strictly before the
action marker -- because distinguishing "reserve then act" from "act then reserve,
both before returning allow" would require fault injection, which a portable
black-box runner cannot induce. That crash-safety property remains a host
obligation (Section 7); this suite asserts the observable gate, not the write
barrier. Implementers SHOULD additionally cover the crash-window ordering with an
in-process test in their own codebase. Stating this limit openly is deliberate: it
scopes exactly what the conformance claim does and does not cover.

# Wire Versioning

Two version tokens live at different layers with deliberately different rules.

Wire-facing envelopes are integer-major. The host request "version" (Section 4.1)
and the internal bundle version are single integers, negotiated by major only. A
verifier supports a fixed set of wire majors; an unsupported major is
"deny code=unsupported_version". There is no minor/patch at the wire layer: any
breaking change to the request or verdict envelope increments the integer. The
denial-code registry (Section 4.2) is part of the wire contract and is therefore
also governed by the integer-major rule: adding, removing, or renaming a code is a
wire-major change. Embedded proofs carried inside the opaque bundle keep their own
semantic-version string and the verifier's existing major-only compatibility rule.

Additive OPTIONAL fields with a defined default do not bump the wire major. The
verdict "kind" field (Section 5) is OPTIONAL and its absence has a defined meaning
("zk"). Adding it is compatible in the two directions that occur in practice: (i) a
verifier that omits "kind" -- which includes every wire-1 verifier that predates
the field, all of them "zk"-class -- produces verdicts that both pre-revision and
revision-aware hosts accept; and (ii) a revision-aware host accepts those older
no-"kind" verdicts unchanged, reading them as "zk".

The one caveat, stated plainly: the verdict schema is closed
("additionalProperties: false"), so a host validating against the original schema
will reject any verdict that actually carries "kind" -- including a "zk" verifier's
explicit "kind":"zk". The compatibility guarantee is therefore precise rather than
absolute: omitted-"kind" verdicts interoperate in both directions, but any verdict
that emits "kind" requires a revision-aware host. This does not force a wire-major
bump, because the two classes of verifier that would emit "kind" are already paired
with revision-aware hosts: a "zk"-class verifier that must remain interoperable with
a strict pre-revision host SHOULD simply omit the field, and a "classical"- or
"external"-class verifier -- which MUST emit "kind" -- did not exist under the
original wire-1 contract and so is consumed only by revision-aware hosts. A field
that is REQUIRED, or whose omission would change how an existing verdict is
interpreted, would instead remain a wire-major change.

# Relationship to Receipt Signer Discovery

A sibling specification, Receipt Signer Discovery (RSD), defines a
".well-known/bolyra-signers.json" document (an RFC 8615 {{RFC8615}} well-known URI)
that lets a receipt verifier learn which ES256K signer address(es) to accept. It is
relevant to EVC because a "classical"-class verifier that checks signed receipts
MAY consume it to establish which signers it trusts.

RSD is not part of the EVC wire boundary, and a full treatment is out of scope for
this document. Three consumer rules from RSD are pulled into the Security
Considerations (Section 12) because they bear on a verifier's trust configuration:
a consumer MUST fetch over HTTPS, and plain "http://" MUST be rejected except for
loopback addresses (development); a consumer MUST NOT follow redirects; and a
consumer MUST treat any transport or schema failure as a verification failure,
never as "no signer restriction". A separate RSD Internet-Draft, including any
well-known-URI
registration, is deferred past this document (Section 13).

# Relationship to Other Work

## draft-klrc-aiagent-auth-03 (Complementary)

{{I-D.klrc-aiagent-auth}} ("AI Agent Authentication and Authorization",
draft-klrc-aiagent-auth-03, 2026-07-06, Informational) addresses agent
authentication and authorization by leveraging existing standards rather than
defining new protocols. Its Section 7 ("Agent Credentials") adopts the WIMSE
credential formats -- the Workload Identity Token (WIT) and the X.509 Workload
Identity Certificate (WIC); Section 6 addresses agent identifiers (WIMSE
identifiers, potentially SPIFFE IDs); and Section 10 covers authorization via OAuth
2.0 {{RFC6749}} access tokens, including Section 10.3 ("Use of OAuth 2.0 Access
Tokens") on how the "sub" claim carries a delegated subject and Section 10.4.1
("User Delegates Authorization") on delegating authorization to an agent through an
OAuth Authorization Code Grant.

EVC addresses the downstream decision boundary that draft-klrc-aiagent-auth-03 does
not: given a bundle -- which can carry a WIMSE credential or an OAuth access token
inside its opaque "bundle" -- how does a host obtain and enforce a fail-closed
authorization verdict at the point of a privileged action? The framing is that EVC
is the verdict-and-enforcement companion to the identity and authorization layer
that draft-klrc-aiagent-auth-03 assembles from WIMSE and OAuth. A WIMSE/OAuth token
is one possible payload a "classical"-class verifier (Section 5) validates; a
zero-knowledge credential is what a "zk"-class verifier validates. The host contract
is identical either way. The two documents are complementary and operate at
different points in the flow; EVC does not compete with, restate, or depend on the
draft-klrc-aiagent-auth-03 mechanisms.

> **RESOLVED 2026-07-15 (founder):** keep citations as-is; section-number
> re-verification is a MANDATORY pre-submission step. Original note: pin exact
> draft-klrc-aiagent-auth-03 section numbers before
> submit. The numbers above (6, 7, 10.3, 10.4.1) were read from the live datatracker
> version on 2026-07-14. The -03 revision is built on WIMSE (WIT/WIC) plus OAuth
> 2.0, which differs materially from the "Agent Identity Token / client-to-agent
> auth" characterization in the outline (that description tracked the earlier -01).
> Re-verify the section numbers and titles against the -03 text at submission time,
> since datatracker section numbering can shift with each revision.

## draft-pidlisnyi-aps-02 (Related -- Agent Passport System)

{{I-D.pidlisnyi-aps}} ("Agent Passport System", draft-pidlisnyi-aps-02, 2026-07-04)
is a broad governance framework. It defines a DID method "did:aps" using
multibase-encoded Ed25519 public keys, Ed25519-based agent passports, and a
three-signature policy chain (intent, evaluation, receipt) whose receipt signatures
are computed with EdDSA per RFC 8032.

A factual, citable point: draft-pidlisnyi-aps-02 does not define a zero-knowledge or
selective-disclosure verifier class; its signed artifacts are Ed25519-signed and
content-addressed. Its Security Considerations (Section 8) speak to evidence
authenticity rather than disclosure minimization -- for example, that "A valid
receipt signature proves that the issuer attests the receipt's payload; it does not
prove the payload corresponds to external fact."

The positioning is neutral and about altitude, not merit. APS is a full
governance/passport/receipt framework; EVC is the narrow, testable host↔verifier
decision boundary that any such framework needs at the point of enforcement. The
two are complementary: an APS policy-decision engine could be wrapped as an
"external"-class (or "classical"-class) EVC verifier, and in the lane APS does not
define, a "zk"-class verifier adds selective disclosure -- proving authority without
revealing the passport or the underlying attributes. This document does not
characterize APS's disclosure model beyond the factual statement that it defines no
zero-knowledge class.

> **RESOLVED 2026-07-15 (founder):** keep only the citable no-ZK-class claim;
> no stronger characterization in -00. Original note: if the draft is to characterize APS's disclosure model beyond
> "no ZK class," quote the exact draft-pidlisnyi-aps-02 Security-Considerations
> sentence rather than paraphrasing. The Section 8 sentence quoted above was read
> from the live datatracker version on 2026-07-14; re-verify it against the -02 text
> at submission time.

# Implementation Status {#impl-status}

[Note to the RFC Editor: please remove this section before publication, per
{{RFC7942}}.]

This section records the status of known implementations of the contract at the
time of writing, per the process in {{RFC7942}}. Listing here does not imply
endorsement.

## Verifier: bolyra verify (production)

The "@bolyra/cli" npm package (version 0.7.0 at the time of writing) ships
"bolyra verify", a spawnable external verifier implementing the verifier side
of this contract: one JSON request on stdin, one verdict object on stdout,
fail-closed on every malformed, oversized, or unexpected input, with the
denial-code registry of this document. It implements the "zk" and "classical"
verifier classes. Maturity: released, publicly installable.

## Reference hosts (two languages)

Two reference hosts implement the host obligations independently: a JavaScript
host ("spec/reference-host.js") and a Rust host ("spec/reference-host-rs/").
Both pass the host-conformance suite ({{conformance}}): 26 misbehaving- and
well-behaved-verifier fixtures driving 27 "host_behavior" vectors. Maturity:
reference implementations, maintained alongside this document.

## Hosted verifier (preview)

A hosted HTTP mapping of the same contract ("POST /v1/verify", one request
object in, one verdict object out, fail-closed) is operated as a preview for
design partners. It carries no service-level commitment and is not a normative
part of this document; it exists to demonstrate that the contract is
transport-portable. Maturity: preview, access-controlled.

## Independent implementation experience

The maintainer of an unrelated MCP server project (mcp_agent_mail_rust) built
an off-by-default Ed25519 registration-proof gate designed to the v1 contract
boundary, developed without depending on any component of the authors'
implementations. Maturity: shipped in that project, off by default.

# Security Considerations

## Fail-Closed Is the Whole Safety Property

Every ambiguous outcome -- non-zero exit, timeout, signal death, unparseable,
oversized, or multi-object stdout, schema failure, or an unrecognized "kind" -- MUST
result in deny (Section 6). This is the entire safety property of the contract: the
host never proceeds on ambiguity. The host-conformance suite (Section 8) is the
mechanism that makes this claim checkable rather than asserted, spawning
deliberately misbehaving verifiers and confirming the host fails closed. Exit status
dominates a stdout allow (Section 6.2): a non-zero exit is a deny even when a
syntactically valid "allow" reached stdout.

## `kind` Is Unauthenticated Self-Report

A host MUST establish a verifier's proof-system class from configured verifier
identity or policy, never from the "kind" string, and MUST NOT relax trust, verifier
selection, schema validation, or nonce handling on its basis (Section 5). The threat
is a hostile or buggy verifier that claims "kind=zk" to imply privacy guarantees it
did not provide, or that emits an unfamiliar "kind" to probe for a lenient host. An
unrecognized "kind" is a schema failure and MUST fail closed.

## Nonce Reservation and Replay

Reserve-before-act ordering (Section 7) is a load-bearing property. "Record after
proceeding" is a replay window and is FORBIDDEN. On a multi-entry "consume_nonces"
(agent nullifier plus human-uniqueness nullifier), the host MUST reserve every entry
and MUST reject on any conflict. In local nonce mode, a store error MUST fail closed.
The black-box conformance suite proves the observable gate -- that authorization is
conditioned on the durable uniqueness check -- but not the intra-allow-path
write-barrier ordering (Section 8.4); hosts SHOULD cover that crash-window ordering
with an in-process test.

## Redirect and Downgrade in Signer Discovery

For a "classical"-class verifier that consumes a Receipt Signer Discovery document
(Section 11): a consumer MUST fetch over HTTPS, and plain "http://" MUST be
rejected except for loopback addresses (development); a consumer MUST NOT follow
redirects, because a redirect can move the fetch to a plaintext or attacker-chosen
origin after the protocol check; and a consumer MUST treat any transport, status, or
schema
failure as a verification failure, never as "no signer restriction". Discovery is
trust-in-origin, not endorsement and not PKI. When both an out-of-band pinned signer
and a discovery-URL signer source are supplied, a consumer MUST require the two to
agree.

## Output-Bound Truncation and Resource Exhaustion

The stdout output bound and the stdin bound (Section 6.3) bound a hostile verifier
that floods or hangs; the host MUST enforce both and kill on breach. The
"oversize-flood" and hang fixtures (Section 8.1) prove this. A truncated stdout is
unparseable and MUST deny, never yield a partial allow.

## Tail Truncation of Hash-Chained Receipts (Informative) {#tail-truncation}

> **NEW -- draft-only; not in shipped EVC v1 / RSD v1.**

For a hash-chained signed-receipt log that a "zk"- or "classical"-class verifier may
consult, an attacker who can drop the newest entries can mount a tail-truncation
attack: the chain still verifies as a valid prefix, so the verifier sees an older,
shorter-but-consistent history. This is a real property, but it sits below the EVC
host↔verifier boundary -- receipt-chain semantics live in the receipt library, not
in the EVC wire envelope -- so this document states no new normative EVC obligation
here. As guidance a verifier vendor may adopt: a verifier that relies on receipt
ordering should anchor the expected chain tip (a signed high-water mark or a
monotonic counter) out of band and treat a shorter-than-expected chain as a
verification failure. A normative mitigation, if desired, belongs in a dedicated
receipts/RSD companion draft where a MUST can be properly grounded, and would be
referenced from here.

> **RESOLVED 2026-07-15 (founder):** keep informative in -00 (option a);
> companion draft only if chain anchoring becomes its own standards conversation.
> Original note: cross-check the receipt-chain semantics of the "@bolyra/receipts"
> library before finalizing this wording, and decide between (a) keeping this as the
> informative note above, or (b) moving a normative MUST into a receipts/RSD
> companion draft and citing it. The outline's recommendation (task 18/19) is (a):
> keep it informative in this document.

## Domain Separation

The request-binding signature (Appendix B) is domain-separated by a tag that
prevents a binding signature from being replayed as any other signature the
verifier's scheme produces, and vice-versa. This closes a cross-context signature
replay class. The tag is versioned; the binding revision described in Appendix B
uses the ".v2" tag. This consideration applies only to a verifier whose internal
binding follows Appendix B; it is below the EVC boundary (the host never sees the
binding) and is included because Appendix B is retained as informative.

## Binding of Credential Expiry

This consideration applies only to a verifier whose internal binding follows
Appendix B; it is below the EVC boundary (the host never sees the binding) and is
included because Appendix B is retained as informative.

The binding in Appendix B originally signed five fields and did not cover the
credential expiry; that revision is referred to here as binding v1. A verifier whose
proof system does not independently bind expiry -- a "classical"- or
"external"-class verifier (Section 5) -- could therefore be presented a binding whose
signed fields matched an issued mandate while an expiry value drawn from outside the
signature was substituted. A presenter able to re-anchor a later expiry onto an
already-issued mandate could obtain an "allow" past the mandate's intended lifetime,
extending the credential's effective duration. The escalation is bounded: it extends
duration at the already-granted permission tier and audience, and does not permit
tier, audience, or payee escalation. A "zk"-class verifier that binds expiry within
its proof was not exposed to this substitution.

The current binding (binding v2, Appendix B) places "expiry" inside the signed
binding, versions the domain-separation tag to
"bolyra.external-verifier.binding.v2", and, after the signature verifies, requires
the signed "binding.expiry" to equal the credential expiry that the scope and expiry
checks consume; a mismatch is a verification failure ("deny code=invalid_bundle"). A
binding carrying only the earlier five fields is treated as an obsolete binding v1
and rejected as an unsupported version ("deny code=unsupported_version"), with no
compatibility mode and no advisory-expiry fallback. A verifier following Appendix B
therefore signs "expiry" as part of the binding and rejects a five-field binding
rather than accept an expiry that no signature covers. As with Domain Separation
above, this is a property of the reference verifier's internal binding, stated with
the lowercase "must" convention of Appendix B; it is below the EVC wire boundary and
imposes no new normative obligation on the host contract.

## Privacy Considerations

A "zk"-class verifier lets the host authorize an action without learning the agent's
identity or attribute values; this is the selective-disclosure property of
Section 5. EVC bounds what the verifier learns, not what the host already knows: the
request context the host supplies ("agent_name", "project_key", "program", "model",
"granted_capabilities") is host-chosen and may itself be identifying. Implementers
should note this asymmetry -- a privacy-preserving verifier does not make the host's
own request context private -- and minimize identifying content in the request where
the deployment's threat model calls for it.

# IANA Considerations

> **NEW -- draft-only, not in shipped EVC v1.**

## External Verifier Denial Codes Registry

This document requests that IANA create a new registry, "External Verifier Denial
Codes", to catalog the machine-readable denial-code vocabulary of Section 4.2.

- Registry name: External Verifier Denial Codes.
- Registration policy: Specification Required {{RFC8126}}.
- Columns: "code" (the snake_case token); brief description; wire version
  introduced; change controller; reference.

Critical clarification reconciling the registry with the closed wire enum: the
wire denial-code set is a closed enum on the wire. A verifier MUST NOT add, remove,
or rename a code without a wire-major version bump (Section 4.2 and Section 10). The
IANA registry does NOT relax this and does NOT open the enum at runtime. It is a
catalog of the codes each spec version defines: a new registration is admissible
only as part of a published EVC wire-major/spec revision that adds the code, and
each registry entry records the wire version that introduced it. A verifier that
emits an unregistered code is non-conformant exactly as it is today; the registry
changes discoverability, not the closed-set semantics or the version-bump rule.
Third-party ("external"-class) verifiers reuse the existing vocabulary and do not
mint private codes at runtime.

Initial contents: the 15 codes of Section 4.2, each recorded with its meaning, the
wire version that introduced it ("1"), change controller (this document / the EVC
specification), and reference (this document).

## Proof-System Classes: Closed Enum, No Registry Requested

The "kind" value set ("classical", "zk", "external") of Section 5 is deliberately
NOT proposed as an IANA registry. The set is small and closed, and adding a value is
a wire-facing change already governed by the wire-major rule (Section 10). A fixed
enum in the specification is preferable to a registry here; the tradeoff is that a
future proof-system class requires a spec revision rather than a registration, which
is acceptable given how rarely the class set is expected to change.

## Deferred Registrations

- Well-known URI. The Receipt Signer Discovery document
  (".well-known/bolyra-signers.json", Section 11) would need an RFC 8615
  {{RFC8615}} well-known-URI registration, but that belongs to a separate RSD
  Internet-Draft, not this one. It is out of scope for this document.
- Media type. A proof-envelope media type exists in the wider ecosystem but is below
  the EVC boundary (the bundle is opaque); EVC itself defines no new media type. No
  media-type registration is requested.

> **RESOLVED 2026-07-15 (founder):** no media-type registration in -00; revisit
> if the HTTP transport is specified in a later rev. Original note: confirm before submit that the wire request/verdict objects
> receive no structured-suffix or media-type registration for -00. Recommendation
> (outline task): no registration -- the objects are transported over a subprocess
> pipe, not a network media type.

--- back

# Request and Verdict JSON Schemas (Normative) {#schemas}

## Request Schema

~~~ json
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
~~~

## Verdict Schema (Closed)

~~~ json
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
~~~

# Binding Signature (Informative) {#binding}

This appendix describes the request-authorizing signature carried inside a bundle by
Bolyra's "zk"- and "classical"-class reference verifiers. It is included to
illustrate one verifier's internal binding. It is explicitly below the
interoperability boundary: the host never sees these bytes, and a conforming verifier
of any class may use any binding it chooses. Nothing in this appendix is a normative
obligation of the EVC wire contract. The lowercase "must"/"must not" phrasing below
states requirements of the reference verifier implementation, not requirements of
this document; they are not BCP 14 keywords.

The bundle carries a request-authorizing signature that binds the request context to
the cryptographic key the proof commits to. The binding is versioned independently of
the wire envelope; this appendix describes binding v2, in which the credential expiry
is signature-bound. In the reference verifier:

- Canonical payload (binding v2). Let "binding" be the object with exactly the six
  fields "agent_name", "project_key", "program", "model", "capabilities" (a string
  array), and "expiry" (a positive integer, Unix seconds). The canonical payload is
  the sorted-key, compact (no insignificant whitespace) JSON serialization of
  "binding". Object keys must be sorted and array elements (including "capabilities")
  must not be reordered. The verifier compares "capabilities" as a set for
  authorization, but the signed bytes are order-sensitive. "expiry" became part of the
  signed binding in binding v2; the Security Considerations note on expiry binding
  (Section 12) states why.
- Version discrimination is structural, not a declared version field. The reference
  verifier classifies a binding by its exact key set: the six fields above and no
  others. A member outside that set is rejected ("deny code=invalid_bundle") before
  any version is inferred. A well-formed binding carrying only the earlier five fields
  (no "expiry") is an obsolete binding v1 and is rejected
  ("deny code=unsupported_version"); no compatibility mode accepts it. An "expiry"
  that is not a positive integer is rejected ("deny code=invalid_bundle").
- Domain separation. A domain-separation tag prevents a binding signature from being
  replayed as any other signature. The tag is versioned; binding v2 uses the ".v2"
  tag: DST = utf8("bolyra.external-verifier.binding.v2"), and
  dsInput = DST || 0x00 || payload. The single 0x00 byte separates the ASCII domain
  tag from the canonical binding bytes.
- Digest to field element. digest = SHA-256(dsInput) (32 bytes);
  msgField = BigInt("0x" || hex(digest)) mod BN254_FIELD_ORDER, where
  BN254_FIELD_ORDER is
  21888242871839275222246405745257275088548364400416034343698204186575808495617.
- Sign / verify. Sign with EdDSA-Poseidon over BabyJubjub; verify by recomputing
  msgField from the bundle's own "binding" bytes and checking the signature against
  the operator public key the proof commits to. A signing key disjoint from the
  credential is rejected ("deny code=invalid_signature"), closing the cross-signer
  replay class. After the signature verifies, the reference verifier additionally
  requires "binding.expiry" to equal the credential expiry that the scope and expiry
  checks consume, rejecting a mismatch ("deny code=invalid_bundle"); this binds the
  strict-expiry check to the signed value. A verifier consuming a foreign bundle
  recomputes the digest from the bundle's own "binding" bytes and does not trust a
  self-asserted digest.

# Worked Examples (Informative) {#examples}

Each example is a real (stdin request, stdout verdict) pair against the reference
verifier. Requests are abbreviated ("bundle" elided).

## Allow (Local Nonce Mode)

Request:

~~~ json
{ "version": 1, "bundle": "...", "request": {
    "agent_name": "research-bot", "project_key": "/work/acme/research",
    "program": "crewai", "model": "opus-4.1",
    "granted_capabilities": ["fetch_inbox", "send_message"] },
  "now_unix": 1751990400 }
~~~

Verdict (exit 0):

~~~ json
{ "verdict": "allow" }
~~~

## Allow With consume_nonces (Host Nonce Mode)

Same request, verifier spawned in host nonce mode. This agent-only bundle yields a
single entry; a human-backed bundle would add a second "human:NULLIFIER-HASH"
entry. Verdict (exit 0):

~~~ json
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
~~~

The host MUST reserve every entry's "nonce" atomically before acting (Section 7).

## Deny -- scope_exceeded

Request whose credential proves only READ_DATA but whose "send_message" capability
requires WRITE_DATA. Verdict (exit 0):

~~~ json
{
  "verdict": "deny",
  "code": "scope_exceeded",
  "message": "required scope exceeds the credential effective scope",
  "detail": { "required_scope": "2", "effective_scope": "1", "excess_bits": "2" }
}
~~~

## Deny -- model_mismatch

Request whose "model" differs from the model the proof commits to. Verdict (exit 0):

~~~ json
{
  "verdict": "deny",
  "code": "model_mismatch",
  "message": "proven model hash does not match the requested model",
  "detail": { "requestModel": "model-beta" }
}
~~~

## Deny -- malformed_input

Truncated JSON on stdin. Verdict (exit 0):

~~~ json
{ "verdict": "deny", "code": "malformed_input", "message": "request stdin is not valid JSON" }
~~~

## Deny -- internal_error (Fail-Closed, Non-Zero Exit)

No trusted-root source configured. Verdict on stdout AND a non-zero exit code, so the
host fail-closes on either signal:

~~~ json
{ "verdict": "deny", "code": "internal_error", "message": "no trusted root source configured" }
~~~

## Allow -- classical-kind Verifier

A "classical"-class verifier -- for example one that checks an ES256K-signed receipt
and a JWT delegation token {{RFC7519}} rather than a zero-knowledge proof -- returns
the same "allow" envelope, tagged with its "kind". Verdict (exit 0):

~~~ json
{ "verdict": "allow", "kind": "classical" }
~~~

## Deny -- external-kind Verifier

A third-party verifier denies with the shared registry (Section 4.2) and its own
"kind". Verdict (exit 0):

~~~ json
{ "verdict": "deny", "kind": "external", "code": "expired", "message": "credential expired" }
~~~

An agent-only "zk" verdict carries no "kind"; the host reads its absence as "zk".

# Host-Conformance Fixture List (Informative) {#fixtures}

The 27 "host_behavior" vectors and the Host-Under-Test environment variables of
Section 8 are reproduced there as tables. Implementers building or testing a host
should consult Section 8.1 (fixture inventory), Section 8.2 (the HUT convention and
environment variables), and Section 8.3 (failure classes), together with the two
reference hosts at "spec/reference-host.js" and "spec/reference-host-rs/".
