# Scope-bound authorization at a verifying relying party: a hypothetical walkthrough (2026-10-03)

**Status.** Explanatory document. It describes what a relying party that verifies operator-signed
authorization can and cannot enforce, using the published Bolyra verifier as the worked example.
It makes **no claim about any real incident**: nothing here states or implies what would have
happened in any system that was actually breached, because the controls, network position and
configuration of those systems are not known to the authors. Mechanics are cited to `origin/main`
at `5b0ab459`. The authorization scenes in §4.1 and §4.2 are runnable in `examples/gov-stats-portal`.

## 1. The question

A relying party serving protected data needs to decide whether an operator authorized the
requested capability for its configured audience. This hypothetical walkthrough examines what the
published verifier checks under explicit assumptions, and what remains outside that boundary. It
makes no assessment of any real incident.

## 2. Assumptions (the hypothetical)

Everything in §3 and §4 depends on all of these holding. Where one does not hold, §5 applies.

- **A1. The relying party verifies.** The system serving the request runs an EVC verifier
  (`spec/external-verifier-contract-v1.md`) on every request to a protected route and honors a
  denial. A route that does not verify is unaffected by anything below.
- **A2. Deny by default.** A request without a presentation is refused before any data is served.
  Verification only constrains agents that present a credential; the relying party's own policy
  is what refuses the ones that do not.
- **A3. The operator issued a scoped binding.** A human or organization signed an EVC binding v2
  naming exactly `{agent_name, project_key, program, model, capabilities, expiry}` under the
  domain-separation tag `bolyra.external-verifier.binding.v2` (§4.1). The capability list is the
  operator's statement of what the agent may ask for, for example `["read:public-stats"]`.
- **A4. The relying party supplies its own audience and policy.** `request.project_key` is the
  relying party's own identity string, never copied from the inbound request; the route policy
  (which capability a route requires) and the capability map (which permission bits a token
  needs) are the relying party's configuration.
- **A5. The zk path proves the credential's permission bits.** The classical path authenticates
  a trusted operator's signature over the binding; it does not independently authenticate the
  revealed permission ceiling. §5.6 states what each path does and does not establish.
- **A6. Nonce handling is in place.** For the zk walkthrough, nonce handling rejects repeat use
  while the consumed nullifier remains in the applicable replay store (§8 of the contract). The
  CLI caps retention at 30 days in both modes; host mode requires reserve-before-act. The
  published MPP classical verifier does not itself consume nonces.

## 3. The boundary: one question, checked in a fixed order

Under A1 to A6 the relying party asks the verifier one question per request: *did an
operator-signed binding authorize THIS agent, for THIS capability, at THIS audience?* The published
zk verifier (`@bolyra/cli` 0.9.0, `integrations/cli/src/verify/core.ts` L321–370) answers it in
this order after the proof, root, scope-commitment and binding-signature checks pass:

1. the request's literal binding fields (`agent_name`, `project_key`, `program`, `model`) must
   equal the signed ones byte for byte (`request_mismatch`);
2. every requested capability must appear in the signed `capabilities` (`request_mismatch`);
3. the requested model must match the proven model hash (`model_mismatch`);
4. every requested capability must have a mapping (`unknown_capability`, fail-closed);
5. the mapped permission bits must be a subset of the credential's effective scope
   (`scope_exceeded`);
6. `now_unix` must be strictly less than the effective expiry, including any delegation
   attenuation (equality is expired);
7. replay handling on the agent nullifier.

Each denial names a code from the registry (§9) and no data is served. Separately, a relying
party can record verdicts in signed, hash-chained decision receipts (`@bolyra/receipts`, §4.3).

## 4. Walkthrough

`examples/gov-stats-portal` runs the authorization scenes in §4.1 and §4.2 against the published
verifier. §4.3 describes the separate receipts package, used by the gateway and the MPP gate; the
portal example does not emit receipts. P1 is a presentation whose binding names `read:public-stats` only; P2 names `read:public-stats`
and `read:internal-files`. Both are bound to the audience `https://stats.example.gov`. The
portal's policy is `/public/stats` requires `read:public-stats` and `/internal/files` requires
`read:internal-files`; its map is `read:public-stats → READ_DATA` and
`read:internal-files → READ_DATA, ACCESS_PII`. "allow" is the verdict, not a code.

### 4.1 An agent authorized for public statistics asks for non-public files

| Situation | What the verifier sees | Verdict |
|---|---|---|
| P1 at `/public/stats` | `read:public-stats` is in the binding, maps to `READ_DATA`, and bit 0 is inside the proven bitmask `3` | allow, 200 |
| P1 at `/internal/files` | the route requires `read:internal-files`; the signed binding does not name it | `request_mismatch` (`field: granted_capabilities`), 403 |
| P2 at `/internal/files` | the binding names it, but `ACCESS_PII` (bit 7) is not inside the proven bitmask `3` | `scope_exceeded` (`required_scope 129`, `effective_scope 3`), 403 |

What this constrains: under the stated route policy and capability map, P1 and P2 are denied
access to `/internal/files`, regardless of why the agent requested it. The second row is a check
against the operator's signed statement; the third is a check against the proof itself, which is
the one place a signature cannot grant more than the credential carries. Neither row depends on
the agent's cooperation, its prompt, or how many other controls it worked around on the way.

What this does not constrain: a route that is not behind the verifier (§5.1), and a binding the
operator chose to sign too broadly (§5.4).

### 4.2 A credential issued for one audience is presented at another

| Situation | What the verifier sees | Verdict |
|---|---|---|
| P1 at a second portal whose configured audience is `https://internal.example.gov` | the portal put its own audience in `request.project_key`; it differs from the signed `project_key` | `request_mismatch` (`field: project_key`), 403 |

What this constrains: a presentation bound to one audience carries no valid authorization at a
different verifying audience. The comparison is literal, with no path canonicalization (§2.1 of the
contract), so `https://stats.example.gov/` with a trailing slash is a third audience, not the
first one.

What this does not constrain: an audience is an identity string the relying party claims for
itself. The verifier does not establish that the string names the host actually serving the
request (§5.3). If a credential is issued with the audience of a test environment and the test
environment turns out to be reachable from the internet, the credential is still valid *at that
audience*; what it lacks is validity at any other verifying audience.

### 4.3 After the fact: what the record contains

A relying party that signs decision receipts (the gateway and the MPP gate do; the portal
example does not) records, per decision: the issuer and key that signed the receipt, the time,
the recorded credential and effective commitments, the allow/deny result with an optional reason
code, the permission bitmask, the proof hashes, and, when hash-chained, the sequence position and
previous receipt hash (`integrations/receipts/src/types.ts` L20 onward). Receipt fields do not by
themselves establish verified credential attribution. The gateway may retain submitted
commitments, derived DIDs and proof hashes for a rejected but usable bundle; without a usable
bundle, it records anonymous DIDs, zero commitments and placeholder proof inputs
(`integrations/gateway/src/receipt-signer.ts` L172, L203). The MPP gate uses placeholder
credential fields when parsed bundle metadata is unavailable, but may still record an acting DID
derived from the request's agent name (`integrations/mpp-payments/src/receipts.ts` L191). Chain
verification detects deletion from the
beginning or middle of the log and reordering; detecting truncation at the tail requires an
externally known receipt count or head hash (`integrations/receipts/src/chain.ts` L112).

What this constrains: when the relying party successfully signs and retains a receipt, it has a
signed record of the decision time and the recorded credential references, made at decision time
rather than when someone later notices.

What this does not constrain: a receipt identifies a credential commitment and DIDs, not a person
or company; mapping a key to a legal identity is the relying party's or the operator's registry
problem, outside the protocol. A receipt is also evidence held by the relying party. It notifies no
one. Any disclosure timeline is still a human process.

## 5. What remains unprotected

This section is the point of the document. Each item is a way the assumptions in §2 fail.

### 5.1 Endpoints that do not verify (A1, A2)

An unauthenticated endpoint checks nothing, and a weak password protecting an endpoint is checked
by that endpoint's own login, not by a verifier. Verification changes the behavior of exactly the
routes it is wired into. It does not reduce the attack surface of the routes it is not wired into,
and it does not make an agent *carry* a credential: an agent that never presents one is handled
entirely by the relying party's default-deny policy (A2), which is ordinary access control.

### 5.2 Activity at systems that are not relying parties (A1)

Authorization bound to one audience says nothing about what the agent does elsewhere. If the agent
can reach a package registry, a third party's server, or a second internal system, and that
system does not verify, the credential neither permits nor prevents the action. Confinement of an
agent's overall activity is a sandboxing and network problem, not an authorization one.

### 5.3 What an audience string does and does not establish (A4)

`project_key` is compared literally against whatever the relying party configured. Neither
verification path establishes DNS ownership, TLS identity, or that the configured string
corresponds to the network host serving the request. Two relying parties can claim the same
string. The protection in §4.2 is "a credential for audience X is invalid at a verifier that
claims audience Y"; it is not "a credential for X can only be used by the true owner of X".

### 5.4 Issuance quality (A3)

The operator decides the binding. An overly broad binding, one that names every capability or an
audience wider than the task, can pass signature verification; requests it covers may be allowed
if all remaining verifier checks pass. In the zk
path the proven bitmask caps what the binding can grant (§4.1, third row); in the classical path
there is no independent cap beyond the trusted operator's own signature. The published classical
verifier in `@bolyra/mpp` 0.7.0 additionally evaluates only the fixed payments capability map, so
today a non-payment capability such as `read:public-stats` is enforceable through the zk CLI and
the hosted preview, not through that package. These limits are itemized in
`docs/superpowers/specs/2026-10-03-resource-scoped-authorization-gap.md`.

### 5.5 Resource granularity (A4)

Binding v2 has no dedicated resource field and no path, method or origin matching. A capability
token means whatever the relying party's policy says it means; "`read:public-stats` covers
`/public/stats` and nothing else" is a configuration the relying party owns, and a mistake there
is a relying-party mistake the verifier cannot see.

### 5.6 What the two verification paths establish (A5)

The classical path authenticates a trusted operator's signature over the six binding fields,
checks the requested capability subset, and enforces the signed expiry; its revealed permission
mask is a consistency check, not independent evidence of a ceiling. The zk path additionally
anchors the bitmask, model hash and expiry in a Groth16 proof. Neither establishes the model that
is actually running, real-world operator identity, or anything about the agent's reasoning.

### 5.7 Not covered by the example (A6 and beyond)

Revocation, delegation, human proofs and host-nonce mode (reserve-before-act) exist in the
protocol but are not exercised in `examples/gov-stats-portal`. The example also discloses that its
bindings are signed with a publicly known test key, so it demonstrates relying-party enforcement
and not operator identity.

## 6. Summary

Under the assumptions in §2, a verifying relying party can refuse, before serving protected data,
a request that an operator did not authorize for this capability at this audience, regardless of
how the agent arrived at the request, and, if receipt recording is configured and succeeds, retain
a signed decision record. Everything outside those assumptions
is unchanged: routes that do not verify, systems that are not relying parties, the gap between an
audience string and a real host, the operator's own issuance choices, and the agent's behavior
everywhere else. The honest scope of this control is "where the relying party verifies", and the
work of making that true for a given system is ordinary integration work, not a property of the
protocol.

## 7. Where to look

- Contract: `spec/external-verifier-contract-v1.md` (§2.1 request, §4 binding, §9 denial codes).
- Runnable scenes: `examples/gov-stats-portal` (disclosure section first).
- What is and is not scoped today: `docs/superpowers/specs/2026-10-03-resource-scoped-authorization-gap.md`.
- Receipts: `integrations/receipts/README.md`.
