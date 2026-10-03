# Resource- and domain-scoped authorization claims: what exists, what is missing (2026-10-03)

**Question.** Can a Bolyra credential say "this agent may do THIS kind of thing at THIS audience",
and can our verifiers enforce it?

**Short answer.** The operator-signed EVC binding already carries an audience (`project_key`) and
named capability tokens, and both the published zk verifier and the hosted preview verifier
enforce them against a host-supplied capability map. The gaps are narrower than "no scoping":
there is no supported high-level API that assembles a non-payment EVC presentation; the published
classical verifier in `@bolyra/mpp` evaluates only a fixed payments map; EVC binding v2 has no
dedicated resource field and no standardized path, method or origin matching; and the normative
text for capability mapping points at a document that is not on `main`. This note records the
audit and states the contract that would close the gaps. It is a design note, not a plan or a
commitment.

Line numbers are from `origin/main` at `0d9ee2ee`. Surfaces audited: the TypeScript SDK, the EVC
binding and its two EVC-class verifiers (zk CLI, hosted preview), the published classical verifier
and gate in `@bolyra/mpp`, the gateway/MCP bundle path, and the JWS delegation package. The Python
SDK's SD-JWT issuance and audience verification (`sdk-python/bolyra/sd_jwt.py` L217) is noted but
excluded from this audit.

## 1. What exists today

### 1.1 Two different credentials

- The **SDK agent credential** (`@bolyra/sdk` 0.6.1, `createAgentCredential`,
  `sdk/src/identity.ts` L102–126) signs `poseidon5(modelHash, Ax, Ay, bitmask, expiry)`. It
  carries permission bits and an expiry; no audience, no capability, no resource.
- The **EVC presentation binding** (binding v2) is a separate operator signature over exactly
  `{agent_name, project_key, program, model, capabilities, expiry}` under DST
  `bolyra.external-verifier.binding.v2` (`spec/external-verifier-contract-v1.md` §4, L341–343,
  L376–377). This is where scoping lives.

### 1.2 Scoping claims in binding v2

- **`project_key` is the audience.** The host's `request.project_key` is "compared literally,
  byte-for-byte, against the bundle's signed binding. The verifier MUST NOT apply path
  canonicalization" (§2.1 L88–91); mismatch → `request_mismatch`. The MPP gate fills it from its
  configured `audience`, never from the request (`integrations/mpp-payments/src/gate.ts`
  L415–422). The x402 profile reads it as the payee identity (`spec/x402-evc-profile-v0.md` §4.2).
- **`capabilities` are named, host-defined tokens.** "Opaque strings that the verifier maps to its
  internal permission model" (§2.1 L94–97). `granted_capabilities` ⊆ `binding.capabilities` or
  `request_mismatch`; an unmapped token → `unknown_capability` (fail-closed); a mapped token whose
  bits exceed the proven or asserted scope → `scope_exceeded` (§9 L589–592).

### 1.3 Verifiers that evaluate these claims

| Surface | Audience (`project_key`) | Host-defined capability map | Notes |
|---|---|---|---|
| zk CLI, `@bolyra/cli` 0.9.0 `bolyra verify` | literal compare | `--capability-map`, merged over a built-in default of `fetch_inbox`, `send_message`, `read_message`, `broadcast`, `list_agents` (`integrations/cli/src/verify/capabilities.ts` L33–39, L75–116) | requires real Groth16 proofs; vkeys/roots are not in the tarball |
| hosted preview, `integrations/hosted-verify` | literal compare (`src/verify/core.ts` L279) | custom map via config (`src/verify/capabilities.ts` L49) | not a published package; design-partner preview |
| classical, `@bolyra/mpp` 0.7.0 `verifyClassical` | literal compare (`src/classical.ts` L194–204) | **fixed**: `mpp:financial:{small,medium,unlimited}` only (`src/tiers.ts` L41–45, L132–146); any other token → `unknown_capability` | `bolyraGate` always requests an `mpp:financial:*` capability derived from the route amount (`gate.ts` L415–422) |
| gateway/MCP, `@bolyra/gateway` 0.6.0 | none | none | a different bundle format (`integrations/mcp/src/types.ts` L51, `BolyraProofBundle`, no binding or binding signature); policy is per-tool bitmask, score and chain depth; a tool with no entry gets no additional tool-policy restriction after authentication (`integrations/mcp/src/verify.ts` L483). Not an EVC verifier. |
| delegation, `@bolyra/delegation` 0.2.3 | `aud`, required by the v0.2 verifier (`audience`, `trustedIssuers`, `kbNonce`; options `delegation/src/types.ts` L260–288, enforcement in `src/verify.ts`) | `act`/`perm` claims, checked only when the verifier requests them (`src/verify-claims.ts` L26) | JWS/SD-JWT with Ed25519 issuers; a parallel classical mechanism, not integrated with the EVC binding or the zk proof |

### 1.4 The zk verifier's late authorization checks

After proof, root, scope-commitment and binding-signature checks: binding fields literal →
capability subset → model-hash match → map → bits ⊆ effective scope → effective expiry → replay
handling (`integrations/cli/src/verify/core.ts` L323–377). In local nonce mode the verifier
consumes nullifiers itself; in host mode it returns `consume_nonces` obligations the host must
reserve before acting. In local mode, delegation processing can consume nonces earlier in the
pipeline.

### 1.5 Issuance

- `issueMandate` (`@bolyra/mpp`, `integrations/mpp-payments/src/issue.ts` L163–166, L392–400)
  signs binding v2 with `capabilities` fixed to the cumulative `mpp:financial:*` set for a tier.
  The lower-level assembler that takes an arbitrary binding is module-exported but deliberately
  absent from the package's public index (`src/index.ts` L24–27).
- `bolyra mandate issue` is tier-only (`integrations/cli/src/commands/mandate-issue.ts` L35–58).
- The primitives are public: `eddsaSign` and `bindingDigest` are exported, which is how
  `examples/gov-stats-portal` assembles a non-payment presentation (by re-signing a repository
  test vector under the publicly known test private key `42n`).
- `@bolyra/delegation` issues audience- and action-scoped credentials today, in its own format.

## 2. What the two paths establish (and do not)

- **Classical path.** Authenticates a trusted operator's signature over the six binding fields,
  checks the requested capability subset, and enforces the signed expiry. The revealed permission
  mask and recomputed commitments are consistency checks, not cryptographic evidence of an
  independently authorized bit ceiling (`integrations/mpp-payments/src/classical.ts` L9).
- **zk path.** Additionally anchors the bitmask, model hash and expiry in a Groth16 proof, so a
  signature cannot grant permission bits the proof does not carry (`scope_exceeded`).
- **Both.** Enforcement happens only at a participating relying party that supplies authoritative
  audience and capability requirements and honors a denial. An audience string is an identity the
  relying party claims for itself; neither path establishes DNS ownership, the actually running
  model, real-world operator identity, or any confinement of the agent's other activity.

## 3. The gaps, precisely

| # | Gap |
|---|---|
| G1 | **No supported high-level API assembles a non-payment EVC presentation.** `issueMandate` is tier-only; the arbitrary-binding assembler is not on the public index; `createAgentCredential` produces the proof-side credential, not the binding. The primitives exist, so today this means composing them by hand. |
| G2 | **The published classical verifier evaluates only the fixed payments map.** `verifyClassical` takes no map and `bolyraGate` always requests a financial tier, so `@bolyra/mpp` cannot allow `read:public-stats` even when the operator signed it. The zk CLI and the hosted preview do not share this limitation. |
| G3 | **No dedicated resource field and no standardized path, method or origin matching in binding v2.** Audience identifiers and capability tokens are signed and can name individual resources, but their meaning (which routes, which methods) is supplied by the relying party, and by design there is no URL normalization (`https://a.gov` and `https://a.gov/` are different audiences). The x402 profile adds a resource context and resource-to-signed-product checks (`spec/x402-evc-profile-v0.md` L77; `integrations/payment-protocols/src/x402-issuer-quote/index.ts` L321), but `resource` is not part of the operator-signed EVC binding. |
| G4 | **Hidden map composition.** The zk CLI merges its built-in default map under any host map (`integrations/cli/src/verify/capabilities.ts` L75), and the hosted preview shares the pattern: tokens omitted from the supplied map remain mapped through built-in defaults. Allowing them still requires host-requested capability coverage in the signed binding and sufficient scope, so this is a surprise, not a bypass. (Different hosts assigning different meanings to the same token is permitted by the host-defined model and is not a defect.) |
| G5 | **Dangling normative reference.** The EVC spec cites `docs/superpowers/specs/2026-07-08-external-verifier-cli-design.md` for the supplementary capability-map definition and implementation behavior (L14, L49, L97, L828); that document is not on `main`. The spec itself does define the mapping, subset and denial obligations; the supplementary material is what is missing. |
| G6 | **Published conformance vectors cover neither `request_mismatch` for audience nor `unknown_capability`** (`spec/test-vectors.json`); the CLI's own end-to-end tests exercise both (`integrations/cli/test/verify.e2e.test.ts` L211 onward), but outside implementers cannot rely on a published vector. |

## 4. The contract that would close G1, G2, G5 and G6 (and G4 on the proposed surface only)

Contract-level only: fields, outcomes, compatibility requirements and conformance cases. Not an
implementation recipe, not a release order. Ordered by leverage.

1. **Clarify guarantees and resource semantics in the spec** (G3, §2 above). State that resource
   scoping is expressed as capability tokens: the relying party's policy associates resources and
   actions with required capability tokens, and its capability map translates those tokens into
   permission bits (a `{token: [PermissionName]}` map does not itself describe routes, methods or
   origins); keep literal audience comparison and no built-in URL matching as the intended model;
   state what classical and zk verdicts do and do not establish, as in §2.
2. **Repair the normative references** (G5): maintained public specification text for the
   capability-map rules, cited from the four locations. The missing design document should not be
   restored without reviewing its contents against the public-moat boundary.
3. **General classical verification and high-level EVC issuance, specified together with
   conformance cases** (G1, G2, G6):
   - *Verification contract.* A classical verifier accepts an optional host capability map
     (`{token: [PermissionName]}`). With no map, behavior is unchanged (the payments map). With a
     map, the map **replaces** the default unless the host explicitly opts into composition
     (this prevents implicit composition on the proposed classical surface only; the existing
     CLI and hosted-preview composition remains deferred); an invalid map is a configuration
     failure (`internal_error`),
     never an allow. Every requested token still requires signed coverage in the binding, then a
     mapping, then a scope check, in that order, with the existing codes.
   - *Issuance contract.* A high-level API assembles an EVC presentation from: operator private
     key, `agent_name`, `project_key` (audience), `program`, `model`, `capabilities` (non-empty
     tokens), the permission set the credential asserts, `expiry`, and the capability map the
     issuer considers authoritative, from which the asserted permission set must cover every
     named token (cumulative-bit validity is checked separately from any payments naming). An
     optional nonce is unsigned correlation metadata, not replay protection. The audience
     identifier restriction (`AUDIENCE_IDENTIFIER_PATTERN`) is an issuance/profile rule; generic
     EVC accepts broader strings. A classical presentation carries a placeholder proof and is
     rejected by the zk verifier; a zk presentation requires proving.
   - *Conformance cases* for the published vector set: wrong audience → `request_mismatch`;
     capability not in the signed binding → `request_mismatch`; signed-but-unmapped token →
     `unknown_capability`; mapped token exceeding scope → `scope_exceeded`; classical placeholder
     proof presented to the zk verifier → rejected; legacy behavior preserved when no map is
     supplied.
4. **Advisory token naming**: a suggested `<namespace>:<verb>:<object>` shape and a
   recommendation that hosts declare every token they grant. Advisory only (it does not close
   G4); no grammar is
   enforced, since enforcement would reject existing tokens (including the CLI's underscore
   names). Namespace reservation and any change to the CLI's default map are deferred and would
   need their own migration.

**Deferred, explicitly:** gateway/MCP integration with the EVC binding (a different bundle format;
an audience-enforcing mode there would have to deny bundles without a binding, and the unlisted-
tool default is a separate policy question); generalizing the payment gate beyond financial
capabilities (a payment route must keep its financial requirement); per-hop attenuation of
audience or capabilities in delegation (current SDK delegation narrows permission bits and expiry
only); unifying the JWS delegation package with the EVC binding.

## 5. Non-goals

No hosted policy service, no capability registry, no change to the circuits or the binding DST, no
URL normalization, no change to the delegation package's JWS model.

## 6. Acceptance for the contract in §4.3

- A relying party outside payments obtains a presentation for `read:public-stats` at its audience
  through the high-level issuance API with a **fresh operator key**, and the published classical
  verifier allows it with a host map, denies it at another audience (`request_mismatch`), denies
  an unsigned capability (`request_mismatch`), denies a signed-but-unmapped token
  (`unknown_capability`), and rejects the classical placeholder on the zk verifier. This is a
  separate classical example with fresh keys; `examples/gov-stats-portal` keeps its test-vector
  proof and its public-test-key disclosure as long as it depends on that proof, because a fresh
  operator key cannot authenticate the fixture's existing proof.
- The six conformance cases above exist in the published vector set.
- The EVC spec's four references resolve to maintained text.

## 7. Sources audited

`sdk/src/identity.ts`, `sdk/src/delegation.ts`, `spec/external-verifier-contract-v1.md` (§2.1, §4, §9,
§12), `spec/x402-evc-profile-v0.md`, `integrations/cli/src/verify/{core,binding,capabilities}.ts`,
`integrations/cli/test/verify.e2e.test.ts`, `integrations/mpp-payments/src/{classical,tiers,issue,gate,index}.ts`,
`integrations/hosted-verify/src/verify/{core,capabilities}.ts`, `integrations/gateway/src/{middleware,types}.ts`,
`integrations/mcp/src/{verify,types}.ts`, `integrations/payment-protocols/src/x402-issuer-quote/index.ts`,
`delegation/src/{types,verify-claims}.ts`, `sdk-python/bolyra/sd_jwt.py` (noted only),
`examples/gov-stats-portal`.
