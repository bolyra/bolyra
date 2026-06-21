# Conformance Test Vectors v3 — Design Document

**Date:** 2026-06-21
**Author:** PDLC Orchestrator + Codex review
**Status:** APPROVED

## 1. Motivation

The existing conformance suite (`spec/test-vectors.json` v0.3.0) has 48 vectors across 6 categories, all passing via `conformance-runner.js`. It covers ZKP circuit behavior (handshake, delegation, enrollment, Merkle inclusion, signature verification) but lacks:

- A formal JSON Schema that third-party implementors can validate against
- Coverage for SD-JWT delegation receipts (shipped in bolyra v0.5.0)
- Coverage for proof envelopes (wire format proposal from protocol autoresearch)
- Coverage for session tokens (experimental, not yet implemented)
- Normative prose for semantic/stateful requirements the schema cannot express

This upgrade makes Bolyra's conformance suite an executable interop spec that external teams can consume without reading source code.

## 2. Audience

Third-party implementors first. Our own CI consumes the same format. The schema IS the contract — if your implementation passes all vectors against the schema, you're conformant.

## 3. Version

**0.4.0** (not 1.0.0). Session token vectors are experimental (not yet implemented). Promote to 1.0.0 after implementation validates them. Per Codex review: don't stamp a stable contract on unimplemented features.

## 4. Schema (`spec/conformance-schema.json`)

JSON Schema draft 2020-12. Defines the vector format:

```
{
  "version": "0.4.0",
  "vectors": [
    {
      "id": "string (kebab-case, unique)",
      "description": "string",
      "type": "enum: handshake | delegation | delegation_chain | enrollment | merkle_inclusion | signature_verification | sd_jwt | proof_envelope | session_token",
      "status": "enum: stable | experimental (default: stable)",
      "inputs": { ... per-type sub-schema },
      "expected": { ... per-type sub-schema }
    }
  ]
}
```

Per-type input/expected shapes use `if/then` composition keyed on `type`. The `status` field defaults to `"stable"`. Session token vectors use `"status": "experimental"`.

## 5. New Vector Categories

### SD-JWT (`sd_jwt`, ~8 vectors, status: stable)

SD-JWT delegation receipts are implemented and shipped (bolyra v0.5.0, pure Python).

| Vector ID | Expected | Tests |
|---|---|---|
| sd-jwt-valid-issuance | PASS | Valid allow() + present() round-trip |
| sd-jwt-expired-receipt | FAIL | Receipt past exp timestamp |
| sd-jwt-wrong-audience | FAIL | Presented to wrong audience |
| sd-jwt-missing-nonce-production | FAIL | No nonce in production mode |
| sd-jwt-nonce-replay | FAIL | Same nonce used twice |
| sd-jwt-max-amount-exceeded | FAIL | Amount > max cap |
| sd-jwt-selective-disclosure | PASS | Reveal action, hide amount |
| sd-jwt-jti-uniqueness | PASS | Two receipts have distinct JTIs |

### Proof Envelope (`proof_envelope`, ~6 vectors, status: stable)

Wire format for carrying ZKP proofs with metadata. Defines the envelope structure that adapters serialize/deserialize.

| Vector ID | Expected | Tests |
|---|---|---|
| envelope-valid-handshake | PASS | Valid envelope with content-type + proof bytes |
| envelope-missing-required-field | FAIL | Envelope without proof_type |
| envelope-malformed-proof-bytes | FAIL | Invalid base64 in proof field |
| envelope-unknown-fields-forward-compat | PASS | Extra fields preserved, not rejected |
| envelope-cross-circuit | PASS | Handshake + delegation proofs in one payload |
| envelope-empty-public-signals | FAIL | Public signals array empty |

### Session Token (`session_token`, ~5 vectors, status: experimental)

Off-chain JWT session tokens derived from a verified handshake. NOT YET IMPLEMENTED — vectors define the expected format spec-first.

| Vector ID | Expected | Tests |
|---|---|---|
| session-valid-jwt | PASS | Valid JWT from handshake result |
| session-expired | FAIL | Token past exp timestamp |
| session-scope-narrowing | PASS | Delegation narrows scope, token reflects it |
| session-missing-nullifier-binding | FAIL | Token without nullifier claim |
| session-nonce-replay | FAIL | Stale nonce reused |

## 6. Normative Prose (CONFORMANCE.md additions)

Per Codex review, add semantic requirements the JSON Schema cannot express:

- **Nonce replay:** A conformant implementation MUST reject a handshake proof that reuses a sessionNonce seen in any prior verified handshake within the same scope.
- **Token replay:** A session token MUST be rejected if its nonce has been consumed by a prior verification within the token's audience scope.
- **Vault JTI uniqueness:** SD-JWT issuers MUST generate globally unique JTI values. Collision constitutes a conformance failure.
- **Audience binding:** An SD-JWT receipt presented to an audience not matching the `aud` claim MUST be rejected, even if the signature is valid.
- **Nullifier binding:** Session tokens MUST include the humanNullifierHash from the originating handshake. Tokens without this binding are non-conformant.
- **Forward compatibility:** Implementations MUST preserve unknown fields in proof envelopes without error. Rejecting unknown fields is a conformance failure.

## 7. Runner Upgrade (`spec/conformance-runner.js`)

- Add `--validate-schema` flag: runs `ajv` validation against `conformance-schema.json` before executing vectors
- New handler functions for `sd_jwt`, `proof_envelope`, `session_token` types
- `session_token` handler: skip with `SKIPPED (experimental)` until implementation exists
- Exit codes: 0 = all pass, 1 = test failures, 2 = schema validation error
- `--skip-experimental` flag to exclude experimental vectors from the run

## 8. Files

| File | Action |
|---|---|
| `spec/conformance-schema.json` | New — JSON Schema draft 2020-12 |
| `spec/test-vectors.json` | Update — add ~19 vectors, bump to 0.4.0 |
| `spec/conformance-runner.js` | Update — schema validation, new handlers |
| `spec/CONFORMANCE.md` | Regenerate + normative prose section |

## 9. Out of Scope

- Language-specific test stub generation (future, layers on top)
- IETF appendix formatting (future, when draft engagement materializes)
- Cross-chain vectors (protocol autoresearch candidate, not mature enough)
- Nullifier domain separation vectors (circuit-level, already covered by existing vectors)
