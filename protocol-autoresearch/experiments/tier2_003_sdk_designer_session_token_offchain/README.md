# Experiment: SD-JWT Session Token for Off-Chain Proof Reuse

**ID:** `sdk_designer_session_token_offchain`  
**Persona:** SDK Designer  
**Dimension:** Adoption  
**Priority:** High

## Summary

After a successful mutual ZKP handshake, emit an SD-JWT (Selective Disclosure
JWT) session token encoding the verified nullifiers, scope commitment, and
expiry. Subsequent API calls present the compact token instead of re-running
the full ZKP verification (~2 s → <1 ms).

## Artifacts

| File | Type | Description |
|---|---|---|
| `spec/session-token-sd-jwt.md` | Spec | SD-JWT claim schema, signing conventions, lifecycle |
| `sdk/src/session.ts` | SDK | `issueSessionToken()` and `verifySessionToken()` (TS) |
| `sdk/src/index.ts` | SDK | Public API re-exports |
| `sdk-python/bolyra/session.py` | SDK | Python mirror of TS session API |
| `sdk-python/bolyra/__init__.py` | SDK | Python public API exports |
| `sdk/test/session.test.ts` | Test | TS unit tests (Mocha/Chai) |
| `sdk-python/tests/test_session.py` | Test | Python pytest suite |
| `sdk/QUICKSTART.md` | Docs | Usage guide with latency comparison |

## Key Design Decisions

1. **HMAC-SHA256 by default** — simpler than EdDSA for same-service
   issuer/verifier pattern. EdDSA recommended for federated verification.
2. **SD-JWT format** — follows draft-ietf-oauth-selective-disclosure-jwt.
   Disclosures use 128-bit random salts + SHA-256 digests.
3. **No external deps** — uses Node.js `crypto` module directly instead of
   `jose` or `sd-jwt-vc` to keep the SDK dependency-light.
4. **Cross-language interop** — camelCase claim names in wire format,
   snake_case function names in Python. Tokens are interchangeable.
5. **Opt-in API** — session tokens don't change existing `proveHandshake` /
   `verifyHandshake` flow. Developers explicitly call `issueSessionToken()`.

## Running Tests

```bash
# TypeScript
cd sdk && npm test

# Python
cd sdk-python && pytest -v tests/test_session.py
```
