# Experiment: JWT-Encoded Off-Chain Session Token

**ID:** `standards_architect_session_token_offchain_jwt`
**Dimension:** Standards
**Priority:** High
**Persona:** Standards Architect

## Summary

Defines a `bolyra+jwt` JWT profile that encodes verified Bolyra handshake
results as compact, offline-verifiable tokens. After a single on-chain
`verifyHandshake()`, the verifier mints a short-lived JWT. Subsequent
interactions present only the JWT — reducing per-call overhead to a
signature check.

## Artifacts

| File | Type | Description |
|------|------|-------------|
| `spec/draft-bolyra-session-token-01.md` | Spec | IETF-style draft defining the bolyra+jwt profile |
| `spec/session-token-claims-registry.md` | Spec | Normative claims registry table |
| `sdk/src/types/session-token.ts` | SDK | TypeScript type definitions |
| `sdk/src/session-token.ts` | SDK | `issueSessionToken()` and `verifySessionToken()` implementation |
| `sdk/test/session-token.test.ts` | Test | Unit tests with conformance vector consumption |
| `spec/conformance/session-token-vectors.json` | Test | 3 valid + 5 invalid normative test vectors |
| `docs/session-token-quickstart.md` | Docs | Developer guide with code examples |

## Key Design Decisions

1. **bolyra+jwt media type** — `typ` header distinguishes from generic JWTs
2. **bolyra.* claim namespace** — avoids collision with other JWT profiles
3. **Dual replay protection** — `jti` (token-level) + `bolyra.nonce` (ZKP-bound)
4. **vtx header** — optional on-chain tx hash for auditability
5. **DPoP binding** (RFC 9449) — sessionNonce maps to DPoP nonce for OAuth flows
6. **NonceStore interface** — pluggable replay detection (in-memory default, Redis/DB for production)
7. **Max TTL 900s** — short-lived by design; refresh via re-handshake
8. **EdDSA preferred, ES256 permitted** — Ed25519 for new deployments, P-256 for OAuth compat

## Claims Mapping

| Handshake Output | JWT Claim | Type |
|-----------------|-----------|------|
| humanNullifier | `sub` | Registered |
| agentNullifier | `bolyra.agn` | Private |
| scopeCommitment | `bolyra.scp` | Private |
| sessionNonce | `bolyra.nonce` | Private |
| verificationTimestamp | `iat` | Registered |
| on-chain tx hash | `vtx` (header) + `bolyra.vtx` (payload) | Extension |
| permissions | `bolyra.perm` | Private |

## Usage

```typescript
import { issueSessionToken, verifySessionToken } from '@bolyra/sdk';

// After verifyHandshake() succeeds:
const token = await issueSessionToken(handshakeResult, signingKey, {
  ttlSeconds: 300,
  verificationTxHash: '0x1234...ef90',
});

// Relying party verifies offline:
const claims = await verifySessionToken(token, publicKey);
console.log(claims.sub);           // humanNullifier
console.log(claims['bolyra.agn']); // agentNullifier
```

## Dependencies

- `jose` (npm) — JOSE/JWT signing and verification
- RFC 7519 (JWT), RFC 7515 (JWS), RFC 7517 (JWK), RFC 9449 (DPoP)
- `draft-bolyra-mutual-zkp-auth-01` — upstream handshake spec

## Test

```bash
npm test  # runs sdk/test/session-token.test.ts
```
