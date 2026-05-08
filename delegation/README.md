# @bolyra/delegation v0.2

> SD-JWT (draft-20) + KB-JWT delegation receipts with IETF status-list (draft-20) revocation.

`@bolyra/delegation` is the lightweight on-ramp into the [Bolyra](https://bolyra.ai) protocol. A human (or upstream agent) issues a scoped, holder-bound receipt; the holder presents it with a fresh key-binding JWT; middleware verifies before the agent calls a tool. Standards-aligned wire format means downstream verifiers can audit the receipt with off-the-shelf SD-JWT tooling.

## Wire format

```
<issuer-jws>~~<kb-jwt>
```

- **Issuer JWS** — `typ: "bolyra-delegation+sd-jwt"`, `alg: "EdDSA"`, `_sd_alg: "sha-256"`. Payload includes `cnf.jwk` (holder pubkey) and `_sd: []` (zero disclosures in v0.2).
- **KB-JWT** — `typ: "kb+jwt"`, signed by the holder. Payload `{aud, nonce, sd_hash, iat}` per SD-JWT draft-20 §4.3.
- The empty middle segment between the two `~` separators is the zero-disclosure slot mandated by `draft-ietf-oauth-selective-disclosure-jwt-20`.

## Install

```bash
npm install @bolyra/delegation
```

## API

```ts
import {
  allow,
  present,
  verify,
  staticIssuerResolver,
  fetchStatusList,
} from "@bolyra/delegation";

// Issuer signs a scoped, holder-bound receipt.
const receipt = await allow(
  {
    iss: "https://issuer.example",
    sub: "did:bolyra:holder",
    aud: "https://merchant.example",
    act: "spend",
    perm: "FINANCIAL_SMALL",
    agentPubKey: holderPublicKey,
    ttlSeconds: 3600,
    max: { amount: 5000, currency: "USD" },
  },
  { privateKey: issuerPrivateKey, kid: "k1" },
);

// Holder produces a presentation with a fresh KB-JWT.
const presented = await present(receipt, holderPrivateKey, {
  audience: "https://merchant.example",
  nonce: "fresh-server-nonce",
});

// Verifier validates the receipt + KB-JWT + (optionally) status-list.
const trustedIssuers = staticIssuerResolver({
  "https://issuer.example": { k1: issuerPublicKey },
});

const result = await verify(presented, {
  audience: "https://merchant.example",
  action: "spend",
  perm: "FINANCIAL_SMALL",
  kbNonce: "fresh-server-nonce",
  amount: 1000,
  currency: "USD",
  trustedIssuers,
  // Optional: revocation via IETF status-list draft-20.
  checkStatus: (uri, idx, expectedIss) =>
    fetchStatusList(uri, idx, expectedIss, { verifyKey: trustedIssuers }),
});

if (!result.ok) throw new Error(`delegation rejected: ${result.reason}`);
// proceed with the call
```

## Permission model

The 8-bit cumulative encoding mirrors `circuits/Delegation.circom` so receipts are upgrade-compatible with full ZKP delegation later.

| Bit | Permission | Notes |
|-----|------------|-------|
| 0 | `READ_DATA` | |
| 1 | `WRITE_DATA` | |
| 2 | `FINANCIAL_SMALL` | < $100 |
| 3 | `FINANCIAL_MEDIUM` | < $10K (implies bit 2) |
| 4 | `FINANCIAL_UNLIMITED` | implies bits 2 + 3 |
| 5 | `SIGN_ON_BEHALF` | |
| 6 | `SUB_DELEGATE` | |
| 7 | `ACCESS_PII` | |

In v0.2, `perm` is passed as the string label (e.g. `"FINANCIAL_SMALL"`); the verifier expands cumulative implication internally.

## Migration from v0.1

- v0.1 plain-JWS receipts still verify if you pass `acceptLegacyV01: true` to `verify()`. The result includes `legacyV01: true`.
- New issuance must use `allow()` (v0.2 only — produces SD-JWT issuer form).
- Holders must sign the KB-JWT with the private key matching `cnf.jwk` in the receipt.
- Status-list revocation is opt-in: set `claims.status.status_list = { uri, idx }` at issuance and pass `checkStatus` to `verify()`.

## Failure reasons

`VerifyFailureReason` is a discriminated union of 51 enumerated reasons (plus `"UNKNOWN"` as a catch-all default). Every enumerated reason is exercised by at least one test under `test/conformance/`. The negative-space gate (`test/conformance/negative-space.test.ts`) enforces full coverage in CI.

Reasons partition into five families:

- **Envelope** — `BAD_FORMAT`, `INVALID_SIGNATURE`, `UNSUPPORTED_ALG`, `TYP_MISMATCH`, `KID_MISSING`, `KID_RESOLVER_ERROR`, `UNKNOWN_ISSUER_KID`, `LEGACY_V01_REJECTED`
- **Claims** — `EXPIRED`, `FUTURE_NBF`, `WRONG_ISSUER`, `WRONG_AUDIENCE`, `WRONG_SUBJECT`, `WRONG_ACTION`, `MISSING_CLAIM`, `PARENT_NOT_FOUND`, `DELEGATION_LOOP`, `PERMISSION_VIOLATION`, `AMOUNT_EXCEEDS_CAP`, `CURRENCY_MISMATCH`
- **Selective disclosure** — `DISCLOSURE_TAMPERED`, `DISCLOSURE_HASH_MISMATCH`, `UNDISCLOSED_CLAIM_REQUIRED`, `DUPLICATE_DISCLOSURE`, `MALFORMED_DISCLOSURE`, `SD_ALG_UNSUPPORTED`, `SD_JWT_MALFORMED`
- **Key binding** — `CNF_MISSING`, `CNF_KEY_MISMATCH`, `CNF_JWK_INVALID`, `KB_MISSING`, `KB_NONCE_REQUIRED`, `KB_BAD_FORMAT`, `KB_INVALID_SIGNATURE`, `KB_WRONG_NONCE`, `KB_WRONG_AUDIENCE`, `KB_WRONG_SD_HASH`, `KB_TYP_INVALID`, `KB_ALG_UNSUPPORTED`, `KB_IAT_FUTURE`, `KB_IAT_TOO_OLD`, `KB_BINDING_MISMATCH`
- **Status list** — `STATUS_REVOKED`, `STATUS_SUSPENDED`, `STATUS_CHECK_UNCONFIGURED`, `STATUS_LIST_INVALID`, `STATUS_LIST_SIG_INVALID`, `STATUS_LIST_ISSUER_MISMATCH`, `STATUS_LIST_UNREACHABLE`, `STATUS_INDEX_OUT_OF_RANGE`

## Standards

- **SD-JWT:** `draft-ietf-oauth-selective-disclosure-jwt-20`
- **KB-JWT:** same draft, §4.3
- **Status list:** `draft-ietf-oauth-status-list-20` (2-bit slots, zlib RFC 1950, base64url)
- **JWK thumbprint:** RFC 7638
- **Media types:** `application/bolyra-delegation+sd-jwt`, `application/statuslist+jwt`, `application/kb+jwt`

## Roadmap

- **v0.1:** EdDSA-signed plain JWS receipts (back-compat shim retained in v0.2).
- **v0.2 (now):** SD-JWT + KB-JWT + IETF status-list revocation.
- **v0.3:** ZKP-wrapped receipts (via `@bolyra/sdk` + Circom `Delegation` circuit). Privacy-preserving issuer + agent identity.

## License

Apache-2.0. Patent grant per Apache 2.0 §3 (US provisional 64/043,898 filed 2026-04-20). DCO sign-off required for contributions (see `CONTRIBUTING.md` in repo root).
