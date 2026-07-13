# Receipt Signer Discovery v1

Status: v1, additive. Companion to the receipt format shipped in
`@bolyra/receipts` (0.8.0+) and the External Verifier Contract v1.

## Problem

A Bolyra receipt is ES256K-signed and verifiable offline, but the verifier
must know which signer address(es) to accept. Today that is a manual trust
decision: the operator hands you a `signer.json` (or you read
`signature.signer` off a receipt you already trust). This document defines a
minimal, fetchable alternative: a **well-known signer discovery document**.

## Non-goals

Discovery is **not** endorsement, and this is **not** a PKI. Fetching a
signer list moves the trust decision from "trust this key" to "trust this
origin" — it does not eliminate it. Out of scope, deliberately: certificate
chains, revocation infrastructure, key-rotation history proofs, transparency
logs, wallet binding, HSM attestation. A deployment that needs those layers
them on top.

## Document

An operator that signs receipts SHOULD serve:

```
GET https://<origin>/.well-known/bolyra-signers.json
```

with `Content-Type: application/json` and a body of the shape:

```json
{
  "v": 1,
  "issuer": "corpus.bolyra.ai",
  "updatedAt": 1783987200,
  "signers": [
    {
      "keyId": "test-kit-a-1",
      "alg": "ES256K",
      "signer": "0x17c5185167401ed00cf5f5b2fc97d9bbfdb7d025",
      "label": "scoring-kit corpus signer"
    }
  ]
}
```

Field rules (a consumer MUST reject a document that violates any of them):

- `v` (number, REQUIRED) — document version. This document defines `1`.
  Consumers MUST reject other values.
- `issuer` (string, REQUIRED) — operator identifier. SHOULD match the
  `issuer` field of the receipts this document vouches for.
- `updatedAt` (number, REQUIRED) — Unix seconds when the document was last
  generated.
- `signers` (array, REQUIRED, non-empty) — each entry:
  - `keyId` (string, REQUIRED) — matches `signature.keyId` on receipts.
  - `alg` (string, REQUIRED) — MUST be `"ES256K"` in v1. Consumers MUST
    reject entries with any other value (closed set; new algorithms require
    a new document version).
  - `signer` (string, REQUIRED) — the recovered signer address,
    `^0x[0-9a-fA-F]{40}$`, as it appears at `signature.signer`.
  - `label` (string, OPTIONAL) — human-readable note. Advisory only; never
    an input to verification.

Unknown top-level or entry-level fields MUST be ignored (forward
compatibility). Duplicate `signer` values are permitted (e.g. two keyIds for
one address); duplicate `keyId` values with conflicting `signer` values MUST
be rejected.

## Consumer behavior

A verifier given a discovery URL (for example `bolyra receipt verify
--signer-from <url>`):

1. MUST fetch over HTTPS. Plain `http://` MUST be rejected except for
   loopback addresses (development). Consumers MUST NOT follow redirects —
   a redirect can move the fetch to a plaintext or attacker-chosen origin
   after the protocol check. Operators serve the document directly at the
   well-known path.
2. MUST treat any transport failure, non-200 status, non-JSON body, or
   schema violation as a **verification failure** (fail closed), never as
   "no signer restriction".
3. MUST accept a receipt's signature only if `signature.signer` matches
   (case-insensitively) the `signer` of some entry whose `alg` the consumer
   supports. If the matching entry's `keyId` differs from the receipt's
   `signature.keyId`, the consumer SHOULD warn but MAY accept (keyId is a
   rotation hint, not key material).
4. MUST NOT cache a rejected document. Caching accepted documents is
   consumer policy.

## Trust semantics (the plain-language caveat)

The verifier still chooses whether to trust the discovery **origin**. A
compromised origin can serve an attacker's signer list; HTTPS pins the
document to the origin, nothing more. For the highest-assurance path, pin
the signer address out of band exactly as before — `--signer` and
`--signer-from` express the same check with different provenance, and when
both are supplied a consumer MUST require both to agree.

## Reference deployments

- `@bolyra/gateway` (HTTP mode) serves the document for its configured
  receipt signer.
- The Bolyra hosted-verify preview serves the document for its pinned
  receipt signer.
