# v0.6.0 Design: Signed Receipts (revised after Codex review)

**Date:** 2026-06-13
**Status:** Approved (10 Codex findings incorporated, scope reduced)
**Theme:** "MCP verification decisions produce cryptographically signed, auditable receipts."

## Summary

v0.6.0 adds `@bolyra/receipts` — a new package with signed receipt
primitives (types, canonical hashing, secp256k1 sign/verify). MCP
verifier integration produces a `SignedReceipt` on every verification
decision. Commerce receipts deferred to v0.7.0.

## Scope Reduction (Codex recommendation)

v0.6.0: `@bolyra/receipts` + MCP signed verification receipts + tests.
v0.7.0: Commerce signed receipts (needs proof bundle threading through
`authorizeCommerceIntent`).

## 1. Package: `@bolyra/receipts`

`integrations/receipts/`. Minimal deps: `@noble/secp256k1` +
`@noble/hashes`.

No imports from `@bolyra/mcp` or `@bolyra/payment-protocols` — receipts
uses structural input types only to avoid package cycles.

## 2. Types

### 2.1 `ReceiptPayload`

```typescript
export interface ReceiptPayload {
  v: 1;
  kind: 'bolyra.auth';
  /** Unix seconds when the decision was made. */
  issuedAt: number;
  /** Server identifier. */
  issuer: string;
  /** Signing key identifier for rotation. */
  keyId: string;

  subject: {
    /** Root credential DID. */
    rootDid: string;
    /** Acting agent DID (leaf of delegation chain, or root if no chain). */
    actingDid: string;
    credentialCommitment: string;
    effectiveCommitment: string;
  };

  decision: {
    allowed: boolean;
    reasonCode?: string;
    score: number;
    /** Decimal string to avoid BigInt serialization issues. */
    permissionBitmask: string;
    chainDepth: number;
  };

  proof: {
    bundleVersion: 1 | 2;
    /** Decimal string. */
    nonce: string;
    /** SHA-256 of canonical JSON of humanProof.proof. */
    humanProofHash: string;
    /** SHA-256 of canonical JSON of agentProof.proof. */
    agentProofHash: string;
    /** SHA-256 of canonical JSON of all public signals (human + agent). */
    publicSignalsHash: string;
    /** SHA-256 of canonical JSON of delegationChain (if v=2). */
    delegationChainHash?: string;
  };
}
```

**`id` removed from payload (Codex finding).** Receipt ID is derived
AFTER hashing: `id = payloadHash.slice(0, 16)`. It lives on
`SignedReceipt`, not inside the payload that gets hashed.

**`rootDid` vs `actingDid` (Codex finding).** Explicitly distinguishes
root credential DID from effective acting agent DID.

### 2.2 `SignedReceipt`

```typescript
export interface SignedReceipt {
  /** First 16 hex chars of payloadHash. */
  id: string;
  payload: ReceiptPayload;
  signature: {
    alg: 'ES256K';
    keyId: string;
    /** Ethereum address of the signer (hex, 0x-prefixed). */
    signer: string;
    /** keccak256 of canonical JSON payload (hex, 0x-prefixed). */
    payloadHash: string;
    /** r (32 bytes) + s (32 bytes) + v (1 byte) = 65 bytes (hex). */
    value: string;
  };
}
```

**Signature includes `v` (Codex finding).** 65-byte `r || s || v` format
so `ecrecover` works for EVM address recovery.

### 2.3 `ReceiptSignerConfig`

```typescript
export interface ReceiptSignerConfig {
  issuer: string;
  keyId: string;
  /** secp256k1 private key, 32 bytes, hex-encoded, 0x-prefixed. */
  privateKey: string;
}
```

## 3. Canonical JSON (Codex finding)

`JSON.stringify` does NOT guarantee key order. Use a deterministic
serializer with sorted keys:

```typescript
export function canonicalize(obj: unknown): string {
  return JSON.stringify(obj, (_key, value) => {
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      return Object.keys(value).sort().reduce((sorted, k) => {
        sorted[k] = value[k];
        return sorted;
      }, {} as Record<string, unknown>);
    }
    return value;
  });
}
```

All hashing uses `canonicalize()`, not raw `JSON.stringify()`.

## 4. Functions

### 4.1 `createAuthReceipt()`

```typescript
export interface AuthReceiptInput {
  /** From BolyraAuthContext or equivalent. */
  rootDid: string;
  actingDid: string;
  credentialCommitment: string;
  effectiveCommitment: string;
  allowed: boolean;
  reasonCode?: string;
  score: number;
  permissionBitmask: string;
  chainDepth: number;
  /** Raw proof bundle for hashing. */
  humanProof: { proof: unknown };
  agentProof: { proof: unknown };
  humanPublicSignals: string[];
  agentPublicSignals: string[];
  bundleVersion: 1 | 2;
  nonce: string;
  delegationChain?: unknown[];
}

export function createAuthReceipt(
  input: AuthReceiptInput,
  config: { issuer: string; keyId: string },
): ReceiptPayload;
```

Uses structural input type — no import from `@bolyra/mcp`.

### 4.2 `signReceipt()`

```typescript
export function signReceipt(
  payload: ReceiptPayload,
  config: ReceiptSignerConfig,
): SignedReceipt;
```

1. `canonicalize(payload)`
2. `keccak256(utf8Bytes(canonical))`
3. `secp256k1.sign(hash, privateKey)` → get `r, s, recovery`
4. Build 65-byte signature: `r || s || v` where `v = recovery + 27`
5. Derive signer address from public key
6. `id = payloadHash.slice(2, 18)` (first 16 hex chars after 0x)

### 4.3 `verifyReceipt()`

```typescript
export function verifyReceipt(
  receipt: SignedReceipt,
  expectedSigner?: string,
): boolean;
```

1. Recompute hash from `canonicalize(receipt.payload)`
2. Recover public key from signature `value` (65 bytes with `v`)
3. Derive address from recovered public key
4. If `expectedSigner`, check address matches
5. Check recomputed hash matches `receipt.signature.payloadHash`

### 4.4 `hashPayload()`

```typescript
export function hashPayload(payload: ReceiptPayload): string;
```

## 5. MCP Integration

Add to `BolyraMcpConfig`:
```typescript
receiptSigner?: ReceiptSignerConfig;
```

Add to `BolyraAuthContext`:
```typescript
receipt?: SignedReceipt;
```

In `verifyBundle()`: after computing the final `BolyraAuthContext`, if
`config.receiptSigner` is set, call `createAuthReceipt()` +
`signReceipt()` and attach to `ctx.receipt`.

**All return paths (Codex finding).** `verifyBundle` has many early
returns. Use a finalizing wrapper that catches the `BolyraAuthContext`
from any path and appends the receipt:

```typescript
function withReceipt(
  ctx: BolyraAuthContext,
  bundle: BolyraProofBundle,
  config: BolyraMcpConfig,
): BolyraAuthContext {
  if (!config.receiptSigner) return ctx;
  const receipt = signReceipt(
    createAuthReceipt(extractReceiptInput(ctx, bundle), config.receiptSigner),
    config.receiptSigner,
  );
  return { ...ctx, receipt };
}
```

Skip receipts in dev mode (dev bundles have no real proof evidence).

**`checkToolPolicy` (Codex finding).** Per-tool allow/deny is a
secondary decision after bundle verification. v0.6.0 receipts cover
bundle verification only. Per-tool receipts deferred.

## 6. File Map

### New files
| File | Responsibility |
|------|---------------|
| `integrations/receipts/src/types.ts` | ReceiptPayload, SignedReceipt, ReceiptSignerConfig, AuthReceiptInput |
| `integrations/receipts/src/canonical.ts` | canonicalize() |
| `integrations/receipts/src/receipt.ts` | createAuthReceipt() |
| `integrations/receipts/src/sign.ts` | signReceipt, verifyReceipt, hashPayload |
| `integrations/receipts/src/index.ts` | Barrel exports |
| `integrations/receipts/test/canonical.test.ts` | Canonical JSON tests |
| `integrations/receipts/test/receipt.test.ts` | Receipt creation tests |
| `integrations/receipts/test/sign.test.ts` | Sign/verify round-trip tests |
| `integrations/receipts/package.json` | Package config |
| `integrations/receipts/tsconfig.json` | TypeScript config |

### Modified files
| File | Change |
|------|--------|
| `integrations/mcp/src/types.ts` | Add receiptSigner + receipt fields |
| `integrations/mcp/src/verify.ts` | withReceipt wrapper on all return paths |
| `integrations/mcp/package.json` | Add @bolyra/receipts dep |
| `CHANGELOG.md` | v0.6.0 entry |

## 7. Tests

| Test | What |
|------|------|
| Canonical JSON sorts keys | `{b:1, a:2}` → `{"a":2,"b":1}` |
| Canonical JSON handles nested | Nested objects sorted recursively |
| Create auth receipt | All fields populated from input |
| Proof hashes include both proofs | humanProofHash + agentProofHash both present |
| Delegation chain hash present for v=2 | Only when chain exists |
| Sign + verify round-trip | Valid signature, correct signer address |
| Verify rejects wrong key | Returns false |
| Verify rejects tampered payload | Returns false |
| Receipt ID determinism | Same input → same ID |
| MCP integration | verifyBundle with receiptSigner → receipt in context |
| MCP denied decision | Failed verification also gets receipt |
| Dev mode skips receipts | devMode=true → no receipt |

## 8. Version Bump

| Package | Current | v0.6.0 |
|---------|---------|--------|
| `@bolyra/receipts` | new | 0.6.0 |
| `@bolyra/mcp` | 0.4.0 | 0.6.0 |
| Others | unchanged | unchanged |

## 9. Implementation Order

1. Package scaffold (`integrations/receipts/`)
2. Canonical JSON (`canonical.ts` + tests)
3. Types (`types.ts`)
4. Receipt creation (`receipt.ts` + tests)
5. Signing (`sign.ts` + tests)
6. MCP integration (config + withReceipt wrapper)
7. CHANGELOG, version bumps
8. Codex review
9. Release (tag + OIDC publish)

## 10. Codex Findings Tracker

| Finding | Resolution |
|---------|-----------|
| `id` circular hash | `id` moved to SignedReceipt, not in hashed payload |
| JSON.stringify not canonical | `canonicalize()` with sorted keys |
| Signature needs `v` for ecrecover | 65-byte `r\|\|s\|\|v` format |
| Proof hashing incomplete | Hash both human + agent proofs + delegation chain |
| Commerce needs proof bundle | Commerce receipts deferred to v0.7.0 |
| Unsigned receipt conflict | Commerce untouched in v0.6.0 |
| Type locations wrong | Noted in file map |
| Multiple early returns | `withReceipt` wrapper pattern |
| checkToolPolicy receipts | Deferred, v0.6.0 covers bundle verification only |
| rootDid vs actingDid | Both explicitly in subject |
| amount: number precision | Deferred (commerce receipts in v0.7.0) |
