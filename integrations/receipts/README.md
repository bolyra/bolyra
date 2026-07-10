# @bolyra/receipts

Tamper-evident signed receipts for Bolyra ZKP verification decisions — secp256k1 / ES256K signatures, canonical JSON, EVM-compatible r‖s‖v encoding.

## Install

```bash
npm install @bolyra/receipts
```

## Usage

```typescript
import { createAuthReceipt, signReceipt, verifyReceipt } from '@bolyra/receipts';

// 1. Build a receipt from a verification result
const payload = createAuthReceipt(
  {
    rootDid: 'did:bolyra:0xabc…',
    actingDid: 'did:bolyra:0xdef…',
    credentialCommitment: '0x1234…',
    effectiveCommitment: '0x1234…',
    humanProof: verifiedBundle.humanProof,
    agentProof: verifiedBundle.agentProof,
    humanPublicSignals: verifiedBundle.humanPublicSignals,
    agentPublicSignals: verifiedBundle.agentPublicSignals,
    allowed: true,
    score: 95,
    permissionBitmask: 3n,
    chainDepth: 0,
    bundleVersion: 1,
    nonce: '0xdeadbeef',
  },
  { issuer: 'https://gateway.example.com', keyId: 'k1' },
);

// 2. Sign it with your secp256k1 private key
const signed = signReceipt(payload, {
  privateKey: process.env.RECEIPT_SIGNING_KEY!,
  keyId: 'k1',
});

// 3. Verify later (or on another service)
const ok = verifyReceipt(signed, '0xYourExpectedSignerAddress');
console.log(ok); // true
```

The `signed` object is JSON-serializable and can be stored in a database, forwarded to an audit log, or returned to the caller as proof of the verification decision.

## License

Apache-2.0
