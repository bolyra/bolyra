# Proof Envelope Content Type

**Experiment:** `framework_integrator_proof_envelope_content_type`  
**Dimension:** Standards  
**Status:** Implementation

## Summary

Defines a canonical JSON envelope format (`application/bolyra+json`) for all Bolyra ZKP proof payloads. Every SDK method that produces a proof (`proveHandshake`, `delegate`) returns a `ProofEnvelope`, and every framework integration (LangChain, MCP) accepts and emits this format.

## Envelope Shape

```json
{
  "version": "1.0",
  "proofType": "handshake | delegation | agent_policy",
  "publicSignals": ["..."],
  "proof": {
    "pi_a": ["...", "...", "..."],
    "pi_b": [["...", "..."], ["...", "..."], ["...", "..."]],
    "pi_c": ["...", "...", "..."],
    "protocol": "groth16 | plonk",
    "curve": "bn128"
  },
  "metadata": {
    "issuedAt": 1719878400,
    "nonce": "session-abc123"
  }
}
```

## Artifacts

| File | Description |
|---|---|
| `spec/proof-envelope.md` | Normative specification |
| `sdk/src/envelope.schema.json` | JSON Schema for validation |
| `sdk/src/envelope.ts` | TypeScript types + serialize/deserialize/validate |
| `sdk/src/index.ts` | Updated `proveHandshake()` and `delegate()` return types |
| `sdk/test/envelope.test.ts` | Unit tests: round-trip, validation, edge cases |
| `spec/conformance/envelope-vectors.json` | Conformance test vectors (valid + invalid) |
| `spec/conformance/envelope.test.ts` | Conformance runner against vectors |
| `integrations/langchain/src/middleware.ts` | LangChain credential middleware using ProofEnvelope |
| `integrations/mcp/src/index.ts` | MCP integration using ProofEnvelope |
| `docs/proof-envelope.md` | Developer guide with migration notes |

## Usage

```ts
import {
  proveHandshake,
  serializeEnvelope,
  deserializeEnvelope,
  BOLYRA_CONTENT_TYPE,
  ProofType,
} from '@bolyra/sdk';

// Produce — proveHandshake now returns ProofEnvelope
const envelope = await proveHandshake(human, agent, nonce);

// Serialize for HTTP transport
const json = serializeEnvelope(envelope);
fetch('/verify', {
  method: 'POST',
  headers: { 'Content-Type': BOLYRA_CONTENT_TYPE },
  body: json,
});

// Receive and validate
const parsed = deserializeEnvelope(json);
console.log(parsed.proofType); // 'handshake'
```

## Running Tests

```bash
# SDK unit tests
cd sdk && npx mocha test/envelope.test.ts

# Conformance tests
cd spec/conformance && npx mocha envelope.test.ts

# Full regression check
npm run test:circuits:fast
npm run test:contracts
```

## Design Decisions

1. **`additionalProperties: false` at top level** — prevents field drift across integrations while allowing extensibility in `metadata`.
2. **Version uses `major.minor`** — major breaks schema; minor adds optional fields. SDK rejects unknown major versions.
3. **`proofType` uses lowercase snake_case** — matches typical JSON API conventions, not Circom circuit names.
4. **AJV for validation** — already used by JSON Schema ecosystem; avoids adding zod as a new dependency for this one feature.
5. **Metadata `issuedAt` is required** — every proof should carry its creation timestamp for audit and expiry checks.
