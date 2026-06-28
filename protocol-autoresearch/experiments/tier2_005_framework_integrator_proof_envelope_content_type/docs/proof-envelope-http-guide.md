# Proof Envelope HTTP Integration Guide

This guide shows how to send and receive Bolyra proof envelopes over HTTP
using the `application/bolyra-proof+json` content type.

## Content Type

All Bolyra proof payloads SHOULD be sent with:

```
Content-Type: application/bolyra-proof+json
```

Both the TypeScript and Python SDKs export this as `BOLYRA_PROOF_CONTENT_TYPE`.

## TypeScript (fetch)

```typescript
import {
  ProofEnvelope,
  BOLYRA_PROOF_CONTENT_TYPE,
} from "@bolyra/sdk/proof-envelope";

// --- Sending a proof ---
const envelope = new ProofEnvelope({
  version: "1",
  circuit: "AgentPolicy",
  publicSignals: ["123", "456"],
  proof: {
    pi_a: ["1", "2", "1"],
    pi_b: [["3", "4"], ["5", "6"], ["1", "0"]],
    pi_c: ["7", "8", "1"],
  },
  sessionToken: "eyJ...",
});

const response = await fetch("https://api.example.com/verify", {
  method: "POST",
  headers: { "Content-Type": BOLYRA_PROOF_CONTENT_TYPE },
  body: envelope.serialize(),
});

// --- Receiving a proof ---
const body = await request.text();
const received = ProofEnvelope.parse(body);
console.log(received.circuit);       // "AgentPolicy"
console.log(received.publicSignals); // ["123", "456"]
```

## Python (requests)

```python
import requests
from bolyra.proof_envelope import (
    ProofEnvelope,
    SnarkProof,
    BOLYRA_PROOF_CONTENT_TYPE,
)

# --- Sending a proof ---
envelope = ProofEnvelope(
    version="1",
    circuit="AgentPolicy",
    public_signals=["123", "456"],
    proof=SnarkProof(
        pi_a=["1", "2", "1"],
        pi_b=[["3", "4"], ["5", "6"], ["1", "0"]],
        pi_c=["7", "8", "1"],
    ),
    session_token="eyJ...",
)

resp = requests.post(
    "https://api.example.com/verify",
    data=envelope.serialize(),
    headers={"Content-Type": BOLYRA_PROOF_CONTENT_TYPE},
)

# --- Receiving a proof ---
received = ProofEnvelope.parse(request.body)
print(received.circuit)         # "AgentPolicy"
print(received.public_signals)  # ["123", "456"]
```

## LangChain APIChain Integration

When using LangChain's `APIChain` to call a Bolyra-protected endpoint,
set the content type header so the server knows to parse the envelope:

```typescript
import { APIChain } from "langchain/chains";

const chain = APIChain.fromLLMAndAPIDocs(llm, apiDocs, {
  headers: {
    "Content-Type": BOLYRA_PROOF_CONTENT_TYPE,
  },
});
```

## AutoGen ConversableAgent Integration

AutoGen agents can attach proof envelopes to HTTP tool calls:

```python
from autogen import ConversableAgent

def call_with_proof(url: str, envelope: ProofEnvelope) -> str:
    """Tool function that sends a proof envelope."""
    resp = requests.post(
        url,
        data=envelope.serialize(),
        headers={"Content-Type": BOLYRA_PROOF_CONTENT_TYPE},
    )
    return resp.text

agent = ConversableAgent(
    name="bolyra_agent",
    llm_config={"tools": [call_with_proof]},
)
```

## MCP Tool Results

When returning proof envelopes from an MCP tool, embed the serialized
envelope as a JSON string in the tool result:

```typescript
server.tool("prove-identity", async () => {
  const envelope = new ProofEnvelope({ /* ... */ });
  return {
    content: [{
      type: "text",
      text: envelope.serialize(),
      mimeType: BOLYRA_PROOF_CONTENT_TYPE,
    }],
  };
});
```

## Validation

Both `ProofEnvelope.parse()` (TS) and `ProofEnvelope.parse()` (Python)
perform full schema validation. Invalid envelopes throw/raise
`BolyraEnvelopeError` with a descriptive error code:

| Code | Meaning |
|---|---|
| `INVALID_JSON` | Input is not valid JSON |
| `INVALID_ENVELOPE` | Top-level value is not an object |
| `UNSUPPORTED_VERSION` | Version field is not `"1"` |
| `UNKNOWN_CIRCUIT` | Circuit is not one of the three known types |
| `INVALID_PUBLIC_SIGNALS` | Missing or empty publicSignals array |
| `INVALID_PROOF` | Malformed proof structure |
| `INVALID_DELEGATION_CHAIN` | Malformed delegation chain |
