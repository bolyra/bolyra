# Define application/bolyra-proof+cbor content type and envelope schema

The protocol lacks a standardized wire format for transmitting proof payloads between parties. Define an IANA-registrable media type application/bolyra-proof+cbor with a CDDL schema covering the three proof types (human, agent, delegation), their public signals, and the session nonce binding. This enables HTTP-native transport (Content-Type negotiation), MCP tool interop, and framework-agnostic deserialization. Deliverables: CDDL schema file, IANA considerations section for the IETF draft, and a reference encoder/decoder in the TS SDK.

## Status

Placeholder — awaiting implementation.
