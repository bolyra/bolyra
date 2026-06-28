# Media Type Registration: `application/bolyra-proof+cbor`

This document follows the template defined in [RFC 6838 §5.6](https://datatracker.ietf.org/doc/html/rfc6838#section-5.6) for registration of a new media type.

## 1. Media Type Name

- **Type name:** application
- **Subtype name:** bolyra-proof+cbor
- **Suffix:** +cbor (per [RFC 9052 §16.1](https://www.rfc-editor.org/rfc/rfc9052#section-16.1))

## 2. Required Parameters

None. All envelope metadata is carried inside the CBOR payload itself.

## 3. Optional Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `v`       | uint | Envelope schema version (default: 1) |
| `circuit` | tstr | Circuit identifier hint for pre-routing |
| `ps`      | tstr | Proving system hint (`groth16` \| `plonk`) |

These parameters are informational and MUST NOT contradict the values inside the CBOR envelope. If a mismatch is detected, the values inside the envelope are authoritative.

## 4. Encoding Considerations

- Binary. The content is a single CBOR data item ([RFC 8949](https://www.rfc-editor.org/rfc/rfc8949)) encoding a CBOR map.
- The normative CDDL schema is defined in `proof-envelope.cddl` and reproduced below.
- Implementations MUST ignore unknown integer keys in the map to preserve forward compatibility.
- Maximum envelope size: 65536 bytes (64 KiB). Decoders SHOULD reject envelopes exceeding this limit.

## 5. CDDL Schema

```cddl
proof-envelope = {
  version:        1,           ; uint — schema version, currently 1
  circuit-id:     2,           ; tstr — circuit identifier
  proving-system: 3,           ; tstr — "groth16" / "plonk"
  proof-bytes:    4,           ; bstr — serialized proof
  public-signals: 5,           ; [+ tstr] — decimal string signals
  ? delegation-chain: 6,      ; [* bstr] — optional delegation chain
  * int => any                 ; future extension (keys > 6)
}
```

## 6. Security Considerations

- **Proof integrity:** The envelope does not provide integrity protection. Transport-layer security (TLS) is REQUIRED. Application-layer signing (e.g., JWS wrapping) is RECOMMENDED for store-and-forward scenarios.
- **Proof replay:** Each proof binds to a `sessionNonce` via the circuit's public signals. Verifiers MUST check nonce freshness.
- **Denial of service:** Decoders MUST enforce the 64 KiB envelope limit and reject deeply nested delegation chains (recommended maximum depth: 8).
- **Privacy:** `circuitId` and `provingSystem` are cleartext metadata. In privacy-sensitive contexts, consider encrypting the entire envelope at the transport layer.
- **Delegation chain ordering:** If present, `delegationChain[0]` is the root credential and `delegationChain[n-1]` is the most-derived. Verifiers MUST validate the chain from root to leaf.

## 7. Interoperability Considerations

- Reference implementations are provided in TypeScript (`@bolyra/sdk`) and Python (`bolyra`).
- Cross-language interoperability is verified by encoding in one SDK and decoding in the other.
- The CBOR map uses integer keys (not string keys) for compactness. Implementations MUST use the key mapping defined in the CDDL schema.

## 8. Fragment Identifier Considerations

None defined.

## 9. Contact Information

- **Contact:** ZKProva Inc.
- **Email:** protocol@bolyra.ai
- **Website:** https://bolyra.ai

## 10. Author

Viswa Swaminathan, ZKProva Inc.

## 11. Change Controller

ZKProva Inc.
