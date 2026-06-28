# Type-safe proof envelope codec with serialize/deserialize

The SDK currently passes raw proof arrays and public signal tuples between proveHandshake() and verifyHandshake(). Add a BolyraProofEnvelope type with toJSON()/fromJSON()/toBytes()/fromBytes() methods that bundle the proof, public signals, circuit type, and protocol version into a single portable object. This eliminates the most common integration mistake: misaligning signal indices when passing proofs across service boundaries (HTTP, message queues, MCP tool results).

## Status

Placeholder — awaiting implementation.
