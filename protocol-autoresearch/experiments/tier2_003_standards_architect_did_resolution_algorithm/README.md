# Complete DID resolution algorithm with revocation and delegation discovery

The existing did-method-bolyra.md spec defines the DID syntax but lacks a complete resolution algorithm. Specify the full CRUD lifecycle: Create (enrollment tx → DID Document with verificationMethod), Read (resolve commitment → on-chain lookup of enrollment event + current Merkle inclusion status), Update (not applicable — commitments are immutable), Deactivate (revocation nullifier check). Add a `delegationService` endpoint in the DID Document that points to the delegation chain discovery API. Include concrete JSON-LD examples for each operation and error codes for stale-root and revoked-identity resolution failures.

## Status

Placeholder — awaiting implementation.
