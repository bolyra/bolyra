# Complete did:bolyra resolution algorithm per W3C DID Core §7

spec/did-method-bolyra.md exists but the resolution algorithm is underspecified — it doesn't define how a resolver maps did:bolyra:<commitment> to a DID Document, which verification methods to include (Ed25519VerificationKey2020 for operators, JsonWebKey2020 for providers), or how revocation status maps to the deactivated metadata property. Write the full CRUD operation definitions per W3C DID Core §7, including Read (resolve against on-chain humanTree/agentTree roots), Deactivate (revocation event), and the DID Document JSON-LD context. No Create/Update since commitments are immutable.

## Status

Placeholder — awaiting implementation.
