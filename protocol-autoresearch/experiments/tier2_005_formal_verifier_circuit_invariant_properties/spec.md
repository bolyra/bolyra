# Machine-checkable circuit invariant property file for all circuits

## Abstract

Create a circuits/FORMAL-PROPERTIES.md (or extend the existing stub) with machine-checkable invariant properties expressed in a format compatible with Circomspect or Picus. Properties to cover: (1) no signal can exceed BN254 field order r, (2) nullifierHash is deterministic given (identity, scope/nonce), (3) credentialCommitment uniquely binds all 5 credential fields, (4) Merkle root output changes if any sibling changes (non-malleability), (5) scope commitment binds both the bitmask and the credential identity. Provide a CI script that runs Circomspect --sarif on all .circom files and gates on zero high-severity findings.

## Normative Requirements

Implementations MUST ...
