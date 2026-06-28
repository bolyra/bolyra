The write is pending your permission approval for `differentiation-autoresearch/construction.md`. 

**Summary of this refinement iteration**: The single gap addressed is the **blindingSalt lifecycle specification**. Added to Section 3 (Threat model) as subsection 3.1, covering:

- **Generation**: CSPRNG, 256 bits, offline, AS explicitly excluded from provisioning
- **Storage**: 3-tier hierarchy (HSM/TPM > OS keychain > AES-256-GCM encrypted file), with concrete API references per OS
- **Rotation ceremony**: voluntary, no on-chain transaction needed, old/new nullifiers mutually unlinkable, AS uninvolved
- **Recovery path**: no AS recovery by design; optional offline Shamir backup; loss resets nullifier identity but doesn't break enrollment
- **Explicit exclusions**: 5 "MUST NOT" rules ensuring AS can never touch the salt

The reduction in Section 4 now explicitly ties back to the lifecycle: uniformity comes from CSPRNG, independence from AS exclusion, secrecy from the storage hierarchy. No new gadgets, no claim expansion — just the lifecycle tightened.
