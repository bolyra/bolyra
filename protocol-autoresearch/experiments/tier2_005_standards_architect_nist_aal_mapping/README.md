# NIST SP 800-63B Authenticator Assurance Level Mapping

Produce a formal analysis mapping Bolyra's authentication factors to NIST AAL levels. The human side (EdDSA secret + Merkle membership) constitutes a single cryptographic authenticator factor; the agent side (operator EdDSA signature + model hash + permission bitmask) constitutes a bound multi-factor authenticator. Analyze whether the handshake protocol meets AAL2 requirements (two distinct factors, verifier impersonation resistance, replay resistance via nonce). Identify gaps: the current HumanUniqueness circuit is Phase 1 'proof of enrollment' without a second factor (e.g., biometric or PIN), which likely caps human-side assurance at AAL1. Document what Phase 4 behavioral enrollment would need to reach AAL2. This mapping is essential for credit union adoption where NCUA examiners will ask for NIST alignment.

## Status

Placeholder — awaiting implementation.
