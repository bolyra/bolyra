# Integrate revert decoder and structured error codes into @bolyra/sdk

The tier2_004 experiment produced a complete BolyraError hierarchy with machine-readable ErrorCode enum, interpolated recovery hints, and an ethers-based revert decoder that maps IdentityRegistry custom errors (StaleRoot, ScopeMismatch, CredentialExpired, etc.) to typed BolyraError instances. Merge this into the production SDK so every on-chain revert and proof failure surfaces a .code for programmatic branching and a .hint with actionable recovery steps. This is the single highest-impact DX improvement because today developers get raw revert data with zero guidance.

## Status

Placeholder — awaiting implementation.
