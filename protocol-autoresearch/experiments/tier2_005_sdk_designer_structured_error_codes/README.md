# Typed error hierarchy with machine-readable codes for SDK and contracts

The current SDK throws generic `new Error(string)` and the IdentityRegistry uses unparameterized custom errors (e.g., `StaleAgentRoot()` with no context). Replace SDK errors with a typed `BolyraError` class hierarchy carrying `code` (enum like `STALE_ROOT`, `NONCE_MISMATCH`, `SCOPE_SUBSET_VIOLATION`), `context` object, and human-readable `message`. On the Solidity side, add indexed parameters to custom errors (e.g., `StaleAgentRoot(uint256 providedRoot, uint256 latestRoot)`). Publish the error code enum in both `@bolyra/sdk` and `bolyra` Python package so integrators can programmatically catch and recover from specific failure modes without string-parsing.

## Status

Placeholder — awaiting implementation.
