# Harden cross-chain storage proof block hash verification

RootRelay.sol's _getL1BlockHash uses a simplified trust model (documented as placeholder) that returns bytes32(0) on failure but does not parse actual block header RLP or validate against a real L1 oracle like the EIP-4788 beacon root contract. An attacker controlling the oracle address could inject arbitrary state roots. Replace with EIP-4788 parentBeaconBlockRoot precompile on L2s that support it, or Axiom/Relic-style historic block hash proofs. Add a block age check (reject blocks older than ~256 blocks or staler than the root history buffer window). Artifact: production-grade _getL1BlockHash using 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02, integration test with forked mainnet.

## Status

Placeholder — awaiting implementation.
