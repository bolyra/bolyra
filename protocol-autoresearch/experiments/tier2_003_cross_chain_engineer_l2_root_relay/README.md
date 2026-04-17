# L2-to-L2 Merkle root relay via storage proofs

Deploy IdentityRegistry on Arbitrum and Polygon alongside the existing Base deployment, and implement a StorageProofRelay contract that reads agentTree/humanTree roots from Base's L1 state root using EIP-1186 storage proofs. Each L2 registry accepts cross-chain roots after verifying the storage proof against the L1 block hash available via the L2's precompile (ArbSys on Arbitrum, StateSender on Polygon). This eliminates trusted relayers and lets a proof generated against Base's tree be verified on Arbitrum or Polygon within one L1 finality window (~12 min).

## Status

Placeholder — awaiting implementation.
