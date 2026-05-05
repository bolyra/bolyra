---
description: Deploy Bolyra contracts to Base Sepolia testnet
---

Deploy Solidity contracts (verifiers + registry) to Base Sepolia.

Pre-flight:
1. Verify `contracts/.env` has `BASE_SEPOLIA_RPC_URL` and a funded deployer key.
2. Run `cd contracts && npx hardhat compile` first to ensure latest bytecode.
3. Confirm with the user before broadcasting any transaction.

Deploy:
```bash
cd contracts && npm run deploy:base-sepolia
```

After deploy:
1. Record contract addresses in `contracts/deployments/baseSepolia.json` (or wherever the deploy script writes).
2. Verify on Basescan if a verifier API key is configured.
3. Run a smoke test: enroll a test human commitment + verify a known-good handshake proof on-chain.
4. Report gas used + total ETH spent.
