# Bolyra SDK Quickstart

**Time:** 5 minutes | **Result:** A working mutual ZKP handshake between a human and an AI agent

## Prerequisites

- **Node.js 18+** (BigInt support required)
- **Circuit artifacts** -- the compiled `.wasm` and `.zkey` files for the HumanUniqueness and AgentPolicy circuits. See [circuits/README](../circuits/README.md) for build instructions, or download prebuilt artifacts from the [releases page](https://github.com/bolyra/bolyra/releases).

## Install

```bash
npm install @bolyra/sdk
```

## Complete Example

```ts
import {
  createHumanIdentity,
  createAgentCredential,
  proveHandshake,
  verifyHandshake,
  Permission,
} from "@bolyra/sdk";

// 1. Create a human identity (EdDSA keypair + Poseidon commitment)
const secret = 123456789n; // In production: use crypto.getRandomValues()
const human = await createHumanIdentity(secret);

// 2. Create an AI agent credential (operator-signed, time-bound)
const operatorKey = 42n; // In production: use a secure operator private key
const agent = await createAgentCredential(
  1001n,                                              // model hash
  operatorKey,                                        // operator's EdDSA key
  [Permission.READ_DATA, Permission.WRITE_DATA],      // scoped permissions
  BigInt(Math.floor(Date.now() / 1000) + 86400),      // expires in 24h
);

// 3. Generate mutual handshake proofs (human + agent, in parallel)
const { humanProof, agentProof, nonce } = await proveHandshake(human, agent, {
  scope: 1n,
});

// 4. Verify both proofs locally
const result = await verifyHandshake(humanProof, agentProof, nonce);

// 5. Check the result
console.log("Verified:", result.verified);
console.log("Human nullifier:", result.humanNullifier);
console.log("Agent nullifier:", result.agentNullifier);
```

## What Each Step Does

| Step | Function | What happens |
|------|----------|-------------|
| 1 | `createHumanIdentity(secret)` | Derives a Baby Jubjub keypair from the secret and computes a Poseidon2 commitment (the Merkle leaf). |
| 2 | `createAgentCredential(...)` | Computes a Poseidon5 commitment over the agent's parameters, then EdDSA-signs it with the operator key. |
| 3 | `proveHandshake(human, agent)` | Generates a Groth16 proof (human uniqueness) and a PLONK proof (agent policy) in parallel via snarkjs. |
| 4 | `verifyHandshake(...)` | Verifies both proofs against their verification keys. Returns nullifiers and a `verified` boolean. |
| 5 | Check `result.verified` | `true` means both proofs are valid -- the human is unique in this scope and the agent's credential is authentic and unexpired. |

## Expected Output

```
Verified: true
Human nullifier: 8219384756102938...  (unique per scope)
Agent nullifier: 3847291056384710...  (unique per session)
```

Both nullifiers are deterministic: the same human + scope always produces the same human nullifier (enabling double-spend prevention), while the agent nullifier is unique per session nonce.

## Circuit Artifacts Note

The `proveHandshake` function expects compiled circuit artifacts at `circuits/build/` by default. Override this with the `config.circuitDir` option:

```ts
const { humanProof, agentProof, nonce } = await proveHandshake(human, agent, {
  scope: 1n,
  config: { circuitDir: "/path/to/your/artifacts" },
});
```

Required files in the circuit directory:
- `HumanUniqueness_js/HumanUniqueness.wasm`
- `HumanUniqueness_final.zkey`
- `HumanUniqueness_vkey.json`
- `AgentPolicy_js/AgentPolicy.wasm`
- `AgentPolicy_plonk.zkey`
- `AgentPolicy_vkey.json`

## Next Steps

- **On-chain verification**: Submit proofs to the `IdentityRegistry.verifyHandshake()` contract on Base Sepolia
- **Delegation chains**: Use `delegate()` to let agents sub-delegate scoped permissions (v0.3)
- **Permission model**: See the cumulative bit encoding in [`Permission`](../sdk/src/types.ts) -- `FINANCIAL_UNLIMITED` implies `FINANCIAL_MEDIUM` implies `FINANCIAL_SMALL`

## Links

- [Full API documentation](https://github.com/bolyra/bolyra/tree/main/sdk)
- [GitHub repository](https://github.com/bolyra/bolyra)
- [Circuit specifications](https://github.com/bolyra/bolyra/tree/main/circuits)
- [Protocol whitepaper](https://github.com/bolyra/bolyra/blob/main/docs/superpowers)
