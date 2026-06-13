/**
 * Merkle root validator.
 *
 * This mock accepts all roots. Production: use ethers.js to check the
 * on-chain IdentityRegistry for humanRootExists + agentRootExists.
 */

export function createMockRootValidator() {
  return async (humanRoot: bigint, agentRoot: bigint): Promise<boolean> => {
    void humanRoot;
    void agentRoot;
    // Production: use ethers.js to check on-chain registry
    // const registry = new ethers.Contract(addr, abi, provider);
    // return registry.humanRootExists(humanRoot) && registry.agentRootExists(agentRoot);
    return true;
  };
}
