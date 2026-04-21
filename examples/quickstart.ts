/**
 * Bolyra SDK Quickstart — Mutual Handshake
 *
 * Demonstrates a complete human-agent mutual authentication flow
 * using zero-knowledge proofs. Run with:
 *
 *   npx ts-node examples/quickstart.ts
 *
 * Prerequisites:
 *   - Node.js 18+
 *   - Circuit artifacts built (see circuits/README.md)
 *   - npm install @bolyra/sdk
 */

import {
  createHumanIdentity,
  createAgentCredential,
  proveHandshake,
  verifyHandshake,
  Permission,
} from "@bolyra/sdk";

async function main() {
  // Step 1: Create a human identity (EdDSA keypair + Poseidon commitment)
  const secret = 123456789n; // In production: use crypto.getRandomValues()
  const human = await createHumanIdentity(secret);
  console.log("Human commitment:", human.commitment);

  // Step 2: Create an AI agent credential (operator-signed, time-bound)
  const operatorKey = 42n; // In production: use a secure operator private key
  const agent = await createAgentCredential(
    1001n,                                              // model hash
    operatorKey,                                        // operator's EdDSA key
    [Permission.READ_DATA, Permission.WRITE_DATA],      // scoped permissions
    BigInt(Math.floor(Date.now() / 1000) + 86400),      // expires in 24h
  );
  console.log("Agent commitment:", agent.commitment);

  // Step 3: Generate mutual handshake proofs (human + agent, in parallel)
  console.log("Generating ZK proofs (this may take a few seconds)...");
  const { humanProof, agentProof, nonce } = await proveHandshake(human, agent, {
    scope: 1n,
  });
  console.log("Proofs generated. Session nonce:", nonce);

  // Step 4: Verify both proofs locally
  const result = await verifyHandshake(humanProof, agentProof, nonce);

  // Step 5: Check the result
  console.log("\n--- Handshake Result ---");
  console.log("Verified:         ", result.verified);
  console.log("Human nullifier:  ", result.humanNullifier);
  console.log("Agent nullifier:  ", result.agentNullifier);
  console.log("Scope commitment: ", result.scopeCommitment);

  if (result.verified) {
    console.log("\nMutual handshake succeeded. Both parties are authenticated.");
    console.log("Submit proofs to IdentityRegistry.verifyHandshake() for on-chain finality.");
  } else {
    console.error("\nHandshake verification failed.");
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("Error:", err.message);
  process.exit(1);
});
