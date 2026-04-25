const hre = require("hardhat");

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  const balance = await hre.ethers.provider.getBalance(deployer.address);

  console.log("Deploying Bolyra contracts with account:", deployer.address);
  console.log("Account balance:", hre.ethers.formatEther(balance), "ETH");
  console.log("Network:", hre.network.name);
  console.log("");

  if (balance === 0n) {
    console.error("ERROR: Deployer has no ETH. Fund the wallet first.");
    process.exit(1);
  }

  // 1. Deploy PoseidonT3 library (required by LeanIMT)
  console.log("1/5 Deploying PoseidonT3 library...");
  const PoseidonT3 = await hre.ethers.getContractFactory("PoseidonT3");
  const poseidonT3 = await PoseidonT3.deploy();
  await poseidonT3.waitForDeployment();
  const poseidonAddr = await poseidonT3.getAddress();
  console.log("     PoseidonT3:", poseidonAddr);

  // 2. Deploy Groth16 verifier (HumanUniqueness)
  console.log("2/5 Deploying Groth16Verifier (HumanUniqueness)...");
  const HumanVerifier = await hre.ethers.getContractFactory(
    "contracts/HumanVerifier.sol:Groth16Verifier"
  );
  const humanVerifier = await HumanVerifier.deploy();
  await humanVerifier.waitForDeployment();
  const humanAddr = await humanVerifier.getAddress();
  console.log("     Groth16Verifier (Human):", humanAddr);

  // 3. Deploy Groth16 verifier (AgentPolicy)
  console.log("3/5 Deploying AgentGroth16Verifier (AgentPolicy)...");
  const AgentVerifier = await hre.ethers.getContractFactory(
    "contracts/AgentVerifier.sol:AgentGroth16Verifier"
  );
  const agentVerifier = await AgentVerifier.deploy();
  await agentVerifier.waitForDeployment();
  const agentAddr = await agentVerifier.getAddress();
  console.log("     AgentGroth16Verifier:", agentAddr);

  // 4. Deploy Delegation Groth16 verifier
  console.log("4/5 Deploying DelegationGroth16Verifier...");
  const DelegationVerifier = await hre.ethers.getContractFactory(
    "contracts/DelegationVerifier.sol:DelegationGroth16Verifier"
  );
  const delegationVerifier = await DelegationVerifier.deploy();
  await delegationVerifier.waitForDeployment();
  const delegationAddr = await delegationVerifier.getAddress();
  console.log("     DelegationGroth16Verifier:", delegationAddr);

  // 5. Deploy IdentityRegistry (main contract)
  console.log("5/5 Deploying IdentityRegistry...");
  const IdentityRegistry = await hre.ethers.getContractFactory(
    "IdentityRegistry",
    { libraries: { PoseidonT3: poseidonAddr } }
  );
  const registry = await IdentityRegistry.deploy(
    humanAddr,
    agentAddr,
    delegationAddr
  );
  await registry.waitForDeployment();
  const registryAddr = await registry.getAddress();
  console.log("     IdentityRegistry:", registryAddr);

  // Summary
  console.log("\n========================================");
  console.log("  BOLYRA DEPLOYMENT COMPLETE");
  console.log("========================================");
  console.log("  Network:              ", hre.network.name);
  console.log("  PoseidonT3:                 ", poseidonAddr);
  console.log("  Groth16Verifier (Human):    ", humanAddr);
  console.log("  AgentGroth16Verifier:       ", agentAddr);
  console.log("  DelegationGroth16Verifier:  ", delegationAddr);
  console.log("  IdentityRegistry:           ", registryAddr);
  console.log("========================================");
  console.log("");
  console.log("  Add to SDK config:");
  console.log(`    registryAddress: "${registryAddr}"`);
  console.log("");
  console.log("  View on BaseScan:");
  console.log(`    https://sepolia.basescan.org/address/${registryAddr}`);

  // Write deployment addresses to JSON
  const deployment = {
    network: hre.network.name,
    chainId: (await hre.ethers.provider.getNetwork()).chainId.toString(),
    timestamp: new Date().toISOString(),
    deployer: deployer.address,
    contracts: {
      PoseidonT3: poseidonAddr,
      HumanGroth16Verifier: humanAddr,
      AgentGroth16Verifier: agentAddr,
      DelegationGroth16Verifier: delegationAddr,
      IdentityRegistry: registryAddr,
    },
  };

  const fs = require("fs");
  fs.writeFileSync(
    "deployments/base-sepolia.json",
    JSON.stringify(deployment, null, 2)
  );
  console.log("  Deployment saved to: deployments/base-sepolia.json");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
