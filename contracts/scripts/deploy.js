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
  const Groth16Verifier = await hre.ethers.getContractFactory("Groth16Verifier");
  const groth16Verifier = await Groth16Verifier.deploy();
  await groth16Verifier.waitForDeployment();
  const groth16Addr = await groth16Verifier.getAddress();
  console.log("     Groth16Verifier:", groth16Addr);

  // 3. Deploy PLONK verifier (AgentPolicy)
  console.log("3/5 Deploying PlonkVerifier (AgentPolicy)...");
  const PlonkVerifier = await hre.ethers.getContractFactory(
    "contracts/AgentVerifier.sol:PlonkVerifier"
  );
  const plonkVerifier = await PlonkVerifier.deploy();
  await plonkVerifier.waitForDeployment();
  const plonkAddr = await plonkVerifier.getAddress();
  console.log("     PlonkVerifier:", plonkAddr);

  // 4. Deploy Delegation PLONK verifier
  console.log("4/5 Deploying DelegationPlonkVerifier...");
  const DelegationVerifier = await hre.ethers.getContractFactory(
    "DelegationPlonkVerifier"
  );
  const delegationVerifier = await DelegationVerifier.deploy();
  await delegationVerifier.waitForDeployment();
  const delegationAddr = await delegationVerifier.getAddress();
  console.log("     DelegationPlonkVerifier:", delegationAddr);

  // 5. Deploy IdentityRegistry (main contract)
  console.log("5/5 Deploying IdentityRegistry...");
  const IdentityRegistry = await hre.ethers.getContractFactory(
    "IdentityRegistry",
    { libraries: { PoseidonT3: poseidonAddr } }
  );
  const registry = await IdentityRegistry.deploy(
    groth16Addr,
    plonkAddr,
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
  console.log("  PoseidonT3:           ", poseidonAddr);
  console.log("  Groth16Verifier:      ", groth16Addr);
  console.log("  PlonkVerifier:        ", plonkAddr);
  console.log("  DelegationVerifier:   ", delegationAddr);
  console.log("  IdentityRegistry:     ", registryAddr);
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
      Groth16Verifier: groth16Addr,
      PlonkVerifier: plonkAddr,
      DelegationPlonkVerifier: delegationAddr,
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
