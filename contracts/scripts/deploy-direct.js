#!/usr/bin/env node
/**
 * Direct deployment to Base Sepolia using ethers.js (no hardhat runtime).
 * Bypasses the "intrinsic gas too high" issue with hardhat's gas estimation.
 */
require("dotenv").config();
const { ethers } = require("ethers");
const fs = require("fs");
const path = require("path");

const ARTIFACTS = path.join(__dirname, "..", "artifacts");

function loadArtifact(contractPath) {
  return JSON.parse(fs.readFileSync(path.join(ARTIFACTS, contractPath)));
}

async function main() {
  const provider = new ethers.JsonRpcProvider(
    process.env.BASE_SEPOLIA_RPC_URL || "https://sepolia.base.org"
  );
  const wallet = new ethers.Wallet(process.env.DEPLOYER_PRIVATE_KEY, provider);

  console.log("Deployer:", wallet.address);
  const bal = await provider.getBalance(wallet.address);
  console.log("Balance:", ethers.formatEther(bal), "ETH");
  console.log("Chain:", (await provider.getNetwork()).chainId.toString());
  console.log("");

  // 1. PoseidonT3
  console.log("1/5 Deploying PoseidonT3...");
  const poseidonArt = loadArtifact("poseidon-solidity/PoseidonT3.sol/PoseidonT3.json");
  const PoseidonFactory = new ethers.ContractFactory(poseidonArt.abi, poseidonArt.bytecode, wallet);
  const poseidon = await PoseidonFactory.deploy({ gasLimit: 5000000 });
  await poseidon.waitForDeployment();
  const poseidonAddr = await poseidon.getAddress();
  console.log("     PoseidonT3:", poseidonAddr);

  // 2. Groth16Verifier
  console.log("2/5 Deploying Groth16Verifier...");
  const groth16Art = loadArtifact("contracts/HumanVerifier.sol/Groth16Verifier.json");
  const Groth16Factory = new ethers.ContractFactory(groth16Art.abi, groth16Art.bytecode, wallet);
  const groth16 = await Groth16Factory.deploy({ gasLimit: 2000000 });
  await groth16.waitForDeployment();
  const groth16Addr = await groth16.getAddress();
  console.log("     Groth16Verifier:", groth16Addr);

  // 3. AgentGroth16Verifier (AgentPolicy)
  console.log("3/5 Deploying AgentGroth16Verifier...");
  const agentArt = loadArtifact("contracts/AgentVerifier.sol/AgentGroth16Verifier.json");
  const AgentFactory = new ethers.ContractFactory(agentArt.abi, agentArt.bytecode, wallet);
  const agent = await AgentFactory.deploy({ gasLimit: 2000000 });
  await agent.waitForDeployment();
  const agentAddr = await agent.getAddress();
  console.log("     AgentGroth16Verifier:", agentAddr);

  // 4. DelegationGroth16Verifier
  console.log("4/5 Deploying DelegationGroth16Verifier...");
  const delegArt = loadArtifact("contracts/DelegationVerifier.sol/DelegationGroth16Verifier.json");
  const DelegFactory = new ethers.ContractFactory(delegArt.abi, delegArt.bytecode, wallet);
  const deleg = await DelegFactory.deploy({ gasLimit: 2000000 });
  await deleg.waitForDeployment();
  const delegAddr = await deleg.getAddress();
  console.log("     DelegationGroth16Verifier:", delegAddr);

  // 5. IdentityRegistry (link PoseidonT3 library)
  console.log("5/5 Deploying IdentityRegistry...");
  const registryArt = loadArtifact("contracts/IdentityRegistry.sol/IdentityRegistry.json");
  let bytecode = registryArt.bytecode;
  // Replace library placeholder with deployed PoseidonT3 address
  const addrClean = poseidonAddr.toLowerCase().replace("0x", "");
  // Hardhat uses __$<hash>$__ format for library placeholders
  bytecode = bytecode.replace(/__\$[a-f0-9]{34}\$__/g, addrClean);

  const RegistryFactory = new ethers.ContractFactory(registryArt.abi, bytecode, wallet);
  const registry = await RegistryFactory.deploy(groth16Addr, agentAddr, delegAddr, {
    gasLimit: 8000000,
  });
  await registry.waitForDeployment();
  const registryAddr = await registry.getAddress();
  console.log("     IdentityRegistry:", registryAddr);

  // Summary
  console.log("\n========================================");
  console.log("  BOLYRA DEPLOYED ON BASE SEPOLIA");
  console.log("========================================");
  console.log("  PoseidonT3:                 ", poseidonAddr);
  console.log("  Groth16Verifier (Human):    ", groth16Addr);
  console.log("  AgentGroth16Verifier:       ", agentAddr);
  console.log("  DelegationGroth16Verifier:  ", delegAddr);
  console.log("  IdentityRegistry:           ", registryAddr);
  console.log("========================================");
  console.log("  https://sepolia.basescan.org/address/" + registryAddr);

  // Save deployment
  const deployment = {
    network: "baseSepolia",
    chainId: "84532",
    timestamp: new Date().toISOString(),
    deployer: wallet.address,
    contracts: {
      PoseidonT3: poseidonAddr,
      HumanGroth16Verifier: groth16Addr,
      AgentGroth16Verifier: agentAddr,
      DelegationGroth16Verifier: delegAddr,
      IdentityRegistry: registryAddr,
    },
  };
  fs.mkdirSync("deployments", { recursive: true });
  fs.writeFileSync("deployments/base-sepolia.json", JSON.stringify(deployment, null, 2));
  console.log("  Saved to deployments/base-sepolia.json");
}

main().catch((e) => {
  console.error("FAILED:", e.message);
  process.exit(1);
});
