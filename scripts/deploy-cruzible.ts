/**
 * Cruzible Deployment Script
 *
 * Deploys the complete Cruzible liquid staking infrastructure:
 *   1. VaultTEEVerifier — TEE attestation verification
 *   2. StAETHEL         — Liquid staking token
 *   3. Cruzible       — Core staking vault
 *
 * Usage:
 *   npx hardhat run scripts/deploy-cruzible.ts --network <network>
 *
 * Environment Variables:
 *   DEPLOYER_PRIVATE_KEY  — Deployer wallet private key
 *   ADMIN_ADDRESS         — Multisig admin (required for non-local networks)
 *   TREASURY_ADDRESS      — Protocol treasury
 *   AETHEL_TOKEN_ADDRESS  — AETHEL token contract address
 */

import { ethers, upgrades } from "hardhat";

interface DeploymentAddresses {
  vaultTEEVerifier: string;
  vaultTEEVerifierImpl: string;
  stAETHEL: string;
  stAETHELImpl: string;
  cruzible: string;
  cruzibleImpl: string;
  deployer: string;
  admin: string;
  treasury: string;
  aethelToken: string;
  network: string;
  chainId: number;
  blockNumber: number;
  timestamp: string;
}

async function main() {
  const [deployer] = await ethers.getSigners();
  const network = await ethers.provider.getNetwork();
  const chainId = Number(network.chainId);

  console.log("╔══════════════════════════════════════════════════════════╗");
  console.log("║           CRUZIBLE DEPLOYMENT                       ║");
  console.log("║           Liquid Staking with TEE Verification          ║");
  console.log("╠══════════════════════════════════════════════════════════╣");
  console.log(`║  Network:  ${network.name} (chain ID: ${chainId})`);
  console.log(`║  Deployer: ${deployer.address}`);
  console.log(`║  Balance:  ${ethers.formatEther(await ethers.provider.getBalance(deployer.address))} ETH`);
  console.log("╚══════════════════════════════════════════════════════════╝\n");

  // Resolve addresses
  const isLocal = chainId === 31337 || chainId === 1337;
  const admin = process.env.ADMIN_ADDRESS || deployer.address;
  const treasury = process.env.TREASURY_ADDRESS || deployer.address;

  let aethelTokenAddr = process.env.AETHEL_TOKEN_ADDRESS;

  // Deploy mock AETHEL token for local/test networks
  if (!aethelTokenAddr && isLocal) {
    console.log("📦 Deploying mock AETHEL token for local testing...");
    const MockToken = await ethers.getContractFactory("AethelredToken");
    const mockToken = await upgrades.deployProxy(
      MockToken,
      [admin, deployer.address, deployer.address, ethers.parseEther("1000000000")],
      { kind: "uups" }
    );
    await mockToken.waitForDeployment();
    aethelTokenAddr = await mockToken.getAddress();
    console.log(`   ✅ Mock AETHEL: ${aethelTokenAddr}\n`);
  }

  if (!aethelTokenAddr) {
    throw new Error("AETHEL_TOKEN_ADDRESS required for non-local networks");
  }

  // ─────────────────────────────────────────────────────────────────────
  // Step 1: Deploy VaultTEEVerifier
  // ─────────────────────────────────────────────────────────────────────

  console.log("📦 Step 1/3: Deploying VaultTEEVerifier...");
  const VaultTEEVerifier = await ethers.getContractFactory("VaultTEEVerifier");
  const verifier = await upgrades.deployProxy(VaultTEEVerifier, [admin], {
    kind: "uups",
  });
  await verifier.waitForDeployment();
  const verifierAddr = await verifier.getAddress();
  const verifierImplAddr = await upgrades.erc1967.getImplementationAddress(verifierAddr);
  console.log(`   ✅ VaultTEEVerifier Proxy: ${verifierAddr}`);
  console.log(`   ✅ VaultTEEVerifier Impl:  ${verifierImplAddr}\n`);

  // ─────────────────────────────────────────────────────────────────────
  // Step 2: Deploy StAETHEL (with temporary vault address)
  // ─────────────────────────────────────────────────────────────────────

  console.log("📦 Step 2/3: Deploying StAETHEL token...");
  // We need the vault address to initialize StAETHEL, but we need StAETHEL
  // to initialize the vault. Solution: deploy with admin as temporary vault,
  // then update after vault deployment.
  const StAETHEL = await ethers.getContractFactory("StAETHEL");
  const stAethel = await upgrades.deployProxy(StAETHEL, [admin, admin], {
    kind: "uups",
  });
  await stAethel.waitForDeployment();
  const stAethelAddr = await stAethel.getAddress();
  const stAethelImplAddr = await upgrades.erc1967.getImplementationAddress(stAethelAddr);
  console.log(`   ✅ StAETHEL Proxy: ${stAethelAddr}`);
  console.log(`   ✅ StAETHEL Impl:  ${stAethelImplAddr}\n`);

  // ─────────────────────────────────────────────────────────────────────
  // Step 3: Deploy Cruzible
  // ─────────────────────────────────────────────────────────────────────

  console.log("📦 Step 3/3: Deploying Cruzible...");
  const Cruzible = await ethers.getContractFactory("Cruzible");
  const vault = await upgrades.deployProxy(
    Cruzible,
    [admin, aethelTokenAddr, stAethelAddr, verifierAddr, treasury],
    { kind: "uups" }
  );
  await vault.waitForDeployment();
  const vaultAddr = await vault.getAddress();
  const vaultImplAddr = await upgrades.erc1967.getImplementationAddress(vaultAddr);
  console.log(`   ✅ Cruzible Proxy: ${vaultAddr}`);
  console.log(`   ✅ Cruzible Impl:  ${vaultImplAddr}\n`);

  // ─────────────────────────────────────────────────────────────────────
  // Post-deployment: Grant VAULT_ROLE to Cruzible on StAETHEL
  // ─────────────────────────────────────────────────────────────────────

  console.log("🔧 Post-deployment configuration...");

  const VAULT_ROLE = ethers.keccak256(ethers.toUtf8Bytes("VAULT_ROLE"));

  // Grant VAULT_ROLE to the vault contract
  const stAethelContract = await ethers.getContractAt("StAETHEL", stAethelAddr);
  const grantTx = await stAethelContract.grantRole(VAULT_ROLE, vaultAddr);
  await grantTx.wait();
  console.log(`   ✅ Granted VAULT_ROLE to Cruzible on StAETHEL`);

  // Revoke VAULT_ROLE from admin (was temporary)
  const revokeTx = await stAethelContract.revokeRole(VAULT_ROLE, admin);
  await revokeTx.wait();
  console.log(`   ✅ Revoked temporary VAULT_ROLE from admin\n`);

  // ─────────────────────────────────────────────────────────────────────
  // Summary
  // ─────────────────────────────────────────────────────────────────────

  const blockNumber = await ethers.provider.getBlockNumber();
  const deployment: DeploymentAddresses = {
    vaultTEEVerifier: verifierAddr,
    vaultTEEVerifierImpl: verifierImplAddr,
    stAETHEL: stAethelAddr,
    stAETHELImpl: stAethelImplAddr,
    cruzible: vaultAddr,
    cruzibleImpl: vaultImplAddr,
    deployer: deployer.address,
    admin,
    treasury,
    aethelToken: aethelTokenAddr,
    network: network.name,
    chainId,
    blockNumber,
    timestamp: new Date().toISOString(),
  };

  console.log("╔══════════════════════════════════════════════════════════╗");
  console.log("║           DEPLOYMENT COMPLETE                          ║");
  console.log("╠══════════════════════════════════════════════════════════╣");
  console.log(`║  VaultTEEVerifier: ${verifierAddr}`);
  console.log(`║  StAETHEL:         ${stAethelAddr}`);
  console.log(`║  Cruzible:      ${vaultAddr}`);
  console.log(`║  AETHEL Token:     ${aethelTokenAddr}`);
  console.log(`║  Admin:            ${admin}`);
  console.log(`║  Treasury:         ${treasury}`);
  console.log(`║  Block:            ${blockNumber}`);
  console.log("╚══════════════════════════════════════════════════════════╝");

  // Write deployment addresses to file
  const fs = await import("fs");
  const path = await import("path");
  const deployDir = path.join(__dirname, "..", "deployments");
  if (!fs.existsSync(deployDir)) {
    fs.mkdirSync(deployDir, { recursive: true });
  }
  const deployFile = path.join(deployDir, `vault-${network.name}-${chainId}.json`);
  fs.writeFileSync(deployFile, JSON.stringify(deployment, null, 2));
  console.log(`\n📝 Deployment addresses saved to: ${deployFile}`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("❌ Deployment failed:", error);
    process.exit(1);
  });
