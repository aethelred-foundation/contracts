/**
 * Aethelred Bridge Deployment Script
 *
 * Enterprise-grade deployment script for the AethelredBridge contract.
 * Supports UUPS proxy pattern for upgradeability.
 *
 * Usage:
 *   npx hardhat run scripts/deploy.ts --network devnet
 *   npx hardhat run scripts/deploy.ts --network sepolia
 *   npx hardhat run scripts/deploy.ts --network mainnet
 *
 * Environment Variables Required:
 *   - DEPLOYER_PRIVATE_KEY: Private key of deployer account
 *   - ADMIN_ADDRESS: Address to receive admin role (defaults to deployer)
 *   - RELAYER_ADDRESSES: Comma-separated list of relayer addresses
 *   - CONSENSUS_THRESHOLD_BPS: Consensus threshold in basis points (default: 6700)
 *
 * @author Aethelred Team
 * @license Apache-2.0
 */

import { ethers, upgrades, network } from "hardhat";
import { AethelredBridge } from "../typechain-types";
import * as fs from "fs";
import * as path from "path";

// ============================================================================
// Configuration Types
// ============================================================================

interface DeploymentConfig {
  adminAddress: string;
  relayerAddresses: string[];
  consensusThresholdBps: number;
  upgraderTimelockAddress?: string;
  timelockProposers: string[];
  timelockExecutors: string[];
  timelockAdminAddress: string;
  upgraderTimelockMinDelaySeconds: number;
  networkName: string;
  chainId: number;
}

interface DeploymentResult {
  proxyAddress: string;
  implementationAddress: string;
  adminAddress: string;
  relayerAddresses: string[];
  consensusThresholdBps: number;
  upgraderTimelockAddress: string;
  upgraderTimelockMinDelaySeconds: number;
  deploymentTimestamp: number;
  transactionHash: string;
  blockNumber: number;
  deployer: string;
  networkName: string;
  chainId: number;
}

const UPGRADER_TIMELOCK_MIN_DELAY_SECONDS = 27 * 24 * 60 * 60;

function parseAddressList(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw
    .split(",")
    .map((value) => value.trim())
    .filter((value) => value.length > 0);
}

// ============================================================================
// Default Configurations per Network
// ============================================================================

const NETWORK_CONFIGS: Record<string, Partial<DeploymentConfig>> = {
  // DevNet - Local development with mock relayers
  devnet: {
    consensusThresholdBps: 6700, // 67%
    relayerAddresses: [
      "0x0000000000000000000000000000000000000004", // bridge-relayer from genesis
    ],
  },

  // Sepolia Testnet
  sepolia: {
    consensusThresholdBps: 6700,
    relayerAddresses: [], // Must be provided via environment
  },

  // Mainnet - Production configuration
  mainnet: {
    consensusThresholdBps: 6700,
    relayerAddresses: [], // Must be provided via environment
  },

  // Hardhat Local
  hardhat: {
    consensusThresholdBps: 6700,
    relayerAddresses: [], // Will use hardhat accounts
  },
};

// ============================================================================
// Deployment Functions
// ============================================================================

async function getDeploymentConfig(): Promise<DeploymentConfig> {
  const networkName = network.name;
  const chainId = network.config.chainId ?? 31337;
  const [deployer] = await ethers.getSigners();

  console.log(`\n📋 Preparing deployment configuration for network: ${networkName} (chainId: ${chainId})`);

  // Get network-specific defaults
  const networkConfig = NETWORK_CONFIGS[networkName] ?? {};

  // Admin address (defaults to deployer)
  const adminAddress = process.env.ADMIN_ADDRESS ?? deployer.address;
  console.log(`   Admin: ${adminAddress}`);

  // Relayer addresses
  let relayerAddresses: string[];

  if (process.env.RELAYER_ADDRESSES) {
    relayerAddresses = process.env.RELAYER_ADDRESSES.split(",").map((addr) => addr.trim());
  } else if (networkConfig.relayerAddresses && networkConfig.relayerAddresses.length > 0) {
    relayerAddresses = networkConfig.relayerAddresses;
  } else if (networkName === "hardhat" || networkName === "devnet") {
    // Use first few hardhat accounts as relayers for testing
    const signers = await ethers.getSigners();
    relayerAddresses = signers.slice(1, 4).map((s) => s.address);
  } else {
    throw new Error(
      `No relayer addresses configured for network ${networkName}. ` +
      `Set RELAYER_ADDRESSES environment variable.`
    );
  }

  console.log(`   Relayers (${relayerAddresses.length}):`);
  relayerAddresses.forEach((addr, i) => console.log(`     ${i + 1}. ${addr}`));

  // Consensus threshold
  const consensusThresholdBps = process.env.CONSENSUS_THRESHOLD_BPS
    ? parseInt(process.env.CONSENSUS_THRESHOLD_BPS, 10)
    : networkConfig.consensusThresholdBps ?? 6700;

  console.log(`   Consensus Threshold: ${consensusThresholdBps / 100}%`);

  // Calculate minimum votes required
  const minVotes = Math.max(1, Math.floor((relayerAddresses.length * consensusThresholdBps) / 10000));
  console.log(`   Minimum Votes Required: ${minVotes}/${relayerAddresses.length}`);

  const timelockAdminAddress = process.env.TIMELOCK_ADMIN_ADDRESS ?? adminAddress;
  const timelockProposers = parseAddressList(process.env.TIMELOCK_PROPOSERS);
  const timelockExecutors = parseAddressList(process.env.TIMELOCK_EXECUTORS);
  const upgraderTimelockAddress = process.env.UPGRADER_TIMELOCK_ADDRESS?.trim();
  const upgraderTimelockMinDelaySeconds = process.env.UPGRADER_TIMELOCK_MIN_DELAY_SECONDS
    ? parseInt(process.env.UPGRADER_TIMELOCK_MIN_DELAY_SECONDS, 10)
    : UPGRADER_TIMELOCK_MIN_DELAY_SECONDS;

  if (upgraderTimelockMinDelaySeconds < UPGRADER_TIMELOCK_MIN_DELAY_SECONDS) {
    throw new Error(
      `UPGRADER_TIMELOCK_MIN_DELAY_SECONDS must be >= ${UPGRADER_TIMELOCK_MIN_DELAY_SECONDS} (27 days)`
    );
  }

  if (!upgraderTimelockAddress) {
    if (timelockProposers.length === 0) {
      timelockProposers.push(adminAddress);
    }
    if (timelockExecutors.length === 0) {
      timelockExecutors.push(adminAddress);
    }
  }

  console.log(`   Upgrader Timelock: ${upgraderTimelockAddress ?? "(deploy new)"}`);
  console.log(`   Timelock Delay: ${upgraderTimelockMinDelaySeconds}s`);
  console.log(`   Timelock Admin: ${timelockAdminAddress}`);
  console.log(`   Timelock Proposers (${timelockProposers.length})`);
  console.log(`   Timelock Executors (${timelockExecutors.length})`);

  return {
    adminAddress,
    relayerAddresses,
    consensusThresholdBps,
    upgraderTimelockAddress,
    timelockProposers,
    timelockExecutors,
    timelockAdminAddress,
    upgraderTimelockMinDelaySeconds,
    networkName,
    chainId,
  };
}

async function deployBridge(config: DeploymentConfig): Promise<DeploymentResult> {
  const [deployer] = await ethers.getSigners();

  console.log(`\n🚀 Deploying AethelredBridge...`);
  console.log(`   Deployer: ${deployer.address}`);

  // Check deployer balance
  const balance = await ethers.provider.getBalance(deployer.address);
  console.log(`   Balance: ${ethers.formatEther(balance)} ETH`);

  if (balance < ethers.parseEther("0.01")) {
    throw new Error("Insufficient deployer balance. Need at least 0.01 ETH.");
  }

  let upgraderTimelockAddress = config.upgraderTimelockAddress;
  if (!upgraderTimelockAddress) {
    console.log(`\n⏱️  Deploying upgrade timelock (27-day min delay)...`);
    const TimelockFactory = await ethers.getContractFactory("TimelockController");
    const timelock = await TimelockFactory.deploy(
      config.upgraderTimelockMinDelaySeconds,
      config.timelockProposers,
      config.timelockExecutors,
      config.timelockAdminAddress
    );
    await timelock.waitForDeployment();
    upgraderTimelockAddress = await timelock.getAddress();
    console.log(`   Timelock Address: ${upgraderTimelockAddress}`);
  } else {
    const code = await ethers.provider.getCode(upgraderTimelockAddress);
    if (code === "0x") {
      throw new Error(`UPGRADER_TIMELOCK_ADDRESS ${upgraderTimelockAddress} is not a deployed contract`);
    }
  }

  const timelock = await ethers.getContractAt("TimelockController", upgraderTimelockAddress);
  const timelockDelay = Number(await timelock.getMinDelay());
  if (timelockDelay < UPGRADER_TIMELOCK_MIN_DELAY_SECONDS) {
    throw new Error(
      `Timelock min delay ${timelockDelay}s is below required ${UPGRADER_TIMELOCK_MIN_DELAY_SECONDS}s (27 days)`
    );
  }
  console.log(`   Timelock Verified Delay: ${timelockDelay}s`);

  // Get contract factory
  const BridgeFactory = await ethers.getContractFactory("AethelredBridge");

  console.log(`\n📦 Deploying UUPS proxy...`);

  // Deploy with UUPS proxy
  const bridge = await upgrades.deployProxy(
    BridgeFactory,
    [
      config.adminAddress,
      upgraderTimelockAddress,
      config.relayerAddresses,
      config.consensusThresholdBps,
    ],
    {
      kind: "uups",
      initializer: "initializeWithTimelock",
      timeout: 120000,
      pollingInterval: 5000,
    }
  ) as unknown as AethelredBridge;

  // Wait for deployment
  await bridge.waitForDeployment();

  const proxyAddress = await bridge.getAddress();
  const implementationAddress = await upgrades.erc1967.getImplementationAddress(proxyAddress);

  // Get deployment transaction
  const deploymentTx = bridge.deploymentTransaction();
  if (!deploymentTx) {
    throw new Error("Could not get deployment transaction");
  }

  const receipt = await deploymentTx.wait();
  if (!receipt) {
    throw new Error("Could not get transaction receipt");
  }

  console.log(`\n✅ Deployment Successful!`);
  console.log(`   Proxy Address: ${proxyAddress}`);
  console.log(`   Implementation Address: ${implementationAddress}`);
  console.log(`   Transaction Hash: ${receipt.hash}`);
  console.log(`   Block Number: ${receipt.blockNumber}`);
  console.log(`   Gas Used: ${receipt.gasUsed.toString()}`);

  return {
    proxyAddress,
    implementationAddress,
    adminAddress: config.adminAddress,
    relayerAddresses: config.relayerAddresses,
    consensusThresholdBps: config.consensusThresholdBps,
    upgraderTimelockAddress,
    upgraderTimelockMinDelaySeconds: timelockDelay,
    deploymentTimestamp: Math.floor(Date.now() / 1000),
    transactionHash: receipt.hash,
    blockNumber: receipt.blockNumber,
    deployer: deployer.address,
    networkName: config.networkName,
    chainId: config.chainId,
  };
}

async function verifyDeployment(
  bridge: AethelredBridge,
  config: DeploymentConfig,
  result: DeploymentResult
): Promise<void> {
  console.log(`\n🔍 Verifying deployment...`);

  // Verify relayer configuration
  const relayerConfig = await bridge.relayerConfig();
  console.log(`   Relayer Count: ${relayerConfig.relayerCount}`);
  console.log(`   Consensus Threshold: ${relayerConfig.consensusThresholdBps} bps`);
  console.log(`   Min Votes Required: ${relayerConfig.minVotesRequired}`);

  // Verify rate limit configuration
  const rateLimitConfig = await bridge.rateLimitConfig();
  console.log(`   Rate Limit Enabled: ${rateLimitConfig.enabled}`);
  console.log(`   Max Deposit/Period: ${ethers.formatEther(rateLimitConfig.maxDepositPerPeriod)} ETH`);
  console.log(`   Max Withdrawal/Period: ${ethers.formatEther(rateLimitConfig.maxWithdrawalPerPeriod)} ETH`);

  // Verify roles
  const RELAYER_ROLE = await bridge.RELAYER_ROLE();
  const GUARDIAN_ROLE = await bridge.GUARDIAN_ROLE();
  const ADMIN_ROLE = await bridge.DEFAULT_ADMIN_ROLE();

  const hasAdminRole = await bridge.hasRole(ADMIN_ROLE, config.adminAddress);
  console.log(`   Admin Role Granted: ${hasAdminRole}`);

  const hasGuardianRole = await bridge.hasRole(GUARDIAN_ROLE, config.adminAddress);
  console.log(`   Guardian Role Granted: ${hasGuardianRole}`);

  const UPGRADER_ROLE = await bridge.UPGRADER_ROLE();
  const timelockHasUpgradeRole = await bridge.hasRole(UPGRADER_ROLE, result.upgraderTimelockAddress);
  console.log(`   Timelock UPGRADER_ROLE Granted: ${timelockHasUpgradeRole}`);
  const adminHasUpgradeRole = await bridge.hasRole(UPGRADER_ROLE, config.adminAddress);
  console.log(`   Admin UPGRADER_ROLE Granted: ${adminHasUpgradeRole} (expected false)`);

  // Verify all relayers have role
  for (const relayer of config.relayerAddresses) {
    const hasRole = await bridge.hasRole(RELAYER_ROLE, relayer);
    console.log(`   Relayer ${relayer.slice(0, 10)}... Role: ${hasRole}`);
  }

  // Verify contract is not paused
  const paused = await bridge.paused();
  console.log(`   Contract Paused: ${paused}`);

  console.log(`\n✅ Deployment verification complete!`);
}

function saveDeployment(result: DeploymentResult): void {
  const deploymentsDir = path.join(__dirname, "..", "deployments");
  const networkDir = path.join(deploymentsDir, result.networkName);

  // Create directories if they don't exist
  if (!fs.existsSync(deploymentsDir)) {
    fs.mkdirSync(deploymentsDir, { recursive: true });
  }
  if (!fs.existsSync(networkDir)) {
    fs.mkdirSync(networkDir, { recursive: true });
  }

  // Save deployment info
  const deploymentFile = path.join(networkDir, "AethelredBridge.json");
  fs.writeFileSync(deploymentFile, JSON.stringify(result, null, 2));
  console.log(`\n💾 Deployment saved to: ${deploymentFile}`);

  // Save addresses for quick reference
  const addressesFile = path.join(networkDir, "addresses.json");
  const addresses = {
    AethelredBridge: {
      proxy: result.proxyAddress,
      implementation: result.implementationAddress,
      upgraderTimelock: result.upgraderTimelockAddress,
    },
    deployedAt: new Date(result.deploymentTimestamp * 1000).toISOString(),
  };
  fs.writeFileSync(addressesFile, JSON.stringify(addresses, null, 2));

  // Also update .env.deployed for easy access
  const envFile = path.join(__dirname, "..", ".env.deployed");
  const envContent = `
# Auto-generated deployment addresses for ${result.networkName}
# Generated at: ${new Date().toISOString()}
BRIDGE_PROXY_ADDRESS=${result.proxyAddress}
BRIDGE_IMPLEMENTATION_ADDRESS=${result.implementationAddress}
BRIDGE_UPGRADER_TIMELOCK_ADDRESS=${result.upgraderTimelockAddress}
BRIDGE_UPGRADER_TIMELOCK_MIN_DELAY_SECONDS=${result.upgraderTimelockMinDelaySeconds}
NETWORK_NAME=${result.networkName}
CHAIN_ID=${result.chainId}
`.trim();

  fs.writeFileSync(envFile, envContent);
  console.log(`   Environment file saved to: ${envFile}`);
}

// ============================================================================
// Main Entry Point
// ============================================================================

async function main(): Promise<void> {
  console.log(`
╔═══════════════════════════════════════════════════════════════════════════╗
║                     AETHELRED BRIDGE DEPLOYMENT                            ║
║                     Enterprise Lock-and-Mint Bridge                         ║
╚═══════════════════════════════════════════════════════════════════════════╝
  `);

  try {
    // Step 1: Get configuration
    const config = await getDeploymentConfig();

    // Step 2: Deploy bridge
    const result = await deployBridge(config);

    // Step 3: Get deployed contract
    const BridgeFactory = await ethers.getContractFactory("AethelredBridge");
    const bridge = BridgeFactory.attach(result.proxyAddress) as AethelredBridge;

    // Step 4: Verify deployment
    await verifyDeployment(bridge, config, result);

    // Step 5: Save deployment info
    saveDeployment(result);

    console.log(`
╔═══════════════════════════════════════════════════════════════════════════╗
║                         DEPLOYMENT COMPLETE                                 ║
╠═══════════════════════════════════════════════════════════════════════════╣
║  Proxy Address:          ${result.proxyAddress}      ║
║  Implementation Address: ${result.implementationAddress}      ║
║  Network:                ${result.networkName.padEnd(46)}║
╚═══════════════════════════════════════════════════════════════════════════╝
    `);

  } catch (error) {
    console.error("\n❌ Deployment failed:", error);
    process.exit(1);
  }
}

// Run deployment
main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
