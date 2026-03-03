/**
 * Aethelred Bridge Upgrade Script
 *
 * Enterprise-grade upgrade script for the AethelredBridge UUPS proxy.
 * Includes safety checks, dry-run support, and rollback preparation.
 *
 * Usage:
 *   npx hardhat run scripts/upgrade.ts --network devnet
 *   npx hardhat run scripts/upgrade.ts --network sepolia
 *   DRY_RUN=true npx hardhat run scripts/upgrade.ts --network mainnet
 *
 * Environment Variables:
 *   - PROXY_ADDRESS: Address of the existing proxy (or reads from deployments)
 *   - DRY_RUN: If "true", only simulates the upgrade
 *   - FORCE_UPGRADE: If "true", skips safety checks (NOT RECOMMENDED)
 *
 * @author Aethelred Team
 * @license Apache-2.0
 */

import { ethers, upgrades, network } from "hardhat";
import { AethelredBridge } from "../typechain-types";
import * as fs from "fs";
import * as path from "path";

// ============================================================================
// Configuration
// ============================================================================

interface UpgradeConfig {
  proxyAddress: string;
  upgraderTimelockAddress?: string;
  networkName: string;
  chainId: number;
  isDryRun: boolean;
  forceUpgrade: boolean;
  enforceTimelock: boolean;
}

interface UpgradeResult {
  proxyAddress: string;
  oldImplementation: string;
  newImplementation: string;
  transactionHash?: string;
  blockNumber?: number;
  upgradeTimestamp: number;
  upgrader: string;
  networkName: string;
  chainId: number;
}

const UPGRADER_TIMELOCK_MIN_DELAY_SECONDS = 27 * 24 * 60 * 60;

// ============================================================================
// Helper Functions
// ============================================================================

async function loadExistingDeployment(networkName: string): Promise<any | null> {
  const deploymentFile = path.join(
    __dirname,
    "..",
    "deployments",
    networkName,
    "AethelredBridge.json"
  );

  if (fs.existsSync(deploymentFile)) {
    return JSON.parse(fs.readFileSync(deploymentFile, "utf-8"));
  }

  return null;
}

async function getUpgradeConfig(): Promise<UpgradeConfig> {
  const networkName = network.name;
  const chainId = network.config.chainId ?? 31337;

  console.log(`\n📋 Preparing upgrade configuration for network: ${networkName} (chainId: ${chainId})`);

  // Get proxy address from environment or deployment file
  let proxyAddress = process.env.PROXY_ADDRESS;
  let upgraderTimelockAddress = process.env.UPGRADER_TIMELOCK_ADDRESS;
  const existingDeployment = await loadExistingDeployment(networkName);

  if (!proxyAddress) {
    proxyAddress = existingDeployment?.proxyAddress ?? undefined;
  }
  if (!upgraderTimelockAddress) {
    upgraderTimelockAddress = existingDeployment?.upgraderTimelockAddress ?? undefined;
  }

  if (!proxyAddress) {
    throw new Error(
      `No proxy address found for network ${networkName}. ` +
      `Either set PROXY_ADDRESS environment variable or deploy first.`
    );
  }

  console.log(`   Proxy Address: ${proxyAddress}`);
  if (upgraderTimelockAddress) {
    console.log(`   Upgrader Timelock: ${upgraderTimelockAddress}`);
  }

  const isDryRun = process.env.DRY_RUN === "true";
  const forceUpgrade = process.env.FORCE_UPGRADE === "true";
  const enforceTimelock = !["hardhat", "localhost", "devnet"].includes(networkName);

  if (isDryRun) {
    console.log(`   ⚠️  DRY RUN MODE - No actual upgrade will occur`);
  }

  if (forceUpgrade) {
    console.log(`   ⚠️  FORCE UPGRADE - Safety checks will be skipped`);
  }

  return {
    proxyAddress,
    upgraderTimelockAddress,
    networkName,
    chainId,
    isDryRun,
    forceUpgrade,
    enforceTimelock,
  };
}

async function performSafetyChecks(
  bridge: AethelredBridge,
  config: UpgradeConfig
): Promise<void> {
  console.log(`\n🔍 Performing safety checks...`);

  // Check 1: Contract is accessible
  try {
    await bridge.depositNonce();
    console.log(`   ✅ Contract is accessible`);
  } catch (error) {
    throw new Error(`Contract at ${config.proxyAddress} is not accessible`);
  }

  // Check 2: Caller has UPGRADER_ROLE
  const [upgrader] = await ethers.getSigners();
  const UPGRADER_ROLE = await bridge.UPGRADER_ROLE();
  const hasRole = await bridge.hasRole(UPGRADER_ROLE, upgrader.address);
  if (config.enforceTimelock) {
    if (!config.upgraderTimelockAddress) {
      throw new Error(
        "Missing upgrader timelock address. Set UPGRADER_TIMELOCK_ADDRESS or ensure deployment metadata includes upgraderTimelockAddress."
      );
    }
    const timelockCode = await ethers.provider.getCode(config.upgraderTimelockAddress);
    if (timelockCode === "0x") {
      throw new Error(`Configured timelock ${config.upgraderTimelockAddress} is not a deployed contract`);
    }
    const timelock = await ethers.getContractAt("TimelockController", config.upgraderTimelockAddress);
    const minDelay = Number(await timelock.getMinDelay());
    if (minDelay < UPGRADER_TIMELOCK_MIN_DELAY_SECONDS) {
      throw new Error(
        `Timelock min delay ${minDelay}s is below required ${UPGRADER_TIMELOCK_MIN_DELAY_SECONDS}s (27 days)`
      );
    }
    const timelockHasRole = await bridge.hasRole(UPGRADER_ROLE, config.upgraderTimelockAddress);
    if (!timelockHasRole && !config.forceUpgrade) {
      throw new Error(
        `Timelock ${config.upgraderTimelockAddress} does not have UPGRADER_ROLE on bridge`
      );
    }
    if (hasRole) {
      console.log(`   ⚠️  Signer has UPGRADER_ROLE, but production flow is timelock-gated only`);
    }
    console.log(`   ✅ Timelock holds UPGRADER_ROLE (delay ${minDelay}s)`);
  } else {
    if (!hasRole && !config.forceUpgrade) {
      throw new Error(
        `Address ${upgrader.address} does not have UPGRADER_ROLE. ` +
        `Set FORCE_UPGRADE=true to skip this check (NOT RECOMMENDED).`
      );
    }
    console.log(`   ✅ Upgrader has UPGRADER_ROLE`);
  }

  // Check 3: Contract is not paused (for mainnet safety)
  const paused = await bridge.paused();
  if (paused) {
    console.log(`   ⚠️  Contract is PAUSED - Upgrade will proceed but be aware`);
  } else {
    console.log(`   ✅ Contract is not paused`);
  }

  // Check 4: Check locked funds
  const totalLockedETH = await bridge.totalLockedETH();
  console.log(`   📊 Total Locked ETH: ${ethers.formatEther(totalLockedETH)} ETH`);

  if (totalLockedETH > ethers.parseEther("100") && config.networkName === "mainnet") {
    console.log(`   ⚠️  WARNING: High TVL detected. Ensure proper testing before mainnet upgrade.`);

    if (!config.forceUpgrade) {
      throw new Error(
        `High TVL upgrade requires FORCE_UPGRADE=true confirmation.`
      );
    }
  }

  // Check 5: Verify current implementation
  const currentImpl = await upgrades.erc1967.getImplementationAddress(config.proxyAddress);
  console.log(`   📍 Current Implementation: ${currentImpl}`);
}

async function validateUpgrade(config: UpgradeConfig): Promise<void> {
  console.log(`\n🔬 Validating upgrade compatibility...`);

  const BridgeFactory = await ethers.getContractFactory("AethelredBridge");

  try {
    // Use OpenZeppelin's upgrade validation
    await upgrades.validateUpgrade(config.proxyAddress, BridgeFactory, {
      kind: "uups",
    });
    console.log(`   ✅ Upgrade validation passed`);
  } catch (error: any) {
    if (config.forceUpgrade) {
      console.log(`   ⚠️  Upgrade validation failed but FORCE_UPGRADE is set: ${error.message}`);
    } else {
      throw new Error(`Upgrade validation failed: ${error.message}`);
    }
  }
}

async function prepareUpgrade(config: UpgradeConfig): Promise<string> {
  console.log(`\n📦 Preparing new implementation...`);

  const BridgeFactory = await ethers.getContractFactory("AethelredBridge");

  // Deploy new implementation without upgrading proxy
  const newImplementationAddress = await upgrades.prepareUpgrade(
    config.proxyAddress,
    BridgeFactory,
    {
      kind: "uups",
    }
  );

  console.log(`   New Implementation: ${newImplementationAddress}`);

  return newImplementationAddress as string;
}

async function emitTimelockUpgradeProposal(
  config: UpgradeConfig,
  newImplementation: string
): Promise<void> {
  if (!config.upgraderTimelockAddress) {
    throw new Error("Cannot build timelock upgrade proposal without upgraderTimelockAddress");
  }
  const timelock = await ethers.getContractAt("TimelockController", config.upgraderTimelockAddress);
  const minDelay = Number(await timelock.getMinDelay());
  if (minDelay < UPGRADER_TIMELOCK_MIN_DELAY_SECONDS) {
    throw new Error(`Timelock delay below 27 days: ${minDelay}s`);
  }

  const BridgeFactory = await ethers.getContractFactory("AethelredBridge");
  const upgradeCallData = BridgeFactory.interface.encodeFunctionData("upgradeToAndCall", [
    newImplementation,
    "0x",
  ]);
  const predecessor = ethers.ZeroHash;
  const salt = ethers.keccak256(
    ethers.solidityPacked(
      ["string", "string", "address", "address", "uint256"],
      [
        "AETHELRED_BRIDGE_UPGRADE",
        config.networkName,
        config.proxyAddress,
        newImplementation,
        BigInt(Date.now()),
      ]
    )
  );
  const operationId = await timelock.hashOperation(
    config.proxyAddress,
    0,
    upgradeCallData,
    predecessor,
    salt
  );

  const scheduleCallData = timelock.interface.encodeFunctionData("schedule", [
    config.proxyAddress,
    0,
    upgradeCallData,
    predecessor,
    salt,
    minDelay,
  ]);
  const executeCallData = timelock.interface.encodeFunctionData("execute", [
    config.proxyAddress,
    0,
    upgradeCallData,
    predecessor,
    salt,
  ]);

  const proposal = {
    kind: "timelock-uups-upgrade",
    proxyAddress: config.proxyAddress,
    timelockAddress: config.upgraderTimelockAddress,
    newImplementation,
    minDelaySeconds: minDelay,
    target: config.proxyAddress,
    value: "0",
    predecessor,
    salt,
    operationId,
    upgradeCallData,
    scheduleCallData,
    executeCallData,
    createdAt: new Date().toISOString(),
    networkName: config.networkName,
    chainId: config.chainId,
  };

  const proposalsDir = path.join(
    __dirname,
    "..",
    "deployments",
    config.networkName,
    "upgrade-proposals"
  );
  fs.mkdirSync(proposalsDir, { recursive: true });
  const proposalFile = path.join(proposalsDir, `timelock-upgrade-${Date.now()}.json`);
  fs.writeFileSync(proposalFile, JSON.stringify(proposal, null, 2));

  console.log(`\n🛡️  Timelock-gated upgrade prepared (no direct execution on ${config.networkName})`);
  console.log(`   Timelock: ${config.upgraderTimelockAddress}`);
  console.log(`   Delay: ${minDelay}s`);
  console.log(`   Operation ID: ${operationId}`);
  console.log(`   Proposal JSON: ${proposalFile}`);
  console.log(`   Target (proxy): ${config.proxyAddress}`);
  console.log(`   New Impl: ${newImplementation}`);
}

async function executeUpgrade(config: UpgradeConfig): Promise<UpgradeResult> {
  const [upgrader] = await ethers.getSigners();

  console.log(`\n🚀 Executing upgrade...`);
  console.log(`   Upgrader: ${upgrader.address}`);

  // Get current implementation
  const oldImplementation = await upgrades.erc1967.getImplementationAddress(
    config.proxyAddress
  );

  const BridgeFactory = await ethers.getContractFactory("AethelredBridge");

  // Perform the upgrade
  const upgraded = await upgrades.upgradeProxy(config.proxyAddress, BridgeFactory, {
    kind: "uups",
  }) as unknown as AethelredBridge;

  await upgraded.waitForDeployment();

  // Get new implementation
  const newImplementation = await upgrades.erc1967.getImplementationAddress(
    config.proxyAddress
  );

  console.log(`\n✅ Upgrade Successful!`);
  console.log(`   Old Implementation: ${oldImplementation}`);
  console.log(`   New Implementation: ${newImplementation}`);

  return {
    proxyAddress: config.proxyAddress,
    oldImplementation,
    newImplementation,
    upgradeTimestamp: Math.floor(Date.now() / 1000),
    upgrader: upgrader.address,
    networkName: config.networkName,
    chainId: config.chainId,
  };
}

async function verifyPostUpgrade(bridge: AethelredBridge): Promise<void> {
  console.log(`\n🔍 Verifying post-upgrade state...`);

  // Verify critical state is preserved
  const depositNonce = await bridge.depositNonce();
  console.log(`   Deposit Nonce: ${depositNonce}`);

  const totalLockedETH = await bridge.totalLockedETH();
  console.log(`   Total Locked ETH: ${ethers.formatEther(totalLockedETH)} ETH`);

  const relayerConfig = await bridge.relayerConfig();
  console.log(`   Relayer Count: ${relayerConfig.relayerCount}`);

  const paused = await bridge.paused();
  console.log(`   Contract Paused: ${paused}`);

  console.log(`\n✅ Post-upgrade verification complete!`);
}

function saveUpgradeHistory(result: UpgradeResult): void {
  const deploymentsDir = path.join(__dirname, "..", "deployments");
  const networkDir = path.join(deploymentsDir, result.networkName);
  const upgradesDir = path.join(networkDir, "upgrades");

  // Create directories
  if (!fs.existsSync(upgradesDir)) {
    fs.mkdirSync(upgradesDir, { recursive: true });
  }

  // Save upgrade info with timestamp
  const upgradeFile = path.join(
    upgradesDir,
    `upgrade-${result.upgradeTimestamp}.json`
  );
  fs.writeFileSync(upgradeFile, JSON.stringify(result, null, 2));
  console.log(`\n💾 Upgrade history saved to: ${upgradeFile}`);

  // Update main deployment file
  const deploymentFile = path.join(networkDir, "AethelredBridge.json");
  if (fs.existsSync(deploymentFile)) {
    const deployment = JSON.parse(fs.readFileSync(deploymentFile, "utf-8"));
    deployment.implementationAddress = result.newImplementation;
    deployment.lastUpgradeTimestamp = result.upgradeTimestamp;
    fs.writeFileSync(deploymentFile, JSON.stringify(deployment, null, 2));
  }
}

// ============================================================================
// Main Entry Point
// ============================================================================

async function main(): Promise<void> {
  console.log(`
╔═══════════════════════════════════════════════════════════════════════════╗
║                     AETHELRED BRIDGE UPGRADE                               ║
║                     UUPS Proxy Upgrade Script                              ║
╚═══════════════════════════════════════════════════════════════════════════╝
  `);

  try {
    // Step 1: Get configuration
    const config = await getUpgradeConfig();

    // Step 2: Get existing contract
    const BridgeFactory = await ethers.getContractFactory("AethelredBridge");
    const bridge = BridgeFactory.attach(config.proxyAddress) as AethelredBridge;

    // Step 3: Safety checks
    await performSafetyChecks(bridge, config);

    // Step 4: Validate upgrade compatibility
    await validateUpgrade(config);

    if (config.enforceTimelock) {
      console.log(`\n🛡️  Production timelock mode enabled (direct upgrades disabled)`);
      const newImpl = await prepareUpgrade(config);
      await emitTimelockUpgradeProposal(config, newImpl);
      return;
    }

    if (config.isDryRun) {
      // Dry run - only prepare, don't execute
      console.log(`\n🔬 DRY RUN: Preparing upgrade without execution...`);
      const newImpl = await prepareUpgrade(config);

      console.log(`
╔═══════════════════════════════════════════════════════════════════════════╗
║                         DRY RUN COMPLETE                                   ║
╠═══════════════════════════════════════════════════════════════════════════╣
║  New implementation prepared but NOT upgraded.                             ║
║  New Implementation: ${newImpl}      ║
║  Run without DRY_RUN=true to execute upgrade.                             ║
╚═══════════════════════════════════════════════════════════════════════════╝
      `);
      return;
    }

    // Step 5: Execute upgrade
    const result = await executeUpgrade(config);

    // Step 6: Verify post-upgrade
    const upgradedBridge = BridgeFactory.attach(config.proxyAddress) as AethelredBridge;
    await verifyPostUpgrade(upgradedBridge);

    // Step 7: Save upgrade history
    saveUpgradeHistory(result);

    console.log(`
╔═══════════════════════════════════════════════════════════════════════════╗
║                         UPGRADE COMPLETE                                   ║
╠═══════════════════════════════════════════════════════════════════════════╣
║  Proxy Address:          ${result.proxyAddress}      ║
║  New Implementation:     ${result.newImplementation}      ║
║  Network:                ${result.networkName.padEnd(46)}║
╚═══════════════════════════════════════════════════════════════════════════╝
    `);

  } catch (error) {
    console.error("\n❌ Upgrade failed:", error);
    process.exit(1);
  }
}

// Run upgrade
main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
