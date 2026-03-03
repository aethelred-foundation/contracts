import { ethers } from "hardhat";

const DEFAULT_MAX_ASSETS_PER_RUN = 16n;

function parseAssetIds(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((id) => (id.startsWith("0x") && id.length === 66 ? id : ethers.id(id)));
}

async function main() {
  const bridgeAddress = process.env.INSTITUTIONAL_BRIDGE_ADDRESS;
  if (!bridgeAddress) {
    throw new Error("INSTITUTIONAL_BRIDGE_ADDRESS is required");
  }

  const ownerAddress = process.env.KEEPER_OWNER_ADDRESS;
  const assetIds = parseAssetIds(process.env.RESERVE_MONITOR_ASSET_IDS);
  const maxAssetsPerRun = process.env.MAX_ASSETS_PER_RUN
    ? BigInt(process.env.MAX_ASSETS_PER_RUN)
    : DEFAULT_MAX_ASSETS_PER_RUN;
  const grantPauserRole = process.env.GRANT_PAUSER_ROLE_TO_KEEPER !== "false";

  const [deployer] = await ethers.getSigners();
  console.log("Deployer:", deployer.address);
  console.log("Institutional bridge:", bridgeAddress);
  console.log("Tracked assets:", assetIds.length);

  const Factory = await ethers.getContractFactory("InstitutionalReserveAutomationKeeper");
  const keeper = await Factory.deploy(bridgeAddress, assetIds);
  await keeper.waitForDeployment();

  const keeperAddress = await keeper.getAddress();
  console.log("Automation keeper deployed:", keeperAddress);

  if (maxAssetsPerRun !== DEFAULT_MAX_ASSETS_PER_RUN) {
    await (await keeper.setMaxAssetsPerRun(maxAssetsPerRun)).wait();
  }

  if (ownerAddress && ownerAddress.toLowerCase() !== deployer.address.toLowerCase()) {
    console.log("Transferring keeper ownership to:", ownerAddress);
    await (await keeper.transferOwnership(ownerAddress)).wait();
  }

  const bridge = await ethers.getContractAt("InstitutionalStablecoinBridge", bridgeAddress);
  if (grantPauserRole) {
    const pauserRole = await bridge.PAUSER_ROLE();
    const hasRole = await bridge.hasRole(pauserRole, keeperAddress);
    if (!hasRole) {
      console.log("Granting PAUSER_ROLE to automation keeper...");
      await (await bridge.grantRole(pauserRole, keeperAddress)).wait();
    }
  }

  console.log("Done.");
  console.log(
    JSON.stringify(
      {
        keeperAddress,
        bridgeAddress,
        trackedAssets: assetIds,
        owner: ownerAddress ?? deployer.address,
        maxAssetsPerRun: maxAssetsPerRun.toString(),
      },
      null,
      2
    )
  );
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
