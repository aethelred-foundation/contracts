import { expect } from "chai";
import { ethers } from "hardhat";

describe("InstitutionalReserveAutomationKeeper", function () {
  it("performUpkeep calls monitorReserve on the configured bridge for enabled assets", async function () {
    const MockBridgeFactory = await ethers.getContractFactory("MockInstitutionalBridgeMonitor");
    const mockBridge = await MockBridgeFactory.deploy();
    await mockBridge.waitForDeployment();

    const assetA = ethers.id("USDC");
    const assetB = ethers.id("USDT");

    const KeeperFactory = await ethers.getContractFactory("InstitutionalReserveAutomationKeeper");
    const keeper = await KeeperFactory.deploy(await mockBridge.getAddress(), [assetA, assetB]);
    await keeper.waitForDeployment();

    // Disable one asset to ensure keeper only invokes monitorReserve for enabled assets.
    await (await keeper.setAsset(assetB, false)).wait();

    const [upkeepNeeded, performData] = await keeper.checkUpkeep("0x");
    expect(upkeepNeeded).to.equal(true);

    await expect(keeper.performUpkeep(performData))
      .to.emit(mockBridge, "ReserveMonitored")
      .withArgs(assetA);

    expect(await mockBridge.monitorCallCount()).to.equal(1n);
    expect(await mockBridge.monitorCallsByAsset(assetA)).to.equal(1n);
    expect(await mockBridge.monitorCallsByAsset(assetB)).to.equal(0n);
    expect(await mockBridge.lastMonitoredAssetId()).to.equal(assetA);
  });

  it("emits ReserveMonitorFailed and continues processing when one asset monitor reverts", async function () {
    const MockBridgeFactory = await ethers.getContractFactory("MockInstitutionalBridgeMonitor");
    const mockBridge = await MockBridgeFactory.deploy();
    await mockBridge.waitForDeployment();

    const assetA = ethers.id("USDU");
    const assetB = ethers.id("DDSC");

    const KeeperFactory = await ethers.getContractFactory("InstitutionalReserveAutomationKeeper");
    const keeper = await KeeperFactory.deploy(await mockBridge.getAddress(), [assetA, assetB]);
    await keeper.waitForDeployment();

    await (await mockBridge.setShouldRevert(assetA, true)).wait();

    const [, performData] = await keeper.checkUpkeep("0x");

    await expect(keeper.performUpkeep(performData))
      .to.emit(keeper, "ReserveMonitorFailed")
      .and.to.emit(mockBridge, "ReserveMonitored")
      .withArgs(assetB);

    // Failed asset should not increment counters; successful asset should.
    expect(await mockBridge.monitorCallsByAsset(assetA)).to.equal(0n);
    expect(await mockBridge.monitorCallsByAsset(assetB)).to.equal(1n);
    expect(await mockBridge.monitorCallCount()).to.equal(1n);
    expect(await mockBridge.lastMonitoredAssetId()).to.equal(assetB);
  });
});
