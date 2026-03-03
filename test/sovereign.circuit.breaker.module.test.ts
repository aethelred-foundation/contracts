import { expect } from "chai";
import { ethers } from "hardhat";

function units(amount: number, decimals = 6): bigint {
  return BigInt(amount) * (10n ** BigInt(decimals));
}

describe("SovereignCircuitBreakerModule", function () {
  it("pauses when projected supply deviation exceeds threshold", async function () {
    const [owner, multisig] = await ethers.getSigners();

    const TokenFactory = await ethers.getContractFactory("MockMintableBurnableERC20");
    const token = await TokenFactory.connect(owner).deploy("DDSC", "DDSC", 6);
    await token.waitForDeployment();
    await token.mint(owner.address, units(1000));

    const FeedFactory = await ethers.getContractFactory("MockAggregatorV3");
    const feed = await FeedFactory.connect(owner).deploy(6);
    await feed.waitForDeployment();
    const now = (await ethers.provider.getBlock("latest"))!.timestamp;
    await feed.setRoundData(units(1000), now);

    const ModuleFactory = await ethers.getContractFactory("SovereignCircuitBreakerModule");
    const module = await ModuleFactory.connect(owner).deploy(
      owner.address,
      await token.getAddress(),
      await feed.getAddress(),
      multisig.address,
      50 // 0.5%
    );
    await module.waitForDeployment();

    await module.checkReserveAnomaly(units(4)); // 0.4% projected deviation
    expect(await module.isPaused()).to.equal(false);

    await module.checkReserveAnomaly(units(10)); // 1% projected deviation
    expect(await module.isPaused()).to.equal(true);
  });

  it("only allows configured multisig to unpause", async function () {
    const [owner, multisig, attacker] = await ethers.getSigners();

    const TokenFactory = await ethers.getContractFactory("MockMintableBurnableERC20");
    const token = await TokenFactory.connect(owner).deploy("USDU", "USDU", 6);
    await token.waitForDeployment();
    await token.mint(owner.address, units(1000));

    const FeedFactory = await ethers.getContractFactory("MockAggregatorV3");
    const feed = await FeedFactory.connect(owner).deploy(6);
    await feed.waitForDeployment();
    const now = (await ethers.provider.getBlock("latest"))!.timestamp;
    await feed.setRoundData(units(900), now);

    const ModuleFactory = await ethers.getContractFactory("SovereignCircuitBreakerModule");
    const module = await ModuleFactory.connect(owner).deploy(
      owner.address,
      await token.getAddress(),
      await feed.getAddress(),
      multisig.address,
      50
    );
    await module.waitForDeployment();

    await module.checkReserveAnomaly(0);
    expect(await module.isPaused()).to.equal(true);

    await expect(module.connect(attacker).unpauseMinting()).to.be.revertedWithCustomError(
      module,
      "Unauthorized"
    );

    await module.connect(multisig).unpauseMinting();
    expect(await module.isPaused()).to.equal(false);
  });

  it("auto-pauses when reserve feed is stale for more than 24 hours", async function () {
    const [owner, multisig] = await ethers.getSigners();

    const TokenFactory = await ethers.getContractFactory("MockMintableBurnableERC20");
    const token = await TokenFactory.connect(owner).deploy("USDT", "USDT", 6);
    await token.waitForDeployment();
    await token.mint(owner.address, units(1000));

    const FeedFactory = await ethers.getContractFactory("MockAggregatorV3");
    const feed = await FeedFactory.connect(owner).deploy(6);
    await feed.waitForDeployment();
    const now = (await ethers.provider.getBlock("latest"))!.timestamp;
    await feed.setRoundData(units(1000), now - (24 * 60 * 60 + 1));

    const ModuleFactory = await ethers.getContractFactory("SovereignCircuitBreakerModule");
    const module = await ModuleFactory.connect(owner).deploy(
      owner.address,
      await token.getAddress(),
      await feed.getAddress(),
      multisig.address,
      50
    );
    await module.waitForDeployment();

    await module.checkReserveAnomaly(0);
    expect(await module.isPaused()).to.equal(true);
  });
});
