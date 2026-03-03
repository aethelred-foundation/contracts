import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";

async function deployVestingFixture() {
  const [admin, beneficiary] = await ethers.getSigners();

  const TokenFactory = await ethers.getContractFactory("MockMintableBurnableERC20");
  const token = await TokenFactory.deploy("Aethelred", "AETHEL", 18);
  await token.waitForDeployment();

  const VestingFactory = await ethers.getContractFactory("AethelredVesting");
  const vesting = await upgrades.deployProxy(
    VestingFactory,
    [await token.getAddress(), admin.address],
    { kind: "uups", initializer: "initialize" }
  );
  await vesting.waitForDeployment();

  return { admin, beneficiary, token, vesting };
}

describe("AethelredVesting (Critical regressions)", function () {
  it("core team cliff-linear schedule vests 0 at cliff end and starts linear after cliff (C-04)", async function () {
    const { vesting, beneficiary } = await deployVestingFixture();
    const amount = ethers.parseUnits("1000", 18);

    await vesting.executeTGE();
    const createTx = await vesting.createCoreContributorSchedule(beneficiary.address, amount);
    await createTx.wait();

    const scheduleIds = await vesting.getBeneficiarySchedules(beneficiary.address);
    expect(scheduleIds).to.have.length(1);
    const scheduleId = scheduleIds[0];

    const schedule = await vesting.getSchedule(scheduleId);
    const cliffEnd = Number(schedule.startTime + schedule.cliffDuration);

    await time.increaseTo(cliffEnd);
    const vestedAtCliff = await vesting.getVested(scheduleId);
    // At cliff end, 25% cliff unlock is immediately available (cliffUnlockBps=2500)
    const expectedCliffAmount = (amount * 2500n) / 10000n;
    expect(vestedAtCliff).to.equal(expectedCliffAmount);

    await time.increaseTo(cliffEnd + 1);
    const vestedAfter = await vesting.getVested(scheduleId);
    expect(vestedAfter).to.be.greaterThan(expectedCliffAmount);
    expect(vestedAfter).to.be.lessThan(amount);
  });

  it("activateSchedule uses TGE time (not delayed call time) for pre-TGE schedules (C-04 hardening)", async function () {
    const { vesting, beneficiary } = await deployVestingFixture();
    const amount = ethers.parseUnits("500", 18);

    await vesting.createCoreContributorSchedule(beneficiary.address, amount);
    const [scheduleId] = await vesting.getBeneficiarySchedules(beneficiary.address);
    let schedule = await vesting.getSchedule(scheduleId);
    expect(schedule.startTime).to.equal(0n);

    const tgeTx = await vesting.executeTGE();
    const tgeReceipt = await tgeTx.wait();
    const tgeBlock = await ethers.provider.getBlock(tgeReceipt!.blockNumber);
    const tgeTimestamp = BigInt(tgeBlock!.timestamp);

    await time.increase(3600); // delayed ops should not shift economics
    await vesting.activateSchedule(scheduleId);

    schedule = await vesting.getSchedule(scheduleId);
    expect(schedule.startTime).to.equal(tgeTimestamp);
  });
});
