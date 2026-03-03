import { expect } from "chai";
import { ethers, upgrades } from "hardhat";

async function deployTokenFixture() {
  const [admin, , user] = await ethers.getSigners();
  const TokenFactory = await ethers.getContractFactory("AethelredToken");
  const initialAmount = ethers.parseUnits("1000", 18);
  const token = await upgrades.deployProxy(
    TokenFactory,
    [admin.address, ethers.ZeroAddress, user.address, initialAmount],
    { kind: "uups", initializer: "initialize" }
  );
  await token.waitForDeployment();
  return { token, admin, user };
}

async function deployVestingFixture() {
  const [admin, beneficiary] = await ethers.getSigners();
  const MockToken = await ethers.getContractFactory("MockMintableBurnableERC20");
  const token = await MockToken.deploy("Aethelred", "AETHEL", 18);
  await token.waitForDeployment();

  const VestingFactory = await ethers.getContractFactory("AethelredVesting");
  const vesting = await upgrades.deployProxy(
    VestingFactory,
    [await token.getAddress(), admin.address],
    { kind: "uups", initializer: "initialize" }
  );
  await vesting.waitForDeployment();

  return { vesting, token, admin, beneficiary };
}

describe("Medium Findings Regression Coverage (M-03, M-06)", function () {
  it("M-03: recoverTokens fails safely when vesting liabilities exceed current token balance", async function () {
    const { vesting, token, admin, beneficiary } = await deployVestingFixture();
    const allocated = ethers.parseUnits("100", 18);

    // Create a liability without funding the vesting contract to exercise the
    // saturating recoverable-balance logic (pre-fix code underflowed here).
    await vesting.createCoreContributorSchedule(beneficiary.address, allocated);

    await expect(
      vesting.recoverTokens(await token.getAddress(), 1n, admin.address)
    ).to.be.revertedWith("Cannot recover vesting tokens");
  });

  it("M-03: recoverTokens allows recovering only surplus vesting tokens", async function () {
    const { vesting, token, admin, beneficiary } = await deployVestingFixture();
    const allocated = ethers.parseUnits("100", 18);
    const surplus = ethers.parseUnits("25", 18);

    await vesting.createCoreContributorSchedule(beneficiary.address, allocated);

    // Fund only the surplus path; liabilities remain reserved.
    await token.mint(await vesting.getAddress(), allocated + surplus);
    const adminBefore = await token.balanceOf(admin.address);

    await vesting.recoverTokens(await token.getAddress(), surplus, admin.address);

    expect(await token.balanceOf(await vesting.getAddress())).to.equal(allocated);
    expect(await token.balanceOf(admin.address)).to.equal(adminBefore + surplus);
  });

  it("M-06: adminBurn requires target-account allowance (consent) before burning", async function () {
    const { token, admin, user } = await deployTokenFixture();
    const burnAmount = ethers.parseUnits("10", 18);

    await expect(
      token.connect(admin).adminBurn(user.address, burnAmount)
    ).to.be.reverted;

    await token.connect(user).approve(admin.address, burnAmount);
    await token.connect(admin).adminBurn(user.address, burnAmount);

    expect(await token.balanceOf(user.address)).to.equal(
      ethers.parseUnits("1000", 18) - burnAmount
    );
  });
});
