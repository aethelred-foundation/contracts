import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";

async function deployBridgeFixture(relayerCount = 3) {
  const signers = await ethers.getSigners();
  const [admin, ...rest] = signers;
  const relayers = rest.slice(0, relayerCount);
  const user = rest[relayerCount];
  const BridgeFactory = await ethers.getContractFactory("AethelredBridge");
  const bridge = await upgrades.deployProxy(
    BridgeFactory,
    [admin.address, relayers.map((r) => r.address), 6700],
    { kind: "uups", initializer: "initialize" }
  );
  await bridge.waitForDeployment();
  return { bridge, admin, relayers, user };
}

async function deployTokenFixture() {
  const [admin, bridgeOperator, user] = await ethers.getSigners();
  const TokenFactory = await ethers.getContractFactory("AethelredToken");
  const initialAmount = ethers.parseUnits("1000", 18);
  const token = await upgrades.deployProxy(
    TokenFactory,
    [admin.address, ethers.ZeroAddress, user.address, initialAmount],
    { kind: "uups", initializer: "initialize" }
  );
  await token.waitForDeployment();
  return { token, admin, bridgeOperator, user, initialAmount };
}

async function deployVestingFixture() {
  const [admin, beneficiary] = await ethers.getSigners();
  const TokenFactory = await ethers.getContractFactory("MockMintableBurnableERC20");
  const token = await TokenFactory.deploy("Aethelred", "AETH", 18);
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

async function extractDepositId(bridge: any, txHash: string): Promise<string> {
  const receipt = await ethers.provider.getTransactionReceipt(txHash);
  if (!receipt) throw new Error("missing transaction receipt");

  for (const log of receipt.logs) {
    try {
      const parsed = bridge.interface.parseLog(log);
      if (parsed?.name === "DepositInitiated") {
        return parsed.args.depositId as string;
      }
    } catch {
      // ignore other logs
    }
  }
  throw new Error("DepositInitiated event not found");
}

async function extractOperationId(bridge: any, txHash: string): Promise<string> {
  const receipt = await ethers.provider.getTransactionReceipt(txHash);
  if (!receipt) throw new Error("missing transaction receipt");

  for (const log of receipt.logs) {
    try {
      const parsed = bridge.interface.parseLog(log);
      if (parsed?.name === "EmergencyWithdrawalQueued") {
        return parsed.args.operationId as string;
      }
    } catch {
      // ignore other logs
    }
  }
  throw new Error("EmergencyWithdrawalQueued event not found");
}

describe("High Findings Regression Coverage (H-01..H-12)", function () {
  it("H-01: bridgeBurn requires holder allowance before authorized bridge can burn", async function () {
    const { token, admin, bridgeOperator, user } = await deployTokenFixture();
    const burnAmount = ethers.parseUnits("10", 18);

    await token.connect(admin).setAuthorizedBridge(bridgeOperator.address, true);

    await expect(
      token.connect(bridgeOperator).bridgeBurn(user.address, burnAmount)
    ).to.be.reverted;

    await token.connect(user).approve(bridgeOperator.address, burnAmount);
    await expect(token.connect(bridgeOperator).bridgeBurn(user.address, burnAmount))
      .to.emit(token, "TokensBurnedByBridge")
      .withArgs(bridgeOperator.address, user.address, burnAmount);
  });

  it("H-02: deposit IDs match abi.encode hash (not packed encoding path)", async function () {
    const { bridge, user } = await deployBridgeFixture(2);
    const recipient = ethers.zeroPadValue("0x1234", 32);
    const amount = await bridge.MIN_DEPOSIT();
    const nonceBefore = await bridge.depositNonce();
    const chainId = (await ethers.provider.getNetwork()).chainId;

    const tx = await bridge.connect(user).depositETH(recipient, { value: amount });
    const depositId = await extractDepositId(bridge, tx.hash);

    const expected = ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
        ["address", "bytes32", "address", "uint256", "uint256", "uint256"],
        [user.address, recipient, ethers.ZeroAddress, amount, nonceBefore, chainId]
      )
    );
    const packed = ethers.solidityPackedKeccak256(
      ["address", "bytes32", "address", "uint256", "uint256", "uint256"],
      [user.address, recipient, ethers.ZeroAddress, amount, nonceBefore, chainId]
    );

    expect(depositId).to.equal(expected);
    expect(depositId).to.not.equal(packed);
  });

  it("H-03: relayer count/threshold stay synchronized on revoke + renounce", async function () {
    const { bridge, admin, relayers } = await deployBridgeFixture(3);
    const relayerRole = await bridge.RELAYER_ROLE();

    let cfg = await bridge.relayerConfig();
    expect(cfg.relayerCount).to.equal(3n);

    await bridge.connect(admin).revokeRole(relayerRole, relayers[2].address);
    cfg = await bridge.relayerConfig();
    expect(cfg.relayerCount).to.equal(2n);
    expect(cfg.minVotesRequired).to.equal(1n); // floor(2 * 6700 / 10000)

    await bridge.connect(relayers[1]).renounceRole(relayerRole, relayers[1].address);
    cfg = await bridge.relayerConfig();
    expect(cfg.relayerCount).to.equal(1n);
    expect(cfg.minVotesRequired).to.equal(1n);
  });

  it("H-05: queue/executeEmergencyWithdrawal are blocked while bridge is paused", async function () {
    const { bridge, admin, relayers, user } = await deployBridgeFixture(2);

    await bridge
      .connect(user)
      .depositETH(ethers.zeroPadValue("0xabcd", 32), { value: ethers.parseEther("1") });

    await bridge.connect(admin).pause();
    await expect(
      bridge.connect(admin).queueEmergencyWithdrawal(ethers.ZeroAddress, ethers.parseEther("0.1"), admin.address)
    ).to.be.reverted;

    await bridge.connect(admin).unpause();
    const queueTx = await bridge
      .connect(admin)
      .queueEmergencyWithdrawal(ethers.ZeroAddress, ethers.parseEther("0.1"), admin.address);
    const operationId = await extractOperationId(bridge, queueTx.hash);
    const request = await bridge.emergencyWithdrawalRequests(operationId);

    const guardianRole = await bridge.GUARDIAN_ROLE();
    await bridge.connect(admin).grantRole(guardianRole, relayers[0].address);
    await bridge.connect(admin).approveEmergencyWithdrawal(operationId);
    await bridge.connect(relayers[0]).approveEmergencyWithdrawal(operationId);

    await time.increaseTo(request.executeAfter);
    await bridge.connect(admin).pause();

    await expect(bridge.connect(admin).executeEmergencyWithdrawal(operationId)).to.be.reverted;
  });

  it("H-06: timelock does not self-grant PROPOSER_ROLE or EXECUTOR_ROLE", async function () {
    const [admin] = await ethers.getSigners();
    const TimelockFactory = await ethers.getContractFactory("SovereignGovernanceTimelock");
    const timelock = await TimelockFactory.deploy(
      7 * 24 * 60 * 60,
      [admin.address],
      [admin.address],
      admin.address
    );
    await timelock.waitForDeployment();

    const proposerRole = await timelock.PROPOSER_ROLE();
    const executorRole = await timelock.EXECUTOR_ROLE();
    const timelockAddress = await timelock.getAddress();

    expect(await timelock.hasRole(proposerRole, timelockAddress)).to.equal(false);
    expect(await timelock.hasRole(executorRole, timelockAddress)).to.equal(false);
  });

  it("H-07: setCategoryCap reverts when cap is reduced below already allocated amount", async function () {
    const { vesting, beneficiary } = await deployVestingFixture();
    const amount = ethers.parseUnits("100", 18);

    await vesting.createCoreContributorSchedule(beneficiary.address, amount);
    const [scheduleId] = await vesting.getBeneficiarySchedules(beneficiary.address);
    const schedule = await vesting.getSchedule(scheduleId);

    await expect(
      vesting.setCategoryCap(schedule.category, amount - 1n)
    ).to.be.revertedWithCustomError(vesting, "CategoryCapBelowAllocated");
  });
});
