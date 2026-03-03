import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { mine, time } from "@nomicfoundation/hardhat-network-helpers";

async function deployBridgeFixture() {
  const [admin, relayer1, relayer2, user] = await ethers.getSigners();
  const BridgeFactory = await ethers.getContractFactory("AethelredBridge");
  const bridge = await upgrades.deployProxy(
    BridgeFactory,
    [admin.address, [relayer1.address, relayer2.address], 6700],
    {
      kind: "uups",
      initializer: "initialize",
    }
  );
  await bridge.waitForDeployment();
  return { bridge, admin, relayer1, relayer2, user };
}

async function extractOperationId(bridge: any, txHash: string): Promise<string> {
  const receipt = await ethers.provider.getTransactionReceipt(txHash);
  if (!receipt) {
    throw new Error("missing transaction receipt");
  }

  for (const log of receipt.logs) {
    try {
      const parsed = bridge.interface.parseLog(log);
      if (parsed?.name === "EmergencyWithdrawalQueued") {
        return parsed.args.operationId as string;
      }
    } catch {
      // Ignore logs from other contracts.
    }
  }

  throw new Error("EmergencyWithdrawalQueued event not found");
}

async function extractDepositId(bridge: any, txHash: string): Promise<string> {
  const receipt = await ethers.provider.getTransactionReceipt(txHash);
  if (!receipt) {
    throw new Error("missing transaction receipt");
  }

  for (const log of receipt.logs) {
    try {
      const parsed = bridge.interface.parseLog(log);
      if (parsed?.name === "DepositInitiated") {
        return parsed.args.depositId as string;
      }
    } catch {
      // Ignore logs from other contracts.
    }
  }

  throw new Error("DepositInitiated event not found");
}

describe("AethelredBridge (Hardhat lane)", function () {
  it("rejects initializeWithTimelock when upgrader timelock delay is below 27 days", async function () {
    const [admin, relayer1, relayer2] = await ethers.getSigners();

    const TimelockFactory = await ethers.getContractFactory("TimelockController");
    const shortDelay = 7 * 24 * 60 * 60; // 7 days
    const timelock = await TimelockFactory.deploy(
      shortDelay,
      [admin.address],
      [admin.address],
      admin.address
    );
    await timelock.waitForDeployment();

    const BridgeFactory = await ethers.getContractFactory("AethelredBridge");
    await expect(
      upgrades.deployProxy(
        BridgeFactory,
        [
          admin.address,
          await timelock.getAddress(),
          [relayer1.address, relayer2.address],
          6700,
        ],
        {
          kind: "uups",
          initializer: "initializeWithTimelock",
        }
      )
    ).to.be.revertedWithCustomError(BridgeFactory, "UpgraderTimelockDelayTooShort");
  });

  it("emergencyWithdraw queues a timelocked operation (no immediate transfer)", async function () {
    const { bridge, admin, user } = await deployBridgeFixture();

    // Seed bridge ETH balance via a valid deposit.
    await bridge
      .connect(user)
      .depositETH(ethers.zeroPadValue("0x01", 32), { value: ethers.parseEther("1") });

    const initialBridgeBalance = await ethers.provider.getBalance(await bridge.getAddress());
    const amount = ethers.parseEther("0.2");
    const nonceBefore = await bridge.emergencyWithdrawalNonce();

    const tx = await bridge
      .connect(admin)
      .emergencyWithdraw(ethers.ZeroAddress, amount, admin.address);
    const opId = await extractOperationId(bridge, tx.hash);

    const nonceAfter = await bridge.emergencyWithdrawalNonce();
    const request = await bridge.emergencyWithdrawalRequests(opId);
    const bridgeBalanceAfter = await ethers.provider.getBalance(await bridge.getAddress());

    expect(nonceAfter).to.equal(nonceBefore + 1n);
    expect(request.queuedAt).to.be.gt(0);
    expect(request.executeAfter).to.be.gt(request.queuedAt);
    expect(request.executed).to.equal(false);
    expect(request.cancelled).to.equal(false);
    expect(bridgeBalanceAfter).to.equal(initialBridgeBalance);
  });

  it("executeEmergencyWithdrawal enforces timelock + guardian quorum then transfers", async function () {
    const { bridge, admin, relayer1, user } = await deployBridgeFixture();

    await bridge
      .connect(user)
      .depositETH(ethers.zeroPadValue("0x02", 32), { value: ethers.parseEther("1") });

    const amount = ethers.parseEther("0.3");
    const queueTx = await bridge
      .connect(admin)
      .queueEmergencyWithdrawal(ethers.ZeroAddress, amount, admin.address);
    const opId = await extractOperationId(bridge, queueTx.hash);
    const request = await bridge.emergencyWithdrawalRequests(opId);

    await expect(bridge.connect(admin).executeEmergencyWithdrawal(opId)).to.be.revertedWithCustomError(
      bridge,
      "EmergencyWithdrawalNotReady"
    );

    await time.increaseTo(request.executeAfter);

    // Current bridge hardening requires a 2-of-N guardian quorum.
    const guardianRole = await bridge.GUARDIAN_ROLE();
    await bridge.connect(admin).grantRole(guardianRole, relayer1.address);
    await bridge.connect(admin).approveEmergencyWithdrawal(opId);
    await bridge.connect(relayer1).approveEmergencyWithdrawal(opId);

    const bridgeBalanceBefore = await ethers.provider.getBalance(await bridge.getAddress());
    const execTx = await bridge.connect(admin).executeEmergencyWithdrawal(opId);
    await execTx.wait();
    const bridgeBalanceAfter = await ethers.provider.getBalance(await bridge.getAddress());
    const requestAfter = await bridge.emergencyWithdrawalRequests(opId);

    expect(bridgeBalanceBefore - bridgeBalanceAfter).to.equal(amount);
    expect(requestAfter.executed).to.equal(true);
    expect(requestAfter.cancelled).to.equal(false);
  });

  it("finalizeDeposit sets finalized flag and prevents later cancellation (C-01)", async function () {
    const { bridge, relayer1, user } = await deployBridgeFixture();

    const depositTx = await bridge
      .connect(user)
      .depositETH(ethers.zeroPadValue("0x03", 32), { value: ethers.parseEther("0.5") });
    const depositId = await extractDepositId(bridge, depositTx.hash);

    // Ensure the L1-side deposit passed the confirmation threshold before relayer finalization.
    const minConfirmations = await bridge.MIN_ETH_CONFIRMATIONS();
    await mine(Number(minConfirmations));

    await expect(bridge.connect(relayer1).finalizeDeposit(depositId))
      .to.emit(bridge, "DepositFinalized")
      .withArgs(depositId, user.address, ethers.parseEther("0.5"));

    const deposit = await bridge.deposits(depositId);
    expect(deposit.finalized).to.equal(true);

    await expect(bridge.connect(user).cancelDeposit(depositId)).to.be.revertedWithCustomError(
      bridge,
      "DepositAlreadyFinalized"
    );
  });
});
