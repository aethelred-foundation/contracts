import { expect } from "chai";
import { ethers, upgrades } from "hardhat";

describe("SovereignGovernanceTimelock", function () {
  it("rotates institutional keys only after 7-day timelock with issuer+foundation consent", async function () {
    const [admin, issuer, foundation, auditor, nextAuditor] = await ethers.getSigners();

    const BridgeFactory = await ethers.getContractFactory("InstitutionalStablecoinBridge");
    const bridge = await upgrades.deployProxy(
      BridgeFactory,
      [admin.address, issuer.address, foundation.address, auditor.address],
      { kind: "uups", initializer: "initialize" }
    );
    await bridge.waitForDeployment();

    const TimelockFactory = await ethers.getContractFactory("SovereignGovernanceTimelock");
    const timelock = await TimelockFactory.connect(admin).deploy(
      7 * 24 * 60 * 60,
      [admin.address],
      [admin.address],
      admin.address
    );
    await timelock.waitForDeployment();

    const configRole = await bridge.CONFIG_ROLE();
    await bridge.grantRole(configRole, await timelock.getAddress());

    // The timelock calls this.schedule() / this.execute() externally, so it
    // needs PROPOSER_ROLE and EXECUTOR_ROLE granted to its own address.
    const proposerRole = await timelock.PROPOSER_ROLE();
    const executorRole = await timelock.EXECUTOR_ROLE();
    await timelock.grantRole(proposerRole, await timelock.getAddress());
    await timelock.grantRole(executorRole, await timelock.getAddress());

    const predecessor = ethers.ZeroHash;
    const salt = ethers.id("ROTATE_AUDITOR_1");
    const deadline = (await ethers.provider.getBlock("latest"))!.timestamp + 3600;
    const chainId = (await ethers.provider.getNetwork()).chainId;
    const timelockAddress = await timelock.getAddress();
    const bridgeAddress = await bridge.getAddress();

    const digest = ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
        [
          "string",
          "address",
          "uint256",
          "address",
          "uint8",
          "address",
          "bytes32",
          "bytes32",
          "uint256",
        ],
        [
          "AETHELRED_ROTATE_KEY_V1",
          timelockAddress,
          chainId,
          bridgeAddress,
          2, // KeyType.Auditor
          nextAuditor.address,
          predecessor,
          salt,
          deadline,
        ]
      )
    );

    const issuerSig = await issuer.signMessage(ethers.getBytes(digest));
    const foundationSig = await foundation.signMessage(ethers.getBytes(digest));

    await timelock.rotateKey(
      bridgeAddress,
      2,
      nextAuditor.address,
      predecessor,
      salt,
      deadline,
      issuerSig,
      foundationSig
    );

    const data = bridge.interface.encodeFunctionData("setGovernanceKeys", [
      issuer.address,
      foundation.address,
      nextAuditor.address,
    ]);
    const operationId = await timelock.hashOperation(
      bridgeAddress,
      0,
      data,
      predecessor,
      salt
    );

    await expect(timelock.executeKeyRotation(operationId)).to.be.reverted;

    await ethers.provider.send("evm_increaseTime", [7 * 24 * 60 * 60 + 1]);
    await ethers.provider.send("evm_mine", []);

    await timelock.executeKeyRotation(operationId);
    expect(await bridge.auditorGovernanceKey()).to.equal(nextAuditor.address);
  });

  it("rejects key rotation proposals without issuer+foundation signatures", async function () {
    const [admin, issuer, foundation, auditor, attacker, nextAuditor] = await ethers.getSigners();

    const BridgeFactory = await ethers.getContractFactory("InstitutionalStablecoinBridge");
    const bridge = await upgrades.deployProxy(
      BridgeFactory,
      [admin.address, issuer.address, foundation.address, auditor.address],
      { kind: "uups", initializer: "initialize" }
    );
    await bridge.waitForDeployment();

    const TimelockFactory = await ethers.getContractFactory("SovereignGovernanceTimelock");
    const timelock = await TimelockFactory.connect(admin).deploy(
      7 * 24 * 60 * 60,
      [admin.address],
      [admin.address],
      admin.address
    );
    await timelock.waitForDeployment();

    const predecessor = ethers.ZeroHash;
    const salt = ethers.id("ROTATE_AUDITOR_INVALID");
    const deadline = (await ethers.provider.getBlock("latest"))!.timestamp + 3600;
    const chainId = (await ethers.provider.getNetwork()).chainId;

    const digest = ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
        [
          "string",
          "address",
          "uint256",
          "address",
          "uint8",
          "address",
          "bytes32",
          "bytes32",
          "uint256",
        ],
        [
          "AETHELRED_ROTATE_KEY_V1",
          await timelock.getAddress(),
          chainId,
          await bridge.getAddress(),
          2,
          nextAuditor.address,
          predecessor,
          salt,
          deadline,
        ]
      )
    );

    const badIssuerSig = await attacker.signMessage(ethers.getBytes(digest));
    const badFoundationSig = await foundation.signMessage(ethers.getBytes(digest));

    await expect(
      timelock.rotateKey(
        await bridge.getAddress(),
        2,
        nextAuditor.address,
        predecessor,
        salt,
        deadline,
        badIssuerSig,
        badFoundationSig
      )
    ).to.be.revertedWithCustomError(timelock, "InvalidSignature");
  });

  it("rotates guardian key via timelock using sovereign unpause key setter", async function () {
    const [
      admin,
      issuer,
      foundation,
      auditor,
      issuerRecovery,
      guardian,
      newGuardian,
    ] = await ethers.getSigners();

    const BridgeFactory = await ethers.getContractFactory("InstitutionalStablecoinBridge");
    const bridge = await upgrades.deployProxy(
      BridgeFactory,
      [admin.address, issuer.address, foundation.address, auditor.address],
      { kind: "uups", initializer: "initialize" }
    );
    await bridge.waitForDeployment();

    await bridge.setSovereignUnpauseKeys(issuerRecovery.address, guardian.address);

    const TimelockFactory = await ethers.getContractFactory("SovereignGovernanceTimelock");
    const timelock = await TimelockFactory.connect(admin).deploy(
      7 * 24 * 60 * 60,
      [admin.address],
      [admin.address],
      admin.address
    );
    await timelock.waitForDeployment();

    const configRole = await bridge.CONFIG_ROLE();
    await bridge.grantRole(configRole, await timelock.getAddress());

    // The timelock calls this.schedule() / this.execute() externally, so it
    // needs PROPOSER_ROLE and EXECUTOR_ROLE granted to its own address.
    const proposerRole = await timelock.PROPOSER_ROLE();
    const executorRole = await timelock.EXECUTOR_ROLE();
    await timelock.grantRole(proposerRole, await timelock.getAddress());
    await timelock.grantRole(executorRole, await timelock.getAddress());

    const predecessor = ethers.ZeroHash;
    const salt = ethers.id("ROTATE_GUARDIAN_1");
    const deadline = (await ethers.provider.getBlock("latest"))!.timestamp + 3600;
    const chainId = (await ethers.provider.getNetwork()).chainId;
    const timelockAddress = await timelock.getAddress();
    const bridgeAddress = await bridge.getAddress();

    const digest = ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
        [
          "string",
          "address",
          "uint256",
          "address",
          "uint8",
          "address",
          "bytes32",
          "bytes32",
          "uint256",
        ],
        [
          "AETHELRED_ROTATE_KEY_V1",
          timelockAddress,
          chainId,
          bridgeAddress,
          4, // KeyType.Guardian
          newGuardian.address,
          predecessor,
          salt,
          deadline,
        ]
      )
    );

    const issuerSig = await issuer.signMessage(ethers.getBytes(digest));
    const foundationSig = await foundation.signMessage(ethers.getBytes(digest));

    await timelock.rotateKey(
      bridgeAddress,
      4,
      newGuardian.address,
      predecessor,
      salt,
      deadline,
      issuerSig,
      foundationSig
    );

    const data = bridge.interface.encodeFunctionData("setSovereignUnpauseKeys", [
      issuerRecovery.address,
      newGuardian.address,
    ]);
    const operationId = await timelock.hashOperation(
      bridgeAddress,
      0,
      data,
      predecessor,
      salt
    );

    await ethers.provider.send("evm_increaseTime", [7 * 24 * 60 * 60 + 1]);
    await ethers.provider.send("evm_mine", []);

    await timelock.executeKeyRotation(operationId);
    expect(await bridge.guardianGovernanceKey()).to.equal(newGuardian.address);
  });
});
