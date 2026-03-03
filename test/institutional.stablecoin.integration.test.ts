import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";

const ASSET_USDU = ethers.id("USDU");
const ASSET_USDC = ethers.id("USDC");
const ENCLAVE_MEASUREMENT = ethers.id("AWS_NITRO_MRENCLAVE_V1");
const EIP712_DOMAIN_NAME = "InstitutionalStablecoinBridge";
const EIP712_DOMAIN_VERSION = "2";

const MINT_TYPES = {
  TeeMint: [
    { name: "assetId", type: "bytes32" },
    { name: "recipient", type: "address" },
    { name: "amount", type: "uint256" },
    { name: "mintOperationId", type: "bytes32" },
    { name: "enclaveMeasurement", type: "bytes32" },
    { name: "deadline", type: "uint256" },
  ],
} as const;

const UNPAUSE_TYPES = {
  JointUnpause: [
    { name: "actionId", type: "bytes32" },
    { name: "deadline", type: "uint256" },
  ],
} as const;

const CCTP_FAST_TYPES = {
  CCTPFast: [
    { name: "assetId", type: "bytes32" },
    { name: "messageHash", type: "bytes32" },
    { name: "attestationHash", type: "bytes32" },
    { name: "deadline", type: "uint256" },
  ],
} as const;

function units(amount: number, decimals = 6): bigint {
  return BigInt(amount) * (10n ** BigInt(decimals));
}

function bridgeDomain(bridgeAddress: string, chainId: bigint) {
  return {
    name: EIP712_DOMAIN_NAME,
    version: EIP712_DOMAIN_VERSION,
    chainId,
    verifyingContract: bridgeAddress,
  };
}

function buildMintDigest(
  bridgeAddress: string,
  chainId: bigint,
  assetId: string,
  recipient: string,
  amount: bigint,
  mintOperationId: string,
  enclaveMeasurement: string,
  deadline: number
): string {
  return ethers.TypedDataEncoder.hash(
    bridgeDomain(bridgeAddress, chainId),
    MINT_TYPES,
    {
      assetId,
      recipient,
      amount,
      mintOperationId,
      enclaveMeasurement,
      deadline,
    }
  );
}

function buildUnpauseDigest(
  bridgeAddress: string,
  chainId: bigint,
  actionId: string,
  deadline: number
): string {
  return ethers.TypedDataEncoder.hash(
    bridgeDomain(bridgeAddress, chainId),
    UNPAUSE_TYPES,
    { actionId, deadline }
  );
}

function buildCCTPFastDigest(
  bridgeAddress: string,
  chainId: bigint,
  assetId: string,
  messageHash: string,
  attestationHash: string,
  deadline: number
): string {
  return ethers.TypedDataEncoder.hash(
    bridgeDomain(bridgeAddress, chainId),
    CCTP_FAST_TYPES,
    { assetId, messageHash, attestationHash, deadline }
  );
}

async function signMintTyped(
  signer: any,
  bridgeAddress: string,
  chainId: bigint,
  assetId: string,
  recipient: string,
  amount: bigint,
  mintOperationId: string,
  enclaveMeasurement: string,
  deadline: number
): Promise<string> {
  return signer.signTypedData(bridgeDomain(bridgeAddress, chainId), MINT_TYPES, {
    assetId,
    recipient,
    amount,
    mintOperationId,
    enclaveMeasurement,
    deadline,
  });
}

async function signUnpauseTyped(
  signer: any,
  bridgeAddress: string,
  chainId: bigint,
  actionId: string,
  deadline: number
): Promise<string> {
  return signer.signTypedData(bridgeDomain(bridgeAddress, chainId), UNPAUSE_TYPES, {
    actionId,
    deadline,
  });
}

async function signCCTPFastTyped(
  signer: any,
  bridgeAddress: string,
  chainId: bigint,
  assetId: string,
  messageHash: string,
  attestationHash: string,
  deadline: number
): Promise<string> {
  return signer.signTypedData(bridgeDomain(bridgeAddress, chainId), CCTP_FAST_TYPES, {
    assetId,
    messageHash,
    attestationHash,
    deadline,
  });
}

async function buildFixture() {
  const [
    admin,
    relayer,
    user,
    issuer1,
    issuer2,
    issuer3,
    issuer4,
    issuer5,
    foundation,
    auditor,
    attacker,
    irisAttester,
  ] = await ethers.getSigners();

  const BridgeFactory = await ethers.getContractFactory("InstitutionalStablecoinBridge");
  const bridge = await upgrades.deployProxy(
    BridgeFactory,
    [admin.address, issuer1.address, foundation.address, auditor.address],
    { kind: "uups", initializer: "initialize" }
  );
  await bridge.waitForDeployment();

  const relayerRole = await bridge.RELAYER_ROLE();
  await bridge.connect(admin).grantRole(relayerRole, relayer.address);

  const TokenFactory = await ethers.getContractFactory("MockMintableBurnableERC20");
  const usdu = await TokenFactory.connect(admin).deploy("USDU Stablecoin", "USDU", 6);
  const usdc = await TokenFactory.connect(admin).deploy("USD Coin", "USDC", 6);
  const aethel = await TokenFactory.connect(admin).deploy("AETHEL", "AETHEL", 18);
  await usdu.waitForDeployment();
  await usdc.waitForDeployment();
  await aethel.waitForDeployment();

  await bridge.connect(admin).configureRelayerBonding(
    await aethel.getAddress(),
    units(500_000, 18)
  );
  await aethel.connect(admin).mint(relayer.address, units(600_000, 18));
  await aethel.connect(relayer).approve(await bridge.getAddress(), units(500_000, 18));
  await bridge.connect(relayer).postRelayerBond(units(500_000, 18));

  const MessengerFactory = await ethers.getContractFactory("MockTokenMessengerV2");
  const messenger = await MessengerFactory.connect(admin).deploy();
  await messenger.waitForDeployment();

  const TransmitterFactory = await ethers.getContractFactory("MockMessageTransmitterV2");
  const transmitter = await TransmitterFactory.connect(admin).deploy();
  await transmitter.waitForDeployment();

  const FeedFactory = await ethers.getContractFactory("MockAggregatorV3");
  const porFeed = await FeedFactory.connect(admin).deploy(6);
  await porFeed.waitForDeployment();
  const now = (await ethers.provider.getBlock("latest"))!.timestamp;
  await porFeed.setRoundData(units(1_000_000), now);

  // Configure USDU as TEE + issuer multisig minted stablecoin.
  await bridge.connect(admin).configureStablecoin(
    {
      assetId: ASSET_USDU,
      enabled: true,
      routingType: 2, // TEE_ISSUER_MINT
      token: await usdu.getAddress(),
      tokenMessengerV2: ethers.ZeroAddress,
      messageTransmitterV2: ethers.ZeroAddress,
      proofOfReserveFeed: await porFeed.getAddress(),
    },
    {
      mintCeilingPerEpoch: units(1000),
      dailyTxLimit: units(5000),
      hourlyOutflowBps: 500,
      dailyOutflowBps: 1000,
      porDeviationBps: 50,
      porHeartbeatSeconds: 3600,
    }
  );

  await bridge.connect(issuer1).setIssuerSignerSet(
    ASSET_USDU,
    [issuer1.address, issuer2.address, issuer3.address, issuer4.address, issuer5.address],
    3
  );
  await bridge.connect(admin).setSovereignUnpauseKeys(issuer2.address, issuer4.address);
  await bridge.connect(admin).setEnclaveMeasurement(ENCLAVE_MEASUREMENT, true);

  const CircuitBreakerFactory = await ethers.getContractFactory("SovereignCircuitBreakerModule");
  const usduCircuitBreaker = await CircuitBreakerFactory.connect(admin).deploy(
    admin.address,
    await usdu.getAddress(),
    await porFeed.getAddress(),
    admin.address,
    50
  );
  await usduCircuitBreaker.waitForDeployment();
  await bridge.connect(admin).setCircuitBreakerModule(
    ASSET_USDU,
    await usduCircuitBreaker.getAddress()
  );

  // Bridge must own mint/burn privileges for TEE assets.
  await usdu.connect(admin).transferOwnership(await bridge.getAddress());

  // Configure USDC as CCTP-routed asset.
  await bridge.connect(admin).configureStablecoin(
    {
      assetId: ASSET_USDC,
      enabled: true,
      routingType: 1, // CCTP_V2
      token: await usdc.getAddress(),
      tokenMessengerV2: await messenger.getAddress(),
      messageTransmitterV2: await transmitter.getAddress(),
      proofOfReserveFeed: ethers.ZeroAddress,
    },
    {
      mintCeilingPerEpoch: 0,
      dailyTxLimit: units(50_000),
      hourlyOutflowBps: 300,
      dailyOutflowBps: 1000,
      porDeviationBps: 50,
      porHeartbeatSeconds: 3600,
    }
  );

  return {
    bridge,
    usdu,
    usdc,
    aethel,
    porFeed,
    usduCircuitBreaker,
    messenger,
    admin,
    relayer,
    user,
    issuer1,
    issuer2,
    issuer3,
    issuer4,
    foundation,
    auditor,
    attacker,
    irisAttester,
  };
}

describe("InstitutionalStablecoinBridge (TRD V2)", function () {
  it("keeps USDC routing as pure CCTP wrapper and blocks custom TEE mint path", async function () {
    const { bridge, relayer, user } = await buildFixture();

    await expect(
      bridge.connect(relayer).mintFromAttestedRelayer(
        ASSET_USDC,
        user.address,
        units(10),
        ethers.id("USDC_TEE_MINT_SHOULD_FAIL"),
        ENCLAVE_MEASUREMENT,
        (await ethers.provider.getBlock("latest"))!.timestamp + 3600,
        []
      )
    ).to.be.revertedWithCustomError(bridge, "NotTeeMintAsset");
  });

  it("blocks CCTP flow for non-CCTP assets to keep bridge logic isolated", async function () {
    const { bridge, user } = await buildFixture();

    await expect(
      bridge.connect(user).bridgeOutViaCCTP(
        ASSET_USDU,
        units(10),
        7,
        ethers.id("USDU_CCTP_SHOULD_FAIL")
      )
    ).to.be.revertedWithCustomError(bridge, "NotCCTPAsset");
  });

  it("enforces relayer bonding before relayer mint execution", async function () {
    const {
      bridge,
      attacker,
      user,
    } = await buildFixture();

    const relayerRole = await bridge.RELAYER_ROLE();
    await bridge.grantRole(relayerRole, attacker.address);

    await expect(
      bridge.connect(attacker).mintFromAttestedRelayer(
        ASSET_USDU,
        user.address,
        units(100),
        ethers.id("UNBONDED_MINT"),
        ENCLAVE_MEASUREMENT,
        (await ethers.provider.getBlock("latest"))!.timestamp + 3600,
        []
      )
    ).to.be.revertedWithCustomError(bridge, "RelayerBondInsufficient");
  });

  it("does not allow MINTER_ROLE-only accounts to call relayer entrypoints", async function () {
    const {
      bridge,
      admin,
      attacker,
    } = await buildFixture();

    const minterRole = await bridge.MINTER_ROLE();
    await bridge.connect(admin).grantRole(minterRole, attacker.address);

    await expect(
      bridge.connect(attacker).postRelayerBond(units(1, 18))
    ).to.be.revertedWithCustomError(bridge, "AccessControlUnauthorizedAccount");

    await expect(
      bridge.connect(attacker).relayCCTPMessage(
        ASSET_USDC,
        "0x12",
        "0x34"
      )
    ).to.be.revertedWithCustomError(bridge, "AccessControlUnauthorizedAccount");
  });

  it("exposes minimal ops getters for relayer bond state and enclave approval", async function () {
    const { bridge, relayer, aethel } = await buildFixture();

    const [bondedAmount, requiredBond, bondToken] =
      await bridge.getRelayerBondStatus(relayer.address);

    expect(bondedAmount).to.equal(units(500_000, 18));
    expect(requiredBond).to.equal(units(500_000, 18));
    expect(bondToken).to.equal(await aethel.getAddress());
    expect(bondToken).to.not.equal(ethers.ZeroAddress);
    expect(bondedAmount >= requiredBond).to.equal(true);

    expect(await bridge.isEnclaveMeasurementApproved(ENCLAVE_MEASUREMENT)).to.equal(true);
    expect(await bridge.isEnclaveMeasurementApproved(ethers.id("UNKNOWN_MEASUREMENT"))).to.equal(false);
  });

  it("requires configured governance timelock as admin caller once enabled", async function () {
    const {
      bridge,
      admin,
      attacker,
      irisAttester,
    } = await buildFixture();

    const configRole = await bridge.CONFIG_ROLE();
    await bridge.connect(admin).grantRole(configRole, attacker.address);
    await bridge.connect(admin).configureGovernanceTimelock(
      attacker.address,
      7 * 24 * 60 * 60
    );

    await expect(
      bridge.connect(admin).setIrisAttester(irisAttester.address)
    ).to.be.revertedWithCustomError(bridge, "TimelockRequired");

    await bridge.connect(attacker).setIrisAttester(irisAttester.address);
    expect(await bridge.irisAttester()).to.equal(irisAttester.address);
  });

  it("enforces issuer-exclusive fixed 3-of-5 signer set management", async function () {
    const {
      bridge,
      admin,
      issuer1,
      issuer2,
      issuer3,
      foundation,
      auditor,
    } = await buildFixture();

    await expect(
      bridge.connect(admin).setIssuerSignerSet(
        ASSET_USDU,
        [issuer1.address, issuer2.address, issuer3.address, foundation.address, auditor.address],
        3
      )
    ).to.be.revertedWithCustomError(bridge, "InvalidSignature");

    await expect(
      bridge.connect(issuer1).setIssuerSignerSet(
        ASSET_USDU,
        [issuer1.address, issuer2.address, issuer3.address, foundation.address, auditor.address],
        3
      )
    ).to.be.revertedWithCustomError(bridge, "InvalidConfig");

    await expect(
      bridge.connect(issuer1).setIssuerSignerSet(
        ASSET_USDU,
        [issuer1.address, issuer2.address, issuer3.address, admin.address, auditor.address],
        2
      )
    ).to.be.revertedWithCustomError(bridge, "InvalidConfig");
  });

  it("enforces issuer-controlled multisig for TEE minting", async function () {
    const {
      bridge,
      usdu,
      relayer,
      user,
      issuer1,
      issuer2,
      issuer3,
    } = await buildFixture();

    const mintOperationId = ethers.id("MINT_OP_1");
    const amount = units(100);
    const deadline = (await ethers.provider.getBlock("latest"))!.timestamp + 3600;
    const chainId = (await ethers.provider.getNetwork()).chainId;
    const bridgeAddress = await bridge.getAddress();
    const digest = buildMintDigest(
      bridgeAddress,
      chainId,
      ASSET_USDU,
      user.address,
      amount,
      mintOperationId,
      ENCLAVE_MEASUREMENT,
      deadline
    );

    const sig1 = await signMintTyped(issuer1, bridgeAddress, chainId, ASSET_USDU, user.address, amount, mintOperationId, ENCLAVE_MEASUREMENT, deadline);
    const sig2 = await signMintTyped(issuer2, bridgeAddress, chainId, ASSET_USDU, user.address, amount, mintOperationId, ENCLAVE_MEASUREMENT, deadline);
    const sig3 = await signMintTyped(issuer3, bridgeAddress, chainId, ASSET_USDU, user.address, amount, mintOperationId, ENCLAVE_MEASUREMENT, deadline);

    await bridge.connect(relayer).mintFromAttestedRelayer(
      ASSET_USDU,
      user.address,
      amount,
      mintOperationId,
      ENCLAVE_MEASUREMENT,
      deadline,
      [sig1, sig2, sig3]
    );

    expect(await usdu.balanceOf(user.address)).to.equal(amount);

    const mintOperationId2 = ethers.id("MINT_OP_2");
    const digest2 = buildMintDigest(
      bridgeAddress,
      chainId,
      ASSET_USDU,
      user.address,
      amount,
      mintOperationId2,
      ENCLAVE_MEASUREMENT,
      deadline
    );
    const shortSig1 = await signMintTyped(issuer1, bridgeAddress, chainId, ASSET_USDU, user.address, amount, mintOperationId2, ENCLAVE_MEASUREMENT, deadline);
    const shortSig2 = await signMintTyped(issuer2, bridgeAddress, chainId, ASSET_USDU, user.address, amount, mintOperationId2, ENCLAVE_MEASUREMENT, deadline);

    await expect(
      bridge.connect(relayer).mintFromAttestedRelayer(
        ASSET_USDU,
        user.address,
        amount,
        mintOperationId2,
        ENCLAVE_MEASUREMENT,
        deadline,
        [shortSig1, shortSig2]
      )
    ).to.be.revertedWithCustomError(bridge, "InsufficientIssuerSignatures");
  });

  it("M-01: rejects typed signatures signed for the wrong EIP-712 domain", async function () {
    const {
      bridge,
      relayer,
      user,
      issuer1,
      issuer2,
      issuer3,
      attacker,
    } = await buildFixture();

    const mintOperationId = ethers.id("M01_WRONG_DOMAIN_MINT");
    const amount = units(100);
    const deadline = (await ethers.provider.getBlock("latest"))!.timestamp + 3600;
    const chainId = (await ethers.provider.getNetwork()).chainId;
    const bridgeAddress = await bridge.getAddress();

    const wrongDomain = {
      name: EIP712_DOMAIN_NAME,
      version: EIP712_DOMAIN_VERSION,
      chainId: chainId + 1n,
      verifyingContract: attacker.address,
    };

    const sig1 = await issuer1.signTypedData(wrongDomain, MINT_TYPES, {
      assetId: ASSET_USDU,
      recipient: user.address,
      amount,
      mintOperationId,
      enclaveMeasurement: ENCLAVE_MEASUREMENT,
      deadline,
    });
    const sig2 = await issuer2.signTypedData(wrongDomain, MINT_TYPES, {
      assetId: ASSET_USDU,
      recipient: user.address,
      amount,
      mintOperationId,
      enclaveMeasurement: ENCLAVE_MEASUREMENT,
      deadline,
    });
    const sig3 = await issuer3.signTypedData(wrongDomain, MINT_TYPES, {
      assetId: ASSET_USDU,
      recipient: user.address,
      amount,
      mintOperationId,
      enclaveMeasurement: ENCLAVE_MEASUREMENT,
      deadline,
    });

    await expect(
      bridge.connect(relayer).mintFromAttestedRelayer(
        ASSET_USDU,
        user.address,
        amount,
        mintOperationId,
        ENCLAVE_MEASUREMENT,
        deadline,
        [sig1, sig2, sig3]
      )
    ).to.be.revertedWithCustomError(bridge, "InsufficientIssuerSignatures");
  });

  it("pauses minting via PoR anomaly monitoring instead of mint-time oracle reverts", async function () {
    const {
      bridge,
      usdu,
      porFeed,
      relayer,
      user,
      issuer1,
      issuer2,
      issuer3,
    } = await buildFixture();

    // Seed supply with a valid mint.
    const mintOperationId = ethers.id("POR_MINT_OP");
    const amount = units(1000);
    const deadline = (await ethers.provider.getBlock("latest"))!.timestamp + 3600;
    const chainId = (await ethers.provider.getNetwork()).chainId;
    const bridgeAddress = await bridge.getAddress();
    const digest = buildMintDigest(
      bridgeAddress,
      chainId,
      ASSET_USDU,
      user.address,
      amount,
      mintOperationId,
      ENCLAVE_MEASUREMENT,
      deadline
    );
    const s1 = await signMintTyped(issuer1, bridgeAddress, chainId, ASSET_USDU, user.address, amount, mintOperationId, ENCLAVE_MEASUREMENT, deadline);
    const s2 = await signMintTyped(issuer2, bridgeAddress, chainId, ASSET_USDU, user.address, amount, mintOperationId, ENCLAVE_MEASUREMENT, deadline);
    const s3 = await signMintTyped(issuer3, bridgeAddress, chainId, ASSET_USDU, user.address, amount, mintOperationId, ENCLAVE_MEASUREMENT, deadline);
    await bridge.connect(relayer).mintFromAttestedRelayer(
      ASSET_USDU,
      user.address,
      amount,
      mintOperationId,
      ENCLAVE_MEASUREMENT,
      deadline,
      [s1, s2, s3]
    );

    // Simulate reserve deviation > 0.5% (reserve 994 vs liabilities 1000).
    const now = (await ethers.provider.getBlock("latest"))!.timestamp;
    await porFeed.setRoundData(units(994), now);
    await bridge.monitorReserve(ASSET_USDU);

    const cfg = await bridge.stablecoins(ASSET_USDU);
    expect(cfg.mintPaused).to.equal(true);
    expect(await bridge.paused()).to.equal(true);

    // Already-minted state remains; monitor does not revert existing settlement txs.
    expect(await usdu.balanceOf(user.address)).to.equal(amount);
  });

  it("wires external circuit breaker module into USDU mint path", async function () {
    const {
      bridge,
      usdu,
      porFeed,
      usduCircuitBreaker,
      relayer,
      user,
      issuer1,
      issuer2,
      issuer3,
    } = await buildFixture();

    const deadline = (await ethers.provider.getBlock("latest"))!.timestamp + 3600;
    const chainId = (await ethers.provider.getNetwork()).chainId;
    const bridgeAddress = await bridge.getAddress();

    const seedOperation = ethers.id("CB_SEED_OP");
    const seedAmount = units(900);
    const seedDigest = buildMintDigest(
      bridgeAddress,
      chainId,
      ASSET_USDU,
      user.address,
      seedAmount,
      seedOperation,
      ENCLAVE_MEASUREMENT,
      deadline
    );
    const seedSig1 = await signMintTyped(issuer1, bridgeAddress, chainId, ASSET_USDU, user.address, seedAmount, seedOperation, ENCLAVE_MEASUREMENT, deadline);
    const seedSig2 = await signMintTyped(issuer2, bridgeAddress, chainId, ASSET_USDU, user.address, seedAmount, seedOperation, ENCLAVE_MEASUREMENT, deadline);
    const seedSig3 = await signMintTyped(issuer3, bridgeAddress, chainId, ASSET_USDU, user.address, seedAmount, seedOperation, ENCLAVE_MEASUREMENT, deadline);

    await bridge.connect(relayer).mintFromAttestedRelayer(
      ASSET_USDU,
      user.address,
      seedAmount,
      seedOperation,
      ENCLAVE_MEASUREMENT,
      deadline,
      [seedSig1, seedSig2, seedSig3]
    );

    // Tight reserve baseline so projected mint exceeds 0.5% deviation threshold.
    const now = (await ethers.provider.getBlock("latest"))!.timestamp;
    await porFeed.setRoundData(units(900), now);

    const secondOperation = ethers.id("CB_SECOND_OP");
    const secondAmount = units(10);
    const secondDigest = buildMintDigest(
      bridgeAddress,
      chainId,
      ASSET_USDU,
      user.address,
      secondAmount,
      secondOperation,
      ENCLAVE_MEASUREMENT,
      deadline
    );
    const secondSig1 = await signMintTyped(issuer1, bridgeAddress, chainId, ASSET_USDU, user.address, secondAmount, secondOperation, ENCLAVE_MEASUREMENT, deadline);
    const secondSig2 = await signMintTyped(issuer2, bridgeAddress, chainId, ASSET_USDU, user.address, secondAmount, secondOperation, ENCLAVE_MEASUREMENT, deadline);
    const secondSig3 = await signMintTyped(issuer3, bridgeAddress, chainId, ASSET_USDU, user.address, secondAmount, secondOperation, ENCLAVE_MEASUREMENT, deadline);

    // Current mint proceeds, but the bridge is paused for subsequent mints.
    await bridge.connect(relayer).mintFromAttestedRelayer(
      ASSET_USDU,
      user.address,
      secondAmount,
      secondOperation,
      ENCLAVE_MEASUREMENT,
      deadline,
      [secondSig1, secondSig2, secondSig3]
    );

    expect(await usdu.balanceOf(user.address)).to.equal(seedAmount + secondAmount);
    expect(await usduCircuitBreaker.isPaused()).to.equal(true);
    expect(await bridge.paused()).to.equal(true);
  });

  it("triggers a global pause when CCTP outflow breaches velocity limits", async function () {
    const { bridge, usdc, user, messenger } = await buildFixture();

    // 1,000 USDC circulating.
    await usdc.mint(user.address, units(1000));
    await usdc.connect(user).approve(await bridge.getAddress(), units(50));

    // 50 USDC outflow in one tx exceeds 3% hourly threshold (30 USDC at 1,000 supply).
    await bridge
      .connect(user)
      .bridgeOutViaCCTP(ASSET_USDC, units(50), 7, ethers.id("DESTINATION_RECIPIENT"));

    expect(await bridge.paused()).to.equal(true);
    expect(await messenger.nonce()).to.equal(1n);
  });

  it("M-02: hourly outflow ring buffer overwrites stale bucket values after 48h wrap", async function () {
    const { bridge, usdc, user, messenger } = await buildFixture();

    await usdc.mint(user.address, units(1000));
    await usdc.connect(user).approve(await bridge.getAddress(), units(40));

    // 20 USDC is below the 3% hourly cap at ~1,000 circulating.
    await bridge
      .connect(user)
      .bridgeOutViaCCTP(ASSET_USDC, units(20), 7, ethers.id("M02_HOURLY_WRAP_1"));

    expect(await bridge.paused()).to.equal(false);
    expect(await messenger.nonce()).to.equal(1n);

    // Same hourly slot after 48 hours (ring size = 48); stale values must be reset.
    await time.increase(48 * 60 * 60 + 5);

    await bridge
      .connect(user)
      .bridgeOutViaCCTP(ASSET_USDC, units(20), 7, ethers.id("M02_HOURLY_WRAP_2"));

    expect(await bridge.paused()).to.equal(false);
    expect(await messenger.nonce()).to.equal(2n);
  });

  it("M-02: daily outflow ring buffer overwrites stale bucket values after 14d wrap", async function () {
    const { bridge, usdc, user, messenger } = await buildFixture();

    const cfg = await bridge.stablecoins(ASSET_USDC);
    await bridge.configureStablecoin(
      {
        assetId: ASSET_USDC,
        enabled: cfg.enabled,
        routingType: cfg.routingType,
        token: cfg.token,
        tokenMessengerV2: cfg.tokenMessengerV2,
        messageTransmitterV2: cfg.messageTransmitterV2,
        proofOfReserveFeed: cfg.proofOfReserveFeed,
      },
      {
        mintCeilingPerEpoch: cfg.mintCeilingPerEpoch,
        dailyTxLimit: cfg.dailyTxLimit,
        hourlyOutflowBps: 10000, // neutralize hourly threshold for this daily wrap regression
        dailyOutflowBps: cfg.dailyOutflowBps,
        porDeviationBps: cfg.porDeviationBps,
        porHeartbeatSeconds: cfg.porHeartbeatSeconds,
      }
    );

    await usdc.mint(user.address, units(1000));
    await usdc.connect(user).approve(await bridge.getAddress(), units(120));

    // 60 USDC is below the 10% daily cap at ~1,000 circulating.
    await bridge
      .connect(user)
      .bridgeOutViaCCTP(ASSET_USDC, units(60), 7, ethers.id("M02_DAILY_WRAP_1"));

    expect(await bridge.paused()).to.equal(false);
    expect(await messenger.nonce()).to.equal(1n);

    // Same daily slot after 14 days (ring size = 14); stale values must be reset.
    await time.increase(14 * 24 * 60 * 60 + 5);

    await bridge
      .connect(user)
      .bridgeOutViaCCTP(ASSET_USDC, units(60), 7, ethers.id("M02_DAILY_WRAP_2"));

    expect(await bridge.paused()).to.equal(false);
    expect(await messenger.nonce()).to.equal(2n);
  });

  it("requires sovereign 3-of-5 signatures with at least one issuer key to unpause", async function () {
    const {
      bridge,
      issuer1,
      issuer2,
      issuer4,
      foundation,
      auditor,
      attacker,
    } = await buildFixture();

    await bridge.pauseFromCircuitBreaker(ASSET_USDU, ethers.id("TEST_PAUSE"));
    expect(await bridge.paused()).to.equal(true);

    const actionId = ethers.id("UNPAUSE_ACTION_1");
    const deadline = (await ethers.provider.getBlock("latest"))!.timestamp + 3600;
    const chainId = (await ethers.provider.getNetwork()).chainId;
    const bridgeAddress = await bridge.getAddress();
    const digest = buildUnpauseDigest(bridgeAddress, chainId, actionId, deadline);

    const issuerPrimarySig = await signUnpauseTyped(issuer1, bridgeAddress, chainId, actionId, deadline);
    const issuerRecoverySig = await signUnpauseTyped(issuer2, bridgeAddress, chainId, actionId, deadline);
    const foundationSig = await signUnpauseTyped(foundation, bridgeAddress, chainId, actionId, deadline);
    await bridge.unpauseWithJointSignatures(
      actionId,
      deadline,
      [issuerPrimarySig, issuerRecoverySig, foundationSig]
    );
    expect(await bridge.paused()).to.equal(false);

    await bridge.pauseFromCircuitBreaker(ASSET_USDU, ethers.id("TEST_PAUSE_2"));
    expect(await bridge.paused()).to.equal(true);

    const secondActionId = ethers.id("UNPAUSE_ACTION_2");
    const secondDigest = buildUnpauseDigest(bridgeAddress, chainId, secondActionId, deadline);
    const issuerSig2 = await signUnpauseTyped(issuer1, bridgeAddress, chainId, secondActionId, deadline);
    const auditorSig2 = await signUnpauseTyped(auditor, bridgeAddress, chainId, secondActionId, deadline);
    const guardianSig2 = await signUnpauseTyped(issuer4, bridgeAddress, chainId, secondActionId, deadline);
    await bridge.unpauseWithJointSignatures(
      secondActionId,
      deadline,
      [issuerSig2, auditorSig2, guardianSig2]
    );
    expect(await bridge.paused()).to.equal(false);

    await bridge.pauseFromCircuitBreaker(ASSET_USDU, ethers.id("TEST_PAUSE_3"));
    expect(await bridge.paused()).to.equal(true);

    const badActionId = ethers.id("UNPAUSE_ACTION_4");
    const badDigest = buildUnpauseDigest(bridgeAddress, chainId, badActionId, deadline);
    const badIssuerPrimarySig = await signUnpauseTyped(issuer1, bridgeAddress, chainId, badActionId, deadline);
    const badFoundationSig = await signUnpauseTyped(foundation, bridgeAddress, chainId, badActionId, deadline);
    const badAuditorSig = await signUnpauseTyped(attacker, bridgeAddress, chainId, badActionId, deadline);
    const badGuardianSig = await signUnpauseTyped(attacker, bridgeAddress, chainId, badActionId, deadline);

    await expect(
      bridge.unpauseWithJointSignatures(
        badActionId,
        deadline,
        [badIssuerPrimarySig, badFoundationSig, badAuditorSig, badGuardianSig]
      )
    ).to.be.revertedWithCustomError(bridge, "InvalidSignature");

    const missingIssuerActionId = ethers.id("UNPAUSE_ACTION_5");
    const missingIssuerDigest = buildUnpauseDigest(
      bridgeAddress,
      chainId,
      missingIssuerActionId,
      deadline
    );
    const fakeIssuerPrimarySig = await signUnpauseTyped(attacker, bridgeAddress, chainId, missingIssuerActionId, deadline);
    const fakeIssuerRecoverySig = await signUnpauseTyped(attacker, bridgeAddress, chainId, missingIssuerActionId, deadline);
    const validFoundationSig = await signUnpauseTyped(foundation, bridgeAddress, chainId, missingIssuerActionId, deadline);
    const validAuditorSig = await signUnpauseTyped(auditor, bridgeAddress, chainId, missingIssuerActionId, deadline);
    const validGuardianSig = await signUnpauseTyped(issuer4, bridgeAddress, chainId, missingIssuerActionId, deadline);

    await expect(
      bridge.unpauseWithJointSignatures(
        missingIssuerActionId,
        deadline,
        [
          fakeIssuerPrimarySig,
          fakeIssuerRecoverySig,
          validFoundationSig,
          validAuditorSig,
          validGuardianSig,
        ]
      )
    ).to.be.revertedWithCustomError(bridge, "InvalidSignature");
  });

  it("hard-reverts minting above daily mint ceiling even with valid issuer signatures", async function () {
    const {
      bridge,
      relayer,
      user,
      issuer1,
      issuer2,
      issuer3,
    } = await buildFixture();

    const deadline = (await ethers.provider.getBlock("latest"))!.timestamp + 3600;
    const chainId = (await ethers.provider.getNetwork()).chainId;
    const bridgeAddress = await bridge.getAddress();

    const op1 = ethers.id("QUOTA_MINT_OP_1");
    const amount1 = units(900);
    const digest1 = buildMintDigest(
      bridgeAddress,
      chainId,
      ASSET_USDU,
      user.address,
      amount1,
      op1,
      ENCLAVE_MEASUREMENT,
      deadline
    );
    const sig11 = await signMintTyped(issuer1, bridgeAddress, chainId, ASSET_USDU, user.address, amount1, op1, ENCLAVE_MEASUREMENT, deadline);
    const sig12 = await signMintTyped(issuer2, bridgeAddress, chainId, ASSET_USDU, user.address, amount1, op1, ENCLAVE_MEASUREMENT, deadline);
    const sig13 = await signMintTyped(issuer3, bridgeAddress, chainId, ASSET_USDU, user.address, amount1, op1, ENCLAVE_MEASUREMENT, deadline);

    await bridge.connect(relayer).mintFromAttestedRelayer(
      ASSET_USDU,
      user.address,
      amount1,
      op1,
      ENCLAVE_MEASUREMENT,
      deadline,
      [sig11, sig12, sig13]
    );

    const op2 = ethers.id("QUOTA_MINT_OP_2");
    const amount2 = units(200);
    const digest2 = buildMintDigest(
      bridgeAddress,
      chainId,
      ASSET_USDU,
      user.address,
      amount2,
      op2,
      ENCLAVE_MEASUREMENT,
      deadline
    );
    const sig21 = await signMintTyped(issuer1, bridgeAddress, chainId, ASSET_USDU, user.address, amount2, op2, ENCLAVE_MEASUREMENT, deadline);
    const sig22 = await signMintTyped(issuer2, bridgeAddress, chainId, ASSET_USDU, user.address, amount2, op2, ENCLAVE_MEASUREMENT, deadline);
    const sig23 = await signMintTyped(issuer3, bridgeAddress, chainId, ASSET_USDU, user.address, amount2, op2, ENCLAVE_MEASUREMENT, deadline);

    await expect(
      bridge.connect(relayer).mintFromAttestedRelayer(
        ASSET_USDU,
        user.address,
        amount2,
        op2,
        ENCLAVE_MEASUREMENT,
        deadline,
        [sig21, sig22, sig23]
      )
    ).to.be.revertedWithCustomError(bridge, "MintCeilingExceeded");
  });

  it("supports CCTP fast relay only with a valid Iris attester signature", async function () {
    const {
      bridge,
      relayer,
      irisAttester,
      attacker,
    } = await buildFixture();

    await bridge.setIrisAttester(irisAttester.address);

    const message = ethers.hexlify(ethers.toUtf8Bytes("cctp-fast-message"));
    const attestation = ethers.hexlify(ethers.toUtf8Bytes("iris-fast-attestation"));
    const deadline = (await ethers.provider.getBlock("latest"))!.timestamp + 3600;
    const chainId = (await ethers.provider.getNetwork()).chainId;

    const bridgeAddress = await bridge.getAddress();
    const messageHash = ethers.keccak256(message);
    const attestationHash = ethers.keccak256(attestation);
    const digest = buildCCTPFastDigest(bridgeAddress, chainId, ASSET_USDC, messageHash, attestationHash, deadline);
    const validSig = await signCCTPFastTyped(irisAttester, bridgeAddress, chainId, ASSET_USDC, messageHash, attestationHash, deadline);

    await expect(
      bridge.connect(relayer).relayCCTPFastMessage(
        ASSET_USDC,
        message,
        attestation,
        deadline,
        validSig
      )
    ).to.emit(bridge, "CCTPFastMessageRelayed");

    const invalidSig = await signCCTPFastTyped(attacker, bridgeAddress, chainId, ASSET_USDC, messageHash, attestationHash, deadline);
    await expect(
      bridge.connect(relayer).relayCCTPFastMessage(
        ASSET_USDC,
        message,
        attestation,
        deadline,
        invalidSig
      )
    ).to.be.revertedWithCustomError(bridge, "InvalidSignature");
  });

  it("records and verifies Merkle reserve proofs for auditor checks", async function () {
    const { bridge } = await buildFixture();

    const leaf = ethers.keccak256(ethers.toUtf8Bytes("walletA:1000000"));
    const reportHash = ethers.id("BIG4_REPORT_2026_02");
    const reportTimestamp = Math.floor(Date.now() / 1000);

    await bridge.recordMerkleAuditRoot(
      ASSET_USDU,
      leaf,
      reportHash,
      reportTimestamp
    );

    expect(await bridge.verifyReserveMerkleProof(ASSET_USDU, leaf, [])).to.equal(true);

    const badLeaf = ethers.keccak256(ethers.toUtf8Bytes("walletA:999999"));
    expect(await bridge.verifyReserveMerkleProof(ASSET_USDU, badLeaf, [])).to.equal(false);
  });
});
