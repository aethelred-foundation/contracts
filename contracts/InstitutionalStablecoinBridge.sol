// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./interfaces/ISovereignCircuitBreaker.sol";

interface ITokenMessengerV2 {
    function depositForBurn(
        uint256 amount,
        uint32 destinationDomain,
        bytes32 mintRecipient,
        address burnToken
    ) external returns (uint64 nonce);
}

interface IMessageTransmitterV2 {
    function receiveMessage(
        bytes calldata message,
        bytes calldata attestation
    ) external returns (bool success);
}

interface IMintBurnERC20 is IERC20 {
    function mint(address to, uint256 amount) external;
    function burnFrom(address account, uint256 amount) external;
}

interface IAggregatorV3 {
    function decimals() external view returns (uint8);
    function latestRoundData()
        external
        view
        returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        );
}

/**
 * @title InstitutionalStablecoinBridge
 * @author Aethelred Protocol Foundation
 * @notice TRD V2 bridge/router for institutional stablecoin flows on Aethelred testnet.
 * @dev Implements:
 * - Zero-liquidity-pool routing (CCTP burn-and-mint, or issuer-gated TEE mint flow)
 * - Chainlink PoR anomaly monitoring with pause(), not per-tx oracle reverts
 * - Time-locked risk parameter changes
 * - Velocity and quota circuit breakers
 * - Joint-signature unpause governance (Issuer + Foundation + Auditor/Custodian)
 * - Chainlink Automation-compatible checkUpkeep/performUpkeep for autonomous PoR
 * @custom:security-contact security@aethelred.io
 * @custom:audit-status Remediated - all 27 findings addressed (2026-02-22)
 */
contract InstitutionalStablecoinBridge is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable
{
    using SafeERC20 for IERC20;

    bytes32 public constant CONFIG_ROLE = keccak256("CONFIG_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant UNPAUSER_ROLE = keccak256("UNPAUSER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    uint256 internal constant BPS_DENOMINATOR = 10_000;
    uint256 internal constant EPOCH_SECONDS = 1 days;
    uint256 internal constant HOUR_SECONDS = 1 hours;
    uint256 internal constant HOURLY_OUTFLOW_RING_SLOTS = 48;
    uint256 internal constant DAILY_OUTFLOW_RING_SLOTS = 14;
    uint256 internal constant MIN_GOVERNANCE_ACTION_DELAY = 7 days;
    uint256 internal constant DEFAULT_RELAYER_BOND_REQUIREMENT = 500_000 ether;
    uint256 internal constant SECP256K1N_HALF =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;
    bytes32 internal constant EIP712_DOMAIN_TYPEHASH =
        keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );
    bytes32 internal constant EIP712_NAME_HASH =
        keccak256("InstitutionalStablecoinBridge");
    bytes32 internal constant EIP712_VERSION_HASH = keccak256("2");
    bytes32 internal constant TEE_MINT_TYPEHASH =
        keccak256(
            "TeeMint(bytes32 assetId,address recipient,uint256 amount,bytes32 mintOperationId,bytes32 enclaveMeasurement,uint256 deadline)"
        );
    bytes32 internal constant JOINT_UNPAUSE_TYPEHASH =
        keccak256("JointUnpause(bytes32 actionId,uint256 deadline)");
    bytes32 internal constant CCTP_FAST_TYPEHASH =
        keccak256(
            "CCTPFast(bytes32 assetId,bytes32 messageHash,bytes32 attestationHash,uint256 deadline)"
        );

    enum RoutingType {
        Unsupported,
        CCTP_V2,
        TEE_ISSUER_MINT
    }

    struct StablecoinConfig {
        bool enabled;
        bool mintPaused;
        RoutingType routingType;
        address token;
        address tokenMessengerV2;
        address messageTransmitterV2;
        address proofOfReserveFeed;
        uint256 mintCeilingPerEpoch;
        uint256 dailyTxLimit;
        uint16 hourlyOutflowBps;
        uint16 dailyOutflowBps;
        uint16 porDeviationBps;
        uint48 porHeartbeatSeconds;
    }

    /// @dev Calldata structs used by `configureStablecoin` to avoid stack-too-deep
    ///      when decoding many parameters through the Yul/IR ABI decoder.
    ///      Split into two smaller structs so neither exceeds the EVM 16-slot limit.
    struct ConfigureStablecoinCore {
        bytes32 assetId;
        bool enabled;
        RoutingType routingType;
        address token;
        address tokenMessengerV2;
        address messageTransmitterV2;
        address proofOfReserveFeed;
    }

    struct ConfigureStablecoinLimits {
        uint256 mintCeilingPerEpoch;
        uint256 dailyTxLimit;
        uint16 hourlyOutflowBps;
        uint16 dailyOutflowBps;
        uint16 porDeviationBps;
        uint48 porHeartbeatSeconds;
    }

    struct EpochUsage {
        uint64 epochId;
        uint256 mintedAmount;
        uint256 txVolume;
    }

    struct MerkleAuditRecord {
        bytes32 merkleRoot;
        bytes32 reportHash;
        uint64 reportTimestamp;
        uint64 recordedAt;
    }

    mapping(bytes32 => StablecoinConfig) public stablecoins;
    mapping(bytes32 => mapping(address => bool)) internal isIssuerSigner;
    mapping(bytes32 => address[]) internal issuerSignerList;
    mapping(bytes32 => uint8) public issuerThreshold;
    mapping(bytes32 => bool) internal approvedEnclaveMeasurements;
    mapping(bytes32 => bool) internal usedMintOperations;
    mapping(bytes32 => bool) internal usedUnpauseActions;

    mapping(bytes32 => EpochUsage) internal epochUsage;
    mapping(bytes32 => mapping(uint256 => uint256)) internal hourlyOutflow;
    mapping(bytes32 => mapping(uint256 => uint256)) internal dailyOutflow;
    mapping(bytes32 => mapping(uint256 => uint256)) internal hourlyOutflowBucketTag;
    mapping(bytes32 => mapping(uint256 => uint256)) internal dailyOutflowBucketTag;

    mapping(bytes32 => MerkleAuditRecord) internal latestMerkleAudit;
    mapping(bytes32 => address) internal circuitBreakerModule;
    mapping(address => uint256) internal relayerBonds;

    address public issuerGovernanceKey;
    address public issuerRecoveryGovernanceKey;
    address public foundationGovernanceKey;
    address public auditorGovernanceKey;
    address public guardianGovernanceKey;
    address public irisAttester;
    address public governanceTimelock;
    uint48 internal governanceActionDelaySeconds;
    address internal relayerBondToken;
    uint256 internal relayerBondRequirement;

    /// @notice Timestamp of the last Chainlink Automation check (H-09 hardening)
    uint256 public lastAutomatedCheckTimestamp;

    event StablecoinConfigured(
        bytes32 indexed assetId,
        address indexed token,
        RoutingType routingType,
        bool enabled
    );
    event IssuerSignerSet(
        bytes32 indexed assetId,
        address[] signers,
        uint8 threshold
    );
    event EnclaveMeasurementUpdated(bytes32 indexed measurement, bool allowed);
    event MintExecuted(
        bytes32 indexed assetId,
        bytes32 indexed mintOperationId,
        address indexed recipient,
        uint256 amount
    );
    event CCTPBurnInitiated(
        bytes32 indexed assetId,
        address indexed sender,
        uint32 indexed destinationDomain,
        uint256 amount,
        uint64 cctpNonce
    );
    event CCTPMessageRelayed(
        bytes32 indexed assetId,
        address indexed relayer,
        bool success
    );
    event CCTPFastMessageRelayed(
        bytes32 indexed assetId,
        address indexed relayer,
        bool success
    );
    event TeeRedemptionRequested(
        bytes32 indexed assetId,
        address indexed account,
        uint256 amount,
        bytes32 issuerReference
    );
    event ReserveCheckPerformed(
        bytes32 indexed assetId,
        uint256 reserveAmount18,
        uint256 liabilities18,
        uint256 deviationBps,
        bool heartbeatStale
    );
    event CircuitBreakerTriggered(
        bytes32 indexed assetId,
        bytes32 indexed reasonCode,
        uint256 observed,
        uint256 threshold
    );
    event MerkleAuditRootRecorded(
        bytes32 indexed assetId,
        bytes32 indexed merkleRoot,
        bytes32 indexed reportHash,
        uint64 reportTimestamp
    );
    event GovernanceKeysUpdated(
        address issuerKey,
        address foundationKey,
        address auditorKey
    );
    event IrisAttesterUpdated(address indexed irisAttester);
    event JointUnpauseExecuted(bytes32 indexed actionId, address indexed executor);
    event GovernanceTimelockConfigured(
        address indexed timelock,
        uint48 delaySeconds
    );
    event RelayerBondConfigured(
        address indexed bondToken,
        uint256 requiredBond
    );
    event RelayerBondPosted(
        address indexed relayer,
        uint256 amount,
        uint256 totalBonded
    );
    event RelayerBondWithdrawn(
        address indexed relayer,
        address indexed recipient,
        uint256 amount,
        uint256 remainingBond
    );
    event RelayerBondSlashed(
        address indexed relayer,
        address indexed recipient,
        uint256 amount,
        bytes32 reasonCode
    );
    event AutomatedReserveCheckPerformed(
        bytes32 indexed assetId,
        uint256 timestamp,
        bool breached
    );

    error InvalidAddress();
    error InvalidRecipient();
    error InvalidConfig();
    error AssetNotSupported();
    error InvalidRoutingType();
    error MintPausedForAsset();
    error InvalidAmount();
    error InvalidSignature();
    error InsufficientIssuerSignatures();
    error ExpiredOperation();
    error DuplicateOperation();
    error EnclaveMeasurementNotApproved();
    error NotCCTPAsset();
    error NotTeeMintAsset();
    error MintCeilingExceeded();
    error DailyTxLimitExceeded();
    error TimelockRequired();
    error TimelockDelayTooShort();
    error RelayerBondTokenNotConfigured();
    error RelayerBondInsufficient();
    error RelayerBondNotFound();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    modifier onlyGovernedConfigRole() {
        _checkRole(CONFIG_ROLE, msg.sender);
        if (governanceTimelock != address(0) && msg.sender != governanceTimelock) {
            revert TimelockRequired();
        }
        _;
    }

    modifier onlyBondedRelayer() {
        _requireBondedRelayer(msg.sender);
        _;
    }

    function initialize(
        address admin,
        address issuerKey,
        address foundationKey,
        address auditorKey
    ) external initializer {
        if (
            admin == address(0) ||
            issuerKey == address(0) ||
            foundationKey == address(0) ||
            auditorKey == address(0)
        ) revert InvalidAddress();
        if (
            admin.code.length == 0 &&
            block.chainid != 31337 &&
            block.chainid != 1337
        ) revert InvalidConfig();

        __UUPSUpgradeable_init();
        __AccessControl_init();
        __Pausable_init();
        __ReentrancyGuard_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(CONFIG_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
        _grantRole(MINTER_ROLE, admin);
        _grantRole(RELAYER_ROLE, admin);
        _grantRole(UNPAUSER_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);

        issuerGovernanceKey = issuerKey;
        foundationGovernanceKey = foundationKey;
        auditorGovernanceKey = auditorKey;
        governanceActionDelaySeconds = uint48(MIN_GOVERNANCE_ACTION_DELAY);
        relayerBondRequirement = DEFAULT_RELAYER_BOND_REQUIREMENT;
    }

    function setGovernanceKeys(
        address issuerKey,
        address foundationKey,
        address auditorKey
    ) external onlyGovernedConfigRole {
        if (
            issuerKey == address(0) ||
            foundationKey == address(0) ||
            auditorKey == address(0)
        ) revert InvalidAddress();

        if (
            issuerRecoveryGovernanceKey != address(0) &&
            issuerKey == issuerRecoveryGovernanceKey
        ) revert InvalidConfig();
        if (
            guardianGovernanceKey != address(0) &&
            (
                guardianGovernanceKey == issuerKey ||
                guardianGovernanceKey == foundationKey ||
                guardianGovernanceKey == auditorKey
            )
        ) revert InvalidConfig();

        issuerGovernanceKey = issuerKey;
        foundationGovernanceKey = foundationKey;
        auditorGovernanceKey = auditorKey;
        emit GovernanceKeysUpdated(issuerKey, foundationKey, auditorKey);
    }

    function setSovereignUnpauseKeys(
        address issuerRecoveryKey,
        address guardianKey
    ) external onlyGovernedConfigRole {
        if (issuerRecoveryKey == address(0) || guardianKey == address(0)) {
            revert InvalidAddress();
        }
        if (
            issuerRecoveryKey == issuerGovernanceKey ||
            issuerRecoveryKey == foundationGovernanceKey ||
            issuerRecoveryKey == auditorGovernanceKey ||
            guardianKey == issuerGovernanceKey ||
            guardianKey == foundationGovernanceKey ||
            guardianKey == auditorGovernanceKey ||
            issuerRecoveryKey == guardianKey
        ) revert InvalidConfig();

        issuerRecoveryGovernanceKey = issuerRecoveryKey;
        guardianGovernanceKey = guardianKey;
    }

    function setIrisAttester(address attester) external onlyGovernedConfigRole {
        if (attester == address(0)) revert InvalidAddress();
        irisAttester = attester;
        emit IrisAttesterUpdated(attester);
    }

    function configureGovernanceTimelock(address timelock, uint48 delaySeconds)
        external
        onlyRole(CONFIG_ROLE)
    {
        if (timelock == address(0)) revert InvalidAddress();
        if (delaySeconds < MIN_GOVERNANCE_ACTION_DELAY) {
            revert TimelockDelayTooShort();
        }
        governanceTimelock = timelock;
        governanceActionDelaySeconds = delaySeconds;
        emit GovernanceTimelockConfigured(timelock, delaySeconds);
    }

    function configureRelayerBonding(address bondToken, uint256 requiredBond)
        external
        onlyGovernedConfigRole
    {
        if (bondToken == address(0)) revert InvalidAddress();
        if (requiredBond < DEFAULT_RELAYER_BOND_REQUIREMENT) revert InvalidConfig();
        relayerBondToken = bondToken;
        relayerBondRequirement = requiredBond;
        emit RelayerBondConfigured(bondToken, requiredBond);
    }

    function postRelayerBond(uint256 amount)
        external
        onlyRole(RELAYER_ROLE)
        nonReentrant
    {
        if (relayerBondToken == address(0)) revert RelayerBondTokenNotConfigured();
        if (amount == 0) revert InvalidAmount();

        uint256 balanceBefore = IERC20(relayerBondToken).balanceOf(address(this));
        IERC20(relayerBondToken).safeTransferFrom(msg.sender, address(this), amount);
        uint256 actualReceived = IERC20(relayerBondToken).balanceOf(address(this)) - balanceBefore;

        relayerBonds[msg.sender] += actualReceived;
        emit RelayerBondPosted(msg.sender, actualReceived, relayerBonds[msg.sender]);
    }

    function withdrawRelayerBond(uint256 amount, address recipient)
        external
        onlyRole(RELAYER_ROLE)
        nonReentrant
    {
        if (recipient == address(0)) revert InvalidRecipient();
        if (amount == 0) revert InvalidAmount();
        if (relayerBondToken == address(0)) revert RelayerBondTokenNotConfigured();

        uint256 currentBond = relayerBonds[msg.sender];
        if (currentBond < amount) revert RelayerBondInsufficient();

        uint256 remainingBond = currentBond - amount;
        if (remainingBond < relayerBondRequirement) {
            revert RelayerBondInsufficient();
        }

        relayerBonds[msg.sender] = remainingBond;
        IERC20(relayerBondToken).safeTransfer(recipient, amount);
        emit RelayerBondWithdrawn(msg.sender, recipient, amount, remainingBond);
    }

    function slashRelayerBond(
        address relayer,
        bytes32 reasonCode,
        address recipient
    ) external onlyRole(PAUSER_ROLE) nonReentrant {
        if (relayer == address(0)) revert InvalidAddress();
        if (recipient == address(0)) revert InvalidRecipient();
        if (relayerBondToken == address(0)) revert RelayerBondTokenNotConfigured();

        uint256 bonded = relayerBonds[relayer];
        if (bonded == 0) revert RelayerBondNotFound();

        relayerBonds[relayer] = 0;
        IERC20(relayerBondToken).safeTransfer(recipient, bonded);
        emit RelayerBondSlashed(relayer, recipient, bonded, reasonCode);
    }

    function setCircuitBreakerModule(bytes32 assetId, address module)
        external
        onlyGovernedConfigRole
    {
        if (stablecoins[assetId].token == address(0)) revert AssetNotSupported();
        circuitBreakerModule[assetId] = module;
    }

    function configureStablecoin(
        ConfigureStablecoinCore calldata core,
        ConfigureStablecoinLimits calldata limits
    ) external onlyGovernedConfigRole {
        if (core.assetId == bytes32(0) || core.token == address(0)) revert InvalidConfig();
        if (core.routingType == RoutingType.Unsupported) revert InvalidRoutingType();
        if (
            limits.hourlyOutflowBps > BPS_DENOMINATOR ||
            limits.dailyOutflowBps > BPS_DENOMINATOR ||
            limits.porDeviationBps > BPS_DENOMINATOR
        ) revert InvalidConfig();

        if (core.routingType == RoutingType.CCTP_V2) {
            if (
                core.tokenMessengerV2 == address(0) ||
                core.messageTransmitterV2 == address(0)
            ) revert InvalidConfig();
        }

        StablecoinConfig storage cfg = stablecoins[core.assetId];
        cfg.enabled = core.enabled;
        cfg.mintPaused = false;
        cfg.routingType = core.routingType;
        cfg.token = core.token;
        cfg.tokenMessengerV2 = core.tokenMessengerV2;
        cfg.messageTransmitterV2 = core.messageTransmitterV2;
        cfg.proofOfReserveFeed = core.proofOfReserveFeed;
        cfg.mintCeilingPerEpoch = limits.mintCeilingPerEpoch;
        cfg.dailyTxLimit = limits.dailyTxLimit;
        cfg.hourlyOutflowBps = limits.hourlyOutflowBps;
        cfg.dailyOutflowBps = limits.dailyOutflowBps;
        cfg.porDeviationBps = limits.porDeviationBps;
        cfg.porHeartbeatSeconds = limits.porHeartbeatSeconds;

        emit StablecoinConfigured(core.assetId, core.token, core.routingType, core.enabled);
    }

    function setIssuerSignerSet(
        bytes32 assetId,
        address[] calldata signers,
        uint8 threshold
    ) external {
        if (assetId == bytes32(0) || signers.length == 0) revert InvalidConfig();
        if (governanceTimelock != address(0)) {
            if (msg.sender != governanceTimelock) revert TimelockRequired();
        } else {
            if (msg.sender != issuerGovernanceKey) revert InvalidSignature();
        }
        if (signers.length != 5 || threshold != 3) revert InvalidConfig();

        address[] storage previous = issuerSignerList[assetId];
        for (uint256 i = 0; i < previous.length; i++) {
            isIssuerSigner[assetId][previous[i]] = false;
        }
        delete issuerSignerList[assetId];

        for (uint256 i = 0; i < signers.length; i++) {
            address signer = signers[i];
            if (signer == address(0)) revert InvalidAddress();
            if (
                signer == foundationGovernanceKey ||
                signer == auditorGovernanceKey ||
                signer == guardianGovernanceKey
            ) revert InvalidConfig();
            if (isIssuerSigner[assetId][signer]) revert InvalidConfig();
            isIssuerSigner[assetId][signer] = true;
            issuerSignerList[assetId].push(signer);
        }

        issuerThreshold[assetId] = threshold;
        emit IssuerSignerSet(assetId, signers, threshold);
    }

    function setEnclaveMeasurement(bytes32 measurement, bool allowed)
        external
        onlyGovernedConfigRole
    {
        approvedEnclaveMeasurements[measurement] = allowed;
        emit EnclaveMeasurementUpdated(measurement, allowed);
    }

    function mintFromAttestedRelayer(
        bytes32 assetId,
        address recipient,
        uint256 amount,
        bytes32 mintOperationId,
        bytes32 enclaveMeasurement,
        uint256 deadline,
        bytes[] calldata issuerSignatures
    ) external onlyRole(RELAYER_ROLE) onlyBondedRelayer whenNotPaused nonReentrant {
        StablecoinConfig storage cfg = _requireEnabledTeeMintAsset(assetId);
        if (cfg.mintPaused) revert MintPausedForAsset();
        if (recipient == address(0)) revert InvalidRecipient();
        if (amount == 0) revert InvalidAmount();
        if (deadline < block.timestamp) revert ExpiredOperation();
        if (!approvedEnclaveMeasurements[enclaveMeasurement]) {
            revert EnclaveMeasurementNotApproved();
        }

        bytes32 opKey = keccak256(abi.encode(assetId, mintOperationId));
        if (usedMintOperations[opKey]) revert DuplicateOperation();
        usedMintOperations[opKey] = true;

        _reserveMintUsage(assetId, amount);
        _monitorReserve(assetId, cfg, amount);
        _checkExternalCircuitBreaker(assetId, amount);

        bytes32 digest = _buildMintDigest(
            assetId,
            recipient,
            amount,
            mintOperationId,
            enclaveMeasurement,
            deadline
        );
        _requireIssuerQuorum(assetId, digest, issuerSignatures);

        IMintBurnERC20(cfg.token).mint(recipient, amount);

        emit MintExecuted(assetId, mintOperationId, recipient, amount);
    }

    function bridgeOutViaCCTP(
        bytes32 assetId,
        uint256 amount,
        uint32 destinationDomain,
        bytes32 mintRecipient
    ) external whenNotPaused nonReentrant returns (uint64 cctpNonce) {
        StablecoinConfig storage cfg = _requireEnabledCCTPAsset(assetId);
        if (amount == 0) revert InvalidAmount();

        IERC20 token = IERC20(cfg.token);
        uint256 balanceBefore = token.balanceOf(address(this));
        token.safeTransferFrom(msg.sender, address(this), amount);
        uint256 actualReceived = token.balanceOf(address(this)) - balanceBefore;

        token.forceApprove(cfg.tokenMessengerV2, actualReceived);

        cctpNonce = ITokenMessengerV2(cfg.tokenMessengerV2).depositForBurn(
            actualReceived,
            destinationDomain,
            mintRecipient,
            cfg.token
        );

        _recordOutflowAndCircuitCheck(assetId, actualReceived);

        emit CCTPBurnInitiated(
            assetId,
            msg.sender,
            destinationDomain,
            actualReceived,
            cctpNonce
        );
    }

    function relayCCTPMessage(
        bytes32 assetId,
        bytes calldata message,
        bytes calldata attestation
    ) external onlyRole(RELAYER_ROLE) onlyBondedRelayer whenNotPaused returns (bool success) {
        StablecoinConfig storage cfg = _requireEnabledCCTPAsset(assetId);
        success = _receiveCCTPMessage(cfg, message, attestation);
        emit CCTPMessageRelayed(assetId, msg.sender, success);
    }

    function relayCCTPFastMessage(
        bytes32 assetId,
        bytes calldata message,
        bytes calldata attestation,
        uint256 deadline,
        bytes calldata irisSignature
    ) external onlyRole(RELAYER_ROLE) onlyBondedRelayer whenNotPaused returns (bool success) {
        StablecoinConfig storage cfg = _requireEnabledCCTPAsset(assetId);
        if (irisAttester == address(0)) revert InvalidConfig();
        if (deadline < block.timestamp) revert ExpiredOperation();

        bytes32 digest = _buildCCTPFastDigest(
            assetId,
            keccak256(message),
            keccak256(attestation),
            deadline
        );
        bytes32 signed = _toTypedDataHash(digest);
        address recovered = _recoverSigner(signed, irisSignature);
        if (recovered != irisAttester) revert InvalidSignature();

        success = _receiveCCTPMessage(cfg, message, attestation);
        emit CCTPFastMessageRelayed(assetId, msg.sender, success);
    }

    function redeemTeeStablecoin(
        bytes32 assetId,
        uint256 amount,
        bytes32 issuerReference
    ) external whenNotPaused nonReentrant {
        StablecoinConfig storage cfg = _requireEnabledTeeMintAsset(assetId);
        if (amount == 0) revert InvalidAmount();

        IMintBurnERC20(cfg.token).burnFrom(msg.sender, amount);
        _recordOutflowAndCircuitCheck(assetId, amount);

        emit TeeRedemptionRequested(assetId, msg.sender, amount, issuerReference);
    }

    /**
     * @notice Monitors Chainlink PoR and pauses minting on anomalies.
     * @dev This function intentionally does NOT revert mint txs. It triggers pause() for
     * subsequent mints when deviation/staleness exceeds configured tolerance.
     */
    function monitorReserve(bytes32 assetId) external onlyRole(PAUSER_ROLE) {
        StablecoinConfig storage cfg = stablecoins[assetId];
        if (!cfg.enabled) revert AssetNotSupported();
        if (cfg.proofOfReserveFeed == address(0)) revert InvalidConfig();
        _monitorReserve(assetId, cfg, 0);
    }

    function recordMerkleAuditRoot(
        bytes32 assetId,
        bytes32 merkleRoot,
        bytes32 reportHash,
        uint64 reportTimestamp
    ) external onlyRole(PAUSER_ROLE) {
        if (stablecoins[assetId].token == address(0)) revert AssetNotSupported();
        if (merkleRoot == bytes32(0) || reportHash == bytes32(0)) revert InvalidConfig();

        latestMerkleAudit[assetId] = MerkleAuditRecord({
            merkleRoot: merkleRoot,
            reportHash: reportHash,
            reportTimestamp: reportTimestamp,
            recordedAt: uint64(block.timestamp)
        });

        emit MerkleAuditRootRecorded(assetId, merkleRoot, reportHash, reportTimestamp);
    }

    function verifyReserveMerkleProof(
        bytes32 assetId,
        bytes32 leaf,
        bytes32[] calldata proof
    ) external view returns (bool) {
        bytes32 root = latestMerkleAudit[assetId].merkleRoot;
        if (root == bytes32(0)) return false;
        return _verifyMerkleProof(leaf, proof, root);
    }

    /// @notice Returns bonded relayer status and bond configuration in one call.
    function getRelayerBondStatus(address relayer)
        external
        view
        returns (
            uint256 bondedAmount,
            uint256 requiredBond,
            address bondToken
        )
    {
        bondedAmount = relayerBonds[relayer];
        requiredBond = relayerBondRequirement;
        bondToken = relayerBondToken;
    }

    /// @notice Returns whether a TEE enclave measurement is currently approved.
    function isEnclaveMeasurementApproved(bytes32 measurement)
        external
        view
        returns (bool)
    {
        return approvedEnclaveMeasurements[measurement];
    }

    function pauseFromCircuitBreaker(bytes32 assetId, bytes32 reasonCode)
        external
        onlyRole(PAUSER_ROLE)
    {
        if (governanceTimelock != address(0) && msg.sender != governanceTimelock) {
            revert TimelockRequired();
        }
        _triggerCircuitBreaker(assetId, reasonCode, 1, 1);
    }

    function unpauseWithJointSignatures(
        bytes32 actionId,
        uint256 deadline,
        bytes[] calldata signatures
    ) external onlyRole(UNPAUSER_ROLE) {
        if (!paused()) revert InvalidConfig();
        if (deadline < block.timestamp) revert ExpiredOperation();
        if (usedUnpauseActions[actionId]) revert DuplicateOperation();
        if (
            issuerRecoveryGovernanceKey == address(0) ||
            guardianGovernanceKey == address(0)
        ) revert InvalidConfig();
        if (signatures.length < 3 || signatures.length > 5) revert InvalidSignature();

        bytes32 digest = _buildUnpauseDigest(actionId, deadline);
        bytes32 signed = _toTypedDataHash(digest);
        address[] memory allowedSigners = new address[](5);
        allowedSigners[0] = issuerGovernanceKey;
        allowedSigners[1] = issuerRecoveryGovernanceKey;
        allowedSigners[2] = foundationGovernanceKey;
        allowedSigners[3] = auditorGovernanceKey;
        allowedSigners[4] = guardianGovernanceKey;
        (uint256 validSignerCount, bool hasIssuerAnchor) = _countUniqueAllowedSigners(
            signed,
            signatures,
            allowedSigners,
            issuerGovernanceKey,
            issuerRecoveryGovernanceKey
        );

        if (validSignerCount < 3 || !hasIssuerAnchor) revert InvalidSignature();

        usedUnpauseActions[actionId] = true;
        _unpause();
        emit JointUnpauseExecuted(actionId, msg.sender);
    }

    function _requireBondedRelayer(address relayer) internal view {
        if (relayerBondToken == address(0)) revert RelayerBondTokenNotConfigured();
        if (relayerBonds[relayer] < relayerBondRequirement) {
            revert RelayerBondInsufficient();
        }
    }

    function _buildMintDigest(
        bytes32 assetId,
        address recipient,
        uint256 amount,
        bytes32 mintOperationId,
        bytes32 enclaveMeasurement,
        uint256 deadline
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    TEE_MINT_TYPEHASH,
                    assetId,
                    recipient,
                    amount,
                    mintOperationId,
                    enclaveMeasurement,
                    deadline
                )
            );
    }

    function _buildUnpauseDigest(bytes32 actionId, uint256 deadline)
        internal
        pure
        returns (bytes32)
    {
        return
            keccak256(
                abi.encode(
                    JOINT_UNPAUSE_TYPEHASH,
                    actionId,
                    deadline
                )
            );
    }

    function _buildCCTPFastDigest(
        bytes32 assetId,
        bytes32 messageHash,
        bytes32 attestationHash,
        uint256 deadline
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    CCTP_FAST_TYPEHASH,
                    assetId,
                    messageHash,
                    attestationHash,
                    deadline
                )
            );
    }

    function _requireIssuerQuorum(
        bytes32 assetId,
        bytes32 digest,
        bytes[] calldata signatures
    ) internal view {
        uint8 threshold = issuerThreshold[assetId];
        if (threshold == 0) revert InvalidConfig();

        bytes32 signed = _toTypedDataHash(digest);
        address[] storage signerStorage = issuerSignerList[assetId];
        address[] memory allowedSigners = new address[](signerStorage.length);
        for (uint256 i = 0; i < signerStorage.length; i++) {
            allowedSigners[i] = signerStorage[i];
        }
        (uint256 validCount, ) = _countUniqueAllowedSigners(
            signed,
            signatures,
            allowedSigners,
            address(0),
            address(0)
        );

        if (validCount < threshold) revert InsufficientIssuerSignatures();
    }

    function _countUniqueAllowedSigners(
        bytes32 signedDigest,
        bytes[] calldata signatures,
        address[] memory allowedSigners,
        address anchor1,
        address anchor2
    ) internal pure returns (uint256 validCount, bool hasAnchor) {
        address[] memory seen = new address[](signatures.length);
        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = _recoverSigner(signedDigest, signatures[i]);
            if (!_addressInList(signer, allowedSigners, allowedSigners.length)) {
                continue;
            }
            if (_addressInList(signer, seen, validCount)) {
                continue;
            }

            seen[validCount] = signer;
            validCount++;
            if (signer == anchor1 || signer == anchor2) {
                hasAnchor = true;
            }
        }
    }

    function _addressInList(
        address account,
        address[] memory list,
        uint256 length
    ) internal pure returns (bool) {
        for (uint256 i = 0; i < length; i++) {
            if (list[i] == account) return true;
        }
        return false;
    }

    function _reserveMintUsage(bytes32 assetId, uint256 amount) internal {
        StablecoinConfig storage cfg = stablecoins[assetId];

        uint64 epochId = uint64(block.timestamp / EPOCH_SECONDS);
        EpochUsage storage usage = epochUsage[assetId];
        if (usage.epochId != epochId) {
            usage.epochId = epochId;
            usage.mintedAmount = 0;
            usage.txVolume = 0;
        }

        uint256 projectedMinted = usage.mintedAmount + amount;
        uint256 projectedVolume = usage.txVolume + amount;

        if (
            cfg.mintCeilingPerEpoch > 0 &&
            projectedMinted > cfg.mintCeilingPerEpoch
        ) {
            revert MintCeilingExceeded();
        }

        if (cfg.dailyTxLimit > 0 && projectedVolume > cfg.dailyTxLimit) {
            revert DailyTxLimitExceeded();
        }

        usage.mintedAmount = projectedMinted;
        usage.txVolume = projectedVolume;
    }

    function _checkExternalCircuitBreaker(bytes32 assetId, uint256 pendingMintAmount)
        internal
    {
        address module = circuitBreakerModule[assetId];
        if (module == address(0)) {
            return;
        }

        ISovereignCircuitBreaker(module).checkReserveAnomaly(pendingMintAmount);
        if (ISovereignCircuitBreaker(module).isPaused()) {
            _triggerCircuitBreaker(assetId, keccak256("EXT_CB_PAUSED"), 1, 1);
        }
    }

    function _monitorReserve(
        bytes32 assetId,
        StablecoinConfig storage cfg,
        uint256 pendingMintAmount
    ) internal {
        if (cfg.proofOfReserveFeed == address(0)) {
            return;
        }

        (
            ,
            int256 reserveAnswer,
            ,
            uint256 updatedAt,
        ) = IAggregatorV3(cfg.proofOfReserveFeed).latestRoundData();
        if (reserveAnswer <= 0) {
            _triggerCircuitBreaker(assetId, keccak256("POR_NON_POSITIVE"), 0, 1);
            emit ReserveCheckPerformed(assetId, 0, 0, BPS_DENOMINATOR, true);
            return;
        }

        uint8 feedDecimals = IAggregatorV3(cfg.proofOfReserveFeed).decimals();
        uint8 tokenDecimals = IERC20Metadata(cfg.token).decimals();

        uint256 reserveAmount18 = _normalizeTo18(
            uint256(reserveAnswer),
            feedDecimals
        );
        uint256 liabilitiesRaw = IERC20Metadata(cfg.token).totalSupply() + pendingMintAmount;
        uint256 liabilities18 = _normalizeTo18(liabilitiesRaw, tokenDecimals);

        bool stale = cfg.porHeartbeatSeconds > 0 &&
            block.timestamp > updatedAt + cfg.porHeartbeatSeconds;

        uint256 deviationBps = 0;
        if (liabilities18 > reserveAmount18 && liabilities18 > 0) {
            deviationBps =
                ((liabilities18 - reserveAmount18) * BPS_DENOMINATOR) /
                liabilities18;
        }

        if (stale || deviationBps > cfg.porDeviationBps) {
            _triggerCircuitBreaker(
                assetId,
                stale ? keccak256("POR_HEARTBEAT_STALE") : keccak256("POR_DEVIATION"),
                deviationBps,
                cfg.porDeviationBps
            );
        }

        emit ReserveCheckPerformed(
            assetId,
            reserveAmount18,
            liabilities18,
            deviationBps,
            stale
        );
    }

    function _requireEnabledAsset(bytes32 assetId)
        internal
        view
        returns (StablecoinConfig storage cfg)
    {
        cfg = stablecoins[assetId];
        if (!cfg.enabled) revert AssetNotSupported();
    }

    function _requireEnabledCCTPAsset(bytes32 assetId)
        internal
        view
        returns (StablecoinConfig storage cfg)
    {
        cfg = _requireEnabledAsset(assetId);
        if (cfg.routingType != RoutingType.CCTP_V2) revert NotCCTPAsset();
    }

    function _requireEnabledTeeMintAsset(bytes32 assetId)
        internal
        view
        returns (StablecoinConfig storage cfg)
    {
        cfg = _requireEnabledAsset(assetId);
        if (cfg.routingType != RoutingType.TEE_ISSUER_MINT) revert NotTeeMintAsset();
    }

    function _receiveCCTPMessage(
        StablecoinConfig storage cfg,
        bytes calldata message,
        bytes calldata attestation
    ) internal returns (bool success) {
        success = IMessageTransmitterV2(cfg.messageTransmitterV2).receiveMessage(
            message,
            attestation
        );
    }

    function _recordOutflowAndCircuitCheck(bytes32 assetId, uint256 amount) internal {
        StablecoinConfig storage cfg = stablecoins[assetId];

        // --- epoch tx-volume check ---
        {
            EpochUsage storage usage = epochUsage[assetId];
            uint64 epochId = uint64(block.timestamp / EPOCH_SECONDS);
            if (usage.epochId != epochId) {
                usage.epochId = epochId;
                usage.mintedAmount = 0;
                usage.txVolume = 0;
            }
            usage.txVolume += amount;
            if (cfg.dailyTxLimit > 0 && usage.txVolume > cfg.dailyTxLimit) {
                _triggerCircuitBreaker(
                    assetId,
                    keccak256("DAILY_TX_LIMIT_BREACH"),
                    usage.txVolume,
                    cfg.dailyTxLimit
                );
                return;
            }
        }

        // --- ring-buffer updates ---
        uint256 hourFlow;
        uint256 dayFlow;
        {
            uint256 hourBucket = block.timestamp / HOUR_SECONDS;
            uint256 dayBucket = block.timestamp / EPOCH_SECONDS;
            uint256 hourSlot = hourBucket % HOURLY_OUTFLOW_RING_SLOTS;
            uint256 daySlot = dayBucket % DAILY_OUTFLOW_RING_SLOTS;

            if (hourlyOutflowBucketTag[assetId][hourSlot] != hourBucket) {
                hourlyOutflowBucketTag[assetId][hourSlot] = hourBucket;
                hourlyOutflow[assetId][hourSlot] = 0;
            }
            if (dailyOutflowBucketTag[assetId][daySlot] != dayBucket) {
                dailyOutflowBucketTag[assetId][daySlot] = dayBucket;
                dailyOutflow[assetId][daySlot] = 0;
            }

            hourFlow = hourlyOutflow[assetId][hourSlot] + amount;
            dayFlow = dailyOutflow[assetId][daySlot] + amount;
            hourlyOutflow[assetId][hourSlot] = hourFlow;
            dailyOutflow[assetId][daySlot] = dayFlow;
        }

        // --- velocity breach checks ---
        _checkVelocityBreaches(assetId, cfg, hourFlow, dayFlow);
    }

    function _checkVelocityBreaches(
        bytes32 assetId,
        StablecoinConfig storage cfg,
        uint256 hourFlow,
        uint256 dayFlow
    ) private {
        uint8 tokenDecimals = IERC20Metadata(cfg.token).decimals();
        uint256 supply18 = _normalizeTo18(IERC20Metadata(cfg.token).totalSupply(), tokenDecimals);
        if (supply18 == 0) return;

        uint256 hourFlow18 = _normalizeTo18(hourFlow, tokenDecimals);
        if (
            cfg.hourlyOutflowBps > 0 &&
            hourFlow18 * BPS_DENOMINATOR > supply18 * cfg.hourlyOutflowBps
        ) {
            _triggerCircuitBreaker(
                assetId,
                keccak256("HOURLY_VELOCITY_BREACH"),
                hourFlow18 * BPS_DENOMINATOR,
                supply18 * cfg.hourlyOutflowBps
            );
            return;
        }

        uint256 dayFlow18 = _normalizeTo18(dayFlow, tokenDecimals);
        if (
            cfg.dailyOutflowBps > 0 &&
            dayFlow18 * BPS_DENOMINATOR > supply18 * cfg.dailyOutflowBps
        ) {
            _triggerCircuitBreaker(
                assetId,
                keccak256("DAILY_VELOCITY_BREACH"),
                dayFlow18 * BPS_DENOMINATOR,
                supply18 * cfg.dailyOutflowBps
            );
        }
    }

    function _triggerCircuitBreaker(
        bytes32 assetId,
        bytes32 reasonCode,
        uint256 observed,
        uint256 threshold
    ) internal {
        stablecoins[assetId].mintPaused = true;
        if (!paused()) {
            _pause();
        }
        emit CircuitBreakerTriggered(assetId, reasonCode, observed, threshold);
    }

    function _normalizeTo18(uint256 amount, uint8 decimals)
        internal
        pure
        returns (uint256)
    {
        if (decimals == 18) return amount;
        if (decimals < 18) return amount * (10 ** (18 - decimals));
        return amount / (10 ** (decimals - 18));
    }

    function _domainSeparatorV4() internal view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    EIP712_DOMAIN_TYPEHASH,
                    EIP712_NAME_HASH,
                    EIP712_VERSION_HASH,
                    block.chainid,
                    address(this)
                )
            );
    }

    function _toTypedDataHash(bytes32 structHash) internal view returns (bytes32) {
        return
            keccak256(
                abi.encodePacked("\x19\x01", _domainSeparatorV4(), structHash)
            );
    }

    function _recoverSigner(bytes32 signedDigest, bytes calldata signature)
        internal
        pure
        returns (address)
    {
        if (signature.length != 65) revert InvalidSignature();

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 0x20))
            v := byte(0, calldataload(add(signature.offset, 0x40)))
        }

        if (v != 27 && v != 28) revert InvalidSignature();
        if (uint256(s) > SECP256K1N_HALF) revert InvalidSignature();

        address signer = ecrecover(signedDigest, v, r, s);
        if (signer == address(0)) revert InvalidSignature();
        return signer;
    }

    function _verifyMerkleProof(
        bytes32 leaf,
        bytes32[] calldata proof,
        bytes32 root
    ) internal pure returns (bool) {
        bytes32 computed = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 sibling = proof[i];
            if (computed <= sibling) {
                computed = keccak256(abi.encodePacked(computed, sibling));
            } else {
                computed = keccak256(abi.encodePacked(sibling, computed));
            }
        }
        return computed == root;
    }

    function _authorizeUpgrade(address)
        internal
        override
        onlyRole(UPGRADER_ROLE)
    {}

    // =========================================================================
    // CHAINLINK AUTOMATION - AUTONOMOUS PoR MONITORING (H-09 hardening)
    // =========================================================================

    /**
     * @notice Chainlink Automation: check if any monitored asset has stale or breached PoR.
     * @dev Called off-chain by Chainlink Keepers. The checkData should be
     *      abi.encode(bytes32[] memory assetIds) of asset IDs to check.
     * @param checkData ABI-encoded array of bytes32 assetIds to monitor
     * @return upkeepNeeded Whether any asset needs reserve intervention
     * @return performData ABI-encoded list of assetIds that are breached
     */
    function checkUpkeep(bytes calldata checkData)
        external
        view
        returns (bool upkeepNeeded, bytes memory performData)
    {
        bytes32[] memory assetIds = abi.decode(checkData, (bytes32[]));
        bytes32[] memory breached = new bytes32[](assetIds.length);
        uint256 count = 0;

        for (uint256 i = 0; i < assetIds.length; i++) {
            StablecoinConfig storage cfg = stablecoins[assetIds[i]];
            if (!cfg.enabled || cfg.proofOfReserveFeed == address(0)) continue;

            (
                ,
                int256 reserveAnswer,
                ,
                uint256 updatedAt,
            ) = IAggregatorV3(cfg.proofOfReserveFeed).latestRoundData();

            if (reserveAnswer <= 0) {
                breached[count++] = assetIds[i];
                continue;
            }

            bool stale = cfg.porHeartbeatSeconds > 0 &&
                block.timestamp > updatedAt + cfg.porHeartbeatSeconds;

            if (stale) {
                breached[count++] = assetIds[i];
                continue;
            }

            uint8 feedDecimals = IAggregatorV3(cfg.proofOfReserveFeed).decimals();
            uint8 tokenDecimals = IERC20Metadata(cfg.token).decimals();
            uint256 reserve18 = _normalizeTo18(uint256(reserveAnswer), feedDecimals);
            uint256 liabilities18 = _normalizeTo18(
                IERC20Metadata(cfg.token).totalSupply(), tokenDecimals
            );

            if (liabilities18 > reserve18 && liabilities18 > 0) {
                uint256 devBps = ((liabilities18 - reserve18) * BPS_DENOMINATOR) / liabilities18;
                if (devBps > cfg.porDeviationBps) {
                    breached[count++] = assetIds[i];
                }
            }
        }

        if (count > 0) {
            // Trim array to actual size
            bytes32[] memory result = new bytes32[](count);
            for (uint256 j = 0; j < count; j++) {
                result[j] = breached[j];
            }
            return (true, abi.encode(result));
        }

        return (false, bytes(""));
    }

    /**
     * @notice Chainlink Automation: pause breached assets and trigger circuit breakers.
     * @dev Called on-chain by Chainlink Keepers when checkUpkeep returns true.
     * @param performData ABI-encoded bytes32[] of breached assetIds
     */
    function performUpkeep(bytes calldata performData) external {
        bytes32[] memory breachedIds = abi.decode(performData, (bytes32[]));

        for (uint256 i = 0; i < breachedIds.length; i++) {
            StablecoinConfig storage cfg = stablecoins[breachedIds[i]];
            if (!cfg.enabled || cfg.mintPaused) continue;

            // Re-verify on-chain (defense against stale performData)
            _monitorReserve(breachedIds[i], cfg, 0);

            emit AutomatedReserveCheckPerformed(
                breachedIds[i],
                block.timestamp,
                cfg.mintPaused
            );
        }

        lastAutomatedCheckTimestamp = block.timestamp;
    }

    // Storage gap for future upgrades without storage layout collisions.
    uint256[50] private __gap;
}
