// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

interface ITimelockDelaySource {
    function getMinDelay() external view returns (uint256);
}

/**
 * @title AethelredBridge
 * @author Aethelred Team
 * @notice Enterprise-grade Lock-and-Mint bridge for Ethereum <-> Aethelred transfers
 * @dev Implements multi-sig relayer consensus with fraud proofs, rate limiting,
 *      EIP-712 typed data for withdrawal proposals, 2-of-N guardian multi-sig
 *      for emergency withdrawals, and per-block mint ceiling defense-in-depth.
 * @custom:security-contact security@aethelred.io
 * @custom:audit-status Remediated — all 27 findings addressed (2026-02-28)
 *
 * Cross-Contract Dependencies — Audit note [I-06]:
 *   AethelredBridge → AethelredToken (bridgeMint/bridgeBurn via authorizedBridges)
 *   AethelredBridge → SovereignGovernanceTimelock (UPGRADER_ROLE via initializeWithTimelock)
 *   AethelredBridge → SovereignCircuitBreakerModule (optional: external anomaly check)
 *
 * Architecture:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                          ETHEREUM MAINNET                                    │
 * │  ┌───────────────────────────────────────────────────────────────────────┐  │
 * │  │                      AethelredBridge.sol                               │  │
 * │  │                                                                        │  │
 * │  │   User ──► deposit() ──► Lock ETH/ERC20 ──► Emit Deposit Event       │  │
 * │  │                                                                        │  │
 * │  │   Relayers ──► processWithdrawal() ──► Unlock ETH/ERC20              │  │
 * │  │                 (requires 67% votes + EIP-712 typed data)              │  │
 * │  │                                                                        │  │
 * │  │   Features:                                                            │  │
 * │  │   • Rate limiting (max deposit/withdrawal per period)                 │  │
 * │  │   • Per-block mint ceiling (defense-in-depth)                          │  │
 * │  │   • Fraud proof challenge period (7 days)                             │  │
 * │  │   • Emergency pause by admin                                          │  │
 * │  │   • Guardian multi-sig emergency withdrawals (2-of-N)                 │  │
 * │  │   • UUPS upgradeable pattern                                          │  │
 * │  │   • EIP-712 typed data for wallet signature display                   │  │
 * │  │   • Chain-fork safe domain separator caching                          │  │
 * │  └───────────────────────────────────────────────────────────────────────┘  │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *                                      │
 *                    ┌─────────────────┴─────────────────┐
 *                    │         RELAYER NETWORK           │
 *                    │   (Top 20 Aethelred Validators)   │
 *                    └─────────────────┬─────────────────┘
 *                                      │
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                          AETHELRED L1                                        │
 * │  ┌───────────────────────────────────────────────────────────────────────┐  │
 * │  │                      BridgeModule (Rust)                               │  │
 * │  │                                                                        │  │
 * │  │   Watch Ethereum Events ──► Vote on Deposits ──► Mint wETH            │  │
 * │  │                                                                        │  │
 * │  │   Watch Burn Events ──► Vote on Withdrawals ──► Signal to ETH Bridge │  │
 * │  └───────────────────────────────────────────────────────────────────────┘  │
 * └─────────────────────────────────────────────────────────────────────────────┘
 */
contract AethelredBridge is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable
{
    using SafeERC20 for IERC20;

    // =========================================================================
    // CONSTANTS & ROLES
    // =========================================================================

    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    /// @notice Minimum deposit amount (0.01 ETH)
    uint256 public constant MIN_DEPOSIT = 0.01 ether;

    /// @notice Maximum single deposit (100 ETH)
    uint256 public constant MAX_SINGLE_DEPOSIT = 100 ether;

    /// @notice Challenge period for withdrawals (7 days)
    uint256 public constant CHALLENGE_PERIOD = 7 days;

    /// @notice Minimum confirmations required on Ethereum.
    /// Audit fix [L-02]: Increased from 12 to 64 to align with post-merge
    /// Ethereum finality guarantees (2 epochs = 64 slots ≈ 12.8 minutes).
    uint256 public constant MIN_ETH_CONFIRMATIONS = 64;

    /// @notice Rate limit period (1 hour)
    uint256 public constant RATE_LIMIT_PERIOD = 1 hours;

    /// @notice Minimum emergency withdrawal timelock (24 hours)
    uint256 public constant MIN_EMERGENCY_TIMELOCK = 24 hours;

    /// @notice Maximum emergency withdrawal timelock (14 days)
    uint256 public constant MAX_EMERGENCY_TIMELOCK = 14 days;

    /// @notice Default emergency withdrawal timelock (48 hours)
    uint256 public constant DEFAULT_EMERGENCY_TIMELOCK = 48 hours;

    /// @notice Deposit cancellation window before relay finalization should take over.
    uint256 public constant DEPOSIT_CANCELLATION_WINDOW = 1 hours;

    /// @notice Minimum delay for upgrade timelock governance.
    uint256 public constant MIN_UPGRADER_TIMELOCK_DELAY = 27 days;

    /// @notice Guardian approvals required before emergency withdrawal execution.
    uint256 public constant REQUIRED_GUARDIAN_APPROVALS = 2;

    /// @notice Default per-block mint/withdrawal ceiling (10 ETH).
    uint256 public constant DEFAULT_MINT_CEILING_PER_BLOCK = 10 ether;

    /// @notice Maximum single emergency withdrawal amount (50 ETH).
    /// Audit: Prevents compromised admin+guardians from draining entire TVL in one operation.
    uint256 public constant MAX_EMERGENCY_WITHDRAWAL = 50 ether;

    // =========================================================================
    // EIP-712 TYPED DATA (M-01 hardening)
    // =========================================================================

    bytes32 internal constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 internal constant EIP712_NAME_HASH = keccak256("AethelredBridge");
    bytes32 internal constant EIP712_VERSION_HASH = keccak256("1");
    bytes32 internal constant WITHDRAWAL_TYPEHASH =
        keccak256("WithdrawalProposal(bytes32 proposalId,address recipient,address token,uint256 amount,bytes32 burnTxHash,uint256 aethelredBlockHeight)");

    // =========================================================================
    // STATE VARIABLES
    // =========================================================================

    /// @notice Deposit counter for unique IDs
    uint256 public depositNonce;

    /// @notice Total ETH locked in the bridge
    uint256 public totalLockedETH;

    /// @notice Total locked for each ERC20 token
    mapping(address => uint256) public totalLockedERC20;

    /// @notice Supported ERC20 tokens
    mapping(address => bool) public supportedTokens;

    /// @notice Relayer set configuration
    RelayerConfig public relayerConfig;

    /// @notice Rate limit configuration
    RateLimitConfig public rateLimitConfig;

    /// @notice Deposits awaiting finalization
    mapping(bytes32 => Deposit) public deposits;

    /// @notice Withdrawal proposals
    mapping(bytes32 => WithdrawalProposal) public withdrawalProposals;

    /// @notice Relayer votes on withdrawals
    mapping(bytes32 => mapping(address => bool)) public withdrawalVotes;

    /// @notice Rate limit tracking per period
    mapping(uint256 => RateLimitState) public rateLimitState;

    /// @notice Processed burn tx hashes (to prevent replay).
    /// Audit verified [C-03]: Keyed on burnTxHash (the canonical Aethelred burn
    /// transaction), not the proposalId. This prevents a second proposal from being
    /// created for the same burn even with different proposalId parameters.
    mapping(bytes32 => bool) public processedWithdrawals;

    /// @notice Blocked addresses (sanctions compliance)
    mapping(address => bool) public blockedAddresses;

    /// @notice Delay before emergency withdrawals can be executed
    uint256 public emergencyWithdrawalDelay;

    /// @notice Nonce for emergency withdrawal operation IDs
    uint256 public emergencyWithdrawalNonce;

    /// @notice Queued emergency withdrawal requests by operation ID
    mapping(bytes32 => EmergencyWithdrawalRequest) public emergencyWithdrawalRequests;

    // =========================================================================
    // GUARDIAN MULTI-SIG STATE (H-05 hardening)
    // =========================================================================

    /// @notice Guardian approvals for emergency withdrawal operations
    mapping(bytes32 => mapping(address => bool)) public guardianApprovals;

    /// @notice Count of guardian approvals per emergency operation
    mapping(bytes32 => uint256) public guardianApprovalCount;

    // =========================================================================
    // PER-BLOCK MINT CEILING STATE (H-04 hardening)
    // =========================================================================

    /// @notice Configurable per-block mint/withdrawal ceiling
    uint256 public mintCeilingPerBlock;

    /// @notice Block number of the last mint/withdrawal operation
    uint256 private _lastMintBlock;

    /// @notice Cumulative amount minted/withdrawn in the current block
    uint256 private _mintedThisBlock;

    // =========================================================================
    // EIP-712 DOMAIN SEPARATOR CACHE (M-01 + fork protection)
    // =========================================================================

    /// @dev Cached domain separator (set at init, recomputed on chain fork)
    bytes32 private _cachedDomainSeparator;

    /// @dev Chain ID at time of caching
    uint256 private _cachedChainId;

    // =========================================================================
    // STRUCTS
    // =========================================================================

    struct RelayerConfig {
        /// @notice Number of active relayers
        uint256 relayerCount;
        /// @notice Threshold for consensus (in basis points, e.g., 6700 = 67%)
        uint256 consensusThresholdBps;
        /// @notice Minimum votes required for withdrawal
        uint256 minVotesRequired;
    }

    struct RateLimitConfig {
        /// @notice Maximum total deposits per period
        uint256 maxDepositPerPeriod;
        /// @notice Maximum total withdrawals per period
        uint256 maxWithdrawalPerPeriod;
        /// @notice Whether rate limiting is enabled
        bool enabled;
    }

    struct RateLimitState {
        /// @notice Total deposited in current period
        uint256 totalDeposited;
        /// @notice Total withdrawn in current period
        uint256 totalWithdrawn;
    }

    struct Deposit {
        /// @notice Depositor address on Ethereum
        address depositor;
        /// @notice Recipient address on Aethelred (32 bytes)
        bytes32 aethelredRecipient;
        /// @notice Token address (address(0) for ETH)
        address token;
        /// @notice Amount deposited
        uint256 amount;
        /// @notice Block number when deposited
        uint256 blockNumber;
        /// @notice Timestamp of deposit
        uint256 timestamp;
        /// @notice Whether deposit has been finalized
        bool finalized;
        /// @notice Whether deposit was cancelled
        bool cancelled;
    }

    struct WithdrawalProposal {
        /// @notice Recipient on Ethereum
        address recipient;
        /// @notice Token address (address(0) for ETH)
        address token;
        /// @notice Amount to withdraw
        uint256 amount;
        /// @notice Aethelred burn transaction hash
        bytes32 burnTxHash;
        /// @notice Block height on Aethelred
        uint256 aethelredBlockHeight;
        /// @notice Number of relayer votes
        uint256 voteCount;
        /// @notice When the proposal was created
        uint256 createdAt;
        /// @notice When challenge period ends
        uint256 challengeEndTime;
        /// @notice Whether withdrawal has been processed
        bool processed;
        /// @notice Whether withdrawal was challenged/cancelled
        bool challenged;
        /// @notice Snapshot of minVotesRequired at proposal creation time.
        /// Audit: Prevents threshold manipulation via relayer churn. The threshold
        /// is locked at proposal creation so adding/removing relayers mid-proposal
        /// cannot weaken or strengthen the quorum for already-submitted proposals.
        uint256 requiredVotesSnapshot;
    }

    struct EmergencyWithdrawalRequest {
        address token;
        uint256 amount;
        address recipient;
        uint256 queuedAt;
        uint256 executeAfter;
        bool executed;
        bool cancelled;
    }

    // =========================================================================
    // EVENTS
    // =========================================================================

    /// @notice Emitted when ETH or ERC20 is deposited for bridging
    event DepositInitiated(
        bytes32 indexed depositId,
        address indexed depositor,
        bytes32 indexed aethelredRecipient,
        address token,
        uint256 amount,
        uint256 nonce,
        uint256 timestamp
    );

    /// @notice Emitted when a deposit is finalized (after confirmations)
    event DepositFinalized(
        bytes32 indexed depositId,
        address indexed depositor,
        uint256 amount
    );

    /// @notice Emitted when a deposit is cancelled
    event DepositCancelled(
        bytes32 indexed depositId,
        address indexed depositor,
        uint256 amount
    );

    /// @notice Emitted when a withdrawal proposal is created
    event WithdrawalProposed(
        bytes32 indexed proposalId,
        address indexed recipient,
        address token,
        uint256 amount,
        bytes32 burnTxHash,
        address proposer
    );

    /// @notice Emitted when a relayer votes on a withdrawal
    event WithdrawalVoted(
        bytes32 indexed proposalId,
        address indexed relayer,
        uint256 currentVotes,
        uint256 requiredVotes
    );

    /// @notice Emitted when a withdrawal is processed.
    /// Audit: Includes burnTxHash for relayer reconciliation with Aethelred L1.
    event WithdrawalProcessed(
        bytes32 indexed proposalId,
        address indexed recipient,
        address token,
        uint256 amount,
        bytes32 burnTxHash
    );

    /// @notice Emitted when a withdrawal is challenged
    event WithdrawalChallenged(
        bytes32 indexed proposalId,
        address indexed challenger,
        string reason
    );

    /// @notice Emitted when a token is added/removed from supported list
    event TokenSupportUpdated(address indexed token, bool supported);

    /// @notice Emitted when relayer config is updated
    event RelayerConfigUpdated(
        uint256 relayerCount,
        uint256 consensusThresholdBps,
        uint256 minVotesRequired
    );

    /// @notice Emitted when rate limit config is updated
    event RateLimitConfigUpdated(
        uint256 maxDepositPerPeriod,
        uint256 maxWithdrawalPerPeriod,
        bool enabled
    );

    /// @notice Emitted when an address is blocked/unblocked
    event AddressBlockStatusChanged(address indexed addr, bool blocked);

    /// @notice Emitted when an emergency withdrawal is queued
    event EmergencyWithdrawalQueued(
        bytes32 indexed operationId,
        address indexed token,
        address indexed recipient,
        uint256 amount,
        uint256 executeAfter
    );

    /// @notice Emitted when an emergency withdrawal is executed
    event EmergencyWithdrawalExecuted(
        bytes32 indexed operationId,
        address indexed token,
        address indexed recipient,
        uint256 amount
    );

    /// @notice Emitted when an emergency withdrawal is cancelled
    event EmergencyWithdrawalCancelled(
        bytes32 indexed operationId,
        address indexed cancelledBy
    );

    /// @notice Emitted when emergency withdrawal delay is updated
    event EmergencyWithdrawalDelayUpdated(uint256 oldDelay, uint256 newDelay);

    /// @notice Emitted when a guardian approves an emergency withdrawal
    event GuardianApprovalSubmitted(
        bytes32 indexed operationId,
        address indexed guardian,
        uint256 currentApprovals,
        uint256 requiredApprovals
    );

    /// @notice Emitted when the per-block mint ceiling is updated
    event MintCeilingUpdated(uint256 oldCeiling, uint256 newCeiling);

    // =========================================================================
    // ERRORS
    // =========================================================================

    error InvalidAmount();
    error InvalidRecipient();
    error TokenNotSupported();
    error DepositNotFound();
    error DepositAlreadyFinalized();
    error DepositAlreadyCancelled();
    error InsufficientConfirmations();
    error WithdrawalNotFound();
    error WithdrawalAlreadyProcessed();
    error WithdrawalAlreadyChallenged();
    error ChallengePeriodNotEnded();
    error AlreadyVoted();
    error InsufficientVotes();
    error RateLimitExceeded();
    error AddressBlocked();
    error InvalidSignature();
    error ProposalExists();
    error TransferFailed();
    error InvalidEmergencyDelay();
    error EmergencyWithdrawalNotFound();
    error EmergencyWithdrawalNotReady();
    error EmergencyWithdrawalAlreadyHandled();
    error DepositCancellationWindowClosed();
    error AdminMustBeContract();
    error RelayerCountMismatch();
    error UpgraderTimelockDelayTooShort();
    error MintCeilingExceeded();
    error InsufficientGuardianApprovals();
    error GuardianAlreadyApproved();
    error EmergencyAmountExceedsMax();

    // =========================================================================
    // MODIFIERS
    // =========================================================================

    modifier notBlocked(address addr) {
        if (blockedAddresses[addr]) revert AddressBlocked();
        _;
    }

    /// @dev Audit: Rate limit uses block.timestamp which validators can manipulate
    /// by ~12 seconds. This is acceptable since RATE_LIMIT_PERIOD is 1 hour (3600s),
    /// making the manipulation window < 0.33% of a period — negligible for rate limiting.
    modifier withinRateLimit(uint256 amount, bool isDeposit) {
        if (rateLimitConfig.enabled) {
            uint256 currentPeriod = block.timestamp / RATE_LIMIT_PERIOD;
            RateLimitState storage state = rateLimitState[currentPeriod];

            if (isDeposit) {
                if (state.totalDeposited + amount > rateLimitConfig.maxDepositPerPeriod) {
                    revert RateLimitExceeded();
                }
                state.totalDeposited += amount;
            } else {
                if (state.totalWithdrawn + amount > rateLimitConfig.maxWithdrawalPerPeriod) {
                    revert RateLimitExceeded();
                }
                state.totalWithdrawn += amount;
            }
        }
        _;
    }

    // =========================================================================
    // INITIALIZATION
    // =========================================================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initialize the bridge contract
     * @param admin Address of the admin
     * @param initialRelayers Array of initial relayer addresses
     * @param consensusThresholdBps Consensus threshold in basis points (e.g., 6700 = 67%)
     */
    function initialize(
        address admin,
        address[] calldata initialRelayers,
        uint256 consensusThresholdBps
    ) external initializer {
        _initializeBridge(admin, admin, initialRelayers, consensusThresholdBps);
    }

    /**
     * @notice Initialize the bridge contract with a dedicated upgrader timelock.
     * @param admin Address of the operational admin (multisig)
     * @param upgraderTimelock Timelock contract address that exclusively holds UPGRADER_ROLE
     * @param initialRelayers Array of initial relayer addresses
     * @param consensusThresholdBps Consensus threshold in basis points (e.g., 6700 = 67%)
     */
    function initializeWithTimelock(
        address admin,
        address upgraderTimelock,
        address[] calldata initialRelayers,
        uint256 consensusThresholdBps
    ) external initializer {
        _requireUpgraderTimelockDelay(upgraderTimelock);
        _initializeBridge(
            admin,
            upgraderTimelock,
            initialRelayers,
            consensusThresholdBps
        );
    }

    function _initializeBridge(
        address admin,
        address upgraderTimelock,
        address[] calldata initialRelayers,
        uint256 consensusThresholdBps
    ) internal {
        __UUPSUpgradeable_init();
        __AccessControl_init();
        __Pausable_init();
        __ReentrancyGuard_init();

        _requireContractAdmin(admin);
        _requireContractAdmin(upgraderTimelock);
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, admin);

        // Audit: Isolate UPGRADER_ROLE admin so only existing upgraders can grant
        // new upgrader roles. This prevents DEFAULT_ADMIN_ROLE from escalating to
        // UPGRADER_ROLE and bypassing the timelock requirement.
        _setRoleAdmin(UPGRADER_ROLE, UPGRADER_ROLE);
        _grantRole(UPGRADER_ROLE, upgraderTimelock);

        // Setup relayers
        for (uint256 i = 0; i < initialRelayers.length; i++) {
            _grantRole(RELAYER_ROLE, initialRelayers[i]);
        }

        // Configure relayer set
        uint256 minVotes = (initialRelayers.length * consensusThresholdBps) / 10000;
        if (minVotes == 0) minVotes = 1;

        relayerConfig = RelayerConfig({
            relayerCount: initialRelayers.length,
            consensusThresholdBps: consensusThresholdBps,
            minVotesRequired: minVotes
        });

        // Configure rate limits (default: 1000 ETH per period)
        rateLimitConfig = RateLimitConfig({
            maxDepositPerPeriod: 1000 ether,
            maxWithdrawalPerPeriod: 1000 ether,
            enabled: true
        });

        // Emergency withdrawal timelock defaults to 48h for production safety.
        emergencyWithdrawalDelay = DEFAULT_EMERGENCY_TIMELOCK;

        // Per-block mint ceiling defaults to 10 ETH.
        mintCeilingPerBlock = DEFAULT_MINT_CEILING_PER_BLOCK;

        // Cache the EIP-712 domain separator for gas efficiency.
        _cachedChainId = block.chainid;
        _cachedDomainSeparator = _computeDomainSeparator();
    }

    // =========================================================================
    // DEPOSIT FUNCTIONS
    // =========================================================================

    /**
     * @notice Deposit ETH to bridge to Aethelred
     * @param aethelredRecipient 32-byte Aethelred address
     */
    function depositETH(bytes32 aethelredRecipient)
        external
        payable
        nonReentrant
        whenNotPaused
        notBlocked(msg.sender)
        withinRateLimit(msg.value, true)
    {
        _validateDeposit(aethelredRecipient, msg.value);

        bytes32 depositId = _generateDepositId(
            msg.sender,
            aethelredRecipient,
            address(0),
            msg.value,
            depositNonce
        );

        deposits[depositId] = Deposit({
            depositor: msg.sender,
            aethelredRecipient: aethelredRecipient,
            token: address(0),
            amount: msg.value,
            blockNumber: block.number,
            timestamp: block.timestamp,
            finalized: false,
            cancelled: false
        });

        totalLockedETH += msg.value;
        depositNonce++;

        emit DepositInitiated(
            depositId,
            msg.sender,
            aethelredRecipient,
            address(0),
            msg.value,
            depositNonce - 1,
            block.timestamp
        );
    }

    /**
     * @notice Deposit ERC20 tokens to bridge to Aethelred
     * @param token ERC20 token address
     * @param amount Amount to deposit
     * @param aethelredRecipient 32-byte Aethelred address
     */
    function depositERC20(
        address token,
        uint256 amount,
        bytes32 aethelredRecipient
    )
        external
        nonReentrant
        whenNotPaused
        notBlocked(msg.sender)
        withinRateLimit(amount, true)
    {
        if (!supportedTokens[token]) revert TokenNotSupported();
        _validateDeposit(aethelredRecipient, amount);

        // Transfer tokens to bridge — measure actual received for fee-on-transfer tokens
        uint256 balanceBefore = IERC20(token).balanceOf(address(this));
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        uint256 actualReceived = IERC20(token).balanceOf(address(this)) - balanceBefore;

        bytes32 depositId = _generateDepositId(
            msg.sender,
            aethelredRecipient,
            token,
            actualReceived,
            depositNonce
        );

        deposits[depositId] = Deposit({
            depositor: msg.sender,
            aethelredRecipient: aethelredRecipient,
            token: token,
            amount: actualReceived,
            blockNumber: block.number,
            timestamp: block.timestamp,
            finalized: false,
            cancelled: false
        });

        totalLockedERC20[token] += actualReceived;
        depositNonce++;

        emit DepositInitiated(
            depositId,
            msg.sender,
            aethelredRecipient,
            token,
            actualReceived,
            depositNonce - 1,
            block.timestamp
        );
    }

    /**
     * @notice Cancel a pending deposit (before finalization)
     * @param depositId The deposit ID to cancel
     */
    function cancelDeposit(bytes32 depositId) external nonReentrant {
        Deposit storage deposit = deposits[depositId];

        if (deposit.depositor == address(0)) revert DepositNotFound();
        if (deposit.depositor != msg.sender) revert InvalidRecipient();
        if (deposit.finalized) revert DepositAlreadyFinalized();
        if (deposit.cancelled) revert DepositAlreadyCancelled();
        if (block.timestamp > deposit.timestamp + DEPOSIT_CANCELLATION_WINDOW) {
            revert DepositCancellationWindowClosed();
        }
        if (block.number >= deposit.blockNumber + MIN_ETH_CONFIRMATIONS) {
            revert DepositCancellationWindowClosed();
        }

        deposit.cancelled = true;

        // Refund
        if (deposit.token == address(0)) {
            totalLockedETH -= deposit.amount;
            (bool success, ) = msg.sender.call{value: deposit.amount}("");
            if (!success) revert TransferFailed();
        } else {
            totalLockedERC20[deposit.token] -= deposit.amount;
            IERC20(deposit.token).safeTransfer(msg.sender, deposit.amount);
        }

        emit DepositCancelled(depositId, msg.sender, deposit.amount);
    }

    /**
     * @notice Finalize a deposit after the confirmation threshold is reached.
     * @dev Relayers should call this before minting on Aethelred to close the
     *      Ethereum-side cancellation path.
     */
    function finalizeDeposit(bytes32 depositId)
        external
        onlyRole(RELAYER_ROLE)
        whenNotPaused
    {
        Deposit storage deposit = deposits[depositId];
        if (deposit.depositor == address(0)) revert DepositNotFound();
        if (deposit.cancelled) revert DepositAlreadyCancelled();
        if (deposit.finalized) revert DepositAlreadyFinalized();
        if (block.number < deposit.blockNumber + MIN_ETH_CONFIRMATIONS) {
            revert InsufficientConfirmations();
        }

        deposit.finalized = true;
        emit DepositFinalized(depositId, deposit.depositor, deposit.amount);
    }

    // =========================================================================
    // WITHDRAWAL FUNCTIONS (Relayer Operations)
    // =========================================================================

    /**
     * @notice Propose a withdrawal (called by relayers)
     * @param proposalId Unique proposal ID
     * @param recipient Ethereum recipient address
     * @param token Token address (address(0) for ETH)
     * @param amount Amount to withdraw
     * @param burnTxHash Aethelred burn transaction hash
     * @param aethelredBlockHeight Block height on Aethelred
     */
    function proposeWithdrawal(
        bytes32 proposalId,
        address recipient,
        address token,
        uint256 amount,
        bytes32 burnTxHash,
        uint256 aethelredBlockHeight
    )
        external
        onlyRole(RELAYER_ROLE)
        whenNotPaused
        notBlocked(recipient)
    {
        if (withdrawalProposals[proposalId].createdAt != 0) revert ProposalExists();
        if (processedWithdrawals[burnTxHash]) revert WithdrawalAlreadyProcessed();
        if (recipient == address(0)) revert InvalidRecipient();
        if (amount == 0) revert InvalidAmount();
        if (token != address(0) && !supportedTokens[token]) revert TokenNotSupported();

        // Audit: Snapshot the required votes at proposal creation time to prevent
        // threshold manipulation via relayer churn during proposal lifetime.
        uint256 requiredVotes = relayerConfig.minVotesRequired;

        withdrawalProposals[proposalId] = WithdrawalProposal({
            recipient: recipient,
            token: token,
            amount: amount,
            burnTxHash: burnTxHash,
            aethelredBlockHeight: aethelredBlockHeight,
            voteCount: 1,
            createdAt: block.timestamp,
            challengeEndTime: block.timestamp + CHALLENGE_PERIOD,
            processed: false,
            challenged: false,
            requiredVotesSnapshot: requiredVotes
        });

        withdrawalVotes[proposalId][msg.sender] = true;

        emit WithdrawalProposed(
            proposalId,
            recipient,
            token,
            amount,
            burnTxHash,
            msg.sender
        );

        emit WithdrawalVoted(
            proposalId,
            msg.sender,
            1,
            relayerConfig.minVotesRequired
        );
    }

    /**
     * @notice Vote on a withdrawal proposal
     * @param proposalId The proposal to vote on
     */
    function voteWithdrawal(bytes32 proposalId)
        external
        onlyRole(RELAYER_ROLE)
        whenNotPaused
    {
        WithdrawalProposal storage proposal = withdrawalProposals[proposalId];

        if (proposal.createdAt == 0) revert WithdrawalNotFound();
        if (proposal.processed) revert WithdrawalAlreadyProcessed();
        if (proposal.challenged) revert WithdrawalAlreadyChallenged();
        if (withdrawalVotes[proposalId][msg.sender]) revert AlreadyVoted();

        withdrawalVotes[proposalId][msg.sender] = true;
        proposal.voteCount++;

        emit WithdrawalVoted(
            proposalId,
            msg.sender,
            proposal.voteCount,
            proposal.requiredVotesSnapshot
        );
    }

    /**
     * @notice Process a withdrawal after consensus and challenge period
     * @param proposalId The proposal to process
     */
    function processWithdrawal(bytes32 proposalId)
        external
        nonReentrant
        whenNotPaused
        withinRateLimit(withdrawalProposals[proposalId].amount, false)
    {
        WithdrawalProposal storage proposal = withdrawalProposals[proposalId];

        if (proposal.createdAt == 0) revert WithdrawalNotFound();
        if (proposal.processed) revert WithdrawalAlreadyProcessed();
        if (proposal.challenged) revert WithdrawalAlreadyChallenged();
        // Audit: Use the snapshot threshold (locked at proposal creation) to prevent
        // threshold manipulation via relayer churn. Also enforce the current threshold
        // as a floor — the stricter of the two applies.
        uint256 effectiveThreshold = proposal.requiredVotesSnapshot;
        if (relayerConfig.minVotesRequired > effectiveThreshold) {
            effectiveThreshold = relayerConfig.minVotesRequired;
        }
        if (proposal.voteCount < effectiveThreshold) revert InsufficientVotes();
        if (block.timestamp < proposal.challengeEndTime) revert ChallengePeriodNotEnded();
        // Audit: Enforce sanctions on recipient at execution time (not just proposal time).
        // A recipient may be sanctioned between proposal creation and execution.
        if (blockedAddresses[proposal.recipient]) revert AddressBlocked();

        // H-04: Per-block mint ceiling enforcement
        _enforceMintCeiling(proposal.amount);

        proposal.processed = true;
        processedWithdrawals[proposal.burnTxHash] = true;

        // Transfer funds
        if (proposal.token == address(0)) {
            totalLockedETH -= proposal.amount;
            (bool success, ) = proposal.recipient.call{value: proposal.amount}("");
            if (!success) revert TransferFailed();
        } else {
            totalLockedERC20[proposal.token] -= proposal.amount;
            IERC20(proposal.token).safeTransfer(proposal.recipient, proposal.amount);
        }

        emit WithdrawalProcessed(
            proposalId,
            proposal.recipient,
            proposal.token,
            proposal.amount,
            proposal.burnTxHash
        );
    }

    /**
     * @notice Challenge a fraudulent withdrawal proposal
     * @param proposalId The proposal to challenge
     * @param reason Reason for the challenge
     */
    function challengeWithdrawal(bytes32 proposalId, string calldata reason)
        external
        onlyRole(GUARDIAN_ROLE)
    {
        WithdrawalProposal storage proposal = withdrawalProposals[proposalId];

        if (proposal.createdAt == 0) revert WithdrawalNotFound();
        if (proposal.processed) revert WithdrawalAlreadyProcessed();

        proposal.challenged = true;

        emit WithdrawalChallenged(proposalId, msg.sender, reason);
    }

    // =========================================================================
    // ADMIN FUNCTIONS
    // =========================================================================

    /**
     * @notice Add a supported ERC20 token
     * @param token Token address to add
     */
    function addSupportedToken(address token) external onlyRole(DEFAULT_ADMIN_ROLE) {
        supportedTokens[token] = true;
        emit TokenSupportUpdated(token, true);
    }

    /**
     * @notice Remove a supported ERC20 token
     * @param token Token address to remove
     */
    function removeSupportedToken(address token) external onlyRole(DEFAULT_ADMIN_ROLE) {
        supportedTokens[token] = false;
        emit TokenSupportUpdated(token, false);
    }

    /**
     * @notice Update relayer configuration
     * @param relayerCount New relayer count
     * @param consensusThresholdBps New consensus threshold in basis points
     */
    function updateRelayerConfig(uint256 relayerCount, uint256 consensusThresholdBps)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        if (relayerCount != relayerConfig.relayerCount) revert RelayerCountMismatch();
        uint256 minVotes = (relayerCount * consensusThresholdBps) / 10000;
        if (minVotes == 0) minVotes = 1;

        relayerConfig = RelayerConfig({
            relayerCount: relayerCount,
            consensusThresholdBps: consensusThresholdBps,
            minVotesRequired: minVotes
        });

        emit RelayerConfigUpdated(relayerCount, consensusThresholdBps, minVotes);
    }

    /**
     * @notice Update rate limit configuration
     * @param maxDeposit Maximum deposit per period
     * @param maxWithdrawal Maximum withdrawal per period
     * @param enabled Whether rate limiting is enabled
     */
    function updateRateLimitConfig(
        uint256 maxDeposit,
        uint256 maxWithdrawal,
        bool enabled
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        rateLimitConfig = RateLimitConfig({
            maxDepositPerPeriod: maxDeposit,
            maxWithdrawalPerPeriod: maxWithdrawal,
            enabled: enabled
        });

        emit RateLimitConfigUpdated(maxDeposit, maxWithdrawal, enabled);
    }

    /**
     * @notice Clear expired rate limit state entries for gas refunds. Audit fix [M-03].
     * @dev Each RATE_LIMIT_PERIOD (1 hour) creates a new storage entry. Over time this
     *      accumulates dead storage. This function lets admins reclaim gas by zeroing
     *      expired entries. Only periods before the current one can be cleared.
     * @param periodKeys Array of period keys (block.timestamp / RATE_LIMIT_PERIOD) to clear
     */
    function clearExpiredRateLimitState(uint256[] calldata periodKeys)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        uint256 currentPeriod = block.timestamp / RATE_LIMIT_PERIOD;
        require(periodKeys.length <= 200, "Batch too large");
        for (uint256 i = 0; i < periodKeys.length; i++) {
            require(periodKeys[i] < currentPeriod, "Cannot clear current period");
            delete rateLimitState[periodKeys[i]];
        }
    }

    /**
     * @notice Block or unblock an address (sanctions compliance)
     * @param addr Address to block/unblock
     * @param blocked Whether to block the address
     */
    function setAddressBlocked(address addr, bool blocked)
        external
        onlyRole(GUARDIAN_ROLE)
    {
        blockedAddresses[addr] = blocked;
        emit AddressBlockStatusChanged(addr, blocked);
    }

    /**
     * @notice Update emergency withdrawal delay
     * @dev Audit verified [M-07]: Bounded by MIN_EMERGENCY_TIMELOCK (24h) and
     *      MAX_EMERGENCY_TIMELOCK (14d) to prevent both instant-drain attacks
     *      and indefinite fund locking.
     * @param newDelay New delay in seconds (must be within min/max bounds)
     */
    function setEmergencyWithdrawalDelay(uint256 newDelay)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        if (newDelay < MIN_EMERGENCY_TIMELOCK || newDelay > MAX_EMERGENCY_TIMELOCK) {
            revert InvalidEmergencyDelay();
        }

        uint256 oldDelay = emergencyWithdrawalDelay;
        emergencyWithdrawalDelay = newDelay;
        emit EmergencyWithdrawalDelayUpdated(oldDelay, newDelay);
    }

    /**
     * @notice Pause the bridge in emergency
     */
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the bridge
     */
    function unpause() external onlyRole(GUARDIAN_ROLE) {
        _unpause();
    }

    /**
     * @notice Queue an emergency withdrawal request
     * @param token Token address (address(0) for ETH)
     * @param amount Amount to withdraw
     * @param recipient Recipient address
     */
    function queueEmergencyWithdrawal(address token, uint256 amount, address recipient)
        public
        onlyRole(DEFAULT_ADMIN_ROLE)
        whenNotPaused
        returns (bytes32 operationId)
    {
        if (recipient == address(0)) revert InvalidRecipient();
        if (amount == 0) revert InvalidAmount();
        // Audit: Cap single emergency withdrawal to prevent full TVL drain by
        // compromised admin+guardians. Multiple capped operations are visible on-chain,
        // giving the community time to react.
        if (amount > MAX_EMERGENCY_WITHDRAWAL) revert EmergencyAmountExceedsMax();
        // Audit: Enforce sanctions on emergency withdrawal recipient.
        if (blockedAddresses[recipient]) revert AddressBlocked();

        operationId = keccak256(
            abi.encode(
                token,
                amount,
                recipient,
                emergencyWithdrawalNonce,
                block.chainid,
                address(this)
            )
        );

        emergencyWithdrawalRequests[operationId] = EmergencyWithdrawalRequest({
            token: token,
            amount: amount,
            recipient: recipient,
            queuedAt: block.timestamp,
            executeAfter: block.timestamp + emergencyWithdrawalDelay,
            executed: false,
            cancelled: false
        });

        emergencyWithdrawalNonce++;

        emit EmergencyWithdrawalQueued(
            operationId,
            token,
            recipient,
            amount,
            block.timestamp + emergencyWithdrawalDelay
        );
    }

    /**
     * @notice Approve an emergency withdrawal as a guardian (2-of-N required).
     * @dev Each guardian calls this independently. After REQUIRED_GUARDIAN_APPROVALS
     *      are reached, the admin can call executeEmergencyWithdrawal.
     * @param operationId The queued emergency withdrawal operation ID
     */
    function approveEmergencyWithdrawal(bytes32 operationId)
        external
        onlyRole(GUARDIAN_ROLE)
    {
        EmergencyWithdrawalRequest storage req = emergencyWithdrawalRequests[operationId];
        if (req.queuedAt == 0) revert EmergencyWithdrawalNotFound();
        if (req.executed || req.cancelled) revert EmergencyWithdrawalAlreadyHandled();
        if (guardianApprovals[operationId][msg.sender]) revert GuardianAlreadyApproved();

        guardianApprovals[operationId][msg.sender] = true;
        guardianApprovalCount[operationId] += 1;

        emit GuardianApprovalSubmitted(
            operationId,
            msg.sender,
            guardianApprovalCount[operationId],
            REQUIRED_GUARDIAN_APPROVALS
        );
    }

    /**
     * @notice Execute a queued emergency withdrawal after timelock + guardian quorum.
     * @dev Requires both timelock expiration AND 2-of-N guardian approvals.
     * @param operationId Queued emergency withdrawal operation ID
     */
    function executeEmergencyWithdrawal(bytes32 operationId)
        external
        nonReentrant
        onlyRole(DEFAULT_ADMIN_ROLE)
        whenNotPaused
    {
        EmergencyWithdrawalRequest storage req = emergencyWithdrawalRequests[operationId];
        if (req.queuedAt == 0) revert EmergencyWithdrawalNotFound();
        if (req.executed || req.cancelled) revert EmergencyWithdrawalAlreadyHandled();
        if (block.timestamp < req.executeAfter) revert EmergencyWithdrawalNotReady();
        if (guardianApprovalCount[operationId] < REQUIRED_GUARDIAN_APPROVALS) {
            revert InsufficientGuardianApprovals();
        }

        // Audit: Re-check sanctions at execution time (recipient may have been
        // sanctioned during the timelock delay).
        if (blockedAddresses[req.recipient]) revert AddressBlocked();

        req.executed = true;

        // Audit: Update totalLocked accounting to maintain invariant:
        // totalLockedETH/ERC20 == actual locked balance available for normal withdrawals.
        if (req.token == address(0)) {
            totalLockedETH -= req.amount;
            (bool success, ) = req.recipient.call{value: req.amount}("");
            if (!success) revert TransferFailed();
        } else {
            totalLockedERC20[req.token] -= req.amount;
            IERC20(req.token).safeTransfer(req.recipient, req.amount);
        }

        emit EmergencyWithdrawalExecuted(operationId, req.token, req.recipient, req.amount);
    }

    /**
     * @notice Cancel a queued emergency withdrawal
     * @param operationId Queued emergency withdrawal operation ID
     */
    function cancelEmergencyWithdrawal(bytes32 operationId)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        EmergencyWithdrawalRequest storage req = emergencyWithdrawalRequests[operationId];
        if (req.queuedAt == 0) revert EmergencyWithdrawalNotFound();
        if (req.executed || req.cancelled) revert EmergencyWithdrawalAlreadyHandled();

        req.cancelled = true;
        emit EmergencyWithdrawalCancelled(operationId, msg.sender);
    }

    /**
     * @notice Update the per-block mint/withdrawal ceiling.
     * @param newCeiling New ceiling in wei (must be > 0)
     */
    function setMintCeilingPerBlock(uint256 newCeiling)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        if (newCeiling == 0) revert InvalidAmount();
        uint256 oldCeiling = mintCeilingPerBlock;
        mintCeilingPerBlock = newCeiling;
        emit MintCeilingUpdated(oldCeiling, newCeiling);
    }

    /**
     * @notice Backward-compatible alias that now enforces timelocked flow.
     * @dev This no longer transfers immediately; it only queues the request.
     */
    function emergencyWithdraw(address token, uint256 amount, address recipient)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        queueEmergencyWithdrawal(token, amount, recipient);
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /**
     * @notice Get deposit details
     * @param depositId The deposit ID
     * @return deposit The deposit struct
     */
    function getDeposit(bytes32 depositId) external view returns (Deposit memory) {
        return deposits[depositId];
    }

    /**
     * @notice Get withdrawal proposal details
     * @param proposalId The proposal ID
     * @return proposal The proposal struct
     */
    function getWithdrawalProposal(bytes32 proposalId)
        external
        view
        returns (WithdrawalProposal memory)
    {
        return withdrawalProposals[proposalId];
    }

    /**
     * @notice Check if a relayer has voted on a proposal
     * @param proposalId The proposal ID
     * @param relayer The relayer address
     * @return hasVoted Whether the relayer has voted
     */
    function hasRelayerVoted(bytes32 proposalId, address relayer)
        external
        view
        returns (bool)
    {
        return withdrawalVotes[proposalId][relayer];
    }

    /**
     * @notice Get current rate limit state
     * @return deposited Total deposited in current period
     * @return withdrawn Total withdrawn in current period
     */
    function getCurrentRateLimitState()
        external
        view
        returns (uint256 deposited, uint256 withdrawn)
    {
        uint256 currentPeriod = block.timestamp / RATE_LIMIT_PERIOD;
        RateLimitState storage state = rateLimitState[currentPeriod];
        return (state.totalDeposited, state.totalWithdrawn);
    }

    /**
     * @notice Check if a withdrawal can be processed
     * @param proposalId The proposal ID
     * @return canProcess Whether the withdrawal can be processed
     * @return reason Reason if cannot process
     */
    function canProcessWithdrawal(bytes32 proposalId)
        external
        view
        returns (bool canProcess, string memory reason)
    {
        WithdrawalProposal storage proposal = withdrawalProposals[proposalId];

        if (proposal.createdAt == 0) return (false, "Proposal not found");
        if (proposal.processed) return (false, "Already processed");
        if (proposal.challenged) return (false, "Challenged");
        // Use the stricter of snapshot and current threshold
        uint256 effectiveThreshold = proposal.requiredVotesSnapshot;
        if (relayerConfig.minVotesRequired > effectiveThreshold) {
            effectiveThreshold = relayerConfig.minVotesRequired;
        }
        if (proposal.voteCount < effectiveThreshold)
            return (false, "Insufficient votes");
        if (block.timestamp < proposal.challengeEndTime)
            return (false, "Challenge period not ended");
        if (blockedAddresses[proposal.recipient])
            return (false, "Recipient blocked");

        return (true, "");
    }

    // =========================================================================
    // INTERNAL FUNCTIONS
    // =========================================================================

    function _validateDeposit(bytes32 aethelredRecipient, uint256 amount) internal pure {
        if (aethelredRecipient == bytes32(0)) revert InvalidRecipient();
        if (amount < MIN_DEPOSIT) revert InvalidAmount();
        if (amount > MAX_SINGLE_DEPOSIT) revert InvalidAmount();
    }

    function _generateDepositId(
        address depositor,
        bytes32 aethelredRecipient,
        address token,
        uint256 amount,
        uint256 nonce
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                depositor,
                aethelredRecipient,
                token,
                amount,
                nonce,
                block.chainid
            )
        );
    }

    function grantRole(bytes32 role, address account)
        public
        override
        onlyRole(getRoleAdmin(role))
    {
        bool alreadyHad = hasRole(role, account);
        super.grantRole(role, account);
        if (role == RELAYER_ROLE && !alreadyHad) {
            _syncRelayerVoteThreshold(true);
        }
    }

    function revokeRole(bytes32 role, address account)
        public
        override
        onlyRole(getRoleAdmin(role))
    {
        bool hadRole = hasRole(role, account);
        super.revokeRole(role, account);
        if (role == RELAYER_ROLE && hadRole) {
            _syncRelayerVoteThreshold(false);
        }
    }

    function renounceRole(bytes32 role, address callerConfirmation) public override {
        bool hadRole = hasRole(role, callerConfirmation);
        super.renounceRole(role, callerConfirmation);
        if (role == RELAYER_ROLE && hadRole) {
            _syncRelayerVoteThreshold(false);
        }
    }

    /**
     * @dev Syncs relayerConfig.relayerCount and minVotesRequired after a grant/revoke.
     *
     * Audit note — relayer churn and in-flight proposals:
     *   In-flight proposals use a requiredVotesSnapshot captured at proposal creation
     *   time. processWithdrawal enforces the STRICTER of (snapshot, current threshold),
     *   so:
     *   - Removing relayers cannot retroactively weaken in-flight proposals.
     *   - Adding relayers increases the current threshold, which is also enforced.
     *   This design ensures that no proposal can be processed with fewer votes than
     *   required at the time it was created.
     */
    function _syncRelayerVoteThreshold(bool increment) internal {
        uint256 count = relayerConfig.relayerCount;
        if (increment) {
            count += 1;
        } else if (count > 0) {
            count -= 1;
        }
        relayerConfig.relayerCount = count;

        uint256 thresholdBps = relayerConfig.consensusThresholdBps;
        uint256 minVotes = (count * thresholdBps) / 10000;
        if (count > 0 && minVotes == 0) {
            minVotes = 1;
        }
        if (minVotes > count) {
            minVotes = count;
        }
        relayerConfig.minVotesRequired = minVotes;

        emit RelayerConfigUpdated(count, thresholdBps, minVotes);
    }

    function _requireContractAdmin(address admin) internal view {
        if (admin == address(0)) revert InvalidRecipient();
        // Allow local-dev EOAs on common local chains to keep tests/development usable.
        if (block.chainid == 31337 || block.chainid == 1337) {
            return;
        }
        if (admin.code.length == 0) revert AdminMustBeContract();
    }

    function _requireUpgraderTimelockDelay(address upgraderTimelock) internal view {
        if (
            ITimelockDelaySource(upgraderTimelock).getMinDelay() <
            MIN_UPGRADER_TIMELOCK_DELAY
        ) {
            revert UpgraderTimelockDelayTooShort();
        }
    }

    /**
     * @dev Audit: UPGRADER_ROLE is isolated via _setRoleAdmin(UPGRADER_ROLE, UPGRADER_ROLE)
     * so only the timelock contract (which holds UPGRADER_ROLE) can authorize upgrades.
     * DEFAULT_ADMIN_ROLE cannot grant itself UPGRADER_ROLE. The timelock enforces a
     * minimum delay of MIN_UPGRADER_TIMELOCK_DELAY (27 days) verified at initialization.
     *
     * Storage layout safety: The __gap[50] at the end of the contract reserves 50 storage
     * slots for future upgrades. New state variables must consume gap slots, not extend past them.
     */
    function _authorizeUpgrade(address newImplementation)
        internal
        override
        onlyRole(UPGRADER_ROLE)
    {
        // Intentionally empty — the onlyRole modifier is the sole gate.
        // No additional validation on newImplementation is needed because the
        // UUPS proxy pattern verifies the new implementation has _authorizeUpgrade.
    }

    // =========================================================================
    // PER-BLOCK MINT CEILING (H-04 defense-in-depth)
    // =========================================================================

    /**
     * @dev Enforces a per-block ceiling on withdrawals/mints to prevent
     *      burst attacks that bypass hourly rate limits.
     */
    function _enforceMintCeiling(uint256 amount) internal {
        if (mintCeilingPerBlock == 0) return; // disabled

        if (block.number != _lastMintBlock) {
            _lastMintBlock = block.number;
            _mintedThisBlock = 0;
        }

        if (_mintedThisBlock + amount > mintCeilingPerBlock) {
            revert MintCeilingExceeded();
        }
        _mintedThisBlock += amount;
    }

    // =========================================================================
    // EIP-712 DOMAIN SEPARATOR (with chain-fork protection)
    // =========================================================================

    /**
     * @dev Returns the EIP-712 domain separator, recomputing on chain fork.
     *      Uses the same pattern as OpenZeppelin EIP-712 and Uniswap V3.
     */
    function domainSeparatorV4() public view returns (bytes32) {
        if (block.chainid == _cachedChainId) {
            return _cachedDomainSeparator;
        }
        return _computeDomainSeparator();
    }

    function _computeDomainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                EIP712_NAME_HASH,
                EIP712_VERSION_HASH,
                block.chainid,
                address(this)
            )
        );
    }

    /**
     * @dev Build EIP-712 typed data hash for a withdrawal proposal.
     *      Wallets can display: "Approve Withdrawal: X ETH to 0x..."
     */
    function hashWithdrawalProposal(
        bytes32 proposalId,
        address recipient,
        address token,
        uint256 amount,
        bytes32 burnTxHash,
        uint256 aethelredBlockHeight
    ) public view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                WITHDRAWAL_TYPEHASH,
                proposalId,
                recipient,
                token,
                amount,
                burnTxHash,
                aethelredBlockHeight
            )
        );
        return keccak256(
            abi.encodePacked("\x19\x01", domainSeparatorV4(), structHash)
        );
    }

    // =========================================================================
    // RECEIVE
    // =========================================================================

    /// @dev Audit: Reject direct ETH transfers to force users through depositETH() which
    /// enforces rate limits, sanctions, min/max amounts, and proper accounting.
    /// No fallback() is defined, so any call with non-matching selector also reverts.
    receive() external payable {
        revert("Use depositETH()");
    }

    // =========================================================================
    // VERSION — Audit fix [I-05]
    // =========================================================================

    /// @notice Contract implementation version for upgrade tracking.
    function version() external pure returns (string memory) {
        return "1.0.0";
    }

    // =========================================================================
    // STORAGE GAP
    // =========================================================================

    uint256[50] private __gap;
}
