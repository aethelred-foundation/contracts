// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";

import "./ICruzible.sol";
import "./StAETHEL.sol";
import "./VaultTEEVerifier.sol";

/**
 * @title Cruzible
 * @author Aethelred Team
 * @notice Production-grade liquid staking vault with TEE-verified validator selection,
 *         MEV protection, and cryptographic reward distribution.
 *
 * @dev Core staking primitive for the Aethelred L1. Distinguishing features:
 *      1. TEE-Verified Validator Selection — The validator scoring algorithm runs
 *         inside Intel SGX / AWS Nitro enclaves. Selection criteria (performance,
 *         decentralization, reputation) are computed confidentially and verified
 *         on-chain via attestation proofs.
 *      2. MEV Protection — Commit-reveal scheme for block proposals processed inside
 *         TEE enclaves eliminates front-running and sandwich attacks.
 *      3. Cryptographic Reward Verification — Epoch rewards are calculated inside
 *         TEE enclaves and published as Merkle trees, allowing any staker to verify
 *         their allocation independently.
 *      4. Fair Decentralization Scoring — Geographic diversity, unique operator
 *         detection, and Sybil resistance are enforced algorithmically.
 *
 * Architecture:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                           CRUZIBLE                                       │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                             │
 * │  ┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐       │
 * │  │  Staking Pool    │   │  Validator Set    │   │  Reward Engine   │       │
 * │  │  ─────────────── │   │  ─────────────── │   │  ─────────────── │       │
 * │  │  • stake()       │   │  • TEE Selection  │   │  • TEE Calc      │       │
 * │  │  • unstake()     │   │  • Performance    │   │  • Merkle Proofs │       │
 * │  │  • withdraw()    │   │  • Diversity      │   │  • MEV Redistr.  │       │
 * │  │  • stAETHEL mint │   │  • Reputation     │   │  • Protocol Fee  │       │
 * │  └──────────────────┘   └──────────────────┘   └──────────────────┘       │
 * │                                                                             │
 * │  ┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐       │
 * │  │  Unbonding Queue │   │  TEE Verifier    │   │  Circuit Breaker │       │
 * │  │  ─────────────── │   │  ─────────────── │   │  ─────────────── │       │
 * │  │  • 14-day lock   │   │  • SGX/Nitro/SEV │   │  • Rate limiting │       │
 * │  │  • Batch claims  │   │  • Attestation   │   │  • Emergency     │       │
 * │  │  • Slashing prot │   │  • Multi-TEE     │   │  • Guardian sig  │       │
 * │  └──────────────────┘   └──────────────────┘   └──────────────────┘       │
 * │                                                                             │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * ## Trust Model — Delegation Bridge
 *
 * Delegation is native-chain state (which validator each staker selected)
 * that the EVM cannot independently derive.  The delegation pipeline
 * crosses this trust boundary through a defense-in-depth model with eight
 * layers, each narrowing the residual trust assumption:
 *
 *   1. **Go keeper** snapshots the delegation mapping from native-chain
 *      records (SnapshotDelegationState → BuildDelegationAttestationRequest).
 *      Fail-closed: every delegation target must be a registered validator.
 *   2. **Rust TEE** receives the staker-delegation data, independently
 *      recomputes both the staker registry root and the delegation registry
 *      root, and attests the result via hardware-backed signature.
 *   3. **EVM** verifies the TEE attestation and cross-checks the staker
 *      registry root against the on-chain XOR accumulator (StAETHEL),
 *      proving the TEE computed over the correct staker set.
 *   4. **Challenge period** (DELEGATION_CHALLENGE_PERIOD = 1 hour) allows
 *      off-chain watchers to detect and request guardian revocation before
 *      the delegation root is consumed by distributeRewards().
 *   5. **Delegation cardinality anchor** (delegatingStakerCount) is committed
 *      alongside the root, allowing off-chain monitors to verify no stakers
 *      were omitted from the delegation snapshot.
 *   6. **Staleness guard** (DELEGATION_MAX_AGE = 6 hours) prevents stale
 *      commitments from being consumed, forcing fresh TEE attestation close
 *      to reward distribution time.
 *   7. **Multi-attestor quorum** (DELEGATION_QUORUM = 2) — when enabled,
 *      multiple independent attestors (each running their own keeper + TEE)
 *      must agree on the same delegation root.  No single operator can
 *      fabricate delegation state.  (submitDelegationVote flow)
 *   8. **Keeper bond & slash** (KEEPER_BOND_MINIMUM = 100K AETHEL) —
 *      keepers/attestors must post an economic bond that the guardian can
 *      slash if delegation fraud is proven during the challenge period.
 *      This makes false commitments economically irrational.
 *   9. **Bonded permissionless challenge** (DELEGATION_CHALLENGE_THRESHOLD = 3,
 *      CHALLENGE_BOND = 10K AETHEL) — any address can flag a delegation
 *      commitment during the challenge period by posting a slashable bond.
 *      When enough independent bonded challengers flag, the commitment is
 *      automatically revoked as a circuit-breaker safety measure.
 *      Auto-revocation does NOT refund bonds.  Bonds are only refunded
 *      when the guardian explicitly confirms fraud (via confirmDelegationFraud)
 *      within CHALLENGE_ADJUDICATION_PERIOD (24 h).  If the guardian does
 *      not confirm, bonds are slashed to the treasury.  This makes griefing
 *      cost the full bond amount per challenger, preventing Sybil-based
 *      liveness attacks on delegation finalization.
 *
 * Residual trust assumption: the keeper provides the delegated_to field for
 * each staker.  The TEE validates the staker set (via registry root) but
 * cannot independently read native-chain delegation state.  This is an
 * inherent property of cross-chain state bridging without light-client
 * proofs.  The nine defense layers above make exploitation require:
 *   - Compromising DELEGATION_QUORUM independent TEE operators
 *   - Posting KEEPER_BOND_MINIMUM × QUORUM in slashable collateral
 *   - Avoiding detection by all off-chain watchers for the challenge period
 *   - Avoiding DELEGATION_CHALLENGE_THRESHOLD independent bonded challengers
 *     (each posting CHALLENGE_BOND in slashable AETHEL)
 *
 * This model parallels standard optimistic bridge designs (Optimism,
 * Arbitrum) where the happy path trusts a sequencer/proposer and the
 * challenge path provides fraud resistance, enhanced with distributed
 * trust, economic security, and permissionless challenge.
 *
 * @custom:security-contact security@aethelred.io
 * @custom:audit-status Pre-audit
 */
contract Cruzible is
    Initializable,
    ICruzible,
    AccessControlUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable,
    UUPSUpgradeable
{
    using SafeERC20 for IERC20;
    using Math for uint256;

    // =========================================================================
    // CONSTANTS & ROLES
    // =========================================================================

    bytes32 public constant ORACLE_ROLE = keccak256("ORACLE_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    /// @notice Role for the native-chain keeper that bridges off-chain state
    ///         commitments (stake snapshots, universe hashes, delegation roots).
    ///         Separated from DEFAULT_ADMIN_ROLE so governance and the keeper
    ///         have independent trust boundaries.
    bytes32 public constant KEEPER_ROLE = keccak256("KEEPER_ROLE");

    /// @notice Minimum stake amount (32 AETHEL).
    uint256 public constant MIN_STAKE = 32 ether;

    /// @notice Maximum stake per transaction to prevent whale manipulation.
    uint256 public constant MAX_STAKE_PER_TX = 10_000_000 ether;

    /// @notice Minimum delay between delegation root commitment and its use
    ///         in distributeRewards().  This gives off-chain watchers time to
    ///         verify the keeper's commitment against native-chain delegation
    ///         state and request guardian revocation if fraud is detected.
    uint256 public constant DELEGATION_CHALLENGE_PERIOD = 1 hours;

    /// @notice Maximum age of a delegation commitment before it becomes stale.
    ///         A stale commitment cannot be consumed by distributeRewards() — the
    ///         keeper must re-commit with a fresh TEE attestation.  This prevents
    ///         a compromised keeper from committing a valid delegation root early
    ///         in the epoch and then altering native delegation state before
    ///         reward distribution, knowing the challenge period has already expired.
    uint256 public constant DELEGATION_MAX_AGE = 6 hours;

    /// @notice Unbonding period (14 days in seconds).
    uint256 public constant UNBONDING_PERIOD = 14 days;

    /// @notice Maximum validator commission (10%).
    uint256 public constant MAX_COMMISSION_BPS = 1000;

    /// @notice Protocol fee on rewards (5% — used for development and insurance).
    uint256 public constant PROTOCOL_FEE_BPS = 500;

    /// @notice MEV redistribution: staker share (90%).
    uint256 public constant MEV_STAKER_SHARE_BPS = 9000;

    /// @notice Basis points denominator.
    uint256 public constant BPS_DENOMINATOR = 10000;

    /// @notice Epoch duration (24 hours in seconds).
    uint256 public constant EPOCH_DURATION = 24 hours;

    /// @notice Maximum withdrawal requests per user.
    uint256 public constant MAX_WITHDRAWAL_REQUESTS = 100;

    /// @notice Maximum active validators in the set.
    uint256 public constant MAX_VALIDATORS = 200;

    /// @notice Minimum validators for the protocol to operate.
    uint256 public constant MIN_VALIDATORS = 4;

    /// @notice Maximum batch withdraw size.
    uint256 public constant MAX_BATCH_SIZE = 50;

    /// @notice Rate limit: maximum stake per epoch to prevent flash-loan attacks.
    uint256 public constant MAX_STAKE_PER_EPOCH = 500_000_000 ether;

    // =========================================================================
    // DELEGATION BRIDGE HARDENING — CONSTANTS
    // =========================================================================

    /// @notice Role for independent delegation attestors that participate in the
    ///         multi-attestor quorum.  Each attestor runs their own Go keeper
    ///         connected to the native chain and their own TEE instance.
    ///         Separated from KEEPER_ROLE so the single-keeper direct-commit path
    ///         can coexist with the quorum path during migration.
    bytes32 public constant DELEGATION_ATTESTOR_ROLE = keccak256("DELEGATION_ATTESTOR_ROLE");

    /// @notice Minimum number of independent attestors that must agree on the
    ///         same delegation root before the commitment is accepted.
    ///         Distributes trust: no single keeper can fabricate delegation state.
    uint256 public constant DELEGATION_QUORUM = 2;

    /// @notice Minimum bond (in AETHEL) a keeper must deposit before calling
    ///         commitDelegationSnapshot() or submitDelegationVote().
    ///         The bond is slashable by the guardian if delegation fraud is proven,
    ///         creating an economic deterrent against false commitments.
    uint256 public constant KEEPER_BOND_MINIMUM = 100_000 ether;

    /// @notice Number of independent challenge flags required to auto-revoke a
    ///         delegation commitment during the challenge period.
    ///         Permissionless: any address can flag (with a bond).  This
    ///         democratizes fraud detection beyond the single guardian.
    uint256 public constant DELEGATION_CHALLENGE_THRESHOLD = 3;

    /// @notice Bond (in AETHEL) that each challenger must post when flagging
    ///         a delegation commitment.  Refunded only if the guardian confirms
    ///         fraud via confirmDelegationFraud(); slashed to the treasury
    ///         otherwise.  Prevents Sybil-based liveness attacks.
    uint256 public constant CHALLENGE_BOND = 10_000 ether;

    /// @notice Time window after auto-revocation during which the guardian can
    ///         confirm that the revoked commitment was genuinely fraudulent.
    ///         If the guardian confirms within this period, challenger bonds are
    ///         refunded.  If not, bonds are slashed (presumption of validity).
    uint256 public constant CHALLENGE_ADJUDICATION_PERIOD = 24 hours;

    // =========================================================================
    // STRUCTS
    // =========================================================================

    /// @notice Validator record in the active set.
    struct ValidatorInfo {
        address validatorAddress;
        uint256 delegatedStake;
        uint256 performanceScore;     // 0-10000 (basis points)
        uint256 decentralizationScore; // 0-10000
        uint256 reputationScore;       // 0-10000
        uint256 compositeScore;        // TEE-computed weighted score
        bytes32 teePublicKey;
        uint256 commission;            // Commission in basis points
        uint256 activeSince;
        uint256 slashCount;
        bool isActive;
    }

    /// @notice Withdrawal request in the unbonding queue.
    struct WithdrawalRequest {
        address owner;
        uint256 shares;
        uint256 aethelAmount;
        uint256 requestTime;
        uint256 completionTime;
        bool claimed;
    }

    /// @notice Epoch snapshot for reward accounting.
    struct EpochSnapshot {
        uint256 totalPooledAethel;
        uint256 totalShares;
        uint256 rewardsDistributed;
        uint256 mevRedistributed;
        uint256 protocolFee;
        bytes32 rewardsMerkleRoot;
        bytes32 validatorSetHash;
        bytes32 eligibleUniverseHash;
        bytes32 stakeSnapshotHash;
        bytes32 stakerRegistryRoot;
        /// @notice Delegation registry root committed for this epoch.
        /// @dev XOR accumulator of keccak256(staker_address, delegated_to) for
        ///      every staker with non-zero shares.  Captures the delegation
        ///      topology that drives performance-weighted reward allocation.
        ///
        ///      Committed by governance via commitDelegationSnapshot() before
        ///      reward distribution, mirroring the stakeSnapshotHash pattern.
        ///      distributeRewards() verifies the TEE-attested delegation root
        ///      matches this committed value.
        ///
        ///      Unlike stakerRegistryRoot (independently derived from on-chain
        ///      share balances via the StAETHEL XOR accumulator), delegation is
        ///      native-chain state that the EVM cannot independently derive.
        ///      The commitment is sourced from the Go native keeper, which
        ///      computes it from native-chain delegation records.
        bytes32 delegationRegistryRoot;
        bytes32 teeAttestationHash;
        uint256 timestamp;
        bool finalized;
    }

    // =========================================================================
    // STATE VARIABLES
    // =========================================================================

    /// @notice The AETHEL token contract.
    IERC20 public aethelToken;

    /// @notice The stAETHEL liquid staking token.
    StAETHEL public stAethelToken;

    /// @notice The TEE attestation verifier.
    VaultTEEVerifier public teeVerifier;

    /// @notice Protocol treasury for fee collection.
    address public treasury;

    /// @notice Current epoch number.
    uint256 public currentEpoch;

    /// @notice Timestamp when the current epoch started.
    uint256 public epochStartTime;

    /// @notice Total AETHEL staked in the vault.
    uint256 public totalPooledAethel;

    /// @notice Total pending withdrawals (AETHEL reserved for unbonding).
    uint256 public totalPendingWithdrawals;

    /// @notice Next withdrawal request ID.
    uint256 public nextWithdrawalId;

    /// @notice Active validator set.
    mapping(address => ValidatorInfo) public validators;
    address[] public activeValidators;

    /// @notice Withdrawal requests.
    mapping(uint256 => WithdrawalRequest) public withdrawalRequests;

    /// @notice User's active withdrawal request IDs.
    mapping(address => uint256[]) public userWithdrawals;

    /// @notice Epoch snapshots for reward verification.
    mapping(uint256 => EpochSnapshot) public epochSnapshots;

    /// @notice Stake amount per epoch (for rate limiting).
    mapping(uint256 => uint256) public stakePerEpoch;

    /// @notice Claimed rewards per user per epoch (for Merkle claims).
    mapping(address => mapping(uint256 => bool)) public rewardsClaimed;

    /// @notice Total accumulated MEV revenue.
    uint256 public totalMEVRevenue;

    /// @notice AETHEL reserved for unclaimed Merkle reward claims, per epoch.
    mapping(uint256 => uint256) public epochReservedForClaims;

    /// @notice Total AETHEL reserved across all epochs (sum of per-epoch reserves).
    uint256 public totalReservedForClaims;

    /// @notice Whether the vault has been bootstrapped.
    bool public bootstrapped;

    /// @notice Canonical hash of the approved validator selection policy.
    /// @dev Set by governance via `setSelectionPolicyHash()`. The TEE worker must
    ///      use a SelectionConfig whose canonical hash matches this value, otherwise
    ///      `updateValidatorSet()` reverts. This prevents callers from biasing
    ///      validator selection by supplying arbitrary scoring weights/thresholds
    ///      while still obtaining a valid TEE attestation.
    ///
    ///      The hash is computed as:
    ///        SHA-256("CruzibleSelectionPolicy-v1" ||
    ///                float64_be(performance_weight) || float64_be(decentralization_weight) ||
    ///                float64_be(reputation_weight)  || float64_be(min_uptime_pct) ||
    ///                uint256(max_commission_bps)    || uint256(max_per_region) ||
    ///                uint256(max_per_operator)      || uint256(min_stake))
    ///
    ///      Matching implementations:
    ///        - Rust: server::compute_selection_policy_hash()
    ///        - Go:   keeper.computeSelectionPolicyHash()
    bytes32 public selectionPolicyHash;

    /// @notice Legacy slot — universe commitments are now epoch-scoped inside EpochSnapshot.
    /// @dev Preserved for storage layout compatibility.  Use commitUniverseHash()
    ///      which writes to epochSnapshots[epoch].eligibleUniverseHash.
    bytes32 private __deprecated_committedUniverseHash;

    /// @notice The eligible-universe hash from the most recent validator set update.
    /// @dev Stored for auditability. Also available via epochSnapshots[epoch].eligibleUniverseHash.
    bytes32 public lastEligibleUniverseHash;

    /// @notice Legacy slot reserved for the removed committedStakeSnapshotHash.
    /// @dev Stake snapshot hashes are now epoch-scoped inside EpochSnapshot.
    ///      See commitStakeSnapshot(uint256,bytes32) and epochSnapshots[epoch].stakeSnapshotHash.
    ///      This placeholder preserves the storage layout for upgradeability.
    bytes32 private __deprecated_committedStakeSnapshotHash;

    /// @notice Timestamp when each epoch's delegation root was committed.
    /// @dev Used by the DELEGATION_CHALLENGE_PERIOD check in distributeRewards().
    ///      Cleared on guardian revocation to allow re-commitment.
    mapping(uint256 => uint256) public delegationCommitTimestamp;

    /// @notice Number of stakers with non-zero delegation in each epoch's snapshot.
    /// @dev Cardinality anchor: off-chain monitors compare this against the
    ///      native-chain staker count to detect omissions in the delegation
    ///      snapshot.  Set by commitDelegationSnapshot() alongside the root.
    ///      A zero count with a non-zero root is rejected as inconsistent.
    mapping(uint256 => uint256) public delegatingStakerCount;

    // =========================================================================
    // DELEGATION BRIDGE HARDENING — STATE
    // =========================================================================

    /// @notice Vote tally per epoch per delegation root.
    /// @dev epoch → delegationRoot → number of attestors that submitted this root.
    ///      When the count reaches DELEGATION_QUORUM, the root is auto-committed.
    mapping(uint256 => mapping(bytes32 => uint256)) public delegationVoteCount;

    /// @notice Tracks whether an attestor has already voted for a given epoch.
    /// @dev epoch → attestor address → has voted.
    mapping(uint256 => mapping(address => bool)) public delegationAttestorVoted;

    /// @notice Enumerable list of attestors who voted in each epoch's delegation
    ///         quorum.  Used by _freezeDelegationSubmitters() to freeze all
    ///         participating attestors on fraud determination.
    mapping(uint256 => address[]) internal delegationEpochAttestors;

    /// @notice Address that committed the delegation snapshot via the single-keeper
    ///         path (commitDelegationSnapshot).  Used to lock their bond during the
    ///         challenge/adjudication window, mirroring the lock that
    ///         delegationAttestorVoted provides for the quorum path.
    mapping(uint256 => address) public delegationCommitter;

    /// @notice When true, commitDelegationSnapshot() (single-keeper) is disabled
    ///         and delegation must go through the multi-attestor quorum flow
    ///         (submitDelegationVote).  Toggled by governance.
    bool public delegationQuorumEnabled;

    /// @notice Keeper bond deposits (in AETHEL).  Keepers must deposit at least
    ///         KEEPER_BOND_MINIMUM before committing delegation snapshots.
    ///         The guardian can slash the bond if delegation fraud is proven.
    mapping(address => uint256) public keeperBonds;

    /// @notice Sum of all keeper bond deposits.  Used to reconcile the vault's
    ///         AETHEL balance against staked + reserved + bonded amounts.
    uint256 public totalKeeperBonds;

    /// @notice Per-keeper freeze flag.  Set when the guardian determines fraud
    ///         (via revokeDelegationSnapshot or confirmDelegationFraud) to
    ///         prevent the keeper from withdrawing before slashing executes.
    ///         Cleared by slashKeeperBond() or releaseKeeperBondFreeze().
    mapping(address => bool) public keeperBondFrozen;

    /// @notice Number of independent challenge flags per epoch.
    /// @dev When this reaches DELEGATION_CHALLENGE_THRESHOLD, the delegation
    ///      commitment is automatically revoked.
    mapping(uint256 => uint256) public delegationChallengeCount;

    /// @notice Tracks whether an address has already flagged a delegation
    ///         commitment for a given epoch (prevents double-counting).
    mapping(uint256 => mapping(address => bool)) public delegationChallengers;

    /// @notice Bond deposited by each challenger per epoch.
    /// @dev Non-zero only while the bond is held; cleared on refund or slash.
    mapping(uint256 => mapping(address => uint256)) public challengerBonds;

    /// @notice Sum of all outstanding challenger bonds for a given epoch.
    uint256 public totalChallengerBonds;

    /// @notice Set to true only when the guardian explicitly confirms that a
    ///         revoked delegation commitment was genuinely fraudulent.
    ///         Determines whether challenger bonds are refunded (true) or
    ///         slashed (false) when claimed.
    ///
    ///         NOT set by auto-revocation — auto-revocation is a safety
    ///         circuit-breaker, not a fraud determination.
    mapping(uint256 => bool) public delegationChallengeSucceeded;

    /// @notice Timestamp when a delegation commitment was auto-revoked by
    ///         reaching DELEGATION_CHALLENGE_THRESHOLD.  Zero if not auto-
    ///         revoked.  Used to determine the adjudication deadline.
    mapping(uint256 => uint256) public delegationAutoRevokedAt;

    // =========================================================================
    // ERRORS
    // =========================================================================

    error ZeroAddress();
    error ZeroAmount();
    error BelowMinStake(uint256 amount, uint256 minimum);
    error ExceedsMaxStake(uint256 amount, uint256 maximum);
    error EpochRateLimitExceeded(uint256 requested, uint256 remaining);
    error InsufficientShares(uint256 requested, uint256 available);
    error WithdrawalNotReady(uint256 withdrawalId, uint256 completionTime);
    error WithdrawalAlreadyClaimed(uint256 withdrawalId);
    error WithdrawalNotOwned(uint256 withdrawalId);
    error TooManyWithdrawalRequests(address user);
    error BatchTooLarge(uint256 size, uint256 maximum);
    error InvalidAttestation();
    error SelectionPolicyMismatch(bytes32 attested, bytes32 expected);
    error StakeSnapshotMismatch(bytes32 attested, bytes32 committed);
    error ValidatorSetHashMismatch(bytes32 attested, bytes32 committed);
    error ProtocolFeeMismatch(uint256 provided, uint256 expected);
    error EpochAlreadyFinalized(uint256 epoch);
    error EpochNotFinalized(uint256 epoch);
    error InvalidEpoch(uint256 provided, uint256 expected);
    error InsufficientValidators(uint256 count, uint256 minimum);
    error ValidatorAlreadyActive(address validator);
    error ValidatorNotActive(address validator);
    error ExceedsMaxValidators();
    error DuplicateValidator(address validator);
    error RewardsAlreadyClaimed(address user, uint256 epoch);
    error InvalidMerkleProof();
    error EligibleUniverseMismatch(bytes32 attested, bytes32 committed);
    error UniverseHashAlreadyCommitted(uint256 epoch);
    error StakeSnapshotAlreadyCommitted(uint256 epoch);
    error SnapshotSharesMismatch(uint256 claimed, uint256 onChain);
    error RegistryRootMismatch(bytes32 attested, bytes32 committed);
    error DelegationRootMismatch(bytes32 attested, bytes32 committed);
    error DelegationSnapshotAlreadyCommitted(uint256 epoch);
    error StakeSnapshotNotCommitted(uint256 epoch);
    error StakerRegistryAnchorMismatch(bytes32 supplied, bytes32 committed);
    error DelegationChallengePeriodActive(uint256 epoch, uint256 availableAt);
    error DelegationNotCommitted(uint256 epoch);
    error DelegationAttestationInvalid();
    error DelegationCommitmentStale(uint256 epoch, uint256 committedAt, uint256 maxAge);
    error DelegationCardinalityZeroWithNonZeroRoot(uint256 epoch);
    error DelegationAttestorAlreadyVoted(uint256 epoch, address attestor);
    error InsufficientKeeperBond(uint256 deposited, uint256 required);
    error DelegationQuorumRequired(uint256 epoch);
    error ChallengeOutsidePeriod(uint256 epoch);
    error AlreadyChallenged(uint256 epoch, address challenger);
    error BondWithdrawalExceedsDeposit(uint256 requested, uint256 available);
    error KeeperBondLocked();
    error KeeperBondIsFrozen(address keeper);
    error KeeperBondNotFrozen(address keeper);
    error ChallengeClaimTooEarly(uint256 epoch);
    error NoChallengerBond(uint256 epoch, address challenger);
    error NotAutoRevoked(uint256 epoch);
    error AdjudicationPeriodExpired(uint256 epoch);
    error NotBootstrapped();
    error AlreadyBootstrapped();
    error InsufficientVaultBalance(uint256 requested, uint256 available);

    // =========================================================================
    // INITIALIZATION
    // =========================================================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initialize the Cruzible.
     * @param admin Admin address (multisig on mainnet).
     * @param aethel The AETHEL token address.
     * @param stAethel The stAETHEL token address.
     * @param verifier The TEE attestation verifier address.
     * @param treasuryAddr The protocol treasury address.
     */
    function initialize(
        address admin,
        address aethel,
        address stAethel,
        address verifier,
        address treasuryAddr
    ) external initializer {
        if (admin == address(0)) revert ZeroAddress();
        if (aethel == address(0)) revert ZeroAddress();
        if (stAethel == address(0)) revert ZeroAddress();
        if (verifier == address(0)) revert ZeroAddress();
        if (treasuryAddr == address(0)) revert ZeroAddress();

        __AccessControl_init();
        __Pausable_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);
        _grantRole(KEEPER_ROLE, admin);

        aethelToken = IERC20(aethel);
        stAethelToken = StAETHEL(stAethel);
        teeVerifier = VaultTEEVerifier(verifier);
        treasury = treasuryAddr;

        currentEpoch = 1;
        epochStartTime = block.timestamp;
        nextWithdrawalId = 1;
    }

    // =========================================================================
    // STAKING
    // =========================================================================

    /// @inheritdoc ICruzible
    function stake(uint256 amount) external returns (uint256 shares) {
        return _stake(msg.sender, amount, 0);
    }

    /// @inheritdoc ICruzible
    function stakeWithReferral(uint256 amount, uint256 referralCode)
        external
        returns (uint256 shares)
    {
        return _stake(msg.sender, amount, referralCode);
    }

    /**
     * @notice Internal staking logic.
     */
    function _stake(address user, uint256 amount, uint256 referralCode)
        internal
        nonReentrant
        whenNotPaused
        returns (uint256 shares)
    {
        if (amount == 0) revert ZeroAmount();
        if (amount < MIN_STAKE) revert BelowMinStake(amount, MIN_STAKE);
        if (amount > MAX_STAKE_PER_TX) revert ExceedsMaxStake(amount, MAX_STAKE_PER_TX);

        // Rate limiting per epoch
        uint256 epochStake = stakePerEpoch[currentEpoch] + amount;
        if (epochStake > MAX_STAKE_PER_EPOCH) {
            revert EpochRateLimitExceeded(amount, MAX_STAKE_PER_EPOCH - stakePerEpoch[currentEpoch]);
        }
        stakePerEpoch[currentEpoch] = epochStake;

        // Transfer AETHEL from user
        aethelToken.safeTransferFrom(user, address(this), amount);

        // Calculate shares to mint
        if (totalPooledAethel == 0) {
            shares = amount; // 1:1 for the first staker
        } else {
            shares = (amount * stAethelToken.getTotalShares()) / totalPooledAethel;
        }
        if (shares == 0) revert ZeroAmount();

        // Update state
        totalPooledAethel += amount;

        // Mint stAETHEL shares
        stAethelToken.mintShares(user, shares);
        stAethelToken.setTotalPooledAethel(totalPooledAethel);

        emit Staked(user, amount, shares, referralCode);
    }

    // =========================================================================
    // UNSTAKING & WITHDRAWAL
    // =========================================================================

    /// @inheritdoc ICruzible
    function unstake(uint256 shares)
        external
        nonReentrant
        whenNotPaused
        returns (uint256 withdrawalId, uint256 aethelAmount)
    {
        if (shares == 0) revert ZeroAmount();

        uint256 userShares = stAethelToken.sharesOf(msg.sender);
        if (userShares < shares) revert InsufficientShares(shares, userShares);

        if (userWithdrawals[msg.sender].length >= MAX_WITHDRAWAL_REQUESTS) {
            revert TooManyWithdrawalRequests(msg.sender);
        }

        // Calculate AETHEL amount at current exchange rate
        aethelAmount = stAethelToken.getAethelByShares(shares);
        if (aethelAmount == 0) revert ZeroAmount();

        // Burn shares
        stAethelToken.burnShares(msg.sender, shares);

        // Update pool (reduce total pooled AETHEL)
        totalPooledAethel -= aethelAmount;
        totalPendingWithdrawals += aethelAmount;
        stAethelToken.setTotalPooledAethel(totalPooledAethel);

        // Create withdrawal request
        withdrawalId = nextWithdrawalId++;
        uint256 completionTime = block.timestamp + UNBONDING_PERIOD;

        withdrawalRequests[withdrawalId] = WithdrawalRequest({
            owner: msg.sender,
            shares: shares,
            aethelAmount: aethelAmount,
            requestTime: block.timestamp,
            completionTime: completionTime,
            claimed: false
        });

        userWithdrawals[msg.sender].push(withdrawalId);

        emit UnstakeRequested(msg.sender, shares, aethelAmount, withdrawalId, completionTime);
    }

    /// @inheritdoc ICruzible
    function withdraw(uint256 withdrawalId)
        external
        nonReentrant
        returns (uint256 amount)
    {
        WithdrawalRequest storage request = withdrawalRequests[withdrawalId];

        if (request.owner != msg.sender) revert WithdrawalNotOwned(withdrawalId);
        if (request.claimed) revert WithdrawalAlreadyClaimed(withdrawalId);
        if (block.timestamp < request.completionTime) {
            revert WithdrawalNotReady(withdrawalId, request.completionTime);
        }

        amount = request.aethelAmount;
        request.claimed = true;
        totalPendingWithdrawals -= amount;

        uint256 vaultBalance = aethelToken.balanceOf(address(this));
        if (vaultBalance < amount) {
            revert InsufficientVaultBalance(amount, vaultBalance);
        }

        aethelToken.safeTransfer(msg.sender, amount);

        emit Withdrawn(msg.sender, withdrawalId, amount);
    }

    /// @inheritdoc ICruzible
    function batchWithdraw(uint256[] calldata withdrawalIds)
        external
        nonReentrant
        returns (uint256 totalAmount)
    {
        if (withdrawalIds.length > MAX_BATCH_SIZE) {
            revert BatchTooLarge(withdrawalIds.length, MAX_BATCH_SIZE);
        }

        for (uint256 i = 0; i < withdrawalIds.length; i++) {
            WithdrawalRequest storage request = withdrawalRequests[withdrawalIds[i]];

            if (request.owner != msg.sender) revert WithdrawalNotOwned(withdrawalIds[i]);
            if (request.claimed) revert WithdrawalAlreadyClaimed(withdrawalIds[i]);
            if (block.timestamp < request.completionTime) {
                revert WithdrawalNotReady(withdrawalIds[i], request.completionTime);
            }

            request.claimed = true;
            totalAmount += request.aethelAmount;
            totalPendingWithdrawals -= request.aethelAmount;

            emit Withdrawn(msg.sender, withdrawalIds[i], request.aethelAmount);
        }

        if (totalAmount == 0) revert ZeroAmount();

        uint256 vaultBalance = aethelToken.balanceOf(address(this));
        if (vaultBalance < totalAmount) {
            revert InsufficientVaultBalance(totalAmount, vaultBalance);
        }

        aethelToken.safeTransfer(msg.sender, totalAmount);
    }

    // =========================================================================
    // VALIDATOR MANAGEMENT (TEE-CONTROLLED)
    // =========================================================================

    /// @inheritdoc ICruzible
    function updateValidatorSet(
        bytes calldata teeAttestation,
        bytes calldata validatorData,
        uint256 epoch
    ) external onlyRole(ORACLE_ROLE) whenNotPaused {
        if (epoch != currentEpoch) revert InvalidEpoch(epoch, currentEpoch);

        // Verify TEE attestation
        (bool valid, bytes memory payload,) = teeVerifier.verifyAttestation(teeAttestation);
        if (!valid) revert InvalidAttestation();

        // Decode validator data
        (
            address[] memory addrs,
            uint256[] memory stakes,
            uint256[] memory perfScores,
            uint256[] memory decentScores,
            uint256[] memory repScores,
            uint256[] memory compositeScores,
            bytes32[] memory teeKeys,
            uint256[] memory commissions
        ) = abi.decode(validatorData, (
            address[], uint256[], uint256[], uint256[], uint256[], uint256[], bytes32[], uint256[]
        ));

        // Verify the attested payload matches the canonical validator set hash,
        // the approved selection policy hash, AND the eligible-universe hash.
        //
        // The TEE producer computes:
        //   1. canonical_hash — domain-separated SHA-256 of (epoch, validator fields)
        //   2. policy_hash   — SHA-256 of the SelectionConfig weights/thresholds
        //   3. universe_hash — SHA-256 of sorted eligible validator addresses
        //
        // The attestation payload is:
        //   abi.encodePacked(canonical_hash, policy_hash, universe_hash)  (96 bytes)
        //
        // This binds the attestation to the selection output, the policy that
        // produced it, AND the full eligible candidate universe — preventing both
        // parameter bias and candidate-set truncation attacks.
        bytes32 canonicalHash = _computeValidatorSetHash(
            epoch, addrs, stakes, perfScores, decentScores,
            repScores, compositeScores, teeKeys, commissions
        );

        // Payload must be exactly 96 bytes: canonicalHash || policyHash || universeHash
        if (payload.length != 96) revert InvalidAttestation();

        bytes32 attestedCanonicalHash;
        bytes32 attestedPolicyHash;
        bytes32 attestedUniverseHash;
        // solc Yul needs the memory-safe annotation so the IR optimizer can
        // re-use stack slots; without it the `updateValidatorSet` function
        // exceeds the EVM stack limit when compiled with via_ir.
        assembly ("memory-safe") {
            attestedCanonicalHash := mload(add(payload, 32))
            attestedPolicyHash := mload(add(payload, 64))
            attestedUniverseHash := mload(add(payload, 96))
        }

        // Verify the canonical validator set hash matches
        if (attestedCanonicalHash != canonicalHash) {
            revert InvalidAttestation();
        }

        // Verify the selection policy hash matches the governance-approved policy
        if (attestedPolicyHash != selectionPolicyHash) {
            revert SelectionPolicyMismatch(attestedPolicyHash, selectionPolicyHash);
        }

        // Verify the TEE-attested universe hash against the epoch-scoped
        // commitment set by commitUniverseHash().
        //
        // The eligible-universe hash is committed per-epoch by governance and
        // is immutable once set, preventing mid-epoch manipulation.  The TEE
        // worker derives its universe hash from the caller-supplied candidate
        // list; this comparison ensures the relayer did not omit eligible
        // validators from the TEE request (truncation attack).
        //
        // Cross-layer verification:
        //   - EVM path:   compares attested hash against epoch-committed value
        //   - Native path: Go keeper independently recomputes the universe
        //                  from live on-chain telemetry (keeper.go)
        //
        // Both paths reject attestations whose universe hash does not match
        // an independently-derived source, closing the completeness gap.
        if (attestedUniverseHash != epochSnapshots[epoch].eligibleUniverseHash) {
            revert EligibleUniverseMismatch(attestedUniverseHash, epochSnapshots[epoch].eligibleUniverseHash);
        }
        lastEligibleUniverseHash = attestedUniverseHash;

        if (addrs.length < MIN_VALIDATORS) {
            revert InsufficientValidators(addrs.length, MIN_VALIDATORS);
        }
        if (addrs.length > MAX_VALIDATORS) revert ExceedsMaxValidators();

        // Deactivate all current validators
        for (uint256 i = 0; i < activeValidators.length; i++) {
            validators[activeValidators[i]].isActive = false;
        }
        delete activeValidators;

        // Set new validator set (with uniqueness enforcement).
        //
        // After the deactivation loop above, every address has isActive = false
        // (or the default zero-struct for new addresses).  We check isActive
        // before writing — if it's already true, the address appeared earlier
        // in this same loop, meaning the attested set contains duplicates.
        // This is O(1) per check using the existing mapping.
        for (uint256 i = 0; i < addrs.length; i++) {
            if (validators[addrs[i]].isActive) revert DuplicateValidator(addrs[i]);
            validators[addrs[i]] = ValidatorInfo({
                validatorAddress: addrs[i],
                delegatedStake: stakes[i],
                performanceScore: perfScores[i],
                decentralizationScore: decentScores[i],
                reputationScore: repScores[i],
                compositeScore: compositeScores[i],
                teePublicKey: teeKeys[i],
                commission: commissions[i] > MAX_COMMISSION_BPS ? MAX_COMMISSION_BPS : commissions[i],
                activeSince: block.timestamp,
                slashCount: validators[addrs[i]].slashCount, // Preserve history
                isActive: true
            });
            activeValidators.push(addrs[i]);

            emit ValidatorActivated(
                addrs[i],
                stakes[i],
                perfScores[i],
                decentScores[i]
            );
        }

        // Update epoch snapshot with the canonical SHA-256 validator set hash.
        // This is the same cross-layer hash verified against the TEE attestation,
        // replacing the prior keccak256(validatorData) with the domain-separated
        // SHA-256 hash for cross-layer consistency and reward binding.
        epochSnapshots[epoch].validatorSetHash = canonicalHash;

        emit ValidatorSetUpdated(epoch, addrs.length, keccak256(teeAttestation), attestedUniverseHash);
    }

    // =========================================================================
    // REWARD DISTRIBUTION (TEE-VERIFIED)
    // =========================================================================

    /// @inheritdoc ICruzible
    function distributeRewards(
        bytes calldata teeAttestation,
        uint256 epoch,
        uint256 totalRewards,
        bytes32 merkleRoot,
        uint256 protocolFee
    ) external onlyRole(ORACLE_ROLE) whenNotPaused {
        if (epoch != currentEpoch) revert InvalidEpoch(epoch, currentEpoch);
        if (epochSnapshots[epoch].finalized) revert EpochAlreadyFinalized(epoch);

        // Verify TEE attestation and bind parameters to attested payload.
        //
        // The attested payload is 256 bytes:
        //   abi.encode(epoch, totalRewards, merkleRoot, protocolFee,
        //              stakeSnapshotHash, validatorSetHash,
        //              stakerRegistryRoot, delegationRegistryRoot)
        //
        // This binds the attestation to:
        //   1. The reward summary (epoch, totalRewards, merkleRoot, protocolFee)
        //   2. The specific stake state the TEE computed from (stakeSnapshotHash)
        //   3. The specific validator scores used for performance-weighted
        //      distribution (validatorSetHash)
        //   4. The per-staker share distribution (stakerRegistryRoot)
        //   5. The delegation topology (delegationRegistryRoot) — which
        //      validator each staker delegated to, driving performance-
        //      weighted reward allocation
        //
        // This prevents a relayer from omitting stakers, skewing balances,
        // manipulating validator performance scores, or altering delegations
        // while still obtaining a valid TEE attestation.
        (bool valid, bytes memory payload,) = teeVerifier.verifyAttestation(teeAttestation);
        if (!valid) revert InvalidAttestation();
        if (payload.length != 256) revert InvalidAttestation();

        // Extract the stake snapshot hash, validator set hash, staker
        // registry root, and delegation registry root from the 256-byte
        // payload (8 × 32 bytes).
        bytes32 attestedSnapshotHash;
        bytes32 attestedValidatorSetHash;
        bytes32 attestedRegistryRoot;
        bytes32 attestedDelegationRoot;
        assembly ("memory-safe") {
            attestedSnapshotHash := mload(add(payload, 160))
            attestedValidatorSetHash := mload(add(payload, 192))
            attestedRegistryRoot := mload(add(payload, 224))
            attestedDelegationRoot := mload(add(payload, 256))
        }

        // Verify the summary fields match the function parameters
        bytes memory expectedPayload = abi.encode(
            epoch, totalRewards, merkleRoot, protocolFee,
            attestedSnapshotHash, attestedValidatorSetHash,
            attestedRegistryRoot, attestedDelegationRoot
        );
        if (keccak256(payload) != keccak256(expectedPayload)) revert InvalidAttestation();

        // Verify the stake snapshot hash against the epoch-scoped commitment.
        // epochSnapshots[epoch].stakeSnapshotHash is set by commitStakeSnapshot()
        // and is immutable once committed, preventing mid-epoch manipulation.
        // This mirrors the validator set hash pattern where the on-chain epoch
        // snapshot is the single source of truth for cross-layer verification.
        if (attestedSnapshotHash != epochSnapshots[epoch].stakeSnapshotHash) {
            revert StakeSnapshotMismatch(attestedSnapshotHash, epochSnapshots[epoch].stakeSnapshotHash);
        }

        // Verify the TEE-attested staker registry root against the on-chain
        // XOR accumulator captured at commitStakeSnapshot() time.  This proves
        // the TEE computed rewards from the actual on-chain staker set rather
        // than a relayer-fabricated list.
        if (attestedRegistryRoot != epochSnapshots[epoch].stakerRegistryRoot) {
            revert RegistryRootMismatch(attestedRegistryRoot, epochSnapshots[epoch].stakerRegistryRoot);
        }

        // Verify the TEE-attested delegation registry root against the
        // epoch-scoped commitment set by commitDelegationSnapshot().  This
        // proves the TEE used the same delegation topology that the native
        // keeper committed, preventing a relayer from altering which
        // validator each staker delegated to (which drives performance-
        // weighted reward allocation).
        //
        // Delegation is native-chain state that the EVM cannot independently
        // derive.  The commitment is sourced from the Go native keeper, which
        // computes it from native-chain delegation records.  This check
        // ensures the TEE-attested value matches the keeper-committed value.
        if (attestedDelegationRoot != epochSnapshots[epoch].delegationRegistryRoot) {
            revert DelegationRootMismatch(attestedDelegationRoot, epochSnapshots[epoch].delegationRegistryRoot);
        }

        // Enforce the optimistic challenge period for non-zero delegation roots.
        // This gives off-chain watchers time to verify the keeper's commitment
        // against native-chain delegation state and request guardian revocation
        // before the committed root is consumed in reward distribution.
        // When delegationRegistryRoot is bytes32(0) (no delegation data), the
        // challenge period is skipped — there is nothing to dispute.
        if (epochSnapshots[epoch].delegationRegistryRoot != bytes32(0)) {
            uint256 commitTs = delegationCommitTimestamp[epoch];
            uint256 availableAt = commitTs + DELEGATION_CHALLENGE_PERIOD;
            if (block.timestamp < availableAt) {
                revert DelegationChallengePeriodActive(epoch, availableAt);
            }

            // Staleness guard: reject delegation commitments older than
            // DELEGATION_MAX_AGE.  This prevents a compromised keeper from
            // committing a valid delegation root early in the epoch (passing
            // the challenge period), then altering native delegation state
            // before reward distribution.  The keeper must re-commit a fresh
            // TEE attestation close to reward distribution time, minimizing
            // the window for delegation state drift.
            uint256 maxAge = commitTs + DELEGATION_MAX_AGE;
            if (block.timestamp > maxAge) {
                revert DelegationCommitmentStale(epoch, commitTs, DELEGATION_MAX_AGE);
            }
        }

        // Verify the validator set hash against the on-chain epoch snapshot.
        // epochSnapshots[epoch].validatorSetHash is set by updateValidatorSet()
        // and represents the TEE-verified canonical validator set that was
        // actually activated on-chain. Checking against this authoritative
        // value (rather than a separately mutable admin commitment) ensures
        // the reward engine used exactly the validator scores the contract
        // already accepted, with no additional trust boundary.
        if (attestedValidatorSetHash != epochSnapshots[epoch].validatorSetHash) {
            revert ValidatorSetHashMismatch(attestedValidatorSetHash, epochSnapshots[epoch].validatorSetHash);
        }

        // Verify protocol fee matches the deterministic formula exactly.
        // Both the Rust TEE worker (reward_calculator.rs) and this contract
        // compute the fee from the same integer expression:
        //   fee = totalRewards * PROTOCOL_FEE_BPS / BPS_DENOMINATOR
        // There is no cross-runtime rounding gap, so exact equality is required.
        // Any deviation indicates a buggy or manipulated attester attempting to
        // overcharge protocol fees and reduce claimable rewards for stakers.
        uint256 expectedFee = (totalRewards * PROTOCOL_FEE_BPS) / BPS_DENOMINATOR;
        if (protocolFee != expectedFee) {
            revert ProtocolFeeMismatch(protocolFee, expectedFee);
        }

        // Ingest reward tokens: caller must have approved vault for totalRewards.
        // This ensures all Merkle claims are backed by actual tokens held in the vault.
        aethelToken.safeTransferFrom(msg.sender, address(this), totalRewards);

        // Reserve net rewards (totalRewards - protocolFee) for this epoch's Merkle claims
        uint256 netRewards = totalRewards - protocolFee;
        epochReservedForClaims[epoch] = netRewards;
        totalReservedForClaims += netRewards;

        // Transfer protocol fee to treasury
        if (protocolFee > 0 && treasury != address(0)) {
            aethelToken.safeTransfer(treasury, protocolFee);
        }

        // Finalize epoch snapshot.
        // Preserve fields that were already written to the snapshot before
        // finalization: validatorSetHash (set by updateValidatorSet),
        // eligibleUniverseHash (set by commitUniverseHash),
        // stakeSnapshotHash (set by commitStakeSnapshot),
        // stakerRegistryRoot (captured by commitStakeSnapshot),
        // delegationRegistryRoot (set by commitDelegationSnapshot), and
        // mevRedistributed (accumulated by submitMEVRevenue).
        epochSnapshots[epoch] = EpochSnapshot({
            totalPooledAethel: totalPooledAethel,
            totalShares: stAethelToken.getTotalShares(),
            rewardsDistributed: totalRewards,
            mevRedistributed: epochSnapshots[epoch].mevRedistributed,
            protocolFee: protocolFee,
            rewardsMerkleRoot: merkleRoot,
            validatorSetHash: epochSnapshots[epoch].validatorSetHash,
            eligibleUniverseHash: epochSnapshots[epoch].eligibleUniverseHash,
            stakeSnapshotHash: epochSnapshots[epoch].stakeSnapshotHash,
            stakerRegistryRoot: epochSnapshots[epoch].stakerRegistryRoot,
            delegationRegistryRoot: epochSnapshots[epoch].delegationRegistryRoot,
            teeAttestationHash: keccak256(teeAttestation),
            timestamp: block.timestamp,
            finalized: true
        });

        emit RewardsDistributed(epoch, totalRewards, protocolFee, merkleRoot, keccak256(teeAttestation));

        // Advance epoch
        _advanceEpoch();
    }

    /// @inheritdoc ICruzible
    function submitMEVRevenue(
        bytes calldata teeAttestation,
        uint256 epoch,
        uint256 mevAmount
    ) external onlyRole(ORACLE_ROLE) whenNotPaused {
        if (epoch != currentEpoch) revert InvalidEpoch(epoch, currentEpoch);

        // Verify TEE attestation and bind parameters to attested payload
        (bool valid, bytes memory payload,) = teeVerifier.verifyAttestation(teeAttestation);
        if (!valid) revert InvalidAttestation();
        bytes memory expectedPayload = abi.encode(epoch, mevAmount);
        if (keccak256(payload) != keccak256(expectedPayload)) revert InvalidAttestation();

        // Ingest MEV tokens: caller must have approved vault for mevAmount.
        // This ensures the exchange rate inflation is backed by real assets.
        aethelToken.safeTransferFrom(msg.sender, address(this), mevAmount);

        // Split MEV revenue: 90% to stakers, 10% to protocol
        uint256 stakerShare = (mevAmount * MEV_STAKER_SHARE_BPS) / BPS_DENOMINATOR;
        uint256 protocolShare = mevAmount - stakerShare;

        // Staker share increases total pooled (auto-compounds via exchange rate)
        totalPooledAethel += stakerShare;
        stAethelToken.setTotalPooledAethel(totalPooledAethel);

        // Protocol share to treasury
        if (protocolShare > 0 && treasury != address(0)) {
            aethelToken.safeTransfer(treasury, protocolShare);
        }

        totalMEVRevenue += mevAmount;
        epochSnapshots[epoch].mevRedistributed += mevAmount;

        emit MEVRedistributed(epoch, mevAmount, stakerShare, protocolShare);
    }

    /**
     * @notice Verify a reward claim using the epoch's Merkle tree.
     * @param epoch The epoch to claim from.
     * @param account The account claiming rewards.
     * @param amount The claimed reward amount.
     * @param proof The Merkle proof.
     * @return valid Whether the claim is valid.
     */
    function verifyRewardClaim(
        uint256 epoch,
        address account,
        uint256 amount,
        bytes32[] calldata proof
    ) external view returns (bool valid) {
        if (!epochSnapshots[epoch].finalized) return false;

        bytes32 leaf = sha256(bytes.concat(sha256(abi.encode(account, amount, epoch))));
        return _verifySHA256Proof(proof, epochSnapshots[epoch].rewardsMerkleRoot, leaf);
    }

    /**
     * @notice Claim individual rewards from a finalized epoch using Merkle proof.
     * @param epoch The epoch to claim from.
     * @param amount The reward amount to claim.
     * @param proof The Merkle proof for the claim.
     */
    function claimRewards(
        uint256 epoch,
        uint256 amount,
        bytes32[] calldata proof
    ) external nonReentrant {
        if (!epochSnapshots[epoch].finalized) revert EpochNotFinalized(epoch);
        if (rewardsClaimed[msg.sender][epoch]) {
            revert RewardsAlreadyClaimed(msg.sender, epoch);
        }

        bytes32 leaf = sha256(bytes.concat(sha256(abi.encode(msg.sender, amount, epoch))));
        if (!_verifySHA256Proof(proof, epochSnapshots[epoch].rewardsMerkleRoot, leaf)) {
            revert InvalidMerkleProof();
        }

        rewardsClaimed[msg.sender][epoch] = true;

        // Decrement the epoch-specific reserve and global total
        require(epochReservedForClaims[epoch] >= amount, "Claim exceeds epoch reserved rewards");
        epochReservedForClaims[epoch] -= amount;
        totalReservedForClaims -= amount;
        aethelToken.safeTransfer(msg.sender, amount);
    }

    /**
     * @dev Verify a SHA-256 Merkle proof. Replaces OpenZeppelin's keccak256-based
     *      MerkleProof.verify() to match the Aethelred protocol SHA-256 standard.
     * @param proof The sibling hashes from leaf to root.
     * @param root The expected Merkle root.
     * @param leaf The leaf hash to verify.
     * @return Whether the proof is valid.
     */
    function _verifySHA256Proof(
        bytes32[] calldata proof,
        bytes32 root,
        bytes32 leaf
    ) private pure returns (bool) {
        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            if (computedHash <= proof[i]) {
                computedHash = sha256(abi.encodePacked(computedHash, proof[i]));
            } else {
                computedHash = sha256(abi.encodePacked(proof[i], computedHash));
            }
        }
        return computedHash == root;
    }

    // =========================================================================
    // TEE ATTESTATION VERIFICATION
    // =========================================================================

    /// @inheritdoc ICruzible
    function verifyAttestation(bytes calldata attestation)
        external
        view
        returns (bool valid, bytes memory payload, uint8 platform)
    {
        return teeVerifier.verifyAttestationView(attestation);
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /// @inheritdoc ICruzible
    function getExchangeRate() external view returns (uint256) {
        uint256 totalShares = stAethelToken.getTotalShares();
        if (totalShares == 0) return 1e18;
        return (totalPooledAethel * 1e18) / totalShares;
    }

    /// @inheritdoc ICruzible
    function getTotalPooledAethel() external view returns (uint256) {
        return totalPooledAethel;
    }

    /// @inheritdoc ICruzible
    function getTotalShares() external view returns (uint256) {
        return stAethelToken.getTotalShares();
    }

    /// @inheritdoc ICruzible
    function getSharesForAethel(uint256 aethelAmount) external view returns (uint256) {
        return stAethelToken.getSharesByAethel(aethelAmount);
    }

    /// @inheritdoc ICruzible
    function getAethelForShares(uint256 shares) external view returns (uint256) {
        return stAethelToken.getAethelByShares(shares);
    }

    /// @inheritdoc ICruzible
    function getCurrentEpoch() external view returns (uint256) {
        return currentEpoch;
    }

    /// @inheritdoc ICruzible
    function getActiveValidatorCount() external view returns (uint256) {
        return activeValidators.length;
    }

    /// @inheritdoc ICruzible
    function isWithdrawalClaimable(uint256 withdrawalId) external view returns (bool) {
        WithdrawalRequest storage request = withdrawalRequests[withdrawalId];
        return !request.claimed && block.timestamp >= request.completionTime && request.owner != address(0);
    }

    /**
     * @notice Get the effective APY based on last epoch's net staker yield.
     * @dev Uses net amounts that actually accrued to stakers, excluding
     *      protocol fees and MEV protocol share sent to treasury:
     *        - Net rewards  = rewardsDistributed − protocolFee
     *        - Net MEV      = mevRedistributed × MEV_STAKER_SHARE_BPS / BPS_DENOMINATOR
     *      This prevents overstating yield by counting treasury cuts as user returns.
     * @return apy Annual percentage yield scaled by 1e4 (e.g., 1000 = 10%).
     */
    function getEffectiveAPY() external view returns (uint256 apy) {
        if (currentEpoch <= 1 || totalPooledAethel == 0) return 0;

        EpochSnapshot storage lastEpoch = epochSnapshots[currentEpoch - 1];
        if (!lastEpoch.finalized) return 0;

        // Net staker yield = claimable rewards + auto-compounded MEV staker share.
        uint256 netRewards = lastEpoch.rewardsDistributed - lastEpoch.protocolFee;
        uint256 netMEV = (lastEpoch.mevRedistributed * MEV_STAKER_SHARE_BPS) / BPS_DENOMINATOR;
        uint256 epochYield = netRewards + netMEV;

        // APY = (epochYield / totalPooled) * 365 * 10000
        uint256 dailyRate = (epochYield * 1e18) / lastEpoch.totalPooledAethel;
        apy = (dailyRate * 365 * 10000) / 1e18;
    }

    /**
     * @notice Get a validator's full information.
     */
    function getValidator(address validatorAddress)
        external
        view
        returns (ValidatorInfo memory)
    {
        return validators[validatorAddress];
    }

    /**
     * @notice Get all active validator addresses.
     */
    function getActiveValidators() external view returns (address[] memory) {
        return activeValidators;
    }

    /**
     * @notice Get a user's pending withdrawal requests.
     */
    function getUserWithdrawals(address user) external view returns (uint256[] memory) {
        return userWithdrawals[user];
    }

    /**
     * @notice Get epoch snapshot for verification.
     */
    function getEpochSnapshot(uint256 epoch) external view returns (EpochSnapshot memory) {
        return epochSnapshots[epoch];
    }

    /**
     * @notice Get the list of attestors who voted in a given epoch's delegation quorum.
     */
    function getDelegationEpochAttestors(uint256 epoch) external view returns (address[] memory) {
        return delegationEpochAttestors[epoch];
    }

    /**
     * @notice Get the vault's available balance (excluding pending withdrawals
     *         AND reserved-but-unclaimed Merkle reward claims).
     */
    function getAvailableBalance() external view returns (uint256) {
        uint256 balance = aethelToken.balanceOf(address(this));
        uint256 committed = totalPendingWithdrawals + totalReservedForClaims;
        if (balance <= committed) return 0;
        return balance - committed;
    }

    // =========================================================================
    // ADMIN FUNCTIONS
    // =========================================================================

    /**
     * @notice Update the TEE verifier contract.
     */
    function setTEEVerifier(address newVerifier) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newVerifier == address(0)) revert ZeroAddress();
        teeVerifier = VaultTEEVerifier(newVerifier);
    }

    /**
     * @notice Update the treasury address.
     */
    function setTreasury(address newTreasury) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newTreasury == address(0)) revert ZeroAddress();
        treasury = newTreasury;
    }

    /**
     * @notice Emergency: Slash a validator's reputation after misconduct.
     * @param validator The validator address to slash.
     * @param reason The reason for the slash.
     */
    function slashValidator(address validator, string calldata reason)
        external
        onlyRole(GUARDIAN_ROLE)
    {
        ValidatorInfo storage info = validators[validator];
        if (!info.isActive) revert ValidatorNotActive(validator);

        info.slashCount++;
        info.isActive = false;

        // Remove from active set
        for (uint256 i = 0; i < activeValidators.length; i++) {
            if (activeValidators[i] == validator) {
                activeValidators[i] = activeValidators[activeValidators.length - 1];
                activeValidators.pop();
                break;
            }
        }

        emit ValidatorDeactivated(validator, reason);
    }

    /**
     * @notice Set the canonical selection policy hash that the TEE worker must use.
     * @dev Only governance (DEFAULT_ADMIN_ROLE) can change the approved policy.
     *      The hash must match compute_selection_policy_hash() in the Rust TEE worker
     *      and computeSelectionPolicyHash() in the Go keeper.
     * @param policyHash The SHA-256 hash of the canonical selection policy parameters.
     */
    function setSelectionPolicyHash(bytes32 policyHash) external onlyRole(DEFAULT_ADMIN_ROLE) {
        selectionPolicyHash = policyHash;
        emit SelectionPolicyUpdated(policyHash);
    }

    /**
     * @notice Commit the eligible-universe hash for a specific epoch.
     * @dev Only the native keeper (KEEPER_ROLE) can commit the universe hash.
     *      The commitment is epoch-scoped and immutable once set, preventing:
     *        1. Stale universe reuse across epochs (epoch must match currentEpoch).
     *        2. Mid-epoch universe manipulation (cannot overwrite once committed).
     *        3. Keeper choosing a different universe for past/future epochs.
     *
     *      updateValidatorSet() verifies the TEE-attested universe hash against
     *      this committed value, ensuring the relayer did not truncate the
     *      candidate list when submitting to the TEE worker.
     *
     *      Cross-layer note: the Go native keeper independently recomputes the
     *      universe from on-chain telemetry (computeEligibleUniverseHash in
     *      keeper.go).  This EVM commitment provides an equivalent independent
     *      source for the EVM path.
     *
     * @param epoch The epoch number this universe applies to (must be currentEpoch).
     * @param universeHash The SHA-256 hash of the canonical eligible universe.
     */
    function commitUniverseHash(uint256 epoch, bytes32 universeHash) external onlyRole(KEEPER_ROLE) {
        if (epoch != currentEpoch) revert InvalidEpoch(epoch, currentEpoch);
        if (epochSnapshots[epoch].eligibleUniverseHash != bytes32(0)) {
            revert UniverseHashAlreadyCommitted(epoch);
        }
        epochSnapshots[epoch].eligibleUniverseHash = universeHash;
        emit EligibleUniverseHashCommitted(epoch, universeHash);
    }

    /**
     * @notice Commit the stake snapshot hash for a specific epoch's reward distribution.
     * @dev Only the native keeper (KEEPER_ROLE) can commit the snapshot hash.
     *      The commitment is epoch-scoped and immutable once set, mirroring the
     *      validator set hash pattern. This prevents:
     *        1. Stale snapshot reuse across epochs (epoch must match currentEpoch).
     *        2. Mid-epoch snapshot manipulation (cannot overwrite once committed).
     *        3. Keeper choosing reward recipients for past/future epochs.
     *
     *      The hash must match the SHA-256 of domain-separated sorted staker
     *      records, identical to the Rust TEE's compute_stake_snapshot_hash().
     *
     *      The caller must also supply the total share supply used to produce
     *      the snapshot.  This value is verified against the on-chain aggregate
     *      (stAethelToken.getTotalShares()) to ensure the committed hash is
     *      anchored to the live EVM state rather than being an arbitrary value.
     *
     *      Additionally, the contract captures the stAETHEL XOR staker-registry
     *      root at commit time.  This accumulator encodes the exact per-staker
     *      share distribution and is later verified against the TEE attestation
     *      in distributeRewards(), proving the TEE computed rewards from the
     *      correct on-chain staker set (not a relayer-fabricated list).
     *
     * @param epoch The epoch number this snapshot applies to (must be currentEpoch).
     * @param snapshotHash The SHA-256 hash of the canonical stake snapshot.
     * @param totalSharesAtSnapshot The total stAETHEL share supply used when
     *        building the snapshot — must equal stAethelToken.getTotalShares().
     */
    function commitStakeSnapshot(
        uint256 epoch,
        bytes32 snapshotHash,
        uint256 totalSharesAtSnapshot
    ) external onlyRole(KEEPER_ROLE) {
        if (epoch != currentEpoch) revert InvalidEpoch(epoch, currentEpoch);
        if (epochSnapshots[epoch].stakeSnapshotHash != bytes32(0)) {
            revert StakeSnapshotAlreadyCommitted(epoch);
        }
        uint256 onChainTotalShares = stAethelToken.getTotalShares();
        if (totalSharesAtSnapshot != onChainTotalShares) {
            revert SnapshotSharesMismatch(totalSharesAtSnapshot, onChainTotalShares);
        }
        epochSnapshots[epoch].stakeSnapshotHash = snapshotHash;

        // Capture the per-staker XOR accumulator from stAETHEL.  This value
        // is independently derived from live on-chain share balances and
        // cannot be influenced by the keeper.  distributeRewards() will later
        // verify the TEE attestation includes the same root.
        epochSnapshots[epoch].stakerRegistryRoot = stAethelToken.stakerRegistryRoot();

        emit StakeSnapshotCommitted(epoch, snapshotHash, totalSharesAtSnapshot);
    }

    /**
     * @notice Commit the delegation registry root for a specific epoch.
     * @dev Only the native keeper (KEEPER_ROLE) can commit the delegation root.
     *      The commitment is epoch-scoped and immutable once set, mirroring the
     *      stakeSnapshotHash pattern. This prevents:
     *        1. Stale delegation reuse across epochs (epoch must match currentEpoch).
     *        2. Mid-epoch delegation manipulation (cannot overwrite once committed).
     *        3. Keeper choosing different delegations for past/future epochs.
     *
     *      Ordering constraint: commitStakeSnapshot() must be called first for
     *      this epoch.  The stake snapshot anchors the staker set (via the
     *      on-chain stakerRegistryRoot XOR accumulator), and the delegation root
     *      is built from the same set of stakers.  Requiring the caller to pass
     *      the stakerRegistryRoot and verifying it matches the on-chain value
     *      ensures the delegation root was derived from the same staker
     *      universe the EVM already verified.
     *
     *      The delegation registry root is an XOR accumulator of
     *      keccak256(staker_address, delegated_to) for every staker with
     *      non-zero shares.  Delegation is native-chain state that the EVM
     *      cannot independently derive — the value is sourced from the Go
     *      native keeper which computes it from native-chain delegation records.
     *
     *      To remove the single-keeper trust assumption, the commitment
     *      MUST include a TEE attestation proving the enclave independently
     *      read native-chain delegation state and computed the same root.
     *      The attestation payload is 96 bytes:
     *        abi.encode(epoch, delegationRoot, stakerRegistryRoot)
     *      binding the TEE's independent computation to this specific epoch
     *      and staker set.  This gives the EVM the same TEE-backed assurance
     *      for delegation state as it already has for validator selection
     *      (updateValidatorSet) and reward distribution (distributeRewards).
     *
     * @param teeAttestation The TEE attestation proving the enclave independently
     *        verified the delegation root against native-chain state.
     * @param epoch The epoch number this delegation root applies to (must be currentEpoch).
     * @param delegationRoot The XOR delegation registry root from the native keeper.
     * @param stakerRegistryRoot The staker registry root that the keeper used
     *        to identify the staker set — must equal the on-chain value captured
     *        by commitStakeSnapshot().
     * @param stakerCount Number of stakers with non-zero shares in the delegation
     *        snapshot.  Stored as a cardinality anchor for off-chain monitors
     *        that compare against the native-chain staker count to detect omissions.
     *        Must be non-zero when delegationRoot is non-zero.
     */
    function commitDelegationSnapshot(
        bytes calldata teeAttestation,
        uint256 epoch,
        bytes32 delegationRoot,
        bytes32 stakerRegistryRoot,
        uint256 stakerCount
    ) external onlyRole(KEEPER_ROLE) {
        // When quorum mode is enabled, the single-keeper direct-commit path
        // is disabled.  Delegation must go through submitDelegationVote().
        if (delegationQuorumEnabled) revert DelegationQuorumRequired(epoch);

        // Require the keeper to have posted a bond.  This creates an economic
        // deterrent against false delegation commitments: the guardian can
        // slash the bond if fraud is proven during the challenge period.
        if (keeperBonds[msg.sender] < KEEPER_BOND_MINIMUM) {
            revert InsufficientKeeperBond(keeperBonds[msg.sender], KEEPER_BOND_MINIMUM);
        }

        // Record the committer so withdrawKeeperBond() can lock their bond
        // during the challenge/adjudication window — mirroring the lock that
        // delegationAttestorVoted provides for the quorum path.
        delegationCommitter[epoch] = msg.sender;

        _commitDelegationSnapshotInternal(teeAttestation, epoch, delegationRoot, stakerRegistryRoot, stakerCount);
    }

    /**
     * @notice Submit a delegation vote as an independent attestor.
     * @dev Part of the multi-attestor quorum flow.  Each attestor independently
     *      runs their own Go keeper connected to the native chain and their own
     *      TEE instance.  When DELEGATION_QUORUM attestors agree on the same
     *      delegation root, the root is automatically committed.
     *
     *      This distributes trust across multiple independent operators: no
     *      single keeper can fabricate delegation state.
     *
     *      Requires the caller to have DELEGATION_ATTESTOR_ROLE and a bond of
     *      at least KEEPER_BOND_MINIMUM.
     *
     * @param teeAttestation The TEE attestation from this attestor's enclave.
     * @param epoch The epoch number (must be currentEpoch).
     * @param delegationRoot The delegation registry root this attestor computed.
     * @param stakerRegistryRoot The staker registry root used to build the delegation.
     * @param stakerCount Number of stakers in the delegation snapshot.
     */
    function submitDelegationVote(
        bytes calldata teeAttestation,
        uint256 epoch,
        bytes32 delegationRoot,
        bytes32 stakerRegistryRoot,
        uint256 stakerCount
    ) external onlyRole(DELEGATION_ATTESTOR_ROLE) {
        if (epoch != currentEpoch) revert InvalidEpoch(epoch, currentEpoch);

        // Reject if the delegation root is already committed (quorum already
        // reached, or committed via the single-keeper path before quorum was enabled).
        if (epochSnapshots[epoch].delegationRegistryRoot != bytes32(0)) {
            revert DelegationSnapshotAlreadyCommitted(epoch);
        }

        // Require attestor bond.
        if (keeperBonds[msg.sender] < KEEPER_BOND_MINIMUM) {
            revert InsufficientKeeperBond(keeperBonds[msg.sender], KEEPER_BOND_MINIMUM);
        }

        // Each attestor votes once per epoch.
        if (delegationAttestorVoted[epoch][msg.sender]) {
            revert DelegationAttestorAlreadyVoted(epoch, msg.sender);
        }

        // Run the same validation as the direct-commit path (stake snapshot
        // committed, registry root anchor, TEE attestation, cardinality).
        _validateDelegationSnapshot(teeAttestation, epoch, delegationRoot, stakerRegistryRoot, stakerCount);

        // Record the vote and track the attestor for potential bond freezing.
        delegationAttestorVoted[epoch][msg.sender] = true;
        delegationEpochAttestors[epoch].push(msg.sender);
        uint256 votes = ++delegationVoteCount[epoch][delegationRoot];
        emit DelegationVoteSubmitted(epoch, msg.sender, delegationRoot, votes);

        // When quorum is reached, auto-commit.
        if (votes >= DELEGATION_QUORUM) {
            epochSnapshots[epoch].delegationRegistryRoot = delegationRoot;
            delegationCommitTimestamp[epoch] = block.timestamp;
            delegatingStakerCount[epoch] = stakerCount;
            emit DelegationQuorumReached(epoch, delegationRoot, votes);
            emit DelegationSnapshotCommitted(epoch, delegationRoot);
        }
    }

    /**
     * @notice Revoke a delegation root commitment during the challenge period.
     * @dev Only the guardian (GUARDIAN_ROLE) can revoke.  This is the safety
     *      valve for the optimistic delegation commitment model: off-chain
     *      watchers compare the committed root against native-chain delegation
     *      state and, if they detect a discrepancy, request the guardian to
     *      revoke before the challenge period expires and distributeRewards()
     *      can consume the commitment.
     *
     *      Guardian revocation is an explicit fraud determination:
     *        - Challenger bonds become refundable.
     *        - The committing keeper/attestors' bonds are frozen until
     *          the guardian slashes or explicitly releases them via
     *          releaseKeeperBondFreeze().
     *
     *      After revocation, the keeper can re-commit a corrected root via
     *      commitDelegationSnapshot() (the slot is cleared back to bytes32(0)).
     *
     * @param epoch The epoch whose delegation commitment should be revoked.
     */
    function revokeDelegationSnapshot(uint256 epoch) external onlyRole(GUARDIAN_ROLE) {
        if (epoch != currentEpoch) revert InvalidEpoch(epoch, currentEpoch);
        if (epochSnapshots[epoch].delegationRegistryRoot == bytes32(0)) {
            revert DelegationNotCommitted(epoch);
        }
        if (epochSnapshots[epoch].finalized) revert InvalidEpoch(epoch, currentEpoch);

        // Freeze the submitting keeper/attestors' bonds before clearing the
        // commitment, so they cannot front-run slashKeeperBond() by
        // withdrawing in the same block.
        _freezeDelegationSubmitters(epoch);

        _clearDelegationCommitment(epoch);
        // Guardian revocation is an explicit fraud confirmation — challengers
        // who flagged this commitment were correct and get bonds refunded.
        delegationChallengeSucceeded[epoch] = true;
        emit DelegationSnapshotRevoked(epoch);
    }

    // =========================================================================
    // KEEPER BOND
    // =========================================================================

    /**
     * @notice Deposit AETHEL as a keeper bond.
     * @dev Any address can deposit a bond.  The bond must be at least
     *      KEEPER_BOND_MINIMUM before the depositor can commit delegation
     *      snapshots.  Bonds are slashable by the guardian if delegation
     *      fraud is proven during the challenge period.
     *
     *      Callers must approve this contract for `amount` AETHEL first.
     *
     * @param amount The amount of AETHEL to deposit as bond.
     */
    function depositKeeperBond(uint256 amount) external {
        if (amount == 0) revert ZeroAmount();
        aethelToken.safeTransferFrom(msg.sender, address(this), amount);
        keeperBonds[msg.sender] += amount;
        totalKeeperBonds += amount;
        emit KeeperBondDeposited(msg.sender, amount, keeperBonds[msg.sender]);
    }

    /**
     * @notice Withdraw keeper bond.
     * @dev Only callable when the keeper has no pending delegation commitment
     *      in the current epoch's challenge/adjudication window.  This prevents
     *      keepers from withdrawing their bond immediately after committing
     *      false data, ensuring the bond is available for guardian slashing.
     *
     *      The lock applies to both delegation paths:
     *        - Single-keeper: tracked by delegationCommitter[epoch]
     *        - Multi-attestor quorum: tracked by delegationAttestorVoted[epoch]
     *
     * @param amount The amount of AETHEL to withdraw.
     */
    function withdrawKeeperBond(uint256 amount) external {
        if (amount == 0) revert ZeroAmount();
        if (keeperBonds[msg.sender] < amount) {
            revert BondWithdrawalExceedsDeposit(amount, keeperBonds[msg.sender]);
        }

        // Hard freeze: bond is locked by guardian fraud determination until
        // slashed or explicitly released.
        if (keeperBondFrozen[msg.sender]) {
            revert KeeperBondIsFrozen(msg.sender);
        }

        // Soft lock: prevent withdrawal while the caller has a pending
        // delegation commitment in the challenge window for the current epoch.
        // This ensures the bond is available for slashing during the
        // entire challenge period and any subsequent adjudication period.
        uint256 epoch = currentEpoch;
        bool hasUnfinalizedCommitment = epochSnapshots[epoch].delegationRegistryRoot != bytes32(0)
            && !epochSnapshots[epoch].finalized;
        // Also lock if the commitment was auto-revoked and adjudication is pending.
        bool adjudicationPending = delegationAutoRevokedAt[epoch] > 0
            && !delegationChallengeSucceeded[epoch]
            && block.timestamp <= delegationAutoRevokedAt[epoch] + CHALLENGE_ADJUDICATION_PERIOD;

        bool callerCommitted = delegationAttestorVoted[epoch][msg.sender]
            || delegationCommitter[epoch] == msg.sender;

        if (callerCommitted && (hasUnfinalizedCommitment || adjudicationPending)) {
            revert KeeperBondLocked();
        }

        keeperBonds[msg.sender] -= amount;
        totalKeeperBonds -= amount;
        aethelToken.safeTransfer(msg.sender, amount);
        emit KeeperBondWithdrawn(msg.sender, amount, keeperBonds[msg.sender]);
    }

    /**
     * @notice Slash a keeper's bond for delegation fraud.
     * @dev Only the guardian (GUARDIAN_ROLE) can slash.  Transfers the slashed
     *      amount to the specified recipient (typically the treasury or a
     *      challenger reward pool).
     *
     *      This is the economic enforcement layer for the delegation bridge:
     *      a keeper who submits a false delegation commitment during the
     *      challenge period can have their bond seized.
     *
     * @param keeper The address whose bond to slash.
     * @param amount The amount of AETHEL to slash.
     * @param recipient Where to send the slashed funds.
     */
    function slashKeeperBond(
        address keeper,
        uint256 amount,
        address recipient
    ) external onlyRole(GUARDIAN_ROLE) {
        if (recipient == address(0)) revert ZeroAddress();
        if (keeperBonds[keeper] < amount) {
            revert BondWithdrawalExceedsDeposit(amount, keeperBonds[keeper]);
        }
        keeperBonds[keeper] -= amount;
        totalKeeperBonds -= amount;
        // Clear the freeze — slashing is the resolution of the fraud
        // determination and the keeper's remaining bond (if any) is released.
        if (keeperBondFrozen[keeper]) {
            keeperBondFrozen[keeper] = false;
            emit KeeperBondUnfrozen(keeper);
        }
        aethelToken.safeTransfer(recipient, amount);
        emit KeeperBondSlashed(keeper, amount, recipient);
    }

    /**
     * @notice Release a keeper's bond freeze without slashing.
     * @dev Only the guardian can release.  Used when a delegation revocation
     *      was precautionary but investigation found no fraud, or after the
     *      guardian decides not to slash.
     *
     * @param keeper The address whose bond freeze to release.
     */
    function releaseKeeperBondFreeze(address keeper) external onlyRole(GUARDIAN_ROLE) {
        if (!keeperBondFrozen[keeper]) revert KeeperBondNotFrozen(keeper);
        keeperBondFrozen[keeper] = false;
        emit KeeperBondUnfrozen(keeper);
    }

    // =========================================================================
    // PERMISSIONLESS DELEGATION CHALLENGE
    // =========================================================================

    /**
     * @notice Flag a delegation commitment during the challenge period.
     * @dev Each address can flag once per epoch by posting CHALLENGE_BOND
     *      AETHEL as a slashable bond.  When the flag count reaches
     *      DELEGATION_CHALLENGE_THRESHOLD, the commitment is auto-revoked
     *      as a circuit-breaker safety measure.
     *
     *      Auto-revocation does NOT confirm fraud.  Challenger bonds are
     *      held pending guardian adjudication:
     *        - If the guardian calls confirmDelegationFraud() within
     *          CHALLENGE_ADJUDICATION_PERIOD → bonds are refunded.
     *        - If the adjudication period expires without confirmation →
     *          bonds are slashed to the treasury (presumption of validity).
     *
     *      This makes griefing cost the full bond amount per challenger,
     *      not just temporary capital lock.
     *
     *      Callers must approve this contract for CHALLENGE_BOND AETHEL first.
     *
     * @param epoch The epoch whose delegation commitment to challenge.
     */
    function challengeDelegationCommitment(uint256 epoch) external {
        if (epoch != currentEpoch) revert InvalidEpoch(epoch, currentEpoch);

        // Can only challenge a committed (non-zero) delegation root that
        // is still in the challenge window (not yet consumed by distributeRewards).
        if (epochSnapshots[epoch].delegationRegistryRoot == bytes32(0)) {
            revert DelegationNotCommitted(epoch);
        }
        if (epochSnapshots[epoch].finalized) revert InvalidEpoch(epoch, currentEpoch);

        // Challenge must be during the challenge period (between commitment
        // and commitment + DELEGATION_CHALLENGE_PERIOD).
        uint256 commitTs = delegationCommitTimestamp[epoch];
        uint256 challengeDeadline = commitTs + DELEGATION_CHALLENGE_PERIOD;
        if (block.timestamp > challengeDeadline) {
            revert ChallengeOutsidePeriod(epoch);
        }

        // Each address can flag once per epoch.
        if (delegationChallengers[epoch][msg.sender]) {
            revert AlreadyChallenged(epoch, msg.sender);
        }

        // Transfer the challenger bond into the vault.
        aethelToken.safeTransferFrom(msg.sender, address(this), CHALLENGE_BOND);
        challengerBonds[epoch][msg.sender] = CHALLENGE_BOND;
        totalChallengerBonds += CHALLENGE_BOND;

        delegationChallengers[epoch][msg.sender] = true;
        uint256 challenges = ++delegationChallengeCount[epoch];
        emit DelegationChallenged(epoch, msg.sender, challenges);

        // Auto-revoke if threshold reached (circuit-breaker, NOT fraud confirmation).
        if (challenges >= DELEGATION_CHALLENGE_THRESHOLD) {
            _clearDelegationCommitment(epoch);
            delegationAutoRevokedAt[epoch] = block.timestamp;
            emit DelegationAutoRevoked(epoch, challenges);
        }
    }

    /**
     * @notice Confirm that an auto-revoked delegation commitment was
     *         genuinely fraudulent, releasing challenger bonds for refund.
     * @dev Only the guardian (GUARDIAN_ROLE) can confirm.  Must be called
     *      within CHALLENGE_ADJUDICATION_PERIOD of the auto-revocation.
     *
     *      Also freezes the submitting keeper/attestors' bonds so they
     *      cannot withdraw before slashing executes.
     *
     *      Without this confirmation, auto-revocation is treated as a
     *      griefing attack and challenger bonds are slashed when claimed.
     *
     * @param epoch The epoch whose auto-revocation to confirm as fraud.
     */
    function confirmDelegationFraud(uint256 epoch) external onlyRole(GUARDIAN_ROLE) {
        uint256 revokedAt = delegationAutoRevokedAt[epoch];
        if (revokedAt == 0) revert NotAutoRevoked(epoch);

        if (block.timestamp > revokedAt + CHALLENGE_ADJUDICATION_PERIOD) {
            revert AdjudicationPeriodExpired(epoch);
        }

        // Freeze the submitting keeper/attestors' bonds.
        _freezeDelegationSubmitters(epoch);

        delegationChallengeSucceeded[epoch] = true;
        emit DelegationFraudConfirmed(epoch);
    }

    /**
     * @notice Claim a challenger bond after the outcome is determined.
     * @dev Bond disposition depends on whether fraud was confirmed:
     *
     *      1. Guardian direct revocation (revokeDelegationSnapshot):
     *         delegationChallengeSucceeded is set immediately → refund.
     *
     *      2. Auto-revocation + guardian confirms fraud (confirmDelegationFraud):
     *         delegationChallengeSucceeded is set → refund.
     *
     *      3. Auto-revocation + adjudication period expires without confirmation:
     *         Presumption of validity → slash to treasury.
     *
     *      4. Commitment survived the challenge period (no revocation):
     *         Challengers were wrong → slash to treasury.
     *
     * @param epoch The epoch whose challenger bond to claim.
     */
    function claimChallengerBond(uint256 epoch) external {
        uint256 bond = challengerBonds[epoch][msg.sender];
        if (bond == 0) revert NoChallengerBond(epoch, msg.sender);

        // Determine whether the outcome is known yet.
        if (!delegationChallengeSucceeded[epoch]) {
            uint256 revokedAt = delegationAutoRevokedAt[epoch];
            if (revokedAt > 0) {
                // Auto-revoked: must wait for adjudication period to expire.
                if (block.timestamp <= revokedAt + CHALLENGE_ADJUDICATION_PERIOD) {
                    revert ChallengeClaimTooEarly(epoch);
                }
                // Adjudication expired without confirmation → slash path below.
            } else {
                // Not auto-revoked: commitment was either still active or
                // guardian-revoked (which sets succeeded=true, handled above).
                // Must wait for challenge period to expire.
                uint256 commitTs = delegationCommitTimestamp[epoch];
                if (commitTs > 0) {
                    uint256 challengeDeadline = commitTs + DELEGATION_CHALLENGE_PERIOD;
                    if (block.timestamp <= challengeDeadline) {
                        revert ChallengeClaimTooEarly(epoch);
                    }
                }
                // Challenge period expired, commitment survived → slash path below.
            }
        }

        // Clear the bond before transfer (CEI pattern).
        delete challengerBonds[epoch][msg.sender];
        totalChallengerBonds -= bond;

        if (delegationChallengeSucceeded[epoch]) {
            // Fraud confirmed by guardian — refund.
            aethelToken.safeTransfer(msg.sender, bond);
            emit ChallengerBondRefunded(epoch, msg.sender, bond);
        } else {
            // Griefing or false challenge — slash to treasury.
            aethelToken.safeTransfer(treasury, bond);
            emit ChallengerBondSlashed(epoch, msg.sender, bond);
        }
    }

    // =========================================================================
    // DELEGATION GOVERNANCE
    // =========================================================================

    /**
     * @notice Toggle the multi-attestor quorum requirement for delegation.
     * @dev When enabled, commitDelegationSnapshot() (single-keeper) is disabled
     *      and delegation must go through submitDelegationVote() with
     *      DELEGATION_QUORUM independent attestors agreeing.
     *
     *      Migration path:
     *        1. Deploy with quorum disabled (single-keeper works)
     *        2. Onboard independent attestors, grant DELEGATION_ATTESTOR_ROLE
     *        3. Enable quorum — single-keeper path is blocked
     *
     * @param enabled Whether to require the multi-attestor quorum.
     */
    function setDelegationQuorumEnabled(bool enabled) external onlyRole(DEFAULT_ADMIN_ROLE) {
        delegationQuorumEnabled = enabled;
        emit DelegationQuorumToggled(enabled);
    }

    // =========================================================================
    // DELEGATION INTERNAL
    // =========================================================================

    /**
     * @dev Internal: validates and commits a delegation snapshot (shared between
     *      the single-keeper and multi-attestor paths).
     */
    function _commitDelegationSnapshotInternal(
        bytes calldata teeAttestation,
        uint256 epoch,
        bytes32 delegationRoot,
        bytes32 stakerRegistryRoot,
        uint256 stakerCount
    ) internal {
        _validateDelegationSnapshot(teeAttestation, epoch, delegationRoot, stakerRegistryRoot, stakerCount);

        epochSnapshots[epoch].delegationRegistryRoot = delegationRoot;
        delegationCommitTimestamp[epoch] = block.timestamp;
        delegatingStakerCount[epoch] = stakerCount;
        emit DelegationSnapshotCommitted(epoch, delegationRoot);
    }

    /**
     * @dev Internal: validates a delegation snapshot (TEE attestation, epoch,
     *      registry anchor, cardinality).  Shared by commitDelegationSnapshot
     *      and submitDelegationVote.
     */
    function _validateDelegationSnapshot(
        bytes calldata teeAttestation,
        uint256 epoch,
        bytes32 delegationRoot,
        bytes32 stakerRegistryRoot,
        uint256 stakerCount
    ) internal {
        if (epoch != currentEpoch) revert InvalidEpoch(epoch, currentEpoch);
        if (epochSnapshots[epoch].delegationRegistryRoot != bytes32(0)) {
            revert DelegationSnapshotAlreadyCommitted(epoch);
        }
        // Require stake snapshot committed first.
        if (epochSnapshots[epoch].stakeSnapshotHash == bytes32(0)) {
            revert StakeSnapshotNotCommitted(epoch);
        }
        // Registry root anchor check.
        bytes32 committedRegistryRoot = epochSnapshots[epoch].stakerRegistryRoot;
        if (stakerRegistryRoot != committedRegistryRoot) {
            revert StakerRegistryAnchorMismatch(stakerRegistryRoot, committedRegistryRoot);
        }

        // Verify the TEE attestation (96-byte payload).
        (bool valid, bytes memory payload,) = teeVerifier.verifyAttestation(teeAttestation);
        if (!valid) revert DelegationAttestationInvalid();
        if (payload.length != 96) revert DelegationAttestationInvalid();

        bytes memory expectedPayload = abi.encode(epoch, delegationRoot, stakerRegistryRoot);
        if (keccak256(payload) != keccak256(expectedPayload)) {
            revert DelegationAttestationInvalid();
        }

        // Cardinality anchor.
        if (delegationRoot != bytes32(0) && stakerCount == 0) {
            revert DelegationCardinalityZeroWithNonZeroRoot(epoch);
        }
    }

    /**
     * @dev Internal: clears a delegation commitment and associated metadata.
     *      Used by revokeDelegationSnapshot and auto-revocation from challenges.
     *
     *      Does NOT set delegationChallengeSucceeded — callers must handle
     *      fraud confirmation separately.  Guardian revocation sets it directly;
     *      auto-revocation requires confirmDelegationFraud().
     */
    function _clearDelegationCommitment(uint256 epoch) internal {
        delete epochSnapshots[epoch].delegationRegistryRoot;
        delete delegationCommitTimestamp[epoch];
        delete delegatingStakerCount[epoch];
    }

    /**
     * @dev Internal: freezes the bond of whoever submitted the delegation
     *      commitment for the given epoch.  Covers both paths:
     *        - Single-keeper: delegationCommitter[epoch]
     *        - Quorum attestors: all addresses in delegationEpochAttestors[epoch]
     */
    function _freezeDelegationSubmitters(uint256 epoch) internal {
        // Freeze single-keeper committer.
        address committer = delegationCommitter[epoch];
        if (committer != address(0) && !keeperBondFrozen[committer]) {
            keeperBondFrozen[committer] = true;
            emit KeeperBondFrozen(committer, epoch);
        }

        // Freeze all quorum attestors who voted in this epoch.
        address[] storage attestors = delegationEpochAttestors[epoch];
        for (uint256 i = 0; i < attestors.length; i++) {
            address attestor = attestors[i];
            if (!keeperBondFrozen[attestor]) {
                keeperBondFrozen[attestor] = true;
                emit KeeperBondFrozen(attestor, epoch);
            }
        }
    }

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    // =========================================================================
    // CANONICAL VALIDATOR SET HASH
    // =========================================================================

    /**
     * @notice Compute the canonical validator set hash for cross-layer verification.
     * @dev All three layers (Rust TEE producer, Solidity on-chain, Go native) compute
     *      this identical hash. The canonical encoding uses domain-separated SHA-256
     *      with uint256-padded fields, eliminating serialization mismatches.
     *
     *      Schema (big-endian, uint256-padded):
     *        inner_hash_i = SHA-256(
     *          pad32(address) || uint256(stake) || uint256(perfScore) ||
     *          uint256(decentScore) || uint256(repScore) || uint256(compositeScore) ||
     *          bytes32(teeKey) || uint256(commission)
     *        )
     *        canonical_hash = SHA-256(
     *          "CruzibleValidatorSet-v1" || be8(epoch) || be4(count) ||
     *          inner_hash_0 || inner_hash_1 || ...
     *        )
     *
     * Matching implementations:
     *   - Rust: server::compute_validator_set_hash()
     *   - Go:   keeper.computeValidatorSetHash()
     */
    function _computeValidatorSetHash(
        uint256 epoch,
        address[] memory addrs,
        uint256[] memory stakes,
        uint256[] memory perfScores,
        uint256[] memory decentScores,
        uint256[] memory repScores,
        uint256[] memory compositeScores,
        bytes32[] memory teeKeys,
        uint256[] memory commissions
    ) internal pure returns (bytes32) {
        // Build outer preimage: domain tag + header
        bytes memory outerPreimage = abi.encodePacked(
            "CruzibleValidatorSet-v1",
            uint64(epoch),
            uint32(addrs.length)
        );

        // Compute per-validator inner hashes and append to outer preimage
        for (uint256 i = 0; i < addrs.length; i++) {
            bytes32 innerHash = sha256(abi.encodePacked(
                bytes32(uint256(uint160(addrs[i]))),  // address left-padded to 32 bytes
                stakes[i],
                perfScores[i],
                decentScores[i],
                repScores[i],
                compositeScores[i],
                teeKeys[i],
                commissions[i]
            ));
            outerPreimage = abi.encodePacked(outerPreimage, innerHash);
        }

        return sha256(outerPreimage);
    }

    // =========================================================================
    // INTERNAL FUNCTIONS
    // =========================================================================

    /**
     * @notice Advance to the next epoch.
     */
    function _advanceEpoch() internal {
        currentEpoch++;
        epochStartTime = block.timestamp;
    }

    function _authorizeUpgrade(address newImplementation)
        internal
        override
        onlyRole(UPGRADER_ROLE)
    {}

    function version() external pure returns (string memory) {
        return "1.0.0";
    }

    // =========================================================================
    // STORAGE GAP
    // =========================================================================

    uint256[50] private __gap;
}
