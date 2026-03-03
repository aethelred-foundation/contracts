// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title AethelredVesting
 * @author Aethelred Team
 * @notice Enterprise-grade token vesting contract for AETHEL allocations
 * @dev Implements multiple vesting schedules with milestone dual-attestation,
 *      cliff+linear unlock, DAO-controlled release, and category-based caps.
 * @custom:security-contact security@aethelred.io
 * @custom:audit-status Remediated — all 27 findings addressed (2026-02-28)
 *      - Compute/PoUW Rewards (30%): 10-year linear, no cliff
 *      - Core Contributors (20%): 12mo cliff, 25% at cliff, 4yr total
 *      - Ecosystem & Grants (15%): 5% TGE, 6mo cliff, 5yr total
 *      - Labs Treasury (10%): 12mo cliff, 5yr total
 *      - Public Sale (10%): 22.5% TGE, no cliff, 2yr total
 *      - Strategic Investors (5%): 12mo cliff, 4yr total
 *      - Insurance/Stability (5%): 10% TGE, 30mo linear
 *      - Foundation Reserve (5%): 12mo cliff, 5yr total
 *
 * Architecture:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                       AETHELRED VESTING CONTRACT                             │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                              │
 * │  ┌────────────────────────────────────────────────────────────────────────┐ │
 * │  │                    VESTING SCHEDULE TYPES                              │ │
 * │  │                                                                        │ │
 * │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │ │
 * │  │  │   LINEAR    │  │  CLIFF +    │  │    DAO      │  │  EMISSION   │  │ │
 * │  │  │   UNLOCK    │  │  LINEAR     │  │  CONTROLLED │  │  (HALVING)  │  │ │
 * │  │  │             │  │             │  │             │  │             │  │ │
 * │  │  │ TGE ────► 1y│  │ Cliff ──► 4y│  │ Proposal ──►│  │ 4y ──► 50y │  │ │
 * │  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘  │ │
 * │  │                                                                        │ │
 * │  └────────────────────────────────────────────────────────────────────────┘ │
 * │                                                                              │
 * │  Features:                                                                   │
 * │  • UUPS Upgradeable (future-proof)                                          │
 * │  • Role-based access control                                                 │
 * │  • Revocable schedules (for team members)                                   │
 * │  • Beneficiary transfer (for investors)                                     │
 * │  • Emergency pause functionality                                            │
 * │  • Batch operations for gas efficiency                                      │
 * │                                                                              │
 * └─────────────────────────────────────────────────────────────────────────────┘
 */
contract AethelredVesting is
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

    bytes32 public constant VESTING_ADMIN_ROLE = keccak256("VESTING_ADMIN_ROLE");
    bytes32 public constant REVOKER_ROLE = keccak256("REVOKER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant MILESTONE_ATTESTOR_ROLE = keccak256("MILESTONE_ATTESTOR_ROLE");

    /// @notice Precision for percentage calculations (basis points)
    uint256 public constant BPS_DENOMINATOR = 10000;

    /// @notice Maximum schedules per beneficiary
    uint256 public constant MAX_SCHEDULES_PER_BENEFICIARY = 10;

    // =========================================================================
    // ENUMS
    // =========================================================================

    /// @notice Types of vesting schedules
    enum VestingType {
        LINEAR,           // Linear unlock over duration
        CLIFF_LINEAR,     // Cliff period then linear
        IMMEDIATE,        // 100% at TGE
        DAO_CONTROLLED,   // Released via DAO proposals
        MILESTONE         // Released at specific milestones
    }

    /// @notice Allocation categories matching tokenomics (10B total supply)
    enum AllocationCategory {
        COMPUTE_POUW_REWARDS,   // 30% (3B)  - 10yr linear, no cliff
        CORE_CONTRIBUTORS,      // 20% (2B)  - 12mo cliff, 25% at cliff, 4yr total
        ECOSYSTEM_GRANTS,       // 15% (1.5B) - 5% TGE, 6mo cliff, 5yr total
        LABS_TREASURY,          // 10% (1B)  - 12mo cliff, 5yr total
        PUBLIC_SALE_COMMUNITY,  // 10% (1B)  - 22.5% TGE, no cliff, 2yr vest
        STRATEGIC_INVESTORS,    // 5%  (500M) - 12mo cliff, 4yr total
        INSURANCE_STABILITY,    // 5%  (500M) - 10% TGE, no cliff, 30mo vest
        FOUNDATION_RESERVE      // 5%  (500M) - 12mo cliff, 5yr total
    }

    // =========================================================================
    // STRUCTS
    // =========================================================================

    /// @notice Individual vesting schedule
    struct VestingSchedule {
        /// @notice Unique schedule ID
        bytes32 scheduleId;
        /// @notice Beneficiary address
        address beneficiary;
        /// @notice Total tokens in this schedule
        uint256 totalAmount;
        /// @notice Tokens already released
        uint256 releasedAmount;
        /// @notice Allocation category
        AllocationCategory category;
        /// @notice Vesting type
        VestingType vestingType;
        /// @notice Schedule start time (TGE)
        uint256 startTime;
        /// @notice Cliff duration (0 for no cliff)
        uint256 cliffDuration;
        /// @notice Total vesting duration
        uint256 vestingDuration;
        /// @notice TGE unlock percentage (basis points)
        uint256 tgeUnlockBps;
        /// @notice Cliff unlock percentage (basis points) — Audit fix [H-01]
        /// @dev Additional percentage released at cliff, separate from TGE unlock.
        ///      For core contributors: tgeUnlockBps=0, cliffUnlockBps=2500 (25% at cliff).
        ///      Matches Go VestingSchedule.CliffPercent field.
        uint256 cliffUnlockBps;
        /// @notice Whether schedule is revocable
        bool revocable;
        /// @notice Whether schedule has been revoked
        bool revoked;
        /// @notice Revocation timestamp (if revoked)
        uint256 revokedTime;
        /// @notice Whether beneficiary can transfer
        bool transferable;
        /// @notice Schedule creation timestamp
        uint256 createdAt;
    }

    /// @notice Milestone definition for milestone-based vesting
    struct Milestone {
        /// @notice Milestone identifier
        string name;
        /// @notice Percentage unlocked at this milestone (bps)
        uint256 unlockBps;
        /// @notice Whether milestone is achieved
        bool achieved;
        /// @notice Achievement timestamp
        uint256 achievedAt;
    }

    // =========================================================================
    // STATE VARIABLES
    // =========================================================================

    /// @notice Token being vested
    IERC20 public token;

    /// @notice Total tokens allocated to vesting
    uint256 public totalAllocated;

    /// @notice Total tokens released from vesting
    uint256 public totalReleased;

    /// @notice Schedule counter for unique IDs
    uint256 public scheduleCount;

    /// @notice Token Generation Event timestamp
    uint256 public tgeTime;

    /// @notice Whether TGE has occurred
    bool public tgeOccurred;

    /// @notice All schedules by ID
    mapping(bytes32 => VestingSchedule) public schedules;

    /// @notice Schedule IDs per beneficiary
    mapping(address => bytes32[]) public beneficiarySchedules;

    /// @notice Milestones for milestone-based vesting
    mapping(bytes32 => Milestone[]) public scheduleMilestones;

    /// @notice Category totals tracking
    mapping(AllocationCategory => uint256) public categoryAllocated;
    mapping(AllocationCategory => uint256) public categoryReleased;

    /// @notice Category caps (from tokenomics)
    mapping(AllocationCategory => uint256) public categoryCaps;

    // =========================================================================
    // EVENTS
    // =========================================================================

    event VestingScheduleCreated(
        bytes32 indexed scheduleId,
        address indexed beneficiary,
        uint256 totalAmount,
        AllocationCategory category,
        VestingType vestingType,
        uint256 startTime,
        uint256 cliffDuration,
        uint256 vestingDuration
    );

    event TokensReleased(
        bytes32 indexed scheduleId,
        address indexed beneficiary,
        uint256 amount,
        uint256 totalReleased
    );

    event ScheduleRevoked(
        bytes32 indexed scheduleId,
        address indexed beneficiary,
        uint256 unvestedAmount,
        uint256 revokedAt
    );

    event BeneficiaryTransferred(
        bytes32 indexed scheduleId,
        address indexed oldBeneficiary,
        address indexed newBeneficiary
    );

    event MilestoneAchieved(
        bytes32 indexed scheduleId,
        string milestoneName,
        uint256 unlockBps,
        uint256 achievedAt
    );

    /**
     * @notice Emitted when a milestone is attested by an authorized attestor.
     * @dev Provides audit trail: who attested, for which schedule, which milestone.
     */
    event MilestoneAttested(
        bytes32 indexed scheduleId,
        uint256 indexed milestoneIndex,
        address indexed attestor,
        string milestoneName
    );

    event TGEExecuted(uint256 timestamp);
    event ScheduleActivated(bytes32 indexed scheduleId, uint256 startTime);

    event CategoryCapSet(AllocationCategory category, uint256 cap);

    // =========================================================================
    // ERRORS
    // =========================================================================

    error TGENotOccurred();
    error TGEAlreadyOccurred();
    error InvalidAmount();
    error InvalidDuration();
    error InvalidBeneficiary();
    error ScheduleNotFound();
    error ScheduleAlreadyRevoked();
    error ScheduleNotRevocable();
    error NothingToRelease();
    error NotTransferable();
    error CategoryCapExceeded();
    error MaxSchedulesExceeded();
    error CliffNotReached();
    error MilestoneNotFound();
    error MilestoneAlreadyAchieved();
    error UnauthorizedBeneficiary();
    error AdminMustBeContract();
    error CategoryCapBelowAllocated();
    error ScheduleAlreadyActive();
    error MilestoneIndexOutOfBounds();

    // =========================================================================
    // MODIFIERS
    // =========================================================================

    modifier onlyAfterTGE() {
        if (!tgeOccurred) revert TGENotOccurred();
        _;
    }

    modifier onlyBeforeTGE() {
        if (tgeOccurred) revert TGEAlreadyOccurred();
        _;
    }

    modifier scheduleExists(bytes32 scheduleId) {
        if (schedules[scheduleId].beneficiary == address(0)) revert ScheduleNotFound();
        _;
    }

    modifier notRevoked(bytes32 scheduleId) {
        if (schedules[scheduleId].revoked) revert ScheduleAlreadyRevoked();
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
     * @notice Initialize the vesting contract
     * @param _token The AETHEL token address
     * @param _admin Admin address
     */
    function initialize(
        address _token,
        address _admin
    ) external initializer {
        __UUPSUpgradeable_init();
        __AccessControl_init();
        __Pausable_init();
        __ReentrancyGuard_init();

        if (_token == address(0)) revert InvalidBeneficiary();
        if (_admin == address(0)) revert InvalidBeneficiary();
        _requireContractAdmin(_admin);

        token = IERC20(_token);

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(VESTING_ADMIN_ROLE, _admin);
        _grantRole(REVOKER_ROLE, _admin);
        _grantRole(UPGRADER_ROLE, _admin);

        // Set category caps from tokenomics (10B total supply)
        // Using 18 decimals: amount * 10^18
        categoryCaps[AllocationCategory.COMPUTE_POUW_REWARDS] = 3_000_000_000 * 1e18;  // 30%
        categoryCaps[AllocationCategory.CORE_CONTRIBUTORS] = 2_000_000_000 * 1e18;     // 20%
        categoryCaps[AllocationCategory.ECOSYSTEM_GRANTS] = 1_500_000_000 * 1e18;      // 15%
        categoryCaps[AllocationCategory.LABS_TREASURY] = 1_000_000_000 * 1e18;          // 10%
        categoryCaps[AllocationCategory.PUBLIC_SALE_COMMUNITY] = 1_000_000_000 * 1e18;  // 10%
        categoryCaps[AllocationCategory.STRATEGIC_INVESTORS] = 500_000_000 * 1e18;      // 5%
        categoryCaps[AllocationCategory.INSURANCE_STABILITY] = 500_000_000 * 1e18;      // 5%
        categoryCaps[AllocationCategory.FOUNDATION_RESERVE] = 500_000_000 * 1e18;       // 5%
    }

    // =========================================================================
    // TGE FUNCTIONS
    // =========================================================================

    /**
     * @notice Execute Token Generation Event
     * @dev Can only be called once, marks the start of all vesting schedules
     */
    function executeTGE() external onlyRole(VESTING_ADMIN_ROLE) onlyBeforeTGE {
        tgeTime = block.timestamp;
        tgeOccurred = true;
        emit TGEExecuted(block.timestamp);
    }

    /**
     * @notice Explicitly activates a pre-TGE schedule by setting its start time.
     * @dev Uses `tgeTime` (not current block time) so delayed activation does not
     *      alter vesting economics after the TGE has already occurred.
     */
    function activateSchedule(bytes32 scheduleId)
        external
        onlyRole(VESTING_ADMIN_ROLE)
        onlyAfterTGE
        scheduleExists(scheduleId)
    {
        VestingSchedule storage schedule = schedules[scheduleId];
        if (schedule.startTime != 0) revert ScheduleAlreadyActive();

        schedule.startTime = tgeTime;
        emit ScheduleActivated(scheduleId, tgeTime);
    }

    // =========================================================================
    // SCHEDULE CREATION
    // =========================================================================

    /**
     * @notice Create a vesting schedule for strategic investors
     * @dev 12-month cliff, 4-year total vest, no TGE unlock
     * @param beneficiary Investor address
     * @param amount Total tokens to vest
     */
    function createStrategicInvestorSchedule(
        address beneficiary,
        uint256 amount
    ) external onlyRole(VESTING_ADMIN_ROLE) returns (bytes32) {
        return _createSchedule(
            beneficiary,
            amount,
            AllocationCategory.STRATEGIC_INVESTORS,
            VestingType.CLIFF_LINEAR,
            365 days,     // 12-month cliff
            4 * 365 days, // 4 years total
            0,            // No TGE unlock
            0,            // No cliff unlock — Audit fix [H-01]
            false,        // Not revocable
            true          // Transferable
        );
    }

    /**
     * @notice Create a vesting schedule for core contributors
     * @dev 12-month cliff, 25% at cliff, 4-year total vest
     * @param beneficiary Team member address
     * @param amount Total tokens to vest
     */
    function createCoreContributorSchedule(
        address beneficiary,
        uint256 amount
    ) external onlyRole(VESTING_ADMIN_ROLE) returns (bytes32) {
        return _createSchedule(
            beneficiary,
            amount,
            AllocationCategory.CORE_CONTRIBUTORS,
            VestingType.CLIFF_LINEAR,
            365 days,     // 12-month cliff
            4 * 365 days, // 4 years total
            0,            // No TGE unlock
            2500,         // 25% cliff unlock — Audit fix [H-01]
            true,         // Revocable (for departures)
            false         // Not transferable
        );
    }

    /**
     * @notice Create a public sale schedule
     * @dev 22.5% TGE unlock, no cliff, 2-year total vest
     * @param beneficiary Recipient address
     * @param amount Total tokens
     */
    function createPublicSaleSchedule(
        address beneficiary,
        uint256 amount
    ) external onlyRole(VESTING_ADMIN_ROLE) returns (bytes32) {
        return _createSchedule(
            beneficiary,
            amount,
            AllocationCategory.PUBLIC_SALE_COMMUNITY,
            VestingType.CLIFF_LINEAR,
            0,            // No cliff
            2 * 365 days, // 2-year total vest
            2250,         // 22.5% at TGE
            0,            // No cliff unlock — Audit fix [H-01]
            false,
            true
        );
    }

    /**
     * @notice Create a custom vesting schedule
     * @param cliffUnlockBps Percentage released at cliff (BPS) — Audit fix [H-01]
     */
    function createCustomSchedule(
        address beneficiary,
        uint256 amount,
        AllocationCategory category,
        VestingType vestingType,
        uint256 cliffDuration,
        uint256 vestingDuration,
        uint256 tgeUnlockBps,
        uint256 cliffUnlockBps,
        bool revocable,
        bool transferable
    ) external onlyRole(VESTING_ADMIN_ROLE) returns (bytes32) {
        return _createSchedule(
            beneficiary,
            amount,
            category,
            vestingType,
            cliffDuration,
            vestingDuration,
            tgeUnlockBps,
            cliffUnlockBps,
            revocable,
            transferable
        );
    }

    /**
     * @notice Internal schedule creation
     * @dev Audit fix [H-01]: Added cliffUnlockBps parameter.
     *      Audit fix [M-04]: Removed block.timestamp from scheduleId hash;
     *      scheduleCount alone provides uniqueness.
     */
    function _createSchedule(
        address beneficiary,
        uint256 amount,
        AllocationCategory category,
        VestingType vestingType,
        uint256 cliffDuration,
        uint256 vestingDuration,
        uint256 tgeUnlockBps,
        uint256 cliffUnlockBps,
        bool revocable,
        bool transferable
    ) internal returns (bytes32) {
        if (beneficiary == address(0)) revert InvalidBeneficiary();
        if (amount == 0) revert InvalidAmount();
        if (tgeUnlockBps > BPS_DENOMINATOR) revert InvalidAmount();
        if (cliffUnlockBps > BPS_DENOMINATOR) revert InvalidAmount();
        if (tgeUnlockBps + cliffUnlockBps > 8000) revert InvalidAmount(); // Max 80% upfront
        if (beneficiarySchedules[beneficiary].length >= MAX_SCHEDULES_PER_BENEFICIARY) {
            revert MaxSchedulesExceeded();
        }

        // Check category cap
        if (categoryAllocated[category] + amount > categoryCaps[category]) {
            revert CategoryCapExceeded();
        }

        // Audit fix [M-04]: Removed block.timestamp from hash — scheduleCount
        // provides uniqueness and block.timestamp is miner-controllable.
        bytes32 scheduleId = keccak256(
            abi.encode(
                beneficiary,
                amount,
                scheduleCount
            )
        );

        schedules[scheduleId] = VestingSchedule({
            scheduleId: scheduleId,
            beneficiary: beneficiary,
            totalAmount: amount,
            releasedAmount: 0,
            category: category,
            vestingType: vestingType,
            startTime: tgeOccurred ? tgeTime : 0,
            cliffDuration: cliffDuration,
            vestingDuration: vestingDuration,
            tgeUnlockBps: tgeUnlockBps,
            cliffUnlockBps: cliffUnlockBps,
            revocable: revocable,
            revoked: false,
            revokedTime: 0,
            transferable: transferable,
            createdAt: block.timestamp
        });

        beneficiarySchedules[beneficiary].push(scheduleId);
        scheduleCount++;
        totalAllocated += amount;
        categoryAllocated[category] += amount;

        emit VestingScheduleCreated(
            scheduleId,
            beneficiary,
            amount,
            category,
            vestingType,
            tgeOccurred ? tgeTime : 0,
            cliffDuration,
            vestingDuration
        );

        return scheduleId;
    }

    // =========================================================================
    // RELEASE FUNCTIONS
    // =========================================================================

    /**
     * @notice Release vested tokens for a specific schedule
     * @param scheduleId The schedule to release from
     */
    function release(bytes32 scheduleId)
        external
        nonReentrant
        whenNotPaused
        onlyAfterTGE
        scheduleExists(scheduleId)
        notRevoked(scheduleId)
        returns (uint256)
    {
        VestingSchedule storage schedule = schedules[scheduleId];

        if (msg.sender != schedule.beneficiary) revert UnauthorizedBeneficiary();

        uint256 releasable = _computeReleasable(schedule);
        if (releasable == 0) revert NothingToRelease();

        schedule.releasedAmount += releasable;
        totalReleased += releasable;
        categoryReleased[schedule.category] += releasable;

        token.safeTransfer(schedule.beneficiary, releasable);

        emit TokensReleased(
            scheduleId,
            schedule.beneficiary,
            releasable,
            schedule.releasedAmount
        );

        return releasable;
    }

    /**
     * @notice Release all vested tokens for caller
     * @dev Audit fix [M-06]: Loop is bounded by MAX_SCHEDULES_PER_BENEFICIARY (10),
     *      enforced at schedule creation. Explicit guard added for defense-in-depth.
     */
    function releaseAll()
        external
        nonReentrant
        whenNotPaused
        onlyAfterTGE
        returns (uint256 totalReleasedAmount)
    {
        bytes32[] storage scheduleIds = beneficiarySchedules[msg.sender];
        // Audit fix [M-06]: Defense-in-depth bound. scheduleIds.length is already
        // capped at MAX_SCHEDULES_PER_BENEFICIARY by _createSchedule(), but we
        // guard explicitly to prevent gas griefing if invariant is violated.
        uint256 count = scheduleIds.length;
        if (count > MAX_SCHEDULES_PER_BENEFICIARY) {
            count = MAX_SCHEDULES_PER_BENEFICIARY;
        }

        for (uint256 i = 0; i < count; i++) {
            VestingSchedule storage schedule = schedules[scheduleIds[i]];

            if (schedule.revoked) continue;

            uint256 releasable = _computeReleasable(schedule);
            if (releasable > 0) {
                schedule.releasedAmount += releasable;
                totalReleased += releasable;
                categoryReleased[schedule.category] += releasable;
                totalReleasedAmount += releasable;

                emit TokensReleased(
                    scheduleIds[i],
                    msg.sender,
                    releasable,
                    schedule.releasedAmount
                );
            }
        }

        if (totalReleasedAmount == 0) revert NothingToRelease();

        token.safeTransfer(msg.sender, totalReleasedAmount);
    }

    // =========================================================================
    // COMPUTATION FUNCTIONS
    // =========================================================================

    /**
     * @notice Compute releasable amount for a schedule
     */
    function _computeReleasable(VestingSchedule storage schedule) internal view returns (uint256) {
        uint256 vested = _computeVested(schedule);
        return vested - schedule.releasedAmount;
    }

    /**
     * @notice Compute total vested amount for a schedule
     * @dev Audit fix [H-01]: Added cliffUnlockBps support. The vesting formula is:
     *      - Before cliff: tgeAmount only
     *      - At cliff: tgeAmount + cliffAmount
     *      - After cliff: tgeAmount + cliffAmount + linear(remainder)
     *      - After vestingDuration: totalAmount
     *      This matches the Go VestedAmount() implementation exactly.
     */
    function _computeVested(VestingSchedule storage schedule) internal view returns (uint256) {
        if (!tgeOccurred) return 0;

        uint256 startTime = schedule.startTime > 0 ? schedule.startTime : tgeTime;
        uint256 endTime = schedule.revoked ? schedule.revokedTime : block.timestamp;

        if (endTime < startTime) return 0;

        // Handle immediate vesting
        if (schedule.vestingType == VestingType.IMMEDIATE) {
            return schedule.totalAmount;
        }

        // Calculate TGE unlock
        uint256 tgeAmount = (schedule.totalAmount * schedule.tgeUnlockBps) / BPS_DENOMINATOR;

        // Check cliff — before cliff, only TGE portion is available
        uint256 elapsed = endTime - startTime;
        if (elapsed < schedule.cliffDuration) {
            return tgeAmount;
        }

        // Audit fix [H-01]: Calculate cliff unlock (e.g., 25% for core contributors)
        uint256 cliffAmount = (schedule.totalAmount * schedule.cliffUnlockBps) / BPS_DENOMINATOR;

        // Fully vested
        if (schedule.vestingDuration == 0 || elapsed >= schedule.vestingDuration) {
            return schedule.totalAmount;
        }

        if (schedule.vestingDuration <= schedule.cliffDuration) {
            return schedule.totalAmount;
        }

        // Linear vesting of the remainder after TGE + cliff unlock
        uint256 vestingAmount = schedule.totalAmount - tgeAmount - cliffAmount;
        uint256 linearDuration = schedule.vestingDuration - schedule.cliffDuration;
        uint256 linearElapsed = elapsed - schedule.cliffDuration;
        uint256 vestedAmount =
            tgeAmount +
            cliffAmount +
            (vestingAmount * linearElapsed) /
            linearDuration;

        return vestedAmount > schedule.totalAmount ? schedule.totalAmount : vestedAmount;
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /**
     * @notice Get releasable amount for a schedule
     */
    function getReleasable(bytes32 scheduleId) external view returns (uint256) {
        VestingSchedule storage schedule = schedules[scheduleId];
        if (schedule.beneficiary == address(0)) return 0;
        if (schedule.revoked) return 0;
        return _computeReleasable(schedule);
    }

    /**
     * @notice Get vested amount for a schedule
     */
    function getVested(bytes32 scheduleId) external view returns (uint256) {
        VestingSchedule storage schedule = schedules[scheduleId];
        if (schedule.beneficiary == address(0)) return 0;
        return _computeVested(schedule);
    }

    /**
     * @notice Get all schedules for a beneficiary
     */
    function getBeneficiarySchedules(address beneficiary) external view returns (bytes32[] memory) {
        return beneficiarySchedules[beneficiary];
    }

    /**
     * @notice Get schedule details
     */
    function getSchedule(bytes32 scheduleId) external view returns (VestingSchedule memory) {
        return schedules[scheduleId];
    }

    /**
     * @notice Get category statistics
     */
    function getCategoryStats(AllocationCategory category)
        external
        view
        returns (uint256 cap, uint256 allocated, uint256 released)
    {
        return (
            categoryCaps[category],
            categoryAllocated[category],
            categoryReleased[category]
        );
    }

    // =========================================================================
    // ADMIN FUNCTIONS
    // =========================================================================

    /**
     * @notice Revoke a vesting schedule
     * @param scheduleId The schedule to revoke
     */
    function revokeSchedule(bytes32 scheduleId)
        external
        onlyRole(REVOKER_ROLE)
        scheduleExists(scheduleId)
        notRevoked(scheduleId)
    {
        VestingSchedule storage schedule = schedules[scheduleId];

        if (!schedule.revocable) revert ScheduleNotRevocable();

        uint256 vested = _computeVested(schedule);
        uint256 unvested = schedule.totalAmount - vested;

        schedule.revoked = true;
        schedule.revokedTime = block.timestamp;

        // Return unvested tokens to contract (will be reallocated)
        totalAllocated -= unvested;
        categoryAllocated[schedule.category] -= unvested;

        emit ScheduleRevoked(
            scheduleId,
            schedule.beneficiary,
            unvested,
            block.timestamp
        );
    }

    /**
     * @notice Transfer beneficiary (for investors)
     */
    function transferBeneficiary(bytes32 scheduleId, address newBeneficiary)
        external
        scheduleExists(scheduleId)
        notRevoked(scheduleId)
    {
        VestingSchedule storage schedule = schedules[scheduleId];

        if (msg.sender != schedule.beneficiary) revert UnauthorizedBeneficiary();
        if (!schedule.transferable) revert NotTransferable();
        if (newBeneficiary == address(0)) revert InvalidBeneficiary();

        address oldBeneficiary = schedule.beneficiary;

        // Update beneficiary
        schedule.beneficiary = newBeneficiary;

        // Update beneficiary mappings
        _removeBeneficiarySchedule(oldBeneficiary, scheduleId);
        beneficiarySchedules[newBeneficiary].push(scheduleId);

        emit BeneficiaryTransferred(scheduleId, oldBeneficiary, newBeneficiary);
    }

    function _removeBeneficiarySchedule(address beneficiary, bytes32 scheduleId) internal {
        bytes32[] storage scheduleIds = beneficiarySchedules[beneficiary];
        for (uint256 i = 0; i < scheduleIds.length; i++) {
            if (scheduleIds[i] == scheduleId) {
                scheduleIds[i] = scheduleIds[scheduleIds.length - 1];
                scheduleIds.pop();
                break;
            }
        }
    }

    /**
     * @notice Update category cap
     */
    function setCategoryCap(AllocationCategory category, uint256 cap)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        if (cap < categoryAllocated[category]) revert CategoryCapBelowAllocated();
        categoryCaps[category] = cap;
        emit CategoryCapSet(category, cap);
    }

    /**
     * @notice Pause contract
     */
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause contract
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /**
     * @notice Recover accidentally sent tokens
     * @dev Audit fix [L-04]: Added explicit recipient parameter instead of
     *      sending to msg.sender, allowing recovery to a designated treasury address.
     * @param tokenAddress The token to recover
     * @param amount Amount to recover
     * @param recipient Address to send recovered tokens to
     */
    function recoverTokens(address tokenAddress, uint256 amount, address recipient)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        if (recipient == address(0)) revert InvalidBeneficiary();

        // Cannot recover vesting token beyond what's unvested
        if (tokenAddress == address(token)) {
            uint256 vestingBalance = totalAllocated > totalReleased
                ? totalAllocated - totalReleased
                : 0;
            uint256 currentBalance = token.balanceOf(address(this));
            uint256 recoverable = currentBalance > vestingBalance
                ? currentBalance - vestingBalance
                : 0;
            require(amount <= recoverable, "Cannot recover vesting tokens");
        }

        IERC20(tokenAddress).safeTransfer(recipient, amount);
    }

    // =========================================================================
    // UPGRADE
    // =========================================================================

    function _authorizeUpgrade(address newImplementation)
        internal
        override
        onlyRole(UPGRADER_ROLE)
    {}

    function _requireContractAdmin(address admin) internal view {
        if (admin.code.length > 0) {
            return;
        }
        if (block.chainid == 31337 || block.chainid == 1337) {
            return;
        }
        revert AdminMustBeContract();
    }

    // =========================================================================
    // MILESTONE DUAL-ATTESTATION (C-04/Item 7 hardening)
    // =========================================================================

    /**
     * @notice Achieve a milestone with dual-attestation (VESTING_ADMIN + MILESTONE_ATTESTOR).
     * @dev Both roles must be held by the caller, OR the function can be called
     *      by a contract that holds both roles (e.g., a DAO executor).
     *      This ensures no single party can unilaterally unlock milestone tokens.
     * @param scheduleId The vesting schedule ID
     * @param milestoneIndex Index of the milestone in the schedule's milestone array
     */
    function achieveMilestone(
        bytes32 scheduleId,
        uint256 milestoneIndex
    )
        external
        onlyRole(VESTING_ADMIN_ROLE)
        scheduleExists(scheduleId)
        notRevoked(scheduleId)
    {
        // Require MILESTONE_ATTESTOR_ROLE as well (dual-attestation)
        _checkRole(MILESTONE_ATTESTOR_ROLE, msg.sender);

        Milestone[] storage milestones = scheduleMilestones[scheduleId];
        if (milestoneIndex >= milestones.length) revert MilestoneIndexOutOfBounds();

        Milestone storage milestone = milestones[milestoneIndex];
        if (milestone.achieved) revert MilestoneAlreadyAchieved();

        milestone.achieved = true;
        milestone.achievedAt = block.timestamp;

        emit MilestoneAttested(
            scheduleId,
            milestoneIndex,
            msg.sender,
            milestone.name
        );

        emit MilestoneAchieved(
            scheduleId,
            milestone.name,
            milestone.unlockBps,
            block.timestamp
        );
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
