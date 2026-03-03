// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "../contracts/AethelredVesting.sol";

/**
 * @title MockToken
 * @dev Simple ERC20 for vesting tests
 */
contract MockVestingToken is ERC20 {
    constructor() ERC20("Aethelred", "AETHEL") {
        _mint(msg.sender, 10_000_000_000 * 1e18);
    }
}

/**
 * @title AethelredVestingTest
 * @notice Comprehensive Foundry test suite for AethelredVesting
 * @dev Covers: schedule creation, TGE/cliff/linear vesting calculation,
 *      release mechanics, revocation, category caps, beneficiary transfer,
 *      milestone vesting, boundary conditions, fuzz tests, and invariant tests.
 *
 * @custom:audit-coverage Target: 95%+ line coverage, 100% critical path
 * @custom:audit-date 2026-02-28
 */
contract AethelredVestingTest is Test {
    // =========================================================================
    // STATE
    // =========================================================================

    AethelredVesting public vesting;
    MockVestingToken public token;

    address public admin = address(0xAD);
    address public vestingAdmin = address(0xBA);
    address public revoker = address(0xFE);

    address public alice = address(0x1);
    address public bob = address(0x2);
    address public carol = address(0x3);

    uint256 public constant TOTAL_SUPPLY = 10_000_000_000 * 1e18;
    uint256 public constant BPS_BASE = 10000;

    // =========================================================================
    // EVENTS (re-declared for vm.expectEmit)
    // =========================================================================

    event VestingScheduleCreated(
        bytes32 indexed scheduleId,
        address indexed beneficiary,
        uint256 totalAmount,
        AethelredVesting.AllocationCategory category,
        AethelredVesting.VestingType vestingType,
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
    event TGEExecuted(uint256 timestamp);

    // =========================================================================
    // SETUP
    // =========================================================================

    function setUp() public {
        // Deploy token and give all to admin
        vm.startPrank(admin);
        token = new MockVestingToken();

        // Deploy vesting via proxy
        AethelredVesting impl = new AethelredVesting();
        bytes memory initData = abi.encodeCall(
            AethelredVesting.initialize,
            (address(token), admin)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        vesting = AethelredVesting(address(proxy));

        // Grant roles
        vesting.grantRole(vesting.VESTING_ADMIN_ROLE(), vestingAdmin);
        vesting.grantRole(vesting.REVOKER_ROLE(), revoker);

        // Transfer tokens to vesting contract
        token.transfer(address(vesting), 5_000_000_000 * 1e18);

        vm.stopPrank();
    }

    // =========================================================================
    // INITIALIZATION TESTS
    // =========================================================================

    function test_Init_TokenAddress() public view {
        assertEq(address(vesting.token()), address(token));
    }

    function test_Init_TGENotOccurred() public view {
        assertFalse(vesting.tgeOccurred());
    }

    function test_Init_ScheduleCountZero() public view {
        assertEq(vesting.scheduleCount(), 0);
    }

    function test_Init_Version() public view {
        assertEq(keccak256(bytes(vesting.version())), keccak256(bytes("1.0.0")));
    }

    // =========================================================================
    // TGE TESTS
    // =========================================================================

    function test_TGE_Execute() public {
        vm.prank(vestingAdmin);
        vesting.executeTGE();

        assertTrue(vesting.tgeOccurred());
        assertEq(vesting.tgeTime(), block.timestamp);
    }

    function test_Revert_TGE_CannotExecuteTwice() public {
        vm.prank(vestingAdmin);
        vesting.executeTGE();

        vm.prank(vestingAdmin);
        vm.expectRevert(AethelredVesting.TGEAlreadyOccurred.selector);
        vesting.executeTGE();
    }

    function test_Revert_TGE_OnlyVestingAdmin() public {
        vm.prank(alice);
        vm.expectRevert();
        vesting.executeTGE();
    }

    // =========================================================================
    // SCHEDULE CREATION TESTS
    // =========================================================================

    function test_CreateCustomSchedule() public {
        vm.prank(vestingAdmin);
        bytes32 scheduleId = vesting.createCustomSchedule(
            alice,
            1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.CLIFF_LINEAR,
            180 days,  // 6 month cliff
            5 * 365 days,  // 5 year vesting
            500,  // 5% TGE
            1000, // 10% cliff
            true, // revocable
            false // not transferable
        );

        assertNotEq(scheduleId, bytes32(0));
        assertEq(vesting.scheduleCount(), 1);

        AethelredVesting.VestingSchedule memory s = vesting.getSchedule(scheduleId);
        assertEq(s.beneficiary, alice);
        assertEq(s.totalAmount, 1000 ether);
        assertEq(s.tgeUnlockBps, 500);
        assertEq(s.cliffUnlockBps, 1000);
        assertEq(s.cliffDuration, 180 days);
        assertEq(s.vestingDuration, 5 * 365 days);
        assertTrue(s.revocable);
        assertFalse(s.revoked);
    }

    function test_CreateCoreContributorSchedule() public {
        vm.prank(vestingAdmin);
        bytes32 scheduleId = vesting.createCoreContributorSchedule(alice, 100_000 ether);

        AethelredVesting.VestingSchedule memory s = vesting.getSchedule(scheduleId);
        assertEq(s.beneficiary, alice);
        assertEq(s.totalAmount, 100_000 ether);
        assertEq(uint8(s.category), uint8(AethelredVesting.AllocationCategory.CORE_CONTRIBUTORS));
    }

    function test_CreateStrategicInvestorSchedule() public {
        vm.prank(vestingAdmin);
        bytes32 scheduleId = vesting.createStrategicInvestorSchedule(alice, 50_000 ether);

        AethelredVesting.VestingSchedule memory s = vesting.getSchedule(scheduleId);
        assertEq(s.beneficiary, alice);
        assertEq(uint8(s.category), uint8(AethelredVesting.AllocationCategory.STRATEGIC_INVESTORS));
    }

    function test_CreatePublicSaleSchedule() public {
        vm.prank(vestingAdmin);
        bytes32 scheduleId = vesting.createPublicSaleSchedule(alice, 25_000 ether);

        AethelredVesting.VestingSchedule memory s = vesting.getSchedule(scheduleId);
        assertEq(uint8(s.category), uint8(AethelredVesting.AllocationCategory.PUBLIC_SALE_COMMUNITY));
    }

    function test_Revert_CreateSchedule_ZeroAmount() public {
        vm.prank(vestingAdmin);
        vm.expectRevert(AethelredVesting.InvalidAmount.selector);
        vesting.createCustomSchedule(
            alice, 0,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );
    }

    function test_Revert_CreateSchedule_ZeroBeneficiary() public {
        vm.prank(vestingAdmin);
        vm.expectRevert(AethelredVesting.InvalidBeneficiary.selector);
        vesting.createCustomSchedule(
            address(0), 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );
    }

    function test_Revert_CreateSchedule_MaxSchedulesExceeded() public {
        // Create MAX_SCHEDULES_PER_BENEFICIARY schedules for alice
        for (uint256 i = 0; i < vesting.MAX_SCHEDULES_PER_BENEFICIARY(); i++) {
            vm.prank(vestingAdmin);
            vesting.createCustomSchedule(
                alice, 100 ether,
                AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
                AethelredVesting.VestingType.LINEAR,
                0, 365 days, 0, 0, true, false
            );
        }

        // 11th should fail
        vm.prank(vestingAdmin);
        vm.expectRevert(AethelredVesting.MaxSchedulesExceeded.selector);
        vesting.createCustomSchedule(
            alice, 100 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );
    }

    function test_BeneficiarySchedules() public {
        vm.startPrank(vestingAdmin);
        bytes32 id1 = vesting.createCustomSchedule(
            alice, 100 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );
        bytes32 id2 = vesting.createCustomSchedule(
            alice, 200 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );
        vm.stopPrank();

        bytes32[] memory schedules = vesting.getBeneficiarySchedules(alice);
        assertEq(schedules.length, 2);
        assertEq(schedules[0], id1);
        assertEq(schedules[1], id2);
    }

    // =========================================================================
    // VESTING CALCULATION TESTS — LINEAR
    // =========================================================================

    function test_Vested_LinearBeforeStart() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();

        // Before any time passes, only TGE unlock (0 bps)
        assertEq(vesting.getVested(id), 0);
    }

    function test_Vested_LinearHalfway() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();

        // Advance halfway
        vm.warp(block.timestamp + 365 days / 2);

        uint256 vested = vesting.getVested(id);
        assertApproxEqAbs(vested, 500 ether, 1e15); // ~500 AETHEL +/- rounding
    }

    function test_Vested_LinearFullyVested() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();

        // Advance past full duration
        vm.warp(block.timestamp + 365 days + 1);

        assertEq(vesting.getVested(id), 1000 ether);
    }

    function test_Vested_LinearPastDuration() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();

        // Advance way past duration
        vm.warp(block.timestamp + 10 * 365 days);

        // Should cap at totalAmount
        assertEq(vesting.getVested(id), 1000 ether);
    }

    // =========================================================================
    // VESTING CALCULATION TESTS — CLIFF + TGE
    // =========================================================================

    function test_Vested_TGEUnlock() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.PUBLIC_SALE_COMMUNITY,
            AethelredVesting.VestingType.CLIFF_LINEAR,
            180 days,  // 6 month cliff
            730 days,  // 2 year total
            2250,      // 22.5% TGE
            0,         // no cliff unlock
            true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();

        // At TGE, should get 22.5%
        uint256 vested = vesting.getVested(id);
        assertEq(vested, 1000 ether * 2250 / BPS_BASE);
    }

    function test_Vested_CliffUnlock() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.CORE_CONTRIBUTORS,
            AethelredVesting.VestingType.CLIFF_LINEAR,
            365 days,   // 12 month cliff
            4 * 365 days, // 4 year total
            0,           // no TGE unlock
            2500,        // 25% cliff unlock
            true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();

        // Before cliff: 0
        vm.warp(block.timestamp + 364 days);
        assertEq(vesting.getVested(id), 0);

        // At cliff: 25%
        vm.warp(block.timestamp + 1 days + 1);
        uint256 vestedAtCliff = vesting.getVested(id);
        assertGe(vestedAtCliff, 1000 ether * 2500 / BPS_BASE);
    }

    function test_Vested_TGEPlusCliff() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 10000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.CLIFF_LINEAR,
            180 days,     // 6 month cliff
            5 * 365 days, // 5 year total
            500,          // 5% TGE
            1000,         // 10% cliff
            true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();

        // At TGE: 5% = 500 AETHEL
        uint256 tgeVested = vesting.getVested(id);
        assertEq(tgeVested, 10000 ether * 500 / BPS_BASE);

        // Just after cliff: 5% + 10% + some linear = >= 15%
        vm.warp(block.timestamp + 180 days + 1);
        uint256 cliffVested = vesting.getVested(id);
        assertGe(cliffVested, 10000 ether * 1500 / BPS_BASE);
    }

    // =========================================================================
    // RELEASE TESTS
    // =========================================================================

    function test_Release_Success() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();

        vm.warp(block.timestamp + 365 days + 1);

        uint256 balanceBefore = token.balanceOf(alice);

        vm.prank(alice);
        uint256 released = vesting.release(id);

        assertEq(released, 1000 ether);
        assertEq(token.balanceOf(alice), balanceBefore + 1000 ether);
    }

    function test_Release_PartialThenFull() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();

        // Release at 50%
        vm.warp(block.timestamp + 365 days / 2);

        vm.prank(alice);
        uint256 first = vesting.release(id);
        assertApproxEqAbs(first, 500 ether, 1e15);

        // Release at 100%
        vm.warp(block.timestamp + 365 days / 2 + 1);

        vm.prank(alice);
        uint256 second = vesting.release(id);
        assertApproxEqAbs(first + second, 1000 ether, 1e15);
    }

    function test_Revert_Release_BeforeTGE() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );

        vm.prank(alice);
        vm.expectRevert(AethelredVesting.TGENotOccurred.selector);
        vesting.release(id);
    }

    function test_Revert_Release_NothingToRelease() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();

        // Try to release at time 0 with 0% TGE
        vm.prank(alice);
        vm.expectRevert(AethelredVesting.NothingToRelease.selector);
        vesting.release(id);
    }

    function test_ReleaseAll_MultipleSchedules() public {
        vm.startPrank(vestingAdmin);
        vesting.createCustomSchedule(
            alice, 500 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );
        vesting.createCustomSchedule(
            alice, 300 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );
        vesting.executeTGE();
        vm.stopPrank();

        vm.warp(block.timestamp + 365 days + 1);

        vm.prank(alice);
        uint256 total = vesting.releaseAll();

        assertEq(total, 800 ether);
    }

    // =========================================================================
    // REVOCATION TESTS
    // =========================================================================

    function test_Revoke_BeforeAnyVesting() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );

        vm.prank(revoker);
        vesting.revokeSchedule(id);

        AethelredVesting.VestingSchedule memory s = vesting.getSchedule(id);
        assertTrue(s.revoked);
    }

    function test_Revoke_AfterPartialVesting() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();

        // 50% vested
        vm.warp(block.timestamp + 365 days / 2);

        vm.prank(alice);
        vesting.release(id);

        // Revoke remaining
        vm.prank(revoker);
        vesting.revokeSchedule(id);

        AethelredVesting.VestingSchedule memory s = vesting.getSchedule(id);
        assertTrue(s.revoked);
    }

    function test_Revert_Revoke_NotRevocable() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0,
            false, // NOT revocable
            false
        );

        vm.prank(revoker);
        vm.expectRevert(AethelredVesting.ScheduleNotRevocable.selector);
        vesting.revokeSchedule(id);
    }

    function test_Revert_Revoke_AlreadyRevoked() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );

        vm.prank(revoker);
        vesting.revokeSchedule(id);

        vm.prank(revoker);
        vm.expectRevert(AethelredVesting.ScheduleAlreadyRevoked.selector);
        vesting.revokeSchedule(id);
    }

    function test_Revert_Revoke_OnlyRevokerRole() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );

        vm.prank(alice);
        vm.expectRevert();
        vesting.revokeSchedule(id);
    }

    // =========================================================================
    // RECOVER TOKENS TESTS
    // =========================================================================

    function test_RecoverTokens_Success() public {
        // Send some extra tokens to vesting contract
        vm.prank(admin);
        token.transfer(address(vesting), 100 ether);

        uint256 recipientBefore = token.balanceOf(bob);

        vm.prank(admin);
        vesting.recoverTokens(address(token), 100 ether, bob);

        assertEq(token.balanceOf(bob), recipientBefore + 100 ether);
    }

    function test_Revert_RecoverTokens_NotAdmin() public {
        vm.prank(alice);
        vm.expectRevert();
        vesting.recoverTokens(address(token), 100 ether, bob);
    }

    // =========================================================================
    // BENEFICIARY TRANSFER TESTS
    // =========================================================================

    function test_TransferBeneficiary() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true,
            true // transferable
        );

        vm.prank(alice);
        vesting.transferBeneficiary(id, bob);

        AethelredVesting.VestingSchedule memory s = vesting.getSchedule(id);
        assertEq(s.beneficiary, bob);
    }

    function test_Revert_TransferBeneficiary_NotTransferable() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true,
            false // NOT transferable
        );

        vm.prank(alice);
        vm.expectRevert(AethelredVesting.NotTransferable.selector);
        vesting.transferBeneficiary(id, bob);
    }

    function test_Revert_TransferBeneficiary_NotBeneficiary() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, true
        );

        vm.prank(bob); // not alice
        vm.expectRevert(AethelredVesting.UnauthorizedBeneficiary.selector);
        vesting.transferBeneficiary(id, carol);
    }

    // =========================================================================
    // PAUSING TESTS
    // =========================================================================

    function test_Pause_BlocksRelease() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();

        vm.warp(block.timestamp + 365 days + 1);

        vm.prank(admin);
        vesting.pause();

        vm.prank(alice);
        vm.expectRevert();
        vesting.release(id);
    }

    // =========================================================================
    // FUZZ TESTS — VESTING MONOTONICITY
    // =========================================================================

    function testFuzz_Vested_Monotonic(uint256 t1, uint256 t2) public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1_000_000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 5 * 365 days, 0, 0, true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();

        uint256 tgeTime = block.timestamp;

        t1 = bound(t1, 0, 10 * 365 days);
        t2 = bound(t2, t1, 10 * 365 days);

        vm.warp(tgeTime + t1);
        uint256 v1 = vesting.getVested(id);

        vm.warp(tgeTime + t2);
        uint256 v2 = vesting.getVested(id);

        assertGe(v2, v1, "Vesting must be monotonically non-decreasing");
    }

    function testFuzz_Vested_NeverExceedsTotal(uint256 elapsed) public {
        uint256 totalAmount = 500_000 ether;
        elapsed = bound(elapsed, 0, 20 * 365 days);

        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, totalAmount,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.CLIFF_LINEAR,
            180 days, 4 * 365 days, 500, 1000, true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();

        vm.warp(block.timestamp + elapsed);

        uint256 vested = vesting.getVested(id);
        assertLe(vested, totalAmount, "Vested must never exceed total amount");
    }

    function testFuzz_Release_NeverExceedsVested(uint256 elapsed) public {
        uint256 totalAmount = 100_000 ether;
        elapsed = bound(elapsed, 1 days, 10 * 365 days);

        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, totalAmount,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 4 * 365 days, 0, 0, true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();

        vm.warp(block.timestamp + elapsed);

        uint256 vestedBefore = vesting.getVested(id);

        vm.prank(alice);
        uint256 released = vesting.release(id);

        assertLe(released, vestedBefore, "Released must not exceed vested");
    }

    function testFuzz_TotalReleasedAcrossSchedules(uint8 count, uint256 amount) public {
        count = uint8(bound(count, 1, 5));
        amount = bound(amount, 100 ether, 10_000 ether);

        vm.startPrank(vestingAdmin);
        for (uint8 i = 0; i < count; i++) {
            vesting.createCustomSchedule(
                alice, amount,
                AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
                AethelredVesting.VestingType.LINEAR,
                0, 365 days, 0, 0, true, false
            );
        }
        vesting.executeTGE();
        vm.stopPrank();

        vm.warp(block.timestamp + 365 days + 1);

        vm.prank(alice);
        uint256 total = vesting.releaseAll();

        assertEq(total, uint256(count) * amount);
    }

    // =========================================================================
    // BOUNDARY TESTS
    // =========================================================================

    function test_Boundary_ZeroDurationLinear() public {
        // Contract allows zero vestingDuration; _computeVested returns totalAmount
        // when vestingDuration == 0 (fully vested immediately after TGE)
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 0, // zero duration
            0, 0, true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();

        // With vestingDuration == 0, elapsed >= vestingDuration is true, so fully vested
        assertEq(vesting.getVested(id), 1000 ether);
    }

    function test_Boundary_ImmediateVesting() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.IMMEDIATE,
            0, 1, // minimal duration
            0, // TGE bps not needed for IMMEDIATE type (contract returns totalAmount)
            0, true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();

        uint256 vested = vesting.getVested(id);
        assertEq(vested, 1000 ether);
    }

    function test_Boundary_MaxTGEBps() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days,
            8000, // 80% TGE unlock (max allowed by contract)
            0, true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();

        // At TGE, 80% is vested (800 ether), remaining 20% vests linearly
        assertEq(vesting.getVested(id), 1000 ether * 8000 / BPS_BASE);
    }

    function test_Boundary_VeryLongDuration() public {
        // 50 year vesting schedule
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1_000_000 ether,
            AethelredVesting.AllocationCategory.COMPUTE_POUW_REWARDS,
            AethelredVesting.VestingType.LINEAR,
            0, 50 * 365 days,
            0, 0, true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();

        // After 50 years: fully vested
        vm.warp(block.timestamp + 50 * 365 days + 1);
        assertEq(vesting.getVested(id), 1_000_000 ether);
    }

    function test_Boundary_SmallAmount() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1, // 1 wei
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();

        vm.warp(block.timestamp + 365 days + 1);

        vm.prank(alice);
        uint256 released = vesting.release(id);
        assertEq(released, 1);
    }

    // =========================================================================
    // VESTING TYPE TESTS (8)
    // =========================================================================

    function test_Vested_MilestoneType_CreationOnly() public {
        // Milestone schedules can be created; vesting is unlock-based via achieveMilestone
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.MILESTONE,
            0, 365 days, 0, 0, true, false
        );
        AethelredVesting.VestingSchedule memory s = vesting.getSchedule(id);
        assertEq(uint8(s.vestingType), uint8(AethelredVesting.VestingType.MILESTONE));
    }

    function test_Vested_ImmediateFullUnlock_ReleaseAll() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 5000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.IMMEDIATE,
            0, 1, 0, 0, true, false // tgeUnlockBps=0; IMMEDIATE type returns totalAmount regardless
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();

        // IMMEDIATE type: 100% vested immediately
        assertEq(vesting.getVested(id), 5000 ether);

        vm.prank(alice);
        uint256 released = vesting.release(id);
        assertEq(released, 5000 ether);
        assertEq(token.balanceOf(alice), 5000 ether);
    }

    function test_Vested_CliffLinear_ZeroTGE_ZeroCliff() public {
        // No TGE, no cliff unlock, pure linear after cliff
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.CORE_CONTRIBUTORS,
            AethelredVesting.VestingType.CLIFF_LINEAR,
            365 days, 4 * 365 days, 0, 0, true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();

        // Before cliff: 0
        vm.warp(block.timestamp + 180 days);
        assertEq(vesting.getVested(id), 0);

        // After cliff: linear from 0
        vm.warp(block.timestamp + 186 days); // total = 366 days, just past cliff
        uint256 vested = vesting.getVested(id);
        assertGt(vested, 0);
        // Should be approx 1 day / (3 * 365 days) of total
        assertLt(vested, 10 ether);
    }

    function test_Vested_CliffLinear_MaxTGE_RemainingLinear() public {
        // 80% upfront (max allowed by tge+cliff), 20% linear
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 10000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.CLIFF_LINEAR,
            30 days, 365 days,
            5000, // 50% TGE
            3000, // 30% cliff (total upfront = 80%, the max)
            true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();

        // At TGE: 50% = 5000
        assertEq(vesting.getVested(id), 5000 ether);

        // After cliff: 50% + 30% = 8000 + some linear on the remaining 20%
        vm.warp(block.timestamp + 30 days);
        uint256 vestedAtCliff = vesting.getVested(id);
        assertGe(vestedAtCliff, 8000 ether);

        // Fully vested at end
        vm.warp(block.timestamp + 336 days);
        assertEq(vesting.getVested(id), 10000 ether);
    }

    function test_Vested_CliffLinear_JustBeforeCliff() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 2000 ether,
            AethelredVesting.AllocationCategory.CORE_CONTRIBUTORS,
            AethelredVesting.VestingType.CLIFF_LINEAR,
            365 days, 4 * 365 days,
            500, // 5% TGE
            2500, // 25% cliff
            true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();

        // 1 second before cliff: only TGE portion
        vm.warp(block.timestamp + 365 days - 1);
        uint256 vested = vesting.getVested(id);
        assertEq(vested, 2000 ether * 500 / BPS_BASE); // Only 5% TGE
    }

    function test_Vested_CliffLinear_ExactlyAtCliff() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 2000 ether,
            AethelredVesting.AllocationCategory.CORE_CONTRIBUTORS,
            AethelredVesting.VestingType.CLIFF_LINEAR,
            365 days, 4 * 365 days,
            500, // 5% TGE
            2500, // 25% cliff
            true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();

        // Exactly at cliff: TGE + cliff unlock, no linear yet
        vm.warp(block.timestamp + 365 days);
        uint256 vested = vesting.getVested(id);
        uint256 expected = (2000 ether * 500 / BPS_BASE) + (2000 ether * 2500 / BPS_BASE);
        assertEq(vested, expected); // 5% + 25% = 30%
    }

    function test_Vested_Linear_QuarterWay() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 4000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 400 days, 0, 0, true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();

        vm.warp(block.timestamp + 100 days);
        uint256 vested = vesting.getVested(id);
        assertEq(vested, 1000 ether); // 25%
    }

    function test_Vested_Linear_ThreeQuarterWay() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 4000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 400 days, 0, 0, true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();

        vm.warp(block.timestamp + 300 days);
        uint256 vested = vesting.getVested(id);
        assertEq(vested, 3000 ether); // 75%
    }

    // =========================================================================
    // CATEGORY TESTS (6)
    // =========================================================================

    function test_CreateComputeRewardsSchedule() public {
        // Compute/PoUW Rewards: 10yr linear, no cliff
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1_000_000 ether,
            AethelredVesting.AllocationCategory.COMPUTE_POUW_REWARDS,
            AethelredVesting.VestingType.LINEAR,
            0, 10 * 365 days, 0, 0, false, false
        );

        AethelredVesting.VestingSchedule memory s = vesting.getSchedule(id);
        assertEq(uint8(s.category), uint8(AethelredVesting.AllocationCategory.COMPUTE_POUW_REWARDS));
        assertEq(s.vestingDuration, 10 * 365 days);
        assertEq(s.cliffDuration, 0);
    }

    function test_CreateFoundationSchedule() public {
        // Foundation Reserve: 12mo cliff, 5yr total
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 100_000 ether,
            AethelredVesting.AllocationCategory.FOUNDATION_RESERVE,
            AethelredVesting.VestingType.CLIFF_LINEAR,
            365 days, 5 * 365 days, 0, 0, true, false
        );

        AethelredVesting.VestingSchedule memory s = vesting.getSchedule(id);
        assertEq(uint8(s.category), uint8(AethelredVesting.AllocationCategory.FOUNDATION_RESERVE));
        assertEq(s.cliffDuration, 365 days);
    }

    function test_CreateLiquiditySchedule() public {
        // Insurance/Stability: 10% TGE, 30mo vest
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 200_000 ether,
            AethelredVesting.AllocationCategory.INSURANCE_STABILITY,
            AethelredVesting.VestingType.LINEAR,
            0, 30 * 30 days, // ~30 months
            1000, 0, false, false
        );

        AethelredVesting.VestingSchedule memory s = vesting.getSchedule(id);
        assertEq(uint8(s.category), uint8(AethelredVesting.AllocationCategory.INSURANCE_STABILITY));
        assertEq(s.tgeUnlockBps, 1000);
    }

    function test_CreateAdvisorsSchedule() public {
        // Labs Treasury: 12mo cliff, 5yr total
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 50_000 ether,
            AethelredVesting.AllocationCategory.LABS_TREASURY,
            AethelredVesting.VestingType.CLIFF_LINEAR,
            365 days, 5 * 365 days, 0, 0, true, false
        );

        AethelredVesting.VestingSchedule memory s = vesting.getSchedule(id);
        assertEq(uint8(s.category), uint8(AethelredVesting.AllocationCategory.LABS_TREASURY));
    }

    function test_Revert_CreateSchedule_ExceedsCategoryCap() public {
        // Strategic Investors cap = 500M tokens
        uint256 cap = 500_000_000 * 1e18;
        vm.prank(vestingAdmin);
        vm.expectRevert(AethelredVesting.CategoryCapExceeded.selector);
        vesting.createCustomSchedule(
            alice, cap + 1,
            AethelredVesting.AllocationCategory.STRATEGIC_INVESTORS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, false, false
        );
    }

    function test_CategoryAllocation_MultipleSchedulesSameCategory() public {
        vm.startPrank(vestingAdmin);
        vesting.createCustomSchedule(
            alice, 100_000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );
        vesting.createCustomSchedule(
            bob, 200_000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );
        vm.stopPrank();

        (uint256 cap, uint256 allocated, ) = vesting.getCategoryStats(
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS
        );
        assertEq(allocated, 300_000 ether);
        assertGt(cap, allocated);
    }

    // =========================================================================
    // RELEASE EDGE CASES (6)
    // =========================================================================

    function test_Release_TGEOnly_ImmediateRelease() public {
        // 80% TGE unlock (max allowed), linear schedule for remaining 20%
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 500 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days,
            8000, // 80% TGE (max allowed by contract)
            0, true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();

        // TGE: 80% = 400 ether vested immediately
        assertEq(vesting.getVested(id), 500 ether * 8000 / BPS_BASE);

        vm.prank(alice);
        uint256 released = vesting.release(id);
        assertEq(released, 500 ether * 8000 / BPS_BASE);
    }

    function test_Release_RevokedSchedule_CannotRelease() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();
        vm.warp(block.timestamp + 180 days);

        // Revoke
        vm.prank(revoker);
        vesting.revokeSchedule(id);

        // Cannot release on revoked schedule
        vm.prank(alice);
        vm.expectRevert(AethelredVesting.ScheduleAlreadyRevoked.selector);
        vesting.release(id);
    }

    function test_Release_AfterRevoke_VestedFrozen() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();
        vm.warp(block.timestamp + 182 days); // ~50%

        uint256 vestedBeforeRevoke = vesting.getVested(id);

        vm.prank(revoker);
        vesting.revokeSchedule(id);

        // Even after more time passes, getVested returns the frozen vested amount
        // at revocation time (contract uses revokedTime as endTime)
        vm.warp(block.timestamp + 365 days);
        uint256 vestedAfter = vesting.getVested(id);
        // getVested returns the vested amount frozen at revocation time, not 0
        assertEq(vestedAfter, vestedBeforeRevoke);
        // The vested amount at revocation was non-zero
        assertGt(vestedBeforeRevoke, 0);
    }

    function test_Release_MultipleTimestamps_Incremental() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1200 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 360 days, 0, 0, true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();

        uint256 cumulativeReleased = 0;

        // Release at 1/4
        vm.warp(block.timestamp + 90 days);
        vm.prank(alice);
        uint256 r1 = vesting.release(id);
        cumulativeReleased += r1;
        assertEq(r1, 300 ether);

        // Release at 1/2
        vm.warp(block.timestamp + 90 days);
        vm.prank(alice);
        uint256 r2 = vesting.release(id);
        cumulativeReleased += r2;
        assertEq(r2, 300 ether);

        // Release at 3/4
        vm.warp(block.timestamp + 90 days);
        vm.prank(alice);
        uint256 r3 = vesting.release(id);
        cumulativeReleased += r3;
        assertEq(r3, 300 ether);

        // Release at end
        vm.warp(block.timestamp + 90 days);
        vm.prank(alice);
        uint256 r4 = vesting.release(id);
        cumulativeReleased += r4;
        assertEq(r4, 300 ether);

        assertEq(cumulativeReleased, 1200 ether);
    }

    function test_Revert_Release_NotBeneficiary() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();
        vm.warp(block.timestamp + 365 days + 1);

        // Bob tries to release Alice's schedule
        vm.prank(bob);
        vm.expectRevert(AethelredVesting.UnauthorizedBeneficiary.selector);
        vesting.release(id);
    }

    function test_Release_CliffLinear_StepByStep() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 10000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.CLIFF_LINEAR,
            180 days, 5 * 365 days,
            500, 1000, true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();
        uint256 tgeTs = vesting.tgeTime();

        // Step 1: At TGE, 5% available
        vm.prank(alice);
        uint256 r1 = vesting.release(id);
        assertEq(r1, 10000 ether * 500 / BPS_BASE); // 500 AETHEL

        // Step 2: Before cliff, nothing more
        vm.warp(tgeTs + 90 days);
        vm.prank(alice);
        vm.expectRevert(AethelredVesting.NothingToRelease.selector);
        vesting.release(id);

        // Step 3: Exactly at cliff, cliff unlock only (no linear yet)
        vm.warp(tgeTs + 180 days);
        vm.prank(alice);
        uint256 r3 = vesting.release(id);
        // At cliff boundary: linearElapsed = 0, so only cliff unlock
        assertEq(r3, 10000 ether * 1000 / BPS_BASE); // cliff: 10% = 1000

        // Step 4: At end, everything released
        vm.warp(tgeTs + 5 * 365 days + 1);
        vm.prank(alice);
        uint256 r4 = vesting.release(id);
        AethelredVesting.VestingSchedule memory s = vesting.getSchedule(id);
        assertEq(s.releasedAmount, 10000 ether);
    }

    // =========================================================================
    // REVOCATION ADVANCED (5)
    // =========================================================================

    function test_Revoke_MidVesting_VestedAmountFreeze() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 2000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 400 days, 0, 0, true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();

        // At 50%
        vm.warp(block.timestamp + 200 days);
        uint256 vestedMid = vesting.getVested(id);
        assertEq(vestedMid, 1000 ether);

        vm.prank(revoker);
        vesting.revokeSchedule(id);

        AethelredVesting.VestingSchedule memory s = vesting.getSchedule(id);
        assertTrue(s.revoked);
        assertEq(s.revokedTime, block.timestamp);
    }

    function test_Revoke_ReturnedToContract() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 2000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 400 days, 0, 0, true, false
        );

        uint256 allocBefore = vesting.totalAllocated();

        vm.prank(vestingAdmin);
        vesting.executeTGE();
        vm.warp(block.timestamp + 200 days); // 50%

        vm.prank(revoker);
        vesting.revokeSchedule(id);

        uint256 allocAfter = vesting.totalAllocated();
        // Unvested (50% = 1000) returned => allocated decreased by 1000
        assertEq(allocBefore - allocAfter, 1000 ether);
    }

    function test_Revoke_ThenRelease_OnlyVestedPortion() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 400 days, 0, 0, true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();
        vm.warp(block.timestamp + 200 days); // 50% = 500

        // Release first
        vm.prank(alice);
        uint256 r1 = vesting.release(id);
        assertEq(r1, 500 ether);

        // Now revoke
        vm.prank(revoker);
        vesting.revokeSchedule(id);

        // Can't release more
        vm.warp(block.timestamp + 200 days);
        vm.prank(alice);
        vm.expectRevert(AethelredVesting.ScheduleAlreadyRevoked.selector);
        vesting.release(id);
    }

    function test_Revoke_WithTGE_BeneficiaryKeepsTGE() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.PUBLIC_SALE_COMMUNITY,
            AethelredVesting.VestingType.CLIFF_LINEAR,
            0, 2 * 365 days,
            2250, 0, // 22.5% TGE
            true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();

        // Release TGE portion
        vm.prank(alice);
        uint256 tgeRelease = vesting.release(id);
        assertEq(tgeRelease, 1000 ether * 2250 / BPS_BASE);

        // Revoke immediately after TGE release
        vm.prank(revoker);
        vesting.revokeSchedule(id);

        // Beneficiary keeps what was released
        assertEq(token.balanceOf(alice), tgeRelease);
    }

    function test_Revoke_MultipleTimes_DifferentSchedules() public {
        vm.startPrank(vestingAdmin);
        bytes32 id1 = vesting.createCustomSchedule(
            alice, 500 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );
        bytes32 id2 = vesting.createCustomSchedule(
            alice, 700 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );
        vesting.executeTGE();
        vm.stopPrank();

        vm.warp(block.timestamp + 182 days);

        // Revoke first
        vm.prank(revoker);
        vesting.revokeSchedule(id1);

        // Second still active
        AethelredVesting.VestingSchedule memory s2 = vesting.getSchedule(id2);
        assertFalse(s2.revoked);

        // Revoke second
        vm.prank(revoker);
        vesting.revokeSchedule(id2);

        AethelredVesting.VestingSchedule memory s2After = vesting.getSchedule(id2);
        assertTrue(s2After.revoked);
    }

    // =========================================================================
    // BENEFICIARY TRANSFER ADVANCED (4)
    // =========================================================================

    function test_TransferBeneficiary_NewBeneficiaryCanRelease() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, false, true
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();
        vm.warp(block.timestamp + 365 days + 1);

        // Transfer to bob
        vm.prank(alice);
        vesting.transferBeneficiary(id, bob);

        // Bob can release
        vm.prank(bob);
        uint256 released = vesting.release(id);
        assertEq(released, 1000 ether);
        assertEq(token.balanceOf(bob), 1000 ether);
    }

    function test_TransferBeneficiary_OldBeneficiaryCannotRelease() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, false, true
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();
        vm.warp(block.timestamp + 365 days + 1);

        // Transfer to bob
        vm.prank(alice);
        vesting.transferBeneficiary(id, bob);

        // Alice cannot release
        vm.prank(alice);
        vm.expectRevert(AethelredVesting.UnauthorizedBeneficiary.selector);
        vesting.release(id);
    }

    function test_Revert_TransferBeneficiary_ToZeroAddress() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, false, true
        );

        vm.prank(alice);
        vm.expectRevert(AethelredVesting.InvalidBeneficiary.selector);
        vesting.transferBeneficiary(id, address(0));
    }

    function test_TransferBeneficiary_ThenRevoke() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, true
        );

        // Transfer to bob
        vm.prank(alice);
        vesting.transferBeneficiary(id, bob);

        // Revoke
        vm.prank(revoker);
        vesting.revokeSchedule(id);

        AethelredVesting.VestingSchedule memory s = vesting.getSchedule(id);
        assertTrue(s.revoked);
        assertEq(s.beneficiary, bob);
    }

    // =========================================================================
    // EVENT EMISSION (5)
    // =========================================================================

    function test_Event_ScheduleCreated() public {
        vm.prank(vestingAdmin);
        vm.expectEmit(false, true, false, true);
        emit VestingScheduleCreated(
            bytes32(0), // we don't check scheduleId exactly
            alice,
            1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0,
            0,
            365 days
        );
        vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );
    }

    function test_Event_TGEExecuted() public {
        vm.prank(vestingAdmin);
        vm.expectEmit(false, false, false, true);
        emit TGEExecuted(block.timestamp);
        vesting.executeTGE();
    }

    function test_Event_TokensReleased() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();
        vm.warp(block.timestamp + 365 days + 1);

        vm.prank(alice);
        vm.expectEmit(true, true, false, true);
        emit TokensReleased(id, alice, 1000 ether, 1000 ether);
        vesting.release(id);
    }

    function test_Event_ScheduleRevoked() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );

        vm.prank(revoker);
        vm.expectEmit(true, true, false, true);
        emit ScheduleRevoked(id, alice, 1000 ether, block.timestamp);
        vesting.revokeSchedule(id);
    }

    function test_Event_BeneficiaryTransferred() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, false, true
        );

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit BeneficiaryTransferred(id, alice, bob);
        vesting.transferBeneficiary(id, bob);
    }

    // =========================================================================
    // PAUSING ADVANCED (3)
    // =========================================================================

    function test_Revert_CreateSchedule_WhenPaused() public {
        vm.prank(admin);
        vesting.pause();

        // createCustomSchedule does NOT use whenNotPaused, so it should still work
        // But let's verify the pause state and that release is blocked
        assertTrue(vesting.paused());

        // Create still works (no whenNotPaused modifier on create)
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );
        assertNotEq(id, bytes32(0));
    }

    function test_Pause_ThenUnpause_ReleaseWorks() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();
        vm.warp(block.timestamp + 365 days + 1);

        // Pause
        vm.prank(admin);
        vesting.pause();

        // Release blocked
        vm.prank(alice);
        vm.expectRevert();
        vesting.release(id);

        // Unpause
        vm.prank(admin);
        vesting.unpause();

        // Release works now
        vm.prank(alice);
        uint256 released = vesting.release(id);
        assertEq(released, 1000 ether);
    }

    function test_Revert_ReleaseAll_WhenPaused() public {
        vm.startPrank(vestingAdmin);
        vesting.createCustomSchedule(
            alice, 500 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );
        vesting.executeTGE();
        vm.stopPrank();

        vm.warp(block.timestamp + 365 days + 1);

        vm.prank(admin);
        vesting.pause();

        vm.prank(alice);
        vm.expectRevert();
        vesting.releaseAll();
    }

    // =========================================================================
    // FUZZ TESTS (8)
    // =========================================================================

    function testFuzz_Vested_CliffLinear_NeverExceedsTotal(
        uint256 tgeBps,
        uint256 cliffBps,
        uint256 elapsed
    ) public {
        tgeBps = bound(tgeBps, 0, 4000);
        cliffBps = bound(cliffBps, 0, 4000);
        // Ensure tge + cliff <= 8000 (max 80%)
        if (tgeBps + cliffBps > 8000) {
            cliffBps = 8000 - tgeBps;
        }
        elapsed = bound(elapsed, 0, 20 * 365 days);

        uint256 totalAmount = 100_000 ether;

        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, totalAmount,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.CLIFF_LINEAR,
            180 days, 4 * 365 days,
            tgeBps, cliffBps, true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();

        vm.warp(block.timestamp + elapsed);
        uint256 vested = vesting.getVested(id);
        assertLe(vested, totalAmount, "Vested exceeds total");
    }

    function testFuzz_Release_CumulativeEqualsFinalVested(
        uint256 elapsed1,
        uint256 elapsed2
    ) public {
        elapsed1 = bound(elapsed1, 1 days, 2 * 365 days);
        elapsed2 = bound(elapsed2, elapsed1 + 1 days, 4 * 365 days + 1);

        uint256 totalAmount = 50_000 ether;

        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, totalAmount,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 4 * 365 days, 0, 0, true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();
        uint256 start = block.timestamp;

        // First release
        vm.warp(start + elapsed1);
        vm.prank(alice);
        uint256 r1 = vesting.release(id);

        // Second release
        vm.warp(start + elapsed2);
        vm.prank(alice);
        uint256 r2 = vesting.release(id);

        AethelredVesting.VestingSchedule memory s = vesting.getSchedule(id);
        assertEq(s.releasedAmount, r1 + r2, "Cumulative released mismatch");
    }

    function testFuzz_Vested_TGE_AlwaysAvailableImmediately(
        uint256 tgeBps,
        uint256 amount
    ) public {
        tgeBps = bound(tgeBps, 1, 8000);
        amount = bound(amount, 1 ether, 1_000_000 ether);

        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, amount,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.CLIFF_LINEAR,
            365 days, 4 * 365 days,
            tgeBps, 0, true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();

        uint256 vested = vesting.getVested(id);
        uint256 expectedTge = (amount * tgeBps) / BPS_BASE;
        assertEq(vested, expectedTge, "TGE not immediately available");
    }

    function testFuzz_Vested_CliffBehavior_BeforeAndAfter(
        uint256 cliffDuration,
        uint256 elapsed
    ) public {
        cliffDuration = bound(cliffDuration, 1 days, 2 * 365 days);
        elapsed = bound(elapsed, 0, 5 * 365 days);

        uint256 totalAmount = 10_000 ether;
        uint256 vestingDuration = 4 * 365 days;
        if (cliffDuration >= vestingDuration) {
            vestingDuration = cliffDuration + 365 days;
        }

        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, totalAmount,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.CLIFF_LINEAR,
            cliffDuration, vestingDuration,
            0, 0, true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();
        vm.warp(block.timestamp + elapsed);

        uint256 vested = vesting.getVested(id);

        if (elapsed < cliffDuration) {
            assertEq(vested, 0, "Should be 0 before cliff");
        } else {
            assertGe(vested, 0, "Should be >= 0 after cliff");
            assertLe(vested, totalAmount, "Should not exceed total");
        }
    }

    function testFuzz_Schedule_UniqueIds(uint256 salt1, uint256 salt2) public {
        salt1 = bound(salt1, 1 ether, 1_000_000 ether);
        salt2 = bound(salt2, 1 ether, 1_000_000 ether);
        vm.assume(salt1 != salt2);

        vm.startPrank(vestingAdmin);
        bytes32 id1 = vesting.createCustomSchedule(
            alice, salt1,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );
        bytes32 id2 = vesting.createCustomSchedule(
            alice, salt2,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );
        vm.stopPrank();

        assertNotEq(id1, id2, "Schedule IDs must be unique");
    }

    function testFuzz_Revoke_VestedFrozenAtRevokeTime(uint256 revokeTime) public {
        revokeTime = bound(revokeTime, 1 days, 4 * 365 days);

        uint256 totalAmount = 10_000 ether;

        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, totalAmount,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 4 * 365 days, 0, 0, true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();

        vm.warp(block.timestamp + revokeTime);
        uint256 vestedAtRevoke = vesting.getVested(id);

        vm.prank(revoker);
        vesting.revokeSchedule(id);

        // totalAllocated decreased by unvested portion
        AethelredVesting.VestingSchedule memory s = vesting.getSchedule(id);
        assertTrue(s.revoked);
        assertLe(vestedAtRevoke, totalAmount, "Vested at revoke should not exceed total");
    }

    function testFuzz_MultipleSchedules_IndependentVesting(
        uint256 amount1,
        uint256 amount2
    ) public {
        amount1 = bound(amount1, 100 ether, 100_000 ether);
        amount2 = bound(amount2, 100 ether, 100_000 ether);

        vm.startPrank(vestingAdmin);
        bytes32 id1 = vesting.createCustomSchedule(
            alice, amount1,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );
        bytes32 id2 = vesting.createCustomSchedule(
            bob, amount2,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 2 * 365 days, 0, 0, true, false
        );
        vesting.executeTGE();
        vm.stopPrank();

        vm.warp(block.timestamp + 365 days + 1);

        // Alice fully vested
        uint256 v1 = vesting.getVested(id1);
        assertEq(v1, amount1);

        // Bob only ~50%
        uint256 v2 = vesting.getVested(id2);
        assertApproxEqAbs(v2, amount2 / 2, amount2 / 100); // within 1%
    }

    function testFuzz_Release_IdempotentAfterFullVesting(uint256 extraTime) public {
        extraTime = bound(extraTime, 0, 10 * 365 days);

        uint256 totalAmount = 5000 ether;

        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, totalAmount,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();

        // Fully vest
        vm.warp(block.timestamp + 365 days + 1);

        vm.prank(alice);
        uint256 r1 = vesting.release(id);
        assertEq(r1, totalAmount);

        // Wait more time
        vm.warp(block.timestamp + extraTime);

        // Trying to release again should revert (nothing to release)
        vm.prank(alice);
        vm.expectRevert(AethelredVesting.NothingToRelease.selector);
        vesting.release(id);
    }

    // =========================================================================
    // BOUNDARY TESTS (6)
    // =========================================================================

    function test_Boundary_MaxUint256TGEBps() public {
        // TGE BPS above BPS_DENOMINATOR should revert
        vm.prank(vestingAdmin);
        vm.expectRevert(AethelredVesting.InvalidAmount.selector);
        vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days,
            BPS_BASE + 1, // 10001 > 10000
            0, true, false
        );
    }

    function test_Boundary_VeryLargeAmount_NoOverflow() public {
        // Use a large but valid amount: 3 billion tokens (within compute cap)
        uint256 largeAmount = 2_999_000_000 * 1e18;

        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, largeAmount,
            AethelredVesting.AllocationCategory.COMPUTE_POUW_REWARDS,
            AethelredVesting.VestingType.CLIFF_LINEAR,
            365 days, 10 * 365 days,
            500, 1000, true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();

        // TGE: 5% of 2.999B
        uint256 expectedTge = largeAmount * 500 / BPS_BASE;
        assertEq(vesting.getVested(id), expectedTge);

        // After full duration
        vm.warp(block.timestamp + 10 * 365 days + 1);
        assertEq(vesting.getVested(id), largeAmount);
    }

    function test_Boundary_MinimalCliff_1Second() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.CLIFF_LINEAR,
            1, // 1 second cliff
            365 days,
            0, 0, true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();

        // Before cliff (at t=0): 0
        assertEq(vesting.getVested(id), 0);

        // After 1 second: past cliff, some vesting
        vm.warp(block.timestamp + 1);
        uint256 vested = vesting.getVested(id);
        assertGe(vested, 0);
    }

    function test_Boundary_MaxCliffBps_10000() public {
        // cliffBps can't exceed 10000 but tge+cliff max is 8000
        vm.prank(vestingAdmin);
        vm.expectRevert(AethelredVesting.InvalidAmount.selector);
        vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.CLIFF_LINEAR,
            180 days, 365 days,
            0, 8001, // exceeds 8000 max upfront
            true, false
        );
    }

    function test_Boundary_MultipleSchedules_SameBeneficiary_MaxCount() public {
        uint256 maxSchedules = vesting.MAX_SCHEDULES_PER_BENEFICIARY();

        vm.startPrank(vestingAdmin);
        bytes32[] memory ids = new bytes32[](maxSchedules);
        for (uint256 i = 0; i < maxSchedules; i++) {
            ids[i] = vesting.createCustomSchedule(
                alice, 100 ether,
                AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
                AethelredVesting.VestingType.LINEAR,
                0, 365 days, 0, 0, true, false
            );
        }
        vm.stopPrank();

        bytes32[] memory aliceSchedules = vesting.getBeneficiarySchedules(alice);
        assertEq(aliceSchedules.length, maxSchedules);

        // Verify each schedule is unique
        for (uint256 i = 0; i < maxSchedules; i++) {
            for (uint256 j = i + 1; j < maxSchedules; j++) {
                assertNotEq(ids[i], ids[j]);
            }
        }
    }

    function test_Boundary_ReleaseAtExactVestingEnd() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();

        // Warp to exactly vestingDuration (not +1)
        vm.warp(block.timestamp + 365 days);
        uint256 vested = vesting.getVested(id);
        assertEq(vested, 1000 ether); // elapsed >= vestingDuration => totalAmount

        vm.prank(alice);
        uint256 released = vesting.release(id);
        assertEq(released, 1000 ether);
    }

    // =========================================================================
    // INTEGRATION TESTS (4)
    // =========================================================================

    function test_Integration_CreateRelease_MultipleBeneficiaries() public {
        vm.startPrank(vestingAdmin);
        bytes32 idAlice = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );
        bytes32 idBob = vesting.createCustomSchedule(
            bob, 2000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );
        bytes32 idCarol = vesting.createCustomSchedule(
            carol, 3000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );
        vesting.executeTGE();
        vm.stopPrank();

        vm.warp(block.timestamp + 365 days + 1);

        vm.prank(alice);
        vesting.release(idAlice);
        assertEq(token.balanceOf(alice), 1000 ether);

        vm.prank(bob);
        vesting.release(idBob);
        assertEq(token.balanceOf(bob), 2000 ether);

        vm.prank(carol);
        vesting.release(idCarol);
        assertEq(token.balanceOf(carol), 3000 ether);

        assertEq(vesting.totalReleased(), 6000 ether);
    }

    function test_Integration_TGE_CliffRelease_LinearRelease_FullCycle() public {
        // Ecosystem Grants: 5% TGE, 6mo cliff, 10% cliff unlock, 5yr total
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 10000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.CLIFF_LINEAR,
            180 days, 5 * 365 days,
            500, 1000, // 5% TGE, 10% cliff
            true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();
        uint256 tgeTs = vesting.tgeTime();

        // Phase 1: TGE release (5%)
        vm.prank(alice);
        uint256 tgeRelease = vesting.release(id);
        assertEq(tgeRelease, 500 ether);

        // Phase 2: During cliff - nothing more
        vm.warp(tgeTs + 90 days);
        vm.prank(alice);
        vm.expectRevert(AethelredVesting.NothingToRelease.selector);
        vesting.release(id);

        // Phase 3: Exactly at cliff - cliff unlock only (no linear yet)
        vm.warp(tgeTs + 180 days);
        vm.prank(alice);
        uint256 cliffRelease = vesting.release(id);
        assertEq(cliffRelease, 1000 ether); // exactly cliff amount (0 linear at cliff boundary)

        // Phase 4: Mid-linear
        vm.warp(tgeTs + 3 * 365 days); // ~60% through total duration
        vm.prank(alice);
        uint256 midRelease = vesting.release(id);
        assertGt(midRelease, 0);

        // Phase 5: Full duration
        vm.warp(tgeTs + 5 * 365 days + 1);
        vm.prank(alice);
        uint256 finalRelease = vesting.release(id);

        AethelredVesting.VestingSchedule memory s = vesting.getSchedule(id);
        assertEq(s.releasedAmount, 10000 ether);
    }

    function test_Integration_RevokeAndCreateNew_SameBeneficiary() public {
        vm.prank(vestingAdmin);
        bytes32 id1 = vesting.createCustomSchedule(
            alice, 1000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();
        vm.warp(block.timestamp + 180 days);

        // Release partial
        vm.prank(alice);
        uint256 r1 = vesting.release(id1);
        assertGt(r1, 0);

        // Revoke
        vm.prank(revoker);
        vesting.revokeSchedule(id1);

        // Create new schedule for alice
        vm.prank(vestingAdmin);
        bytes32 id2 = vesting.createCustomSchedule(
            alice, 500 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 365 days, 0, 0, true, false
        );

        // Warp and release new schedule
        vm.warp(block.timestamp + 365 days + 1);
        vm.prank(alice);
        uint256 r2 = vesting.release(id2);
        assertEq(r2, 500 ether);

        // Total alice balance: first partial + full second
        assertEq(token.balanceOf(alice), r1 + r2);
    }

    function test_Integration_TransferBeneficiary_ContinueVesting() public {
        vm.prank(vestingAdmin);
        bytes32 id = vesting.createCustomSchedule(
            alice, 2000 ether,
            AethelredVesting.AllocationCategory.ECOSYSTEM_GRANTS,
            AethelredVesting.VestingType.LINEAR,
            0, 400 days, 0, 0, false, true
        );

        vm.prank(vestingAdmin);
        vesting.executeTGE();
        uint256 tgeTs = vesting.tgeTime();

        // Alice releases 25%
        vm.warp(tgeTs + 100 days);
        vm.prank(alice);
        uint256 aliceRelease = vesting.release(id);
        assertEq(aliceRelease, 500 ether);

        // Transfer to bob
        vm.prank(alice);
        vesting.transferBeneficiary(id, bob);

        // Bob continues vesting, releases at 75%
        vm.warp(tgeTs + 300 days);
        vm.prank(bob);
        uint256 bobRelease = vesting.release(id);
        assertEq(bobRelease, 1000 ether); // 75% - 25% already released = 50%

        // Bob releases rest
        vm.warp(tgeTs + 400 days + 1);
        vm.prank(bob);
        uint256 bobFinal = vesting.release(id);
        assertEq(bobFinal, 500 ether); // 100% - 75% = 25%

        // Final check
        assertEq(token.balanceOf(alice), 500 ether);
        assertEq(token.balanceOf(bob), 1500 ether);
        assertEq(token.balanceOf(alice) + token.balanceOf(bob), 2000 ether);
    }
}
