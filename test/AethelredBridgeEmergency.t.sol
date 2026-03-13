// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../contracts/AethelredBridge.sol";

contract AethelredBridgeEmergencyTest is Test {
    AethelredBridge public bridge;
    AethelredBridge public bridgeImplementation;

    address public admin = address(0x1);
    address public user = address(0x2);
    address public recipient = address(0x3);
    address public guardian2 = address(0x4);

    bytes32 public constant AETHELRED_RECIPIENT = bytes32(uint256(0xABCDEF));
    uint256 public constant CONSENSUS_THRESHOLD_BPS = 6700;

    function setUp() public {
        address[] memory relayers = new address[](3);
        relayers[0] = address(0x10);
        relayers[1] = address(0x11);
        relayers[2] = address(0x12);

        bridgeImplementation = new AethelredBridge();

        bytes memory initData = abi.encodeCall(
            AethelredBridge.initialize,
            (admin, relayers, CONSENSUS_THRESHOLD_BPS)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(bridgeImplementation), initData);
        bridge = AethelredBridge(payable(address(proxy)));

        // Grant guardian role to a second guardian for multi-sig approval
        bytes32 guardianRole = bridge.GUARDIAN_ROLE();
        vm.prank(admin);
        bridge.grantRole(guardianRole, guardian2);

        vm.deal(user, 100 ether);
        vm.prank(user);
        bridge.depositETH{value: 10 ether}(AETHELRED_RECIPIENT);
    }

    function test_QueueEmergencyWithdrawal_StoresRequest() public {
        vm.prank(admin);
        bytes32 operationId = bridge.queueEmergencyWithdrawal(address(0), 1 ether, recipient);

        (
            address token,
            uint256 amount,
            address queuedRecipient,
            uint256 queuedAt,
            uint256 executeAfter,
            bool executed,
            bool cancelled
        ) = bridge.emergencyWithdrawalRequests(operationId);

        assertEq(token, address(0));
        assertEq(amount, 1 ether);
        assertEq(queuedRecipient, recipient);
        assertEq(queuedAt, block.timestamp);
        assertEq(executeAfter, block.timestamp + bridge.emergencyWithdrawalDelay());
        assertFalse(executed);
        assertFalse(cancelled);
    }

    function test_ExecuteEmergencyWithdrawal_RevertsBeforeDelay() public {
        vm.prank(admin);
        bytes32 operationId = bridge.queueEmergencyWithdrawal(address(0), 1 ether, recipient);

        vm.prank(admin);
        vm.expectRevert(AethelredBridge.EmergencyWithdrawalNotReady.selector);
        bridge.executeEmergencyWithdrawal(operationId);
    }

    function test_ExecuteEmergencyWithdrawal_AfterDelayTransfers() public {
        vm.prank(admin);
        bytes32 operationId = bridge.queueEmergencyWithdrawal(address(0), 2 ether, recipient);

        // Guardian approvals (need 2 of N)
        vm.prank(admin);
        bridge.approveEmergencyWithdrawal(operationId);
        vm.prank(guardian2);
        bridge.approveEmergencyWithdrawal(operationId);

        vm.warp(block.timestamp + bridge.emergencyWithdrawalDelay() + 1);
        uint256 recipientBalanceBefore = recipient.balance;

        vm.prank(admin);
        bridge.executeEmergencyWithdrawal(operationId);

        assertEq(recipient.balance, recipientBalanceBefore + 2 ether);

        (, , , , , bool executed, bool cancelled) = bridge.emergencyWithdrawalRequests(operationId);
        assertTrue(executed);
        assertFalse(cancelled);
    }

    function test_CancelEmergencyWithdrawal_PreventsExecution() public {
        vm.prank(admin);
        bytes32 operationId = bridge.queueEmergencyWithdrawal(address(0), 1 ether, recipient);

        vm.prank(admin);
        bridge.cancelEmergencyWithdrawal(operationId);

        vm.warp(block.timestamp + bridge.emergencyWithdrawalDelay() + 1);
        vm.prank(admin);
        vm.expectRevert(AethelredBridge.EmergencyWithdrawalAlreadyHandled.selector);
        bridge.executeEmergencyWithdrawal(operationId);
    }

    function test_EmergencyWithdrawAlias_QueuesInsteadOfImmediateTransfer() public {
        uint256 recipientBalanceBefore = recipient.balance;

        vm.prank(admin);
        bridge.emergencyWithdraw(address(0), 1 ether, recipient);

        assertEq(recipient.balance, recipientBalanceBefore);
        assertEq(bridge.emergencyWithdrawalNonce(), 1);
    }

    function test_SetEmergencyWithdrawalDelay_RejectsOutOfRange() public {
        vm.prank(admin);
        vm.expectRevert(AethelredBridge.InvalidEmergencyDelay.selector);
        bridge.setEmergencyWithdrawalDelay(1 hours);
    }

    function test_SetEmergencyWithdrawalDelay_AcceptsValidRange() public {
        vm.prank(admin);
        bridge.setEmergencyWithdrawalDelay(72 hours);
        assertEq(bridge.emergencyWithdrawalDelay(), 72 hours);
    }

    // =========================================================================
    // AUDIT REGRESSION - Emergency Withdrawal Amount Cap
    // =========================================================================

    function test_Audit_EmergencyWithdrawal_ExceedsMaxReverts() public {
        // MAX_EMERGENCY_WITHDRAWAL is 50 ETH; queuing 51 ETH should revert
        vm.prank(admin);
        vm.expectRevert(AethelredBridge.EmergencyAmountExceedsMax.selector);
        bridge.queueEmergencyWithdrawal(address(0), 51 ether, recipient);
    }

    function test_Audit_EmergencyWithdrawal_ExactMaxSucceeds() public {
        // Fund bridge with enough ETH
        vm.deal(user, 200 ether);
        vm.prank(user);
        bridge.depositETH{value: 100 ether}(bytes32(uint256(0xABCDEF)));

        // 50 ETH (exactly at cap) should succeed
        vm.prank(admin);
        bridge.queueEmergencyWithdrawal(address(0), 50 ether, recipient);
        assertEq(bridge.emergencyWithdrawalNonce(), 1);
    }

    // =========================================================================
    // AUDIT REGRESSION - Emergency Withdrawal Accounting
    // =========================================================================

    function test_Audit_EmergencyWithdrawal_UpdatesTotalLockedETH() public {
        uint256 lockedBefore = bridge.totalLockedETH();
        assertEq(lockedBefore, 10 ether); // From setUp deposit

        vm.prank(admin);
        bytes32 operationId = bridge.queueEmergencyWithdrawal(address(0), 3 ether, recipient);

        // Guardian approvals
        vm.prank(admin);
        bridge.approveEmergencyWithdrawal(operationId);
        vm.prank(guardian2);
        bridge.approveEmergencyWithdrawal(operationId);

        vm.warp(block.timestamp + bridge.emergencyWithdrawalDelay() + 1);

        vm.prank(admin);
        bridge.executeEmergencyWithdrawal(operationId);

        // totalLockedETH must be decremented
        assertEq(bridge.totalLockedETH(), 7 ether);
        // Balance must match
        assertEq(address(bridge).balance, 7 ether);
    }
}
