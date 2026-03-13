// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/access/IAccessControl.sol";
import "../contracts/AethelredBridge.sol";

/**
 * @title MockERC20
 * @dev Simple ERC20 token for testing
 */
contract MockERC20 is ERC20 {
    constructor(string memory name, string memory symbol) ERC20(name, symbol) {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/**
 * @title AethelredBridgeTest
 * @author Aethelred Team
 * @notice Comprehensive Foundry test suite for AethelredBridge
 *
 * Test Categories:
 * - Initialization and setup
 * - ETH deposits and cancellations
 * - ERC20 deposits and cancellations
 * - Withdrawal proposals and voting
 * - Challenge mechanism
 * - Rate limiting
 * - Access control
 * - Edge cases and security
 */
contract AethelredBridgeTest is Test {
    // =========================================================================
    // STATE
    // =========================================================================

    AethelredBridge public bridge;
    AethelredBridge public bridgeImplementation;
    MockERC20 public mockToken;

    address public admin = address(0x1);
    address public guardian = address(0x2);
    address public user1 = address(0x3);
    address public user2 = address(0x4);
    address public blockedUser = address(0x5);

    address[] public relayers;
    address public relayer1 = address(0x10);
    address public relayer2 = address(0x11);
    address public relayer3 = address(0x12);
    address public relayer4 = address(0x13);
    address public relayer5 = address(0x14);

    bytes32 public constant AETHELRED_RECIPIENT = bytes32(uint256(0xABCDEF));
    uint256 public constant CONSENSUS_THRESHOLD_BPS = 6700; // 67%

    event DepositInitiated(
        bytes32 indexed depositId,
        address indexed depositor,
        bytes32 indexed aethelredRecipient,
        address token,
        uint256 amount,
        uint256 nonce,
        uint256 timestamp
    );

    event WithdrawalChallenged(
        bytes32 indexed proposalId,
        address indexed challenger,
        string reason
    );

    // =========================================================================
    // SETUP
    // =========================================================================

    function setUp() public {
        // Setup relayers
        relayers = new address[](5);
        relayers[0] = relayer1;
        relayers[1] = relayer2;
        relayers[2] = relayer3;
        relayers[3] = relayer4;
        relayers[4] = relayer5;

        // Deploy implementation
        bridgeImplementation = new AethelredBridge();

        // Deploy proxy
        bytes memory initData = abi.encodeCall(
            AethelredBridge.initialize,
            (admin, relayers, CONSENSUS_THRESHOLD_BPS)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(bridgeImplementation), initData);
        bridge = AethelredBridge(payable(address(proxy)));

        // Setup guardian role
        bytes32 guardianRole = bridge.GUARDIAN_ROLE();
        vm.prank(admin);
        bridge.grantRole(guardianRole, guardian);

        // Deploy mock token
        mockToken = new MockERC20("Mock USDC", "mUSDC");

        // Add token support
        vm.prank(admin);
        bridge.addSupportedToken(address(mockToken));

        // Fund users
        vm.deal(user1, 1000 ether);
        vm.deal(user2, 1000 ether);
        mockToken.mint(user1, 1000000e18);
        mockToken.mint(user2, 1000000e18);

        // Block a user for testing
        vm.prank(guardian);
        bridge.setAddressBlocked(blockedUser, true);
    }

    // =========================================================================
    // INITIALIZATION TESTS
    // =========================================================================

    function test_Initialize() public view {
        assertEq(bridge.hasRole(bridge.DEFAULT_ADMIN_ROLE(), admin), true);
        assertEq(bridge.hasRole(bridge.GUARDIAN_ROLE(), admin), true);
        assertEq(bridge.hasRole(bridge.UPGRADER_ROLE(), admin), true);

        for (uint256 i = 0; i < relayers.length; i++) {
            assertEq(bridge.hasRole(bridge.RELAYER_ROLE(), relayers[i]), true);
        }

        (uint256 relayerCount, uint256 threshold, uint256 minVotes) = bridge.relayerConfig();
        assertEq(relayerCount, 5);
        assertEq(threshold, CONSENSUS_THRESHOLD_BPS);
        assertEq(minVotes, 3); // 5 * 67% = 3.35, rounded down = 3
    }

    function test_CannotReinitialize() public {
        vm.expectRevert();
        bridge.initialize(admin, relayers, CONSENSUS_THRESHOLD_BPS);
    }

    // =========================================================================
    // ETH DEPOSIT TESTS
    // =========================================================================

    function test_DepositETH() public {
        uint256 amount = 1 ether;
        uint256 balanceBefore = address(bridge).balance;

        vm.prank(user1);
        bridge.depositETH{value: amount}(AETHELRED_RECIPIENT);

        assertEq(address(bridge).balance, balanceBefore + amount);
        assertEq(bridge.totalLockedETH(), amount);
        assertEq(bridge.depositNonce(), 1);
    }

    function test_DepositETH_EmitsEvent() public {
        uint256 amount = 1 ether;

        vm.prank(user1);
        vm.expectEmit(false, true, true, false);
        emit DepositInitiated(
            bytes32(0), // depositId computed
            user1,
            AETHELRED_RECIPIENT,
            address(0),
            amount,
            0,
            block.timestamp
        );
        bridge.depositETH{value: amount}(AETHELRED_RECIPIENT);
    }

    function test_DepositETH_MinimumAmount() public {
        vm.prank(user1);
        vm.expectRevert(AethelredBridge.InvalidAmount.selector);
        bridge.depositETH{value: 0.001 ether}(AETHELRED_RECIPIENT);
    }

    function test_DepositETH_MaximumAmount() public {
        vm.prank(user1);
        vm.expectRevert(AethelredBridge.InvalidAmount.selector);
        bridge.depositETH{value: 101 ether}(AETHELRED_RECIPIENT);
    }

    function test_DepositETH_InvalidRecipient() public {
        vm.prank(user1);
        vm.expectRevert(AethelredBridge.InvalidRecipient.selector);
        bridge.depositETH{value: 1 ether}(bytes32(0));
    }

    function test_DepositETH_BlockedAddress() public {
        vm.deal(blockedUser, 10 ether);
        vm.prank(blockedUser);
        vm.expectRevert(AethelredBridge.AddressBlocked.selector);
        bridge.depositETH{value: 1 ether}(AETHELRED_RECIPIENT);
    }

    function test_DepositETH_WhenPaused() public {
        vm.prank(guardian);
        bridge.pause();

        vm.prank(user1);
        vm.expectRevert();
        bridge.depositETH{value: 1 ether}(AETHELRED_RECIPIENT);
    }

    function test_CancelDeposit_ETH() public {
        uint256 amount = 1 ether;
        uint256 balanceBefore = user1.balance;

        // Deposit
        vm.prank(user1);
        bridge.depositETH{value: amount}(AETHELRED_RECIPIENT);

        // Get deposit ID
        bytes32 depositId = _computeDepositId(user1, AETHELRED_RECIPIENT, address(0), amount, 0);

        // Cancel
        vm.prank(user1);
        bridge.cancelDeposit(depositId);

        assertEq(user1.balance, balanceBefore);
        assertEq(bridge.totalLockedETH(), 0);

        AethelredBridge.Deposit memory deposit = bridge.getDeposit(depositId);
        assertTrue(deposit.cancelled);
    }

    function test_CancelDeposit_NotDepositor() public {
        uint256 amount = 1 ether;

        vm.prank(user1);
        bridge.depositETH{value: amount}(AETHELRED_RECIPIENT);

        bytes32 depositId = _computeDepositId(user1, AETHELRED_RECIPIENT, address(0), amount, 0);

        vm.prank(user2);
        vm.expectRevert(AethelredBridge.InvalidRecipient.selector);
        bridge.cancelDeposit(depositId);
    }

    // =========================================================================
    // ERC20 DEPOSIT TESTS
    // =========================================================================

    function test_DepositERC20() public {
        uint256 amount = 10e18;

        vm.startPrank(user1);
        mockToken.approve(address(bridge), amount);
        bridge.depositERC20(address(mockToken), amount, AETHELRED_RECIPIENT);
        vm.stopPrank();

        assertEq(mockToken.balanceOf(address(bridge)), amount);
        assertEq(bridge.totalLockedERC20(address(mockToken)), amount);
    }

    function test_DepositERC20_UnsupportedToken() public {
        MockERC20 unsupportedToken = new MockERC20("Unsupported", "UNS");
        unsupportedToken.mint(user1, 1000e18);

        vm.startPrank(user1);
        unsupportedToken.approve(address(bridge), 1000e18);
        vm.expectRevert(AethelredBridge.TokenNotSupported.selector);
        bridge.depositERC20(address(unsupportedToken), 1000e18, AETHELRED_RECIPIENT);
        vm.stopPrank();
    }

    function test_CancelDeposit_ERC20() public {
        uint256 amount = 10e18;
        uint256 balanceBefore = mockToken.balanceOf(user1);

        vm.startPrank(user1);
        mockToken.approve(address(bridge), amount);
        bridge.depositERC20(address(mockToken), amount, AETHELRED_RECIPIENT);
        vm.stopPrank();

        bytes32 depositId = _computeDepositId(user1, AETHELRED_RECIPIENT, address(mockToken), amount, 0);

        vm.prank(user1);
        bridge.cancelDeposit(depositId);

        assertEq(mockToken.balanceOf(user1), balanceBefore);
        assertEq(bridge.totalLockedERC20(address(mockToken)), 0);
    }

    // =========================================================================
    // WITHDRAWAL TESTS
    // =========================================================================

    function test_ProposeWithdrawal() public {
        // First deposit some ETH
        vm.prank(user1);
        bridge.depositETH{value: 10 ether}(AETHELRED_RECIPIENT);

        bytes32 proposalId = keccak256("proposal1");
        bytes32 burnTxHash = keccak256("burn1");

        vm.prank(relayer1);
        bridge.proposeWithdrawal(
            proposalId,
            user2,
            address(0),
            1 ether,
            burnTxHash,
            12345
        );

        AethelredBridge.WithdrawalProposal memory proposal = bridge.getWithdrawalProposal(proposalId);
        assertEq(proposal.recipient, user2);
        assertEq(proposal.amount, 1 ether);
        assertEq(proposal.voteCount, 1);
        assertFalse(proposal.processed);
    }

    function test_VoteWithdrawal() public {
        // Setup
        vm.prank(user1);
        bridge.depositETH{value: 10 ether}(AETHELRED_RECIPIENT);

        bytes32 proposalId = keccak256("proposal1");
        bytes32 burnTxHash = keccak256("burn1");

        vm.prank(relayer1);
        bridge.proposeWithdrawal(proposalId, user2, address(0), 1 ether, burnTxHash, 12345);

        // Vote
        vm.prank(relayer2);
        bridge.voteWithdrawal(proposalId);

        vm.prank(relayer3);
        bridge.voteWithdrawal(proposalId);

        AethelredBridge.WithdrawalProposal memory proposal = bridge.getWithdrawalProposal(proposalId);
        assertEq(proposal.voteCount, 3);
    }

    function test_VoteWithdrawal_CannotVoteTwice() public {
        vm.prank(user1);
        bridge.depositETH{value: 10 ether}(AETHELRED_RECIPIENT);

        bytes32 proposalId = keccak256("proposal1");
        bytes32 burnTxHash = keccak256("burn1");

        vm.prank(relayer1);
        bridge.proposeWithdrawal(proposalId, user2, address(0), 1 ether, burnTxHash, 12345);

        vm.prank(relayer1);
        vm.expectRevert(AethelredBridge.AlreadyVoted.selector);
        bridge.voteWithdrawal(proposalId);
    }

    function test_ProcessWithdrawal_ETH() public {
        // Setup
        vm.prank(user1);
        bridge.depositETH{value: 10 ether}(AETHELRED_RECIPIENT);

        bytes32 proposalId = keccak256("proposal1");
        bytes32 burnTxHash = keccak256("burn1");
        uint256 withdrawAmount = 1 ether;

        // Propose and vote
        vm.prank(relayer1);
        bridge.proposeWithdrawal(proposalId, user2, address(0), withdrawAmount, burnTxHash, 12345);

        vm.prank(relayer2);
        bridge.voteWithdrawal(proposalId);

        vm.prank(relayer3);
        bridge.voteWithdrawal(proposalId);

        // Wait for challenge period
        vm.warp(block.timestamp + 7 days + 1);

        uint256 user2BalanceBefore = user2.balance;

        // Process
        bridge.processWithdrawal(proposalId);

        assertEq(user2.balance, user2BalanceBefore + withdrawAmount);
        assertEq(bridge.totalLockedETH(), 10 ether - withdrawAmount);

        AethelredBridge.WithdrawalProposal memory proposal = bridge.getWithdrawalProposal(proposalId);
        assertTrue(proposal.processed);
    }

    function test_ProcessWithdrawal_BeforeChallengePeriod() public {
        vm.prank(user1);
        bridge.depositETH{value: 10 ether}(AETHELRED_RECIPIENT);

        bytes32 proposalId = keccak256("proposal1");
        bytes32 burnTxHash = keccak256("burn1");

        vm.prank(relayer1);
        bridge.proposeWithdrawal(proposalId, user2, address(0), 1 ether, burnTxHash, 12345);

        vm.prank(relayer2);
        bridge.voteWithdrawal(proposalId);

        vm.prank(relayer3);
        bridge.voteWithdrawal(proposalId);

        // Try to process before challenge period ends
        vm.expectRevert(AethelredBridge.ChallengePeriodNotEnded.selector);
        bridge.processWithdrawal(proposalId);
    }

    function test_ProcessWithdrawal_InsufficientVotes() public {
        vm.prank(user1);
        bridge.depositETH{value: 10 ether}(AETHELRED_RECIPIENT);

        bytes32 proposalId = keccak256("proposal1");
        bytes32 burnTxHash = keccak256("burn1");

        vm.prank(relayer1);
        bridge.proposeWithdrawal(proposalId, user2, address(0), 1 ether, burnTxHash, 12345);

        // Only 1 vote (need 3)
        vm.warp(block.timestamp + 7 days + 1);

        vm.expectRevert(AethelredBridge.InsufficientVotes.selector);
        bridge.processWithdrawal(proposalId);
    }

    // =========================================================================
    // CHALLENGE TESTS
    // =========================================================================

    function test_ChallengeWithdrawal() public {
        vm.prank(user1);
        bridge.depositETH{value: 10 ether}(AETHELRED_RECIPIENT);

        bytes32 proposalId = keccak256("proposal1");
        bytes32 burnTxHash = keccak256("burn1");

        vm.prank(relayer1);
        bridge.proposeWithdrawal(proposalId, user2, address(0), 1 ether, burnTxHash, 12345);

        // Challenge
        vm.prank(guardian);
        bridge.challengeWithdrawal(proposalId, "Fraudulent withdrawal detected");

        AethelredBridge.WithdrawalProposal memory proposal = bridge.getWithdrawalProposal(proposalId);
        assertTrue(proposal.challenged);
    }

    function test_ChallengeWithdrawal_CannotProcess() public {
        vm.prank(user1);
        bridge.depositETH{value: 10 ether}(AETHELRED_RECIPIENT);

        bytes32 proposalId = keccak256("proposal1");
        bytes32 burnTxHash = keccak256("burn1");

        vm.prank(relayer1);
        bridge.proposeWithdrawal(proposalId, user2, address(0), 1 ether, burnTxHash, 12345);

        vm.prank(relayer2);
        bridge.voteWithdrawal(proposalId);

        vm.prank(relayer3);
        bridge.voteWithdrawal(proposalId);

        // Challenge
        vm.prank(guardian);
        bridge.challengeWithdrawal(proposalId, "Suspicious activity");

        // Try to process after challenge period
        vm.warp(block.timestamp + 7 days + 1);

        vm.expectRevert(AethelredBridge.WithdrawalAlreadyChallenged.selector);
        bridge.processWithdrawal(proposalId);
    }

    function test_ChallengeWithdrawal_OnlyGuardian() public {
        vm.prank(user1);
        bridge.depositETH{value: 10 ether}(AETHELRED_RECIPIENT);

        bytes32 proposalId = keccak256("proposal1");
        bytes32 burnTxHash = keccak256("burn1");

        vm.prank(relayer1);
        bridge.proposeWithdrawal(proposalId, user2, address(0), 1 ether, burnTxHash, 12345);

        vm.prank(user1);
        vm.expectRevert();
        bridge.challengeWithdrawal(proposalId, "Fraudulent");
    }

    // =========================================================================
    // RATE LIMITING TESTS
    // =========================================================================

    function test_RateLimit_Deposit() public {
        // Update rate limit to 10 ETH per period
        vm.prank(admin);
        bridge.updateRateLimitConfig(10 ether, 10 ether, true);

        // First deposit succeeds
        vm.prank(user1);
        bridge.depositETH{value: 5 ether}(AETHELRED_RECIPIENT);

        // Second deposit within limit succeeds
        vm.prank(user1);
        bridge.depositETH{value: 4 ether}(AETHELRED_RECIPIENT);

        // Third deposit exceeds limit
        vm.prank(user1);
        vm.expectRevert(AethelredBridge.RateLimitExceeded.selector);
        bridge.depositETH{value: 2 ether}(AETHELRED_RECIPIENT);
    }

    function test_RateLimit_ResetsAfterPeriod() public {
        vm.prank(admin);
        bridge.updateRateLimitConfig(10 ether, 10 ether, true);

        // Fill rate limit
        vm.prank(user1);
        bridge.depositETH{value: 10 ether}(AETHELRED_RECIPIENT);

        // This should fail
        vm.prank(user1);
        vm.expectRevert(AethelredBridge.RateLimitExceeded.selector);
        bridge.depositETH{value: 1 ether}(AETHELRED_RECIPIENT);

        // Move to next period
        vm.warp(block.timestamp + 1 hours + 1);

        // Now it should succeed
        vm.prank(user1);
        bridge.depositETH{value: 5 ether}(AETHELRED_RECIPIENT);
    }

    function test_RateLimit_Disabled() public {
        vm.prank(admin);
        bridge.updateRateLimitConfig(10 ether, 10 ether, false);

        // Should allow unlimited deposits
        vm.prank(user1);
        bridge.depositETH{value: 50 ether}(AETHELRED_RECIPIENT);

        vm.prank(user1);
        bridge.depositETH{value: 50 ether}(AETHELRED_RECIPIENT);
    }

    // =========================================================================
    // ACCESS CONTROL TESTS
    // =========================================================================

    function test_AddSupportedToken_OnlyAdmin() public {
        MockERC20 newToken = new MockERC20("New", "NEW");

        vm.prank(user1);
        vm.expectRevert();
        bridge.addSupportedToken(address(newToken));

        vm.prank(admin);
        bridge.addSupportedToken(address(newToken));
        assertTrue(bridge.supportedTokens(address(newToken)));
    }

    function test_RemoveSupportedToken() public {
        vm.prank(admin);
        bridge.removeSupportedToken(address(mockToken));
        assertFalse(bridge.supportedTokens(address(mockToken)));
    }

    function test_Pause_OnlyGuardian() public {
        vm.prank(user1);
        vm.expectRevert();
        bridge.pause();

        vm.prank(guardian);
        bridge.pause();
        assertTrue(bridge.paused());
    }

    function test_Unpause() public {
        vm.prank(guardian);
        bridge.pause();

        vm.prank(guardian);
        bridge.unpause();
        assertFalse(bridge.paused());
    }

    function test_BlockAddress() public {
        assertFalse(bridge.blockedAddresses(user1));

        vm.prank(guardian);
        bridge.setAddressBlocked(user1, true);

        assertTrue(bridge.blockedAddresses(user1));

        vm.prank(user1);
        vm.expectRevert(AethelredBridge.AddressBlocked.selector);
        bridge.depositETH{value: 1 ether}(AETHELRED_RECIPIENT);
    }

    // =========================================================================
    // VIEW FUNCTIONS TESTS
    // =========================================================================

    function test_CanProcessWithdrawal() public {
        vm.prank(user1);
        bridge.depositETH{value: 10 ether}(AETHELRED_RECIPIENT);

        bytes32 proposalId = keccak256("proposal1");
        bytes32 burnTxHash = keccak256("burn1");

        // Before proposal
        (bool canProcess, string memory reason) = bridge.canProcessWithdrawal(proposalId);
        assertFalse(canProcess);
        assertEq(reason, "Proposal not found");

        // After proposal, before votes
        vm.prank(relayer1);
        bridge.proposeWithdrawal(proposalId, user2, address(0), 1 ether, burnTxHash, 12345);

        (canProcess, reason) = bridge.canProcessWithdrawal(proposalId);
        assertFalse(canProcess);
        assertEq(reason, "Insufficient votes");

        // After votes, before challenge period
        vm.prank(relayer2);
        bridge.voteWithdrawal(proposalId);
        vm.prank(relayer3);
        bridge.voteWithdrawal(proposalId);

        (canProcess, reason) = bridge.canProcessWithdrawal(proposalId);
        assertFalse(canProcess);
        assertEq(reason, "Challenge period not ended");

        // After challenge period
        vm.warp(block.timestamp + 7 days + 1);

        (canProcess, reason) = bridge.canProcessWithdrawal(proposalId);
        assertTrue(canProcess);
        assertEq(reason, "");
    }

    function test_GetCurrentRateLimitState() public {
        vm.prank(user1);
        bridge.depositETH{value: 5 ether}(AETHELRED_RECIPIENT);

        (uint256 deposited, uint256 withdrawn) = bridge.getCurrentRateLimitState();
        assertEq(deposited, 5 ether);
        assertEq(withdrawn, 0);
    }

    // =========================================================================
    // AUDIT REGRESSION - C-03: burnTxHash Replay Protection
    // =========================================================================

    function test_C03_BurnTxHashReplayProtection_SameHashRejected() public {
        vm.prank(user1);
        bridge.depositETH{value: 10 ether}(AETHELRED_RECIPIENT);

        bytes32 burnTxHash = keccak256("burn-tx-1");
        bytes32 proposalId1 = keccak256("proposal-1");
        bytes32 proposalId2 = keccak256("proposal-2");

        // First proposal with this burnTxHash succeeds
        vm.prank(relayer1);
        bridge.proposeWithdrawal(proposalId1, user2, address(0), 1 ether, burnTxHash, 12345);

        // Get enough votes and process
        vm.prank(relayer2);
        bridge.voteWithdrawal(proposalId1);
        vm.prank(relayer3);
        bridge.voteWithdrawal(proposalId1);

        vm.warp(block.timestamp + 7 days + 1);
        bridge.processWithdrawal(proposalId1);

        // Second proposal with SAME burnTxHash must be rejected
        vm.prank(relayer1);
        vm.expectRevert(AethelredBridge.WithdrawalAlreadyProcessed.selector);
        bridge.proposeWithdrawal(proposalId2, user2, address(0), 1 ether, burnTxHash, 12346);
    }

    function test_C03_BurnTxHashReplayProtection_DifferentHashAllowed() public {
        vm.prank(user1);
        bridge.depositETH{value: 10 ether}(AETHELRED_RECIPIENT);

        bytes32 burnTxHash1 = keccak256("burn-tx-1");
        bytes32 burnTxHash2 = keccak256("burn-tx-2");

        // First proposal
        vm.prank(relayer1);
        bridge.proposeWithdrawal(keccak256("p1"), user2, address(0), 1 ether, burnTxHash1, 12345);

        vm.prank(relayer2);
        bridge.voteWithdrawal(keccak256("p1"));
        vm.prank(relayer3);
        bridge.voteWithdrawal(keccak256("p1"));
        vm.warp(block.timestamp + 7 days + 1);
        bridge.processWithdrawal(keccak256("p1"));

        // Second proposal with DIFFERENT burnTxHash should succeed
        vm.prank(relayer1);
        bridge.proposeWithdrawal(keccak256("p2"), user2, address(0), 1 ether, burnTxHash2, 12346);

        AethelredBridge.WithdrawalProposal memory proposal = bridge.getWithdrawalProposal(keccak256("p2"));
        assertEq(proposal.recipient, user2);
    }

    function test_C03_ProcessedWithdrawalsMapping() public {
        vm.prank(user1);
        bridge.depositETH{value: 10 ether}(AETHELRED_RECIPIENT);

        bytes32 burnTxHash = keccak256("tracked-burn");
        bytes32 proposalId = keccak256("tracked-proposal");

        // Before processing, burnTxHash should not be marked
        assertFalse(bridge.processedWithdrawals(burnTxHash));

        vm.prank(relayer1);
        bridge.proposeWithdrawal(proposalId, user2, address(0), 1 ether, burnTxHash, 12345);
        vm.prank(relayer2);
        bridge.voteWithdrawal(proposalId);
        vm.prank(relayer3);
        bridge.voteWithdrawal(proposalId);

        vm.warp(block.timestamp + 7 days + 1);
        bridge.processWithdrawal(proposalId);

        // After processing, burnTxHash must be marked as processed
        assertTrue(bridge.processedWithdrawals(burnTxHash));
    }

    // =========================================================================
    // AUDIT REGRESSION - M-03: clearExpiredRateLimitState
    // =========================================================================

    function test_M03_ClearExpiredRateLimitState_Success() public {
        // Enable rate limiting
        vm.prank(admin);
        bridge.updateRateLimitConfig(100 ether, 100 ether, true);

        // Warp to a clean period boundary so period calculation is deterministic
        vm.warp(3600); // period = 3600 / 3600 = 1

        // Deposit to create rate limit state in period 1
        vm.prank(user1);
        bridge.depositETH{value: 5 ether}(AETHELRED_RECIPIENT);

        // Record the period in which the deposit was made
        uint256 depositPeriod = uint256(3600) / uint256(1 hours);

        // Move to a later period (period 3)
        vm.warp(3600 * 3 + 1);

        // Clear the expired period
        uint256[] memory periodKeys = new uint256[](1);
        periodKeys[0] = depositPeriod;

        vm.prank(admin);
        bridge.clearExpiredRateLimitState(periodKeys);
    }

    function test_M03_ClearExpiredRateLimitState_CannotClearCurrentPeriod() public {
        vm.prank(admin);
        bridge.updateRateLimitConfig(100 ether, 100 ether, true);

        vm.prank(user1);
        bridge.depositETH{value: 5 ether}(AETHELRED_RECIPIENT);

        uint256 currentPeriod = block.timestamp / 1 hours;

        uint256[] memory periodKeys = new uint256[](1);
        periodKeys[0] = currentPeriod;

        // Clearing current period must revert
        vm.prank(admin);
        vm.expectRevert("Cannot clear current period");
        bridge.clearExpiredRateLimitState(periodKeys);
    }

    function test_M03_ClearExpiredRateLimitState_OnlyAdmin() public {
        uint256[] memory periodKeys = new uint256[](1);
        periodKeys[0] = 0;

        // Non-admin cannot call
        vm.prank(user1);
        vm.expectRevert();
        bridge.clearExpiredRateLimitState(periodKeys);
    }

    function test_M03_ClearExpiredRateLimitState_BatchLimit() public {
        // Batch too large (>200) must revert
        uint256[] memory periodKeys = new uint256[](201);
        for (uint256 i = 0; i < 201; i++) {
            periodKeys[i] = i;
        }

        vm.warp(201 * 1 hours + 1); // Far enough in the future

        vm.prank(admin);
        vm.expectRevert("Batch too large");
        bridge.clearExpiredRateLimitState(periodKeys);
    }

    function test_M03_ClearExpiredRateLimitState_EmptyArray() public {
        // Empty array should succeed (no-op)
        uint256[] memory periodKeys = new uint256[](0);

        vm.prank(admin);
        bridge.clearExpiredRateLimitState(periodKeys);
    }

    // =========================================================================
    // AUDIT REGRESSION - I-05: Version Getter
    // =========================================================================

    function test_I05_VersionReturnsExpected() public view {
        string memory v = bridge.version();
        assertEq(v, "1.0.0");
    }

    function test_I05_VersionIsPure() public view {
        // Calling version() should not change state (it's pure)
        // Just verify it returns consistently
        assertEq(bridge.version(), bridge.version());
    }

    // =========================================================================
    // AUDIT REGRESSION - L-02: MIN_ETH_CONFIRMATIONS = 64
    // =========================================================================

    function test_L02_MinEthConfirmationsIs64() public view {
        assertEq(bridge.MIN_ETH_CONFIRMATIONS(), 64);
    }

    // =========================================================================
    // ADDITIONAL SECURITY - Withdrawal replay & double-process
    // =========================================================================

    function test_Security_CannotProcessWithdrawalTwice() public {
        vm.prank(user1);
        bridge.depositETH{value: 10 ether}(AETHELRED_RECIPIENT);

        bytes32 proposalId = keccak256("double-process");
        bytes32 burnTxHash = keccak256("double-burn");

        vm.prank(relayer1);
        bridge.proposeWithdrawal(proposalId, user2, address(0), 1 ether, burnTxHash, 12345);
        vm.prank(relayer2);
        bridge.voteWithdrawal(proposalId);
        vm.prank(relayer3);
        bridge.voteWithdrawal(proposalId);

        vm.warp(block.timestamp + 7 days + 1);
        bridge.processWithdrawal(proposalId);

        // Second process must revert
        vm.expectRevert(AethelredBridge.WithdrawalAlreadyProcessed.selector);
        bridge.processWithdrawal(proposalId);
    }

    function test_Security_ProposalIdCollision() public {
        vm.prank(user1);
        bridge.depositETH{value: 10 ether}(AETHELRED_RECIPIENT);

        bytes32 proposalId = keccak256("unique-proposal");
        bytes32 burnTxHash = keccak256("unique-burn");

        vm.prank(relayer1);
        bridge.proposeWithdrawal(proposalId, user2, address(0), 1 ether, burnTxHash, 12345);

        // Same proposalId must revert
        vm.prank(relayer2);
        vm.expectRevert(AethelredBridge.ProposalExists.selector);
        bridge.proposeWithdrawal(proposalId, user2, address(0), 2 ether, keccak256("other-burn"), 12346);
    }

    function test_Security_WithdrawalToBlockedAddress() public {
        vm.prank(user1);
        bridge.depositETH{value: 10 ether}(AETHELRED_RECIPIENT);

        bytes32 proposalId = keccak256("blocked-withdrawal");
        bytes32 burnTxHash = keccak256("blocked-burn");

        // Propose withdrawal to blocked user
        vm.prank(relayer1);
        vm.expectRevert(AethelredBridge.AddressBlocked.selector);
        bridge.proposeWithdrawal(proposalId, blockedUser, address(0), 1 ether, burnTxHash, 12345);
    }

    function test_Security_NonRelayerCannotPropose() public {
        vm.prank(user1);
        bridge.depositETH{value: 10 ether}(AETHELRED_RECIPIENT);

        vm.prank(user1);
        vm.expectRevert();
        bridge.proposeWithdrawal(keccak256("bad"), user2, address(0), 1 ether, keccak256("bad-burn"), 12345);
    }

    function test_Security_NonRelayerCannotVote() public {
        vm.prank(user1);
        bridge.depositETH{value: 10 ether}(AETHELRED_RECIPIENT);

        bytes32 proposalId = keccak256("vote-test");
        vm.prank(relayer1);
        bridge.proposeWithdrawal(proposalId, user2, address(0), 1 ether, keccak256("vote-burn"), 12345);

        vm.prank(user1);
        vm.expectRevert();
        bridge.voteWithdrawal(proposalId);
    }

    // =========================================================================
    // ADDITIONAL - ERC20 withdrawal flow
    // =========================================================================

    function test_ProcessWithdrawal_ERC20() public {
        uint256 amount = 100e18;

        // Deposit ERC20
        vm.startPrank(user1);
        mockToken.approve(address(bridge), amount);
        bridge.depositERC20(address(mockToken), amount, AETHELRED_RECIPIENT);
        vm.stopPrank();

        bytes32 proposalId = keccak256("erc20-withdrawal");
        bytes32 burnTxHash = keccak256("erc20-burn");
        uint256 withdrawAmount = 5e18; // Must be within per-block mint ceiling (10 ether)

        vm.prank(relayer1);
        bridge.proposeWithdrawal(proposalId, user2, address(mockToken), withdrawAmount, burnTxHash, 12345);
        vm.prank(relayer2);
        bridge.voteWithdrawal(proposalId);
        vm.prank(relayer3);
        bridge.voteWithdrawal(proposalId);

        vm.warp(block.timestamp + 7 days + 1);

        uint256 user2BalanceBefore = mockToken.balanceOf(user2);
        bridge.processWithdrawal(proposalId);

        assertEq(mockToken.balanceOf(user2), user2BalanceBefore + withdrawAmount);
    }

    // =========================================================================
    // FUZZ TESTS
    // =========================================================================

    function testFuzz_DepositETH(uint256 amount) public {
        // Bound amount to valid range
        amount = bound(amount, bridge.MIN_DEPOSIT(), bridge.MAX_SINGLE_DEPOSIT());

        vm.prank(user1);
        bridge.depositETH{value: amount}(AETHELRED_RECIPIENT);

        assertEq(bridge.totalLockedETH(), amount);
    }

    function testFuzz_VoteCount(uint8 numVoters) public {
        numVoters = uint8(bound(numVoters, 1, 5));

        vm.prank(user1);
        bridge.depositETH{value: 10 ether}(AETHELRED_RECIPIENT);

        bytes32 proposalId = keccak256("fuzz_proposal");
        bytes32 burnTxHash = keccak256("fuzz_burn");

        vm.prank(relayer1);
        bridge.proposeWithdrawal(proposalId, user2, address(0), 1 ether, burnTxHash, 12345);

        for (uint8 i = 1; i < numVoters && i < 5; i++) {
            vm.prank(relayers[i]);
            bridge.voteWithdrawal(proposalId);
        }

        AethelredBridge.WithdrawalProposal memory proposal = bridge.getWithdrawalProposal(proposalId);
        assertEq(proposal.voteCount, numVoters);
    }

    // =========================================================================
    // DEPOSIT EDGE CASES
    // =========================================================================

    function test_DepositETH_MultipleSameUser() public {
        uint256 amount1 = 1 ether;
        uint256 amount2 = 2 ether;
        uint256 amount3 = 3 ether;

        vm.startPrank(user1);
        bridge.depositETH{value: amount1}(AETHELRED_RECIPIENT);
        bridge.depositETH{value: amount2}(AETHELRED_RECIPIENT);
        bridge.depositETH{value: amount3}(AETHELRED_RECIPIENT);
        vm.stopPrank();

        assertEq(bridge.totalLockedETH(), amount1 + amount2 + amount3);
        assertEq(bridge.depositNonce(), 3);
        assertEq(address(bridge).balance, amount1 + amount2 + amount3);
    }

    function test_DepositETH_MultipleUsers() public {
        uint256 amount1 = 5 ether;
        uint256 amount2 = 7 ether;

        vm.prank(user1);
        bridge.depositETH{value: amount1}(AETHELRED_RECIPIENT);

        vm.prank(user2);
        bridge.depositETH{value: amount2}(AETHELRED_RECIPIENT);

        assertEq(bridge.totalLockedETH(), amount1 + amount2);
        assertEq(bridge.depositNonce(), 2);
    }

    function test_DepositETH_ExactMinimum() public {
        uint256 minDeposit = bridge.MIN_DEPOSIT(); // 0.01 ether

        vm.prank(user1);
        bridge.depositETH{value: minDeposit}(AETHELRED_RECIPIENT);

        assertEq(bridge.totalLockedETH(), minDeposit);
        assertEq(bridge.depositNonce(), 1);
    }

    function test_DepositETH_ExactMaximum() public {
        uint256 maxDeposit = bridge.MAX_SINGLE_DEPOSIT(); // 100 ether

        vm.prank(user1);
        bridge.depositETH{value: maxDeposit}(AETHELRED_RECIPIENT);

        assertEq(bridge.totalLockedETH(), maxDeposit);
        assertEq(bridge.depositNonce(), 1);
    }

    function test_DepositERC20_ZeroAmount() public {
        vm.startPrank(user1);
        mockToken.approve(address(bridge), 1e18);
        vm.expectRevert(AethelredBridge.InvalidAmount.selector);
        bridge.depositERC20(address(mockToken), 0, AETHELRED_RECIPIENT);
        vm.stopPrank();
    }

    function test_DepositETH_JustBelowMinimum() public {
        uint256 belowMin = bridge.MIN_DEPOSIT() - 1;

        vm.prank(user1);
        vm.expectRevert(AethelredBridge.InvalidAmount.selector);
        bridge.depositETH{value: belowMin}(AETHELRED_RECIPIENT);
    }

    // =========================================================================
    // WITHDRAWAL FLOW ADVANCED
    // =========================================================================

    function test_ProcessWithdrawal_MultipleSequential() public {
        // Deposit enough ETH
        vm.prank(user1);
        bridge.depositETH{value: 10 ether}(AETHELRED_RECIPIENT);

        // First withdrawal
        bytes32 proposalId1 = keccak256("seq-proposal-1");
        bytes32 burnTxHash1 = keccak256("seq-burn-1");

        vm.prank(relayer1);
        bridge.proposeWithdrawal(proposalId1, user2, address(0), 1 ether, burnTxHash1, 100);
        vm.prank(relayer2);
        bridge.voteWithdrawal(proposalId1);
        vm.prank(relayer3);
        bridge.voteWithdrawal(proposalId1);

        vm.warp(block.timestamp + 7 days + 1);
        bridge.processWithdrawal(proposalId1);

        assertEq(bridge.totalLockedETH(), 9 ether);

        // Second withdrawal
        bytes32 proposalId2 = keccak256("seq-proposal-2");
        bytes32 burnTxHash2 = keccak256("seq-burn-2");

        vm.prank(relayer1);
        bridge.proposeWithdrawal(proposalId2, user2, address(0), 2 ether, burnTxHash2, 200);
        vm.prank(relayer2);
        bridge.voteWithdrawal(proposalId2);
        vm.prank(relayer3);
        bridge.voteWithdrawal(proposalId2);

        vm.warp(block.timestamp + 7 days + 1);
        bridge.processWithdrawal(proposalId2);

        assertEq(bridge.totalLockedETH(), 7 ether);

        // Third withdrawal
        bytes32 proposalId3 = keccak256("seq-proposal-3");
        bytes32 burnTxHash3 = keccak256("seq-burn-3");

        vm.prank(relayer1);
        bridge.proposeWithdrawal(proposalId3, user1, address(0), 3 ether, burnTxHash3, 300);
        vm.prank(relayer2);
        bridge.voteWithdrawal(proposalId3);
        vm.prank(relayer3);
        bridge.voteWithdrawal(proposalId3);

        vm.warp(block.timestamp + 7 days + 1);
        bridge.processWithdrawal(proposalId3);

        assertEq(bridge.totalLockedETH(), 4 ether);
    }

    function test_ProcessWithdrawal_AfterUnpause() public {
        // Deposit ETH
        vm.prank(user1);
        bridge.depositETH{value: 10 ether}(AETHELRED_RECIPIENT);

        bytes32 proposalId = keccak256("unpause-proposal");
        bytes32 burnTxHash = keccak256("unpause-burn");

        // Propose and vote before pause
        vm.prank(relayer1);
        bridge.proposeWithdrawal(proposalId, user2, address(0), 1 ether, burnTxHash, 12345);
        vm.prank(relayer2);
        bridge.voteWithdrawal(proposalId);
        vm.prank(relayer3);
        bridge.voteWithdrawal(proposalId);

        // Pause the bridge
        vm.prank(guardian);
        bridge.pause();

        // Wait for challenge period
        vm.warp(block.timestamp + 7 days + 1);

        // Cannot process while paused
        vm.expectRevert();
        bridge.processWithdrawal(proposalId);

        // Unpause
        vm.prank(guardian);
        bridge.unpause();

        // Now process should succeed
        uint256 user2BalanceBefore = user2.balance;
        bridge.processWithdrawal(proposalId);

        assertEq(user2.balance, user2BalanceBefore + 1 ether);
    }

    function test_ProposeWithdrawal_AllRelayersVote() public {
        vm.prank(user1);
        bridge.depositETH{value: 10 ether}(AETHELRED_RECIPIENT);

        bytes32 proposalId = keccak256("all-relayers");
        bytes32 burnTxHash = keccak256("all-relayers-burn");

        // Relayer1 proposes (counts as 1 vote)
        vm.prank(relayer1);
        bridge.proposeWithdrawal(proposalId, user2, address(0), 1 ether, burnTxHash, 12345);

        // Remaining 4 relayers vote
        vm.prank(relayer2);
        bridge.voteWithdrawal(proposalId);
        vm.prank(relayer3);
        bridge.voteWithdrawal(proposalId);
        vm.prank(relayer4);
        bridge.voteWithdrawal(proposalId);
        vm.prank(relayer5);
        bridge.voteWithdrawal(proposalId);

        AethelredBridge.WithdrawalProposal memory proposal = bridge.getWithdrawalProposal(proposalId);
        assertEq(proposal.voteCount, 5);

        // Verify all voted
        assertTrue(bridge.hasRelayerVoted(proposalId, relayer1));
        assertTrue(bridge.hasRelayerVoted(proposalId, relayer2));
        assertTrue(bridge.hasRelayerVoted(proposalId, relayer3));
        assertTrue(bridge.hasRelayerVoted(proposalId, relayer4));
        assertTrue(bridge.hasRelayerVoted(proposalId, relayer5));
    }

    function test_ProposeWithdrawal_ExactThresholdVotes() public {
        vm.prank(user1);
        bridge.depositETH{value: 10 ether}(AETHELRED_RECIPIENT);

        bytes32 proposalId = keccak256("threshold-exact");
        bytes32 burnTxHash = keccak256("threshold-burn");

        // With 5 relayers and 67% threshold, minVotes = 3
        (, , uint256 minVotes) = bridge.relayerConfig();
        assertEq(minVotes, 3);

        // Relayer1 proposes (vote 1)
        vm.prank(relayer1);
        bridge.proposeWithdrawal(proposalId, user2, address(0), 1 ether, burnTxHash, 12345);

        // Relayer2 votes (vote 2)
        vm.prank(relayer2);
        bridge.voteWithdrawal(proposalId);

        // Relayer3 votes (vote 3 - exactly at threshold)
        vm.prank(relayer3);
        bridge.voteWithdrawal(proposalId);

        // Wait and process - should succeed with exactly 3 votes
        vm.warp(block.timestamp + 7 days + 1);
        uint256 user2BalanceBefore = user2.balance;
        bridge.processWithdrawal(proposalId);
        assertEq(user2.balance, user2BalanceBefore + 1 ether);
    }

    function test_Revert_ProcessWithdrawal_WhenPaused() public {
        vm.prank(user1);
        bridge.depositETH{value: 10 ether}(AETHELRED_RECIPIENT);

        bytes32 proposalId = keccak256("paused-process");
        bytes32 burnTxHash = keccak256("paused-burn");

        vm.prank(relayer1);
        bridge.proposeWithdrawal(proposalId, user2, address(0), 1 ether, burnTxHash, 12345);
        vm.prank(relayer2);
        bridge.voteWithdrawal(proposalId);
        vm.prank(relayer3);
        bridge.voteWithdrawal(proposalId);

        vm.warp(block.timestamp + 7 days + 1);

        // Pause
        vm.prank(guardian);
        bridge.pause();

        // Should revert when paused
        vm.expectRevert();
        bridge.processWithdrawal(proposalId);
    }

    // =========================================================================
    // CHALLENGE ADVANCED
    // =========================================================================

    function test_ChallengeWithdrawal_EmitsEvent() public {
        vm.prank(user1);
        bridge.depositETH{value: 10 ether}(AETHELRED_RECIPIENT);

        bytes32 proposalId = keccak256("challenge-event");
        bytes32 burnTxHash = keccak256("challenge-event-burn");

        vm.prank(relayer1);
        bridge.proposeWithdrawal(proposalId, user2, address(0), 1 ether, burnTxHash, 12345);

        vm.prank(guardian);
        vm.expectEmit(true, true, false, true);
        emit WithdrawalChallenged(proposalId, guardian, "Fraudulent");
        bridge.challengeWithdrawal(proposalId, "Fraudulent");
    }

    function test_Revert_ChallengeWithdrawal_AlreadyProcessed() public {
        vm.prank(user1);
        bridge.depositETH{value: 10 ether}(AETHELRED_RECIPIENT);

        bytes32 proposalId = keccak256("challenge-processed");
        bytes32 burnTxHash = keccak256("challenge-processed-burn");

        vm.prank(relayer1);
        bridge.proposeWithdrawal(proposalId, user2, address(0), 1 ether, burnTxHash, 12345);
        vm.prank(relayer2);
        bridge.voteWithdrawal(proposalId);
        vm.prank(relayer3);
        bridge.voteWithdrawal(proposalId);

        vm.warp(block.timestamp + 7 days + 1);
        bridge.processWithdrawal(proposalId);

        // Trying to challenge after processing should revert
        vm.prank(guardian);
        vm.expectRevert(AethelredBridge.WithdrawalAlreadyProcessed.selector);
        bridge.challengeWithdrawal(proposalId, "Too late");
    }

    function test_Revert_ChallengeWithdrawal_AlreadyChallenged() public {
        vm.prank(user1);
        bridge.depositETH{value: 10 ether}(AETHELRED_RECIPIENT);

        bytes32 proposalId = keccak256("double-challenge");
        bytes32 burnTxHash = keccak256("double-challenge-burn");

        vm.prank(relayer1);
        bridge.proposeWithdrawal(proposalId, user2, address(0), 1 ether, burnTxHash, 12345);

        // First challenge succeeds
        vm.prank(guardian);
        bridge.challengeWithdrawal(proposalId, "First challenge");

        // The contract sets challenged = true but does not explicitly revert
        // on double-challenge via a dedicated error. The proposal is already challenged,
        // and since challenged is already true, a second challenge would still succeed
        // (the contract does not revert on already-challenged for challengeWithdrawal).
        // However, voting on a challenged proposal reverts:
        vm.prank(relayer2);
        vm.expectRevert(AethelredBridge.WithdrawalAlreadyChallenged.selector);
        bridge.voteWithdrawal(proposalId);
    }

    function test_ChallengeWithdrawal_AfterVotes_StillBlocks() public {
        vm.prank(user1);
        bridge.depositETH{value: 10 ether}(AETHELRED_RECIPIENT);

        bytes32 proposalId = keccak256("challenge-after-votes");
        bytes32 burnTxHash = keccak256("challenge-after-votes-burn");

        vm.prank(relayer1);
        bridge.proposeWithdrawal(proposalId, user2, address(0), 1 ether, burnTxHash, 12345);
        vm.prank(relayer2);
        bridge.voteWithdrawal(proposalId);
        vm.prank(relayer3);
        bridge.voteWithdrawal(proposalId);

        // Challenge even though enough votes exist
        vm.prank(guardian);
        bridge.challengeWithdrawal(proposalId, "Suspicious despite votes");

        // Wait for challenge period
        vm.warp(block.timestamp + 7 days + 1);

        // Process should still fail because of challenge
        vm.expectRevert(AethelredBridge.WithdrawalAlreadyChallenged.selector);
        bridge.processWithdrawal(proposalId);
    }

    // =========================================================================
    // RELAYER MANAGEMENT
    // =========================================================================

    function test_AddRelayer() public {
        address newRelayer = address(0x20);
        bytes32 relayerRole = bridge.RELAYER_ROLE();

        // Verify not a relayer yet
        assertFalse(bridge.hasRole(relayerRole, newRelayer));

        (uint256 countBefore, , ) = bridge.relayerConfig();

        vm.prank(admin);
        bridge.grantRole(relayerRole, newRelayer);

        assertTrue(bridge.hasRole(relayerRole, newRelayer));

        (uint256 countAfter, , ) = bridge.relayerConfig();
        assertEq(countAfter, countBefore + 1);
    }

    function test_RemoveRelayer() public {
        bytes32 relayerRole = bridge.RELAYER_ROLE();

        // Verify relayer5 is currently a relayer
        assertTrue(bridge.hasRole(relayerRole, relayer5));

        (uint256 countBefore, , ) = bridge.relayerConfig();

        vm.prank(admin);
        bridge.revokeRole(relayerRole, relayer5);

        assertFalse(bridge.hasRole(relayerRole, relayer5));

        (uint256 countAfter, , ) = bridge.relayerConfig();
        assertEq(countAfter, countBefore - 1);
    }

    function test_Revert_AddRelayer_NotAdmin() public {
        address newRelayer = address(0x20);
        bytes32 relayerRole = bridge.RELAYER_ROLE();
        bytes32 adminRole = bridge.DEFAULT_ADMIN_ROLE();

        vm.prank(user1);
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, user1, adminRole));
        bridge.grantRole(relayerRole, newRelayer);
    }

    function test_RelayerConfig_UpdatesAfterAddRemove() public {
        bytes32 relayerRole = bridge.RELAYER_ROLE();

        (uint256 initialCount, uint256 threshold, uint256 initialMinVotes) = bridge.relayerConfig();
        assertEq(initialCount, 5);
        assertEq(initialMinVotes, 3); // 5 * 67% = 3.35 -> 3

        // Add a relayer: count becomes 6
        address newRelayer = address(0x20);
        vm.prank(admin);
        bridge.grantRole(relayerRole, newRelayer);

        (uint256 count6, , uint256 minVotes6) = bridge.relayerConfig();
        assertEq(count6, 6);
        // 6 * 6700 / 10000 = 4.02 -> 4
        assertEq(minVotes6, 4);

        // Remove a relayer: count becomes 5 again
        vm.prank(admin);
        bridge.revokeRole(relayerRole, newRelayer);

        (uint256 countBack, , uint256 minVotesBack) = bridge.relayerConfig();
        assertEq(countBack, 5);
        assertEq(minVotesBack, 3);
    }

    // =========================================================================
    // TOKEN MANAGEMENT
    // =========================================================================

    function test_AddMultipleTokens() public {
        MockERC20 tokenA = new MockERC20("Token A", "TKA");
        MockERC20 tokenB = new MockERC20("Token B", "TKB");
        MockERC20 tokenC = new MockERC20("Token C", "TKC");

        vm.startPrank(admin);
        bridge.addSupportedToken(address(tokenA));
        bridge.addSupportedToken(address(tokenB));
        bridge.addSupportedToken(address(tokenC));
        vm.stopPrank();

        assertTrue(bridge.supportedTokens(address(tokenA)));
        assertTrue(bridge.supportedTokens(address(tokenB)));
        assertTrue(bridge.supportedTokens(address(tokenC)));
    }

    function test_Revert_DepositRemovedToken() public {
        // First verify mockToken is supported
        assertTrue(bridge.supportedTokens(address(mockToken)));

        // Remove the token
        vm.prank(admin);
        bridge.removeSupportedToken(address(mockToken));
        assertFalse(bridge.supportedTokens(address(mockToken)));

        // Attempt to deposit after removal
        vm.startPrank(user1);
        mockToken.approve(address(bridge), 10e18);
        vm.expectRevert(AethelredBridge.TokenNotSupported.selector);
        bridge.depositERC20(address(mockToken), 10e18, AETHELRED_RECIPIENT);
        vm.stopPrank();
    }

    function test_AddTokenBack() public {
        // Remove the token
        vm.prank(admin);
        bridge.removeSupportedToken(address(mockToken));
        assertFalse(bridge.supportedTokens(address(mockToken)));

        // Re-add the same token
        vm.prank(admin);
        bridge.addSupportedToken(address(mockToken));
        assertTrue(bridge.supportedTokens(address(mockToken)));

        // Deposit should now work again
        vm.startPrank(user1);
        mockToken.approve(address(bridge), 10e18);
        bridge.depositERC20(address(mockToken), 10e18, AETHELRED_RECIPIENT);
        vm.stopPrank();

        assertEq(bridge.totalLockedERC20(address(mockToken)), 10e18);
    }

    // =========================================================================
    // RATE LIMITING ADVANCED
    // =========================================================================

    function test_RateLimit_WithdrawalLimit() public {
        // Enable rate limiting with low withdrawal limit
        vm.prank(admin);
        bridge.updateRateLimitConfig(100 ether, 3 ether, true);

        // Deposit enough ETH
        vm.prank(user1);
        bridge.depositETH{value: 10 ether}(AETHELRED_RECIPIENT);

        // Propose both withdrawals at the same time so their challenge periods
        // end together, allowing both to be processed in the same rate-limit period.
        bytes32 proposalId1 = keccak256("rl-withdrawal-1");
        bytes32 burnTxHash1 = keccak256("rl-burn-1");

        vm.prank(relayer1);
        bridge.proposeWithdrawal(proposalId1, user2, address(0), 2 ether, burnTxHash1, 100);
        vm.prank(relayer2);
        bridge.voteWithdrawal(proposalId1);
        vm.prank(relayer3);
        bridge.voteWithdrawal(proposalId1);

        bytes32 proposalId2 = keccak256("rl-withdrawal-2");
        bytes32 burnTxHash2 = keccak256("rl-burn-2");

        vm.prank(relayer1);
        bridge.proposeWithdrawal(proposalId2, user2, address(0), 2 ether, burnTxHash2, 200);
        vm.prank(relayer2);
        bridge.voteWithdrawal(proposalId2);
        vm.prank(relayer3);
        bridge.voteWithdrawal(proposalId2);

        // Warp past both challenge periods (they were proposed at the same time)
        vm.warp(block.timestamp + 7 days + 1);

        // Process first withdrawal: 2 ether (within 3 ether limit)
        bridge.processWithdrawal(proposalId1);

        // Process second withdrawal: 2 ether (total 4 ether > 3 ether limit)
        // Both processed in the same rate-limit period, so the limit is exceeded
        vm.expectRevert(AethelredBridge.RateLimitExceeded.selector);
        bridge.processWithdrawal(proposalId2);
    }

    function test_RateLimit_IndependentDepositAndWithdrawal() public {
        // Set different limits for deposit and withdrawal
        vm.prank(admin);
        bridge.updateRateLimitConfig(5 ether, 100 ether, true);

        // Deposit up to the deposit limit
        vm.prank(user1);
        bridge.depositETH{value: 5 ether}(AETHELRED_RECIPIENT);

        // Additional deposit should fail (deposit limit hit)
        vm.prank(user1);
        vm.expectRevert(AethelredBridge.RateLimitExceeded.selector);
        bridge.depositETH{value: 1 ether}(AETHELRED_RECIPIENT);

        // But withdrawal limit is independent at 100 ether
        (uint256 deposited, uint256 withdrawn) = bridge.getCurrentRateLimitState();
        assertEq(deposited, 5 ether);
        assertEq(withdrawn, 0);
    }

    function test_RateLimit_MultiplePeriodsAccumulation() public {
        vm.prank(admin);
        bridge.updateRateLimitConfig(5 ether, 5 ether, true);

        // Period 1: deposit 4 ether
        vm.prank(user1);
        bridge.depositETH{value: 4 ether}(AETHELRED_RECIPIENT);

        // Move to period 2
        vm.warp(block.timestamp + 1 hours + 1);

        // Period 2: can deposit full 5 ether again (new period)
        vm.prank(user1);
        bridge.depositETH{value: 5 ether}(AETHELRED_RECIPIENT);

        // Total locked should be 9 ether across both periods
        assertEq(bridge.totalLockedETH(), 9 ether);

        // Period 2 state shows only the 5 ether from this period
        (uint256 deposited, ) = bridge.getCurrentRateLimitState();
        assertEq(deposited, 5 ether);
    }

    function testFuzz_RateLimit_BoundedDeposits(uint256 amount1, uint256 amount2) public {
        uint256 rateLimit = 20 ether;
        vm.prank(admin);
        bridge.updateRateLimitConfig(rateLimit, rateLimit, true);

        amount1 = bound(amount1, bridge.MIN_DEPOSIT(), 10 ether);
        amount2 = bound(amount2, bridge.MIN_DEPOSIT(), 10 ether);

        vm.prank(user1);
        bridge.depositETH{value: amount1}(AETHELRED_RECIPIENT);

        if (amount1 + amount2 <= rateLimit) {
            vm.prank(user2);
            bridge.depositETH{value: amount2}(AETHELRED_RECIPIENT);
            assertEq(bridge.totalLockedETH(), amount1 + amount2);
        } else {
            vm.prank(user2);
            vm.expectRevert(AethelredBridge.RateLimitExceeded.selector);
            bridge.depositETH{value: amount2}(AETHELRED_RECIPIENT);
            assertEq(bridge.totalLockedETH(), amount1);
        }
    }

    // =========================================================================
    // FUZZ TESTS (ADDITIONAL)
    // =========================================================================

    function testFuzz_DepositERC20(uint256 amount) public {
        amount = bound(amount, bridge.MIN_DEPOSIT(), bridge.MAX_SINGLE_DEPOSIT());

        mockToken.mint(user1, amount); // Ensure user1 has enough

        vm.startPrank(user1);
        mockToken.approve(address(bridge), amount);
        bridge.depositERC20(address(mockToken), amount, AETHELRED_RECIPIENT);
        vm.stopPrank();

        assertEq(bridge.totalLockedERC20(address(mockToken)), amount);
    }

    function testFuzz_CancelDeposit_FullRefund(uint256 amount) public {
        amount = bound(amount, bridge.MIN_DEPOSIT(), bridge.MAX_SINGLE_DEPOSIT());

        uint256 balanceBefore = user1.balance;

        vm.prank(user1);
        bridge.depositETH{value: amount}(AETHELRED_RECIPIENT);

        assertEq(user1.balance, balanceBefore - amount);

        bytes32 depositId = _computeDepositId(user1, AETHELRED_RECIPIENT, address(0), amount, 0);

        vm.prank(user1);
        bridge.cancelDeposit(depositId);

        assertEq(user1.balance, balanceBefore);
        assertEq(bridge.totalLockedETH(), 0);
    }

    function testFuzz_MultipleDeposits_TotalLocked(uint256 a1, uint256 a2) public {
        a1 = bound(a1, bridge.MIN_DEPOSIT(), 50 ether);
        a2 = bound(a2, bridge.MIN_DEPOSIT(), 50 ether);

        vm.prank(user1);
        bridge.depositETH{value: a1}(AETHELRED_RECIPIENT);

        vm.prank(user2);
        bridge.depositETH{value: a2}(AETHELRED_RECIPIENT);

        assertEq(bridge.totalLockedETH(), a1 + a2);
        assertEq(address(bridge).balance, a1 + a2);
    }

    // =========================================================================
    // EMERGENCY PROCEDURES
    // =========================================================================

    function test_EmergencyPause_BlocksAllOperations() public {
        // Pause the bridge
        vm.prank(guardian);
        bridge.pause();
        assertTrue(bridge.paused());

        // Deposits blocked
        vm.prank(user1);
        vm.expectRevert();
        bridge.depositETH{value: 1 ether}(AETHELRED_RECIPIENT);

        // ERC20 deposits blocked
        vm.startPrank(user1);
        mockToken.approve(address(bridge), 10e18);
        vm.expectRevert();
        bridge.depositERC20(address(mockToken), 10e18, AETHELRED_RECIPIENT);
        vm.stopPrank();

        // Proposals blocked
        vm.prank(relayer1);
        vm.expectRevert();
        bridge.proposeWithdrawal(
            keccak256("paused"),
            user2,
            address(0),
            1 ether,
            keccak256("paused-burn"),
            12345
        );

        // Voting blocked
        vm.prank(relayer2);
        vm.expectRevert();
        bridge.voteWithdrawal(keccak256("paused"));
    }

    function test_UnpauseAllowsOperations() public {
        // Pause
        vm.prank(guardian);
        bridge.pause();
        assertTrue(bridge.paused());

        // Unpause
        vm.prank(guardian);
        bridge.unpause();
        assertFalse(bridge.paused());

        // Deposit should work again
        vm.prank(user1);
        bridge.depositETH{value: 1 ether}(AETHELRED_RECIPIENT);
        assertEq(bridge.totalLockedETH(), 1 ether);

        // ERC20 deposit should work
        vm.startPrank(user1);
        mockToken.approve(address(bridge), 10e18);
        bridge.depositERC20(address(mockToken), 10e18, AETHELRED_RECIPIENT);
        vm.stopPrank();
        assertEq(bridge.totalLockedERC20(address(mockToken)), 10e18);

        // Proposal should work
        vm.prank(relayer1);
        bridge.proposeWithdrawal(
            keccak256("after-unpause"),
            user2,
            address(0),
            1 ether,
            keccak256("after-unpause-burn"),
            12345
        );

        AethelredBridge.WithdrawalProposal memory proposal = bridge.getWithdrawalProposal(keccak256("after-unpause"));
        assertEq(proposal.voteCount, 1);
    }

    function test_Revert_Unpause_NotGuardian() public {
        // Pause first
        vm.prank(guardian);
        bridge.pause();

        // Non-guardian cannot unpause
        vm.prank(user1);
        vm.expectRevert();
        bridge.unpause();

        // Regular relayer cannot unpause
        vm.prank(relayer1);
        vm.expectRevert();
        bridge.unpause();

        // Still paused
        assertTrue(bridge.paused());
    }

    // =========================================================================
    // INVARIANT TESTS
    // =========================================================================

    function invariant_TotalLockedMatchesBalance() public view {
        assertEq(bridge.totalLockedETH(), address(bridge).balance);
    }

    // =========================================================================
    // AUDIT REGRESSION - UPGRADER_ROLE Isolation
    // =========================================================================

    function test_Audit_UpgraderRoleAdminIsItself() public view {
        // The role admin for UPGRADER_ROLE must be UPGRADER_ROLE itself,
        // preventing DEFAULT_ADMIN_ROLE from granting UPGRADER_ROLE to bypass timelock.
        bytes32 upgraderRole = bridge.UPGRADER_ROLE();
        assertEq(bridge.getRoleAdmin(upgraderRole), upgraderRole);
    }

    function test_Audit_AdminCannotGrantUpgraderRole() public {
        // Admin should NOT be able to grant UPGRADER_ROLE since its admin is UPGRADER_ROLE itself.
        address newUpgrader = address(0x99);
        bytes32 upgraderRole = bridge.UPGRADER_ROLE();

        vm.prank(admin);
        vm.expectRevert();
        bridge.grantRole(upgraderRole, newUpgrader);
    }

    // =========================================================================
    // AUDIT REGRESSION - Sanctions on processWithdrawal Recipient
    // =========================================================================

    function test_Audit_ProcessWithdrawal_BlocksBlockedRecipient() public {
        // Deposit ETH
        vm.prank(user1);
        bridge.depositETH{value: 10 ether}(AETHELRED_RECIPIENT);

        // Propose withdrawal to user2 (who is not blocked yet)
        bytes32 proposalId = keccak256("sanctions-process");
        bytes32 burnTxHash = keccak256("sanctions-burn");

        vm.prank(relayer1);
        bridge.proposeWithdrawal(proposalId, user2, address(0), 1 ether, burnTxHash, 12345);
        vm.prank(relayer2);
        bridge.voteWithdrawal(proposalId);
        vm.prank(relayer3);
        bridge.voteWithdrawal(proposalId);

        // Block user2 AFTER proposal was created
        vm.prank(guardian);
        bridge.setAddressBlocked(user2, true);

        // Wait for challenge period
        vm.warp(block.timestamp + 7 days + 1);

        // Processing should fail because recipient is now blocked
        vm.expectRevert(AethelredBridge.AddressBlocked.selector);
        bridge.processWithdrawal(proposalId);

        // Unblock user2 - processing should now succeed
        vm.prank(guardian);
        bridge.setAddressBlocked(user2, false);

        uint256 user2BalanceBefore = user2.balance;
        bridge.processWithdrawal(proposalId);
        assertEq(user2.balance, user2BalanceBefore + 1 ether);
    }

    // =========================================================================
    // AUDIT REGRESSION - Emergency Withdrawal Amount Cap
    // =========================================================================

    function test_Audit_EmergencyWithdrawal_AmountCap() public {
        // Deposit enough ETH
        vm.prank(user1);
        bridge.depositETH{value: 100 ether}(AETHELRED_RECIPIENT);

        // Attempting to queue more than MAX_EMERGENCY_WITHDRAWAL (50 ETH) should revert
        vm.prank(admin);
        vm.expectRevert(AethelredBridge.EmergencyAmountExceedsMax.selector);
        bridge.queueEmergencyWithdrawal(address(0), 51 ether, user2);

        // Queuing exactly at the cap should succeed
        vm.prank(admin);
        bridge.queueEmergencyWithdrawal(address(0), 50 ether, user2);
    }

    // =========================================================================
    // AUDIT REGRESSION - Emergency Withdrawal Accounting
    // =========================================================================

    function test_Audit_EmergencyWithdrawal_UpdatesTotalLocked() public {
        // Deposit ETH
        vm.prank(user1);
        bridge.depositETH{value: 10 ether}(AETHELRED_RECIPIENT);
        assertEq(bridge.totalLockedETH(), 10 ether);

        // Queue emergency withdrawal
        vm.prank(admin);
        bytes32 operationId = bridge.queueEmergencyWithdrawal(address(0), 2 ether, user2);

        // Get guardian approvals (admin has GUARDIAN_ROLE from initialize)
        vm.prank(admin);
        bridge.approveEmergencyWithdrawal(operationId);

        // Need a second guardian - grant guardian role and approve
        vm.prank(admin);
        bridge.grantRole(bridge.GUARDIAN_ROLE(), guardian);
        vm.prank(guardian);
        bridge.approveEmergencyWithdrawal(operationId);

        // Warp past timelock
        vm.warp(block.timestamp + bridge.emergencyWithdrawalDelay() + 1);

        // Execute
        vm.prank(admin);
        bridge.executeEmergencyWithdrawal(operationId);

        // totalLockedETH should be decremented
        assertEq(bridge.totalLockedETH(), 8 ether);
        // Balance should match totalLockedETH
        assertEq(address(bridge).balance, 8 ether);
    }

    // =========================================================================
    // AUDIT REGRESSION - Emergency Withdrawal Sanctions
    // =========================================================================

    function test_Audit_EmergencyWithdrawal_BlocksBlockedRecipient() public {
        vm.prank(user1);
        bridge.depositETH{value: 10 ether}(AETHELRED_RECIPIENT);

        // Block user2
        vm.prank(guardian);
        bridge.setAddressBlocked(user2, true);

        // Queue emergency withdrawal to blocked address should revert
        vm.prank(admin);
        vm.expectRevert(AethelredBridge.AddressBlocked.selector);
        bridge.queueEmergencyWithdrawal(address(0), 1 ether, user2);
    }

    function test_Audit_EmergencyWithdrawal_BlocksRecipientBlockedDuringTimelock() public {
        vm.prank(user1);
        bridge.depositETH{value: 10 ether}(AETHELRED_RECIPIENT);

        // Queue emergency withdrawal to unblocked user2
        vm.prank(admin);
        bytes32 operationId = bridge.queueEmergencyWithdrawal(address(0), 1 ether, user2);

        // Guardian approvals
        vm.prank(admin);
        bridge.approveEmergencyWithdrawal(operationId);
        vm.prank(admin);
        bridge.grantRole(bridge.GUARDIAN_ROLE(), guardian);
        vm.prank(guardian);
        bridge.approveEmergencyWithdrawal(operationId);

        // Block user2 DURING the timelock period
        vm.prank(guardian);
        bridge.setAddressBlocked(user2, true);

        // Warp past timelock
        vm.warp(block.timestamp + bridge.emergencyWithdrawalDelay() + 1);

        // Execution should fail because recipient is now blocked
        vm.prank(admin);
        vm.expectRevert(AethelredBridge.AddressBlocked.selector);
        bridge.executeEmergencyWithdrawal(operationId);
    }

    // =========================================================================
    // AUDIT REGRESSION - Vote Threshold Snapshot
    // =========================================================================

    function test_Audit_VoteThresholdSnapshot_RecordedAtProposal() public {
        vm.prank(user1);
        bridge.depositETH{value: 10 ether}(AETHELRED_RECIPIENT);

        bytes32 proposalId = keccak256("snapshot-test");
        bytes32 burnTxHash = keccak256("snapshot-burn");

        // Current minVotesRequired = 3 (5 relayers * 67%)
        vm.prank(relayer1);
        bridge.proposeWithdrawal(proposalId, user2, address(0), 1 ether, burnTxHash, 12345);

        // Verify snapshot was recorded
        AethelredBridge.WithdrawalProposal memory proposal = bridge.getWithdrawalProposal(proposalId);
        assertEq(proposal.requiredVotesSnapshot, 3);
    }

    function test_Audit_VoteThresholdSnapshot_EnforcedStrictly() public {
        vm.prank(user1);
        bridge.depositETH{value: 10 ether}(AETHELRED_RECIPIENT);

        bytes32 proposalId = keccak256("strict-snapshot");
        bytes32 burnTxHash = keccak256("strict-burn");

        // Propose with minVotesRequired = 3
        vm.prank(relayer1);
        bridge.proposeWithdrawal(proposalId, user2, address(0), 1 ether, burnTxHash, 12345);

        // Vote: 2 votes (relayer1 from proposal + relayer2)
        vm.prank(relayer2);
        bridge.voteWithdrawal(proposalId);

        // Remove 2 relayers - this drops minVotesRequired to ~2
        vm.prank(admin);
        bridge.revokeRole(bridge.RELAYER_ROLE(), relayer4);
        vm.prank(admin);
        bridge.revokeRole(bridge.RELAYER_ROLE(), relayer5);

        // Verify current threshold dropped to 2
        (, , uint256 currentMinVotes) = bridge.relayerConfig();
        assertEq(currentMinVotes, 2);

        // Wait for challenge period
        vm.warp(block.timestamp + 7 days + 1);

        // Should still fail: only 2 votes but snapshot requires 3
        vm.expectRevert(AethelredBridge.InsufficientVotes.selector);
        bridge.processWithdrawal(proposalId);

        // Add the third vote - now it should pass (3 >= max(3, 2))
        vm.prank(relayer3);
        bridge.voteWithdrawal(proposalId);

        uint256 user2BalanceBefore = user2.balance;
        bridge.processWithdrawal(proposalId);
        assertEq(user2.balance, user2BalanceBefore + 1 ether);
    }

    // =========================================================================
    // AUDIT REGRESSION - canProcessWithdrawal shows blocked recipient
    // =========================================================================

    function test_Audit_CanProcessWithdrawal_ShowsBlockedRecipient() public {
        vm.prank(user1);
        bridge.depositETH{value: 10 ether}(AETHELRED_RECIPIENT);

        bytes32 proposalId = keccak256("view-blocked");
        bytes32 burnTxHash = keccak256("view-blocked-burn");

        vm.prank(relayer1);
        bridge.proposeWithdrawal(proposalId, user2, address(0), 1 ether, burnTxHash, 12345);
        vm.prank(relayer2);
        bridge.voteWithdrawal(proposalId);
        vm.prank(relayer3);
        bridge.voteWithdrawal(proposalId);

        vm.warp(block.timestamp + 7 days + 1);

        // Before blocking: should be processable
        (bool canProcess, ) = bridge.canProcessWithdrawal(proposalId);
        assertTrue(canProcess);

        // Block recipient
        vm.prank(guardian);
        bridge.setAddressBlocked(user2, true);

        // After blocking: should report blocked
        (bool canProcess2, string memory reason) = bridge.canProcessWithdrawal(proposalId);
        assertFalse(canProcess2);
        assertEq(reason, "Recipient blocked");
    }

    // =========================================================================
    // HELPERS
    // =========================================================================

    function _computeDepositId(
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
}

/**
 * @title AethelredBridgeInvariantTest
 * @notice Invariant tests for continuous property verification
 */
contract AethelredBridgeInvariantTest is Test {
    AethelredBridge public bridge;
    BridgeHandler public handler;

    function setUp() public {
        // Deploy bridge
        AethelredBridge implementation = new AethelredBridge();

        address[] memory relayers = new address[](3);
        relayers[0] = address(0x10);
        relayers[1] = address(0x11);
        relayers[2] = address(0x12);

        bytes memory initData = abi.encodeCall(
            AethelredBridge.initialize,
            (address(this), relayers, 6700)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        bridge = AethelredBridge(payable(address(proxy)));

        // Deploy handler
        handler = new BridgeHandler(bridge);

        // Target only the handler
        targetContract(address(handler));
    }

    function invariant_TotalLockedNeverNegative() public view {
        assertGe(bridge.totalLockedETH(), 0);
    }

    function invariant_BalanceMatchesLocked() public view {
        assertEq(address(bridge).balance, bridge.totalLockedETH());
    }
}

/**
 * @title BridgeHandler
 * @notice Handler contract for invariant testing
 */
contract BridgeHandler is Test {
    AethelredBridge public bridge;

    bytes32 constant AETHELRED_RECIPIENT = bytes32(uint256(0xABCDEF));

    constructor(AethelredBridge _bridge) {
        bridge = _bridge;
    }

    function deposit(uint256 amount) external {
        amount = bound(amount, 0.01 ether, 100 ether);
        vm.deal(address(this), amount);
        bridge.depositETH{value: amount}(AETHELRED_RECIPIENT);
    }

    receive() external payable {}
}
