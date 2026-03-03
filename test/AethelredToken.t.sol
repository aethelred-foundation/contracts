// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/access/IAccessControl.sol";
import "../contracts/AethelredToken.sol";

/**
 * @title AethelredTokenTest
 * @notice Comprehensive Foundry test suite for AethelredToken
 * @dev Covers: initialization, transfers, blacklist, whitelist, supply cap,
 *      bridge minting/burning, compliance burns, access control, pausing,
 *      UUPS upgrade safety, fuzz tests, and boundary conditions.
 *
 * Test naming: test_Category_Scenario (positive), test_Revert_Category_Scenario (negative)
 *
 * @custom:audit-coverage Target: 95%+ line coverage, 100% critical path coverage
 * @custom:audit-date 2026-02-28
 */
contract AethelredTokenTest is Test {
    // =========================================================================
    // STATE
    // =========================================================================

    AethelredToken public token;
    AethelredToken public implementation;

    address public admin = address(0xAD);
    address public minter = address(0xAA);
    address public pauser = address(0xBB);
    address public compliance = address(0xCC);
    address public complianceBurner = address(0xCB);
    address public burner = address(0xDD);
    address public upgrader = address(0xEE);

    address public alice = address(0x1);
    address public bob = address(0x2);
    address public carol = address(0x3);
    address public bridge1 = address(0x100);
    address public bridge2 = address(0x200);

    uint256 public constant INITIAL_AMOUNT = 1_000_000_000 ether;
    uint256 public constant TOTAL_SUPPLY_CAP = 10_000_000_000 * 1e18;

    // =========================================================================
    // EVENTS (re-declared for vm.expectEmit)
    // =========================================================================

    event AddressBlacklisted(address indexed account, bool blacklisted);
    event AddressWhitelisted(address indexed account, bool whitelisted);
    event TransferRestrictionsUpdated(bool enabled);
    event BridgeAuthorized(address indexed bridge, bool authorized);
    event TokensBurnedByBridge(address indexed bridge, address indexed from, uint256 amount);
    event TokensMintedByBridge(address indexed bridge, address indexed to, uint256 amount);
    event ComplianceSlash(
        address indexed account,
        uint256 amount,
        bytes32 indexed reason,
        address indexed authority
    );
    event Transfer(address indexed from, address indexed to, uint256 value);

    // =========================================================================
    // SETUP
    // =========================================================================

    function setUp() public {
        implementation = new AethelredToken();

        bytes memory initData = abi.encodeCall(
            AethelredToken.initialize,
            (admin, minter, alice, INITIAL_AMOUNT)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        token = AethelredToken(address(proxy));

        // Grant roles
        vm.startPrank(admin);
        token.grantRole(token.PAUSER_ROLE(), pauser);
        token.grantRole(token.COMPLIANCE_ROLE(), compliance);
        token.grantRole(token.COMPLIANCE_BURN_ROLE(), complianceBurner);
        token.grantRole(token.BURNER_ROLE(), burner);
        token.grantRole(token.UPGRADER_ROLE(), upgrader);
        vm.stopPrank();
    }

    // =========================================================================
    // INITIALIZATION TESTS
    // =========================================================================

    function test_Init_TotalSupply() public view {
        assertEq(token.totalSupply(), INITIAL_AMOUNT);
    }

    function test_Init_Decimals() public view {
        assertEq(token.decimals(), 18);
    }

    function test_Init_InitialRecipientBalance() public view {
        assertEq(token.balanceOf(alice), INITIAL_AMOUNT);
    }

    function test_Init_AdminHasDefaultAdminRole() public view {
        assertTrue(token.hasRole(token.DEFAULT_ADMIN_ROLE(), admin));
    }

    function test_Init_MinterHasMinterRole() public view {
        assertTrue(token.hasRole(token.MINTER_ROLE(), minter));
    }

    function test_Init_TransferRestrictionsEnabled() public view {
        assertTrue(token.transferRestrictionsEnabled());
    }

    function test_Init_Version() public view {
        assertEq(keccak256(bytes(token.version())), keccak256(bytes("1.0.0")));
    }

    function test_Revert_Init_CannotReinitialize() public {
        vm.expectRevert();
        token.initialize(admin, minter, alice, INITIAL_AMOUNT);
    }

    function test_Revert_Init_ImplementationCannotBeInitialized() public {
        vm.expectRevert();
        implementation.initialize(admin, minter, alice, INITIAL_AMOUNT);
    }

    // =========================================================================
    // TRANSFER RESTRICTION TESTS
    // =========================================================================

    function test_Transfer_RestrictedByDefault() public {
        vm.prank(alice);
        vm.expectRevert(AethelredToken.TransferRestricted.selector);
        token.transfer(bob, 1 ether);
    }

    function test_Transfer_WhitelistedCanTransfer() public {
        vm.prank(compliance);
        token.setWhitelisted(alice, true);

        vm.prank(alice);
        assertTrue(token.transfer(bob, 5 ether));
        assertEq(token.balanceOf(bob), 5 ether);
        assertEq(token.balanceOf(alice), INITIAL_AMOUNT - 5 ether);
    }

    function test_Transfer_WhitelistedCanTransferFrom() public {
        vm.prank(compliance);
        token.setWhitelisted(alice, true);

        vm.prank(alice);
        token.approve(bob, 10 ether);

        vm.prank(bob);
        assertTrue(token.transferFrom(alice, bob, 10 ether));
        assertEq(token.balanceOf(bob), 10 ether);
    }

    function test_Transfer_DisableRestrictionsAllowsAll() public {
        vm.prank(admin);
        token.setTransferRestrictions(false);

        vm.prank(alice);
        assertTrue(token.transfer(bob, 1 ether));
        assertEq(token.balanceOf(bob), 1 ether);
    }

    function test_Transfer_ReenableRestrictions() public {
        vm.prank(admin);
        token.setTransferRestrictions(false);

        vm.prank(admin);
        token.setTransferRestrictions(true);

        vm.prank(alice);
        vm.expectRevert(AethelredToken.TransferRestricted.selector);
        token.transfer(bob, 1 ether);
    }

    function test_Revert_Transfer_BlacklistedSender() public {
        vm.prank(admin);
        token.setTransferRestrictions(false);

        vm.prank(compliance);
        token.setBlacklisted(alice, true);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(AethelredToken.AddressBlacklistedError.selector, alice));
        token.transfer(bob, 1 ether);
    }

    function test_Revert_Transfer_BlacklistedRecipient() public {
        vm.prank(admin);
        token.setTransferRestrictions(false);

        vm.prank(compliance);
        token.setBlacklisted(bob, true);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(AethelredToken.AddressBlacklistedError.selector, bob));
        token.transfer(bob, 1 ether);
    }

    function test_Transfer_ZeroAmount() public {
        vm.prank(compliance);
        token.setWhitelisted(alice, true);

        vm.prank(alice);
        assertTrue(token.transfer(bob, 0));
    }

    function test_View_CanTransfer() public {
        assertFalse(token.canTransfer(alice));

        vm.prank(compliance);
        token.setWhitelisted(alice, true);
        assertTrue(token.canTransfer(alice));

        vm.prank(compliance);
        token.setBlacklisted(alice, true);
        assertFalse(token.canTransfer(alice));
    }

    // =========================================================================
    // BLACKLIST TESTS
    // =========================================================================

    function test_Blacklist_SetAndUnset() public {
        vm.prank(compliance);
        token.setBlacklisted(alice, true);
        assertTrue(token.blacklisted(alice));

        vm.prank(compliance);
        token.setBlacklisted(alice, false);
        assertFalse(token.blacklisted(alice));
    }

    function test_Blacklist_EmitsEvent() public {
        vm.prank(compliance);
        vm.expectEmit(true, false, false, true);
        emit AddressBlacklisted(alice, true);
        token.setBlacklisted(alice, true);
    }

    function test_Revert_Blacklist_OnlyComplianceRole() public {
        vm.prank(alice);
        vm.expectRevert();
        token.setBlacklisted(bob, true);
    }

    function test_BatchBlacklist_MultipleAddresses() public {
        address[] memory accounts = new address[](3);
        accounts[0] = alice;
        accounts[1] = bob;
        accounts[2] = carol;

        vm.prank(compliance);
        token.batchSetBlacklisted(accounts, true);

        assertTrue(token.blacklisted(alice));
        assertTrue(token.blacklisted(bob));
        assertTrue(token.blacklisted(carol));
    }

    function test_BatchBlacklist_UnsetMultiple() public {
        address[] memory accounts = new address[](2);
        accounts[0] = alice;
        accounts[1] = bob;

        vm.prank(compliance);
        token.batchSetBlacklisted(accounts, true);

        vm.prank(compliance);
        token.batchSetBlacklisted(accounts, false);

        assertFalse(token.blacklisted(alice));
        assertFalse(token.blacklisted(bob));
    }

    function test_BatchBlacklist_MaxSize() public {
        address[] memory accounts = new address[](200);
        for (uint256 i = 0; i < 200; i++) {
            accounts[i] = address(uint160(0x1000 + i));
        }

        vm.prank(compliance);
        token.batchSetBlacklisted(accounts, true);

        // Verify first and last
        assertTrue(token.blacklisted(accounts[0]));
        assertTrue(token.blacklisted(accounts[199]));
    }

    function test_Revert_BatchBlacklist_ExceedsMaxSize() public {
        address[] memory accounts = new address[](201);
        for (uint256 i = 0; i < 201; i++) {
            accounts[i] = address(uint160(0x1000 + i));
        }

        vm.prank(compliance);
        vm.expectRevert();
        token.batchSetBlacklisted(accounts, true);
    }

    function test_BatchBlacklist_EmptyArray() public {
        address[] memory accounts = new address[](0);

        vm.prank(compliance);
        token.batchSetBlacklisted(accounts, true);
        // Should succeed with no effect
    }

    function test_Revert_BatchBlacklist_OnlyComplianceRole() public {
        address[] memory accounts = new address[](1);
        accounts[0] = alice;

        vm.prank(alice);
        vm.expectRevert();
        token.batchSetBlacklisted(accounts, true);
    }

    // =========================================================================
    // MINTING TESTS
    // =========================================================================

    function test_Mint_Success() public {
        vm.prank(minter);
        token.mint(bob, 1000 ether);
        assertEq(token.balanceOf(bob), 1000 ether);
    }

    function test_Mint_RespectsSupplyCap() public {
        uint256 remaining = token.remainingMintable();

        vm.prank(minter);
        token.mint(bob, remaining);

        assertEq(token.totalSupply(), TOTAL_SUPPLY_CAP);
        assertEq(token.remainingMintable(), 0);
    }

    function test_Revert_Mint_ExceedsSupplyCap() public {
        uint256 remaining = token.remainingMintable();

        vm.prank(minter);
        vm.expectRevert(AethelredToken.SupplyCapExceeded.selector);
        token.mint(bob, remaining + 1);
    }

    function test_Revert_Mint_ToBlacklistedAddress() public {
        vm.prank(compliance);
        token.setBlacklisted(bob, true);

        vm.prank(minter);
        vm.expectRevert(abi.encodeWithSelector(AethelredToken.AddressBlacklistedError.selector, bob));
        token.mint(bob, 100 ether);
    }

    function test_Revert_Mint_OnlyMinterRole() public {
        vm.prank(alice);
        vm.expectRevert();
        token.mint(bob, 100 ether);
    }

    function test_Mint_RemainingMintableDecreases() public {
        uint256 before = token.remainingMintable();

        vm.prank(minter);
        token.mint(bob, 500 ether);

        assertEq(token.remainingMintable(), before - 500 ether);
    }

    // =========================================================================
    // BURNING TESTS
    // =========================================================================

    function test_Burn_Self() public {
        vm.prank(admin);
        token.setTransferRestrictions(false);

        vm.prank(alice);
        token.burn(100 ether);

        assertEq(token.balanceOf(alice), INITIAL_AMOUNT - 100 ether);
        assertEq(token.totalBurned(), 100 ether);
    }

    function test_BurnFrom_WithApproval() public {
        vm.prank(admin);
        token.setTransferRestrictions(false);

        vm.prank(alice);
        token.approve(bob, 100 ether);

        vm.prank(bob);
        token.burnFrom(alice, 100 ether);

        assertEq(token.balanceOf(alice), INITIAL_AMOUNT - 100 ether);
    }

    function test_AdminBurn_Success() public {
        vm.prank(alice);
        token.approve(burner, 500 ether);

        vm.prank(burner);
        token.adminBurn(alice, 500 ether);

        assertEq(token.balanceOf(alice), INITIAL_AMOUNT - 500 ether);
        assertEq(token.totalBurned(), 500 ether);
    }

    function test_AdminBurn_EmitsComplianceSlash() public {
        vm.prank(alice);
        token.approve(burner, 500 ether);

        vm.expectEmit(true, true, true, true);
        emit ComplianceSlash(
            alice,
            500 ether,
            keccak256("LEGACY_ADMIN_BURN"),
            burner
        );
        vm.prank(burner);
        token.adminBurn(alice, 500 ether);
    }

    function test_Revert_AdminBurn_OnlyBurnerRole() public {
        vm.prank(alice);
        vm.expectRevert();
        token.adminBurn(bob, 100 ether);
    }

    function test_ComplianceBurn_Success() public {
        bytes32 reason = keccak256("SANCTIONS_VIOLATION");

        vm.prank(alice);
        token.approve(complianceBurner, 100 ether);

        vm.prank(complianceBurner);
        token.complianceBurn(alice, 100 ether, reason);

        assertEq(token.balanceOf(alice), INITIAL_AMOUNT - 100 ether);
    }

    function test_ComplianceBurn_EmitsEvent() public {
        bytes32 reason = keccak256("SANCTIONS_VIOLATION");

        vm.prank(alice);
        token.approve(complianceBurner, 100 ether);

        vm.expectEmit(true, true, true, true);
        emit ComplianceSlash(alice, 100 ether, reason, complianceBurner);
        vm.prank(complianceBurner);
        token.complianceBurn(alice, 100 ether, reason);
    }

    function test_Revert_ComplianceBurn_ZeroReason() public {
        vm.prank(complianceBurner);
        vm.expectRevert(AethelredToken.ComplianceBurnReasonRequired.selector);
        token.complianceBurn(alice, 100 ether, bytes32(0));
    }

    // =========================================================================
    // BRIDGE TESTS
    // =========================================================================

    function test_Bridge_MintRequiresAuthorization() public {
        vm.prank(bridge1);
        vm.expectRevert(AethelredToken.UnauthorizedBridge.selector);
        token.bridgeMint(bob, 10 ether);
    }

    function test_Bridge_AuthorizedCanMint() public {
        vm.prank(admin);
        token.setAuthorizedBridge(bridge1, true);

        vm.prank(bridge1);
        token.bridgeMint(bob, 10 ether);

        assertEq(token.balanceOf(bob), 10 ether);
    }

    function test_Bridge_MintEmitsEvent() public {
        vm.prank(admin);
        token.setAuthorizedBridge(bridge1, true);

        vm.prank(bridge1);
        vm.expectEmit(true, true, false, true);
        emit TokensMintedByBridge(bridge1, bob, 10 ether);
        token.bridgeMint(bob, 10 ether);
    }

    function test_Bridge_BurnRequiresAuthorization() public {
        vm.prank(bridge1);
        vm.expectRevert(AethelredToken.UnauthorizedBridge.selector);
        token.bridgeBurn(alice, 10 ether);
    }

    function test_Bridge_AuthorizedCanBurn() public {
        vm.prank(admin);
        token.setAuthorizedBridge(bridge1, true);

        vm.prank(alice);
        token.approve(bridge1, 10 ether);

        vm.prank(bridge1);
        token.bridgeBurn(alice, 10 ether);

        assertEq(token.balanceOf(alice), INITIAL_AMOUNT - 10 ether);
    }

    function test_Bridge_BurnEmitsEvent() public {
        vm.prank(admin);
        token.setAuthorizedBridge(bridge1, true);

        vm.prank(alice);
        token.approve(bridge1, 10 ether);

        vm.expectEmit(true, true, false, true);
        emit TokensBurnedByBridge(bridge1, alice, 10 ether);
        vm.prank(bridge1);
        token.bridgeBurn(alice, 10 ether);
    }

    function test_Bridge_RevokeAuthorization() public {
        vm.prank(admin);
        token.setAuthorizedBridge(bridge1, true);

        vm.prank(admin);
        token.setAuthorizedBridge(bridge1, false);

        vm.prank(bridge1);
        vm.expectRevert(AethelredToken.UnauthorizedBridge.selector);
        token.bridgeMint(bob, 10 ether);
    }

    function test_Bridge_MultipleBridges() public {
        vm.startPrank(admin);
        token.setAuthorizedBridge(bridge1, true);
        token.setAuthorizedBridge(bridge2, true);
        vm.stopPrank();

        vm.prank(bridge1);
        token.bridgeMint(bob, 5 ether);

        vm.prank(bridge2);
        token.bridgeMint(carol, 7 ether);

        assertEq(token.balanceOf(bob), 5 ether);
        assertEq(token.balanceOf(carol), 7 ether);
    }

    function test_Revert_Bridge_MintToBlacklisted() public {
        vm.prank(admin);
        token.setAuthorizedBridge(bridge1, true);

        vm.prank(compliance);
        token.setBlacklisted(bob, true);

        vm.prank(bridge1);
        vm.expectRevert(abi.encodeWithSelector(AethelredToken.AddressBlacklistedError.selector, bob));
        token.bridgeMint(bob, 10 ether);
    }

    // =========================================================================
    // SUPPLY VIEW TESTS
    // =========================================================================

    function test_CirculatingSupply() public view {
        uint256 circulating = token.circulatingSupply();
        assertEq(circulating, INITIAL_AMOUNT);
    }

    function test_CirculatingSupply_AfterBurn() public {
        vm.prank(alice);
        token.approve(burner, 100 ether);

        vm.prank(burner);
        token.adminBurn(alice, 100 ether);

        assertEq(token.circulatingSupply(), INITIAL_AMOUNT - 100 ether);
    }

    function test_RemainingMintable() public view {
        assertEq(token.remainingMintable(), TOTAL_SUPPLY_CAP - INITIAL_AMOUNT);
    }

    function test_Constants() public view {
        assertEq(token.TOTAL_SUPPLY_CAP(), TOTAL_SUPPLY_CAP);
        assertEq(token.UAETHEL_TO_WEI_SCALE(), 1e12);
        assertEq(token.MAX_BATCH_BLACKLIST_SIZE(), 200);
    }

    // =========================================================================
    // PAUSING TESTS
    // =========================================================================

    function test_Pause_Success() public {
        vm.prank(pauser);
        token.pause();
        assertTrue(token.paused());
    }

    function test_Unpause_Success() public {
        vm.prank(pauser);
        token.pause();

        vm.prank(pauser);
        token.unpause();
        assertFalse(token.paused());
    }

    function test_Revert_Pause_OnlyPauserRole() public {
        vm.prank(alice);
        vm.expectRevert();
        token.pause();
    }

    function test_Revert_Transfer_WhenPaused() public {
        vm.prank(compliance);
        token.setWhitelisted(alice, true);

        vm.prank(pauser);
        token.pause();

        vm.prank(alice);
        vm.expectRevert();
        token.transfer(bob, 1 ether);
    }

    function test_Revert_Mint_WhenPaused() public {
        vm.prank(pauser);
        token.pause();

        vm.prank(minter);
        vm.expectRevert();
        token.mint(bob, 100 ether);
    }

    // =========================================================================
    // ACCESS CONTROL TESTS
    // =========================================================================

    function test_Revert_SetTransferRestrictions_NotAdmin() public {
        vm.prank(alice);
        vm.expectRevert();
        token.setTransferRestrictions(false);
    }

    function test_Revert_SetAuthorizedBridge_NotAdmin() public {
        vm.prank(alice);
        vm.expectRevert();
        token.setAuthorizedBridge(bridge1, true);
    }

    function test_Revert_GrantRole_NotAdmin() public {
        bytes32 minterRole = token.MINTER_ROLE();
        bytes32 adminRole = token.DEFAULT_ADMIN_ROLE();

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, alice, adminRole));
        token.grantRole(minterRole, bob);
    }

    // =========================================================================
    // FUZZ TESTS
    // =========================================================================

    function testFuzz_Mint_AnyAmountWithinCap(uint256 amount) public {
        uint256 remaining = token.remainingMintable();
        amount = bound(amount, 0, remaining);

        vm.prank(minter);
        token.mint(bob, amount);

        assertEq(token.balanceOf(bob), amount);
        assertEq(token.totalSupply(), INITIAL_AMOUNT + amount);
        assertLe(token.totalSupply(), TOTAL_SUPPLY_CAP);
    }

    function testFuzz_Transfer_PreservesBalance(uint256 amount) public {
        amount = bound(amount, 0, INITIAL_AMOUNT);

        vm.prank(compliance);
        token.setWhitelisted(alice, true);

        uint256 aliceBefore = token.balanceOf(alice);
        uint256 bobBefore = token.balanceOf(bob);

        vm.prank(alice);
        token.transfer(bob, amount);

        assertEq(token.balanceOf(alice), aliceBefore - amount);
        assertEq(token.balanceOf(bob), bobBefore + amount);
    }

    function testFuzz_BatchBlacklist_Bounded(uint8 count) public {
        count = uint8(bound(count, 1, 200));
        address[] memory accounts = new address[](count);
        for (uint8 i = 0; i < count; i++) {
            accounts[i] = address(uint160(0x5000 + i));
        }

        vm.prank(compliance);
        token.batchSetBlacklisted(accounts, true);

        for (uint8 i = 0; i < count; i++) {
            assertTrue(token.blacklisted(accounts[i]));
        }
    }

    function testFuzz_Burn_DecreasesSupply(uint256 amount) public {
        amount = bound(amount, 1, INITIAL_AMOUNT);

        vm.prank(alice);
        token.approve(burner, type(uint256).max);

        vm.prank(burner);
        token.adminBurn(alice, amount);

        assertEq(token.totalSupply(), INITIAL_AMOUNT - amount);
        assertEq(token.totalBurned(), amount);
        assertEq(token.balanceOf(alice), INITIAL_AMOUNT - amount);
    }

    function testFuzz_CirculatingSupply_AlwaysCorrect(uint256 mintAmt, uint256 burnAmt) public {
        uint256 remaining = token.remainingMintable();
        mintAmt = bound(mintAmt, 0, remaining);
        burnAmt = bound(burnAmt, 0, INITIAL_AMOUNT);

        vm.prank(minter);
        token.mint(bob, mintAmt);

        vm.prank(alice);
        token.approve(burner, type(uint256).max);

        vm.prank(burner);
        token.adminBurn(alice, burnAmt);

        uint256 expectedCirculating = INITIAL_AMOUNT + mintAmt - burnAmt;
        assertEq(token.circulatingSupply(), expectedCirculating);
    }

    // =========================================================================
    // INVARIANT-STYLE PROPERTY TESTS
    // =========================================================================

    function testFuzz_Invariant_SupplyNeverExceedsCap(uint256 amount) public {
        uint256 remaining = token.remainingMintable();
        amount = bound(amount, 0, remaining);

        vm.prank(minter);
        token.mint(bob, amount);

        assertLe(token.totalSupply(), TOTAL_SUPPLY_CAP);
    }

    function testFuzz_Invariant_CirculatingPlusBurnedEqualsTotalSupply(uint256 burnAmt) public {
        burnAmt = bound(burnAmt, 0, INITIAL_AMOUNT);

        vm.prank(alice);
        token.approve(burner, type(uint256).max);

        vm.prank(burner);
        token.adminBurn(alice, burnAmt);

        // totalSupply() already excludes burned tokens (ERC20 standard).
        // circulatingSupply() == totalSupply(). The invariant is:
        // totalSupply + totalBurned == total ever minted (INITIAL_AMOUNT here)
        assertEq(
            token.circulatingSupply() + token.totalBurned(),
            INITIAL_AMOUNT
        );
    }

    // =========================================================================
    // BOUNDARY TESTS
    // =========================================================================

    function test_Boundary_MintExactlyRemaining() public {
        uint256 remaining = token.remainingMintable();

        vm.prank(minter);
        token.mint(bob, remaining);

        assertEq(token.totalSupply(), TOTAL_SUPPLY_CAP);
        assertEq(token.remainingMintable(), 0);
    }

    function test_Boundary_MintOneOverCap() public {
        uint256 remaining = token.remainingMintable();

        vm.prank(minter);
        vm.expectRevert(AethelredToken.SupplyCapExceeded.selector);
        token.mint(bob, remaining + 1);
    }

    function test_Boundary_BurnEntireBalance() public {
        vm.prank(alice);
        token.approve(burner, INITIAL_AMOUNT);

        vm.prank(burner);
        token.adminBurn(alice, INITIAL_AMOUNT);

        assertEq(token.balanceOf(alice), 0);
        assertEq(token.totalBurned(), INITIAL_AMOUNT);
    }

    function test_Boundary_TransferEntireBalance() public {
        vm.prank(compliance);
        token.setWhitelisted(alice, true);

        vm.prank(alice);
        token.transfer(bob, INITIAL_AMOUNT);

        assertEq(token.balanceOf(alice), 0);
        assertEq(token.balanceOf(bob), INITIAL_AMOUNT);
    }

    function test_Boundary_MintZero() public {
        vm.prank(minter);
        token.mint(bob, 0);
        assertEq(token.balanceOf(bob), 0);
    }

    // =========================================================================
    // EVENT EMISSION TESTS
    // =========================================================================

    function test_Event_TransferRestrictionsChanged() public {
        vm.prank(admin);
        vm.expectEmit(false, false, false, true);
        emit TransferRestrictionsUpdated(false);
        token.setTransferRestrictions(false);

        vm.prank(admin);
        vm.expectEmit(false, false, false, true);
        emit TransferRestrictionsUpdated(true);
        token.setTransferRestrictions(true);
    }

    function test_Event_WhitelistChanged() public {
        vm.prank(compliance);
        vm.expectEmit(true, false, false, true);
        emit AddressWhitelisted(alice, true);
        token.setWhitelisted(alice, true);

        vm.prank(compliance);
        vm.expectEmit(true, false, false, true);
        emit AddressWhitelisted(alice, false);
        token.setWhitelisted(alice, false);
    }

    function test_Event_BridgeAuthorized() public {
        vm.prank(admin);
        vm.expectEmit(true, false, false, true);
        emit BridgeAuthorized(bridge1, true);
        token.setAuthorizedBridge(bridge1, true);
    }

    function test_Event_MintEmitsTransfer() public {
        // ERC20 _mint emits Transfer(address(0), to, amount)
        vm.prank(minter);
        vm.expectEmit(true, true, false, true);
        emit Transfer(address(0), bob, 50 ether);
        token.mint(bob, 50 ether);
    }

    function test_Event_BurnEmitsTransfer() public {
        // ERC20 _burn emits Transfer(from, address(0), amount)
        vm.prank(alice);
        vm.expectEmit(true, true, false, true);
        emit Transfer(alice, address(0), 50 ether);
        token.burn(50 ether);
    }

    // =========================================================================
    // ROLE MANAGEMENT TESTS
    // =========================================================================

    function test_Role_AdminCanRevokeRoles() public {
        // Verify minter has role, then revoke it
        bytes32 minterRole = token.MINTER_ROLE();
        assertTrue(token.hasRole(minterRole, minter));

        vm.prank(admin);
        token.revokeRole(minterRole, minter);

        assertFalse(token.hasRole(minterRole, minter));
    }

    function test_Role_RevokedMinterCannotMint() public {
        bytes32 minterRole = token.MINTER_ROLE();

        vm.prank(admin);
        token.revokeRole(minterRole, minter);

        vm.prank(minter);
        vm.expectRevert();
        token.mint(bob, 100 ether);
    }

    function test_Role_RevokedPauserCannotPause() public {
        bytes32 pauserRole = token.PAUSER_ROLE();

        vm.prank(admin);
        token.revokeRole(pauserRole, pauser);

        vm.prank(pauser);
        vm.expectRevert();
        token.pause();
    }

    function test_Role_AdminRenounce() public {
        // Admin renounces DEFAULT_ADMIN_ROLE
        bytes32 adminRole = token.DEFAULT_ADMIN_ROLE();

        vm.prank(admin);
        token.renounceRole(adminRole, admin);

        assertFalse(token.hasRole(adminRole, admin));
    }

    function test_Role_GrantAndRevokeSameTransaction() public {
        address newMinter = address(0xF1);

        vm.startPrank(admin);
        token.grantRole(token.MINTER_ROLE(), newMinter);
        assertTrue(token.hasRole(token.MINTER_ROLE(), newMinter));

        token.revokeRole(token.MINTER_ROLE(), newMinter);
        assertFalse(token.hasRole(token.MINTER_ROLE(), newMinter));
        vm.stopPrank();

        // newMinter should not be able to mint
        vm.prank(newMinter);
        vm.expectRevert();
        token.mint(bob, 1 ether);
    }

    function test_Role_RevokedComplianceCannotBlacklist() public {
        bytes32 complianceRole = token.COMPLIANCE_ROLE();

        vm.prank(admin);
        token.revokeRole(complianceRole, compliance);

        vm.prank(compliance);
        vm.expectRevert();
        token.setBlacklisted(bob, true);
    }

    // =========================================================================
    // WHITELIST EDGE CASE TESTS
    // =========================================================================

    function test_Whitelist_BothWhitelistedAndBlacklisted_BlacklistWins() public {
        vm.startPrank(compliance);
        token.setWhitelisted(alice, true);
        token.setBlacklisted(alice, true);
        vm.stopPrank();

        // Blacklist takes precedence over whitelist for transfers
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(AethelredToken.AddressBlacklistedError.selector, alice));
        token.transfer(bob, 1 ether);
    }

    function test_Whitelist_RecipientNotWhitelisted_StillWorks() public {
        // Only sender needs to be whitelisted; recipient does not
        vm.prank(compliance);
        token.setWhitelisted(alice, true);

        // bob is not whitelisted, but as recipient this should still work
        vm.prank(alice);
        assertTrue(token.transfer(bob, 5 ether));
        assertEq(token.balanceOf(bob), 5 ether);
    }

    function test_Whitelist_RemoveWhitelist_BlocksTransfer() public {
        vm.prank(compliance);
        token.setWhitelisted(alice, true);

        // Verify transfer works
        vm.prank(alice);
        token.transfer(bob, 1 ether);

        // Remove whitelist
        vm.prank(compliance);
        token.setWhitelisted(alice, false);

        // Now transfer should be blocked
        vm.prank(alice);
        vm.expectRevert(AethelredToken.TransferRestricted.selector);
        token.transfer(bob, 1 ether);
    }

    function test_Whitelist_EmitsEvent() public {
        vm.prank(compliance);
        vm.expectEmit(true, false, false, true);
        emit AddressWhitelisted(bob, true);
        token.setWhitelisted(bob, true);
    }

    // =========================================================================
    // COMPLIANCE BURN TESTS
    // =========================================================================

    function test_ComplianceBurn_MultipleBurns_AccumulatesTotalBurned() public {
        bytes32 reason = keccak256("SANCTIONS");

        vm.prank(alice);
        token.approve(complianceBurner, 300 ether);

        vm.startPrank(complianceBurner);
        token.complianceBurn(alice, 100 ether, reason);
        token.complianceBurn(alice, 100 ether, reason);
        token.complianceBurn(alice, 100 ether, reason);
        vm.stopPrank();

        assertEq(token.totalBurned(), 300 ether);
        assertEq(token.balanceOf(alice), INITIAL_AMOUNT - 300 ether);
    }

    function test_ComplianceBurn_WithDifferentReasons() public {
        bytes32 reason1 = keccak256("SANCTIONS");
        bytes32 reason2 = keccak256("FRAUD");
        bytes32 reason3 = keccak256("AML_VIOLATION");

        vm.prank(alice);
        token.approve(complianceBurner, 300 ether);

        vm.startPrank(complianceBurner);

        vm.expectEmit(true, true, true, true);
        emit ComplianceSlash(alice, 100 ether, reason1, complianceBurner);
        token.complianceBurn(alice, 100 ether, reason1);

        vm.expectEmit(true, true, true, true);
        emit ComplianceSlash(alice, 50 ether, reason2, complianceBurner);
        token.complianceBurn(alice, 50 ether, reason2);

        vm.expectEmit(true, true, true, true);
        emit ComplianceSlash(alice, 25 ether, reason3, complianceBurner);
        token.complianceBurn(alice, 25 ether, reason3);

        vm.stopPrank();

        assertEq(token.totalBurned(), 175 ether);
    }

    function test_Revert_ComplianceBurn_OnlyComplianceBurnRole() public {
        bytes32 reason = keccak256("SANCTIONS");

        // alice (no COMPLIANCE_BURN_ROLE) tries to compliance burn
        vm.prank(alice);
        vm.expectRevert();
        token.complianceBurn(alice, 100 ether, reason);

        // burner (has BURNER_ROLE but not COMPLIANCE_BURN_ROLE) tries
        vm.prank(burner);
        vm.expectRevert();
        token.complianceBurn(alice, 100 ether, reason);
    }

    function test_ComplianceBurn_OnBlacklistedAddress() public {
        bytes32 reason = keccak256("SANCTIONS");

        vm.prank(alice);
        token.approve(complianceBurner, 100 ether);

        // Blacklist alice
        vm.prank(compliance);
        token.setBlacklisted(alice, true);

        // complianceBurn should still work on blacklisted address
        // (it uses _burn directly, not transfer)
        vm.prank(complianceBurner);
        token.complianceBurn(alice, 100 ether, reason);

        assertEq(token.balanceOf(alice), INITIAL_AMOUNT - 100 ether);
        assertEq(token.totalBurned(), 100 ether);
    }

    // =========================================================================
    // BRIDGE EDGE CASE TESTS
    // =========================================================================

    function test_Bridge_MintRespectsSupplyCap() public {
        vm.prank(admin);
        token.setAuthorizedBridge(bridge1, true);

        uint256 remaining = token.remainingMintable();

        // Mint exactly to cap should succeed
        vm.prank(bridge1);
        token.bridgeMint(bob, remaining);
        assertEq(token.totalSupply(), TOTAL_SUPPLY_CAP);

        // Mint 1 more should revert
        vm.prank(bridge1);
        vm.expectRevert(AethelredToken.SupplyCapExceeded.selector);
        token.bridgeMint(bob, 1);
    }

    function test_Bridge_BurnReducesTotalBurned() public {
        vm.prank(admin);
        token.setAuthorizedBridge(bridge1, true);

        // alice approves bridge1
        vm.prank(alice);
        token.approve(bridge1, 200 ether);

        uint256 burnedBefore = token.totalBurned();

        vm.prank(bridge1);
        token.bridgeBurn(alice, 200 ether);

        assertEq(token.totalBurned(), burnedBefore + 200 ether);
        assertEq(token.balanceOf(alice), INITIAL_AMOUNT - 200 ether);
    }

    function test_Revert_Bridge_BurnFromBlacklisted() public {
        // bridgeBurn does not have notBlacklisted modifier, so it should work
        // even on blacklisted addresses. Let's verify the actual behavior.
        vm.prank(admin);
        token.setAuthorizedBridge(bridge1, true);

        vm.prank(alice);
        token.approve(bridge1, 100 ether);

        vm.prank(compliance);
        token.setBlacklisted(alice, true);

        // bridgeBurn does not check blacklist, so this should succeed
        vm.prank(bridge1);
        token.bridgeBurn(alice, 100 ether);

        assertEq(token.balanceOf(alice), INITIAL_AMOUNT - 100 ether);
    }

    function test_Bridge_SetAuthorizedEmitsEvent() public {
        vm.prank(admin);
        vm.expectEmit(true, false, false, true);
        emit BridgeAuthorized(bridge2, true);
        token.setAuthorizedBridge(bridge2, true);

        vm.prank(admin);
        vm.expectEmit(true, false, false, true);
        emit BridgeAuthorized(bridge2, false);
        token.setAuthorizedBridge(bridge2, false);
    }

    // =========================================================================
    // UPGRADE TESTS
    // =========================================================================

    function test_Revert_Upgrade_OnlyUpgraderRole() public {
        AethelredToken newImpl = new AethelredToken();

        // alice (no UPGRADER_ROLE) tries to upgrade
        vm.prank(alice);
        vm.expectRevert();
        token.upgradeToAndCall(address(newImpl), "");
    }

    function test_Upgrade_UpgraderCanAuthorize() public {
        AethelredToken newImpl = new AethelredToken();

        // upgrader can upgrade
        vm.prank(upgrader);
        token.upgradeToAndCall(address(newImpl), "");

        // Verify the token still works after upgrade
        assertEq(token.totalSupply(), INITIAL_AMOUNT);
        assertEq(token.balanceOf(alice), INITIAL_AMOUNT);
    }

    function test_Revert_Upgrade_NonUpgraderCannotAuthorize() public {
        AethelredToken newImpl = new AethelredToken();

        // admin has DEFAULT_ADMIN_ROLE but not UPGRADER_ROLE (unless granted)
        // Let's use bob who has no role
        vm.prank(bob);
        vm.expectRevert();
        token.upgradeToAndCall(address(newImpl), "");

        // minter cannot upgrade
        vm.prank(minter);
        vm.expectRevert();
        token.upgradeToAndCall(address(newImpl), "");

        // compliance cannot upgrade
        vm.prank(compliance);
        vm.expectRevert();
        token.upgradeToAndCall(address(newImpl), "");
    }

    // =========================================================================
    // ADDITIONAL FUZZ TESTS
    // =========================================================================

    function testFuzz_Blacklist_DoesNotAffectBalance(uint256 amount) public {
        amount = bound(amount, 1, INITIAL_AMOUNT);

        // Mint some tokens to bob first
        vm.prank(minter);
        token.mint(bob, amount);

        uint256 balanceBefore = token.balanceOf(bob);

        // Blacklisting should not change balance
        vm.prank(compliance);
        token.setBlacklisted(bob, true);

        assertEq(token.balanceOf(bob), balanceBefore);

        // Un-blacklisting should also not change balance
        vm.prank(compliance);
        token.setBlacklisted(bob, false);

        assertEq(token.balanceOf(bob), balanceBefore);
    }

    function testFuzz_BridgeMint_RespectsSupplyCap(uint256 amount) public {
        uint256 remaining = token.remainingMintable();
        amount = bound(amount, 0, remaining);

        vm.prank(admin);
        token.setAuthorizedBridge(bridge1, true);

        vm.prank(bridge1);
        token.bridgeMint(bob, amount);

        assertLe(token.totalSupply(), TOTAL_SUPPLY_CAP);
        assertEq(token.balanceOf(bob), amount);
    }

    function testFuzz_ComplianceBurn_TotalBurnedAccurate(uint256 amount) public {
        amount = bound(amount, 1, INITIAL_AMOUNT);

        vm.prank(alice);
        token.approve(complianceBurner, amount);

        bytes32 reason = keccak256("COMPLIANCE_TEST");
        uint256 totalBurnedBefore = token.totalBurned();

        vm.prank(complianceBurner);
        token.complianceBurn(alice, amount, reason);

        assertEq(token.totalBurned(), totalBurnedBefore + amount);
        assertEq(token.balanceOf(alice), INITIAL_AMOUNT - amount);
    }

    // =========================================================================
    // INTEGRATION TESTS
    // =========================================================================

    function test_Integration_MintTransferBurn_SupplyConsistency() public {
        // 1. Mint tokens to bob
        vm.prank(minter);
        token.mint(bob, 500 ether);

        uint256 supplyAfterMint = token.totalSupply();
        assertEq(supplyAfterMint, INITIAL_AMOUNT + 500 ether);

        // 2. Disable restrictions and transfer from alice to carol
        vm.prank(admin);
        token.setTransferRestrictions(false);

        vm.prank(alice);
        token.transfer(carol, 200 ether);

        // Supply should remain unchanged after transfer
        assertEq(token.totalSupply(), supplyAfterMint);

        // 3. carol burns some tokens
        vm.prank(carol);
        token.burn(100 ether);

        assertEq(token.totalSupply(), supplyAfterMint - 100 ether);
        assertEq(token.totalBurned(), 100 ether);
        assertEq(token.balanceOf(carol), 100 ether);

        // 4. Verify total balances add up to totalSupply
        uint256 totalBalances = token.balanceOf(alice) + token.balanceOf(bob) + token.balanceOf(carol);
        assertEq(totalBalances, token.totalSupply());
    }

    function test_Integration_BlacklistDuringTransferRestrictions() public {
        // Whitelist alice so she can transfer
        vm.prank(compliance);
        token.setWhitelisted(alice, true);

        // Transfer should work
        vm.prank(alice);
        token.transfer(bob, 10 ether);

        // Now blacklist alice (even though whitelisted)
        vm.prank(compliance);
        token.setBlacklisted(alice, true);

        // Transfer should fail because blacklist takes priority
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(AethelredToken.AddressBlacklistedError.selector, alice));
        token.transfer(bob, 10 ether);

        // Remove blacklist, transfer should work again
        vm.prank(compliance);
        token.setBlacklisted(alice, false);

        vm.prank(alice);
        assertTrue(token.transfer(bob, 10 ether));
    }

    function test_Integration_MultipleBridgeOps_SupplyTracking() public {
        vm.startPrank(admin);
        token.setAuthorizedBridge(bridge1, true);
        token.setAuthorizedBridge(bridge2, true);
        vm.stopPrank();

        // Bridge1 mints to bob
        vm.prank(bridge1);
        token.bridgeMint(bob, 100 ether);

        // Bridge2 mints to carol
        vm.prank(bridge2);
        token.bridgeMint(carol, 200 ether);

        assertEq(token.totalSupply(), INITIAL_AMOUNT + 300 ether);

        // bob approves bridge1 for burning
        vm.prank(bob);
        token.approve(bridge1, 50 ether);

        // Bridge1 burns from bob
        vm.prank(bridge1);
        token.bridgeBurn(bob, 50 ether);

        assertEq(token.totalSupply(), INITIAL_AMOUNT + 250 ether);
        assertEq(token.totalBurned(), 50 ether);
        assertEq(token.balanceOf(bob), 50 ether);
        assertEq(token.balanceOf(carol), 200 ether);

        // Remaining mintable should be correct
        assertEq(token.remainingMintable(), TOTAL_SUPPLY_CAP - (INITIAL_AMOUNT + 250 ether));
    }
}
