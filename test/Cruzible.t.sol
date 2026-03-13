// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../contracts/vault/Cruzible.sol";
import "../contracts/vault/StAETHEL.sol";
import "../contracts/vault/VaultTEEVerifier.sol";
import "../contracts/vault/PlatformVerifiers.sol";
import "../contracts/vault/ICruzible.sol";

/**
 * @title MockAETHEL
 * @notice Minimal ERC20 mock for testing.
 */
contract MockAETHEL {
    string public name = "Aethelred";
    string public symbol = "AETHEL";
    uint8 public decimals = 18;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "Insufficient balance");
        require(allowance[from][msg.sender] >= amount, "Insufficient allowance");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }
}

/**
 * @title CruzibleTest
 * @notice Comprehensive test suite for Cruzible liquid staking protocol.
 *
 * Test Categories:
 * 1. Initialization & Setup
 * 2. Staking Operations
 * 3. Unstaking & Withdrawal
 * 4. Validator Management (TEE-verified)
 * 5. Reward Distribution (TEE-verified)
 * 6. MEV Revenue Redistribution
 * 7. Exchange Rate Mechanics
 * 8. TEE Attestation Verification
 * 9. Access Control & Permissions
 * 10. Edge Cases & Security
 * 11. Rate Limiting
 * 12. Batch Operations
 */
contract CruzibleTest is Test {
    // =========================================================================
    // STATE
    // =========================================================================

    Cruzible public vaultImpl;
    Cruzible public vault;
    StAETHEL public stAethelImpl;
    StAETHEL public stAethel;
    VaultTEEVerifier public verifierImpl;
    VaultTEEVerifier public verifier;
    MockAETHEL public aethel;
    SgxVerifier public sgxVerifier;

    address public admin = address(0xAD);
    address public oracle = address(0x0AC1E);
    address public guardian = address(0x6AAD);
    address public treasury = address(0x72EA);
    address public alice = address(0xA11CE);
    address public bob = address(0xB0B);
    address public charlie = address(0xC4A);

    // TEE operator key pair (for signing attestations — secp256k1)
    uint256 internal operatorPrivKey = 0xA11CE;
    address internal operatorAddr;

    // P-256 platform key pair for TEE evidence signing
    // Private key = 1 => public key = generator point G
    uint256 internal constant P256_PRIV_KEY = 1;
    uint256 internal constant P256_PUB_X = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296;
    uint256 internal constant P256_PUB_Y = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5;

    // Attestation constants
    bytes32 internal constant ENCLAVE_HASH = keccak256("cruzible-enclave-v1");
    bytes32 internal constant SIGNER_HASH = keccak256("cruzible-signer-v1");

    // Selection policy hash — must be set on-chain before updateValidatorSet.
    // In production, this is SHA-256(SelectionConfig fields). In tests we use a
    // deterministic placeholder; the contract only checks equality.
    bytes32 internal constant TEST_POLICY_HASH = keccak256("test-selection-policy-v1");

    // Eligible-universe hash — placeholder for tests.  In production, this is
    // SHA-256 of sorted eligible validator addresses (null-byte separated),
    // computed by the L1 keeper's computeEligibleUniverseHash().
    bytes32 internal constant TEST_UNIVERSE_HASH = keccak256("test-eligible-universe-v1");

    // Stake snapshot hash — placeholder for tests.  In production, this is
    // domain-separated SHA-256 of sorted staker records, computed by the L1
    // keeper's computeStakeSnapshotHash().
    bytes32 internal constant TEST_SNAPSHOT_HASH = keccak256("test-stake-snapshot-v1");

    // Vendor root P-256 key pair (private key = 2)
    // In production these are Intel/AWS/AMD hardware root keys
    uint256 internal constant VENDOR_ROOT_PRIV = 2;
    uint256 internal constant VENDOR_ROOT_X = 0x7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978;
    uint256 internal constant VENDOR_ROOT_Y = 0x07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1;

    // =========================================================================
    // EVENTS
    // =========================================================================

    event Staked(address indexed user, uint256 aethelAmount, uint256 sharesIssued, uint256 referralCode);
    event UnstakeRequested(address indexed user, uint256 shares, uint256 aethelAmount, uint256 indexed withdrawalId, uint256 completionTime);
    event Withdrawn(address indexed user, uint256 indexed withdrawalId, uint256 aethelAmount);
    event RewardsDistributed(uint256 indexed epoch, uint256 totalRewards, uint256 protocolFee, bytes32 rewardsMerkleRoot, bytes32 teeAttestationHash);
    event ValidatorSetUpdated(uint256 indexed epoch, uint256 validatorCount, bytes32 selectionProofHash, bytes32 eligibleUniverseHash);

    // =========================================================================
    // SETUP
    // =========================================================================

    function setUp() public {
        operatorAddr = vm.addr(operatorPrivKey);

        // Deploy mock AETHEL
        aethel = new MockAETHEL();

        // Deploy VaultTEEVerifier (implementation + proxy)
        verifierImpl = new VaultTEEVerifier();
        bytes memory verifierInit = abi.encodeCall(VaultTEEVerifier.initialize, (admin));
        ERC1967Proxy verifierProxy = new ERC1967Proxy(address(verifierImpl), verifierInit);
        verifier = VaultTEEVerifier(address(verifierProxy));

        // Deploy StAETHEL (implementation, proxy after vault)
        stAethelImpl = new StAETHEL();

        // Deploy Cruzible implementation
        vaultImpl = new Cruzible();

        // Deploy StAETHEL proxy (needs vault address, so deploy vault first as predicted)
        // We'll use create2-style ordering: deploy vault proxy, then stAethel proxy with vault addr
        // Actually, let's deploy vault proxy with a temporary stAethel, then update

        // Step 1: Deploy vault proxy
        bytes memory vaultInit = abi.encodeCall(
            Cruzible.initialize,
            (admin, address(aethel), address(0xDEAD), address(verifier), treasury)
        );
        // We need the vault address to initialize stAETHEL, and stAETHEL address to init vault.
        // Solution: pre-compute addresses or use two-step setup.

        // Pre-compute vault proxy address
        address predictedVault = _predictProxyAddress(address(vaultImpl), vaultInit);

        // Deploy stAETHEL proxy with predicted vault address
        bytes memory stAethelInit = abi.encodeCall(StAETHEL.initialize, (admin, predictedVault));
        ERC1967Proxy stAethelProxy = new ERC1967Proxy(address(stAethelImpl), stAethelInit);
        stAethel = StAETHEL(address(stAethelProxy));

        // Now deploy vault proxy with correct stAETHEL address
        vaultInit = abi.encodeCall(
            Cruzible.initialize,
            (admin, address(aethel), address(stAethel), address(verifier), treasury)
        );
        ERC1967Proxy vaultProxy = new ERC1967Proxy(address(vaultImpl), vaultInit);
        vault = Cruzible(address(vaultProxy));

        // Grant stAETHEL VAULT_ROLE to the actual vault (update from predicted)
        // Cache the role hash before vm.prank to avoid prank being consumed by the view call
        bytes32 vaultRole = stAethel.VAULT_ROLE();
        vm.prank(admin);
        stAethel.grantRole(vaultRole, address(vault));

        // Setup roles
        vm.startPrank(admin);
        vault.grantRole(vault.ORACLE_ROLE(), oracle);
        vault.grantRole(vault.GUARDIAN_ROLE(), guardian);

        // Set vendor root key for SGX platform FIRST (needed by registerEnclave)
        verifier.setVendorRootKey(0, VENDOR_ROOT_X, VENDOR_ROOT_Y);

        // Generate vendor key attestation: vendor root signs the enclave's platform key
        bytes32 keyAttestMsg = sha256(abi.encodePacked(P256_PUB_X, P256_PUB_Y, uint8(0)));
        (bytes32 vendorR, bytes32 vendorS) = vm.signP256(VENDOR_ROOT_PRIV, keyAttestMsg);

        // Register TEE enclave with its per-enclave platform key + vendor attestation
        verifier.registerEnclave(
            ENCLAVE_HASH, SIGNER_HASH, bytes32(0), 0, "Cruzible SGX Enclave v1",
            P256_PUB_X, P256_PUB_Y, uint256(vendorR), uint256(vendorS)
        );
        bytes32 enclaveId = keccak256(abi.encodePacked(ENCLAVE_HASH, uint8(0)));
        verifier.registerOperator(operatorAddr, enclaveId, "Test TEE Operator");

        // Deploy and register stateless SGX platform verifier (logic-only, no key storage)
        sgxVerifier = new SgxVerifier();
        verifier.setPlatformVerifier(0, address(sgxVerifier));

        // Set the approved selection policy hash for validator set updates.
        // Without this, updateValidatorSet reverts with SelectionPolicyMismatch.
        vault.setSelectionPolicyHash(TEST_POLICY_HASH);

        // Commit the eligible-universe hash (epoch-scoped, immutable).
        // Without this, updateValidatorSet reverts with EligibleUniverseMismatch.
        vault.commitUniverseHash(1, TEST_UNIVERSE_HASH);

        // Commit the stake snapshot hash for reward distribution (epoch-scoped).
        // Without this, distributeRewards reverts with StakeSnapshotMismatch.
        // The third arg anchors the commitment to the on-chain total share supply.
        vault.commitStakeSnapshot(1, TEST_SNAPSHOT_HASH, vault.getTotalShares());
        vm.stopPrank();

        // Fund test users
        aethel.mint(alice, 1_000_000 ether);
        aethel.mint(bob, 1_000_000 ether);
        aethel.mint(charlie, 1_000_000 ether);
        // Approve vault
        vm.prank(alice);
        aethel.approve(address(vault), type(uint256).max);
        vm.prank(bob);
        aethel.approve(address(vault), type(uint256).max);
        vm.prank(charlie);
        aethel.approve(address(vault), type(uint256).max);

        // Deposit keeper bond for admin (who has KEEPER_ROLE) so
        // commitDelegationSnapshot succeeds.
        _depositKeeperBond(admin);
    }

    /// @notice Deposit the minimum keeper bond for the given address.
    function _depositKeeperBond(address keeper) internal {
        uint256 bondAmount = vault.KEEPER_BOND_MINIMUM();
        aethel.mint(keeper, bondAmount);
        vm.startPrank(keeper);
        aethel.approve(address(vault), bondAmount);
        vault.depositKeeperBond(bondAmount);
        vm.stopPrank();
    }

    /// @notice Helper to pre-compute proxy address (simplified for tests).
    function _predictProxyAddress(address, bytes memory) internal pure returns (address) {
        // In tests, we use a two-step approach instead of prediction.
        // The stAETHEL VAULT_ROLE is granted after vault deployment.
        return address(0xDEAD);
    }

    // =========================================================================
    // 1. INITIALIZATION TESTS
    // =========================================================================

    function test_initialization() public view {
        assertEq(address(vault.aethelToken()), address(aethel));
        assertEq(address(vault.stAethelToken()), address(stAethel));
        assertEq(address(vault.teeVerifier()), address(verifier));
        assertEq(vault.treasury(), treasury);
        assertEq(vault.currentEpoch(), 1);
        assertEq(vault.totalPooledAethel(), 0);
        assertEq(vault.nextWithdrawalId(), 1);
    }

    function test_stAethelInitialization() public view {
        assertEq(stAethel.name(), "Staked Aethelred");
        assertEq(stAethel.symbol(), "stAETHEL");
        // stAETHEL was initialized with a predicted vault address; VAULT_ROLE
        // was granted to the actual vault after deployment, so operations work.
        assertTrue(stAethel.hasRole(stAethel.VAULT_ROLE(), address(vault)));
    }

    function test_verifierInitialization() public view {
        assertTrue(verifier.isEnclaveActive(ENCLAVE_HASH, 0));
        assertTrue(verifier.isOperatorActive(operatorAddr));
    }

    // =========================================================================
    // 2. STAKING TESTS
    // =========================================================================

    function test_stakeBasic() public {
        uint256 stakeAmount = 100 ether;

        vm.prank(alice);
        uint256 shares = vault.stake(stakeAmount);

        assertEq(shares, stakeAmount); // First stake is 1:1
        assertEq(vault.totalPooledAethel(), stakeAmount);
        assertEq(stAethel.sharesOf(alice), stakeAmount);
        assertEq(stAethel.balanceOf(alice), stakeAmount);
    }

    function test_stakeMultipleUsers() public {
        // Alice stakes 100
        vm.prank(alice);
        vault.stake(100 ether);

        // Bob stakes 200
        vm.prank(bob);
        uint256 bobShares = vault.stake(200 ether);

        assertEq(vault.totalPooledAethel(), 300 ether);
        assertEq(bobShares, 200 ether); // Same rate for second staker (no rewards yet)
    }

    function test_stakeWithReferral() public {
        vm.prank(alice);
        vm.expectEmit(true, false, false, true);
        emit Staked(alice, 100 ether, 100 ether, 42);
        vault.stakeWithReferral(100 ether, 42);
    }

    function test_stakeRevertsBelowMinimum() public {
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.BelowMinStake.selector, 10 ether, 32 ether)
        );
        vault.stake(10 ether);
    }

    function test_stakeRevertsZeroAmount() public {
        vm.prank(alice);
        vm.expectRevert(Cruzible.ZeroAmount.selector);
        vault.stake(0);
    }

    function test_stakeRevertsAboveMaxPerTx() public {
        uint256 tooMuch = 10_000_001 ether;
        aethel.mint(alice, tooMuch);
        vm.prank(alice);
        aethel.approve(address(vault), tooMuch);
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.ExceedsMaxStake.selector, tooMuch, 10_000_000 ether)
        );
        vault.stake(tooMuch);
    }

    // =========================================================================
    // 3. UNSTAKING & WITHDRAWAL TESTS
    // =========================================================================

    function test_unstakeBasic() public {
        // Stake first
        vm.prank(alice);
        vault.stake(100 ether);

        // Unstake
        vm.prank(alice);
        (uint256 withdrawalId, uint256 amount) = vault.unstake(50 ether);

        assertEq(withdrawalId, 1);
        assertEq(amount, 50 ether);
        assertEq(vault.totalPooledAethel(), 50 ether);
        assertEq(vault.totalPendingWithdrawals(), 50 ether);
    }

    function test_withdrawAfterUnbonding() public {
        vm.prank(alice);
        vault.stake(100 ether);

        vm.prank(alice);
        (uint256 withdrawalId,) = vault.unstake(50 ether);

        // Fast-forward past unbonding period
        vm.warp(block.timestamp + 14 days + 1);

        uint256 aliceBalanceBefore = aethel.balanceOf(alice);
        vm.prank(alice);
        uint256 withdrawn = vault.withdraw(withdrawalId);

        assertEq(withdrawn, 50 ether);
        assertEq(aethel.balanceOf(alice), aliceBalanceBefore + 50 ether);
        assertEq(vault.totalPendingWithdrawals(), 0);
    }

    function test_withdrawRevertsBeforeUnbonding() public {
        vm.prank(alice);
        vault.stake(100 ether);

        vm.prank(alice);
        (uint256 withdrawalId,) = vault.unstake(50 ether);

        // Try to withdraw before unbonding period
        vm.prank(alice);
        vm.expectRevert();
        vault.withdraw(withdrawalId);
    }

    function test_withdrawRevertsDoubleClaim() public {
        vm.prank(alice);
        vault.stake(100 ether);

        vm.prank(alice);
        (uint256 withdrawalId,) = vault.unstake(50 ether);

        vm.warp(block.timestamp + 14 days + 1);

        vm.prank(alice);
        vault.withdraw(withdrawalId);

        // Try to claim again
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.WithdrawalAlreadyClaimed.selector, withdrawalId)
        );
        vault.withdraw(withdrawalId);
    }

    function test_withdrawRevertsWrongOwner() public {
        vm.prank(alice);
        vault.stake(100 ether);

        vm.prank(alice);
        (uint256 withdrawalId,) = vault.unstake(50 ether);

        vm.warp(block.timestamp + 14 days + 1);

        // Bob tries to claim Alice's withdrawal
        vm.prank(bob);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.WithdrawalNotOwned.selector, withdrawalId)
        );
        vault.withdraw(withdrawalId);
    }

    function test_batchWithdraw() public {
        vm.startPrank(alice);
        vault.stake(300 ether);
        (uint256 id1,) = vault.unstake(100 ether);
        (uint256 id2,) = vault.unstake(100 ether);
        (uint256 id3,) = vault.unstake(100 ether);
        vm.stopPrank();

        vm.warp(block.timestamp + 14 days + 1);

        uint256[] memory ids = new uint256[](3);
        ids[0] = id1;
        ids[1] = id2;
        ids[2] = id3;

        uint256 balanceBefore = aethel.balanceOf(alice);
        vm.prank(alice);
        uint256 total = vault.batchWithdraw(ids);

        assertEq(total, 300 ether);
        assertEq(aethel.balanceOf(alice), balanceBefore + 300 ether);
    }

    // =========================================================================
    // 4. VALIDATOR MANAGEMENT TESTS
    // =========================================================================

    function test_updateValidatorSet() public {
        // Prepare validator data
        address[] memory addrs = new address[](4);
        addrs[0] = address(0x1);
        addrs[1] = address(0x2);
        addrs[2] = address(0x3);
        addrs[3] = address(0x4);

        uint256[] memory stakes = new uint256[](4);
        stakes[0] = 1000 ether;
        stakes[1] = 2000 ether;
        stakes[2] = 1500 ether;
        stakes[3] = 3000 ether;

        uint256[] memory perfScores = new uint256[](4);
        perfScores[0] = 9500;
        perfScores[1] = 8800;
        perfScores[2] = 9200;
        perfScores[3] = 9700;

        uint256[] memory decentScores = new uint256[](4);
        decentScores[0] = 8000;
        decentScores[1] = 9000;
        decentScores[2] = 7500;
        decentScores[3] = 8500;

        uint256[] memory repScores = new uint256[](4);
        repScores[0] = 10000;
        repScores[1] = 9500;
        repScores[2] = 9800;
        repScores[3] = 10000;

        uint256[] memory compositeScores = new uint256[](4);
        compositeScores[0] = 9100;
        compositeScores[1] = 9000;
        compositeScores[2] = 8700;
        compositeScores[3] = 9300;

        bytes32[] memory teeKeys = new bytes32[](4);
        teeKeys[0] = keccak256("key1");
        teeKeys[1] = keccak256("key2");
        teeKeys[2] = keccak256("key3");
        teeKeys[3] = keccak256("key4");

        uint256[] memory commissions = new uint256[](4);
        commissions[0] = 500;
        commissions[1] = 700;
        commissions[2] = 600;
        commissions[3] = 800;

        bytes memory validatorData = abi.encode(
            addrs, stakes, perfScores, decentScores,
            repScores, compositeScores, teeKeys, commissions
        );

        // Attestation payload is canonicalHash || policyHash || universeHash (96 bytes).
        // The contract verifies both the validator set hash and the policy hash.
        bytes32 vsHash = _computeTestValidatorSetHash(
            1, addrs, stakes, perfScores, decentScores,
            repScores, compositeScores, teeKeys, commissions
        );
        bytes memory attestation = _createAttestation(abi.encodePacked(vsHash, TEST_POLICY_HASH, TEST_UNIVERSE_HASH));

        vm.prank(oracle);
        vault.updateValidatorSet(attestation, validatorData, 1);

        assertEq(vault.getActiveValidatorCount(), 4);

        Cruzible.ValidatorInfo memory v1 = vault.getValidator(address(0x1));
        assertTrue(v1.isActive);
        assertEq(v1.performanceScore, 9500);
        assertEq(v1.delegatedStake, 1000 ether);
    }

    /// @notice A validator-set attestation generated for epoch N is rejected at epoch N+1.
    ///         This verifies temporal binding: the TEE attestation payload includes the
    ///         epoch, so stale validator sets cannot be replayed after epoch advancement.
    function test_validatorAttestation_rejectsStaleEpoch() public {
        // ── Setup: stake so we can call distributeRewards to advance epoch ─
        vm.prank(alice);
        vault.stake(1000 ether);

        // ── Build minimal validator data (4 validators) ─────────────────
        address[] memory addrs = new address[](4);
        addrs[0] = address(0x1);
        addrs[1] = address(0x2);
        addrs[2] = address(0x3);
        addrs[3] = address(0x4);

        uint256[] memory scores = new uint256[](4);
        for (uint256 i = 0; i < 4; i++) scores[i] = 9000;

        bytes32[] memory keys = new bytes32[](4);
        for (uint256 i = 0; i < 4; i++) keys[i] = keccak256(abi.encodePacked("key", i));

        uint256[] memory commissions = new uint256[](4);
        for (uint256 i = 0; i < 4; i++) commissions[i] = 500;

        bytes memory validatorData = abi.encode(
            addrs, scores, scores, scores, scores, scores, keys, commissions
        );

        // ── Create attestation bound to epoch 1 (canonicalHash || policyHash || universeHash) ─
        bytes32 vsHash1 = _computeTestValidatorSetHash(
            1, addrs, scores, scores, scores, scores, scores, keys, commissions
        );
        bytes memory staleAttestation = _createAttestation(abi.encodePacked(vsHash1, TEST_POLICY_HASH, TEST_UNIVERSE_HASH));

        // ── Advance epoch via distributeRewards ───────────────────────────
        uint256 totalRewards = 100 ether;
        uint256 protocolFee = 5 ether;
        bytes32 merkleRoot = keccak256("test-merkle-stale");
        _fundOracleForIngestion(totalRewards);

        bytes memory rewardPayload = abi.encode(uint256(1), totalRewards, merkleRoot, protocolFee, TEST_SNAPSHOT_HASH, bytes32(0), bytes32(0), bytes32(0));
        bytes memory rewardAttestation = _createAttestation(rewardPayload);

        vm.prank(oracle);
        vault.distributeRewards(rewardAttestation, 1, totalRewards, merkleRoot, protocolFee);
        assertEq(vault.currentEpoch(), 2); // epoch advanced

        // ── Attempt to reuse epoch-1 attestation at epoch 2 → must revert ─
        // The canonical hash includes epoch, so the epoch-1 hash won't match
        // the epoch-2 hash computed by the contract. Attestation rejected.
        vm.prank(oracle);
        vm.expectRevert(Cruzible.InvalidAttestation.selector);
        vault.updateValidatorSet(staleAttestation, validatorData, 2);
    }

    // =========================================================================
    // 5. REWARD DISTRIBUTION TESTS
    // =========================================================================

    function test_distributeRewards() public {
        // Alice stakes
        vm.prank(alice);
        vault.stake(1000 ether);

        uint256 totalRewards = 100 ether;
        uint256 protocolFee = 5 ether; // 5%
        bytes32 merkleRoot = keccak256("rewards-merkle-root");

        // Fund oracle so distributeRewards can pull tokens
        _fundOracleForIngestion(totalRewards);

        // Canonical reward payload — this is the exact format the Rust TEE worker
        // produces via compute_canonical_reward_payload() and that
        // Cruzible.distributeRewards() verifies on-chain.
        // See: crates/vault/src/server.rs::compute_canonical_reward_payload()
        bytes memory rewardPayload = abi.encode(uint256(1), totalRewards, merkleRoot, protocolFee, TEST_SNAPSHOT_HASH, bytes32(0), bytes32(0), bytes32(0));
        bytes memory attestation = _createAttestation(rewardPayload);

        vm.prank(oracle);
        vault.distributeRewards(attestation, 1, totalRewards, merkleRoot, protocolFee);

        // Rewards flow via Merkle claims, NOT via exchange rate auto-compound
        assertEq(vault.totalPooledAethel(), 1000 ether);
        assertEq(vault.currentEpoch(), 2);

        // Net rewards (100 - 5 = 95) reserved for claims
        assertEq(vault.totalReservedForClaims(), 95 ether);

        // Exchange rate stays 1:1 (no auto-compound from distributeRewards)
        assertEq(vault.getExchangeRate(), 1e18);
    }

    /// @notice distributeRewards rejects a protocol fee that exceeds the
    ///         deterministic formula by even 1 wei.  The Rust TEE worker and
    ///         Cruzible.sol use the same integer expression
    ///         (totalRewards * PROTOCOL_FEE_BPS / BPS_DENOMINATOR), so exact
    ///         equality is required — no tolerance window.
    function test_distributeRewards_rejectsOverchargedFee() public {
        vm.prank(alice);
        vault.stake(1000 ether);

        uint256 totalRewards = 100 ether;
        bytes32 merkleRoot = keccak256("overcharge-merkle");

        uint256 expectedFee = (totalRewards * 500) / 10000; // 5 ether
        uint256 overchargedFee = expectedFee + 1; // 5 ether + 1 wei
        _fundOracleForIngestion(totalRewards);

        bytes memory payload = abi.encode(uint256(1), totalRewards, merkleRoot, overchargedFee, TEST_SNAPSHOT_HASH, bytes32(0), bytes32(0), bytes32(0));
        bytes memory attestation = _createAttestation(payload);

        vm.prank(oracle);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.ProtocolFeeMismatch.selector, overchargedFee, expectedFee)
        );
        vault.distributeRewards(attestation, 1, totalRewards, merkleRoot, overchargedFee);
    }

    /// @notice distributeRewards also rejects an undercharged protocol fee.
    ///         Both directions of mismatch are caught by exact equality.
    function test_distributeRewards_rejectsUnderchargedFee() public {
        vm.prank(alice);
        vault.stake(1000 ether);

        uint256 totalRewards = 100 ether;
        bytes32 merkleRoot = keccak256("undercharge-merkle");

        uint256 expectedFee = (totalRewards * 500) / 10000; // 5 ether
        uint256 underchargedFee = expectedFee - 1; // 5 ether - 1 wei
        _fundOracleForIngestion(totalRewards);

        bytes memory payload = abi.encode(uint256(1), totalRewards, merkleRoot, underchargedFee, TEST_SNAPSHOT_HASH, bytes32(0), bytes32(0), bytes32(0));
        bytes memory attestation = _createAttestation(payload);

        vm.prank(oracle);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.ProtocolFeeMismatch.selector, underchargedFee, expectedFee)
        );
        vault.distributeRewards(attestation, 1, totalRewards, merkleRoot, underchargedFee);
    }

    // =========================================================================
    // 6. MEV REVENUE TESTS
    // =========================================================================

    function test_submitMEVRevenue() public {
        vm.prank(alice);
        vault.stake(1000 ether);

        uint256 mevAmount = 10 ether;
        _fundOracleForIngestion(mevAmount); // Oracle supplies MEV tokens

        // Payload bound to attestation: abi.encode(epoch, mevAmount)
        bytes memory mevPayload = abi.encode(uint256(1), mevAmount);
        bytes memory attestation = _createAttestation(mevPayload);

        vm.prank(oracle);
        vault.submitMEVRevenue(attestation, 1, mevAmount);

        // 90% to stakers (9 AETHEL), 10% to protocol (1 AETHEL)
        assertEq(vault.totalPooledAethel(), 1009 ether);
        assertEq(vault.totalMEVRevenue(), 10 ether);
    }

    /// @notice MEV accumulated via submitMEVRevenue() is preserved when
    ///         distributeRewards() finalizes the epoch snapshot.
    ///         Regression test: the finalize block previously hard-coded
    ///         mevRedistributed to 0, wiping any pre-finalization MEV.
    function test_mevPreservedAfterEpochFinalization() public {
        vm.prank(alice);
        vault.stake(1000 ether);

        // Submit MEV for epoch 1 BEFORE reward finalization.
        uint256 mevAmount = 5 ether;
        _fundOracleForIngestion(mevAmount);
        bytes memory mevPayload = abi.encode(uint256(1), mevAmount);
        bytes memory mevAtt = _createAttestation(mevPayload);
        vm.prank(oracle);
        vault.submitMEVRevenue(mevAtt, 1, mevAmount);

        // Verify MEV is recorded in the (unfinalized) epoch snapshot.
        Cruzible.EpochSnapshot memory snapBefore = vault.getEpochSnapshot(1);
        assertEq(snapBefore.mevRedistributed, mevAmount);
        assertFalse(snapBefore.finalized);

        // Finalize epoch 1 via distributeRewards.
        _distributeRewardsForCurrentEpoch();
        assertEq(vault.currentEpoch(), 2);

        // The finalized snapshot must still contain the MEV amount.
        Cruzible.EpochSnapshot memory snapAfter = vault.getEpochSnapshot(1);
        assertTrue(snapAfter.finalized);
        assertEq(snapAfter.mevRedistributed, mevAmount, "mevRedistributed wiped by finalization");
    }

    // =========================================================================
    // 7. EXCHANGE RATE TESTS
    // =========================================================================

    function test_exchangeRateAfterRewards() public {
        // Alice stakes 1000 AETHEL
        vm.prank(alice);
        vault.stake(1000 ether);

        // Check initial rate (1:1)
        assertEq(vault.getExchangeRate(), 1e18);

        // Distribute rewards — NO auto-compound, rate stays 1:1
        _fundOracleForIngestion(100 ether);
        bytes memory rewardPayload = abi.encode(uint256(1), uint256(100 ether), bytes32(0), uint256(5 ether), TEST_SNAPSHOT_HASH, bytes32(0), bytes32(0), bytes32(0));
        bytes memory attestation = _createAttestation(rewardPayload);
        vm.prank(oracle);
        vault.distributeRewards(attestation, 1, 100 ether, bytes32(0), 5 ether);

        // Rate stays 1:1 (rewards distributed via Merkle claims, not auto-compound)
        assertEq(vault.getExchangeRate(), 1e18);

        // MEV auto-compounds and DOES change the exchange rate
        uint256 mevAmount = 100 ether;
        _fundOracleForIngestion(mevAmount);
        bytes memory mevPayload = abi.encode(uint256(2), mevAmount);
        bytes memory mevAtt = _createAttestation(mevPayload);
        vm.prank(oracle);
        vault.submitMEVRevenue(mevAtt, 2, mevAmount);

        // Rate should now be > 1:1 (90% of 100 MEV auto-compounded → 1090/1000 = 1.09)
        uint256 rate = vault.getExchangeRate();
        assertGt(rate, 1e18);

        // Bob stakes at the new rate — gets fewer shares
        vm.prank(bob);
        uint256 bobShares = vault.stake(1000 ether);
        assertLt(bobShares, 1000 ether);
    }

    function test_getSharesForAethel() public {
        vm.prank(alice);
        vault.stake(1000 ether);

        // Initially 1:1
        assertEq(vault.getSharesForAethel(100 ether), 100 ether);
        assertEq(vault.getAethelForShares(100 ether), 100 ether);
    }

    // =========================================================================
    // 8. ACCESS CONTROL TESTS
    // =========================================================================

    function test_onlyOracleCanUpdateValidators() public {
        vm.prank(alice);
        vm.expectRevert();
        vault.updateValidatorSet("", "", 1);
    }

    /// @notice Duplicate validator addresses in the attested set must revert.
    ///         The same address occupying multiple slots would reduce the
    ///         effective validator set below decentralization guarantees.
    function test_updateValidatorSet_rejectsDuplicateAddresses() public {
        // Build a 4-validator set where addrs[2] == addrs[0] (duplicate)
        address[] memory addrs = new address[](4);
        addrs[0] = address(0x1);
        addrs[1] = address(0x2);
        addrs[2] = address(0x1); // duplicate
        addrs[3] = address(0x4);

        uint256[] memory scores = new uint256[](4);
        for (uint256 i = 0; i < 4; i++) scores[i] = 9000;

        bytes32[] memory keys = new bytes32[](4);
        for (uint256 i = 0; i < 4; i++) keys[i] = keccak256(abi.encodePacked("key", i));

        uint256[] memory commissions = new uint256[](4);
        for (uint256 i = 0; i < 4; i++) commissions[i] = 500;

        bytes memory validatorData = abi.encode(
            addrs, scores, scores, scores, scores, scores, keys, commissions
        );

        bytes32 vsHash = _computeTestValidatorSetHash(
            1, addrs, scores, scores, scores, scores, scores, keys, commissions
        );
        bytes memory attestation = _createAttestation(abi.encodePacked(vsHash, TEST_POLICY_HASH, TEST_UNIVERSE_HASH));

        vm.prank(oracle);
        vm.expectRevert(abi.encodeWithSelector(Cruzible.DuplicateValidator.selector, address(0x1)));
        vault.updateValidatorSet(attestation, validatorData, 1);
    }

    function test_onlyOracleCanDistributeRewards() public {
        vm.prank(alice);
        vm.expectRevert();
        vault.distributeRewards("", 1, 100 ether, bytes32(0), 5 ether);
    }

    function test_guardianCanSlashValidator() public {
        // First set up a validator
        _setupValidators();

        vm.prank(guardian);
        vault.slashValidator(address(0x1), "Downtime");

        Cruzible.ValidatorInfo memory v = vault.getValidator(address(0x1));
        assertFalse(v.isActive);
        assertEq(v.slashCount, 1);
    }

    function test_onlyAdminCanSetTreasury() public {
        vm.prank(alice);
        vm.expectRevert();
        vault.setTreasury(address(0x123));
    }

    function test_pauseUnpause() public {
        vm.prank(admin);
        vault.pause();

        vm.prank(alice);
        vm.expectRevert();
        vault.stake(100 ether);

        vm.prank(admin);
        vault.unpause();

        vm.prank(alice);
        vault.stake(100 ether);
    }

    // =========================================================================
    // 9. EDGE CASES & SECURITY
    // =========================================================================

    function test_unstakeAllShares() public {
        vm.prank(alice);
        vault.stake(100 ether);

        uint256 allShares = stAethel.sharesOf(alice);

        vm.prank(alice);
        (uint256 wId, uint256 amount) = vault.unstake(allShares);

        assertEq(amount, 100 ether);
        assertEq(stAethel.sharesOf(alice), 0);
        assertEq(vault.totalPooledAethel(), 0);

        vm.warp(block.timestamp + 14 days + 1);
        vm.prank(alice);
        vault.withdraw(wId);
    }

    function test_cannotUnstakeMoreThanBalance() public {
        vm.prank(alice);
        vault.stake(100 ether);

        vm.prank(alice);
        vm.expectRevert();
        vault.unstake(200 ether);
    }

    function test_multipleStakersExchangeRate() public {
        // Alice stakes 1000
        vm.prank(alice);
        vault.stake(1000 ether);

        // MEV auto-compounds → changes exchange rate
        uint256 mevAmount = 100 ether;
        _fundOracleForIngestion(mevAmount);
        bytes memory mevPayload = abi.encode(uint256(1), mevAmount);
        bytes memory att = _createAttestation(mevPayload);
        vm.prank(oracle);
        vault.submitMEVRevenue(att, 1, mevAmount);

        // 90% of 100 MEV → 90 auto-compounded. totalPooled = 1090, totalShares = 1000
        uint256 totalPooled = vault.totalPooledAethel();
        assertEq(totalPooled, 1090 ether);

        // Bob stakes 1090 AETHEL → should get 1000 shares at current rate
        vm.prank(bob);
        uint256 bobShares = vault.stake(1090 ether);

        // Bob's shares should be approximately 1000 ether (1090 / 1.09)
        assertApproxEqAbs(bobShares, 1000 ether, 1);

        // Alice's stAETHEL balance reflects MEV auto-compound
        uint256 aliceBalance = stAethel.balanceOf(alice);
        assertEq(aliceBalance, 1090 ether); // 1000 shares * 1.09 rate
    }

    function test_viewFunctions() public {
        vm.prank(alice);
        vault.stake(100 ether);

        assertEq(vault.getTotalPooledAethel(), 100 ether);
        assertEq(vault.getTotalShares(), 100 ether);
        assertEq(vault.getCurrentEpoch(), 1);
        assertEq(vault.getActiveValidatorCount(), 0);
        assertGt(vault.getAvailableBalance(), 0);
    }

    function test_getUserWithdrawals() public {
        vm.prank(alice);
        vault.stake(300 ether);

        vm.startPrank(alice);
        vault.unstake(100 ether);
        vault.unstake(100 ether);
        vm.stopPrank();

        uint256[] memory withdrawals = vault.getUserWithdrawals(alice);
        assertEq(withdrawals.length, 2);
    }

    function test_isWithdrawalClaimable() public {
        vm.prank(alice);
        vault.stake(100 ether);

        vm.prank(alice);
        (uint256 wId,) = vault.unstake(50 ether);

        assertFalse(vault.isWithdrawalClaimable(wId));

        vm.warp(block.timestamp + 14 days + 1);

        assertTrue(vault.isWithdrawalClaimable(wId));
    }

    function test_effectiveAPY() public {
        vm.prank(alice);
        vault.stake(1000 ether);

        // Before any rewards, APY should be 0
        assertEq(vault.getEffectiveAPY(), 0);

        // Distribute rewards to advance epoch and create finalized snapshot
        uint256 totalRewards = 10 ether;
        uint256 protocolFee = 0.5 ether;
        _fundOracleForIngestion(totalRewards);
        bytes memory payload = abi.encode(uint256(1), totalRewards, bytes32(0), protocolFee, TEST_SNAPSHOT_HASH, bytes32(0), bytes32(0), bytes32(0));
        bytes memory att = _createAttestation(payload);
        vm.prank(oracle);
        vault.distributeRewards(att, 1, totalRewards, bytes32(0), protocolFee);

        // APY should be > 0 (epoch snapshot has rewardsDistributed > 0)
        uint256 apy = vault.getEffectiveAPY();
        assertGt(apy, 0);
    }

    /// @notice getEffectiveAPY uses net staker yield (excluding protocol fees
    ///         and MEV protocol share) and includes both reward and MEV sources.
    function test_effectiveAPY_netStakerYield() public {
        vm.prank(alice);
        vault.stake(1000 ether);

        // Submit MEV for epoch 1.
        uint256 mevAmount = 20 ether;
        _fundOracleForIngestion(mevAmount);
        bytes memory mevPayload = abi.encode(uint256(1), mevAmount);
        bytes memory mevAtt = _createAttestation(mevPayload);
        vm.prank(oracle);
        vault.submitMEVRevenue(mevAtt, 1, mevAmount);

        // Distribute rewards to finalize epoch 1.
        uint256 totalRewards = 10 ether;
        uint256 protocolFee = 0.5 ether;
        _fundOracleForIngestion(totalRewards);
        bytes memory rewardPayload = abi.encode(uint256(1), totalRewards, bytes32(0), protocolFee, TEST_SNAPSHOT_HASH, bytes32(0), bytes32(0), bytes32(0));
        bytes memory rewardAtt = _createAttestation(rewardPayload);
        vm.prank(oracle);
        vault.distributeRewards(rewardAtt, 1, totalRewards, bytes32(0), protocolFee);

        uint256 apy = vault.getEffectiveAPY();

        // Compute expected net yield:
        //   netRewards = 10 - 0.5 = 9.5 ether   (staker claimable)
        //   netMEV     = 20 * 9000/10000 = 18 ether (staker auto-compounded)
        //   epochYield = 9.5 + 18 = 27.5 ether
        //   totalPooledAethel after MEV = 1000 + 18 = 1018 ether
        //   dailyRate  = 27.5e18 / 1018e18
        //   apy        = dailyRate * 365 * 10000 / 1e18
        uint256 netRewards = totalRewards - protocolFee;               // 9.5 ether
        uint256 netMEV = (mevAmount * 9000) / 10000;                   // 18 ether
        uint256 expectedYield = netRewards + netMEV;                   // 27.5 ether
        uint256 pooled = 1018 ether;                                   // 1000 + 18
        uint256 expectedRate = (expectedYield * 1e18) / pooled;
        uint256 expectedAPY = (expectedRate * 365 * 10000) / 1e18;

        assertEq(apy, expectedAPY, "APY should use net staker yield");

        // Verify APY is strictly less than what a gross calculation would give.
        uint256 grossYield = totalRewards + mevAmount;                 // 30 ether
        uint256 grossRate = (grossYield * 1e18) / pooled;
        uint256 grossAPY = (grossRate * 365 * 10000) / 1e18;
        assertLt(apy, grossAPY, "APY must not include protocol cuts");
    }

    // =========================================================================
    // 10. RATE LIMITING TESTS
    // =========================================================================

    function test_epochRateLimitNotExceeded() public {
        // Stake within the limit
        vm.prank(alice);
        vault.stake(100 ether);

        vm.prank(bob);
        vault.stake(200 ether);

        // Both should succeed (well under 500M limit)
        assertEq(vault.totalPooledAethel(), 300 ether);
    }

    // =========================================================================
    // 11. TEE VERIFIER TESTS
    // =========================================================================

    function test_verifierRegistration() public view {
        assertTrue(verifier.isEnclaveActive(ENCLAVE_HASH, 0));
        assertTrue(verifier.isOperatorActive(operatorAddr));
        assertEq(verifier.getRegisteredEnclaveCount(), 1);
        assertEq(verifier.getRegisteredOperatorCount(), 1);
    }

    function test_revokeEnclave() public {
        bytes32 enclaveId = keccak256(abi.encodePacked(ENCLAVE_HASH, uint8(0)));

        vm.prank(admin);
        verifier.revokeEnclave(enclaveId);

        assertFalse(verifier.isEnclaveActive(ENCLAVE_HASH, 0));
    }

    function test_revokeOperator() public {
        vm.prank(admin);
        verifier.revokeOperator(operatorAddr);

        assertFalse(verifier.isOperatorActive(operatorAddr));
    }

    function test_operatorCannotAttestForUnboundEnclave() public {
        // Register a second enclave with different measurements and its own platform key
        bytes32 enclaveHash2 = keccak256("cruzible-enclave-v2");
        bytes32 signerHash2 = keccak256("cruzible-signer-v2");

        // Create a second operator key pair
        uint256 operator2PrivKey = 0xBEEF;
        address operator2Addr = vm.addr(operator2PrivKey);

        vm.startPrank(admin);
        // Enclave v2 uses the same platform key for simplicity (vendor attestation still required)
        bytes32 keyAttestMsg2 = sha256(abi.encodePacked(P256_PUB_X, P256_PUB_Y, uint8(0)));
        (bytes32 vr2, bytes32 vs2) = vm.signP256(VENDOR_ROOT_PRIV, keyAttestMsg2);
        verifier.registerEnclave(
            enclaveHash2, signerHash2, bytes32(0), 0, "Cruzible SGX Enclave v2",
            P256_PUB_X, P256_PUB_Y, uint256(vr2), uint256(vs2)
        );
        bytes32 enclave2Id = keccak256(abi.encodePacked(enclaveHash2, uint8(0)));
        verifier.registerOperator(operator2Addr, enclave2Id, "Operator 2 - bound to enclave v2");
        vm.stopPrank();

        // Operator 2 signs an attestation that claims enclave v1's measurements
        // (attempting to impersonate enclave v1 while only authorized for enclave v2)
        bytes memory fakePayload = abi.encode(uint256(42));
        uint8 platform = 0;
        uint256 timestamp = block.timestamp;
        bytes32 nonce = keccak256(abi.encodePacked(timestamp, block.number, fakePayload));

        // Build an attestation using enclave v1 hashes but signed by operator 2
        // Tagged SHA-256 digest matching Go/Rust verifier format
        bytes32 payloadHash = sha256(fakePayload);
        bytes32 digest = sha256(abi.encodePacked(
            "CruzibleTEEAttestation",
            platform,
            uint64(timestamp),
            nonce,
            ENCLAVE_HASH,  // enclave v1 hash
            SIGNER_HASH,   // enclave v1 signer
            payloadHash
        ));

        // Generate mock raw hardware report hash
        bytes32 rawReportHash2 = sha256(abi.encodePacked("MOCK_HW_REPORT_V1", ENCLAVE_HASH, SIGNER_HASH, digest));

        // Compute binding hash: ties raw report to measurements
        bytes32 bindingHash2 = sha256(abi.encodePacked(rawReportHash2, ENCLAVE_HASH, SIGNER_HASH));

        // Sign report body with P-256 platform key (uses bindingHash)
        bytes32 reportHash = sha256(abi.encodePacked(ENCLAVE_HASH, SIGNER_HASH, digest, uint16(1), uint16(1), bindingHash2));
        (bytes32 p256r, bytes32 p256s) = vm.signP256(P256_PRIV_KEY, reportHash);

        bytes memory evidence = abi.encode(
            ENCLAVE_HASH,      // mrenclave = enclave v1
            SIGNER_HASH,       // mrsigner = enclave v1
            digest,            // reportData
            uint16(1),
            uint16(1),
            rawReportHash2,    // rawReportHash (verifier computes bindingHash)
            uint256(p256r),    // P-256 signature r
            uint256(p256s)     // P-256 signature s
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(operator2PrivKey, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        bytes memory attestation = abi.encode(
            platform, timestamp, nonce,
            ENCLAVE_HASH, SIGNER_HASH, fakePayload, evidence, sig
        );

        // Operator 2 is bound to enclave v2, but the attestation claims enclave v1
        // → the enclaveId derived from (ENCLAVE_HASH, 0) won't match operator2's binding
        vm.expectRevert(
            abi.encodeWithSelector(
                VaultTEEVerifier.OperatorNotAuthorizedForEnclave.selector,
                operator2Addr,
                keccak256(abi.encodePacked(ENCLAVE_HASH, uint8(0)))
            )
        );
        verifier.verifyAttestation(attestation);
    }

    // =========================================================================
    // 12. stAETHEL TOKEN TESTS
    // =========================================================================

    function test_stAethelTransfer() public {
        vm.prank(alice);
        vault.stake(100 ether);

        vm.prank(alice);
        stAethel.transfer(bob, 50 ether);

        assertEq(stAethel.balanceOf(alice), 50 ether);
        assertEq(stAethel.balanceOf(bob), 50 ether);
    }

    function test_stAethelBlacklist() public {
        vm.prank(alice);
        vault.stake(100 ether);

        vm.prank(admin);
        stAethel.setBlacklisted(bob, true);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(StAETHEL.AccountBlacklisted.selector, bob));
        stAethel.transfer(bob, 50 ether);
    }

    function test_stAethelPause() public {
        vm.prank(alice);
        vault.stake(100 ether);

        vm.prank(admin);
        stAethel.pause();

        vm.prank(alice);
        vm.expectRevert();
        stAethel.transfer(bob, 50 ether);
    }

    function test_stAethelExchangeRate() public view {
        // Before any stakes, rate is 1:1
        assertEq(stAethel.getExchangeRate(), 1e18);
    }

    // =========================================================================
    // HELPERS
    // =========================================================================

    /// @notice Fund the oracle with AETHEL and approve the vault so distributeRewards/submitMEVRevenue
    ///         can pull tokens via safeTransferFrom. This replaces the old direct-mint-to-vault pattern.
    function _fundOracleForIngestion(uint256 amount) internal {
        aethel.mint(oracle, amount);
        vm.prank(oracle);
        aethel.approve(address(vault), amount);
    }

    /// @notice Helper: stake, distribute rewards, and advance the current epoch.
    ///         Ensures there is a staker so totalPooled > 0, commits required
    ///         epoch-scoped hashes, then builds a minimal attestation and distributes.
    function _distributeRewardsForCurrentEpoch() internal {
        uint256 epoch = vault.currentEpoch();

        // Ensure at least one staker so the vault has non-zero pooled AETHEL.
        if (vault.getTotalPooledAethel() == 0) {
            vm.prank(alice);
            vault.stake(100 ether);
        }

        uint256 totalRewards = 10 ether;
        uint256 fee = (totalRewards * 500) / 10000;
        _fundOracleForIngestion(totalRewards);

        // Read the epoch's committed hashes so the reward attestation matches
        // the on-chain state exactly.
        Cruzible.EpochSnapshot memory snap = vault.getEpochSnapshot(epoch);
        bytes32 vsHash = snap.validatorSetHash;
        bytes32 regRoot = snap.stakerRegistryRoot;

        // Commit delegation registry root for this epoch if not already committed.
        // distributeRewards() verifies the attested value matches the committed one.
        // commitDelegationSnapshot requires the stakerRegistryRoot anchor (captured
        // at commitStakeSnapshot time) to cross-reference the staker universe.
        bytes32 delRoot;
        if (snap.delegationRegistryRoot == bytes32(0)) {
            delRoot = keccak256("test-delegation-root");
            bytes memory delAtt = _createDelegationAttestation(epoch, delRoot, snap.stakerRegistryRoot);
            vm.prank(admin);
            vault.commitDelegationSnapshot(delAtt, epoch, delRoot, snap.stakerRegistryRoot, 1);
        } else {
            delRoot = snap.delegationRegistryRoot;
        }

        // Fast-forward past the delegation challenge period so distributeRewards() accepts it.
        vm.warp(block.timestamp + vault.DELEGATION_CHALLENGE_PERIOD() + 1);

        bytes memory payload = abi.encode(epoch, totalRewards, bytes32(0), fee, TEST_SNAPSHOT_HASH, vsHash, regRoot, delRoot);
        bytes memory att = _createAttestation(payload);

        vm.prank(oracle);
        vault.distributeRewards(att, epoch, totalRewards, bytes32(0), fee);
    }

    /// @notice Compute canonical validator set hash (mirrors Cruzible._computeValidatorSetHash).
    function _computeTestValidatorSetHash(
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
        bytes memory outerPreimage = abi.encodePacked(
            "CruzibleValidatorSet-v1",
            uint64(epoch),
            uint32(addrs.length)
        );
        for (uint256 i = 0; i < addrs.length; i++) {
            bytes32 innerHash = sha256(abi.encodePacked(
                bytes32(uint256(uint160(addrs[i]))),
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

    function _createAttestation(bytes memory payload) internal view returns (bytes memory) {
        uint8 platformId = 0; // SGX
        uint256 timestamp = block.timestamp;
        bytes32 nonce = keccak256(abi.encodePacked(block.timestamp, block.number, payload));

        // Build tagged SHA-256 digest (matches Go native verifier & Rust TEE producer)
        bytes32 payloadHash = sha256(payload);
        bytes32 digest = sha256(abi.encodePacked(
            "CruzibleTEEAttestation",
            platformId,
            uint64(timestamp),
            nonce,
            ENCLAVE_HASH,
            SIGNER_HASH,
            payloadHash
        ));

        // Generate mock raw hardware report hash (per-attestation binding to fresh hardware report)
        // In production: SHA-256 of actual SGX DCAP quote / Nitro document / SEV report
        bytes32 rawReportHash = sha256(abi.encodePacked(
            "MOCK_HW_REPORT_V1",
            ENCLAVE_HASH,
            SIGNER_HASH,
            digest
        ));

        // Compute binding hash: ties the raw hardware report to these specific measurements.
        // Both Rust TEE and on-chain verifiers compute this independently.
        bytes32 bindingHash = sha256(abi.encodePacked(rawReportHash, ENCLAVE_HASH, SIGNER_HASH));

        // Build report body and sign with P-256 platform key (uses bindingHash for measurement binding)
        bytes32 reportHash = sha256(abi.encodePacked(ENCLAVE_HASH, SIGNER_HASH, digest, uint16(1), uint16(1), bindingHash));
        (bytes32 p256r, bytes32 p256s) = vm.signP256(P256_PRIV_KEY, reportHash);

        // Generate SGX platform evidence bound to this attestation
        // Evidence stores rawReportHash; verifier computes bindingHash independently
        bytes memory evidence = abi.encode(
            ENCLAVE_HASH,         // mrenclave (from hardware report)
            SIGNER_HASH,          // mrsigner (from hardware report)
            digest,               // reportData = attestation digest (data binding)
            uint16(1),            // isvProdId
            uint16(1),            // isvSvn
            rawReportHash,        // SHA-256 commitment to fresh hardware attestation report
            uint256(p256r),       // P-256 signature r
            uint256(p256s)        // P-256 signature s
        );

        // Sign with operator private key (secp256k1)
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(operatorPrivKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        return abi.encode(
            platformId,
            timestamp,
            nonce,
            ENCLAVE_HASH,
            SIGNER_HASH,
            payload,
            evidence,
            signature
        );
    }

    /// @notice Build a valid TEE attestation for commitDelegationSnapshot().
    /// The payload is 96 bytes: abi.encode(epoch, delegationRoot, stakerRegistryRoot).
    function _createDelegationAttestation(
        uint256 epoch,
        bytes32 delegationRoot,
        bytes32 stakerRegistryRoot
    ) internal view returns (bytes memory) {
        bytes memory payload = abi.encode(epoch, delegationRoot, stakerRegistryRoot);
        return _createAttestation(payload);
    }

    function _setupValidators() internal returns (bytes32) {
        address[] memory addrs = new address[](4);
        addrs[0] = address(0x1);
        addrs[1] = address(0x2);
        addrs[2] = address(0x3);
        addrs[3] = address(0x4);

        uint256[] memory empty4 = new uint256[](4);
        for (uint256 i = 0; i < 4; i++) {
            empty4[i] = 1000 ether;
        }

        uint256[] memory scores = new uint256[](4);
        for (uint256 i = 0; i < 4; i++) {
            scores[i] = 9000;
        }

        bytes32[] memory keys = new bytes32[](4);
        for (uint256 i = 0; i < 4; i++) {
            keys[i] = keccak256(abi.encodePacked("key", i));
        }

        uint256[] memory commissions = new uint256[](4);
        for (uint256 i = 0; i < 4; i++) {
            commissions[i] = 500;
        }

        bytes memory validatorData = abi.encode(
            addrs, empty4, scores, scores, scores, scores, keys, commissions
        );
        // Attestation payload is canonicalHash || policyHash || universeHash (96 bytes)
        bytes32 vsHash = _computeTestValidatorSetHash(
            1, addrs, empty4, scores, scores, scores, scores, keys, commissions
        );
        bytes memory attestation = _createAttestation(abi.encodePacked(vsHash, TEST_POLICY_HASH, TEST_UNIVERSE_HASH));

        vm.prank(oracle);
        vault.updateValidatorSet(attestation, validatorData, 1);

        return vsHash;
    }

    // =========================================================================
    // 13. SOLVENCY TESTS
    // =========================================================================

    /// @notice Vault balance must always cover totalPooledAethel after staking.
    function test_vaultSolvencyAfterStake() public {
        vm.prank(alice);
        vault.stake(500 ether);

        vm.prank(bob);
        vault.stake(300 ether);

        // Vault token balance must be >= totalPooledAethel
        uint256 vaultBalance = aethel.balanceOf(address(vault));
        assertGe(vaultBalance, vault.totalPooledAethel());
    }

    /// @notice Vault balance must cover all withdrawals after full unstake cycle.
    function test_fullWithdrawalCycleSolvency() public {
        // Alice and Bob stake
        vm.prank(alice);
        vault.stake(500 ether);

        vm.prank(bob);
        vault.stake(300 ether);

        // Both fully unstake (cache shares before prank to avoid prank consumption)
        uint256 aliceShares = stAethel.sharesOf(alice);
        vm.prank(alice);
        (uint256 wIdAlice,) = vault.unstake(aliceShares);

        uint256 bobShares = stAethel.sharesOf(bob);
        vm.prank(bob);
        (uint256 wIdBob,) = vault.unstake(bobShares);

        // Fast-forward past unbonding
        vm.warp(block.timestamp + 14 days + 1);

        // Both withdraw — vault must have enough balance
        uint256 aliceBefore = aethel.balanceOf(alice);
        vm.prank(alice);
        vault.withdraw(wIdAlice);
        assertGt(aethel.balanceOf(alice), aliceBefore);

        uint256 bobBefore = aethel.balanceOf(bob);
        vm.prank(bob);
        vault.withdraw(wIdBob);
        assertGt(aethel.balanceOf(bob), bobBefore);

        // Vault should have zero pending and zero pooled
        assertEq(vault.totalPooledAethel(), 0);
        assertEq(vault.totalPendingWithdrawals(), 0);
    }

    /// @notice Vault stays solvent after MEV auto-compound + full withdrawal.
    function test_vaultSolvencyAfterMEVAndWithdrawals() public {
        vm.prank(alice);
        vault.stake(1000 ether);

        // MEV auto-compounds
        uint256 mevAmount = 50 ether;
        _fundOracleForIngestion(mevAmount);
        bytes memory mevPayload = abi.encode(uint256(1), mevAmount);
        bytes memory att = _createAttestation(mevPayload);
        vm.prank(oracle);
        vault.submitMEVRevenue(att, 1, mevAmount);

        // Vault balance must cover totalPooledAethel
        uint256 vaultBalance = aethel.balanceOf(address(vault));
        assertGe(vaultBalance, vault.totalPooledAethel());

        // Full unstake at the new (higher) exchange rate
        uint256 aliceShares = stAethel.sharesOf(alice);
        vm.prank(alice);
        (uint256 wId,) = vault.unstake(aliceShares);

        vm.warp(block.timestamp + 14 days + 1);

        uint256 aliceBefore = aethel.balanceOf(alice);
        vm.prank(alice);
        vault.withdraw(wId);

        // Alice should get back more than she staked (due to MEV)
        assertGt(aethel.balanceOf(alice) - aliceBefore, 1000 ether);
    }

    /// @notice distributeRewards must not inflate exchange rate (prevents double-distribution).
    function test_noAutoCompoundFromDistributeRewards() public {
        vm.prank(alice);
        vault.stake(1000 ether);

        uint256 pooledBefore = vault.totalPooledAethel();
        uint256 rateBefore = vault.getExchangeRate();

        _fundOracleForIngestion(50 ether);
        bytes memory payload = abi.encode(uint256(1), uint256(50 ether), bytes32(0), uint256(2.5 ether), TEST_SNAPSHOT_HASH, bytes32(0), bytes32(0), bytes32(0));
        bytes memory att = _createAttestation(payload);
        vm.prank(oracle);
        vault.distributeRewards(att, 1, 50 ether, bytes32(0), 2.5 ether);

        // totalPooledAethel unchanged — no auto-compound
        assertEq(vault.totalPooledAethel(), pooledBefore);
        // Exchange rate unchanged
        assertEq(vault.getExchangeRate(), rateBefore);
    }

    // =========================================================================
    // 14. VENDOR ROOT KEY VERIFICATION TESTS
    // =========================================================================

    function test_vendorRootKeyRequired() public {
        // Try to register an enclave on platform 1 (Nitro) without setting vendor root key
        bytes32 nitroEnclave = keccak256("nitro-enclave-v1");
        bytes32 nitroSigner = keccak256("nitro-signer-v1");

        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(VaultTEEVerifier.VendorRootKeyNotSet.selector, uint8(1)));
        verifier.registerEnclave(
            nitroEnclave, nitroSigner, bytes32(0), 1, "Nitro Enclave v1",
            P256_PUB_X, P256_PUB_Y, 0, 0
        );
    }

    function test_invalidVendorAttestationRejected() public {
        // Set vendor root key for Nitro
        vm.startPrank(admin);
        verifier.setVendorRootKey(1, VENDOR_ROOT_X, VENDOR_ROOT_Y);

        // Try to register an enclave with invalid vendor attestation (wrong signature)
        bytes32 nitroEnclave = keccak256("nitro-enclave-v1");
        bytes32 nitroSigner = keccak256("nitro-signer-v1");
        vm.expectRevert(VaultTEEVerifier.InvalidVendorKeyAttestation.selector);
        verifier.registerEnclave(
            nitroEnclave, nitroSigner, bytes32(0), 1, "Nitro Enclave v1",
            P256_PUB_X, P256_PUB_Y, 1, 1
        );
        vm.stopPrank();
    }

    function test_vendorAttestedPlatformKeyAccepted() public {
        // Set vendor root key for Nitro
        vm.startPrank(admin);
        verifier.setVendorRootKey(1, VENDOR_ROOT_X, VENDOR_ROOT_Y);

        // Register enclave with valid vendor attestation for per-enclave platform key
        bytes32 nitroEnclave = keccak256("nitro-enclave-v1");
        bytes32 nitroSigner = keccak256("nitro-signer-v1");
        bytes32 keyAttestMsg = sha256(abi.encodePacked(P256_PUB_X, P256_PUB_Y, uint8(1)));
        (bytes32 vr, bytes32 vs) = vm.signP256(VENDOR_ROOT_PRIV, keyAttestMsg);

        // Should succeed with valid vendor attestation
        verifier.registerEnclave(
            nitroEnclave, nitroSigner, keccak256("nitro-app-v1"), 1, "Nitro Enclave v1",
            P256_PUB_X, P256_PUB_Y, uint256(vr), uint256(vs)
        );
        vm.stopPrank();

        assertTrue(verifier.isEnclaveActive(nitroEnclave, 1));
    }

    function test_selfIssuedPlatformKeyRejected() public {
        // This is the exact attack the consultant described:
        // Operator creates their own P-256 key and tries to register it
        // without a valid vendor root attestation

        // Use a different P-256 key (private key = 3) as the "self-issued" key
        uint256 selfIssuedX = 0x5ECBE4D1A6330A44C8F7EF951D4BF165E6C6B721EFADA985FB41661BC6E7FD6C;
        uint256 selfIssuedY = 0x8734640C4998FF7E374B06CE1A64A2ECD82AB036384FB83D9A79B127A27D5032;

        vm.startPrank(admin);
        verifier.setVendorRootKey(1, VENDOR_ROOT_X, VENDOR_ROOT_Y);

        // Sign with the self-issued key (not vendor root) — this won't verify
        // against the vendor root key
        bytes32 nitroEnclave = keccak256("nitro-self-issued");
        bytes32 nitroSigner = keccak256("nitro-self-signer");
        bytes32 keyAttestMsg = sha256(abi.encodePacked(selfIssuedX, selfIssuedY, uint8(1)));
        (bytes32 badR, bytes32 badS) = vm.signP256(3, keyAttestMsg); // signed by key 3, not vendor root 2

        vm.expectRevert(VaultTEEVerifier.InvalidVendorKeyAttestation.selector);
        verifier.registerEnclave(
            nitroEnclave, nitroSigner, bytes32(0), 1, "Self-issued key enclave",
            selfIssuedX, selfIssuedY, uint256(badR), uint256(badS)
        );
        vm.stopPrank();
    }

    // =========================================================================
    // 15. PER-ENCLAVE PLATFORM KEY ISOLATION TESTS
    // =========================================================================

    /// @notice Prove that two enclaves on the same platform have independent keys.
    ///         If enclave A's key is compromised (attacker knows P256_PRIV_KEY),
    ///         enclave B (with a different key) is unaffected.
    function test_perEnclavePlatformKeyIsolation() public {
        // Enclave B uses a DIFFERENT P-256 key (private key = 3)
        uint256 enclaveBKeyX = 0x5ECBE4D1A6330A44C8F7EF951D4BF165E6C6B721EFADA985FB41661BC6E7FD6C;
        uint256 enclaveBKeyY = 0x8734640C4998FF7E374B06CE1A64A2ECD82AB036384FB83D9A79B127A27D5032;
        uint256 enclaveBPrivKey = 3;

        bytes32 enclaveHashB = keccak256("cruzible-enclave-B");
        bytes32 signerHashB = keccak256("cruzible-signer-B");

        // Second operator
        uint256 operator2PrivKey = 0xBEEF;
        address operator2Addr = vm.addr(operator2PrivKey);

        vm.startPrank(admin);

        // Register enclave B with its own platform key (vendor-attested)
        bytes32 keyAttestMsgB = sha256(abi.encodePacked(enclaveBKeyX, enclaveBKeyY, uint8(0)));
        (bytes32 vrB, bytes32 vsB) = vm.signP256(VENDOR_ROOT_PRIV, keyAttestMsgB);
        verifier.registerEnclave(
            enclaveHashB, signerHashB, bytes32(0), 0, "Cruzible SGX Enclave B",
            enclaveBKeyX, enclaveBKeyY, uint256(vrB), uint256(vsB)
        );
        bytes32 enclaveBId = keccak256(abi.encodePacked(enclaveHashB, uint8(0)));
        verifier.registerOperator(operator2Addr, enclaveBId, "Operator for enclave B");
        vm.stopPrank();

        // Fund and stake so distributeRewards can work
        vm.prank(alice);
        vault.stake(100 ether);

        // Build an attestation for enclave B signed with enclave B's platform key
        // This should SUCCEED because enclave B's key matches
        {
            uint256 fee1 = (10 ether * 500) / 10000; // 0.5 ether
            bytes memory payload = abi.encode(uint256(1), uint256(10 ether), bytes32(0), fee1, TEST_SNAPSHOT_HASH, bytes32(0), bytes32(0), bytes32(0));
            _fundOracleForIngestion(10 ether);
            bytes memory att = _createAttestationForEnclave(
                payload, enclaveHashB, signerHashB, enclaveBPrivKey, operator2PrivKey
            );
            vm.prank(oracle);
            vault.distributeRewards(att, 1, 10 ether, bytes32(0), fee1);
        }

        // Now try to forge an attestation for enclave B using enclave A's key (P256_PRIV_KEY = 1)
        // This MUST fail because enclave B's registered key is different
        {
            uint256 fee2 = (5 ether * 500) / 10000; // 0.25 ether
            bytes memory payload2 = abi.encode(uint256(2), uint256(5 ether), bytes32(0), fee2, TEST_SNAPSHOT_HASH, bytes32(0), bytes32(0), bytes32(0));
            _fundOracleForIngestion(5 ether);
            bytes memory forgedAtt = _createAttestationForEnclave(
                payload2, enclaveHashB, signerHashB, P256_PRIV_KEY, operator2PrivKey
            );
            vm.prank(oracle);
            vm.expectRevert(VaultTEEVerifier.InvalidPlatformEvidence.selector);
            vault.distributeRewards(forgedAtt, 2, 5 ether, bytes32(0), fee2);
        }
    }

    /// @notice Helper to build an attestation for a specific enclave with a specific platform key.
    function _createAttestationForEnclave(
        bytes memory payload,
        bytes32 enclaveHash,
        bytes32 signerHash,
        uint256 p256PrivKey,
        uint256 operatorKey
    ) internal view returns (bytes memory) {
        uint8 platformId = 0;
        uint256 timestamp = block.timestamp;
        bytes32 nonce = keccak256(abi.encodePacked(block.timestamp, block.number, payload, enclaveHash));

        bytes32 payloadHash = sha256(payload);
        bytes32 digest = sha256(abi.encodePacked(
            "CruzibleTEEAttestation",
            platformId,
            uint64(timestamp),
            nonce,
            enclaveHash,
            signerHash,
            payloadHash
        ));

        bytes32 rawReportHash = sha256(abi.encodePacked("MOCK_HW_REPORT_V1", enclaveHash, signerHash, digest));
        bytes32 bindingHash = sha256(abi.encodePacked(rawReportHash, enclaveHash, signerHash));
        bytes32 reportHash = sha256(abi.encodePacked(enclaveHash, signerHash, digest, uint16(1), uint16(1), bindingHash));
        (bytes32 p256r, bytes32 p256s) = vm.signP256(p256PrivKey, reportHash);

        bytes memory evidence = abi.encode(
            enclaveHash, signerHash, digest, uint16(1), uint16(1),
            rawReportHash, uint256(p256r), uint256(p256s)
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(operatorKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        return abi.encode(platformId, timestamp, nonce, enclaveHash, signerHash, payload, evidence, signature);
    }

    // =========================================================================
    // 17. PER-ATTESTATION HARDWARE EVIDENCE TESTS
    // =========================================================================

    function test_zeroHwReportHashRejected() public {
        // Evidence with zero rawReportHash should be rejected — proves no hardware attestation
        uint8 platformId = 0;
        uint256 timestamp = block.timestamp;
        bytes32 nonce = keccak256("zero-hw-hash-test");
        bytes32 payloadHash = sha256("test-payload");
        bytes32 digest = sha256(abi.encodePacked(
            "CruzibleTEEAttestation", platformId, uint64(timestamp),
            nonce, ENCLAVE_HASH, SIGNER_HASH, payloadHash
        ));

        // Build evidence with rawReportHash = 0
        bytes32 zeroHash = bytes32(0);
        bytes32 bindingHash = sha256(abi.encodePacked(zeroHash, ENCLAVE_HASH, SIGNER_HASH));
        bytes32 reportHash = sha256(abi.encodePacked(ENCLAVE_HASH, SIGNER_HASH, digest, uint16(1), uint16(1), bindingHash));
        (bytes32 p256r, bytes32 p256s) = vm.signP256(P256_PRIV_KEY, reportHash);

        bytes memory evidence = abi.encode(
            ENCLAVE_HASH, SIGNER_HASH, digest, uint16(1), uint16(1),
            zeroHash, uint256(p256r), uint256(p256s)
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(operatorPrivKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory attestation = abi.encode(
            platformId, timestamp, nonce, ENCLAVE_HASH, SIGNER_HASH,
            bytes("test-payload"), evidence, signature
        );

        // Should revert because hwReportHash is zero
        vm.prank(oracle);
        vm.expectRevert(VaultTEEVerifier.InvalidPlatformEvidence.selector);
        vault.distributeRewards(attestation, 1, 0, bytes32(0), 0);
    }

    function test_validHwReportHashAccepted() public {
        // Verify that a non-zero hwReportHash in evidence is accepted
        // (This is implicitly tested by all existing tests using _createAttestation,
        // but we test it explicitly here)
        vm.prank(alice);
        vault.stake(100 ether);
        _fundOracleForIngestion(10 ether);

        uint256 fee = (10 ether * 500) / 10000; // 0.5 ether
        bytes memory payload = abi.encode(uint256(1), uint256(10 ether), bytes32(0), fee, TEST_SNAPSHOT_HASH, bytes32(0), bytes32(0), bytes32(0));
        bytes memory att = _createAttestation(payload);

        // Should succeed — _createAttestation includes a valid hwReportHash
        // (distributeRewards does not auto-compound, so totalPooledAethel stays at staked amount)
        vm.prank(oracle);
        vault.distributeRewards(att, 1, 10 ether, bytes32(0), fee);
        assertEq(vault.totalPooledAethel(), 100 ether);
    }

    // =========================================================================
    // 18. TIMESTAMP OVERFLOW / FUTURE TIMESTAMP TESTS
    // =========================================================================

    /// @notice Timestamps exceeding uint64 range must be rejected to prevent
    ///         high-bit truncation attacks on the signature digest.
    function test_timestampOverflowRejected() public {
        // Attack: use timestamp = block.timestamp + 2^64.
        // uint64(t + 2^64) == uint64(t), so the digest would be identical,
        // letting a stale attestation appear fresh.
        uint256 overflowedTimestamp = block.timestamp + (1 << 64);

        uint8 platformId = 0;
        bytes32 nonce = keccak256("overflow-test");
        bytes memory payload = abi.encode(uint256(1), uint256(0));
        bytes32 payloadHash = sha256(payload);
        bytes32 digest = sha256(abi.encodePacked(
            "CruzibleTEEAttestation", platformId, uint64(overflowedTimestamp),
            nonce, ENCLAVE_HASH, SIGNER_HASH, payloadHash
        ));

        // Build valid evidence and signature for the overflowed timestamp
        bytes32 rawReportHash = sha256(abi.encodePacked("MOCK_HW_REPORT_V1", ENCLAVE_HASH, SIGNER_HASH, digest));
        bytes32 bindingHash = sha256(abi.encodePacked(rawReportHash, ENCLAVE_HASH, SIGNER_HASH));
        bytes32 reportHash = sha256(abi.encodePacked(ENCLAVE_HASH, SIGNER_HASH, digest, uint16(1), uint16(1), bindingHash));
        (bytes32 p256r, bytes32 p256s) = vm.signP256(P256_PRIV_KEY, reportHash);
        bytes memory evidence = abi.encode(
            ENCLAVE_HASH, SIGNER_HASH, digest, uint16(1), uint16(1),
            rawReportHash, uint256(p256r), uint256(p256s)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(operatorPrivKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes memory attestation = abi.encode(
            platformId, overflowedTimestamp, nonce, ENCLAVE_HASH, SIGNER_HASH,
            payload, evidence, signature
        );

        vm.prank(oracle);
        vm.expectRevert(abi.encodeWithSelector(VaultTEEVerifier.TimestampOverflow.selector, overflowedTimestamp));
        vault.distributeRewards(attestation, 1, 0, bytes32(0), 0);
    }

    /// @notice Future timestamps must be rejected.
    function test_futureTimestampRejected() public {
        uint256 futureTimestamp = block.timestamp + 1 hours;

        uint8 platformId = 0;
        bytes32 nonce = keccak256("future-ts-test");
        bytes memory payload = abi.encode(uint256(1), uint256(0));
        bytes32 payloadHash = sha256(payload);
        bytes32 digest = sha256(abi.encodePacked(
            "CruzibleTEEAttestation", platformId, uint64(futureTimestamp),
            nonce, ENCLAVE_HASH, SIGNER_HASH, payloadHash
        ));

        bytes32 rawReportHash = sha256(abi.encodePacked("MOCK_HW_REPORT_V1", ENCLAVE_HASH, SIGNER_HASH, digest));
        bytes32 bindingHash = sha256(abi.encodePacked(rawReportHash, ENCLAVE_HASH, SIGNER_HASH));
        bytes32 reportHash = sha256(abi.encodePacked(ENCLAVE_HASH, SIGNER_HASH, digest, uint16(1), uint16(1), bindingHash));
        (bytes32 p256r, bytes32 p256s) = vm.signP256(P256_PRIV_KEY, reportHash);
        bytes memory evidence = abi.encode(
            ENCLAVE_HASH, SIGNER_HASH, digest, uint16(1), uint16(1),
            rawReportHash, uint256(p256r), uint256(p256s)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(operatorPrivKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes memory attestation = abi.encode(
            platformId, futureTimestamp, nonce, ENCLAVE_HASH, SIGNER_HASH,
            payload, evidence, signature
        );

        vm.prank(oracle);
        vm.expectRevert(abi.encodeWithSelector(VaultTEEVerifier.FutureTimestamp.selector, futureTimestamp, block.timestamp));
        vault.distributeRewards(attestation, 1, 0, bytes32(0), 0);
    }

    /// @notice verifyAttestationView must also reject overflowed timestamps.
    function test_timestampOverflow_viewReturnsInvalid() public view {
        uint256 overflowedTimestamp = block.timestamp + (1 << 64);

        uint8 platformId = 0;
        bytes32 nonce = keccak256("overflow-view-test");
        bytes memory payload = abi.encode(uint256(1), uint256(0));
        bytes32 payloadHash = sha256(payload);
        bytes32 digest = sha256(abi.encodePacked(
            "CruzibleTEEAttestation", platformId, uint64(overflowedTimestamp),
            nonce, ENCLAVE_HASH, SIGNER_HASH, payloadHash
        ));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(operatorPrivKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory evidence = new bytes(0);

        bytes memory attestation = abi.encode(
            platformId, overflowedTimestamp, nonce, ENCLAVE_HASH, SIGNER_HASH,
            payload, evidence, signature
        );

        (bool valid,,) = verifier.verifyAttestationView(attestation);
        assertFalse(valid, "overflowed timestamp should be rejected by view function");
    }

    // =========================================================================
    // CANONICAL REWARD PAYLOAD CROSS-LANGUAGE TEST
    // =========================================================================

    /// @notice Verify the canonical reward payload encoding matches Rust and Go.
    ///
    /// The payload is abi.encode(epoch, totalRewards, merkleRoot, protocolFee,
    ///                           snapshotHash, validatorSetHash, stakerRegistryRoot,
    ///                           delegationRegistryRoot).
    /// The Rust TEE worker produces this via compute_canonical_reward_payload().
    ///
    /// Cross-language test vector:
    ///   epoch                    = 1
    ///   totalRewards             = 100e18
    ///   merkleRoot               = keccak256("rewards-merkle-root")
    ///   protocolFee              = 5e18
    ///   snapshotHash             = keccak256("test-stake-snapshot-v1")
    ///   validatorSetHash         = keccak256("test-validator-set-v1")
    ///   stakerRegistryRoot       = bytes32(0)
    ///   delegationRegistryRoot   = bytes32(0)
    function test_canonicalRewardPayloadEncoding() public {
        uint256 epoch = 1;
        uint256 totalRewards = 100 ether;
        bytes32 merkleRoot = keccak256("rewards-merkle-root");
        uint256 protocolFee = 5 ether;
        bytes32 snapshotHash = TEST_SNAPSHOT_HASH;
        bytes32 vsHash = keccak256("test-validator-set-v1");
        bytes32 registryRoot = bytes32(0);
        bytes32 delegationRoot = bytes32(0);

        bytes memory payload = abi.encode(epoch, totalRewards, merkleRoot, protocolFee, snapshotHash, vsHash, registryRoot, delegationRoot);

        // Must be exactly 256 bytes (8 × 32-byte ABI words)
        assertEq(payload.length, 256, "canonical reward payload must be 256 bytes");

        // Deterministic
        bytes memory payload2 = abi.encode(epoch, totalRewards, merkleRoot, protocolFee, snapshotHash, vsHash, registryRoot, delegationRoot);
        assertEq(keccak256(payload), keccak256(payload2), "payload must be deterministic");

        // Changing any field must change the hash
        bytes memory diffEpoch = abi.encode(uint256(2), totalRewards, merkleRoot, protocolFee, snapshotHash, vsHash, registryRoot, delegationRoot);
        assertTrue(keccak256(payload) != keccak256(diffEpoch), "different epoch should produce different payload");

        bytes memory diffRewards = abi.encode(epoch, uint256(200 ether), merkleRoot, protocolFee, snapshotHash, vsHash, registryRoot, delegationRoot);
        assertTrue(keccak256(payload) != keccak256(diffRewards), "different totalRewards should produce different payload");

        bytes memory diffRoot = abi.encode(epoch, totalRewards, bytes32(uint256(1)), protocolFee, snapshotHash, vsHash, registryRoot, delegationRoot);
        assertTrue(keccak256(payload) != keccak256(diffRoot), "different merkleRoot should produce different payload");

        bytes memory diffFee = abi.encode(epoch, totalRewards, merkleRoot, uint256(10 ether), snapshotHash, vsHash, registryRoot, delegationRoot);
        assertTrue(keccak256(payload) != keccak256(diffFee), "different protocolFee should produce different payload");

        bytes memory diffSnapshot = abi.encode(epoch, totalRewards, merkleRoot, protocolFee, keccak256("different-snapshot"), vsHash, registryRoot, delegationRoot);
        assertTrue(keccak256(payload) != keccak256(diffSnapshot), "different snapshotHash should produce different payload");

        bytes memory diffVsHash = abi.encode(epoch, totalRewards, merkleRoot, protocolFee, snapshotHash, keccak256("different-vs-hash"), registryRoot, delegationRoot);
        assertTrue(keccak256(payload) != keccak256(diffVsHash), "different validatorSetHash should produce different payload");

        bytes memory diffRegRoot = abi.encode(epoch, totalRewards, merkleRoot, protocolFee, snapshotHash, vsHash, keccak256("different-registry-root"), delegationRoot);
        assertTrue(keccak256(payload) != keccak256(diffRegRoot), "different stakerRegistryRoot should produce different payload");

        bytes memory diffDelRoot = abi.encode(epoch, totalRewards, merkleRoot, protocolFee, snapshotHash, vsHash, registryRoot, keccak256("different-delegation-root"));
        assertTrue(keccak256(payload) != keccak256(diffDelRoot), "different delegationRegistryRoot should produce different payload");

        // Log the keccak256 for cross-language verification
        emit log_named_bytes32("reward_payload_keccak256", keccak256(payload));
    }

    // =========================================================================
    // SELECTION POLICY HASH TESTS
    // =========================================================================

    /// @notice Governance can set the selection policy hash.
    function test_setSelectionPolicyHash() public {
        bytes32 newPolicy = keccak256("new-policy-v2");
        vm.prank(admin);
        vault.setSelectionPolicyHash(newPolicy);
        assertEq(vault.selectionPolicyHash(), newPolicy);
    }

    /// @notice Non-admin cannot set the selection policy hash.
    function test_setSelectionPolicyHash_onlyAdmin() public {
        vm.prank(alice);
        vm.expectRevert();
        vault.setSelectionPolicyHash(keccak256("malicious-policy"));
    }

    /// @notice updateValidatorSet reverts with SelectionPolicyMismatch if the
    ///         attested policy hash does not match the governance-set value.
    function test_selectionPolicyMismatch() public {
        // Build minimal valid validator data
        address[] memory addrs = new address[](4);
        addrs[0] = address(0x1);
        addrs[1] = address(0x2);
        addrs[2] = address(0x3);
        addrs[3] = address(0x4);

        uint256[] memory scores = new uint256[](4);
        for (uint256 i = 0; i < 4; i++) scores[i] = 9000;

        bytes32[] memory keys = new bytes32[](4);
        for (uint256 i = 0; i < 4; i++) keys[i] = keccak256(abi.encodePacked("key", i));

        uint256[] memory commissions = new uint256[](4);
        for (uint256 i = 0; i < 4; i++) commissions[i] = 500;

        bytes memory validatorData = abi.encode(
            addrs, scores, scores, scores, scores, scores, keys, commissions
        );

        bytes32 vsHash = _computeTestValidatorSetHash(
            1, addrs, scores, scores, scores, scores, scores, keys, commissions
        );

        // Create attestation with a WRONG policy hash (different from TEST_POLICY_HASH)
        bytes32 wrongPolicy = keccak256("wrong-policy");
        bytes memory attestation = _createAttestation(abi.encodePacked(vsHash, wrongPolicy, TEST_UNIVERSE_HASH));

        // Must revert with SelectionPolicyMismatch
        vm.prank(oracle);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.SelectionPolicyMismatch.selector, wrongPolicy, TEST_POLICY_HASH)
        );
        vault.updateValidatorSet(attestation, validatorData, 1);
    }

    /// @notice updateValidatorSet reverts with InvalidAttestation if the payload
    ///         is 64 bytes (old format without universe hash) instead of 96 bytes.
    function test_validatorAttestation_rejectsTruncatedPayload() public {
        address[] memory addrs = new address[](4);
        addrs[0] = address(0x1);
        addrs[1] = address(0x2);
        addrs[2] = address(0x3);
        addrs[3] = address(0x4);

        uint256[] memory scores = new uint256[](4);
        for (uint256 i = 0; i < 4; i++) scores[i] = 9000;

        bytes32[] memory keys = new bytes32[](4);
        for (uint256 i = 0; i < 4; i++) keys[i] = keccak256(abi.encodePacked("key", i));

        uint256[] memory commissions = new uint256[](4);
        for (uint256 i = 0; i < 4; i++) commissions[i] = 500;

        bytes memory validatorData = abi.encode(
            addrs, scores, scores, scores, scores, scores, keys, commissions
        );

        bytes32 vsHash = _computeTestValidatorSetHash(
            1, addrs, scores, scores, scores, scores, scores, keys, commissions
        );

        // Create attestation with only 64 bytes (old format, no universe hash)
        bytes memory attestation = _createAttestation(abi.encodePacked(vsHash, TEST_POLICY_HASH));

        // Must revert because payload.length != 96
        vm.prank(oracle);
        vm.expectRevert(Cruzible.InvalidAttestation.selector);
        vault.updateValidatorSet(attestation, validatorData, 1);
    }

    /// @notice updateValidatorSet verifies the attested universe hash against the
    ///         epoch commitment and updates lastEligibleUniverseHash().
    function test_updateValidatorSet_storesUniverseHash() public {
        address[] memory addrs = new address[](4);
        addrs[0] = address(0x1);
        addrs[1] = address(0x2);
        addrs[2] = address(0x3);
        addrs[3] = address(0x4);

        uint256[] memory scores = new uint256[](4);
        for (uint256 i = 0; i < 4; i++) scores[i] = 9000;

        bytes32[] memory keys = new bytes32[](4);
        for (uint256 i = 0; i < 4; i++) keys[i] = keccak256(abi.encodePacked("key", i));

        uint256[] memory commissions = new uint256[](4);
        for (uint256 i = 0; i < 4; i++) commissions[i] = 500;

        bytes memory validatorData = abi.encode(
            addrs, scores, scores, scores, scores, scores, keys, commissions
        );

        bytes32 vsHash = _computeTestValidatorSetHash(
            1, addrs, scores, scores, scores, scores, scores, keys, commissions
        );

        // setUp already committed TEST_UNIVERSE_HASH for epoch 1 — use it directly.
        bytes memory attestation = _createAttestation(
            abi.encodePacked(vsHash, TEST_POLICY_HASH, TEST_UNIVERSE_HASH)
        );

        // Verify universe hash was zero before updateValidatorSet
        assertEq(vault.lastEligibleUniverseHash(), bytes32(0));

        vm.prank(oracle);
        vault.updateValidatorSet(attestation, validatorData, 1);

        // Verify universe hash is stored and matches epoch-scoped commitment
        assertEq(vault.lastEligibleUniverseHash(), TEST_UNIVERSE_HASH);
        Cruzible.EpochSnapshot memory snap = vault.getEpochSnapshot(1);
        assertEq(snap.eligibleUniverseHash, TEST_UNIVERSE_HASH);
    }

    /// @notice updateValidatorSet rejects a 32-byte payload (only canonical hash,
    ///         missing both policy and universe hashes).
    function test_validatorAttestation_rejects32BytePayload() public {
        address[] memory addrs = new address[](4);
        addrs[0] = address(0x1);
        addrs[1] = address(0x2);
        addrs[2] = address(0x3);
        addrs[3] = address(0x4);

        uint256[] memory scores = new uint256[](4);
        for (uint256 i = 0; i < 4; i++) scores[i] = 9000;

        bytes32[] memory keys = new bytes32[](4);
        for (uint256 i = 0; i < 4; i++) keys[i] = keccak256(abi.encodePacked("key", i));

        uint256[] memory commissions = new uint256[](4);
        for (uint256 i = 0; i < 4; i++) commissions[i] = 500;

        bytes memory validatorData = abi.encode(
            addrs, scores, scores, scores, scores, scores, keys, commissions
        );

        bytes32 vsHash = _computeTestValidatorSetHash(
            1, addrs, scores, scores, scores, scores, scores, keys, commissions
        );

        // Create attestation with only 32 bytes (just canonical hash)
        bytes memory attestation = _createAttestation(abi.encodePacked(vsHash));

        vm.prank(oracle);
        vm.expectRevert(Cruzible.InvalidAttestation.selector);
        vault.updateValidatorSet(attestation, validatorData, 1);
    }

    // =========================================================================
    // ELIGIBLE UNIVERSE HASH VERIFICATION TESTS
    // =========================================================================

    /// @notice Governance can commit the epoch-scoped eligible-universe hash.
    function test_commitUniverseHash() public {
        // setUp already committed for epoch 1, so verify via epoch snapshot.
        Cruzible.EpochSnapshot memory snap = vault.getEpochSnapshot(1);
        assertEq(snap.eligibleUniverseHash, TEST_UNIVERSE_HASH);
    }

    /// @notice Non-admin cannot commit the eligible-universe hash.
    function test_commitUniverseHash_onlyAdmin() public {
        // Advance to epoch 2 so we have an uncommitted epoch to test.
        _distributeRewardsForCurrentEpoch();

        vm.prank(alice);
        vm.expectRevert();
        vault.commitUniverseHash(2, keccak256("malicious-universe"));
    }

    /// @notice Universe commitment is immutable per epoch.
    function test_commitUniverseHash_immutablePerEpoch() public {
        // setUp already committed for epoch 1. Attempting again must revert.
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.UniverseHashAlreadyCommitted.selector, uint256(1))
        );
        vault.commitUniverseHash(1, keccak256("second-attempt"));
    }

    /// @notice Universe commitment must target the current epoch.
    function test_commitUniverseHash_rejectsWrongEpoch() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.InvalidEpoch.selector, uint256(99), uint256(1))
        );
        vault.commitUniverseHash(99, keccak256("future-epoch"));
    }

    /// @notice updateValidatorSet reverts with EligibleUniverseMismatch if the
    ///         attested universe hash does not match the epoch-committed value.
    ///         This catches relayers that omit eligible validators from the TEE
    ///         request (truncation attack).
    function test_eligibleUniverseMismatch() public {
        address[] memory addrs = new address[](4);
        addrs[0] = address(0x1);
        addrs[1] = address(0x2);
        addrs[2] = address(0x3);
        addrs[3] = address(0x4);

        uint256[] memory scores = new uint256[](4);
        for (uint256 i = 0; i < 4; i++) scores[i] = 9000;

        bytes32[] memory keys = new bytes32[](4);
        for (uint256 i = 0; i < 4; i++) keys[i] = keccak256(abi.encodePacked("key", i));

        uint256[] memory commissions = new uint256[](4);
        for (uint256 i = 0; i < 4; i++) commissions[i] = 500;

        bytes memory validatorData = abi.encode(
            addrs, scores, scores, scores, scores, scores, keys, commissions
        );

        bytes32 vsHash = _computeTestValidatorSetHash(
            1, addrs, scores, scores, scores, scores, scores, keys, commissions
        );

        // Create attestation with a WRONG universe hash (simulating truncated candidate set)
        bytes32 wrongUniverse = keccak256("truncated-universe");
        bytes memory attestation = _createAttestation(abi.encodePacked(vsHash, TEST_POLICY_HASH, wrongUniverse));

        // Must revert with EligibleUniverseMismatch
        vm.prank(oracle);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.EligibleUniverseMismatch.selector, wrongUniverse, TEST_UNIVERSE_HASH)
        );
        vault.updateValidatorSet(attestation, validatorData, 1);
    }

    /// @notice updateValidatorSet succeeds when the attested universe hash
    ///         matches the epoch-committed value (normal operation).
    function test_universeHashVerificationPasses() public {
        address[] memory addrs = new address[](4);
        addrs[0] = address(0x1);
        addrs[1] = address(0x2);
        addrs[2] = address(0x3);
        addrs[3] = address(0x4);

        uint256[] memory scores = new uint256[](4);
        for (uint256 i = 0; i < 4; i++) scores[i] = 9000;

        bytes32[] memory keys = new bytes32[](4);
        for (uint256 i = 0; i < 4; i++) keys[i] = keccak256(abi.encodePacked("key", i));

        uint256[] memory commissions = new uint256[](4);
        for (uint256 i = 0; i < 4; i++) commissions[i] = 500;

        bytes memory validatorData = abi.encode(
            addrs, scores, scores, scores, scores, scores, keys, commissions
        );

        bytes32 vsHash = _computeTestValidatorSetHash(
            1, addrs, scores, scores, scores, scores, scores, keys, commissions
        );

        // Use the committed universe hash (matches setUp)
        bytes memory attestation = _createAttestation(
            abi.encodePacked(vsHash, TEST_POLICY_HASH, TEST_UNIVERSE_HASH)
        );

        vm.prank(oracle);
        vault.updateValidatorSet(attestation, validatorData, 1);

        // Verify last universe hash and epoch snapshot are consistent
        assertEq(vault.lastEligibleUniverseHash(), TEST_UNIVERSE_HASH);
        Cruzible.EpochSnapshot memory snap = vault.getEpochSnapshot(1);
        assertEq(snap.eligibleUniverseHash, TEST_UNIVERSE_HASH);
        assertEq(vault.getActiveValidatorCount(), 4);
    }

    /// @notice updateValidatorSet reverts if no universe hash has been committed
    ///         for the current epoch (epoch-scoped eligibleUniverseHash is zero).
    function test_universeHashRejectsWhenNotCommitted() public {
        // Advance to epoch 2 by distributing for epoch 1.
        _distributeRewardsForCurrentEpoch();
        assertEq(vault.currentEpoch(), 2);

        // Commit stake snapshot for epoch 2 but do NOT commit universe hash.
        // Cache shares before prank — vault.getTotalShares() is an external call
        // that would consume the single-use prank if inlined as an argument.
        uint256 currentShares = vault.getTotalShares();
        vm.prank(admin);
        vault.commitStakeSnapshot(2, TEST_SNAPSHOT_HASH, currentShares);

        address[] memory addrs = new address[](4);
        addrs[0] = address(0x1);
        addrs[1] = address(0x2);
        addrs[2] = address(0x3);
        addrs[3] = address(0x4);

        uint256[] memory scores = new uint256[](4);
        for (uint256 i = 0; i < 4; i++) scores[i] = 9000;

        bytes32[] memory keys = new bytes32[](4);
        for (uint256 i = 0; i < 4; i++) keys[i] = keccak256(abi.encodePacked("key", i));

        uint256[] memory commissions = new uint256[](4);
        for (uint256 i = 0; i < 4; i++) commissions[i] = 500;

        bytes memory validatorData = abi.encode(
            addrs, scores, scores, scores, scores, scores, keys, commissions
        );

        bytes32 vsHash = _computeTestValidatorSetHash(
            2, addrs, scores, scores, scores, scores, scores, keys, commissions
        );

        // Attestation has a non-zero universe hash, but epoch 2 has no commitment.
        bytes memory attestation = _createAttestation(
            abi.encodePacked(vsHash, TEST_POLICY_HASH, TEST_UNIVERSE_HASH)
        );

        vm.prank(oracle);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.EligibleUniverseMismatch.selector, TEST_UNIVERSE_HASH, bytes32(0))
        );
        vault.updateValidatorSet(attestation, validatorData, 2);
    }

    // =========================================================================
    // STAKE SNAPSHOT HASH VERIFICATION TESTS
    // =========================================================================

    /// @notice Governance can commit the epoch-scoped stake snapshot hash.
    function test_commitStakeSnapshot() public {
        // setUp already committed for epoch 1, so verify via epoch snapshot.
        Cruzible.EpochSnapshot memory snap = vault.getEpochSnapshot(1);
        assertEq(snap.stakeSnapshotHash, TEST_SNAPSHOT_HASH);
    }

    /// @notice Non-admin cannot commit the stake snapshot hash.
    function test_commitStakeSnapshot_onlyAdmin() public {
        // Advance to epoch 2 so we have an uncommitted epoch to test.
        _distributeRewardsForCurrentEpoch();

        uint256 shares = vault.getTotalShares();
        vm.prank(alice);
        vm.expectRevert();
        vault.commitStakeSnapshot(2, keccak256("malicious-snapshot"), shares);
    }

    /// @notice Snapshot commitment is immutable per epoch.
    function test_commitStakeSnapshot_immutablePerEpoch() public {
        // setUp already committed for epoch 1. Attempting again must revert.
        uint256 shares = vault.getTotalShares();
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.StakeSnapshotAlreadyCommitted.selector, uint256(1))
        );
        vault.commitStakeSnapshot(1, keccak256("second-attempt"), shares);
    }

    /// @notice Snapshot commitment must target the current epoch.
    function test_commitStakeSnapshot_rejectsWrongEpoch() public {
        uint256 shares = vault.getTotalShares();
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.InvalidEpoch.selector, uint256(99), uint256(1))
        );
        vault.commitStakeSnapshot(99, keccak256("future-epoch"), shares);
    }

    /// @notice commitStakeSnapshot reverts when the caller-supplied total
    ///         share supply does not match the on-chain aggregate, preventing
    ///         a relayer from committing a snapshot built against stale or
    ///         fabricated share data.
    function test_commitStakeSnapshot_rejectsSharesMismatch() public {
        // Advance to epoch 2 so we have an uncommitted epoch.
        _distributeRewardsForCurrentEpoch();
        assertEq(vault.currentEpoch(), 2);

        // The on-chain total shares reflect alice's 100 ether stake from the
        // helper.  Supply a deliberately wrong value.
        uint256 onChainShares = vault.getTotalShares();
        uint256 wrongShares = onChainShares + 999 ether;

        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.SnapshotSharesMismatch.selector, wrongShares, onChainShares)
        );
        vault.commitStakeSnapshot(2, TEST_SNAPSHOT_HASH, wrongShares);
    }

    /// @notice distributeRewards reverts with StakeSnapshotMismatch if the
    ///         attested snapshot hash does not match the governance-committed value.
    function test_stakeSnapshotMismatch() public {
        vm.prank(alice);
        vault.stake(1000 ether);

        uint256 totalRewards = 100 ether;
        uint256 protocolFee = 5 ether;
        bytes32 merkleRoot = keccak256("snapshot-mismatch-merkle");
        _fundOracleForIngestion(totalRewards);

        // Create attestation with a WRONG snapshot hash
        bytes32 wrongSnapshot = keccak256("wrong-snapshot");
        bytes memory payload = abi.encode(uint256(1), totalRewards, merkleRoot, protocolFee, wrongSnapshot, bytes32(0), bytes32(0), bytes32(0));
        bytes memory attestation = _createAttestation(payload);

        // Must revert with StakeSnapshotMismatch (checked before validator set hash)
        vm.prank(oracle);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.StakeSnapshotMismatch.selector, wrongSnapshot, TEST_SNAPSHOT_HASH)
        );
        vault.distributeRewards(attestation, 1, totalRewards, merkleRoot, protocolFee);
    }

    /// @notice distributeRewards succeeds when the attested snapshot hash matches
    ///         the epoch-scoped committed value (normal operation).
    function test_stakeSnapshotVerificationPasses() public {
        vm.prank(alice);
        vault.stake(1000 ether);

        uint256 totalRewards = 50 ether;
        uint256 protocolFee = 2.5 ether;
        bytes32 merkleRoot = keccak256("snapshot-pass-merkle");
        _fundOracleForIngestion(totalRewards);

        // Use the committed snapshot hash and validator set hash (matches setUp epoch 1 commit)
        bytes memory payload = abi.encode(uint256(1), totalRewards, merkleRoot, protocolFee, TEST_SNAPSHOT_HASH, bytes32(0), bytes32(0), bytes32(0));
        bytes memory attestation = _createAttestation(payload);

        vm.prank(oracle);
        vault.distributeRewards(attestation, 1, totalRewards, merkleRoot, protocolFee);

        // Verify epoch advanced and snapshot preserved in epoch 1 snapshot
        assertEq(vault.currentEpoch(), 2);
        Cruzible.EpochSnapshot memory snap = vault.getEpochSnapshot(1);
        assertEq(snap.stakeSnapshotHash, TEST_SNAPSHOT_HASH);
    }

    /// @notice distributeRewards reverts if no snapshot hash has been committed
    ///         for the current epoch (epoch-scoped stakeSnapshotHash is zero).
    function test_stakeSnapshotRejectsWhenNotCommitted() public {
        // Advance to epoch 2 by distributing for epoch 1.
        _distributeRewardsForCurrentEpoch();
        assertEq(vault.currentEpoch(), 2);

        // Do NOT commit snapshot for epoch 2.
        uint256 totalRewards = 10 ether;
        uint256 protocolFee = 0.5 ether;
        bytes32 merkleRoot = keccak256("no-commit-merkle");
        _fundOracleForIngestion(totalRewards);

        // Attestation has a non-zero snapshot hash, but epoch 2 has no commitment.
        bytes memory payload = abi.encode(uint256(2), totalRewards, merkleRoot, protocolFee, TEST_SNAPSHOT_HASH, bytes32(0), bytes32(0), bytes32(0));
        bytes memory attestation = _createAttestation(payload);

        vm.prank(oracle);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.StakeSnapshotMismatch.selector, TEST_SNAPSHOT_HASH, bytes32(0))
        );
        vault.distributeRewards(attestation, 2, totalRewards, merkleRoot, protocolFee);
    }

    /// @notice distributeRewards rejects 192-byte payload (missing
    ///         stakerRegistryRoot AND delegationRegistryRoot — only 6 of 8 required fields).
    function test_distributeRewards_rejects192BytePayload() public {
        vm.prank(alice);
        vault.stake(1000 ether);

        uint256 totalRewards = 10 ether;
        uint256 protocolFee = 0.5 ether;
        _fundOracleForIngestion(totalRewards);

        // Old 192-byte format (6 words, missing stakerRegistryRoot)
        bytes memory payload = abi.encode(uint256(1), totalRewards, bytes32(0), protocolFee, TEST_SNAPSHOT_HASH, bytes32(0));
        bytes memory attestation = _createAttestation(payload);

        vm.prank(oracle);
        vm.expectRevert(Cruzible.InvalidAttestation.selector);
        vault.distributeRewards(attestation, 1, totalRewards, bytes32(0), protocolFee);
    }

    /// @notice distributeRewards rejects 192-byte payload (variant 2)
    ///         (missing stakerRegistryRoot AND delegationRegistryRoot — only 6 of 8 required fields).
    function test_distributeRewards_rejects192BytePayloadVariant() public {
        vm.prank(alice);
        vault.stake(1000 ether);

        uint256 totalRewards = 10 ether;
        uint256 protocolFee = 0.5 ether;
        _fundOracleForIngestion(totalRewards);

        // Old 192-byte format (6 words, missing stakerRegistryRoot)
        bytes memory payload = abi.encode(uint256(1), totalRewards, bytes32(0), protocolFee, TEST_SNAPSHOT_HASH, bytes32(0));
        bytes memory attestation = _createAttestation(payload);

        vm.prank(oracle);
        vm.expectRevert(Cruzible.InvalidAttestation.selector);
        vault.distributeRewards(attestation, 1, totalRewards, bytes32(0), protocolFee);
    }

    /// @notice distributeRewards rejects old 224-byte payload format
    ///         (missing delegationRegistryRoot — only 7 of 8 required fields).
    function test_distributeRewards_rejects224BytePayload() public {
        vm.prank(alice);
        vault.stake(1000 ether);

        uint256 totalRewards = 10 ether;
        uint256 protocolFee = 0.5 ether;
        _fundOracleForIngestion(totalRewards);

        // Old 224-byte format (7 words, missing delegationRegistryRoot)
        bytes memory payload = abi.encode(uint256(1), totalRewards, bytes32(0), protocolFee, TEST_SNAPSHOT_HASH, bytes32(0), bytes32(0));
        bytes memory attestation = _createAttestation(payload);

        vm.prank(oracle);
        vm.expectRevert(Cruzible.InvalidAttestation.selector);
        vault.distributeRewards(attestation, 1, totalRewards, bytes32(0), protocolFee);
    }

    // =========================================================================
    // VALIDATOR SET HASH VERIFICATION TESTS (REWARD DISTRIBUTION)
    // =========================================================================
    //
    // distributeRewards() now verifies the attested validatorSetHash against
    // epochSnapshots[epoch].validatorSetHash — the on-chain value stored by
    // updateValidatorSet(). This anchors reward weighting to the validator
    // set the contract already accepted, with no separate admin commitment.

    /// @notice distributeRewards reverts with ValidatorSetHashMismatch if the
    ///         attested validator set hash does not match the on-chain epoch hash.
    function test_validatorSetHashMismatch() public {
        vm.prank(alice);
        vault.stake(1000 ether);

        // Establish a validator set for epoch 1 → sets epochSnapshots[1].validatorSetHash
        bytes32 epochVsHash = _setupValidators();

        uint256 totalRewards = 100 ether;
        uint256 protocolFee = 5 ether;
        bytes32 merkleRoot = keccak256("vs-mismatch-merkle");
        _fundOracleForIngestion(totalRewards);

        // Create attestation with a WRONG validator set hash (different from epoch's)
        bytes32 wrongVsHash = keccak256("wrong-validator-set");
        bytes memory payload = abi.encode(uint256(1), totalRewards, merkleRoot, protocolFee, TEST_SNAPSHOT_HASH, wrongVsHash, bytes32(0), bytes32(0));
        bytes memory attestation = _createAttestation(payload);

        // Must revert — attested hash doesn't match the on-chain epoch hash
        vm.prank(oracle);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.ValidatorSetHashMismatch.selector, wrongVsHash, epochVsHash)
        );
        vault.distributeRewards(attestation, 1, totalRewards, merkleRoot, protocolFee);
    }

    /// @notice distributeRewards succeeds when the attested validator set hash
    ///         matches the on-chain epoch snapshot hash (normal production flow).
    function test_validatorSetHashVerificationPasses() public {
        vm.prank(alice);
        vault.stake(1000 ether);

        // Establish a validator set for epoch 1 → sets epochSnapshots[1].validatorSetHash
        bytes32 epochVsHash = _setupValidators();

        uint256 totalRewards = 50 ether;
        uint256 protocolFee = 2.5 ether;
        bytes32 merkleRoot = keccak256("vs-pass-merkle");
        _fundOracleForIngestion(totalRewards);

        // Use the epoch's actual validator set hash (from updateValidatorSet)
        bytes memory payload = abi.encode(uint256(1), totalRewards, merkleRoot, protocolFee, TEST_SNAPSHOT_HASH, epochVsHash, bytes32(0), bytes32(0));
        bytes memory attestation = _createAttestation(payload);

        vm.prank(oracle);
        vault.distributeRewards(attestation, 1, totalRewards, merkleRoot, protocolFee);

        // Verify epoch advanced and snapshot hash preserved in epoch 1 snapshot
        assertEq(vault.currentEpoch(), 2);
        Cruzible.EpochSnapshot memory snap = vault.getEpochSnapshot(1);
        assertEq(snap.stakeSnapshotHash, TEST_SNAPSHOT_HASH);
    }

    /// @notice distributeRewards reverts if a non-zero validator set hash is
    ///         attested but no validator set was established for this epoch
    ///         (epochSnapshots[epoch].validatorSetHash is zero).
    function test_validatorSetHashRejectsWhenNoValidatorsEstablished() public {
        vm.prank(alice);
        vault.stake(1000 ether);

        // Do NOT call updateValidatorSet() — epochSnapshots[1].validatorSetHash stays bytes32(0)

        uint256 totalRewards = 10 ether;
        uint256 protocolFee = 0.5 ether;
        bytes32 merkleRoot = keccak256("no-vs-merkle");
        _fundOracleForIngestion(totalRewards);

        // Attestation has a non-zero validator set hash, but epoch has bytes32(0)
        bytes32 fakeVsHash = keccak256("fake-validator-set");
        bytes memory payload = abi.encode(uint256(1), totalRewards, merkleRoot, protocolFee, TEST_SNAPSHOT_HASH, fakeVsHash, bytes32(0), bytes32(0));
        bytes memory attestation = _createAttestation(payload);

        vm.prank(oracle);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.ValidatorSetHashMismatch.selector, fakeVsHash, bytes32(0))
        );
        vault.distributeRewards(attestation, 1, totalRewards, merkleRoot, protocolFee);
    }

    /// @notice distributeRewards accepts bytes32(0) validator set hash when no
    ///         validator set was established for this epoch (both sides zero).
    function test_validatorSetHashZeroMatchesWhenNoValidators() public {
        vm.prank(alice);
        vault.stake(1000 ether);

        // No updateValidatorSet() call → both sides are bytes32(0)
        uint256 totalRewards = 10 ether;
        uint256 protocolFee = 0.5 ether;
        bytes32 merkleRoot = keccak256("zero-vs-merkle");
        _fundOracleForIngestion(totalRewards);

        bytes memory payload = abi.encode(uint256(1), totalRewards, merkleRoot, protocolFee, TEST_SNAPSHOT_HASH, bytes32(0), bytes32(0), bytes32(0));
        bytes memory attestation = _createAttestation(payload);

        vm.prank(oracle);
        vault.distributeRewards(attestation, 1, totalRewards, merkleRoot, protocolFee);

        assertEq(vault.currentEpoch(), 2);
    }

    // =========================================================================
    // STAKER REGISTRY ROOT TESTS
    // =========================================================================

    /// @notice The StAETHEL accumulator starts at bytes32(0) before any stakes.
    function test_registryRoot_startsAtZero() public view {
        // No one has staked yet → accumulator is zero.
        assertEq(stAethel.stakerRegistryRoot(), bytes32(0));
    }

    /// @notice Staking updates the registry root to a non-zero value.
    function test_registryRoot_updatedOnStake() public {
        vm.prank(alice);
        vault.stake(100 ether);

        bytes32 root = stAethel.stakerRegistryRoot();
        assertTrue(root != bytes32(0), "registry root should be non-zero after stake");
    }

    /// @notice The registry root XOR accumulator is order-independent across
    ///         multiple stakers.
    function test_registryRoot_orderIndependent() public {
        // Stake alice then bob.
        vm.prank(alice);
        vault.stake(100 ether);
        vm.prank(bob);
        vault.stake(200 ether);

        bytes32 rootAB = stAethel.stakerRegistryRoot();

        // We cannot easily reset and re-stake in reverse order in the same
        // test, but we can verify the accumulator is the XOR of individual
        // contributions by computing manually.
        uint256 aliceShares = stAethel.sharesOf(alice);
        uint256 bobShares = stAethel.sharesOf(bob);

        bytes32 aliceHash = keccak256(abi.encodePacked(alice, aliceShares));
        bytes32 bobHash = keccak256(abi.encodePacked(bob, bobShares));
        bytes32 expected = aliceHash ^ bobHash;

        assertEq(rootAB, expected, "registry root should equal XOR of individual staker hashes");
    }

    /// @notice Full unstake (burn all shares) removes the staker's contribution
    ///         from the accumulator, returning it to zero for a single staker.
    function test_registryRoot_resetsAfterFullUnstake() public {
        vm.prank(alice);
        vault.stake(100 ether);

        bytes32 rootAfterStake = stAethel.stakerRegistryRoot();
        assertTrue(rootAfterStake != bytes32(0));

        uint256 aliceShares = stAethel.sharesOf(alice);
        vm.prank(alice);
        vault.unstake(aliceShares);

        assertEq(stAethel.stakerRegistryRoot(), bytes32(0), "should return to zero after full unstake");
    }

    /// @notice Transfers between users correctly update both contributions in
    ///         the accumulator.
    function test_registryRoot_updatedOnTransfer() public {
        vm.prank(alice);
        vault.stake(100 ether);

        bytes32 rootBefore = stAethel.stakerRegistryRoot();

        // Transfer half to bob.
        vm.prank(alice);
        stAethel.transfer(bob, 50 ether);

        bytes32 rootAfter = stAethel.stakerRegistryRoot();
        assertTrue(rootAfter != rootBefore, "transfer should change registry root");

        // Verify the accumulator matches manually computed XOR.
        uint256 aliceShares = stAethel.sharesOf(alice);
        uint256 bobShares = stAethel.sharesOf(bob);
        bytes32 expected = keccak256(abi.encodePacked(alice, aliceShares))
                         ^ keccak256(abi.encodePacked(bob, bobShares));
        assertEq(rootAfter, expected);
    }

    /// @notice commitStakeSnapshot captures the live registry root from
    ///         StAETHEL and stores it in the epoch snapshot.
    function test_registryRoot_capturedAtCommitTime() public {
        // Advance to epoch 2 so we can commit fresh.
        _distributeRewardsForCurrentEpoch();
        assertEq(vault.currentEpoch(), 2);

        // After the helper, alice has 100 ether staked.
        bytes32 liveRoot = stAethel.stakerRegistryRoot();
        assertTrue(liveRoot != bytes32(0), "should have non-zero root after stake");

        // Commit snapshot for epoch 2.
        uint256 shares = vault.getTotalShares();
        vm.prank(admin);
        vault.commitStakeSnapshot(2, TEST_SNAPSHOT_HASH, shares);

        // The epoch snapshot should have captured the live registry root.
        Cruzible.EpochSnapshot memory snap = vault.getEpochSnapshot(2);
        assertEq(snap.stakerRegistryRoot, liveRoot, "epoch snapshot should capture live registry root");
    }

    /// @notice distributeRewards reverts with RegistryRootMismatch if the
    ///         TEE-attested registry root does not match the committed value.
    function test_registryRootMismatch() public {
        vm.prank(alice);
        vault.stake(1000 ether);

        uint256 totalRewards = 100 ether;
        uint256 protocolFee = 5 ether;
        bytes32 merkleRoot = keccak256("registry-mismatch-merkle");
        _fundOracleForIngestion(totalRewards);

        // Epoch 1 was committed in setUp before staking → registryRoot = 0.
        // Supply a WRONG (non-zero) registry root in the payload.
        bytes32 wrongRoot = keccak256("wrong-registry-root");
        bytes memory payload = abi.encode(uint256(1), totalRewards, merkleRoot, protocolFee, TEST_SNAPSHOT_HASH, bytes32(0), wrongRoot, bytes32(0));
        bytes memory attestation = _createAttestation(payload);

        vm.prank(oracle);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.RegistryRootMismatch.selector, wrongRoot, bytes32(0))
        );
        vault.distributeRewards(attestation, 1, totalRewards, merkleRoot, protocolFee);
    }

    // =========================================================================
    // DELEGATION REGISTRY ROOT TESTS
    // =========================================================================

    /// @notice distributeRewards preserves the committed delegation registry root
    ///         in the finalized epoch snapshot.
    function test_delegationRegistryRoot_storedInSnapshot() public {
        vm.prank(alice);
        vault.stake(1000 ether);

        // Commit a specific delegation root for epoch 1.
        // stakerRegistryRoot was captured at commitStakeSnapshot() time (setUp,
        // before any staking) → bytes32(0).
        bytes32 testDelRoot = keccak256("specific-delegation-root");
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes memory delAtt = _createDelegationAttestation(1, testDelRoot, snapPre.stakerRegistryRoot);
        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, testDelRoot, snapPre.stakerRegistryRoot, 1);

        // Fast-forward past the delegation challenge period.
        vm.warp(block.timestamp + vault.DELEGATION_CHALLENGE_PERIOD() + 1);

        uint256 totalRewards = 10 ether;
        uint256 protocolFee = 0.5 ether;
        bytes32 merkleRoot = keccak256("del-root-test");
        _fundOracleForIngestion(totalRewards);

        // Attestation must use the same delegation root as the commitment.
        bytes memory payload = abi.encode(
            uint256(1), totalRewards, merkleRoot, protocolFee,
            TEST_SNAPSHOT_HASH, bytes32(0), bytes32(0), testDelRoot
        );
        bytes memory attestation = _createAttestation(payload);

        vm.prank(oracle);
        vault.distributeRewards(attestation, 1, totalRewards, merkleRoot, protocolFee);

        // Verify the committed delegation root was preserved in the finalized snapshot.
        Cruzible.EpochSnapshot memory snap = vault.getEpochSnapshot(1);
        assertEq(snap.delegationRegistryRoot, testDelRoot);
        assertTrue(snap.finalized);
    }

    /// @notice Keeper can commit the epoch-scoped delegation registry root.
    function test_commitDelegationSnapshot() public {
        // setUp committed stake snapshot for epoch 1 (stakerRegistryRoot = bytes32(0)).
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("test-del-commitment");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);
        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        Cruzible.EpochSnapshot memory snap = vault.getEpochSnapshot(1);
        assertEq(snap.delegationRegistryRoot, delRoot);
    }

    /// @notice Non-keeper cannot commit the delegation registry root.
    function test_commitDelegationSnapshot_onlyKeeper() public {
        bytes memory delAtt = _createDelegationAttestation(1, keccak256("malicious-delegation"), bytes32(0));
        vm.prank(alice);
        vm.expectRevert();
        vault.commitDelegationSnapshot(delAtt, 1, keccak256("malicious-delegation"), bytes32(0), 1);
    }

    /// @notice Delegation commitment is immutable per epoch.
    function test_commitDelegationSnapshot_alreadyCommitted() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes memory delAtt1 = _createDelegationAttestation(1, keccak256("first-delegation"), snapPre.stakerRegistryRoot);
        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt1, 1, keccak256("first-delegation"), snapPre.stakerRegistryRoot, 1);

        bytes memory delAtt2 = _createDelegationAttestation(1, keccak256("second-delegation"), snapPre.stakerRegistryRoot);
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.DelegationSnapshotAlreadyCommitted.selector, uint256(1))
        );
        vault.commitDelegationSnapshot(delAtt2, 1, keccak256("second-delegation"), snapPre.stakerRegistryRoot, 1);
    }

    /// @notice Delegation commitment must target the current epoch.
    function test_commitDelegationSnapshot_rejectsWrongEpoch() public {
        bytes memory delAtt = _createDelegationAttestation(99, keccak256("future-epoch"), bytes32(0));
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.InvalidEpoch.selector, uint256(99), uint256(1))
        );
        vault.commitDelegationSnapshot(delAtt, 99, keccak256("future-epoch"), bytes32(0), 1);
    }

    /// @notice commitDelegationSnapshot reverts if stake snapshot has not been
    ///         committed for this epoch (ordering dependency).
    function test_commitDelegationSnapshot_requiresStakeSnapshotFirst() public {
        // Advance to epoch 2 — no stake snapshot committed for epoch 2.
        _distributeRewardsForCurrentEpoch();
        assertEq(vault.currentEpoch(), 2);

        bytes memory delAtt = _createDelegationAttestation(2, keccak256("delegation"), bytes32(0));
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.StakeSnapshotNotCommitted.selector, uint256(2))
        );
        vault.commitDelegationSnapshot(delAtt, 2, keccak256("delegation"), bytes32(0), 1);
    }

    /// @notice commitDelegationSnapshot reverts if the supplied staker registry
    ///         root does not match the on-chain value captured at stake snapshot time.
    function test_commitDelegationSnapshot_rejectsRegistryAnchorMismatch() public {
        // setUp committed stake snapshot for epoch 1 with stakerRegistryRoot = bytes32(0).
        bytes32 wrongAnchor = keccak256("wrong-registry-anchor");
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);

        bytes memory delAtt = _createDelegationAttestation(1, keccak256("delegation"), wrongAnchor);
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                Cruzible.StakerRegistryAnchorMismatch.selector,
                wrongAnchor,
                snapPre.stakerRegistryRoot
            )
        );
        vault.commitDelegationSnapshot(delAtt, 1, keccak256("delegation"), wrongAnchor, 1);
    }

    /// @notice distributeRewards reverts with DelegationRootMismatch if the
    ///         attested delegation root does not match the committed value.
    function test_delegationRootMismatch() public {
        vm.prank(alice);
        vault.stake(1000 ether);

        // Commit a specific delegation root for epoch 1.
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 committedRoot = keccak256("committed-delegation-root");
        bytes memory delAtt = _createDelegationAttestation(1, committedRoot, snapPre.stakerRegistryRoot);
        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, committedRoot, snapPre.stakerRegistryRoot, 1);

        uint256 totalRewards = 10 ether;
        uint256 protocolFee = 0.5 ether;
        bytes32 merkleRoot = keccak256("del-mismatch-merkle");
        _fundOracleForIngestion(totalRewards);

        // Attestation has a DIFFERENT delegation root.
        bytes32 wrongRoot = keccak256("wrong-delegation-root");
        bytes memory payload = abi.encode(
            uint256(1), totalRewards, merkleRoot, protocolFee,
            TEST_SNAPSHOT_HASH, bytes32(0), bytes32(0), wrongRoot
        );
        bytes memory attestation = _createAttestation(payload);

        vm.prank(oracle);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.DelegationRootMismatch.selector, wrongRoot, committedRoot)
        );
        vault.distributeRewards(attestation, 1, totalRewards, merkleRoot, protocolFee);
    }

    /// @notice distributeRewards reverts when a non-zero delegation root is
    ///         attested but no delegation snapshot was committed for the epoch.
    function test_delegationSnapshotRejectsWhenNotCommitted() public {
        vm.prank(alice);
        vault.stake(1000 ether);

        // Do NOT commit delegation root for epoch 1.
        uint256 totalRewards = 10 ether;
        uint256 protocolFee = 0.5 ether;
        bytes32 merkleRoot = keccak256("no-del-commit-merkle");
        _fundOracleForIngestion(totalRewards);

        // Attestation has a non-zero delegation root, but epoch has no commitment.
        bytes32 nonZeroDelRoot = keccak256("uncommitted-delegation-root");
        bytes memory payload = abi.encode(
            uint256(1), totalRewards, merkleRoot, protocolFee,
            TEST_SNAPSHOT_HASH, bytes32(0), bytes32(0), nonZeroDelRoot
        );
        bytes memory attestation = _createAttestation(payload);

        vm.prank(oracle);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.DelegationRootMismatch.selector, nonZeroDelRoot, bytes32(0))
        );
        vault.distributeRewards(attestation, 1, totalRewards, merkleRoot, protocolFee);
    }

    /// @notice distributeRewards succeeds when both the attested and committed
    ///         delegation roots match a non-zero value (normal production flow).
    function test_delegationRootVerificationPasses() public {
        vm.prank(alice);
        vault.stake(1000 ether);

        // Commit a delegation root for epoch 1.
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("verified-delegation-root");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);
        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        // Fast-forward past the delegation challenge period.
        vm.warp(block.timestamp + vault.DELEGATION_CHALLENGE_PERIOD() + 1);

        uint256 totalRewards = 10 ether;
        uint256 protocolFee = 0.5 ether;
        bytes32 merkleRoot = keccak256("del-pass-merkle");
        _fundOracleForIngestion(totalRewards);

        // Attestation uses the same delegation root as the commitment.
        bytes memory payload = abi.encode(
            uint256(1), totalRewards, merkleRoot, protocolFee,
            TEST_SNAPSHOT_HASH, bytes32(0), bytes32(0), delRoot
        );
        bytes memory attestation = _createAttestation(payload);

        vm.prank(oracle);
        vault.distributeRewards(attestation, 1, totalRewards, merkleRoot, protocolFee);

        assertEq(vault.currentEpoch(), 2);
        Cruzible.EpochSnapshot memory snap = vault.getEpochSnapshot(1);
        assertEq(snap.delegationRegistryRoot, delRoot);
    }

    // =========================================================================
    // DELEGATION CHALLENGE PERIOD
    // =========================================================================

    /// @notice distributeRewards reverts when called during the delegation
    ///         challenge period (non-zero delegation root committed but
    ///         DELEGATION_CHALLENGE_PERIOD has not yet elapsed).
    function test_delegationChallengePeriodActive() public {
        vm.prank(alice);
        vault.stake(1000 ether);

        // Commit a non-zero delegation root for epoch 1.
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("challenge-test-delegation");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);
        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        // Do NOT warp — still within the challenge period.
        uint256 totalRewards = 10 ether;
        uint256 protocolFee = 0.5 ether;
        bytes32 merkleRoot = keccak256("challenge-merkle");
        _fundOracleForIngestion(totalRewards);

        bytes memory payload = abi.encode(
            uint256(1), totalRewards, merkleRoot, protocolFee,
            TEST_SNAPSHOT_HASH, bytes32(0), bytes32(0), delRoot
        );
        bytes memory attestation = _createAttestation(payload);

        uint256 expectedAvailableAt = block.timestamp + vault.DELEGATION_CHALLENGE_PERIOD();
        vm.prank(oracle);
        vm.expectRevert(
            abi.encodeWithSelector(
                Cruzible.DelegationChallengePeriodActive.selector,
                uint256(1),
                expectedAvailableAt
            )
        );
        vault.distributeRewards(attestation, 1, totalRewards, merkleRoot, protocolFee);
    }

    /// @notice distributeRewards skips the challenge period check when the
    ///         delegation root is bytes32(0) (no delegation topology committed).
    function test_delegationChallengePeriodSkippedForZeroRoot() public {
        vm.prank(alice);
        vault.stake(1000 ether);

        // Do NOT commit any delegation root — it stays bytes32(0).
        // Do NOT warp — challenge period would block if it applied to zero roots.
        uint256 totalRewards = 10 ether;
        uint256 protocolFee = 0.5 ether;
        bytes32 merkleRoot = keccak256("zero-del-merkle");
        _fundOracleForIngestion(totalRewards);

        // Attestation with bytes32(0) delegation root.
        bytes memory payload = abi.encode(
            uint256(1), totalRewards, merkleRoot, protocolFee,
            TEST_SNAPSHOT_HASH, bytes32(0), bytes32(0), bytes32(0)
        );
        bytes memory attestation = _createAttestation(payload);

        vm.prank(oracle);
        vault.distributeRewards(attestation, 1, totalRewards, merkleRoot, protocolFee);

        // Should succeed — epoch advanced.
        assertEq(vault.currentEpoch(), 2);
    }

    // =========================================================================
    // GUARDIAN DELEGATION REVOCATION
    // =========================================================================

    /// @notice Guardian can revoke a delegation commitment during the challenge
    ///         period, clearing the root and timestamp so the keeper can re-commit.
    function test_revokeDelegationSnapshot() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("revocable-delegation");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);
        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        // Verify it was committed.
        Cruzible.EpochSnapshot memory snapMid = vault.getEpochSnapshot(1);
        assertEq(snapMid.delegationRegistryRoot, delRoot);
        assertGt(vault.delegationCommitTimestamp(1), 0);

        // Guardian revokes.
        vm.prank(admin); // admin has GUARDIAN_ROLE
        vault.revokeDelegationSnapshot(1);

        // Verify cleared.
        Cruzible.EpochSnapshot memory snapPost = vault.getEpochSnapshot(1);
        assertEq(snapPost.delegationRegistryRoot, bytes32(0));
        assertEq(vault.delegationCommitTimestamp(1), 0);
    }

    /// @notice Only GUARDIAN_ROLE can revoke a delegation commitment.
    function test_revokeDelegationSnapshot_onlyGuardian() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("guardian-only-del");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);
        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        vm.prank(alice);
        vm.expectRevert();
        vault.revokeDelegationSnapshot(1);
    }

    /// @notice revokeDelegationSnapshot reverts when no delegation root is committed.
    function test_revokeDelegationSnapshot_rejectsWhenNotCommitted() public {
        // No delegation root committed for epoch 1.
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.DelegationNotCommitted.selector, uint256(1))
        );
        vault.revokeDelegationSnapshot(1);
    }

    /// @notice Full flow: keeper commits → guardian revokes → keeper re-commits →
    ///         challenge period passes → distributeRewards succeeds.
    function test_delegationRecommitmentAfterRevocation() public {
        vm.prank(alice);
        vault.stake(1000 ether);

        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 badRoot = keccak256("fraudulent-delegation");
        bytes memory badAtt = _createDelegationAttestation(1, badRoot, snapPre.stakerRegistryRoot);
        vm.prank(admin);
        vault.commitDelegationSnapshot(badAtt, 1, badRoot, snapPre.stakerRegistryRoot, 1);

        // Guardian detects fraud and revokes.
        vm.prank(admin);
        vault.revokeDelegationSnapshot(1);

        // Keeper re-commits the correct root.
        bytes32 goodRoot = keccak256("corrected-delegation");
        bytes memory goodAtt = _createDelegationAttestation(1, goodRoot, snapPre.stakerRegistryRoot);
        vm.prank(admin);
        vault.commitDelegationSnapshot(goodAtt, 1, goodRoot, snapPre.stakerRegistryRoot, 1);

        // Fast-forward past the challenge period for the new commitment.
        vm.warp(block.timestamp + vault.DELEGATION_CHALLENGE_PERIOD() + 1);

        uint256 totalRewards = 10 ether;
        uint256 protocolFee = 0.5 ether;
        bytes32 merkleRoot = keccak256("recommit-merkle");
        _fundOracleForIngestion(totalRewards);

        bytes memory payload = abi.encode(
            uint256(1), totalRewards, merkleRoot, protocolFee,
            TEST_SNAPSHOT_HASH, bytes32(0), bytes32(0), goodRoot
        );
        bytes memory attestation = _createAttestation(payload);

        vm.prank(oracle);
        vault.distributeRewards(attestation, 1, totalRewards, merkleRoot, protocolFee);

        assertEq(vault.currentEpoch(), 2);
        Cruzible.EpochSnapshot memory snap = vault.getEpochSnapshot(1);
        assertEq(snap.delegationRegistryRoot, goodRoot);
        assertTrue(snap.finalized);
    }

    // =========================================================================
    // DELEGATION TEE ATTESTATION VERIFICATION
    // =========================================================================

    /// @notice commitDelegationSnapshot reverts when the TEE attestation
    ///         payload does not match the supplied delegation parameters.
    function test_commitDelegationSnapshot_rejectsMismatchedAttestation() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("attested-delegation");

        // Create an attestation for a DIFFERENT delegation root.
        bytes32 wrongRoot = keccak256("wrong-attested-delegation");
        bytes memory badAtt = _createDelegationAttestation(1, wrongRoot, snapPre.stakerRegistryRoot);

        vm.prank(admin);
        vm.expectRevert(Cruzible.DelegationAttestationInvalid.selector);
        vault.commitDelegationSnapshot(badAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);
    }

    /// @notice commitDelegationSnapshot reverts when the TEE attestation
    ///         has a wrong payload length (not 96 bytes).
    function test_commitDelegationSnapshot_rejectsWrongPayloadLength() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("length-test-delegation");

        // Create an attestation with a 256-byte payload (reward format, not delegation).
        bytes memory wrongPayload = abi.encode(
            uint256(1), uint256(0), bytes32(0), uint256(0),
            bytes32(0), bytes32(0), bytes32(0), delRoot
        );
        bytes memory badAtt = _createAttestation(wrongPayload);

        vm.prank(admin);
        vm.expectRevert(Cruzible.DelegationAttestationInvalid.selector);
        vault.commitDelegationSnapshot(badAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);
    }

    /// @notice commitDelegationSnapshot reverts with an invalid (garbage) attestation.
    function test_commitDelegationSnapshot_rejectsInvalidAttestation() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("invalid-att-delegation");

        vm.prank(admin);
        vm.expectRevert();
        vault.commitDelegationSnapshot(hex"deadbeef", 1, delRoot, snapPre.stakerRegistryRoot, 1);
    }

    // =========================================================================
    // DELEGATION BRIDGE TRUST MODEL HARDENING TESTS
    //
    // These tests exercise the staleness guard (DELEGATION_MAX_AGE),
    // cardinality anchor (delegatingStakerCount), and guardian revocation
    // clearing of the cardinality slot.
    // =========================================================================

    /// @notice distributeRewards reverts when the delegation commitment is older
    ///         than DELEGATION_MAX_AGE, even if the challenge period has passed.
    function test_distributeRewards_rejectsStaleDelegation() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("stale-delegation");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        // Warp past DELEGATION_MAX_AGE (6 hours + 1 second).
        vm.warp(block.timestamp + vault.DELEGATION_MAX_AGE() + 1);

        // Attempt to distribute rewards — should revert with staleness error.
        uint256 totalRewards = 10 ether;
        uint256 protocolFee = (totalRewards * 500) / 10000;
        bytes32 merkleRoot = keccak256("stale-merkle");
        bytes memory rewardPayload = abi.encode(
            uint256(1), totalRewards, merkleRoot, protocolFee,
            snapPre.stakeSnapshotHash, snapPre.validatorSetHash,
            snapPre.stakerRegistryRoot, delRoot
        );
        bytes memory rewardAtt = _createAttestation(rewardPayload);

        aethel.mint(oracle, totalRewards);
        vm.prank(oracle);
        aethel.approve(address(vault), totalRewards);
        vm.expectRevert(
            abi.encodeWithSelector(
                Cruzible.DelegationCommitmentStale.selector,
                1, block.timestamp - vault.DELEGATION_MAX_AGE() - 1, vault.DELEGATION_MAX_AGE()
            )
        );
        vm.prank(oracle);
        vault.distributeRewards(rewardAtt, 1, totalRewards, merkleRoot, protocolFee);
    }

    /// @notice distributeRewards succeeds when delegation commitment is fresh
    ///         (within both challenge period and max-age window).
    function test_distributeRewards_acceptsFreshDelegation() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("fresh-delegation");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 5);

        // Warp past challenge period but within max-age window.
        vm.warp(block.timestamp + vault.DELEGATION_CHALLENGE_PERIOD() + 1);

        // Verify cardinality was stored.
        assertEq(vault.delegatingStakerCount(1), 5);

        uint256 totalRewards = 10 ether;
        uint256 protocolFee = (totalRewards * 500) / 10000;
        bytes32 merkleRoot = keccak256("fresh-merkle");
        bytes memory rewardPayload = abi.encode(
            uint256(1), totalRewards, merkleRoot, protocolFee,
            snapPre.stakeSnapshotHash, snapPre.validatorSetHash,
            snapPre.stakerRegistryRoot, delRoot
        );
        bytes memory rewardAtt = _createAttestation(rewardPayload);

        aethel.mint(oracle, totalRewards);
        vm.prank(oracle);
        aethel.approve(address(vault), totalRewards);
        vm.prank(oracle);
        vault.distributeRewards(rewardAtt, 1, totalRewards, merkleRoot, protocolFee);

        assertTrue(vault.getEpochSnapshot(1).finalized);
    }

    /// @notice commitDelegationSnapshot rejects zero staker count with non-zero root.
    function test_commitDelegation_rejectsZeroCardinalityWithNonZeroRoot() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("nonzero-root");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                Cruzible.DelegationCardinalityZeroWithNonZeroRoot.selector, 1
            )
        );
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 0);
    }

    /// @notice commitDelegationSnapshot accepts zero root with zero count (no delegation data).
    function test_commitDelegation_acceptsZeroRootWithZeroCount() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = bytes32(0);
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 0);

        assertEq(vault.delegatingStakerCount(1), 0);
    }

    /// @notice Guardian revocation clears the cardinality anchor alongside the root.
    function test_revokeDelegation_clearsCardinality() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("revoke-cardinality");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 42);
        assertEq(vault.delegatingStakerCount(1), 42);

        // Guardian revokes.
        vm.prank(admin);
        vault.revokeDelegationSnapshot(1);

        // Cardinality must be cleared.
        assertEq(vault.delegatingStakerCount(1), 0);
    }

    // =========================================================================
    // DELEGATION BRIDGE HARDENING TESTS
    //
    // These tests exercise the multi-attestor quorum, keeper bond/slash,
    // and permissionless challenge mechanisms that harden the delegation
    // bridge trust model.
    // =========================================================================

    // --- Multi-attestor quorum ---

    /// @notice submitDelegationVote requires DELEGATION_ATTESTOR_ROLE.
    function test_submitDelegationVote_requiresAttestorRole() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("vote-root");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(alice);
        vm.expectRevert();
        vault.submitDelegationVote(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);
    }

    /// @notice submitDelegationVote requires the attestor to have posted a bond.
    function test_submitDelegationVote_requiresBond() public {
        // Create attestor with role but no bond
        address attestor1 = makeAddr("attestor1");
        bytes32 attestorRole = vault.DELEGATION_ATTESTOR_ROLE();
        uint256 bondMinimum = vault.KEEPER_BOND_MINIMUM();
        vm.prank(admin);
        vault.grantRole(attestorRole, attestor1);

        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("vote-root-nobond");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(attestor1);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.InsufficientKeeperBond.selector, uint256(0), bondMinimum)
        );
        vault.submitDelegationVote(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);
    }

    /// @notice A single attestor vote does not commit (quorum = 2).
    function test_submitDelegationVote_singleVoteDoesNotCommit() public {
        address attestor1 = makeAddr("attestor1");
        bytes32 attestorRole = vault.DELEGATION_ATTESTOR_ROLE();
        vm.prank(admin);
        vault.grantRole(attestorRole, attestor1);
        _depositKeeperBond(attestor1);

        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("quorum-root");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(attestor1);
        vault.submitDelegationVote(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        // Vote is recorded but root is NOT committed (quorum not reached).
        assertEq(vault.delegationVoteCount(1, delRoot), 1);
        Cruzible.EpochSnapshot memory snap = vault.getEpochSnapshot(1);
        assertEq(snap.delegationRegistryRoot, bytes32(0));
    }

    /// @notice Two attestors agreeing on the same root auto-commits.
    function test_submitDelegationVote_quorumCommits() public {
        address attestor1 = makeAddr("attestor1");
        address attestor2 = makeAddr("attestor2");
        bytes32 attestorRole = vault.DELEGATION_ATTESTOR_ROLE();
        vm.startPrank(admin);
        vault.grantRole(attestorRole, attestor1);
        vault.grantRole(attestorRole, attestor2);
        vm.stopPrank();
        _depositKeeperBond(attestor1);
        _depositKeeperBond(attestor2);

        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("quorum-root-2");

        // Each attestor creates their own attestation (different block timestamps
        // to avoid TEE nonce collision).
        bytes memory delAtt1 = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        // First vote
        vm.prank(attestor1);
        vault.submitDelegationVote(delAtt1, 1, delRoot, snapPre.stakerRegistryRoot, 5);

        // Advance 1 second so second attestor's attestation has a unique nonce
        vm.warp(block.timestamp + 1);
        bytes memory delAtt2 = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        // Second vote — quorum reached, should auto-commit
        vm.prank(attestor2);
        vault.submitDelegationVote(delAtt2, 1, delRoot, snapPre.stakerRegistryRoot, 5);

        // Root is now committed.
        Cruzible.EpochSnapshot memory snap = vault.getEpochSnapshot(1);
        assertEq(snap.delegationRegistryRoot, delRoot);
        assertEq(vault.delegatingStakerCount(1), 5);
        assertTrue(vault.delegationCommitTimestamp(1) > 0);
    }

    /// @notice An attestor cannot vote twice for the same epoch.
    function test_submitDelegationVote_rejectsDoubleVote() public {
        address attestor1 = makeAddr("attestor1");
        bytes32 attestorRole = vault.DELEGATION_ATTESTOR_ROLE();
        vm.prank(admin);
        vault.grantRole(attestorRole, attestor1);
        _depositKeeperBond(attestor1);

        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("double-vote");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(attestor1);
        vault.submitDelegationVote(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        // Advance time so nonce differs
        vm.warp(block.timestamp + 1);
        bytes memory delAtt2 = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(attestor1);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.DelegationAttestorAlreadyVoted.selector, uint256(1), attestor1)
        );
        vault.submitDelegationVote(delAtt2, 1, delRoot, snapPre.stakerRegistryRoot, 1);
    }

    /// @notice Attestors voting for different roots do not reach quorum.
    function test_submitDelegationVote_disagreementNoCommit() public {
        address attestor1 = makeAddr("attestor1");
        address attestor2 = makeAddr("attestor2");
        bytes32 attestorRole = vault.DELEGATION_ATTESTOR_ROLE();
        vm.startPrank(admin);
        vault.grantRole(attestorRole, attestor1);
        vault.grantRole(attestorRole, attestor2);
        vm.stopPrank();
        _depositKeeperBond(attestor1);
        _depositKeeperBond(attestor2);

        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 rootA = keccak256("root-A");
        bytes32 rootB = keccak256("root-B");
        bytes memory attA = _createDelegationAttestation(1, rootA, snapPre.stakerRegistryRoot);

        vm.prank(attestor1);
        vault.submitDelegationVote(attA, 1, rootA, snapPre.stakerRegistryRoot, 1);

        vm.warp(block.timestamp + 1);
        bytes memory attB = _createDelegationAttestation(1, rootB, snapPre.stakerRegistryRoot);

        vm.prank(attestor2);
        vault.submitDelegationVote(attB, 1, rootB, snapPre.stakerRegistryRoot, 1);

        // Neither root has quorum — delegation is not committed.
        assertEq(vault.delegationVoteCount(1, rootA), 1);
        assertEq(vault.delegationVoteCount(1, rootB), 1);
        Cruzible.EpochSnapshot memory snap = vault.getEpochSnapshot(1);
        assertEq(snap.delegationRegistryRoot, bytes32(0));
    }

    /// @notice When quorum mode is enabled, commitDelegationSnapshot reverts.
    function test_commitDelegationSnapshot_blockedWhenQuorumEnabled() public {
        vm.prank(admin);
        vault.setDelegationQuorumEnabled(true);

        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("quorum-blocked");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.DelegationQuorumRequired.selector, uint256(1))
        );
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);
    }

    // --- Keeper bond ---

    /// @notice depositKeeperBond transfers tokens and updates state.
    function test_depositKeeperBond() public {
        address keeper = makeAddr("new-keeper");
        uint256 bondAmount = vault.KEEPER_BOND_MINIMUM();
        aethel.mint(keeper, bondAmount);

        vm.startPrank(keeper);
        aethel.approve(address(vault), bondAmount);
        vault.depositKeeperBond(bondAmount);
        vm.stopPrank();

        assertEq(vault.keeperBonds(keeper), bondAmount);
        assertEq(vault.totalKeeperBonds(), bondAmount + vault.KEEPER_BOND_MINIMUM()); // admin also bonded in setUp
    }

    /// @notice withdrawKeeperBond returns tokens.
    function test_withdrawKeeperBond() public {
        address keeper = makeAddr("withdraw-keeper");
        uint256 bondAmount = vault.KEEPER_BOND_MINIMUM();
        aethel.mint(keeper, bondAmount);

        vm.startPrank(keeper);
        aethel.approve(address(vault), bondAmount);
        vault.depositKeeperBond(bondAmount);

        uint256 balBefore = aethel.balanceOf(keeper);
        vault.withdrawKeeperBond(bondAmount);
        vm.stopPrank();

        assertEq(vault.keeperBonds(keeper), 0);
        assertEq(aethel.balanceOf(keeper), balBefore + bondAmount);
    }

    /// @notice withdrawKeeperBond reverts if withdrawal exceeds deposit.
    function test_withdrawKeeperBond_exceedsDeposit() public {
        address keeper = makeAddr("over-withdraw");
        vm.prank(keeper);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.BondWithdrawalExceedsDeposit.selector, uint256(1 ether), uint256(0))
        );
        vault.withdrawKeeperBond(1 ether);
    }

    /// @notice withdrawKeeperBond is locked when the keeper has a pending
    ///         delegation commitment in the current epoch.
    function test_withdrawKeeperBond_lockedDuringChallenge() public {
        // Use an attestor who commits via the quorum path
        address attestor1 = makeAddr("lock-attestor1");
        address attestor2 = makeAddr("lock-attestor2");
        bytes32 attestorRole = vault.DELEGATION_ATTESTOR_ROLE();
        vm.startPrank(admin);
        vault.grantRole(attestorRole, attestor1);
        vault.grantRole(attestorRole, attestor2);
        vm.stopPrank();
        _depositKeeperBond(attestor1);
        _depositKeeperBond(attestor2);

        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("lock-test-root");

        bytes memory delAtt1 = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);
        vm.prank(attestor1);
        vault.submitDelegationVote(delAtt1, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        // Advance time for unique nonce
        vm.warp(block.timestamp + 1);
        bytes memory delAtt2 = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);
        vm.prank(attestor2);
        vault.submitDelegationVote(delAtt2, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        // attestor1 voted and commitment is pending — bond is locked
        uint256 bondMinimum = vault.KEEPER_BOND_MINIMUM();
        vm.prank(attestor1);
        vm.expectRevert(abi.encodeWithSelector(Cruzible.KeeperBondLocked.selector));
        vault.withdrawKeeperBond(bondMinimum);
    }

    /// @notice withdrawKeeperBond is locked for single-keeper committer during challenge window.
    function test_withdrawKeeperBond_lockedDuringChallenge_singleKeeper() public {
        // admin has KEEPER_ROLE and a bond from setUp
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("single-keeper-lock-root");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        // Commit via single-keeper path
        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        // admin committed via single-keeper path — bond should be locked
        uint256 bondMinimum = vault.KEEPER_BOND_MINIMUM();
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(Cruzible.KeeperBondLocked.selector));
        vault.withdrawKeeperBond(bondMinimum);
    }

    /// @notice Guardian fraud revocation freezes keeper bond — cannot withdraw until slashed or released.
    function test_withdrawKeeperBond_frozenAfterGuardianRevocation_singleKeeper() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("single-keeper-freeze-root");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        // Locked during challenge window
        uint256 bondMinimum = vault.KEEPER_BOND_MINIMUM();
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(Cruzible.KeeperBondLocked.selector));
        vault.withdrawKeeperBond(bondMinimum);

        // Guardian revokes the delegation (fraud determination)
        vm.prank(admin);
        vault.revokeDelegationSnapshot(1);

        // Bond is now frozen — still cannot withdraw despite root being zero
        assertTrue(vault.keeperBondFrozen(admin));
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(Cruzible.KeeperBondIsFrozen.selector, admin));
        vault.withdrawKeeperBond(bondMinimum);
    }

    /// @notice Slashing clears the freeze and allows withdrawal of remaining bond.
    function test_slashKeeperBond_clearsFreezeAndAllowsWithdrawal() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("slash-clears-freeze");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        // Guardian revokes (freezes bond)
        vm.prank(admin);
        vault.revokeDelegationSnapshot(1);
        assertTrue(vault.keeperBondFrozen(admin));

        // Guardian slashes half the bond
        uint256 bondMinimum = vault.KEEPER_BOND_MINIMUM();
        uint256 slashAmount = bondMinimum / 2;
        vm.prank(admin);
        vault.slashKeeperBond(admin, slashAmount, treasury);

        // Freeze cleared — remaining bond is withdrawable
        assertFalse(vault.keeperBondFrozen(admin));
        assertEq(vault.keeperBonds(admin), bondMinimum - slashAmount);

        vm.prank(admin);
        vault.withdrawKeeperBond(bondMinimum - slashAmount);
        assertEq(vault.keeperBonds(admin), 0);
    }

    /// @notice releaseKeeperBondFreeze allows guardian to unfreeze without slashing.
    function test_releaseKeeperBondFreeze() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("release-freeze");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        // Guardian revokes (freezes bond)
        vm.prank(admin);
        vault.revokeDelegationSnapshot(1);
        assertTrue(vault.keeperBondFrozen(admin));

        // Guardian decides not to slash — releases freeze
        vm.prank(admin);
        vault.releaseKeeperBondFreeze(admin);
        assertFalse(vault.keeperBondFrozen(admin));

        // Now withdrawal succeeds
        uint256 bondMinimum = vault.KEEPER_BOND_MINIMUM();
        vm.prank(admin);
        vault.withdrawKeeperBond(bondMinimum);
        assertEq(vault.keeperBonds(admin), 0);
    }

    /// @notice releaseKeeperBondFreeze rejects if not frozen.
    function test_releaseKeeperBondFreeze_rejectsNotFrozen() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.KeeperBondNotFrozen.selector, alice)
        );
        vault.releaseKeeperBondFreeze(alice);
    }

    /// @notice releaseKeeperBondFreeze is guardian-only.
    function test_releaseKeeperBondFreeze_onlyGuardian() public {
        vm.prank(alice);
        vm.expectRevert();
        vault.releaseKeeperBondFreeze(admin);
    }

    /// @notice confirmDelegationFraud also freezes the keeper's bond.
    function test_confirmDelegationFraud_freezesKeeperBond() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("confirm-freezes-keeper");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        // Auto-revoke (three challengers)
        vm.prank(alice);
        vault.challengeDelegationCommitment(1);
        vm.prank(bob);
        vault.challengeDelegationCommitment(1);
        vm.prank(charlie);
        vault.challengeDelegationCommitment(1);

        // Not frozen yet (auto-revoke is circuit-breaker, not fraud confirmation)
        assertFalse(vault.keeperBondFrozen(admin));

        // Guardian confirms fraud
        vm.prank(admin);
        vault.confirmDelegationFraud(1);

        // Now keeper bond is frozen
        assertTrue(vault.keeperBondFrozen(admin));

        // Cannot withdraw
        uint256 bondMinimum = vault.KEEPER_BOND_MINIMUM();
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(Cruzible.KeeperBondIsFrozen.selector, admin));
        vault.withdrawKeeperBond(bondMinimum);
    }

    /// @notice Guardian fraud revocation freezes ALL quorum attestors, not just the single-keeper committer.
    ///         Regression: _freezeDelegationSubmitters must iterate delegationEpochAttestors[].
    function test_guardianRevoke_freezesQuorumAttestors() public {
        address attestor1 = makeAddr("freezeAttestor1");
        address attestor2 = makeAddr("freezeAttestor2");
        bytes32 attestorRole = vault.DELEGATION_ATTESTOR_ROLE();

        // Grant attestor role and deposit keeper bonds for both attestors.
        vm.startPrank(admin);
        vault.grantRole(attestorRole, attestor1);
        vault.grantRole(attestorRole, attestor2);
        vm.stopPrank();
        _depositKeeperBond(attestor1);
        _depositKeeperBond(attestor2);

        // Enable quorum mode (attestor quorum instead of single-keeper).
        vm.prank(admin);
        vault.setDelegationQuorumEnabled(true);

        // Both attestors vote for the same root — reaching quorum and auto-committing.
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("quorum-freeze-root");
        bytes memory delAtt1 = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(attestor1);
        vault.submitDelegationVote(delAtt1, 1, delRoot, snapPre.stakerRegistryRoot, 5);

        vm.warp(block.timestamp + 1);
        bytes memory delAtt2 = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(attestor2);
        vault.submitDelegationVote(delAtt2, 1, delRoot, snapPre.stakerRegistryRoot, 5);

        // Confirm root was committed via quorum.
        Cruzible.EpochSnapshot memory snap = vault.getEpochSnapshot(1);
        assertEq(snap.delegationRegistryRoot, delRoot);

        // Verify getDelegationEpochAttestors returns both attestors.
        address[] memory attestors = vault.getDelegationEpochAttestors(1);
        assertEq(attestors.length, 2);

        // Neither should be frozen before guardian action.
        assertFalse(vault.keeperBondFrozen(attestor1));
        assertFalse(vault.keeperBondFrozen(attestor2));

        // Guardian revokes the fraudulent delegation snapshot — should freeze both attestors.
        vm.prank(admin);
        vault.revokeDelegationSnapshot(1);

        // Both attestors' bonds must be frozen.
        assertTrue(vault.keeperBondFrozen(attestor1), "attestor1 bond not frozen after revocation");
        assertTrue(vault.keeperBondFrozen(attestor2), "attestor2 bond not frozen after revocation");

        // Neither can withdraw while frozen.
        uint256 bondMinimum = vault.KEEPER_BOND_MINIMUM();
        vm.prank(attestor1);
        vm.expectRevert(abi.encodeWithSelector(Cruzible.KeeperBondIsFrozen.selector, attestor1));
        vault.withdrawKeeperBond(bondMinimum);

        vm.prank(attestor2);
        vm.expectRevert(abi.encodeWithSelector(Cruzible.KeeperBondIsFrozen.selector, attestor2));
        vault.withdrawKeeperBond(bondMinimum);

        // Slash attestor1 — clears freeze, allows withdrawal of remainder.
        uint256 slashAmount = bondMinimum / 2;
        vm.prank(admin);
        vault.slashKeeperBond(attestor1, slashAmount, treasury);
        assertFalse(vault.keeperBondFrozen(attestor1));

        vm.prank(attestor1);
        vault.withdrawKeeperBond(bondMinimum - slashAmount);
        assertEq(vault.keeperBonds(attestor1), 0);

        // Release attestor2 without slashing — guardian decides not to slash.
        vm.prank(admin);
        vault.releaseKeeperBondFreeze(attestor2);
        assertFalse(vault.keeperBondFrozen(attestor2));

        vm.prank(attestor2);
        vault.withdrawKeeperBond(bondMinimum);
        assertEq(vault.keeperBonds(attestor2), 0);
    }

    /// @notice confirmDelegationFraud also freezes quorum attestors after auto-revoke.
    function test_confirmDelegationFraud_freezesQuorumAttestors() public {
        address attestor1 = makeAddr("fraudFreezeA1");
        address attestor2 = makeAddr("fraudFreezeA2");
        bytes32 attestorRole = vault.DELEGATION_ATTESTOR_ROLE();

        vm.startPrank(admin);
        vault.grantRole(attestorRole, attestor1);
        vault.grantRole(attestorRole, attestor2);
        vm.stopPrank();
        _depositKeeperBond(attestor1);
        _depositKeeperBond(attestor2);

        vm.prank(admin);
        vault.setDelegationQuorumEnabled(true);

        // Quorum commit via two attestors.
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("fraud-quorum-root");
        bytes memory delAtt1 = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(attestor1);
        vault.submitDelegationVote(delAtt1, 1, delRoot, snapPre.stakerRegistryRoot, 3);

        vm.warp(block.timestamp + 1);
        bytes memory delAtt2 = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(attestor2);
        vault.submitDelegationVote(delAtt2, 1, delRoot, snapPre.stakerRegistryRoot, 3);

        // Trigger auto-revoke via three challengers.
        vm.prank(alice);
        vault.challengeDelegationCommitment(1);
        vm.prank(bob);
        vault.challengeDelegationCommitment(1);
        vm.prank(charlie);
        vault.challengeDelegationCommitment(1);

        // Auto-revoked but not yet fraud-confirmed — attestors not frozen.
        assertFalse(vault.keeperBondFrozen(attestor1));
        assertFalse(vault.keeperBondFrozen(attestor2));

        // Guardian confirms fraud — should freeze both quorum attestors.
        vm.prank(admin);
        vault.confirmDelegationFraud(1);

        assertTrue(vault.keeperBondFrozen(attestor1), "attestor1 not frozen after fraud confirmation");
        assertTrue(vault.keeperBondFrozen(attestor2), "attestor2 not frozen after fraud confirmation");

        // Neither can withdraw.
        uint256 bondMinimum = vault.KEEPER_BOND_MINIMUM();
        vm.prank(attestor1);
        vm.expectRevert(abi.encodeWithSelector(Cruzible.KeeperBondIsFrozen.selector, attestor1));
        vault.withdrawKeeperBond(bondMinimum);

        vm.prank(attestor2);
        vm.expectRevert(abi.encodeWithSelector(Cruzible.KeeperBondIsFrozen.selector, attestor2));
        vault.withdrawKeeperBond(bondMinimum);
    }

    /// @notice Keeper bond remains locked during adjudication period after auto-revoke.
    function test_withdrawKeeperBond_lockedDuringAdjudication() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("adjudication-lock-root");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        // Trigger auto-revoke
        vm.prank(alice);
        vault.challengeDelegationCommitment(1);
        vm.prank(bob);
        vault.challengeDelegationCommitment(1);
        vm.prank(charlie);
        vault.challengeDelegationCommitment(1);

        // Root is zero (auto-revoked) but adjudication is pending
        Cruzible.EpochSnapshot memory snap = vault.getEpochSnapshot(1);
        assertEq(snap.delegationRegistryRoot, bytes32(0));
        assertTrue(vault.delegationAutoRevokedAt(1) > 0);

        // Keeper bond should still be locked during adjudication
        uint256 bondMinimum = vault.KEEPER_BOND_MINIMUM();
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(Cruzible.KeeperBondLocked.selector));
        vault.withdrawKeeperBond(bondMinimum);

        // Fast-forward past adjudication period — bond unlocks
        vm.warp(block.timestamp + vault.CHALLENGE_ADJUDICATION_PERIOD() + 1);

        vm.prank(admin);
        vault.withdrawKeeperBond(bondMinimum);
        assertEq(vault.keeperBonds(admin), 0);
    }

    /// @notice commitDelegationSnapshot requires keeper bond.
    function test_commitDelegationSnapshot_requiresBond() public {
        // Create a new keeper with KEEPER_ROLE but no bond
        address unbondedKeeper = makeAddr("unbonded-keeper");
        bytes32 keeperRole = vault.KEEPER_ROLE();
        vm.prank(admin);
        vault.grantRole(keeperRole, unbondedKeeper);

        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("bond-required");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        uint256 bondMinimum = vault.KEEPER_BOND_MINIMUM();
        vm.prank(unbondedKeeper);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.InsufficientKeeperBond.selector, uint256(0), bondMinimum)
        );
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);
    }

    /// @notice Guardian can slash a keeper's bond.
    function test_slashKeeperBond() public {
        address keeper = makeAddr("slashable-keeper");
        uint256 bondAmount = vault.KEEPER_BOND_MINIMUM();
        aethel.mint(keeper, bondAmount);
        vm.startPrank(keeper);
        aethel.approve(address(vault), bondAmount);
        vault.depositKeeperBond(bondAmount);
        vm.stopPrank();

        uint256 slashAmount = 50_000 ether;
        uint256 treasuryBefore = aethel.balanceOf(treasury);

        vm.prank(admin); // admin has GUARDIAN_ROLE granted in setUp
        vault.slashKeeperBond(keeper, slashAmount, treasury);

        assertEq(vault.keeperBonds(keeper), bondAmount - slashAmount);
        assertEq(aethel.balanceOf(treasury), treasuryBefore + slashAmount);
    }

    /// @notice Only guardian can slash keeper bonds.
    function test_slashKeeperBond_onlyGuardian() public {
        vm.prank(alice);
        vm.expectRevert();
        vault.slashKeeperBond(admin, 1 ether, treasury);
    }

    // --- Permissionless challenge ---

    /// @notice Anyone can challenge a delegation commitment during the challenge period (with bond).
    function test_challengeDelegationCommitment() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("challenge-root");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        uint256 aliceBefore = aethel.balanceOf(alice);
        uint256 challengeBond = vault.CHALLENGE_BOND();

        // Alice challenges (bond is transferred)
        vm.prank(alice);
        vault.challengeDelegationCommitment(1);
        assertEq(vault.delegationChallengeCount(1), 1);
        assertTrue(vault.delegationChallengers(1, alice));
        assertEq(vault.challengerBonds(1, alice), challengeBond);
        assertEq(aethel.balanceOf(alice), aliceBefore - challengeBond);

        // Root is still committed (threshold not reached).
        Cruzible.EpochSnapshot memory snap = vault.getEpochSnapshot(1);
        assertEq(snap.delegationRegistryRoot, delRoot);
    }

    /// @notice Challenge auto-revokes when threshold is reached; bonds are NOT auto-refunded.
    function test_challengeDelegationCommitment_autoRevokes() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("auto-revoke-root");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        uint256 challengeBond = vault.CHALLENGE_BOND();

        // Three independent bonded challengers (meets DELEGATION_CHALLENGE_THRESHOLD = 3)
        vm.prank(alice);
        vault.challengeDelegationCommitment(1);
        vm.prank(bob);
        vault.challengeDelegationCommitment(1);
        vm.prank(charlie);
        vault.challengeDelegationCommitment(1);

        // Root is auto-revoked (circuit-breaker).
        assertEq(vault.delegationChallengeCount(1), 3);
        Cruzible.EpochSnapshot memory snap = vault.getEpochSnapshot(1);
        assertEq(snap.delegationRegistryRoot, bytes32(0));
        assertEq(vault.delegationCommitTimestamp(1), 0);
        assertEq(vault.delegatingStakerCount(1), 0);

        // Auto-revocation does NOT confirm fraud — bonds are held pending adjudication.
        assertFalse(vault.delegationChallengeSucceeded(1));
        assertTrue(vault.delegationAutoRevokedAt(1) > 0);
        assertEq(vault.totalChallengerBonds(), challengeBond * 3);
    }

    /// @notice Cannot challenge the same epoch twice from the same address.
    function test_challengeDelegationCommitment_rejectsDoubleChallenge() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("double-challenge");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        vm.prank(alice);
        vault.challengeDelegationCommitment(1);

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.AlreadyChallenged.selector, uint256(1), alice)
        );
        vault.challengeDelegationCommitment(1);
    }

    /// @notice Cannot challenge after the challenge period expires.
    function test_challengeDelegationCommitment_rejectsAfterPeriod() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("late-challenge");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        // Fast-forward past challenge period
        vm.warp(block.timestamp + vault.DELEGATION_CHALLENGE_PERIOD() + 1);

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.ChallengeOutsidePeriod.selector, uint256(1))
        );
        vault.challengeDelegationCommitment(1);
    }

    /// @notice Cannot challenge when no delegation is committed.
    function test_challengeDelegationCommitment_rejectsWhenNotCommitted() public {
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.DelegationNotCommitted.selector, uint256(1))
        );
        vault.challengeDelegationCommitment(1);
    }

    // --- Challenger bond lifecycle ---

    /// @notice Guardian direct revocation confirms fraud — bonds refundable immediately.
    function test_claimChallengerBond_refundOnGuardianRevocation() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("refund-test");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        uint256 challengeBond = vault.CHALLENGE_BOND();
        uint256 aliceBefore = aethel.balanceOf(alice);

        // Alice challenges
        vm.prank(alice);
        vault.challengeDelegationCommitment(1);
        assertEq(aethel.balanceOf(alice), aliceBefore - challengeBond);

        // Guardian revokes directly (explicit fraud confirmation)
        vm.prank(admin);
        vault.revokeDelegationSnapshot(1);
        assertTrue(vault.delegationChallengeSucceeded(1));

        // Alice claims refund
        vm.prank(alice);
        vault.claimChallengerBond(1);
        assertEq(aethel.balanceOf(alice), aliceBefore);
        assertEq(vault.challengerBonds(1, alice), 0);
        assertEq(vault.totalChallengerBonds(), 0);
    }

    /// @notice Challenger bonds are slashed when commitment survives (no revocation).
    function test_claimChallengerBond_slashOnSurvival() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("slash-test");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        uint256 challengeBond = vault.CHALLENGE_BOND();
        uint256 aliceBefore = aethel.balanceOf(alice);
        uint256 treasuryBefore = aethel.balanceOf(treasury);

        // Alice challenges (incorrectly — the commitment is valid)
        vm.prank(alice);
        vault.challengeDelegationCommitment(1);

        // Fast-forward past challenge period (commitment survives)
        vm.warp(block.timestamp + vault.DELEGATION_CHALLENGE_PERIOD() + 1);

        // Alice claims — bond is slashed to treasury
        vm.prank(alice);
        vault.claimChallengerBond(1);
        assertEq(aethel.balanceOf(alice), aliceBefore - challengeBond);
        assertEq(aethel.balanceOf(treasury), treasuryBefore + challengeBond);
        assertEq(vault.challengerBonds(1, alice), 0);
    }

    /// @notice Auto-revocation WITHOUT guardian confirmation → bonds slashed after adjudication.
    function test_claimChallengerBond_slashOnAutoRevokeWithoutConfirmation() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("auto-revoke-slash");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        uint256 challengeBond = vault.CHALLENGE_BOND();
        uint256 aliceBefore = aethel.balanceOf(alice);
        uint256 treasuryBefore = aethel.balanceOf(treasury);

        // Three challengers trigger auto-revoke (griefing a valid commitment)
        vm.prank(alice);
        vault.challengeDelegationCommitment(1);
        vm.prank(bob);
        vault.challengeDelegationCommitment(1);
        vm.prank(charlie);
        vault.challengeDelegationCommitment(1);

        // Auto-revoked but NOT confirmed as fraud
        assertFalse(vault.delegationChallengeSucceeded(1));
        assertTrue(vault.delegationAutoRevokedAt(1) > 0);

        // Cannot claim during adjudication period
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.ChallengeClaimTooEarly.selector, uint256(1))
        );
        vault.claimChallengerBond(1);

        // Fast-forward past adjudication period — guardian did NOT confirm
        vm.warp(block.timestamp + vault.CHALLENGE_ADJUDICATION_PERIOD() + 1);

        // All three bonds are slashed to treasury (griefing was punished)
        vm.prank(alice);
        vault.claimChallengerBond(1);
        vm.prank(bob);
        vault.claimChallengerBond(1);
        vm.prank(charlie);
        vault.claimChallengerBond(1);

        assertEq(aethel.balanceOf(alice), aliceBefore - challengeBond);
        assertEq(aethel.balanceOf(treasury), treasuryBefore + challengeBond * 3);
        assertEq(vault.totalChallengerBonds(), 0);
    }

    /// @notice Auto-revocation WITH guardian confirmation → bonds refunded.
    function test_claimChallengerBond_refundOnAutoRevokeWithConfirmation() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("auto-revoke-confirm");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        uint256 challengeBond = vault.CHALLENGE_BOND();
        uint256 aliceBefore = aethel.balanceOf(alice);
        uint256 bobBefore = aethel.balanceOf(bob);
        uint256 charlieBefore = aethel.balanceOf(charlie);

        // Three challengers trigger auto-revoke
        vm.prank(alice);
        vault.challengeDelegationCommitment(1);
        vm.prank(bob);
        vault.challengeDelegationCommitment(1);
        vm.prank(charlie);
        vault.challengeDelegationCommitment(1);

        assertFalse(vault.delegationChallengeSucceeded(1));

        // Guardian confirms fraud within adjudication period
        vm.prank(admin);
        vault.confirmDelegationFraud(1);
        assertTrue(vault.delegationChallengeSucceeded(1));

        // All three claim refunds
        vm.prank(alice);
        vault.claimChallengerBond(1);
        vm.prank(bob);
        vault.claimChallengerBond(1);
        vm.prank(charlie);
        vault.claimChallengerBond(1);

        assertEq(aethel.balanceOf(alice), aliceBefore);
        assertEq(aethel.balanceOf(bob), bobBefore);
        assertEq(aethel.balanceOf(charlie), charlieBefore);
        assertEq(vault.totalChallengerBonds(), 0);
    }

    /// @notice confirmDelegationFraud rejects if not auto-revoked.
    function test_confirmDelegationFraud_rejectsIfNotAutoRevoked() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.NotAutoRevoked.selector, uint256(1))
        );
        vault.confirmDelegationFraud(1);
    }

    /// @notice confirmDelegationFraud rejects after adjudication period expires.
    function test_confirmDelegationFraud_rejectsAfterAdjudicationExpires() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("adjudication-expired");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        // Trigger auto-revoke
        vm.prank(alice);
        vault.challengeDelegationCommitment(1);
        vm.prank(bob);
        vault.challengeDelegationCommitment(1);
        vm.prank(charlie);
        vault.challengeDelegationCommitment(1);

        // Fast-forward past adjudication period
        vm.warp(block.timestamp + vault.CHALLENGE_ADJUDICATION_PERIOD() + 1);

        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.AdjudicationPeriodExpired.selector, uint256(1))
        );
        vault.confirmDelegationFraud(1);
    }

    /// @notice Only guardian can call confirmDelegationFraud.
    function test_confirmDelegationFraud_onlyGuardian() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("only-guardian");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        // Trigger auto-revoke
        vm.prank(alice);
        vault.challengeDelegationCommitment(1);
        vm.prank(bob);
        vault.challengeDelegationCommitment(1);
        vm.prank(charlie);
        vault.challengeDelegationCommitment(1);

        // Non-guardian cannot confirm
        vm.prank(alice);
        vm.expectRevert();
        vault.confirmDelegationFraud(1);
    }

    /// @notice Cannot claim challenger bond before outcome is known (challenge period active).
    function test_claimChallengerBond_rejectsTooEarly() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("too-early");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        vm.prank(alice);
        vault.challengeDelegationCommitment(1);

        // Try to claim while challenge period is still active
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.ChallengeClaimTooEarly.selector, uint256(1))
        );
        vault.claimChallengerBond(1);
    }

    /// @notice Cannot claim bond if none was deposited.
    function test_claimChallengerBond_rejectsNoBond() public {
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.NoChallengerBond.selector, uint256(1), alice)
        );
        vault.claimChallengerBond(1);
    }

    /// @notice Cannot double-claim a challenger bond.
    function test_claimChallengerBond_rejectsDoubleClaim() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("double-claim");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        vm.prank(alice);
        vault.challengeDelegationCommitment(1);

        // Guardian revokes (confirms fraud)
        vm.prank(admin);
        vault.revokeDelegationSnapshot(1);

        // First claim succeeds
        vm.prank(alice);
        vault.claimChallengerBond(1);

        // Second claim fails
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.NoChallengerBond.selector, uint256(1), alice)
        );
        vault.claimChallengerBond(1);
    }

    /// @notice Cannot claim during adjudication period after auto-revoke.
    function test_claimChallengerBond_rejectsDuringAdjudication() public {
        Cruzible.EpochSnapshot memory snapPre = vault.getEpochSnapshot(1);
        bytes32 delRoot = keccak256("adjudication-pending");
        bytes memory delAtt = _createDelegationAttestation(1, delRoot, snapPre.stakerRegistryRoot);

        vm.prank(admin);
        vault.commitDelegationSnapshot(delAtt, 1, delRoot, snapPre.stakerRegistryRoot, 1);

        // Trigger auto-revoke
        vm.prank(alice);
        vault.challengeDelegationCommitment(1);
        vm.prank(bob);
        vault.challengeDelegationCommitment(1);
        vm.prank(charlie);
        vault.challengeDelegationCommitment(1);

        // Try to claim during adjudication period (before guardian decides)
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(Cruzible.ChallengeClaimTooEarly.selector, uint256(1))
        );
        vault.claimChallengerBond(1);
    }

    // --- Governance ---

    /// @notice Only admin can toggle quorum mode.
    function test_setDelegationQuorumEnabled_onlyAdmin() public {
        vm.prank(alice);
        vm.expectRevert();
        vault.setDelegationQuorumEnabled(true);
    }

    /// @notice Admin can toggle quorum mode.
    function test_setDelegationQuorumEnabled() public {
        assertFalse(vault.delegationQuorumEnabled());
        vm.prank(admin);
        vault.setDelegationQuorumEnabled(true);
        assertTrue(vault.delegationQuorumEnabled());
    }

    // =========================================================================
    // ATTESTATION RELAY GOVERNANCE TESTS
    //
    // These tests exercise the relay registration, time-locked key rotation,
    // liveness challenges, and emergency revocation controls added to
    // VaultTEEVerifier.sol to close the P2 relay-rooted trust gap.
    // =========================================================================

    // Relay test key (P-256 private key = 3, public key = 3*G)
    uint256 internal constant RELAY_PRIV = 3;
    uint256 internal constant RELAY_PUB_X = 0x5ECBE4D1A6330A44C8F7EF951D4BF165E6C6B721EFADA985FB41661BC6E7FD6C;
    uint256 internal constant RELAY_PUB_Y = 0x8734640C4998FF7E374B06CE1A64A2ECD82AB036384FB83D9A79B127A27D5032;

    // Rotated relay key (P-256 private key = 4, public key = 4*G)
    uint256 internal constant ROTATED_RELAY_PRIV = 4;
    uint256 internal constant ROTATED_RELAY_X = 0xE2534A3532D08FBBA02DDE659EE62BD0031FE2DB785596EF509302446B030852;
    uint256 internal constant ROTATED_RELAY_Y = 0xE0F1575A4C633CC719DFEE5FDA862D764EFC96C3F30EE0055C42C23F184ED8C6;

    /// @notice Register an attestation relay and verify state.
    function test_registerAttestationRelay() public {
        vm.startPrank(admin);

        // Register relay for Nitro (platform 1) — SGX already has vendor root set in setUp
        verifier.registerAttestationRelay(1, RELAY_PUB_X, RELAY_PUB_Y, "Aethelred Nitro Relay v1");

        // Verify relay is active
        assertTrue(verifier.isRelayActive(1));

        // Verify relay state
        (
            uint256 pubX, uint256 pubY,
            uint256 registeredAt, uint256 lastRotated,
            uint256 attestCount, bool active,
            uint256 pendingX, uint256 pendingY, uint256 rotationUnlocks,
            bytes32 challenge, uint256 challengeDeadline,
            string memory desc
        ) = verifier.attestationRelays(1);
        assertEq(pubX, RELAY_PUB_X);
        assertEq(pubY, RELAY_PUB_Y);
        assertGt(registeredAt, 0);
        assertEq(lastRotated, registeredAt);
        assertEq(attestCount, 0);
        assertTrue(active);
        assertEq(pendingX, 0);
        assertEq(pendingY, 0);
        assertEq(rotationUnlocks, 0);
        assertEq(challenge, bytes32(0));
        assertEq(challengeDeadline, 0);
        assertEq(desc, "Aethelred Nitro Relay v1");

        // Vendor root key should also be set for backward compatibility
        assertEq(verifier.vendorRootKeyX(1), RELAY_PUB_X);
        assertEq(verifier.vendorRootKeyY(1), RELAY_PUB_Y);

        vm.stopPrank();
    }

    /// @notice Duplicate relay registration reverts.
    function test_registerAttestationRelay_duplicateReverts() public {
        vm.startPrank(admin);
        verifier.registerAttestationRelay(1, RELAY_PUB_X, RELAY_PUB_Y, "Relay v1");

        vm.expectRevert(abi.encodeWithSelector(VaultTEEVerifier.RelayAlreadyRegistered.selector, uint8(1)));
        verifier.registerAttestationRelay(1, RELAY_PUB_X, RELAY_PUB_Y, "Relay v2");
        vm.stopPrank();
    }

    /// @notice Full relay key rotation lifecycle: initiate → wait → finalize.
    function test_relayRotation_fullLifecycle() public {
        vm.startPrank(admin);

        // Register relay
        verifier.registerAttestationRelay(1, RELAY_PUB_X, RELAY_PUB_Y, "Relay v1");

        // Initiate rotation
        verifier.initiateRelayRotation(1, ROTATED_RELAY_X, ROTATED_RELAY_Y);

        // Verify pending state
        (bool pending, uint256 unlocksAt) = verifier.hasPendingRotation(1);
        assertTrue(pending);
        assertGt(unlocksAt, block.timestamp);

        // Finalize before timelock must revert
        vm.expectRevert(abi.encodeWithSelector(VaultTEEVerifier.RotationTimelockActive.selector, uint8(1), unlocksAt));
        verifier.finalizeRelayRotation(1);

        // Advance past 48 hours
        vm.warp(block.timestamp + 48 hours + 1);

        // Finalize should succeed
        verifier.finalizeRelayRotation(1);

        // Verify new key is active
        (uint256 newX, uint256 newY,,,,,,,,,,) = verifier.attestationRelays(1);
        assertEq(newX, ROTATED_RELAY_X);
        assertEq(newY, ROTATED_RELAY_Y);

        // Pending should be cleared
        (pending,) = verifier.hasPendingRotation(1);
        assertFalse(pending);

        // Vendor root key should be updated too
        assertEq(verifier.vendorRootKeyX(1), ROTATED_RELAY_X);
        assertEq(verifier.vendorRootKeyY(1), ROTATED_RELAY_Y);

        vm.stopPrank();
    }

    /// @notice Cancel a pending relay key rotation.
    function test_relayRotation_cancel() public {
        vm.startPrank(admin);

        verifier.registerAttestationRelay(1, RELAY_PUB_X, RELAY_PUB_Y, "Relay v1");
        verifier.initiateRelayRotation(1, ROTATED_RELAY_X, ROTATED_RELAY_Y);

        // Cancel
        verifier.cancelRelayRotation(1);

        // Pending should be cleared
        (bool pending,) = verifier.hasPendingRotation(1);
        assertFalse(pending);

        // Original key should be unchanged
        (uint256 x, uint256 y,,,,,,,,,,) = verifier.attestationRelays(1);
        assertEq(x, RELAY_PUB_X);
        assertEq(y, RELAY_PUB_Y);

        // Cancel with nothing pending should revert
        vm.expectRevert(abi.encodeWithSelector(VaultTEEVerifier.NoRotationPending.selector, uint8(1)));
        verifier.cancelRelayRotation(1);

        vm.stopPrank();
    }

    /// @notice Emergency relay revocation clears all state.
    function test_revokeRelay() public {
        vm.startPrank(admin);

        verifier.registerAttestationRelay(1, RELAY_PUB_X, RELAY_PUB_Y, "Relay v1");
        assertTrue(verifier.isRelayActive(1));

        // Revoke
        verifier.revokeRelay(1);
        assertFalse(verifier.isRelayActive(1));

        // Vendor root key should be cleared
        assertEq(verifier.vendorRootKeyX(1), 0);
        assertEq(verifier.vendorRootKeyY(1), 0);

        vm.stopPrank();
    }

    /// @notice Revoking unregistered relay reverts.
    function test_revokeRelay_unregisteredReverts() public {
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(VaultTEEVerifier.RelayNotRegistered.selector, uint8(2)));
        verifier.revokeRelay(2);
    }

    /// @notice Relay liveness challenge with valid P-256 response.
    function test_relayChallenge_successfulResponse() public {
        vm.startPrank(admin);
        verifier.registerAttestationRelay(1, RELAY_PUB_X, RELAY_PUB_Y, "Relay v1");

        // Issue challenge
        bytes32 challenge = keccak256("governance-challenge-1");
        verifier.challengeRelay(1, challenge);

        // Verify challenge is pending
        assertTrue(verifier.hasUnexpiredChallenge(1));
        vm.stopPrank();

        // Respond with valid P-256 signature (anyone can submit)
        bytes32 challengeHash = sha256(abi.encodePacked(challenge));
        (bytes32 sigR, bytes32 sigS) = vm.signP256(RELAY_PRIV, challengeHash);

        verifier.respondRelayChallenge(1, uint256(sigR), uint256(sigS));

        // Challenge should be cleared
        assertFalse(verifier.hasUnexpiredChallenge(1));
    }

    /// @notice Relay challenge response with wrong key reverts.
    function test_relayChallenge_wrongKeyReverts() public {
        vm.startPrank(admin);
        verifier.registerAttestationRelay(1, RELAY_PUB_X, RELAY_PUB_Y, "Relay v1");

        bytes32 challenge = keccak256("governance-challenge-2");
        verifier.challengeRelay(1, challenge);
        vm.stopPrank();

        // Sign with wrong key (vendor root, not relay)
        bytes32 challengeHash = sha256(abi.encodePacked(challenge));
        (bytes32 sigR, bytes32 sigS) = vm.signP256(VENDOR_ROOT_PRIV, challengeHash);

        vm.expectRevert(abi.encodeWithSelector(VaultTEEVerifier.ChallengeResponseInvalid.selector, uint8(1)));
        verifier.respondRelayChallenge(1, uint256(sigR), uint256(sigS));
    }

    /// @notice Relay challenge response after deadline reverts.
    function test_relayChallenge_expiredReverts() public {
        vm.startPrank(admin);
        verifier.registerAttestationRelay(1, RELAY_PUB_X, RELAY_PUB_Y, "Relay v1");

        bytes32 challenge = keccak256("governance-challenge-3");
        verifier.challengeRelay(1, challenge);
        vm.stopPrank();

        // Advance past the 1-hour window
        vm.warp(block.timestamp + 1 hours + 1);

        bytes32 challengeHash = sha256(abi.encodePacked(challenge));
        (bytes32 sigR, bytes32 sigS) = vm.signP256(RELAY_PRIV, challengeHash);

        vm.expectRevert(abi.encodeWithSelector(VaultTEEVerifier.ChallengeExpired.selector, uint8(1)));
        verifier.respondRelayChallenge(1, uint256(sigR), uint256(sigS));
    }

    /// @notice Responding without a pending challenge reverts.
    function test_relayChallenge_noPendingReverts() public {
        vm.startPrank(admin);
        verifier.registerAttestationRelay(1, RELAY_PUB_X, RELAY_PUB_Y, "Relay v1");
        vm.stopPrank();

        vm.expectRevert(abi.encodeWithSelector(VaultTEEVerifier.NoPendingChallenge.selector, uint8(1)));
        verifier.respondRelayChallenge(1, 1, 1);
    }

    /// @notice Registering enclaves increments relay attestation count.
    function test_relayAttestationCount_incrementsOnEnclaveRegister() public {
        vm.startPrank(admin);

        // Register relay for SGX (platform 0) — requires clearing existing vendor root first
        // We'll use Nitro (platform 1) to avoid conflicting with setUp's SGX config
        verifier.registerAttestationRelay(1, RELAY_PUB_X, RELAY_PUB_Y, "Nitro Relay");

        // Initial count should be 0
        (,,,,uint256 countBefore,,,,,,,) = verifier.attestationRelays(1);
        assertEq(countBefore, 0);

        // Register an enclave on the Nitro platform using relay as the vendor root
        bytes32 nitroEncHash = keccak256("nitro-enclave-v1");
        bytes32 nitroSignerHash = keccak256("nitro-signer-v1");

        // Sign platform key attestation with relay private key
        bytes32 keyAttestMsg = sha256(abi.encodePacked(P256_PUB_X, P256_PUB_Y, uint8(1)));
        (bytes32 attestR, bytes32 attestS) = vm.signP256(RELAY_PRIV, keyAttestMsg);

        verifier.registerEnclave(
            nitroEncHash, nitroSignerHash, keccak256("nitro-app-v1"), 1, "Nitro Enclave v1",
            P256_PUB_X, P256_PUB_Y, uint256(attestR), uint256(attestS)
        );

        // Count should now be 1
        (,,,,uint256 countAfter,,,,,,,) = verifier.attestationRelays(1);
        assertEq(countAfter, 1);

        vm.stopPrank();
    }

    /// @notice Operations on a revoked relay revert appropriately.
    function test_revokedRelay_operationsRevert() public {
        vm.startPrank(admin);
        verifier.registerAttestationRelay(1, RELAY_PUB_X, RELAY_PUB_Y, "Relay v1");
        verifier.revokeRelay(1);

        // Rotation on revoked relay should revert
        vm.expectRevert(abi.encodeWithSelector(VaultTEEVerifier.RelayNotActive.selector, uint8(1)));
        verifier.initiateRelayRotation(1, ROTATED_RELAY_X, ROTATED_RELAY_Y);

        // Challenge on revoked relay should revert
        vm.expectRevert(abi.encodeWithSelector(VaultTEEVerifier.RelayNotActive.selector, uint8(1)));
        verifier.challengeRelay(1, keccak256("challenge"));

        vm.stopPrank();
    }

    /// @notice Non-admin cannot register relay.
    function test_registerAttestationRelay_nonAdminReverts() public {
        vm.prank(alice);
        vm.expectRevert();
        verifier.registerAttestationRelay(1, RELAY_PUB_X, RELAY_PUB_Y, "Unauthorized");
    }

    /// @notice setVendorRootKey reverts while an active relay exists.
    function test_setVendorRootKey_blockedWhileRelayActive() public {
        vm.startPrank(admin);

        // Register relay for Nitro (platform 1)
        verifier.registerAttestationRelay(1, RELAY_PUB_X, RELAY_PUB_Y, "Relay v1");

        // Direct override must revert
        vm.expectRevert(abi.encodeWithSelector(VaultTEEVerifier.DirectOverrideWhileRelayActive.selector, uint8(1)));
        verifier.setVendorRootKey(1, VENDOR_ROOT_X, VENDOR_ROOT_Y);

        // Vendor root key should still be the relay key
        assertEq(verifier.vendorRootKeyX(1), RELAY_PUB_X);
        assertEq(verifier.vendorRootKeyY(1), RELAY_PUB_Y);

        vm.stopPrank();
    }

    /// @notice setVendorRootKey works again after relay revocation.
    function test_setVendorRootKey_allowedAfterRelayRevocation() public {
        vm.startPrank(admin);

        verifier.registerAttestationRelay(1, RELAY_PUB_X, RELAY_PUB_Y, "Relay v1");
        verifier.revokeRelay(1);

        // Direct set should work after relay is revoked
        verifier.setVendorRootKey(1, VENDOR_ROOT_X, VENDOR_ROOT_Y);
        assertEq(verifier.vendorRootKeyX(1), VENDOR_ROOT_X);
        assertEq(verifier.vendorRootKeyY(1), VENDOR_ROOT_Y);

        vm.stopPrank();
    }

    /// @notice setVendorRootKey works on platforms with no relay registered.
    function test_setVendorRootKey_allowedWithoutRelay() public {
        vm.startPrank(admin);

        // Platform 2 (SEV) has no relay — direct set should work
        verifier.setVendorRootKey(2, VENDOR_ROOT_X, VENDOR_ROOT_Y);
        assertEq(verifier.vendorRootKeyX(2), VENDOR_ROOT_X);

        vm.stopPrank();
    }

    /// @notice Relay rotation still works despite the direct override guard.
    function test_relayRotation_notBlockedByGuard() public {
        vm.startPrank(admin);

        verifier.registerAttestationRelay(1, RELAY_PUB_X, RELAY_PUB_Y, "Relay v1");

        // Rotation should work — relay methods bypass the guard
        verifier.initiateRelayRotation(1, ROTATED_RELAY_X, ROTATED_RELAY_Y);
        vm.warp(block.timestamp + 48 hours + 1);
        verifier.finalizeRelayRotation(1);

        // Key should be the rotated key
        assertEq(verifier.vendorRootKeyX(1), ROTATED_RELAY_X);
        assertEq(verifier.vendorRootKeyY(1), ROTATED_RELAY_Y);

        vm.stopPrank();
    }

    /// @notice A revoked relay can be replaced with a fresh registration.
    function test_registerAttestationRelay_afterRevocation() public {
        vm.startPrank(admin);

        // Register and revoke relay v1
        verifier.registerAttestationRelay(1, RELAY_PUB_X, RELAY_PUB_Y, "Relay v1");
        verifier.revokeRelay(1);
        assertFalse(verifier.isRelayActive(1));

        // Register a replacement relay v2 with a different key
        verifier.registerAttestationRelay(1, ROTATED_RELAY_X, ROTATED_RELAY_Y, "Relay v2");

        // Verify replacement relay is active with fresh state
        assertTrue(verifier.isRelayActive(1));
        (
            uint256 pubX, uint256 pubY,
            uint256 registeredAt,,
            uint256 attestCount, bool active,
            uint256 pendingX, uint256 pendingY, uint256 rotationUnlocks,
            bytes32 challenge, uint256 challengeDeadline,
            string memory desc
        ) = verifier.attestationRelays(1);
        assertEq(pubX, ROTATED_RELAY_X);
        assertEq(pubY, ROTATED_RELAY_Y);
        assertGt(registeredAt, 0);
        assertEq(attestCount, 0, "attestation count must reset on re-registration");
        assertTrue(active);
        assertEq(pendingX, 0, "stale pending rotation must be cleared");
        assertEq(pendingY, 0);
        assertEq(rotationUnlocks, 0);
        assertEq(challenge, bytes32(0), "stale challenge must be cleared");
        assertEq(challengeDeadline, 0);
        assertEq(desc, "Relay v2");

        // Vendor root key should be the new relay's key
        assertEq(verifier.vendorRootKeyX(1), ROTATED_RELAY_X);
        assertEq(verifier.vendorRootKeyY(1), ROTATED_RELAY_Y);

        // Direct override should be blocked again (new relay is active)
        vm.expectRevert(abi.encodeWithSelector(VaultTEEVerifier.DirectOverrideWhileRelayActive.selector, uint8(1)));
        verifier.setVendorRootKey(1, VENDOR_ROOT_X, VENDOR_ROOT_Y);

        vm.stopPrank();
    }

    /// @notice Replacement relay can register enclaves and track attestation count.
    function test_replacementRelay_registersEnclaves() public {
        vm.startPrank(admin);

        // Register, revoke, re-register
        verifier.registerAttestationRelay(1, RELAY_PUB_X, RELAY_PUB_Y, "Relay v1");
        verifier.revokeRelay(1);
        verifier.registerAttestationRelay(1, RELAY_PUB_X, RELAY_PUB_Y, "Relay v2");

        // Register an enclave using the replacement relay
        bytes32 nitroEncHash = keccak256("nitro-enclave-v2");
        bytes32 nitroSignerHash = keccak256("nitro-signer-v2");
        bytes32 keyAttestMsg = sha256(abi.encodePacked(P256_PUB_X, P256_PUB_Y, uint8(1)));
        (bytes32 attestR, bytes32 attestS) = vm.signP256(RELAY_PRIV, keyAttestMsg);

        verifier.registerEnclave(
            nitroEncHash, nitroSignerHash, keccak256("nitro-app-v2"), 1, "Nitro v2",
            P256_PUB_X, P256_PUB_Y, uint256(attestR), uint256(attestS)
        );

        // Attestation count should be 1
        (,,,,uint256 count,,,,,,,) = verifier.attestationRelays(1);
        assertEq(count, 1);

        vm.stopPrank();
    }

}
