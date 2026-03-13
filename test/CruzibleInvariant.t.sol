// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/StdInvariant.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../contracts/vault/Cruzible.sol";
import "../contracts/vault/StAETHEL.sol";
import "../contracts/vault/VaultTEEVerifier.sol";
import "../contracts/vault/PlatformVerifiers.sol";
import "../contracts/vault/ICruzible.sol";

// ═══════════════════════════════════════════════════════════════════════════════
// Mock ERC20 (namespaced to avoid collision with Cruzible.t.sol)
// ═══════════════════════════════════════════════════════════════════════════════

contract MockAETHELInvariant {
    string public name = "Aethelred";
    string public symbol = "AETHEL";
    uint8 public decimals = 18;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "Insufficient balance");
        require(allowance[from][msg.sender] >= amount, "Insufficient allowance");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Handler - called by Foundry's invariant fuzzer with random sequences
// ═══════════════════════════════════════════════════════════════════════════════

contract CruzibleHandler is Test {
    Cruzible public vault;
    StAETHEL public stAethel;
    MockAETHELInvariant public aethel;

    address public admin;
    address public oracle;
    address[4] public actors;

    // TEE key pair
    uint256 internal operatorPrivKey = 0xA11CE;
    bytes32 internal constant ENCLAVE_HASH = keccak256("cruzible-enclave-v1");
    bytes32 internal constant SIGNER_HASH = keccak256("cruzible-signer-v1");
    uint256 internal constant P256_PRIV_KEY = 1;
    bytes32 internal constant TEST_POLICY_HASH = keccak256("test-selection-policy-v1");
    bytes32 internal constant TEST_UNIVERSE_HASH = keccak256("test-eligible-universe-v1");
    bytes32 internal constant TEST_SNAPSHOT_HASH = keccak256("test-stake-snapshot-v1");

    // ── Ghost variables for invariant verification ──────────────────────────
    uint256 public ghost_totalSharesMinted;
    uint256 public ghost_totalSharesBurned;
    uint256 public ghost_withdrawalsClaimed;
    uint256 public ghost_previousExchangeRate;
    uint256 public ghost_previousEpoch;
    uint256[] public ghost_withdrawalIds;
    mapping(uint256 => bool) public ghost_claimedWithdrawals;

    // Call counters for debugging
    uint256 public calls_stake;
    uint256 public calls_unstake;
    uint256 public calls_withdraw;
    uint256 public calls_distributeRewards;

    constructor(
        Cruzible _vault,
        StAETHEL _stAethel,
        MockAETHELInvariant _aethel,
        address _admin,
        address _oracle,
        address[4] memory _actors
    ) {
        vault = _vault;
        stAethel = _stAethel;
        aethel = _aethel;
        admin = _admin;
        oracle = _oracle;
        actors = _actors;
        ghost_previousExchangeRate = 1e18;
        ghost_previousEpoch = 1;
    }

    // ── Stake ───────────────────────────────────────────────────────────────

    function stake(uint256 actorSeed, uint256 amount) external {
        address actor = actors[actorSeed % actors.length];

        // Bound to valid stake range: [32 ether, 100_000 ether]
        amount = bound(amount, 32 ether, 100_000 ether);

        // Ensure actor has enough tokens
        if (aethel.balanceOf(actor) < amount) {
            aethel.mint(actor, amount);
        }
        // Ensure allowance
        vm.prank(actor);
        aethel.approve(address(vault), amount);

        vm.prank(actor);
        uint256 shares = vault.stake(amount);

        ghost_totalSharesMinted += shares;
        calls_stake++;
    }

    // ── Unstake ─────────────────────────────────────────────────────────────

    function unstake(uint256 actorSeed, uint256 sharesFraction) external {
        address actor = actors[actorSeed % actors.length];
        uint256 actorShares = stAethel.sharesOf(actor);
        if (actorShares == 0) return;

        // Unstake 1-100% of held shares
        sharesFraction = bound(sharesFraction, 1, 100);
        uint256 sharesToUnstake = (actorShares * sharesFraction) / 100;
        if (sharesToUnstake == 0) sharesToUnstake = 1;
        if (sharesToUnstake > actorShares) sharesToUnstake = actorShares;

        vm.prank(actor);
        (uint256 withdrawalId,) = vault.unstake(sharesToUnstake);

        ghost_totalSharesBurned += sharesToUnstake;
        ghost_withdrawalIds.push(withdrawalId);
        calls_unstake++;
    }

    // ── Withdraw ────────────────────────────────────────────────────────────

    function withdraw(uint256 withdrawalSeed) external {
        if (ghost_withdrawalIds.length == 0) return;

        uint256 idx = withdrawalSeed % ghost_withdrawalIds.length;
        uint256 withdrawalId = ghost_withdrawalIds[idx];

        // Skip already claimed
        if (ghost_claimedWithdrawals[withdrawalId]) return;

        // Warp past unbonding period (14 days + margin)
        vm.warp(block.timestamp + 15 days);

        // The withdrawal struct has the user address - we need to find who owns it.
        // Iterate actors to find the owner.
        for (uint256 i = 0; i < actors.length; i++) {
            vm.prank(actors[i]);
            try vault.withdraw(withdrawalId) {
                ghost_claimedWithdrawals[withdrawalId] = true;
                ghost_withdrawalsClaimed++;
                calls_withdraw++;
                return;
            } catch {
                // Not this actor's withdrawal, or not ready
                continue;
            }
        }
    }

    // ── Distribute Rewards (advances epoch) ─────────────────────────────────

    function distributeRewards(uint256 rewardAmount) external {
        // Bound rewards to [0.1 ether, 1000 ether]
        rewardAmount = bound(rewardAmount, 0.1 ether, 1000 ether);

        // Need non-zero pooled AETHEL
        if (vault.getTotalPooledAethel() == 0) return;

        uint256 epoch = vault.currentEpoch();
        uint256 fee = (rewardAmount * 500) / 10000; // 5% protocol fee

        // Fund oracle
        aethel.mint(oracle, rewardAmount);
        vm.prank(oracle);
        aethel.approve(address(vault), rewardAmount);

        // Read committed hashes
        Cruzible.EpochSnapshot memory snap = vault.getEpochSnapshot(epoch);
        bytes32 vsHash = snap.validatorSetHash;
        bytes32 regRoot = snap.stakerRegistryRoot;

        // Commit delegation root if not yet committed
        bytes32 delRoot;
        if (snap.delegationRegistryRoot == bytes32(0)) {
            delRoot = keccak256(abi.encodePacked("test-delegation-root", epoch));
            bytes memory delPayload = abi.encode(epoch, delRoot, snap.stakerRegistryRoot);
            bytes memory delAtt = _createAttestation(delPayload);
            vm.prank(admin);
            vault.commitDelegationSnapshot(delAtt, epoch, delRoot, snap.stakerRegistryRoot, 1);
        } else {
            delRoot = snap.delegationRegistryRoot;
        }

        // Fast-forward past delegation challenge period
        vm.warp(block.timestamp + vault.DELEGATION_CHALLENGE_PERIOD() + 1);

        // Build reward attestation
        bytes memory payload = abi.encode(epoch, rewardAmount, bytes32(0), fee, TEST_SNAPSHOT_HASH, vsHash, regRoot, delRoot);
        bytes memory att = _createAttestation(payload);

        vm.prank(oracle);
        try vault.distributeRewards(att, epoch, rewardAmount, bytes32(0), fee) {
            // Epoch advanced - commit hashes for next epoch
            uint256 nextEpoch = vault.currentEpoch();
            vm.startPrank(admin);
            vault.commitUniverseHash(nextEpoch, TEST_UNIVERSE_HASH);
            vault.commitStakeSnapshot(nextEpoch, TEST_SNAPSHOT_HASH, vault.getTotalShares());
            vm.stopPrank();

            ghost_previousEpoch = nextEpoch;
            calls_distributeRewards++;
        } catch {
            // Distribution failed (e.g. challenge period not met) - acceptable
        }

        // Record exchange rate for monotonicity check
        ghost_previousExchangeRate = vault.getExchangeRate();
    }

    // ── Attestation helper (mirrors Cruzible.t.sol) ─────────────────────────

    function _createAttestation(bytes memory payload) internal view returns (bytes memory) {
        uint8 platformId = 0; // SGX
        uint256 timestamp = block.timestamp;
        bytes32 nonce = keccak256(abi.encodePacked(block.timestamp, block.number, payload));

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

        bytes32 rawReportHash = sha256(abi.encodePacked(
            "MOCK_HW_REPORT_V1",
            ENCLAVE_HASH,
            SIGNER_HASH,
            digest
        ));

        bytes32 bindingHash = sha256(abi.encodePacked(rawReportHash, ENCLAVE_HASH, SIGNER_HASH));
        bytes32 reportHash = sha256(abi.encodePacked(ENCLAVE_HASH, SIGNER_HASH, digest, uint16(1), uint16(1), bindingHash));
        (bytes32 p256r, bytes32 p256s) = vm.signP256(P256_PRIV_KEY, reportHash);

        bytes memory evidence = abi.encode(
            ENCLAVE_HASH,
            SIGNER_HASH,
            digest,
            uint16(1),
            uint16(1),
            rawReportHash,
            uint256(p256r),
            uint256(p256s)
        );

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

    // ── View helpers ────────────────────────────────────────────────────────

    function getWithdrawalIdCount() external view returns (uint256) {
        return ghost_withdrawalIds.length;
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Invariant Test Suite
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * @title CruzibleInvariantTest
 * @notice Foundry invariant + fuzz tests for the Cruzible liquid staking protocol.
 *
 * Invariant tests use a Handler contract that the fuzzer calls with random
 * sequences of (stake, unstake, withdraw, distributeRewards). After each call
 * sequence, invariant_* functions assert protocol-level properties.
 *
 * Fuzz tests verify per-operation properties under random inputs.
 */
contract CruzibleInvariantTest is StdInvariant, Test {
    // ── Contracts ───────────────────────────────────────────────────────────
    Cruzible public vault;
    StAETHEL public stAethel;
    MockAETHELInvariant public aethel;
    VaultTEEVerifier public verifier;
    SgxVerifier public sgxVerifier;
    CruzibleHandler public handler;

    // ── Addresses ───────────────────────────────────────────────────────────
    address public admin = address(0xAD);
    address public oracle = address(0x0AC1E);
    address public guardian = address(0x6AAD);
    address public treasury = address(0x72EA);
    address[4] public actors = [address(0xA11CE), address(0xB0B), address(0xC4A), address(0xDA5)];

    // ── TEE constants ───────────────────────────────────────────────────────
    uint256 internal operatorPrivKey = 0xA11CE;
    address internal operatorAddr;
    uint256 internal constant P256_PRIV_KEY = 1;
    uint256 internal constant P256_PUB_X = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296;
    uint256 internal constant P256_PUB_Y = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5;
    bytes32 internal constant ENCLAVE_HASH = keccak256("cruzible-enclave-v1");
    bytes32 internal constant SIGNER_HASH = keccak256("cruzible-signer-v1");
    bytes32 internal constant TEST_POLICY_HASH = keccak256("test-selection-policy-v1");
    bytes32 internal constant TEST_UNIVERSE_HASH = keccak256("test-eligible-universe-v1");
    bytes32 internal constant TEST_SNAPSHOT_HASH = keccak256("test-stake-snapshot-v1");
    uint256 internal constant VENDOR_ROOT_PRIV = 2;
    uint256 internal constant VENDOR_ROOT_X = 0x7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978;
    uint256 internal constant VENDOR_ROOT_Y = 0x07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1;

    // ═════════════════════════════════════════════════════════════════════════
    // SETUP
    // ═════════════════════════════════════════════════════════════════════════

    function setUp() public {
        operatorAddr = vm.addr(operatorPrivKey);

        // Deploy mock token
        aethel = new MockAETHELInvariant();

        // Deploy VaultTEEVerifier
        VaultTEEVerifier verifierImpl = new VaultTEEVerifier();
        bytes memory verifierInit = abi.encodeCall(VaultTEEVerifier.initialize, (admin));
        ERC1967Proxy verifierProxy = new ERC1967Proxy(address(verifierImpl), verifierInit);
        verifier = VaultTEEVerifier(address(verifierProxy));

        // Deploy StAETHEL impl
        StAETHEL stAethelImpl = new StAETHEL();

        // Deploy Cruzible impl
        Cruzible vaultImpl = new Cruzible();

        // Deploy stAETHEL proxy with placeholder vault
        bytes memory stAethelInit = abi.encodeCall(StAETHEL.initialize, (admin, address(0xDEAD)));
        ERC1967Proxy stAethelProxy = new ERC1967Proxy(address(stAethelImpl), stAethelInit);
        stAethel = StAETHEL(address(stAethelProxy));

        // Deploy vault proxy
        bytes memory vaultInit = abi.encodeCall(
            Cruzible.initialize,
            (admin, address(aethel), address(stAethel), address(verifier), treasury)
        );
        ERC1967Proxy vaultProxy = new ERC1967Proxy(address(vaultImpl), vaultInit);
        vault = Cruzible(address(vaultProxy));

        // Grant stAETHEL VAULT_ROLE to the actual vault
        bytes32 vaultRole = stAethel.VAULT_ROLE();
        vm.prank(admin);
        stAethel.grantRole(vaultRole, address(vault));

        // Setup roles and TEE
        vm.startPrank(admin);
        vault.grantRole(vault.ORACLE_ROLE(), oracle);
        vault.grantRole(vault.GUARDIAN_ROLE(), guardian);

        // Setup vendor root key + enclave
        verifier.setVendorRootKey(0, VENDOR_ROOT_X, VENDOR_ROOT_Y);
        bytes32 keyAttestMsg = sha256(abi.encodePacked(P256_PUB_X, P256_PUB_Y, uint8(0)));
        (bytes32 vendorR, bytes32 vendorS) = vm.signP256(VENDOR_ROOT_PRIV, keyAttestMsg);
        verifier.registerEnclave(
            ENCLAVE_HASH, SIGNER_HASH, bytes32(0), 0, "Cruzible SGX Enclave v1",
            P256_PUB_X, P256_PUB_Y, uint256(vendorR), uint256(vendorS)
        );
        bytes32 enclaveId = keccak256(abi.encodePacked(ENCLAVE_HASH, uint8(0)));
        verifier.registerOperator(operatorAddr, enclaveId, "Test TEE Operator");

        sgxVerifier = new SgxVerifier();
        verifier.setPlatformVerifier(0, address(sgxVerifier));

        // Set selection policy + initial epoch hashes
        vault.setSelectionPolicyHash(TEST_POLICY_HASH);
        vault.commitUniverseHash(1, TEST_UNIVERSE_HASH);
        vault.commitStakeSnapshot(1, TEST_SNAPSHOT_HASH, vault.getTotalShares());
        vm.stopPrank();

        // Fund actors
        for (uint256 i = 0; i < actors.length; i++) {
            aethel.mint(actors[i], 10_000_000 ether);
            vm.prank(actors[i]);
            aethel.approve(address(vault), type(uint256).max);
        }

        // Deposit keeper bond for admin (KEEPER_ROLE) so
        // commitDelegationSnapshot in the handler succeeds.
        {
            uint256 bondAmount = vault.KEEPER_BOND_MINIMUM();
            aethel.mint(admin, bondAmount);
            vm.startPrank(admin);
            aethel.approve(address(vault), bondAmount);
            vault.depositKeeperBond(bondAmount);
            vm.stopPrank();
        }

        // Deploy handler
        handler = new CruzibleHandler(vault, stAethel, aethel, admin, oracle, actors);

        // Tell Foundry to target the handler
        targetContract(address(handler));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // INVARIANT TESTS
    // ═════════════════════════════════════════════════════════════════════════

    /// @notice Total shares across all actors must equal stAETHEL.getTotalShares().
    function invariant_shareConservation() public view {
        uint256 sumShares = 0;
        for (uint256 i = 0; i < actors.length; i++) {
            sumShares += stAethel.sharesOf(actors[i]);
        }
        assertEq(sumShares, stAethel.getTotalShares(), "Share conservation violated");
    }

    /// @notice The vault's AETHEL balance must cover all pending withdrawals.
    function invariant_solvency() public view {
        uint256 vaultBalance = aethel.balanceOf(address(vault));
        uint256 totalPooled = vault.getTotalPooledAethel();
        // Vault balance should be >= totalPooled (may be higher due to pending deposits)
        assertGe(vaultBalance, totalPooled, "Vault insolvent - balance < totalPooled");
    }

    /// @notice Exchange rate should never drop below the initial 1:1 rate.
    ///         (No slashing occurs in the handler, so rate only increases.)
    function invariant_exchangeRateFloor() public view {
        uint256 rate = vault.getExchangeRate();
        assertGe(rate, 1e18, "Exchange rate dropped below initial 1:1");
    }

    /// @notice Epoch counter must be monotonically non-decreasing and >= 1.
    function invariant_epochMonotonicity() public view {
        uint256 epoch = vault.currentEpoch();
        assertGe(epoch, 1, "Epoch below 1");
        assertGe(epoch, handler.ghost_previousEpoch(), "Epoch went backwards");
    }

    /// @notice No duplicate addresses in the active validator set.
    function invariant_noDuplicateValidators() public view {
        address[] memory validators = vault.getActiveValidators();
        for (uint256 i = 0; i < validators.length; i++) {
            for (uint256 j = i + 1; j < validators.length; j++) {
                assertTrue(
                    validators[i] != validators[j],
                    "Duplicate validator address in active set"
                );
            }
        }
    }

    /// @notice Ghost share tracking must match on-chain totals.
    ///         minted - burned = totalShares (when no external minting occurs).
    function invariant_ghostShareAccounting() public view {
        uint256 totalShares = stAethel.getTotalShares();
        uint256 expected = handler.ghost_totalSharesMinted() - handler.ghost_totalSharesBurned();
        assertEq(totalShares, expected, "Ghost share accounting mismatch");
    }

    /// @notice Epoch 1's snapshot hash must remain immutable.
    function invariant_stakeSnapshotImmutability() public view {
        Cruzible.EpochSnapshot memory snap = vault.getEpochSnapshot(1);
        assertEq(snap.stakeSnapshotHash, TEST_SNAPSHOT_HASH, "Epoch 1 snapshot hash was mutated");
    }

    /// @notice Epoch 1's universe hash must remain immutable.
    function invariant_universeHashImmutability() public view {
        Cruzible.EpochSnapshot memory snap = vault.getEpochSnapshot(1);
        assertEq(snap.eligibleUniverseHash, TEST_UNIVERSE_HASH, "Epoch 1 universe hash was mutated");
    }

    // ═════════════════════════════════════════════════════════════════════════
    // FUZZ TESTS
    // ═════════════════════════════════════════════════════════════════════════

    /// @notice Stake → unstake → withdraw round-trip at 1:1 rate preserves value.
    function testFuzz_stakeUnstakeRoundtrip(uint256 amount) public {
        amount = bound(amount, 32 ether, 1_000_000 ether);

        // Deploy fresh vault for isolation
        (Cruzible freshVault, StAETHEL freshSt, MockAETHELInvariant freshToken) = _deployFreshVault();
        address user = address(0xFADE);
        freshToken.mint(user, amount);
        vm.prank(user);
        freshToken.approve(address(freshVault), amount);

        // Stake
        vm.prank(user);
        uint256 shares = freshVault.stake(amount);
        assertEq(shares, amount, "Initial stake should be 1:1");

        // Unstake all
        vm.prank(user);
        (uint256 wId,) = freshVault.unstake(shares);

        // Warp past unbonding
        vm.warp(block.timestamp + 15 days);

        // Withdraw
        uint256 balBefore = freshToken.balanceOf(user);
        vm.prank(user);
        freshVault.withdraw(wId);
        uint256 balAfter = freshToken.balanceOf(user);

        assertEq(balAfter - balBefore, amount, "Round-trip should return exact amount at 1:1");
    }

    /// @notice Multiple stakers at the same rate get proportional shares.
    function testFuzz_multipleStakersProportionalShares(uint256[4] memory amounts) public {
        (Cruzible freshVault, StAETHEL freshSt, MockAETHELInvariant freshToken) = _deployFreshVault();

        uint256 totalDeposited = 0;
        uint256 totalSharesIssued = 0;

        for (uint256 i = 0; i < 4; i++) {
            amounts[i] = bound(amounts[i], 32 ether, 500_000 ether);
            address user = address(uint160(0xF000 + i));
            freshToken.mint(user, amounts[i]);
            vm.prank(user);
            freshToken.approve(address(freshVault), amounts[i]);
            vm.prank(user);
            uint256 shares = freshVault.stake(amounts[i]);

            totalDeposited += amounts[i];
            totalSharesIssued += shares;
        }

        // All at 1:1 rate → total shares = total deposited
        assertEq(totalSharesIssued, totalDeposited, "Total shares != total deposited at 1:1");
        assertEq(freshVault.getTotalPooledAethel(), totalDeposited, "TotalPooled != totalDeposited");
    }

    /// @notice Unstaking more shares than held should always revert.
    function testFuzz_unstakeNeverExceedsShares(uint256 stakeAmount, uint256 extraShares) public {
        stakeAmount = bound(stakeAmount, 32 ether, 1_000_000 ether);
        extraShares = bound(extraShares, 1, 1_000_000 ether);

        (Cruzible freshVault, StAETHEL freshSt, MockAETHELInvariant freshToken) = _deployFreshVault();
        address user = address(0xBEEF);
        freshToken.mint(user, stakeAmount);
        vm.prank(user);
        freshToken.approve(address(freshVault), stakeAmount);
        vm.prank(user);
        uint256 shares = freshVault.stake(stakeAmount);

        // Try to unstake more than held
        uint256 tooMany = shares + extraShares;
        vm.prank(user);
        vm.expectRevert();
        freshVault.unstake(tooMany);
    }

    /// @notice Withdrawal before unbonding period always fails.
    function testFuzz_withdrawalTimingEnforcement(uint256 stakeAmount, uint256 timeWarp) public {
        stakeAmount = bound(stakeAmount, 32 ether, 1_000_000 ether);
        // Warp between 0 and 13 days (less than unbonding period)
        timeWarp = bound(timeWarp, 0, 13 days);

        (Cruzible freshVault, StAETHEL freshSt, MockAETHELInvariant freshToken) = _deployFreshVault();
        address user = address(0xCAFE);
        freshToken.mint(user, stakeAmount);
        vm.prank(user);
        freshToken.approve(address(freshVault), stakeAmount);
        vm.prank(user);
        uint256 shares = freshVault.stake(stakeAmount);

        vm.prank(user);
        (uint256 wId,) = freshVault.unstake(shares);

        // Warp less than unbonding period
        vm.warp(block.timestamp + timeWarp);

        // Should revert
        vm.prank(user);
        vm.expectRevert();
        freshVault.withdraw(wId);
    }

    /// @notice Zero-amount stake always reverts.
    function testFuzz_stakeRevertsOnZero(uint256 dummy) public {
        (Cruzible freshVault,,) = _deployFreshVault();
        address user = address(0xDEAF);
        vm.prank(user);
        vm.expectRevert(Cruzible.ZeroAmount.selector);
        freshVault.stake(0);
    }

    // ═════════════════════════════════════════════════════════════════════════
    // HELPERS - Fresh vault deployment for isolated fuzz tests
    // ═════════════════════════════════════════════════════════════════════════

    function _deployFreshVault() internal returns (Cruzible, StAETHEL, MockAETHELInvariant) {
        MockAETHELInvariant token = new MockAETHELInvariant();
        address adm = address(0xAD);

        // Deploy verifier
        VaultTEEVerifier vImpl = new VaultTEEVerifier();
        bytes memory vInit = abi.encodeCall(VaultTEEVerifier.initialize, (adm));
        ERC1967Proxy vProxy = new ERC1967Proxy(address(vImpl), vInit);
        VaultTEEVerifier ver = VaultTEEVerifier(address(vProxy));

        // Deploy stAETHEL
        StAETHEL stImpl = new StAETHEL();
        bytes memory stInit = abi.encodeCall(StAETHEL.initialize, (adm, address(0xDEAD)));
        ERC1967Proxy stProxy = new ERC1967Proxy(address(stImpl), stInit);
        StAETHEL st = StAETHEL(address(stProxy));

        // Deploy vault
        Cruzible cImpl = new Cruzible();
        bytes memory cInit = abi.encodeCall(
            Cruzible.initialize,
            (adm, address(token), address(st), address(ver), treasury)
        );
        ERC1967Proxy cProxy = new ERC1967Proxy(address(cImpl), cInit);
        Cruzible c = Cruzible(address(cProxy));

        // Grant VAULT_ROLE
        bytes32 vRole = st.VAULT_ROLE();
        vm.prank(adm);
        st.grantRole(vRole, address(c));

        // Setup TEE
        vm.startPrank(adm);
        c.grantRole(c.ORACLE_ROLE(), oracle);
        ver.setVendorRootKey(0, VENDOR_ROOT_X, VENDOR_ROOT_Y);
        bytes32 keyMsg = sha256(abi.encodePacked(P256_PUB_X, P256_PUB_Y, uint8(0)));
        (bytes32 vr, bytes32 vs) = vm.signP256(VENDOR_ROOT_PRIV, keyMsg);
        ver.registerEnclave(
            ENCLAVE_HASH, SIGNER_HASH, bytes32(0), 0, "SGX v1",
            P256_PUB_X, P256_PUB_Y, uint256(vr), uint256(vs)
        );
        bytes32 eid = keccak256(abi.encodePacked(ENCLAVE_HASH, uint8(0)));
        ver.registerOperator(vm.addr(operatorPrivKey), eid, "Op");
        SgxVerifier sv = new SgxVerifier();
        ver.setPlatformVerifier(0, address(sv));
        c.setSelectionPolicyHash(TEST_POLICY_HASH);
        c.commitUniverseHash(1, TEST_UNIVERSE_HASH);
        c.commitStakeSnapshot(1, TEST_SNAPSHOT_HASH, c.getTotalShares());
        vm.stopPrank();

        return (c, st, token);
    }
}
