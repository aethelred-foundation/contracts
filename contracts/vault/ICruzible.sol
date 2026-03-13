// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/**
 * @title ICruzible
 * @author Aethelred Team
 * @notice Interface for the Cruzible liquid staking protocol with TEE-verified
 *         validator selection, MEV protection, and cryptographic reward verification.
 *
 * @dev Cruzible is the flagship staking primitive for the Aethelred L1.
 *      Users stake AETHEL and receive stAETHEL (a rebasing liquid staking token).
 *      Validator selection, MEV ordering, and reward distribution all execute inside
 *      TEE enclaves and are verified on-chain via attestation proofs.
 *
 * Architecture:
 * ┌────────────────────────────────────────────────────────────────────────────┐
 * │                         CRUZIBLE LIFECYCLE                              │
 * ├────────────────────────────────────────────────────────────────────────────┤
 * │                                                                            │
 * │   stake(amount) ──► mint stAETHEL ──► TEE Validator Selection ──►         │
 * │   ──► Delegation ──► Epoch Rewards ──► TEE Reward Calc ──►               │
 * │   ──► distributeRewards() ──► stAETHEL rebases ──► claimRewards()        │
 * │                                                                            │
 * │   unstake(shares) ──► Unbonding Queue (14 days) ──► withdraw()           │
 * │                                                                            │
 * └────────────────────────────────────────────────────────────────────────────┘
 *
 * @custom:security-contact security@aethelred.io
 */
interface ICruzible {
    // =========================================================================
    // EVENTS
    // =========================================================================

    /// @notice Emitted when a user stakes AETHEL and receives stAETHEL shares.
    event Staked(
        address indexed user,
        uint256 aethelAmount,
        uint256 sharesIssued,
        uint256 referralCode
    );

    /// @notice Emitted when a user requests unstaking (enters unbonding queue).
    event UnstakeRequested(
        address indexed user,
        uint256 shares,
        uint256 aethelAmount,
        uint256 indexed withdrawalId,
        uint256 completionTime
    );

    /// @notice Emitted when a user withdraws after the unbonding period.
    event Withdrawn(
        address indexed user,
        uint256 indexed withdrawalId,
        uint256 aethelAmount
    );

    /// @notice Emitted when rewards are distributed for an epoch (TEE-verified).
    event RewardsDistributed(
        uint256 indexed epoch,
        uint256 totalRewards,
        uint256 protocolFee,
        bytes32 rewardsMerkleRoot,
        bytes32 teeAttestationHash
    );

    /// @notice Emitted when the validator set is updated (TEE-verified).
    event ValidatorSetUpdated(
        uint256 indexed epoch,
        uint256 validatorCount,
        bytes32 selectionProofHash,
        bytes32 eligibleUniverseHash
    );

    /// @notice Emitted when a validator is added to the active set.
    event ValidatorActivated(
        address indexed validator,
        uint256 stake,
        uint256 performanceScore,
        uint256 decentralizationScore
    );

    /// @notice Emitted when a validator is removed from the active set.
    event ValidatorDeactivated(
        address indexed validator,
        string reason
    );

    /// @notice Emitted when MEV revenue is redistributed to stakers.
    event MEVRedistributed(
        uint256 indexed epoch,
        uint256 mevAmount,
        uint256 stakerShare,
        uint256 protocolShare
    );

    /// @notice Emitted when the exchange rate between AETHEL and stAETHEL changes.
    event ExchangeRateUpdated(
        uint256 indexed epoch,
        uint256 totalPooledAethel,
        uint256 totalShares
    );

    /// @notice Emitted when the approved selection policy hash is updated.
    event SelectionPolicyUpdated(bytes32 indexed policyHash);

    /// @notice Emitted when the eligible-universe hash is committed for an epoch.
    event EligibleUniverseHashCommitted(uint256 indexed epoch, bytes32 indexed universeHash);

    /// @notice Emitted when the stake snapshot hash is committed for an epoch.
    /// @param totalShares The on-chain total share supply at commitment time,
    ///        anchoring the snapshot to verifiable EVM state.
    event StakeSnapshotCommitted(uint256 indexed epoch, bytes32 indexed snapshotHash, uint256 totalShares);

    /// @notice Emitted when the delegation registry root is committed for an epoch.
    event DelegationSnapshotCommitted(uint256 indexed epoch, bytes32 indexed delegationRoot);

    /// @notice Emitted when a delegation commitment is revoked by the guardian.
    event DelegationSnapshotRevoked(uint256 indexed epoch);

    // --- Delegation bridge hardening events ---

    /// @notice Emitted when an independent attestor submits a delegation vote.
    event DelegationVoteSubmitted(
        uint256 indexed epoch,
        address indexed attestor,
        bytes32 indexed delegationRoot,
        uint256 voteCount
    );

    /// @notice Emitted when enough attestors agree and the delegation root is
    ///         auto-committed via the multi-attestor quorum.
    event DelegationQuorumReached(
        uint256 indexed epoch,
        bytes32 indexed delegationRoot,
        uint256 quorumSize
    );

    /// @notice Emitted when a keeper deposits AETHEL as a bond.
    event KeeperBondDeposited(address indexed keeper, uint256 amount, uint256 totalBond);

    /// @notice Emitted when a keeper withdraws their bond.
    event KeeperBondWithdrawn(address indexed keeper, uint256 amount, uint256 remainingBond);

    /// @notice Emitted when the guardian slashes a keeper's bond for delegation fraud.
    event KeeperBondSlashed(address indexed keeper, uint256 slashedAmount, address indexed recipient);

    /// @notice Emitted when a keeper's bond is frozen pending fraud investigation.
    event KeeperBondFrozen(address indexed keeper, uint256 indexed epoch);

    /// @notice Emitted when a keeper's bond freeze is cleared (by slash or release).
    event KeeperBondUnfrozen(address indexed keeper);

    /// @notice Emitted when an address flags a delegation commitment during
    ///         the challenge period.
    event DelegationChallenged(uint256 indexed epoch, address indexed challenger, uint256 challengeCount);

    /// @notice Emitted when the challenge count reaches DELEGATION_CHALLENGE_THRESHOLD
    ///         and the commitment is automatically revoked (circuit-breaker).
    event DelegationAutoRevoked(uint256 indexed epoch, uint256 challengeCount);

    /// @notice Emitted when the guardian confirms an auto-revoked commitment was
    ///         genuinely fraudulent, making challenger bonds refundable.
    event DelegationFraudConfirmed(uint256 indexed epoch);

    /// @notice Emitted when a challenger bond is refunded (fraud confirmed by guardian).
    event ChallengerBondRefunded(uint256 indexed epoch, address indexed challenger, uint256 amount);

    /// @notice Emitted when a challenger bond is slashed to the treasury
    ///         (griefing/false challenge or adjudication period expired).
    event ChallengerBondSlashed(uint256 indexed epoch, address indexed challenger, uint256 amount);

    /// @notice Emitted when governance toggles the delegation quorum requirement.
    event DelegationQuorumToggled(bool enabled);

    // =========================================================================
    // STAKING OPERATIONS
    // =========================================================================

    /**
     * @notice Stake AETHEL tokens and receive stAETHEL shares.
     * @param amount The amount of AETHEL to stake (in wei, 18 decimals).
     * @return shares The number of stAETHEL shares minted to the caller.
     *
     * @dev Requirements:
     *      - amount >= MIN_STAKE (32 AETHEL)
     *      - Caller must have approved this contract to transfer `amount`
     *      - Contract must not be paused
     *      - Caller must not be blacklisted
     */
    function stake(uint256 amount) external returns (uint256 shares);

    /**
     * @notice Stake AETHEL tokens with a referral code.
     * @param amount The amount of AETHEL to stake.
     * @param referralCode Referral code for tracking (0 = none).
     * @return shares The number of stAETHEL shares minted.
     */
    function stakeWithReferral(uint256 amount, uint256 referralCode)
        external
        returns (uint256 shares);

    /**
     * @notice Request unstaking of stAETHEL shares.
     * @param shares The number of stAETHEL shares to burn.
     * @return withdrawalId Unique ID for tracking the unbonding request.
     * @return aethelAmount The AETHEL amount that will be claimable after unbonding.
     *
     * @dev Enters the unbonding queue. AETHEL is claimable after UNBONDING_PERIOD.
     *      The exchange rate at request time determines the AETHEL amount.
     */
    function unstake(uint256 shares)
        external
        returns (uint256 withdrawalId, uint256 aethelAmount);

    /**
     * @notice Withdraw AETHEL after the unbonding period completes.
     * @param withdrawalId The withdrawal request ID from unstake().
     * @return amount The AETHEL amount transferred to the caller.
     *
     * @dev Reverts if the unbonding period has not elapsed.
     */
    function withdraw(uint256 withdrawalId) external returns (uint256 amount);

    /**
     * @notice Batch withdraw multiple completed unbonding requests.
     * @param withdrawalIds Array of withdrawal request IDs.
     * @return totalAmount Total AETHEL withdrawn.
     */
    function batchWithdraw(uint256[] calldata withdrawalIds)
        external
        returns (uint256 totalAmount);

    // =========================================================================
    // VALIDATOR MANAGEMENT (TEE-CONTROLLED)
    // =========================================================================

    /**
     * @notice Update the active validator set based on TEE-computed scores.
     * @param teeAttestation The TEE attestation proof (SGX/Nitro/SEV).
     * @param validators Encoded validator set from the TEE enclave.
     * @param epoch The epoch number for this update.
     *
     * @dev Only callable by the TEE oracle relayer with a valid attestation.
     *      The attestation must be signed by a registered TEE enclave.
     */
    function updateValidatorSet(
        bytes calldata teeAttestation,
        bytes calldata validators,
        uint256 epoch
    ) external;

    // =========================================================================
    // REWARD DISTRIBUTION (TEE-VERIFIED)
    // =========================================================================

    /**
     * @notice Distribute epoch rewards calculated inside a TEE enclave.
     * @param teeAttestation The TEE attestation proving correct computation.
     * @param epoch The epoch number.
     * @param totalRewards Total rewards to distribute.
     * @param merkleRoot Merkle root of individual reward allocations.
     * @param protocolFee Protocol's share of rewards.
     *
     * @dev The TEE enclave computes fair reward distribution based on:
     *      - Proportional stake weighting
     *      - Performance bonuses (uptime, latency)
     *      - MEV redistribution
     *      The merkle root allows gas-efficient verification of individual claims.
     */
    function distributeRewards(
        bytes calldata teeAttestation,
        uint256 epoch,
        uint256 totalRewards,
        bytes32 merkleRoot,
        uint256 protocolFee
    ) external;

    /**
     * @notice Submit MEV revenue captured by the protocol for redistribution.
     * @param teeAttestation TEE proof of fair MEV ordering.
     * @param epoch The epoch number.
     * @param mevAmount Total MEV revenue to redistribute.
     */
    function submitMEVRevenue(
        bytes calldata teeAttestation,
        uint256 epoch,
        uint256 mevAmount
    ) external;

    // =========================================================================
    // TEE ATTESTATION VERIFICATION
    // =========================================================================

    /**
     * @notice Verify a TEE attestation on-chain.
     * @param attestation The raw attestation document.
     * @return valid Whether the attestation is valid.
     * @return payload The attested payload (decoded).
     * @return platform The TEE platform that produced the attestation.
     */
    function verifyAttestation(bytes calldata attestation)
        external
        view
        returns (bool valid, bytes memory payload, uint8 platform);

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /// @notice Get the current AETHEL-to-stAETHEL exchange rate (scaled by 1e18).
    function getExchangeRate() external view returns (uint256);

    /// @notice Get total AETHEL pooled in the vault.
    function getTotalPooledAethel() external view returns (uint256);

    /// @notice Get total stAETHEL shares outstanding.
    function getTotalShares() external view returns (uint256);

    /// @notice Convert an AETHEL amount to stAETHEL shares.
    function getSharesForAethel(uint256 aethelAmount) external view returns (uint256);

    /// @notice Convert stAETHEL shares to AETHEL amount.
    function getAethelForShares(uint256 shares) external view returns (uint256);

    /// @notice Get the current epoch number.
    function getCurrentEpoch() external view returns (uint256);

    /// @notice Get the number of active validators.
    function getActiveValidatorCount() external view returns (uint256);

    /// @notice Check if a withdrawal request is claimable.
    function isWithdrawalClaimable(uint256 withdrawalId) external view returns (bool);
}
