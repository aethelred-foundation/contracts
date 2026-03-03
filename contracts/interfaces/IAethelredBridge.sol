// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {AethelredTypes} from "../types/AethelredTypes.sol";

/**
 * @title IAethelredBridge
 * @author Aethelred Team
 * @notice Interface for moving assets between Ethereum and the Aethelred L1.
 *
 * @dev Backed by the `AethelredBridge.sol` lock-and-mint contract on Ethereum
 *      and the `BridgeModule` (Rust) on the Aethelred L1.
 *
 *      Deposits:  User locks ETH/ERC-20 on Ethereum → relayers mint wrapped
 *                 tokens on Aethelred.
 *      Withdrawals: User burns wrapped tokens on Aethelred → relayers vote
 *                   to unlock the original asset on Ethereum (67 % consensus
 *                   + 7-day challenge period).
 *
 * Security model:
 *   - Multi-sig relayer consensus (top-20 Aethelred validators).
 *   - Per-block mint ceiling (defense-in-depth).
 *   - Rate limiting per period.
 *   - 7-day fraud-proof challenge window on withdrawals.
 *   - 2-of-N guardian emergency withdrawals.
 *
 * @custom:security-contact security@aethelred.io
 */
interface IAethelredBridge {
    // =====================================================================
    // Events
    // =====================================================================

    /// @notice Emitted when a user deposits ETH or ERC-20 tokens for bridging.
    event Deposited(
        uint256 indexed nonce,
        address indexed sender,
        address indexed token,
        uint256 amount,
        uint256 destChainId,
        address recipient
    );

    /// @notice Emitted when a withdrawal is finalized on the source chain.
    event WithdrawalFinalized(
        uint256 indexed nonce,
        address indexed recipient,
        address indexed token,
        uint256 amount
    );

    /// @notice Emitted when a withdrawal enters the challenge period.
    event WithdrawalProposed(
        uint256 indexed nonce,
        address indexed recipient,
        uint256 amount,
        uint256 challengeDeadline
    );

    /// @notice Emitted when a transfer is challenged during the fraud-proof window.
    event TransferChallenged(
        uint256 indexed nonce,
        address indexed challenger,
        bytes reason
    );

    // =====================================================================
    // Deposits (Ethereum → Aethelred)
    // =====================================================================

    /**
     * @notice Deposit native ETH to be bridged to Aethelred.
     * @param recipient Address on Aethelred that will receive wrapped ETH.
     * @return nonce Unique deposit nonce for tracking.
     *
     * @dev `msg.value` is the deposit amount.
     *
     * Requirements:
     * - `msg.value` >= minimum deposit (0.01 ETH).
     * - `msg.value` <= maximum single deposit (100 ETH).
     * - Caller must not exceed rate limit for the current period.
     */
    function depositETH(
        address recipient
    ) external payable returns (uint256 nonce);

    /**
     * @notice Deposit an ERC-20 token to be bridged to Aethelred.
     * @param token  The ERC-20 token address.
     * @param amount Amount to deposit.
     * @param recipient Address on Aethelred that will receive wrapped tokens.
     * @return nonce Unique deposit nonce for tracking.
     *
     * @dev Caller must have approved this contract for at least `amount`.
     *      Only whitelisted tokens are accepted.
     */
    function depositERC20(
        address token,
        uint256 amount,
        address recipient
    ) external returns (uint256 nonce);

    /**
     * @notice Cancel a pending deposit that has not yet been relayed.
     * @param nonce The deposit nonce to cancel.
     *
     * @dev Only callable by the original depositor within the
     *      cancellation window (1 hour).
     */
    function cancelDeposit(uint256 nonce) external;

    // =====================================================================
    // Withdrawals (Aethelred → Ethereum)
    // =====================================================================

    /**
     * @notice Claim a finalized withdrawal after the challenge period.
     * @param nonce The withdrawal nonce.
     *
     * @dev The withdrawal must have been proposed by the relayer set,
     *      the 7-day challenge period must have elapsed, and no
     *      successful challenge must be outstanding.
     */
    function claimWithdrawal(uint256 nonce) external;

    /**
     * @notice Challenge a pending withdrawal during the fraud-proof window.
     * @param nonce  The withdrawal nonce to challenge.
     * @param proof  Fraud proof data (bridge-specific encoding).
     */
    function challengeWithdrawal(
        uint256 nonce,
        bytes calldata proof
    ) external;

    // =====================================================================
    // Queries
    // =====================================================================

    /**
     * @notice Get a bridge transfer record by nonce.
     * @param nonce The transfer nonce.
     * @return transfer The transfer struct.
     */
    function getTransfer(
        uint256 nonce
    ) external view returns (AethelredTypes.BridgeTransfer memory transfer);

    /**
     * @notice Get the current deposit nonce (next unused nonce).
     * @return nonce The next nonce.
     */
    function currentNonce() external view returns (uint256 nonce);

    /**
     * @notice Check whether a token is whitelisted for bridging.
     * @param token The ERC-20 token address.
     * @return whitelisted True if the token is accepted.
     */
    function isTokenWhitelisted(
        address token
    ) external view returns (bool whitelisted);

    /**
     * @notice Get the remaining deposit capacity for the current rate-limit period.
     * @return remaining Amount (in wei) still available before the rate limit is hit.
     */
    function remainingDepositCapacity()
        external
        view
        returns (uint256 remaining);

    /**
     * @notice Get the challenge deadline for a pending withdrawal.
     * @param nonce The withdrawal nonce.
     * @return deadline Block timestamp after which the withdrawal can be claimed.
     */
    function challengeDeadline(
        uint256 nonce
    ) external view returns (uint256 deadline);
}
