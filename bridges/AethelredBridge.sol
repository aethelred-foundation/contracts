// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @title AethelredBridge
 * @notice Cross-chain bridge for transferring assets and proofs between Ethereum and Aethelred L1
 * @dev Implements a multi-sig validator bridge with proof verification
 */
contract AethelredBridge is ReentrancyGuard, Pausable, AccessControl {
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    // Roles
    bytes32 public constant VALIDATOR_ROLE = keccak256("VALIDATOR_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    // Constants
    uint256 public constant MAX_VALIDATORS = 100;
    uint256 public constant MIN_CONFIRMATIONS = 2;
    uint256 public constant SEAL_VERIFICATION_GAS = 100000;
    uint256 public constant MIN_EMERGENCY_TIMELOCK = 24 hours;
    uint256 public constant MAX_EMERGENCY_TIMELOCK = 14 days;
    uint256 public constant DEFAULT_EMERGENCY_TIMELOCK = 48 hours;

    // Bridge state
    uint256 public requiredConfirmations;
    uint256 public nonce;
    uint256 public bridgeFee; // In wei
    uint256 public emergencyWithdrawalDelay;
    uint256 public emergencyWithdrawalNonce;

    // Supported tokens
    mapping(address => bool) public supportedTokens;
    mapping(address => uint256) public tokenMinAmount;
    mapping(address => uint256) public tokenMaxAmount;

    // Deposit tracking
    struct Deposit {
        address depositor;
        address token;
        uint256 amount;
        bytes32 aethelredRecipient; // 32-byte Aethelred address
        uint256 timestamp;
        bool processed;
    }
    mapping(uint256 => Deposit) public deposits;

    // Withdrawal tracking
    struct Withdrawal {
        bytes32 aethelredTxHash;
        address recipient;
        address token;
        uint256 amount;
        bool executed;
        uint256 confirmations;
        mapping(address => bool) isConfirmed;
    }
    mapping(bytes32 => Withdrawal) public withdrawals;
    bytes32[] public pendingWithdrawals;

    // Seal verification
    struct SealAttestation {
        bytes32 sealId;
        bytes32 modelHash;
        bytes32 inputHash;
        bytes32 outputHash;
        uint256 timestamp;
        bool verified;
        uint256 validatorCount;
    }
    mapping(bytes32 => SealAttestation) public sealAttestations;

    struct EmergencyWithdrawalRequest {
        address token;
        address recipient;
        uint256 amount;
        uint256 queuedAt;
        uint256 executeAfter;
        bool executed;
        bool cancelled;
    }
    mapping(bytes32 => EmergencyWithdrawalRequest) public emergencyWithdrawalRequests;

    // Events
    event TokenAdded(address indexed token, uint256 minAmount, uint256 maxAmount);
    event TokenRemoved(address indexed token);
    event DepositInitiated(
        uint256 indexed depositId,
        address indexed depositor,
        address indexed token,
        uint256 amount,
        bytes32 aethelredRecipient
    );
    event DepositProcessed(uint256 indexed depositId);
    event WithdrawalRequested(
        bytes32 indexed withdrawalId,
        bytes32 aethelredTxHash,
        address indexed recipient,
        address indexed token,
        uint256 amount
    );
    event WithdrawalConfirmed(
        bytes32 indexed withdrawalId,
        address indexed validator
    );
    event WithdrawalExecuted(bytes32 indexed withdrawalId);
    event SealVerified(
        bytes32 indexed sealId,
        bytes32 modelHash,
        bytes32 outputHash
    );
    event EmergencyWithdrawalQueued(
        bytes32 indexed operationId,
        address indexed token,
        address indexed recipient,
        uint256 amount,
        uint256 executeAfter
    );
    event EmergencyWithdrawalExecuted(
        bytes32 indexed operationId,
        address indexed token,
        address indexed recipient,
        uint256 amount
    );
    event EmergencyWithdrawalCancelled(
        bytes32 indexed operationId,
        address indexed cancelledBy
    );
    event EmergencyWithdrawalDelayUpdated(uint256 oldDelay, uint256 newDelay);
    event RequiredConfirmationsUpdated(uint256 oldValue, uint256 newValue);
    event BridgeFeeUpdated(uint256 oldFee, uint256 newFee);

    // SECURITY FIX H-01: EIP-712 domain separator for verifySeal
    bytes32 public DOMAIN_SEPARATOR;
    bytes32 public constant VERIFY_SEAL_TYPEHASH = keccak256(
        "VerifySeal(bytes32 sealId,bytes32 modelHash,bytes32 inputHash,bytes32 outputHash)"
    );

    // Errors
    error TokenNotSupported();
    error AmountBelowMinimum();
    error AmountAboveMaximum();
    error InsufficientFee();
    error WithdrawalAlreadyExecuted();
    error AlreadyConfirmed();
    error InsufficientConfirmations();
    error InvalidSignature();
    error InvalidSealData();
    error SealAlreadyVerified(); // SECURITY FIX H-02
    error InvalidEmergencyDelay();
    error EmergencyWithdrawalNotFound();
    error EmergencyWithdrawalNotReady();
    error EmergencyWithdrawalAlreadyHandled();

    constructor(uint256 _requiredConfirmations, uint256 _bridgeFee) {
        require(_requiredConfirmations >= MIN_CONFIRMATIONS, "Confirmations too low");

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        _grantRole(PAUSER_ROLE, msg.sender);

        requiredConfirmations = _requiredConfirmations;
        bridgeFee = _bridgeFee;
        emergencyWithdrawalDelay = DEFAULT_EMERGENCY_TIMELOCK;

        // SECURITY FIX H-01: EIP-712 domain separator binds signatures to this chain + contract
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("AethelredBridge"),
            keccak256("1"),
            block.chainid,
            address(this)
        ));
    }

    // ============ Token Management ============

    /**
     * @notice Add a supported token
     * @param token Token address
     * @param minAmount Minimum bridge amount
     * @param maxAmount Maximum bridge amount
     */
    function addToken(
        address token,
        uint256 minAmount,
        uint256 maxAmount
    ) external onlyRole(OPERATOR_ROLE) {
        require(maxAmount > minAmount, "Invalid amount range");
        supportedTokens[token] = true;
        tokenMinAmount[token] = minAmount;
        tokenMaxAmount[token] = maxAmount;
        emit TokenAdded(token, minAmount, maxAmount);
    }

    /**
     * @notice Remove a supported token
     * @param token Token address
     */
    function removeToken(address token) external onlyRole(OPERATOR_ROLE) {
        supportedTokens[token] = false;
        emit TokenRemoved(token);
    }

    // ============ Deposit (Ethereum -> Aethelred) ============

    /**
     * @notice Deposit tokens to bridge to Aethelred
     * @param token Token address to deposit
     * @param amount Amount to deposit
     * @param aethelredRecipient Recipient address on Aethelred chain
     */
    function deposit(
        address token,
        uint256 amount,
        bytes32 aethelredRecipient
    ) external payable nonReentrant whenNotPaused {
        if (!supportedTokens[token]) revert TokenNotSupported();
        if (amount < tokenMinAmount[token]) revert AmountBelowMinimum();
        if (amount > tokenMaxAmount[token]) revert AmountAboveMaximum();
        if (msg.value < bridgeFee) revert InsufficientFee();

        // Transfer tokens to bridge — measure actual received for fee-on-transfer tokens
        uint256 balanceBefore = IERC20(token).balanceOf(address(this));
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        uint256 actualReceived = IERC20(token).balanceOf(address(this)) - balanceBefore;

        // Record deposit
        uint256 depositId = nonce++;
        deposits[depositId] = Deposit({
            depositor: msg.sender,
            token: token,
            amount: actualReceived,
            aethelredRecipient: aethelredRecipient,
            timestamp: block.timestamp,
            processed: false
        });

        emit DepositInitiated(
            depositId,
            msg.sender,
            token,
            actualReceived,
            aethelredRecipient
        );
    }

    /**
     * @notice Deposit ETH to bridge to Aethelred
     * @param aethelredRecipient Recipient address on Aethelred chain
     */
    function depositETH(
        bytes32 aethelredRecipient
    ) external payable nonReentrant whenNotPaused {
        uint256 depositAmount = msg.value - bridgeFee;
        require(depositAmount > 0, "Amount must be greater than fee");

        // Record deposit with zero address for ETH
        uint256 depositId = nonce++;
        deposits[depositId] = Deposit({
            depositor: msg.sender,
            token: address(0),
            amount: depositAmount,
            aethelredRecipient: aethelredRecipient,
            timestamp: block.timestamp,
            processed: false
        });

        emit DepositInitiated(
            depositId,
            msg.sender,
            address(0),
            depositAmount,
            aethelredRecipient
        );
    }

    /**
     * @notice Mark deposit as processed (called by validators after Aethelred confirmation)
     * @param depositId Deposit ID to mark processed
     */
    function markDepositProcessed(
        uint256 depositId
    ) external onlyRole(VALIDATOR_ROLE) {
        require(!deposits[depositId].processed, "Already processed");
        deposits[depositId].processed = true;
        emit DepositProcessed(depositId);
    }

    // ============ Withdrawal (Aethelred -> Ethereum) ============

    /**
     * @notice Request a withdrawal from Aethelred
     * @param aethelredTxHash Transaction hash on Aethelred proving the lock
     * @param recipient Ethereum recipient address
     * @param token Token address (0x0 for ETH)
     * @param amount Amount to withdraw
     */
    function requestWithdrawal(
        bytes32 aethelredTxHash,
        address recipient,
        address token,
        uint256 amount
    ) external onlyRole(VALIDATOR_ROLE) {
        bytes32 withdrawalId = keccak256(
            abi.encodePacked(aethelredTxHash, recipient, token, amount)
        );

        require(!withdrawals[withdrawalId].executed, "Already executed");

        if (withdrawals[withdrawalId].aethelredTxHash == bytes32(0)) {
            // New withdrawal
            Withdrawal storage w = withdrawals[withdrawalId];
            w.aethelredTxHash = aethelredTxHash;
            w.recipient = recipient;
            w.token = token;
            w.amount = amount;
            pendingWithdrawals.push(withdrawalId);

            emit WithdrawalRequested(
                withdrawalId,
                aethelredTxHash,
                recipient,
                token,
                amount
            );
        }
    }

    /**
     * @notice Confirm a withdrawal request
     * @param withdrawalId Withdrawal ID to confirm
     */
    function confirmWithdrawal(
        bytes32 withdrawalId
    ) external onlyRole(VALIDATOR_ROLE) {
        Withdrawal storage w = withdrawals[withdrawalId];
        if (w.executed) revert WithdrawalAlreadyExecuted();
        if (w.isConfirmed[msg.sender]) revert AlreadyConfirmed();

        w.isConfirmed[msg.sender] = true;
        w.confirmations++;

        emit WithdrawalConfirmed(withdrawalId, msg.sender);
    }

    /**
     * @notice Execute a confirmed withdrawal
     * @param withdrawalId Withdrawal ID to execute
     */
    function executeWithdrawal(
        bytes32 withdrawalId
    ) external nonReentrant whenNotPaused {
        Withdrawal storage w = withdrawals[withdrawalId];
        if (w.executed) revert WithdrawalAlreadyExecuted();
        if (w.confirmations < requiredConfirmations) revert InsufficientConfirmations();

        w.executed = true;

        if (w.token == address(0)) {
            // Transfer ETH
            (bool success, ) = w.recipient.call{value: w.amount}("");
            require(success, "ETH transfer failed");
        } else {
            // Transfer tokens
            IERC20(w.token).safeTransfer(w.recipient, w.amount);
        }

        emit WithdrawalExecuted(withdrawalId);
    }

    // ============ Seal Verification ============

    /**
     * @notice Verify a Digital Seal from Aethelred
     * @param sealId Seal ID from Aethelred
     * @param modelHash Hash of the AI model used
     * @param inputHash Hash of the input data
     * @param outputHash Hash of the output
     * @param signatures Validator signatures
     */
    function verifySeal(
        bytes32 sealId,
        bytes32 modelHash,
        bytes32 inputHash,
        bytes32 outputHash,
        bytes[] calldata signatures
    ) external whenNotPaused {
        // SECURITY FIX H-02: Prevent overwriting existing verified attestations
        if (sealAttestations[sealId].verified) revert SealAlreadyVerified();

        if (signatures.length < requiredConfirmations) revert InsufficientConfirmations();

        // SECURITY FIX H-01: EIP-712 structured hash with domain separation
        bytes32 structHash = keccak256(abi.encode(
            VERIFY_SEAL_TYPEHASH,
            sealId,
            modelHash,
            inputHash,
            outputHash
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));

        // Verify signatures
        address[] memory signers = new address[](signatures.length);
        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = digest.recover(signatures[i]);
            if (!hasRole(VALIDATOR_ROLE, signer)) revert InvalidSignature();

            // Check for duplicates
            for (uint256 j = 0; j < i; j++) {
                require(signers[j] != signer, "Duplicate signer");
            }
            signers[i] = signer;
        }

        // Store attestation
        sealAttestations[sealId] = SealAttestation({
            sealId: sealId,
            modelHash: modelHash,
            inputHash: inputHash,
            outputHash: outputHash,
            timestamp: block.timestamp,
            verified: true,
            validatorCount: signatures.length
        });

        emit SealVerified(sealId, modelHash, outputHash);
    }

    /**
     * @notice Check if a seal is verified
     * @param sealId Seal ID to check
     * @return isVerified Whether the seal is verified
     * @return attestation The seal attestation data
     */
    function isSealVerified(
        bytes32 sealId
    ) external view returns (bool isVerified, SealAttestation memory attestation) {
        attestation = sealAttestations[sealId];
        isVerified = attestation.verified;
    }

    // ============ Admin Functions ============

    /**
     * @notice Update required confirmations
     * @param _requiredConfirmations New required confirmations
     */
    function setRequiredConfirmations(
        uint256 _requiredConfirmations
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_requiredConfirmations >= MIN_CONFIRMATIONS, "Too low");
        emit RequiredConfirmationsUpdated(requiredConfirmations, _requiredConfirmations);
        requiredConfirmations = _requiredConfirmations;
    }

    /**
     * @notice Update bridge fee
     * @param _bridgeFee New bridge fee in wei
     */
    function setBridgeFee(
        uint256 _bridgeFee
    ) external onlyRole(OPERATOR_ROLE) {
        emit BridgeFeeUpdated(bridgeFee, _bridgeFee);
        bridgeFee = _bridgeFee;
    }

    /**
     * @notice Pause the bridge
     */
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the bridge
     */
    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /**
     * @notice Withdraw collected fees
     * @param to Recipient address
     */
    function withdrawFees(address to) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 balance = address(this).balance;
        (bool success, ) = to.call{value: balance}("");
        require(success, "Transfer failed");
    }

    /**
     * @notice Update emergency withdrawal timelock delay.
     * @param newDelay Delay in seconds.
     */
    function setEmergencyWithdrawalDelay(
        uint256 newDelay
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newDelay < MIN_EMERGENCY_TIMELOCK || newDelay > MAX_EMERGENCY_TIMELOCK) {
            revert InvalidEmergencyDelay();
        }
        uint256 oldDelay = emergencyWithdrawalDelay;
        emergencyWithdrawalDelay = newDelay;
        emit EmergencyWithdrawalDelayUpdated(oldDelay, newDelay);
    }

    /**
     * @notice Queue an emergency withdrawal request.
     * @param token Token address (address(0) for ETH).
     * @param to Recipient address.
     * @param amount Amount to withdraw.
     */
    function queueEmergencyWithdrawal(
        address token,
        address to,
        uint256 amount
    ) public onlyRole(DEFAULT_ADMIN_ROLE) returns (bytes32 operationId) {
        require(to != address(0), "Invalid recipient");
        require(amount > 0, "Invalid amount");

        operationId = keccak256(
            abi.encodePacked(
                token,
                to,
                amount,
                emergencyWithdrawalNonce,
                block.chainid,
                address(this)
            )
        );

        emergencyWithdrawalRequests[operationId] = EmergencyWithdrawalRequest({
            token: token,
            recipient: to,
            amount: amount,
            queuedAt: block.timestamp,
            executeAfter: block.timestamp + emergencyWithdrawalDelay,
            executed: false,
            cancelled: false
        });

        emergencyWithdrawalNonce++;
        emit EmergencyWithdrawalQueued(
            operationId,
            token,
            to,
            amount,
            block.timestamp + emergencyWithdrawalDelay
        );
    }

    /**
     * @notice Execute a queued emergency withdrawal after timelock.
     * @param operationId Queued operation id.
     */
    function executeEmergencyWithdrawal(
        bytes32 operationId
    ) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        EmergencyWithdrawalRequest storage req = emergencyWithdrawalRequests[operationId];
        if (req.queuedAt == 0) revert EmergencyWithdrawalNotFound();
        if (req.executed || req.cancelled) revert EmergencyWithdrawalAlreadyHandled();
        if (block.timestamp < req.executeAfter) revert EmergencyWithdrawalNotReady();

        req.executed = true;
        if (req.token == address(0)) {
            (bool ok, ) = req.recipient.call{value: req.amount}("");
            require(ok, "ETH transfer failed");
        } else {
            IERC20(req.token).safeTransfer(req.recipient, req.amount);
        }

        emit EmergencyWithdrawalExecuted(operationId, req.token, req.recipient, req.amount);
    }

    /**
     * @notice Cancel a queued emergency withdrawal operation.
     * @param operationId Queued operation id.
     */
    function cancelEmergencyWithdrawal(
        bytes32 operationId
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        EmergencyWithdrawalRequest storage req = emergencyWithdrawalRequests[operationId];
        if (req.queuedAt == 0) revert EmergencyWithdrawalNotFound();
        if (req.executed || req.cancelled) revert EmergencyWithdrawalAlreadyHandled();

        req.cancelled = true;
        emit EmergencyWithdrawalCancelled(operationId, msg.sender);
    }

    /**
     * @notice Emergency withdraw stuck tokens
     * @param token Token address
     * @param to Recipient address
     * @param amount Amount to withdraw
     */
    function emergencyWithdraw(
        address token,
        address to,
        uint256 amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        queueEmergencyWithdrawal(token, to, amount);
    }

    // ============ View Functions ============

    /**
     * @notice Get pending withdrawals count
     */
    function getPendingWithdrawalsCount() external view returns (uint256) {
        return pendingWithdrawals.length;
    }

    /**
     * @notice Check if withdrawal is confirmed by validator
     * @param withdrawalId Withdrawal ID
     * @param validator Validator address
     */
    function isWithdrawalConfirmedBy(
        bytes32 withdrawalId,
        address validator
    ) external view returns (bool) {
        return withdrawals[withdrawalId].isConfirmed[validator];
    }

    // Receive ETH
    receive() external payable {}
}
