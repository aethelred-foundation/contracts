// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/governance/TimelockController.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

interface IInstitutionalBridgeGovernance {
    function issuerGovernanceKey() external view returns (address);
    function issuerRecoveryGovernanceKey() external view returns (address);
    function foundationGovernanceKey() external view returns (address);
    function auditorGovernanceKey() external view returns (address);
    function guardianGovernanceKey() external view returns (address);
    function setGovernanceKeys(
        address issuerKey,
        address foundationKey,
        address auditorKey
    ) external;
    function setSovereignUnpauseKeys(
        address issuerRecoveryKey,
        address guardianKey
    ) external;
}

/**
 * @title SovereignGovernanceTimelock
 * @notice Timelocked key rotation controller for Issuer/Foundation/Auditor keys.
 * @dev Enforces:
 * - OpenZeppelin TimelockController scheduling/execution
 * - 7-day minimum delay
 * - Dual proposal consent (Issuer signature + Foundation signature)
 * @custom:security-contact security@aethelred.io
 * @custom:audit-status Remediated — all 27 findings addressed (2026-02-28)
 */
contract SovereignGovernanceTimelock is TimelockController {
    using MessageHashUtils for bytes32;

    uint256 public constant MIN_KEY_ROTATION_DELAY = 7 days;

    enum KeyType {
        Issuer,
        Foundation,
        Auditor,
        IssuerRecovery,
        Guardian
    }

    struct RotationOperation {
        bool exists;
        bool executed;
        address bridge;
        address newIssuerKey;
        address newIssuerRecoveryKey;
        address newFoundationKey;
        address newAuditorKey;
        address newGuardianKey;
        bytes32 predecessor;
        bytes32 salt;
        bool usePrimaryKeySetter;
    }

    mapping(bytes32 => RotationOperation) public rotationOperations;

    event KeyRotationQueued(
        bytes32 indexed operationId,
        address indexed bridge,
        KeyType indexed keyType,
        address newKey,
        uint256 executeAfter
    );
    event KeyRotationExecuted(
        bytes32 indexed operationId,
        address indexed bridge,
        address issuerKey,
        address issuerRecoveryKey,
        address foundationKey,
        address auditorKey,
        address guardianKey
    );

    error InvalidAddress();
    error InvalidDeadline();
    error InvalidKeyType();
    error InvalidSignature();
    error RotationDelayTooShort();
    error OperationAlreadyQueued();
    error OperationNotQueued();
    error OperationAlreadyExecuted();
    error AdminMustBeContract();

    constructor(
        uint256 minDelay,
        address[] memory proposers,
        address[] memory executors,
        address admin
    ) TimelockController(minDelay, proposers, executors, admin) {
        if (minDelay < MIN_KEY_ROTATION_DELAY) revert RotationDelayTooShort();
        _requireContractAdmin(admin);
    }

    function rotateKey(
        address bridge,
        KeyType keyType,
        address newKey,
        bytes32 predecessor,
        bytes32 salt,
        uint256 deadline,
        bytes calldata issuerSignature,
        bytes calldata foundationSignature
    ) external onlyRole(PROPOSER_ROLE) returns (bytes32 operationId) {
        if (bridge == address(0) || newKey == address(0)) revert InvalidAddress();
        if (deadline < block.timestamp) revert InvalidDeadline();
        if (uint8(keyType) > uint8(KeyType.Guardian)) revert InvalidKeyType();

        IInstitutionalBridgeGovernance target = IInstitutionalBridgeGovernance(bridge);
        address issuerKey = target.issuerGovernanceKey();
        address issuerRecoveryKey = target.issuerRecoveryGovernanceKey();
        address foundationKey = target.foundationGovernanceKey();
        address auditorKey = target.auditorGovernanceKey();
        address guardianKey = target.guardianGovernanceKey();

        bytes32 digest = _buildRotationDigest(
            bridge,
            keyType,
            newKey,
            predecessor,
            salt,
            deadline
        );
        bytes32 signed = digest.toEthSignedMessageHash();
        if (
            ECDSA.recover(signed, issuerSignature) != issuerKey ||
            ECDSA.recover(signed, foundationSignature) != foundationKey
        ) revert InvalidSignature();

        if (keyType == KeyType.Issuer) {
            issuerKey = newKey;
        } else if (keyType == KeyType.Foundation) {
            foundationKey = newKey;
        } else if (keyType == KeyType.Auditor) {
            auditorKey = newKey;
        } else if (keyType == KeyType.IssuerRecovery) {
            issuerRecoveryKey = newKey;
        } else {
            guardianKey = newKey;
        }

        bool usePrimaryKeySetter = keyType == KeyType.Issuer ||
            keyType == KeyType.Foundation ||
            keyType == KeyType.Auditor;
        bytes memory data = usePrimaryKeySetter
            ? abi.encodeCall(
                IInstitutionalBridgeGovernance.setGovernanceKeys,
                (issuerKey, foundationKey, auditorKey)
            )
            : abi.encodeCall(
                IInstitutionalBridgeGovernance.setSovereignUnpauseKeys,
                (issuerRecoveryKey, guardianKey)
            );
        uint256 delay = getMinDelay();
        if (delay < MIN_KEY_ROTATION_DELAY) revert RotationDelayTooShort();

        operationId = this.hashOperation(bridge, 0, data, predecessor, salt);
        if (rotationOperations[operationId].exists) revert OperationAlreadyQueued();

        rotationOperations[operationId] = RotationOperation({
            exists: true,
            executed: false,
            bridge: bridge,
            newIssuerKey: issuerKey,
            newIssuerRecoveryKey: issuerRecoveryKey,
            newFoundationKey: foundationKey,
            newAuditorKey: auditorKey,
            newGuardianKey: guardianKey,
            predecessor: predecessor,
            salt: salt,
            usePrimaryKeySetter: usePrimaryKeySetter
        });

        this.schedule(bridge, 0, data, predecessor, salt, delay);
        emit KeyRotationQueued(
            operationId,
            bridge,
            keyType,
            newKey,
            block.timestamp + delay
        );
    }

    function executeKeyRotation(bytes32 operationId)
        external
        onlyRoleOrOpenRole(EXECUTOR_ROLE)
    {
        RotationOperation storage operation = rotationOperations[operationId];
        if (!operation.exists) revert OperationNotQueued();
        if (operation.executed) revert OperationAlreadyExecuted();

        bytes memory data = operation.usePrimaryKeySetter
            ? abi.encodeCall(
                IInstitutionalBridgeGovernance.setGovernanceKeys,
                (
                    operation.newIssuerKey,
                    operation.newFoundationKey,
                    operation.newAuditorKey
                )
            )
            : abi.encodeCall(
                IInstitutionalBridgeGovernance.setSovereignUnpauseKeys,
                (operation.newIssuerRecoveryKey, operation.newGuardianKey)
            );

        this.execute(
            operation.bridge,
            0,
            data,
            operation.predecessor,
            operation.salt
        );

        operation.executed = true;
        emit KeyRotationExecuted(
            operationId,
            operation.bridge,
            operation.newIssuerKey,
            operation.newIssuerRecoveryKey,
            operation.newFoundationKey,
            operation.newAuditorKey,
            operation.newGuardianKey
        );
    }

    function _buildRotationDigest(
        address bridge,
        KeyType keyType,
        address newKey,
        bytes32 predecessor,
        bytes32 salt,
        uint256 deadline
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                "AETHELRED_ROTATE_KEY_V1",
                address(this),
                block.chainid,
                bridge,
                keyType,
                newKey,
                predecessor,
                salt,
                deadline
            )
        );
    }

    function _requireContractAdmin(address admin) internal view {
        if (admin == address(0)) revert InvalidAddress();
        if (admin.code.length > 0) {
            return;
        }
        if (block.chainid == 31337 || block.chainid == 1337) {
            return;
        }
        revert AdminMustBeContract();
    }

    // =========================================================================
    // STORAGE GAP — Audit fix [H-05]
    // =========================================================================

    /// @dev Reserved storage slots for future upgrades.
    /// While this contract uses TimelockController (not UUPS), child contracts
    /// or future proxy patterns may inherit this storage layout.
    uint256[50] private __gap;
}
