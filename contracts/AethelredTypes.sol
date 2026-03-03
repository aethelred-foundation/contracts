// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/**
 * @title AethelredTypes
 * @author Aethelred Team
 * @notice Shared type definitions for the Aethelred interface library.
 *         These mirror the canonical types defined on the Aethelred L1
 *         (Cosmos SDK modules: x/seal, x/verify, x/pouw).
 * @custom:security-contact security@aethelred.io
 */
library AethelredTypes {
    // =====================================================================
    // Job lifecycle — mirrors x/seal
    // =====================================================================

    /// @notice The lifecycle of an AI compute job on Aethelred.
    enum JobStatus {
        /// Job has been submitted but not yet assigned to a TEE worker.
        Submitted,
        /// Job has been assigned to a TEE worker.
        Assigned,
        /// TEE worker is generating the proof (TEE attestation and/or zkML).
        Proving,
        /// Proof has been verified by the validator set.
        Verified,
        /// Job is settled and the escrow has been paid out.
        Settled,
        /// Job was cancelled before completion.
        Cancelled,
        /// Job failed (timeout, invalid proof, etc.).
        Failed
    }

    /// @notice Parameters for submitting an AI compute job.
    struct JobRequest {
        /// @dev Registered model ID on Aethelred (e.g. "credit-score-v2").
        string modelId;
        /// @dev SHA-256 commitment over the input tensor / payload.
        bytes32 inputCommitment;
        /// @dev Preferred verification method (0 = TEE, 1 = zkML, 2 = Hybrid).
        VerificationType verificationType;
        /// @dev Maximum gas/compute budget the caller is willing to pay (in AETHEL wei).
        uint256 maxBudget;
        /// @dev SLA deadline in seconds from submission.
        uint64 slaDeadline;
        /// @dev Callback address that receives the result (address(0) = no callback).
        address callbackTarget;
        /// @dev Arbitrary metadata (JSON-encoded, max 1 KB).
        bytes metadata;
    }

    /// @notice On-chain record of a submitted job.
    struct Job {
        /// @dev Unique job identifier (keccak256).
        bytes32 jobId;
        /// @dev The account that submitted the job.
        address requester;
        /// @dev Current status.
        JobStatus status;
        /// @dev Registered model ID.
        string modelId;
        /// @dev SHA-256 commitment over the input.
        bytes32 inputCommitment;
        /// @dev SHA-256 commitment over the output (populated after Verified).
        bytes32 outputCommitment;
        /// @dev SHA-256 commitment over the model weights.
        bytes32 modelCommitment;
        /// @dev Verification method used.
        VerificationType verificationType;
        /// @dev Escrow amount locked (in AETHEL wei).
        uint256 escrowAmount;
        /// @dev Block number when the job was submitted.
        uint256 submittedAt;
        /// @dev Block number when the job was settled (0 if not settled).
        uint256 settledAt;
        /// @dev Digital Seal ID on the Aethelred L1 (populated after Verified).
        bytes32 sealId;
    }

    // =====================================================================
    // Verification — mirrors x/verify
    // =====================================================================

    /// @notice Verification strategy for a compute job.
    enum VerificationType {
        /// Trusted Execution Environment attestation only.
        TEE,
        /// Zero-knowledge ML proof only (ezkl, risc0, plonky2, halo2).
        ZKML,
        /// Both TEE + zkML with cross-validation.
        Hybrid
    }

    /// @notice TEE platforms supported by Aethelred validators.
    enum TEEPlatform {
        IntelSGX,
        IntelTDX,
        AMDSEV,
        AWSNitro,
        ARMTrustZone
    }

    /// @notice A TEE attestation record.
    struct TEEAttestation {
        /// @dev Validator who produced the attestation.
        address validator;
        /// @dev Platform that was used.
        TEEPlatform platform;
        /// @dev Enclave measurement (PCR values / MRENCLAVE).
        bytes32 measurement;
        /// @dev Raw attestation quote hash.
        bytes32 quoteHash;
        /// @dev Output hash computed inside the enclave.
        bytes32 outputHash;
        /// @dev Block timestamp when attestation was submitted.
        uint256 timestamp;
    }

    // =====================================================================
    // Digital Seal — mirrors x/seal (EnhancedDigitalSeal)
    // =====================================================================

    /// @notice Seal lifecycle status.
    enum SealStatus {
        Pending,
        Active,
        Revoked,
        Expired
    }

    /// @notice On-chain summary of an Aethelred Digital Seal.
    struct Seal {
        /// @dev Seal identifier (SHA-256 derived, 32 bytes).
        bytes32 sealId;
        /// @dev Associated job ID.
        bytes32 jobId;
        /// @dev Model commitment.
        bytes32 modelCommitment;
        /// @dev Input commitment.
        bytes32 inputCommitment;
        /// @dev Output commitment.
        bytes32 outputCommitment;
        /// @dev Current seal status.
        SealStatus status;
        /// @dev Verification type used.
        VerificationType verificationType;
        /// @dev Number of validators that attested.
        uint32 attestationCount;
        /// @dev Total validators in the set at time of consensus.
        uint32 totalValidators;
        /// @dev Whether consensus threshold (⅔ + 1) was met.
        bool consensusReached;
        /// @dev Aethelred L1 block height where the seal was activated.
        uint256 l1BlockHeight;
        /// @dev Timestamp when the seal was created.
        uint256 timestamp;
    }

    // =====================================================================
    // Bridge — mirrors contracts/AethelredBridge.sol
    // =====================================================================

    /// @notice Status of a cross-chain transfer.
    enum TransferStatus {
        Pending,
        Confirmed,
        Challenged,
        Finalized,
        Cancelled
    }

    /// @notice A bridge transfer record.
    struct BridgeTransfer {
        /// @dev Unique nonce for replay protection.
        uint256 nonce;
        /// @dev Sender on the source chain.
        address sender;
        /// @dev Recipient on the destination chain.
        address recipient;
        /// @dev Token address (address(0) for native ETH / AETHEL).
        address token;
        /// @dev Amount transferred.
        uint256 amount;
        /// @dev Source chain ID.
        uint256 sourceChainId;
        /// @dev Destination chain ID.
        uint256 destChainId;
        /// @dev Current transfer status.
        TransferStatus status;
        /// @dev Block timestamp when transfer was initiated.
        uint256 initiatedAt;
    }
}
