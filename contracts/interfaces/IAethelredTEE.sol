// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {AethelredTypes} from "../types/AethelredTypes.sol";

/**
 * @title IAethelredTEE
 * @author Aethelred Team
 * @notice Interface for requesting and managing AI compute jobs on the
 *         Aethelred TEE network.
 *
 * @dev Backed by the Aethelred L1 `x/seal` module.  A developer building
 *      on-chain DeFi (e.g. a lending protocol) calls `submitJob` with
 *      the model ID and input commitment.  The Aethelred validator set
 *      executes the model inside a Trusted Execution Environment, produces
 *      a Digital Seal, and relays the result back via `IAethelredOracle`.
 *
 *      If the caller supplies a `callbackTarget`, the oracle layer will
 *      invoke `IAethelredCallback.onJobCompleted` once the seal is active.
 *
 * Lifecycle:
 *   submitJob → Submitted → Assigned → Proving → Verified → Settled
 *
 * @custom:security-contact security@aethelred.io
 */
interface IAethelredTEE {
    // =====================================================================
    // Events
    // =====================================================================

    /// @notice Emitted when a new AI compute job is submitted.
    event JobSubmitted(
        bytes32 indexed jobId,
        address indexed requester,
        string modelId,
        AethelredTypes.VerificationType verificationType,
        uint256 escrowAmount
    );

    /// @notice Emitted when a job transitions to a new status.
    event JobStatusChanged(
        bytes32 indexed jobId,
        AethelredTypes.JobStatus oldStatus,
        AethelredTypes.JobStatus newStatus
    );

    /// @notice Emitted when a job is settled and the escrow is released.
    event JobSettled(
        bytes32 indexed jobId,
        bytes32 indexed sealId,
        bytes32 outputCommitment,
        uint256 payout
    );

    /// @notice Emitted when a job is cancelled and the escrow is refunded.
    event JobCancelled(bytes32 indexed jobId, address indexed requester);

    // =====================================================================
    // Job Submission
    // =====================================================================

    /**
     * @notice Submit an AI compute job to the Aethelred TEE network.
     * @param request The job parameters (model ID, input commitment, etc.).
     * @return jobId Unique identifier for the submitted job.
     *
     * @dev `msg.value` must be >= `request.maxBudget` and is held in escrow
     *      until the job is settled or cancelled.
     *
     * Requirements:
     * - `request.modelId` must be registered in the Aethelred model registry.
     * - `request.inputCommitment` must be non-zero.
     * - `msg.value` must cover the compute fee.
     */
    function submitJob(
        AethelredTypes.JobRequest calldata request
    ) external payable returns (bytes32 jobId);

    /**
     * @notice Cancel a pending job and reclaim the escrow.
     * @param jobId The job to cancel.
     *
     * @dev Only callable by the original requester.  Only jobs in
     *      `Submitted` status can be cancelled.
     */
    function cancelJob(bytes32 jobId) external;

    // =====================================================================
    // Job Queries
    // =====================================================================

    /**
     * @notice Retrieve the full job record.
     * @param jobId The job identifier.
     * @return job The job struct.
     */
    function getJob(
        bytes32 jobId
    ) external view returns (AethelredTypes.Job memory job);

    /**
     * @notice Get the current status of a job.
     * @param jobId The job identifier.
     * @return status Current job status.
     */
    function getJobStatus(
        bytes32 jobId
    ) external view returns (AethelredTypes.JobStatus status);

    /**
     * @notice Check whether a model ID is registered and available.
     * @param modelId The model identifier string.
     * @return registered True if the model is available for jobs.
     */
    function isModelRegistered(
        string calldata modelId
    ) external view returns (bool registered);

    /**
     * @notice Get the current fee estimate for a job (in AETHEL wei).
     * @param modelId The model to query.
     * @param verificationType The verification method.
     * @return fee Estimated compute fee.
     */
    function estimateFee(
        string calldata modelId,
        AethelredTypes.VerificationType verificationType
    ) external view returns (uint256 fee);

    /**
     * @notice List all job IDs submitted by a given requester.
     * @param requester The address to look up.
     * @param offset Pagination offset.
     * @param limit Maximum number of IDs to return.
     * @return jobIds Array of job identifiers.
     */
    function getJobsByRequester(
        address requester,
        uint256 offset,
        uint256 limit
    ) external view returns (bytes32[] memory jobIds);
}

/**
 * @title IAethelredCallback
 * @notice Optional callback interface for contracts that want to receive
 *         job results automatically once the Digital Seal is active.
 *
 * @dev Implement this on any contract passed as `callbackTarget` in a
 *      `JobRequest`.  The Aethelred oracle relayer will call
 *      `onJobCompleted` after the seal transitions to Active status.
 */
interface IAethelredCallback {
    /**
     * @notice Called by the oracle relayer when an AI compute job completes.
     * @param jobId          The completed job's identifier.
     * @param sealId         The Digital Seal ID on the Aethelred L1.
     * @param outputCommitment SHA-256 commitment over the AI output.
     * @param result         ABI-encoded result payload (model-specific).
     */
    function onJobCompleted(
        bytes32 jobId,
        bytes32 sealId,
        bytes32 outputCommitment,
        bytes calldata result
    ) external;
}
