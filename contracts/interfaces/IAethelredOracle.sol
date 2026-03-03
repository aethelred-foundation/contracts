// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {AethelredTypes} from "../types/AethelredTypes.sol";

/**
 * @title IAethelredOracle
 * @author Aethelred Team
 * @notice Interface for reading AI computation results and verifying
 *         Digital Seals on-chain.
 *
 * @dev Backed by the Aethelred L1 relayer network.  After a TEE compute
 *      job reaches `Verified` status and a Digital Seal is activated,
 *      relayers post the seal summary and the ABI-encoded result to this
 *      oracle contract.
 *
 *      Third-party contracts (e.g. a DeFi lending protocol) can then call
 *      `getResult` or `getSeal` to consume the AI output trustlessly,
 *      knowing that the result was:
 *        1. Executed inside a TEE enclave (and/or proved via zkML).
 *        2. Attested to by ⅔ + 1 of the Aethelred validator set.
 *        3. Anchored in an immutable Digital Seal on the Aethelred L1.
 *
 * Example — DeFi credit scoring:
 * ```solidity
 * IAethelredOracle oracle = IAethelredOracle(ORACLE_ADDR);
 * (bytes memory result, bool valid) = oracle.getResult(jobId);
 * require(valid, "Result not yet verified");
 * uint256 creditScore = abi.decode(result, (uint256));
 * ```
 *
 * @custom:security-contact security@aethelred.io
 */
interface IAethelredOracle {
    // =====================================================================
    // Events
    // =====================================================================

    /// @notice Emitted when a new result is posted by the relayer network.
    event ResultPosted(
        bytes32 indexed jobId,
        bytes32 indexed sealId,
        bytes32 outputCommitment
    );

    /// @notice Emitted when a seal status changes (e.g. revoked).
    event SealStatusUpdated(
        bytes32 indexed sealId,
        AethelredTypes.SealStatus oldStatus,
        AethelredTypes.SealStatus newStatus
    );

    // =====================================================================
    // Result Reads
    // =====================================================================

    /**
     * @notice Get the AI computation result for a completed job.
     * @param jobId The job identifier.
     * @return result  ABI-encoded result payload (model-specific).
     * @return valid   True if the backing Digital Seal is Active.
     *
     * @dev Reverts if no result has been posted for this job.
     */
    function getResult(
        bytes32 jobId
    ) external view returns (bytes memory result, bool valid);

    /**
     * @notice Get only the raw output commitment for a job.
     * @param jobId The job identifier.
     * @return outputCommitment SHA-256 hash of the AI output.
     * @return valid True if the seal is Active.
     */
    function getOutputCommitment(
        bytes32 jobId
    ) external view returns (bytes32 outputCommitment, bool valid);

    /**
     * @notice Check whether a verified result exists for a job.
     * @param jobId The job identifier.
     * @return exists True if a result has been posted and the seal is Active.
     */
    function hasResult(bytes32 jobId) external view returns (bool exists);

    // =====================================================================
    // Seal Verification
    // =====================================================================

    /**
     * @notice Retrieve the full Digital Seal summary.
     * @param sealId The seal identifier.
     * @return seal The seal struct.
     */
    function getSeal(
        bytes32 sealId
    ) external view returns (AethelredTypes.Seal memory seal);

    /**
     * @notice Look up the seal associated with a job.
     * @param jobId The job identifier.
     * @return seal The seal struct.
     */
    function getSealByJobId(
        bytes32 jobId
    ) external view returns (AethelredTypes.Seal memory seal);

    /**
     * @notice Verify that a seal is active and reached consensus.
     * @param sealId The seal identifier.
     * @return verified True if the seal is Active AND consensus was reached.
     *
     * @dev This is the primary "trust gate" for downstream contracts.
     *      A seal is considered verified when:
     *        - status == Active
     *        - attestationCount >= (totalValidators * 2 / 3) + 1
     */
    function verifySeal(
        bytes32 sealId
    ) external view returns (bool verified);

    /**
     * @notice Verify a seal and also confirm the output commitment matches.
     * @param sealId           The seal identifier.
     * @param outputCommitment Expected SHA-256 output hash.
     * @return verified True if the seal is valid AND the output matches.
     *
     * @dev Useful for contracts that store the expected output hash
     *      and want a single-call verification.
     */
    function verifySealWithOutput(
        bytes32 sealId,
        bytes32 outputCommitment
    ) external view returns (bool verified);

    /**
     * @notice Get the TEE attestation records for a seal.
     * @param sealId The seal identifier.
     * @return attestations Array of attestation structs.
     */
    function getAttestations(
        bytes32 sealId
    ) external view returns (AethelredTypes.TEEAttestation[] memory attestations);

    // =====================================================================
    // Model Registry Reads
    // =====================================================================

    /**
     * @notice Get the model commitment hash for a registered model.
     * @param modelId The model identifier string.
     * @return modelCommitment SHA-256 hash of the model weights.
     * @return version Current model version string.
     */
    function getModelInfo(
        string calldata modelId
    ) external view returns (bytes32 modelCommitment, string memory version);
}
