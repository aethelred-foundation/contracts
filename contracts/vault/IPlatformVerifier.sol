// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/**
 * @title IPlatformVerifier
 * @notice Interface for TEE platform-specific evidence verification.
 *
 * Each TEE platform (SGX, Nitro, SEV) has a dedicated verifier that:
 *   1. Decodes the platform-specific evidence structure
 *   2. Extracts and validates enclave measurements
 *   3. Verifies data binding (evidence references the attestation digest)
 *
 * Evidence proves attestation was generated inside a real TEE, not ordinary software.
 * Level 1 (structural): decode evidence, extract measurements, check binding.
 * Level 2 (cryptographic): additionally verify platform signatures (Intel DCAP,
 *          AWS NSM certificate, AMD VCEK chain). Extensible via contract upgrade.
 */
interface IPlatformVerifier {
    /// @notice Result of platform evidence verification.
    struct VerificationResult {
        bool valid;              // Whether evidence is structurally valid
        bytes32 enclaveHash;     // Extracted enclave measurement (normalized to bytes32)
        bytes32 signerHash;      // Extracted signer identity (normalized to bytes32)
        bytes32 dataBinding;     // Report data binding to attestation digest
        bytes32 applicationHash; // Application measurement (Nitro PCR2; zero for SGX/SEV)
    }

    /// @notice Verify platform-specific TEE evidence.
    /// @param evidence ABI-encoded platform evidence (format varies by platform).
    /// @param pkX The x-coordinate of the enclave's P-256 platform public key.
    /// @param pkY The y-coordinate of the enclave's P-256 platform public key.
    /// @return result The verification result with extracted measurements and binding.
    function verify(bytes calldata evidence, uint256 pkX, uint256 pkY) external view returns (VerificationResult memory result);

    /// @notice Returns the platform identifier this verifier handles.
    function platform() external pure returns (uint8);
}
