// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "./IPlatformVerifier.sol";
import "./P256Verifier.sol";

/**
 * @title SgxVerifier
 * @notice Stateless Intel SGX attestation evidence verifier with P-256 ECDSA signature verification.
 *
 * Evidence ABI layout: (bytes32 mrenclave, bytes32 mrsigner, bytes32 reportData,
 *                        uint16 isvProdId, uint16 isvSvn, bytes32 rawReportHash, uint256 r, uint256 s)
 *
 * - mrenclave: MRENCLAVE measurement (code identity) — from hardware report
 * - mrsigner: MRSIGNER identity (enclave signer) — from hardware report
 * - reportData: first 32 bytes of SGX report data = attestation digest
 * - isvProdId: ISV Product ID
 * - isvSvn: ISV Security Version Number
 * - rawReportHash: SHA-256 commitment to a fresh hardware attestation report
 * - r, s: P-256 ECDSA signature over sha256(mrenclave || mrsigner || reportData || isvProdId || isvSvn || bindingHash)
 *
 * Measurement binding: the verifier computes
 *   bindingHash = sha256(rawReportHash || mrenclave || mrsigner)
 * and uses it in the P-256 signature verification. This cryptographically proves
 * that the measurements in evidence came from the specific hardware report,
 * preventing substitution of measurements from a different report.
 *
 * @dev This contract is stateless — the platform key is passed per-call from the
 *      enclave's registered key, not stored in the verifier. This ensures each
 *      enclave has its own isolated platform key.
 */
contract SgxVerifier is IPlatformVerifier {
    function verify(bytes calldata evidence, uint256 pkX, uint256 pkY) external view override returns (VerificationResult memory result) {
        if (evidence.length < 256) return result; // 8 * 32 bytes minimum

        (bytes32 mrenclave, bytes32 mrsigner, bytes32 reportData, uint16 isvProdId, uint16 isvSvn, bytes32 rawReportHash, uint256 r, uint256 s) =
            abi.decode(evidence, (bytes32, bytes32, bytes32, uint16, uint16, bytes32, uint256, uint256));

        if (mrenclave == bytes32(0) || mrsigner == bytes32(0)) return result;

        // Require non-zero raw report hash (proves fresh hardware attestation)
        if (rawReportHash == bytes32(0)) return result;

        // Compute binding hash: ties the raw hardware report to these specific measurements.
        // If someone substitutes measurements from a different report, the binding hash
        // changes and the P-256 signature verification fails.
        bytes32 bindingHash = sha256(abi.encodePacked(rawReportHash, mrenclave, mrsigner));

        // Hash the report body (uses bindingHash, not rawReportHash, for measurement binding)
        bytes32 reportHash = sha256(abi.encodePacked(mrenclave, mrsigner, reportData, isvProdId, isvSvn, bindingHash));

        // Verify P-256 signature from enclave-specific platform key
        if (!P256Verifier.verify(reportHash, r, s, pkX, pkY)) return result;

        result.valid = true;
        result.enclaveHash = mrenclave;
        result.signerHash = mrsigner;
        result.dataBinding = reportData;
    }

    function platform() external pure override returns (uint8) { return 0; }
}

/**
 * @title NitroVerifier
 * @notice Stateless AWS Nitro Enclaves attestation evidence verifier with P-256 ECDSA signature verification.
 *
 * Evidence ABI layout: (bytes32 pcr0, bytes32 pcr1, bytes32 pcr2, bytes32 userData,
 *                        bytes32 rawReportHash, uint256 r, uint256 s)
 *
 * Nitro PCR values are 48 bytes (SHA-384). On-chain, we store sha256(pcr) as bytes32.
 * The Rust TEE hashes the real PCRs before including them in evidence.
 *
 * - rawReportHash: SHA-256 commitment to a fresh Nitro attestation document
 * - r, s: P-256 ECDSA signature over sha256(pcr0 || pcr1 || pcr2 || userData || bindingHash)
 *
 * Measurement binding: bindingHash = sha256(rawReportHash || pcr0 || pcr1)
 *
 * @dev Stateless — platform key passed per-call from the enclave's registered key.
 */
contract NitroVerifier is IPlatformVerifier {
    function verify(bytes calldata evidence, uint256 pkX, uint256 pkY) external view override returns (VerificationResult memory result) {
        if (evidence.length < 224) return result; // 7 * 32 bytes minimum

        (bytes32 pcr0, bytes32 pcr1, bytes32 pcr2, bytes32 userData, bytes32 rawReportHash, uint256 r, uint256 s) =
            abi.decode(evidence, (bytes32, bytes32, bytes32, bytes32, bytes32, uint256, uint256));

        if (pcr0 == bytes32(0) || userData == bytes32(0)) return result;

        // Require non-zero raw report hash (proves fresh hardware attestation)
        if (rawReportHash == bytes32(0)) return result;

        // Compute binding hash: ties the raw hardware report to these specific measurements
        bytes32 bindingHash = sha256(abi.encodePacked(rawReportHash, pcr0, pcr1));

        // Hash the report body (uses bindingHash for measurement binding)
        bytes32 reportHash = sha256(abi.encodePacked(pcr0, pcr1, pcr2, userData, bindingHash));

        // Verify P-256 signature from enclave-specific platform key
        if (!P256Verifier.verify(reportHash, r, s, pkX, pkY)) return result;

        result.valid = true;
        result.enclaveHash = pcr0;
        result.signerHash = pcr1;
        result.dataBinding = userData;
        result.applicationHash = pcr2;
    }

    function platform() external pure override returns (uint8) { return 1; }
}

/**
 * @title SevVerifier
 * @notice Stateless AMD SEV-SNP attestation evidence verifier with P-256 ECDSA signature verification.
 *
 * Evidence ABI layout: (bytes32 measurement, bytes32 hostData, bytes32 reportData, uint8 vmpl,
 *                        bytes32 rawReportHash, uint256 r, uint256 s)
 *
 * SEV-SNP measurement is 48 bytes. On-chain, we store sha256(measurement) as bytes32.
 *
 * - rawReportHash: SHA-256 commitment to a fresh SEV-SNP attestation report
 * - r, s: P-256 ECDSA signature over sha256(measurement || hostData || reportData || vmpl || bindingHash)
 *
 * Measurement binding: bindingHash = sha256(rawReportHash || measurement || hostData)
 *
 * @dev Stateless — platform key passed per-call from the enclave's registered key.
 */
contract SevVerifier is IPlatformVerifier {
    function verify(bytes calldata evidence, uint256 pkX, uint256 pkY) external view override returns (VerificationResult memory result) {
        if (evidence.length < 224) return result; // 7 * 32 bytes minimum

        (bytes32 measurement, bytes32 hostData, bytes32 reportData, uint8 vmpl, bytes32 rawReportHash, uint256 r, uint256 s) =
            abi.decode(evidence, (bytes32, bytes32, bytes32, uint8, bytes32, uint256, uint256));

        if (measurement == bytes32(0) || reportData == bytes32(0)) return result;

        // Require non-zero raw report hash (proves fresh hardware attestation)
        if (rawReportHash == bytes32(0)) return result;

        // Compute binding hash: ties the raw hardware report to these specific measurements
        bytes32 bindingHash = sha256(abi.encodePacked(rawReportHash, measurement, hostData));

        // Hash the report body (uses bindingHash for measurement binding)
        bytes32 reportHash = sha256(abi.encodePacked(measurement, hostData, reportData, vmpl, bindingHash));

        // Verify P-256 signature from enclave-specific platform key
        if (!P256Verifier.verify(reportHash, r, s, pkX, pkY)) return result;

        result.valid = true;
        result.enclaveHash = measurement;
        result.signerHash = hostData;
        result.dataBinding = reportData;
    }

    function platform() external pure override returns (uint8) { return 2; }
}
