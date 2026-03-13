// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "./IPlatformVerifier.sol";
import "./P256Verifier.sol";

/**
 * @title VaultTEEVerifier
 * @author Aethelred Team
 * @notice On-chain TEE attestation verifier for AethelVault operations.
 *
 * @dev Verifies attestation documents from Intel SGX, AWS Nitro, and AMD SEV
 *      enclaves. Attestations are validated against:
 *      1. Registered enclave measurements (MRENCLAVE / PCR values)
 *      2. Timestamp freshness (max 5 minutes)
 *      3. Nonce uniqueness (replay protection)
 *      4. Signer identity (registered TEE operators)
 *
 * Trust Model - Attestation Authority Keys:
 *
 * The `vendorRootKey` per platform stores the P-256 public key of the
 * **attestation authority** that certifies enclave platform keys. This
 * authority may be either:
 *
 *   (a) A **direct hardware vendor key** (Intel DCAP root, AWS Nitro root,
 *       AMD ARK/VCEK) - set via `setVendorRootKey()`.
 *
 *   (b) An **attestation relay** - a trusted bridge service that verifies
 *       hardware evidence off-chain and signs the platform key binding
 *       with its own P-256 key. Registered via `registerAttestationRelay()`.
 *
 * In production deployments using (b), the relay is a trusted intermediary:
 * it verifies the full hardware attestation chain (DCAP/NSM/PSP) before
 * signing. The relay's public key is registered on-chain as the attestation
 * authority. Compromise or misconfiguration of the relay could certify
 * arbitrary platform keys. To mitigate this risk, the contract provides:
 *
 *   - Explicit relay identity tracking and metadata
 *   - Time-locked key rotation (48-hour delay)
 *   - On-chain liveness challenges with P-256 proof-of-possession
 *   - Emergency revocation by governance
 *
 * Attestation Format (ABI-encoded):
 * ┌──────────────────────────────────────────────────────────────┐
 * │  platform (uint8)     - 0=SGX, 1=Nitro, 2=SEV              │
 * │  timestamp (uint256)  - Attestation creation time           │
 * │  nonce (bytes32)      - Unique nonce for replay protection  │
 * │  enclaveHash (bytes32) - MRENCLAVE / PCR0                   │
 * │  signerHash (bytes32) - MRSIGNER / PCR1                     │
 * │  payload (bytes)      - The attested data                   │
 * │  signature (bytes)    - ECDSA signature over the above      │
 * └──────────────────────────────────────────────────────────────┘
 *
 * @custom:security-contact security@aethelred.io
 */
contract VaultTEEVerifier is
    Initializable,
    AccessControlUpgradeable,
    UUPSUpgradeable
{
    // =========================================================================
    // CONSTANTS & ROLES
    // =========================================================================

    bytes32 public constant REGISTRAR_ROLE = keccak256("REGISTRAR_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    /// @notice Maximum attestation age (5 minutes).
    uint256 public constant MAX_ATTESTATION_AGE = 5 minutes;

    /// @notice Time-lock delay for relay key rotations (48 hours).
    /// @dev Gives governance time to intervene if a rotation is malicious.
    uint256 public constant RELAY_ROTATION_DELAY = 48 hours;

    /// @notice Window for relay liveness challenge responses (1 hour).
    uint256 public constant RELAY_CHALLENGE_WINDOW = 1 hours;

    /// @notice TEE Platform identifiers.
    uint8 public constant PLATFORM_SGX = 0;
    uint8 public constant PLATFORM_NITRO = 1;
    uint8 public constant PLATFORM_SEV = 2;

    // =========================================================================
    // STRUCTS
    // =========================================================================

    /// @notice Registered enclave configuration.
    struct EnclaveConfig {
        bytes32 enclaveHash;      // MRENCLAVE / PCR0
        bytes32 signerHash;       // MRSIGNER / PCR1
        bytes32 applicationHash;  // Nitro PCR2 (zero for SGX/SEV)
        uint8 platform;           // TEE platform
        bool active;
        uint256 registeredAt;
        string description;
        uint256 platformKeyX;     // Enclave-specific P-256 platform key X
        uint256 platformKeyY;     // Enclave-specific P-256 platform key Y
    }

    /// @notice Registered TEE operator (signer).
    struct TEEOperator {
        address signer;           // ECDSA address of the TEE operator
        bool active;
        uint256 registeredAt;
        uint256 attestationCount;
        string description;
    }

    /// @notice Registered attestation relay configuration.
    /// @dev Tracks relays that verify hardware evidence off-chain and sign
    ///      platform key bindings. The relay's P-256 key is also stored in
    ///      vendorRootKeyX/Y for backward compatibility with registerEnclave().
    struct AttestationRelay {
        uint256 publicKeyX;           // Current P-256 signing key X
        uint256 publicKeyY;           // Current P-256 signing key Y
        uint256 registeredAt;         // Block timestamp of initial registration
        uint256 lastRotatedAt;        // Block timestamp of last key rotation
        uint256 attestationCount;     // Enclaves certified by this relay
        bool active;                  // Whether the relay is currently active
        // Time-locked key rotation
        uint256 pendingKeyX;          // Pending new key X (zero if no rotation pending)
        uint256 pendingKeyY;          // Pending new key Y
        uint256 rotationUnlocksAt;    // Timestamp when pending rotation can finalize
        // Liveness challenge
        bytes32 activeChallenge;      // Current governance-issued challenge nonce
        uint256 challengeDeadline;    // Deadline for the relay to respond
        string description;           // Human-readable relay identity
    }

    /// @notice Decoded attestation.
    struct DecodedAttestation {
        uint8 platform;
        uint256 timestamp;
        bytes32 nonce;
        bytes32 enclaveHash;
        bytes32 signerHash;
        bytes payload;
        bytes platformEvidence;
        bytes signature;
    }

    // =========================================================================
    // STATE VARIABLES
    // =========================================================================

    /// @notice Registered enclave configurations.
    mapping(bytes32 => EnclaveConfig) public enclaves;
    bytes32[] public registeredEnclaveIds;

    /// @notice Registered TEE operators.
    mapping(address => TEEOperator) public operators;
    address[] public registeredOperators;

    /// @notice Operator → authorized enclave ID binding.
    /// Each operator can only attest for the enclave they are registered against.
    mapping(address => bytes32) public operatorEnclaveBinding;

    /// @notice Used nonces (replay protection).
    mapping(bytes32 => bool) public usedNonces;

    /// @notice Total attestations verified.
    uint256 public totalAttestationsVerified;

    /// @notice Registered platform evidence verifiers.
    mapping(uint8 => address) public platformVerifiers;

    /// @notice Attestation authority P-256 public keys per platform (set by governance).
    /// @dev These keys verify that enclave platform keys were certified by a
    ///      trusted authority. The authority may be either a direct hardware vendor
    ///      key (Intel/AWS/AMD) or an attestation relay's signing key.
    ///      See the contract-level NatSpec for the full trust model.
    mapping(uint8 => uint256) public vendorRootKeyX;
    mapping(uint8 => uint256) public vendorRootKeyY;

    /// @notice Registered attestation relays per platform.
    /// @dev Provides relay accountability: identity tracking, rotation governance,
    ///      and liveness challenges. Only populated when the attestation authority
    ///      is a relay (registered via registerAttestationRelay), not when a direct
    ///      vendor key is set via setVendorRootKey.
    mapping(uint8 => AttestationRelay) public attestationRelays;

    // =========================================================================
    // EVENTS
    // =========================================================================

    event EnclaveRegistered(bytes32 indexed enclaveId, bytes32 enclaveHash, uint8 platform);
    event EnclaveRevoked(bytes32 indexed enclaveId);
    event OperatorRegistered(address indexed operator);
    event OperatorRevoked(address indexed operator);
    event AttestationVerified(bytes32 indexed nonce, uint8 platform, address indexed signer);
    event PlatformVerifierSet(uint8 indexed platform, address verifier);
    event VendorRootKeySet(uint8 indexed platform, uint256 x, uint256 y);
    event AttestationRelayRegistered(uint8 indexed platform, uint256 x, uint256 y, string description);
    event RelayRotationInitiated(uint8 indexed platform, uint256 newX, uint256 newY, uint256 unlocksAt);
    event RelayRotationFinalized(uint8 indexed platform, uint256 newX, uint256 newY);
    event RelayRotationCancelled(uint8 indexed platform);
    event RelayRevoked(uint8 indexed platform);
    event RelayChallengeIssued(uint8 indexed platform, bytes32 challenge, uint256 deadline);
    event RelayChallengeResponded(uint8 indexed platform, bytes32 challenge);

    // =========================================================================
    // ERRORS
    // =========================================================================

    error ZeroAddress();
    error InvalidAttestation();
    error AttestationExpired(uint256 timestamp, uint256 maxAge);
    error NonceAlreadyUsed(bytes32 nonce);
    error UnregisteredEnclave(bytes32 enclaveHash);
    error InactiveEnclave(bytes32 enclaveHash);
    error SignerHashMismatch(bytes32 provided, bytes32 expected);
    error UnregisteredOperator(address signer);
    error InactiveOperator(address signer);
    error InvalidSignature();
    error EnclaveAlreadyRegistered(bytes32 enclaveId);
    error OperatorAlreadyRegistered(address operator);
    error OperatorNotAuthorizedForEnclave(address operator, bytes32 enclaveId);
    error MissingPlatformEvidence();
    error NoPlatformVerifier(uint8 platform);
    error InvalidPlatformEvidence();
    error EvidenceMeasurementMismatch(bytes32 evidenceValue, bytes32 expected);
    error EvidenceDataBindingMismatch(bytes32 evidenceBinding, bytes32 expectedDigest);
    error VendorRootKeyNotSet(uint8 platform);
    error InvalidVendorKeyAttestation();
    error TimestampOverflow(uint256 timestamp);
    error FutureTimestamp(uint256 attestationTime, uint256 blockTime);
    error RelayAlreadyRegistered(uint8 platform);
    error RelayNotRegistered(uint8 platform);
    error RelayNotActive(uint8 platform);
    error NoRotationPending(uint8 platform);
    error RotationTimelockActive(uint8 platform, uint256 unlocksAt);
    error NoPendingChallenge(uint8 platform);
    error ChallengeExpired(uint8 platform);
    error ChallengeResponseInvalid(uint8 platform);
    error DirectOverrideWhileRelayActive(uint8 platform);

    // =========================================================================
    // INITIALIZATION
    // =========================================================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address admin) external initializer {
        if (admin == address(0)) revert ZeroAddress();

        __AccessControl_init();
        __UUPSUpgradeable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(REGISTRAR_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);
    }

    // =========================================================================
    // ATTESTATION VERIFICATION
    // =========================================================================

    /**
     * @notice Verify a TEE attestation.
     * @param attestation ABI-encoded attestation document.
     * @return valid Whether the attestation is valid.
     * @return payload The attested payload data.
     * @return platform The TEE platform that produced it.
     */
    function verifyAttestation(bytes calldata attestation)
        external
        returns (bool valid, bytes memory payload, uint8 platform)
    {
        // Decode attestation
        DecodedAttestation memory decoded = _decodeAttestation(attestation);
        platform = decoded.platform;
        payload = decoded.payload;

        // 1. Validate timestamp fits in uint64 (prevents high-bit truncation in digest)
        if (decoded.timestamp > type(uint64).max) {
            revert TimestampOverflow(decoded.timestamp);
        }
        if (decoded.timestamp > block.timestamp) {
            revert FutureTimestamp(decoded.timestamp, block.timestamp);
        }

        // 2. Check timestamp freshness
        if (block.timestamp > decoded.timestamp + MAX_ATTESTATION_AGE) {
            revert AttestationExpired(decoded.timestamp, MAX_ATTESTATION_AGE);
        }

        // 3. Check nonce uniqueness (replay protection)
        if (usedNonces[decoded.nonce]) revert NonceAlreadyUsed(decoded.nonce);
        usedNonces[decoded.nonce] = true;

        // 4. Verify enclave is registered and active
        bytes32 enclaveId = keccak256(abi.encodePacked(decoded.enclaveHash, decoded.platform));
        EnclaveConfig storage enclave = enclaves[enclaveId];
        if (enclave.enclaveHash == bytes32(0)) revert UnregisteredEnclave(decoded.enclaveHash);
        if (!enclave.active) revert InactiveEnclave(decoded.enclaveHash);

        // 4a. Verify signerHash matches the registered enclave's trusted signer identity
        if (decoded.signerHash != enclave.signerHash) {
            revert SignerHashMismatch(decoded.signerHash, enclave.signerHash);
        }

        // 5. Verify signature and recover signer
        //    Digest matches Go native verifier & Rust TEE producer:
        //    SHA-256("CruzibleTEEAttestation" ‖ platform ‖ timestamp_u64 ‖
        //            nonce ‖ enclaveHash ‖ signerHash ‖ sha256(payload))
        bytes32 payloadHash = sha256(decoded.payload);
        bytes32 digest = sha256(abi.encodePacked(
            "CruzibleTEEAttestation",
            decoded.platform,
            uint64(decoded.timestamp),
            decoded.nonce,
            decoded.enclaveHash,
            decoded.signerHash,
            payloadHash
        ));

        address signer = _recoverSigner(digest, decoded.signature);
        if (signer == address(0)) revert InvalidSignature();

        // 6. Verify platform evidence (proves attestation came from real TEE hardware)
        _verifyPlatformEvidence(
            decoded.platform,
            decoded.platformEvidence,
            decoded.enclaveHash,
            decoded.signerHash,
            enclave.applicationHash,
            digest,
            enclave.platformKeyX,
            enclave.platformKeyY
        );

        // 7. Verify signer is a registered and active operator
        TEEOperator storage operator = operators[signer];
        if (operator.signer == address(0)) revert UnregisteredOperator(signer);
        if (!operator.active) revert InactiveOperator(signer);

        // 8. Verify operator is authorized for this specific enclave
        if (operatorEnclaveBinding[signer] != enclaveId) {
            revert OperatorNotAuthorizedForEnclave(signer, enclaveId);
        }

        // Update stats
        operator.attestationCount++;
        totalAttestationsVerified++;

        valid = true;

        emit AttestationVerified(decoded.nonce, decoded.platform, signer);
    }

    /**
     * @notice Verify attestation without state changes (view-only).
     */
    function verifyAttestationView(bytes calldata attestation)
        external
        view
        returns (bool valid, bytes memory payload, uint8 platform)
    {
        DecodedAttestation memory decoded = _decodeAttestation(attestation);
        platform = decoded.platform;
        payload = decoded.payload;

        // Reject timestamps outside uint64 range or in the future
        if (decoded.timestamp > type(uint64).max) return (false, payload, platform);
        if (decoded.timestamp > block.timestamp) return (false, payload, platform);

        // Check freshness
        if (block.timestamp > decoded.timestamp + MAX_ATTESTATION_AGE) return (false, payload, platform);

        // Check nonce
        if (usedNonces[decoded.nonce]) return (false, payload, platform);

        // Check enclave
        bytes32 enclaveId = keccak256(abi.encodePacked(decoded.enclaveHash, decoded.platform));
        EnclaveConfig storage enclave = enclaves[enclaveId];
        if (enclave.enclaveHash == bytes32(0) || !enclave.active) return (false, payload, platform);

        // Check signerHash matches registered enclave identity
        if (decoded.signerHash != enclave.signerHash) return (false, payload, platform);

        // Verify signature — tagged SHA-256 digest (matches Go & Rust verifiers)
        bytes32 payloadHash = sha256(decoded.payload);
        bytes32 digest = sha256(abi.encodePacked(
            "CruzibleTEEAttestation",
            decoded.platform,
            uint64(decoded.timestamp),
            decoded.nonce,
            decoded.enclaveHash,
            decoded.signerHash,
            payloadHash
        ));
        address signer = _recoverSigner(digest, decoded.signature);

        if (signer == address(0)) return (false, payload, platform);

        // Check platform evidence using enclave-specific platform key
        if (!_checkPlatformEvidence(decoded.platform, decoded.platformEvidence,
                                     decoded.enclaveHash, decoded.signerHash, enclave.applicationHash, digest,
                                     enclave.platformKeyX, enclave.platformKeyY))
            return (false, payload, platform);

        TEEOperator storage operator = operators[signer];
        if (operator.signer == address(0) || !operator.active) return (false, payload, platform);

        // Check operator ↔ enclave binding
        if (operatorEnclaveBinding[signer] != enclaveId) return (false, payload, platform);

        valid = true;
    }

    // =========================================================================
    // ENCLAVE MANAGEMENT
    // =========================================================================

    /**
     * @notice Register a new enclave configuration with its enclave-specific platform key.
     * @dev Each enclave gets its own P-256 platform key, verified by the vendor root.
     *      This isolates key compromise to a single enclave (matching the Go native verifier).
     * @param enclaveHash MRENCLAVE / PCR0 measurement.
     * @param signerHash MRSIGNER / PCR1 identity.
     * @param applicationHash Nitro PCR2 application hash (pass bytes32(0) for SGX/SEV).
     * @param platformId TEE platform (0=SGX, 1=Nitro, 2=SEV).
     * @param description Human-readable description.
     * @param platformKeyX P-256 platform key X coordinate (generated inside TEE hardware).
     * @param platformKeyY P-256 platform key Y coordinate (generated inside TEE hardware).
     * @param vendorAttestR P-256 vendor attestation signature r over the platform key.
     * @param vendorAttestS P-256 vendor attestation signature s over the platform key.
     */
    function registerEnclave(
        bytes32 enclaveHash,
        bytes32 signerHash,
        bytes32 applicationHash,
        uint8 platformId,
        string calldata description,
        uint256 platformKeyX,
        uint256 platformKeyY,
        uint256 vendorAttestR,
        uint256 vendorAttestS
    ) external onlyRole(REGISTRAR_ROLE) {
        bytes32 enclaveId = keccak256(abi.encodePacked(enclaveHash, platformId));
        if (enclaves[enclaveId].enclaveHash != bytes32(0)) {
            revert EnclaveAlreadyRegistered(enclaveId);
        }

        // Verify vendor root key signed this enclave's platform key
        uint256 vrX = vendorRootKeyX[platformId];
        uint256 vrY = vendorRootKeyY[platformId];
        if (vrX == 0 && vrY == 0) revert VendorRootKeyNotSet(platformId);

        bytes32 keyAttestMsg = sha256(abi.encodePacked(platformKeyX, platformKeyY, platformId));
        if (!P256Verifier.verify(keyAttestMsg, vendorAttestR, vendorAttestS, vrX, vrY)) {
            revert InvalidVendorKeyAttestation();
        }

        enclaves[enclaveId] = EnclaveConfig({
            enclaveHash: enclaveHash,
            signerHash: signerHash,
            applicationHash: applicationHash,
            platform: platformId,
            active: true,
            registeredAt: block.timestamp,
            description: description,
            platformKeyX: platformKeyX,
            platformKeyY: platformKeyY
        });
        registeredEnclaveIds.push(enclaveId);

        // Track relay attestation count if this platform uses a relay
        AttestationRelay storage relay = attestationRelays[platformId];
        if (relay.registeredAt != 0 && relay.active) {
            relay.attestationCount++;
        }

        emit EnclaveRegistered(enclaveId, enclaveHash, platformId);
    }

    /**
     * @notice Revoke an enclave configuration.
     */
    function revokeEnclave(bytes32 enclaveId) external onlyRole(REGISTRAR_ROLE) {
        enclaves[enclaveId].active = false;
        emit EnclaveRevoked(enclaveId);
    }

    // =========================================================================
    // OPERATOR MANAGEMENT
    // =========================================================================

    /**
     * @notice Register a new TEE operator, bound to a specific enclave.
     * @param signer The ECDSA address of the TEE operator.
     * @param enclaveId The enclave ID this operator is authorized to attest for.
     *                  Must be a registered enclave (keccak256(enclaveHash, platform)).
     * @param description Human-readable description.
     */
    function registerOperator(address signer, bytes32 enclaveId, string calldata description)
        external
        onlyRole(REGISTRAR_ROLE)
    {
        if (signer == address(0)) revert ZeroAddress();
        if (operators[signer].signer != address(0)) {
            revert OperatorAlreadyRegistered(signer);
        }
        // The enclave must be registered
        if (enclaves[enclaveId].enclaveHash == bytes32(0)) {
            revert UnregisteredEnclave(enclaves[enclaveId].enclaveHash);
        }

        operators[signer] = TEEOperator({
            signer: signer,
            active: true,
            registeredAt: block.timestamp,
            attestationCount: 0,
            description: description
        });
        operatorEnclaveBinding[signer] = enclaveId;
        registeredOperators.push(signer);

        emit OperatorRegistered(signer);
    }

    /**
     * @notice Revoke a TEE operator.
     */
    function revokeOperator(address signer) external onlyRole(REGISTRAR_ROLE) {
        operators[signer].active = false;
        emit OperatorRevoked(signer);
    }

    // =========================================================================
    // VENDOR ROOT KEY MANAGEMENT
    // =========================================================================

    /// @notice Set the attestation authority P-256 public key for a TEE platform.
    /// @dev Sets the key used to verify that enclave platform keys were certified
    ///      by a trusted authority. Only for direct hardware vendor root keys:
    ///        Intel SGX -> Intel DCAP root key
    ///        AWS Nitro -> Nitro root certificate key
    ///        AMD SEV   -> AMD ARK/VCEK root key
    ///
    ///      This function CANNOT be called while an active attestation relay is
    ///      registered for the platform. Relay-managed keys must be changed via
    ///      the relay lifecycle methods (initiateRelayRotation / finalizeRelayRotation)
    ///      which enforce rotation timelock, liveness challenges, and audit trails.
    ///      To switch from relay back to direct vendor keys, first call revokeRelay().
    ///
    ///      Reverts with DirectOverrideWhileRelayActive if a relay is active.
    function setVendorRootKey(uint8 platformId, uint256 x, uint256 y)
        external
        onlyRole(REGISTRAR_ROLE)
    {
        // Prevent bypassing relay governance controls via direct override
        AttestationRelay storage relay = attestationRelays[platformId];
        if (relay.registeredAt != 0 && relay.active) {
            revert DirectOverrideWhileRelayActive(platformId);
        }

        vendorRootKeyX[platformId] = x;
        vendorRootKeyY[platformId] = y;
        emit VendorRootKeySet(platformId, x, y);
    }

    // =========================================================================
    // ATTESTATION RELAY MANAGEMENT
    // =========================================================================

    /// @notice Register an attestation relay as the attestation authority for a platform.
    /// @dev The relay verifies hardware evidence (DCAP/NSM/PSP) off-chain and signs
    ///      platform key bindings. Its P-256 public key becomes the vendorRootKey for
    ///      the platform, enabling `registerEnclave()` to verify relay-signed attestations.
    ///
    ///      Relay accountability features:
    ///        - Identity and registration timestamp are permanently recorded
    ///        - Key rotation requires a 48-hour timelock (RELAY_ROTATION_DELAY)
    ///        - Governance can issue liveness challenges requiring P-256 proof-of-possession
    ///        - Emergency revocation immediately disables the relay
    ///
    ///      After emergency revocation, a replacement relay can be registered for the
    ///      same platform — the revoked relay's struct is fully overwritten with fresh
    ///      state. The previous relay's attestation count is not carried forward.
    /// @param platformId TEE platform (0=SGX, 1=Nitro, 2=SEV).
    /// @param x P-256 public key X coordinate of the relay's signing key.
    /// @param y P-256 public key Y coordinate of the relay's signing key.
    /// @param description Human-readable relay identity (e.g., "Aethelred Production Relay v1").
    function registerAttestationRelay(
        uint8 platformId,
        uint256 x,
        uint256 y,
        string calldata description
    ) external onlyRole(REGISTRAR_ROLE) {
        AttestationRelay storage relay = attestationRelays[platformId];
        if (relay.registeredAt != 0 && relay.active) revert RelayAlreadyRegistered(platformId);

        relay.publicKeyX = x;
        relay.publicKeyY = y;
        relay.registeredAt = block.timestamp;
        relay.lastRotatedAt = block.timestamp;
        relay.attestationCount = 0;
        relay.active = true;
        // Clear any stale state from a previous revoked relay
        relay.pendingKeyX = 0;
        relay.pendingKeyY = 0;
        relay.rotationUnlocksAt = 0;
        relay.activeChallenge = bytes32(0);
        relay.challengeDeadline = 0;
        relay.description = description;

        // Also set vendorRootKey for backward compatibility with registerEnclave()
        vendorRootKeyX[platformId] = x;
        vendorRootKeyY[platformId] = y;

        emit AttestationRelayRegistered(platformId, x, y, description);
        emit VendorRootKeySet(platformId, x, y);
    }

    /// @notice Initiate a time-locked relay key rotation.
    /// @dev The new key becomes effective after RELAY_ROTATION_DELAY (48 hours).
    ///      During the delay, governance can cancel via `cancelRelayRotation()`.
    ///      Finalize with `finalizeRelayRotation()` after the timelock expires.
    /// @param platformId TEE platform whose relay key to rotate.
    /// @param newX New P-256 public key X coordinate.
    /// @param newY New P-256 public key Y coordinate.
    function initiateRelayRotation(
        uint8 platformId,
        uint256 newX,
        uint256 newY
    ) external onlyRole(REGISTRAR_ROLE) {
        AttestationRelay storage relay = attestationRelays[platformId];
        if (relay.registeredAt == 0) revert RelayNotRegistered(platformId);
        if (!relay.active) revert RelayNotActive(platformId);

        relay.pendingKeyX = newX;
        relay.pendingKeyY = newY;
        relay.rotationUnlocksAt = block.timestamp + RELAY_ROTATION_DELAY;

        emit RelayRotationInitiated(platformId, newX, newY, relay.rotationUnlocksAt);
    }

    /// @notice Finalize a pending relay key rotation after the timelock expires.
    /// @param platformId TEE platform whose relay rotation to finalize.
    function finalizeRelayRotation(uint8 platformId) external onlyRole(REGISTRAR_ROLE) {
        AttestationRelay storage relay = attestationRelays[platformId];
        if (relay.registeredAt == 0) revert RelayNotRegistered(platformId);
        if (relay.pendingKeyX == 0 && relay.pendingKeyY == 0) revert NoRotationPending(platformId);
        if (block.timestamp < relay.rotationUnlocksAt) {
            revert RotationTimelockActive(platformId, relay.rotationUnlocksAt);
        }

        relay.publicKeyX = relay.pendingKeyX;
        relay.publicKeyY = relay.pendingKeyY;
        relay.lastRotatedAt = block.timestamp;

        // Update vendorRootKey for registerEnclave() compatibility
        vendorRootKeyX[platformId] = relay.pendingKeyX;
        vendorRootKeyY[platformId] = relay.pendingKeyY;

        emit RelayRotationFinalized(platformId, relay.pendingKeyX, relay.pendingKeyY);
        emit VendorRootKeySet(platformId, relay.pendingKeyX, relay.pendingKeyY);

        // Clear pending rotation
        relay.pendingKeyX = 0;
        relay.pendingKeyY = 0;
        relay.rotationUnlocksAt = 0;
    }

    /// @notice Cancel a pending relay key rotation.
    /// @param platformId TEE platform whose pending rotation to cancel.
    function cancelRelayRotation(uint8 platformId) external onlyRole(REGISTRAR_ROLE) {
        AttestationRelay storage relay = attestationRelays[platformId];
        if (relay.pendingKeyX == 0 && relay.pendingKeyY == 0) revert NoRotationPending(platformId);

        relay.pendingKeyX = 0;
        relay.pendingKeyY = 0;
        relay.rotationUnlocksAt = 0;

        emit RelayRotationCancelled(platformId);
    }

    /// @notice Emergency revocation of an attestation relay.
    /// @dev Immediately deactivates the relay AND clears the vendorRootKey,
    ///      preventing any further enclave registrations for this platform.
    ///      Existing enclaves already registered remain valid.
    /// @param platformId TEE platform whose relay to revoke.
    function revokeRelay(uint8 platformId) external onlyRole(REGISTRAR_ROLE) {
        AttestationRelay storage relay = attestationRelays[platformId];
        if (relay.registeredAt == 0) revert RelayNotRegistered(platformId);

        relay.active = false;
        // Clear vendorRootKey to prevent new enclave registrations
        vendorRootKeyX[platformId] = 0;
        vendorRootKeyY[platformId] = 0;
        // Clear any pending rotation
        relay.pendingKeyX = 0;
        relay.pendingKeyY = 0;
        relay.rotationUnlocksAt = 0;
        // Clear any pending challenge
        relay.activeChallenge = bytes32(0);
        relay.challengeDeadline = 0;

        emit RelayRevoked(platformId);
    }

    /// @notice Issue a liveness challenge to an attestation relay.
    /// @dev The relay must respond within RELAY_CHALLENGE_WINDOW (1 hour) by
    ///      providing a valid P-256 signature over the challenge nonce using its
    ///      registered signing key. Failure to respond indicates the relay may be
    ///      offline or its key compromised.
    /// @param platformId TEE platform whose relay to challenge.
    /// @param challenge Random nonce for the relay to sign (governance picks this).
    function challengeRelay(uint8 platformId, bytes32 challenge)
        external
        onlyRole(REGISTRAR_ROLE)
    {
        AttestationRelay storage relay = attestationRelays[platformId];
        if (relay.registeredAt == 0) revert RelayNotRegistered(platformId);
        if (!relay.active) revert RelayNotActive(platformId);

        relay.activeChallenge = challenge;
        relay.challengeDeadline = block.timestamp + RELAY_CHALLENGE_WINDOW;

        emit RelayChallengeIssued(platformId, challenge, relay.challengeDeadline);
    }

    /// @notice Respond to a relay liveness challenge with a P-256 signature.
    /// @dev Anyone can submit this (permissionless) since the P-256 signature
    ///      proves possession of the relay's private key. The signature is
    ///      verified against the relay's registered public key.
    /// @param platformId TEE platform whose challenge to respond to.
    /// @param sigR P-256 signature R component over the challenge nonce.
    /// @param sigS P-256 signature S component over the challenge nonce.
    function respondRelayChallenge(
        uint8 platformId,
        uint256 sigR,
        uint256 sigS
    ) external {
        AttestationRelay storage relay = attestationRelays[platformId];
        if (relay.activeChallenge == bytes32(0)) revert NoPendingChallenge(platformId);
        if (block.timestamp > relay.challengeDeadline) revert ChallengeExpired(platformId);

        // Verify P-256 signature: sig(SHA-256(challenge)) against relay's public key
        bytes32 challengeHash = sha256(abi.encodePacked(relay.activeChallenge));
        if (!P256Verifier.verify(challengeHash, sigR, sigS, relay.publicKeyX, relay.publicKeyY)) {
            revert ChallengeResponseInvalid(platformId);
        }

        bytes32 respondedChallenge = relay.activeChallenge;
        relay.activeChallenge = bytes32(0);
        relay.challengeDeadline = 0;

        emit RelayChallengeResponded(platformId, respondedChallenge);
    }

    /// @notice Check if a platform has an active attestation relay.
    function isRelayActive(uint8 platformId) external view returns (bool) {
        return attestationRelays[platformId].active;
    }

    /// @notice Check if a relay has an outstanding unanswered challenge.
    function hasUnexpiredChallenge(uint8 platformId) external view returns (bool) {
        AttestationRelay storage relay = attestationRelays[platformId];
        return relay.activeChallenge != bytes32(0) && block.timestamp <= relay.challengeDeadline;
    }

    /// @notice Check if a relay has a pending key rotation.
    function hasPendingRotation(uint8 platformId) external view returns (bool, uint256) {
        AttestationRelay storage relay = attestationRelays[platformId];
        bool pending = relay.pendingKeyX != 0 || relay.pendingKeyY != 0;
        return (pending, relay.rotationUnlocksAt);
    }

    /// @notice Register a platform evidence verifier logic contract.
    /// @dev Verifier contracts are now stateless — they contain only evidence
    ///      parsing and P-256 signature verification logic. Platform keys are
    ///      stored per-enclave and passed to the verifier at verification time.
    /// @param platformId The platform identifier (0=SGX, 1=Nitro, 2=SEV).
    /// @param verifier The IPlatformVerifier contract address.
    function setPlatformVerifier(
        uint8 platformId,
        address verifier
    )
        external
        onlyRole(REGISTRAR_ROLE)
    {
        platformVerifiers[platformId] = verifier;
        emit PlatformVerifierSet(platformId, verifier);
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    function getRegisteredEnclaveCount() external view returns (uint256) {
        return registeredEnclaveIds.length;
    }

    function getRegisteredOperatorCount() external view returns (uint256) {
        return registeredOperators.length;
    }

    function isEnclaveActive(bytes32 enclaveHash, uint8 platform) external view returns (bool) {
        bytes32 enclaveId = keccak256(abi.encodePacked(enclaveHash, platform));
        return enclaves[enclaveId].active;
    }

    function isOperatorActive(address signer) external view returns (bool) {
        return operators[signer].active;
    }

    // =========================================================================
    // INTERNAL FUNCTIONS
    // =========================================================================

    /**
     * @dev Verify platform evidence using the enclave's specific platform key (reverts on failure).
     */
    function _verifyPlatformEvidence(
        uint8 platformId,
        bytes memory evidence,
        bytes32 expectedEnclaveHash,
        bytes32 expectedSignerHash,
        bytes32 expectedApplicationHash,
        bytes32 attestationDigest,
        uint256 pkX,
        uint256 pkY
    ) internal view {
        if (evidence.length == 0) revert MissingPlatformEvidence();

        address verifierAddr = platformVerifiers[platformId];
        if (verifierAddr == address(0)) revert NoPlatformVerifier(platformId);

        IPlatformVerifier.VerificationResult memory result =
            IPlatformVerifier(verifierAddr).verify(evidence, pkX, pkY);

        if (!result.valid) revert InvalidPlatformEvidence();
        if (result.enclaveHash != expectedEnclaveHash) {
            revert EvidenceMeasurementMismatch(result.enclaveHash, expectedEnclaveHash);
        }
        if (result.signerHash != expectedSignerHash) {
            revert EvidenceMeasurementMismatch(result.signerHash, expectedSignerHash);
        }
        // Nitro PCR2 (application hash) — only enforced when the registered value is non-zero
        if (expectedApplicationHash != bytes32(0) && result.applicationHash != expectedApplicationHash) {
            revert EvidenceMeasurementMismatch(result.applicationHash, expectedApplicationHash);
        }
        if (result.dataBinding != attestationDigest) {
            revert EvidenceDataBindingMismatch(result.dataBinding, attestationDigest);
        }
    }

    /**
     * @dev Check platform evidence using the enclave's specific platform key
     *      (returns false instead of reverting, for view functions).
     */
    function _checkPlatformEvidence(
        uint8 platformId,
        bytes memory evidence,
        bytes32 expectedEnclaveHash,
        bytes32 expectedSignerHash,
        bytes32 expectedApplicationHash,
        bytes32 attestationDigest,
        uint256 pkX,
        uint256 pkY
    ) internal view returns (bool) {
        if (evidence.length == 0) return false;
        address verifierAddr = platformVerifiers[platformId];
        if (verifierAddr == address(0)) return false;

        IPlatformVerifier.VerificationResult memory result =
            IPlatformVerifier(verifierAddr).verify(evidence, pkX, pkY);

        if (!result.valid) return false;
        if (result.enclaveHash != expectedEnclaveHash) return false;
        if (result.signerHash != expectedSignerHash) return false;
        // Nitro PCR2 (application hash) — only enforced when registered value is non-zero
        if (expectedApplicationHash != bytes32(0) && result.applicationHash != expectedApplicationHash) return false;
        if (result.dataBinding != attestationDigest) return false;
        return true;
    }

    function _decodeAttestation(bytes calldata attestation)
        internal
        pure
        returns (DecodedAttestation memory decoded)
    {
        (
            decoded.platform,
            decoded.timestamp,
            decoded.nonce,
            decoded.enclaveHash,
            decoded.signerHash,
            decoded.payload,
            decoded.platformEvidence,
            decoded.signature
        ) = abi.decode(attestation, (uint8, uint256, bytes32, bytes32, bytes32, bytes, bytes, bytes));
    }

    function _recoverSigner(bytes32 digest, bytes memory signature)
        internal
        pure
        returns (address)
    {
        if (signature.length != 65) return address(0);

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        if (v < 27) v += 27;
        if (v != 27 && v != 28) return address(0);

        // Prevent signature malleability (EIP-2)
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return address(0);
        }

        return ecrecover(digest, v, r, s);
    }

    function _authorizeUpgrade(address newImplementation)
        internal
        override
        onlyRole(UPGRADER_ROLE)
    {}

    function version() external pure returns (string memory) {
        return "1.1.0";
    }

    // =========================================================================
    // STORAGE GAP
    // =========================================================================

    uint256[47] private __gap;
}
