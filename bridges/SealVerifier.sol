// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title SealVerifier
 * @notice On-chain verification of Aethelred Digital Seals
 * @dev Allows Ethereum smart contracts to verify AI computation proofs from Aethelred
 */
contract SealVerifier is Ownable {
    using ECDSA for bytes32;

    // SECURITY FIX H-01: EIP-712 domain separator to prevent cross-chain/contract replay
    bytes32 public DOMAIN_SEPARATOR;
    bytes32 public constant VERIFY_SEAL_TYPEHASH = keccak256(
        "VerifySeal(bytes32 sealId,bytes32 modelHash,bytes32 inputCommitment,bytes32 outputCommitment,uint256 blockHeight)"
    );

    // Aethelred validator public keys
    mapping(address => bool) public validators;
    uint256 public validatorCount;
    uint256 public requiredValidators;

    // Verified seals cache
    struct VerifiedSeal {
        bytes32 sealId;
        bytes32 modelHash;
        bytes32 inputCommitment;
        bytes32 outputCommitment;
        uint256 blockHeight;
        uint256 verifiedAt;
        bool valid;
    }
    mapping(bytes32 => VerifiedSeal) public verifiedSeals;

    // Model registry - known/approved AI models
    struct RegisteredModel {
        bytes32 modelHash;
        string name;
        string version;
        bool active;
        uint256 registeredAt;
    }
    mapping(bytes32 => RegisteredModel) public registeredModels;
    bytes32[] public modelList;

    // Events
    event ValidatorAdded(address indexed validator);
    event ValidatorRemoved(address indexed validator);
    event SealVerified(
        bytes32 indexed sealId,
        bytes32 indexed modelHash,
        bytes32 outputCommitment,
        uint256 blockHeight
    );
    event ModelRegistered(bytes32 indexed modelHash, string name, string version);
    event ModelDeactivated(bytes32 indexed modelHash);

    // Errors
    error InvalidValidatorSignature();
    error InsufficientValidatorSignatures();
    error SealAlreadyVerified();
    error ModelNotRegistered();
    error InvalidSealData();

    constructor(uint256 _requiredValidators) Ownable(msg.sender) {
        requiredValidators = _requiredValidators;
        // SECURITY FIX H-01: EIP-712 domain separator binds signatures to this chain + contract
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("SealVerifier"),
            keccak256("1"),
            block.chainid,
            address(this)
        ));
    }

    // ============ Validator Management ============

    /**
     * @notice Add a validator
     * @param validator Validator address
     */
    function addValidator(address validator) external onlyOwner {
        require(!validators[validator], "Already validator");
        validators[validator] = true;
        validatorCount++;
        emit ValidatorAdded(validator);
    }

    /**
     * @notice Remove a validator
     * @param validator Validator address
     */
    function removeValidator(address validator) external onlyOwner {
        require(validators[validator], "Not validator");
        validators[validator] = false;
        validatorCount--;
        emit ValidatorRemoved(validator);
    }

    /**
     * @notice Update required validator count
     * @param _requiredValidators New required count
     */
    function setRequiredValidators(uint256 _requiredValidators) external onlyOwner {
        require(_requiredValidators > 0 && _requiredValidators <= validatorCount, "Invalid count");
        requiredValidators = _requiredValidators;
    }

    // ============ Model Registry ============

    /**
     * @notice Register an AI model
     * @param modelHash Hash of the model weights
     * @param name Model name
     * @param version Model version
     */
    function registerModel(
        bytes32 modelHash,
        string calldata name,
        string calldata version
    ) external onlyOwner {
        require(registeredModels[modelHash].registeredAt == 0, "Already registered");

        registeredModels[modelHash] = RegisteredModel({
            modelHash: modelHash,
            name: name,
            version: version,
            active: true,
            registeredAt: block.timestamp
        });
        modelList.push(modelHash);

        emit ModelRegistered(modelHash, name, version);
    }

    /**
     * @notice Deactivate a model
     * @param modelHash Model hash to deactivate
     */
    function deactivateModel(bytes32 modelHash) external onlyOwner {
        require(registeredModels[modelHash].active, "Not active");
        registeredModels[modelHash].active = false;
        emit ModelDeactivated(modelHash);
    }

    // ============ Seal Verification ============

    /**
     * @notice Verify a Digital Seal from Aethelred
     * @param sealId Unique seal identifier
     * @param modelHash Hash of the AI model
     * @param inputCommitment Commitment to input data
     * @param outputCommitment Commitment to output data
     * @param blockHeight Aethelred block height when seal was created
     * @param signatures Array of validator signatures
     */
    function verifySeal(
        bytes32 sealId,
        bytes32 modelHash,
        bytes32 inputCommitment,
        bytes32 outputCommitment,
        uint256 blockHeight,
        bytes[] calldata signatures
    ) external {
        // Check not already verified
        if (verifiedSeals[sealId].valid) revert SealAlreadyVerified();

        // Check model is registered and active
        if (!registeredModels[modelHash].active) revert ModelNotRegistered();

        // Check sufficient signatures
        if (signatures.length < requiredValidators) revert InsufficientValidatorSignatures();

        // SECURITY FIX H-01: EIP-712 structured hash with domain separation
        bytes32 structHash = keccak256(abi.encode(
            VERIFY_SEAL_TYPEHASH,
            sealId,
            modelHash,
            inputCommitment,
            outputCommitment,
            blockHeight
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));

        // Verify signatures
        address[] memory signers = new address[](signatures.length);
        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = digest.recover(signatures[i]);

            // Check signer is validator
            if (!validators[signer]) revert InvalidValidatorSignature();

            // Check for duplicates
            for (uint256 j = 0; j < i; j++) {
                if (signers[j] == signer) revert InvalidValidatorSignature();
            }
            signers[i] = signer;
        }

        // Store verified seal
        verifiedSeals[sealId] = VerifiedSeal({
            sealId: sealId,
            modelHash: modelHash,
            inputCommitment: inputCommitment,
            outputCommitment: outputCommitment,
            blockHeight: blockHeight,
            verifiedAt: block.timestamp,
            valid: true
        });

        emit SealVerified(sealId, modelHash, outputCommitment, blockHeight);
    }

    /**
     * @notice Check if a seal is verified
     * @param sealId Seal ID to check
     * @return valid Whether the seal is verified
     * @return seal The seal data
     */
    function isSealValid(bytes32 sealId) external view returns (bool valid, VerifiedSeal memory seal) {
        seal = verifiedSeals[sealId];
        valid = seal.valid;
    }

    /**
     * @notice Check if seal output matches expected
     * @param sealId Seal ID
     * @param expectedOutput Expected output commitment
     */
    function verifySealOutput(
        bytes32 sealId,
        bytes32 expectedOutput
    ) external view returns (bool) {
        VerifiedSeal memory seal = verifiedSeals[sealId];
        return seal.valid && seal.outputCommitment == expectedOutput;
    }

    /**
     * @notice Verify seal was created with specific model
     * @param sealId Seal ID
     * @param expectedModelHash Expected model hash
     */
    function verifySealModel(
        bytes32 sealId,
        bytes32 expectedModelHash
    ) external view returns (bool) {
        VerifiedSeal memory seal = verifiedSeals[sealId];
        return seal.valid && seal.modelHash == expectedModelHash;
    }

    // ============ View Functions ============

    /**
     * @notice Get registered model count
     */
    function getModelCount() external view returns (uint256) {
        return modelList.length;
    }

    /**
     * @notice Check if model is registered and active
     * @param modelHash Model hash to check
     */
    function isModelActive(bytes32 modelHash) external view returns (bool) {
        return registeredModels[modelHash].active;
    }

    /**
     * @notice Check if address is validator
     * @param addr Address to check
     */
    function isValidator(address addr) external view returns (bool) {
        return validators[addr];
    }
}

/**
 * @title ISealConsumer
 * @notice Interface for contracts that consume verified seals
 */
interface ISealConsumer {
    /**
     * @notice Called when a seal is verified
     * @param sealId The verified seal ID
     * @param modelHash The model hash used
     * @param outputCommitment The output commitment
     */
    function onSealVerified(
        bytes32 sealId,
        bytes32 modelHash,
        bytes32 outputCommitment
    ) external;
}

/**
 * @title SealConsumerExample
 * @notice Example contract showing how to use verified seals
 */
contract SealConsumerExample is ISealConsumer {
    SealVerifier public immutable verifier;

    // Track processed seals
    mapping(bytes32 => bool) public processedSeals;

    // Credit score results (example use case)
    struct CreditResult {
        bytes32 sealId;
        uint256 score;
        uint256 timestamp;
    }
    mapping(address => CreditResult) public creditResults;

    event CreditScoreUpdated(address indexed user, uint256 score, bytes32 sealId);

    constructor(address _verifier) {
        verifier = SealVerifier(_verifier);
    }

    /**
     * @notice Submit a credit score sealed by Aethelred
     * @param sealId The seal ID proving the computation
     * @param score The credit score (100-850)
     * @param scoreCommitment Expected output commitment
     */
    function submitCreditScore(
        bytes32 sealId,
        uint256 score,
        bytes32 scoreCommitment
    ) external {
        require(!processedSeals[sealId], "Already processed");
        require(score >= 100 && score <= 850, "Invalid score range");

        // Verify the seal exists and output matches
        require(
            verifier.verifySealOutput(sealId, scoreCommitment),
            "Invalid seal"
        );

        // Verify the commitment matches the score
        require(
            keccak256(abi.encodePacked(msg.sender, score)) == scoreCommitment,
            "Score mismatch"
        );

        processedSeals[sealId] = true;
        creditResults[msg.sender] = CreditResult({
            sealId: sealId,
            score: score,
            timestamp: block.timestamp
        });

        emit CreditScoreUpdated(msg.sender, score, sealId);
    }

    /**
     * @notice Callback when seal is verified (if registered as listener)
     */
    function onSealVerified(
        bytes32 sealId,
        bytes32 modelHash,
        bytes32 outputCommitment
    ) external override {
        // Only accept from verifier
        require(msg.sender == address(verifier), "Unauthorized");

        // Handle seal verification callback
        // Implementation depends on use case
    }

    /**
     * @notice Get user's credit result
     * @param user User address
     */
    function getCreditResult(address user) external view returns (CreditResult memory) {
        return creditResults[user];
    }
}
