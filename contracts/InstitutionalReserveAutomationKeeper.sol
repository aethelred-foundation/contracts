// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/**
 * @dev Minimal Chainlink Automation interface (local declaration to avoid adding
 * an external package dependency to this repo).
 */
interface AutomationCompatibleInterface {
    function checkUpkeep(bytes calldata checkData)
        external
        returns (bool upkeepNeeded, bytes memory performData);

    function performUpkeep(bytes calldata performData) external;
}

interface IInstitutionalStablecoinBridgeMonitor {
    function monitorReserve(bytes32 assetId) external;
}

/**
 * @title InstitutionalReserveAutomationKeeper
 * @notice External automation keeper that triggers reserve monitoring on
 *         InstitutionalStablecoinBridge without increasing bridge bytecode size.
 * @dev The keeper contract must be granted `PAUSER_ROLE` on the bridge.
 */
contract InstitutionalReserveAutomationKeeper is AutomationCompatibleInterface {
    address public owner;
    address public pendingOwner;
    IInstitutionalStablecoinBridgeMonitor public bridge;

    // Operational cap to keep upkeep gas bounded.
    uint256 public maxAssetsPerRun = 16;

    bytes32[] private trackedAssets;
    mapping(bytes32 => bool) public isTrackedAsset;
    mapping(bytes32 => bool) public isAssetEnabled;

    event OwnershipTransferStarted(
        address indexed previousOwner,
        address indexed pendingOwner
    );
    event OwnershipTransferred(
        address indexed previousOwner,
        address indexed newOwner
    );
    event BridgeUpdated(address indexed previousBridge, address indexed newBridge);
    event AssetConfigured(bytes32 indexed assetId, bool enabled);
    event MaxAssetsPerRunUpdated(uint256 oldValue, uint256 newValue);
    event ReserveMonitorTriggered(bytes32 indexed assetId);
    event ReserveMonitorFailed(bytes32 indexed assetId, bytes reason);

    error Unauthorized();
    error InvalidAddress();
    error InvalidConfig();

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    constructor(address bridgeAddress, bytes32[] memory initialAssets) {
        if (bridgeAddress == address(0)) revert InvalidAddress();
        owner = msg.sender;
        bridge = IInstitutionalStablecoinBridgeMonitor(bridgeAddress);

        for (uint256 i = 0; i < initialAssets.length; i++) {
            _setAsset(initialAssets[i], true);
        }
    }

    function setBridge(address bridgeAddress) external onlyOwner {
        if (bridgeAddress == address(0)) revert InvalidAddress();
        address previous = address(bridge);
        bridge = IInstitutionalStablecoinBridgeMonitor(bridgeAddress);
        emit BridgeUpdated(previous, bridgeAddress);
    }

    function setMaxAssetsPerRun(uint256 newMax) external onlyOwner {
        if (newMax == 0 || newMax > 128) revert InvalidConfig();
        uint256 old = maxAssetsPerRun;
        maxAssetsPerRun = newMax;
        emit MaxAssetsPerRunUpdated(old, newMax);
    }

    function setAsset(bytes32 assetId, bool enabled) external onlyOwner {
        _setAsset(assetId, enabled);
    }

    function setAssets(bytes32[] calldata assetIds, bool enabled) external onlyOwner {
        for (uint256 i = 0; i < assetIds.length; i++) {
            _setAsset(assetIds[i], enabled);
        }
    }

    function getTrackedAssets() external view returns (bytes32[] memory) {
        return trackedAssets;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert InvalidAddress();
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert Unauthorized();
        address oldOwner = owner;
        owner = pendingOwner;
        pendingOwner = address(0);
        emit OwnershipTransferred(oldOwner, owner);
    }

    function checkUpkeep(bytes calldata)
        external
        view
        override
        returns (bool upkeepNeeded, bytes memory performData)
    {
        bytes32[] memory batch = _buildAssetBatch();
        upkeepNeeded = batch.length > 0;
        performData = upkeepNeeded ? abi.encode(batch) : bytes("");
    }

    function performUpkeep(bytes calldata performData) external override {
        bytes32[] memory batch;
        if (performData.length == 0) {
            batch = _buildAssetBatch();
        } else {
            batch = abi.decode(performData, (bytes32[]));
        }

        for (uint256 i = 0; i < batch.length; i++) {
            bytes32 assetId = batch[i];
            if (!isAssetEnabled[assetId]) {
                continue;
            }
            try bridge.monitorReserve(assetId) {
                emit ReserveMonitorTriggered(assetId);
            } catch (bytes memory reason) {
                emit ReserveMonitorFailed(assetId, reason);
            }
        }
    }

    function _setAsset(bytes32 assetId, bool enabled) internal {
        if (assetId == bytes32(0)) revert InvalidConfig();
        if (!isTrackedAsset[assetId]) {
            isTrackedAsset[assetId] = true;
            trackedAssets.push(assetId);
        }
        isAssetEnabled[assetId] = enabled;
        emit AssetConfigured(assetId, enabled);
    }

    function _buildAssetBatch() internal view returns (bytes32[] memory batch) {
        uint256 count = 0;
        uint256 length = trackedAssets.length;
        for (uint256 i = 0; i < length && count < maxAssetsPerRun; i++) {
            if (isAssetEnabled[trackedAssets[i]]) {
                count++;
            }
        }

        if (count == 0) {
            return new bytes32[](0);
        }

        batch = new bytes32[](count);
        uint256 cursor = 0;
        for (uint256 i = 0; i < length && cursor < count; i++) {
            bytes32 assetId = trackedAssets[i];
            if (!isAssetEnabled[assetId]) continue;
            batch[cursor] = assetId;
            cursor++;
        }
    }
}
