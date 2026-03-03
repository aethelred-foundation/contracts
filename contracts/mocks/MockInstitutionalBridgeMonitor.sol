// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

contract MockInstitutionalBridgeMonitor {
    uint256 public monitorCallCount;
    bytes32 public lastMonitoredAssetId;
    mapping(bytes32 => uint256) public monitorCallsByAsset;
    mapping(bytes32 => bool) public shouldRevertForAsset;

    event ReserveMonitored(bytes32 indexed assetId);

    function setShouldRevert(bytes32 assetId, bool shouldRevert) external {
        shouldRevertForAsset[assetId] = shouldRevert;
    }

    function monitorReserve(bytes32 assetId) external {
        if (shouldRevertForAsset[assetId]) revert("mock-monitor-revert");
        monitorCallCount += 1;
        lastMonitoredAssetId = assetId;
        monitorCallsByAsset[assetId] += 1;
        emit ReserveMonitored(assetId);
    }
}
