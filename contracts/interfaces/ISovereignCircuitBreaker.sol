// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/**
 * @title ISovereignCircuitBreaker
 * @notice Interface for anomaly-triggered mint pausing based on attested reserve feeds.
 */
interface ISovereignCircuitBreaker {
    event AnomalyDetected(
        uint256 onChainSupply,
        uint256 oracleReserve,
        uint256 deviationBps
    );
    event MintingPaused(address indexed triggeredBy, uint256 timestamp);
    event MintingUnpaused(address indexed executedBy, uint256 timestamp);

    function MAX_DEVIATION_BPS() external view returns (uint256);
    function reserveOracle() external view returns (address);
    function checkReserveAnomaly(uint256 pendingMintAmount) external;
    function isPaused() external view returns (bool);
    function unpauseMinting() external;
}
