// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import "./interfaces/ISovereignCircuitBreaker.sol";

interface IReserveOracle {
    function decimals() external view returns (uint8);
    function latestRoundData()
        external
        view
        returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        );
}

/**
 * @title SovereignCircuitBreakerModule
 * @notice Reference module that pauses minting when projected supply deviates from
 *         attested reserves beyond a configured threshold.
 * @dev Designed as a drop-in module for single-asset stablecoin contracts.
 * @custom:security-contact security@aethelred.io
 * @custom:audit-status Remediated - all 27 findings addressed (2026-02-28)
 */
contract SovereignCircuitBreakerModule is ISovereignCircuitBreaker, Ownable {
    uint256 public constant BPS_DENOMINATOR = 10_000;
    uint256 public constant MAX_ORACLE_STALENESS_SECONDS = 24 hours;

    uint256 public immutable override MAX_DEVIATION_BPS;
    address public immutable override reserveOracle;
    IERC20 public immutable stablecoin;

    address public multiSigWallet;
    bool public override isPaused;

    error InvalidAddress();
    error InvalidAmount();
    error Unauthorized();
    error NotPaused();

    constructor(
        address owner_,
        address stablecoin_,
        address reserveOracle_,
        address multiSigWallet_,
        uint256 maxDeviationBps_
    ) Ownable(owner_) {
        if (
            owner_ == address(0) ||
            stablecoin_ == address(0) ||
            reserveOracle_ == address(0) ||
            multiSigWallet_ == address(0)
        ) revert InvalidAddress();
        if (maxDeviationBps_ > BPS_DENOMINATOR) revert InvalidAmount();

        stablecoin = IERC20(stablecoin_);
        reserveOracle = reserveOracle_;
        multiSigWallet = multiSigWallet_;
        MAX_DEVIATION_BPS = maxDeviationBps_;
    }

    modifier onlyMultiSig() {
        if (msg.sender != multiSigWallet) revert Unauthorized();
        _;
    }

    function setMultiSigWallet(address nextWallet) external onlyOwner {
        if (nextWallet == address(0)) revert InvalidAddress();
        multiSigWallet = nextWallet;
    }

    function checkReserveAnomaly(uint256 pendingMintAmount) public override {
        if (isPaused) return;

        uint8 tokenDecimals = IERC20Metadata(address(stablecoin)).decimals();
        uint256 projectedSupply = stablecoin.totalSupply() + pendingMintAmount;
        uint256 projectedSupply18 = _normalizeTo18(projectedSupply, tokenDecimals);

        (
            ,
            int256 reserveBalance,
            ,
            uint256 updatedAt,
        ) = IReserveOracle(reserveOracle).latestRoundData();
        if (reserveBalance <= 0) {
            isPaused = true;
            emit AnomalyDetected(projectedSupply18, 0, BPS_DENOMINATOR);
            emit MintingPaused(msg.sender, block.timestamp);
            return;
        }
        if (
            updatedAt == 0 ||
            block.timestamp > updatedAt + MAX_ORACLE_STALENESS_SECONDS
        ) {
            isPaused = true;
            emit AnomalyDetected(projectedSupply18, 0, BPS_DENOMINATOR);
            emit MintingPaused(msg.sender, block.timestamp);
            return;
        }

        uint8 oracleDecimals = IReserveOracle(reserveOracle).decimals();
        uint256 oracleReserve18 = _normalizeTo18(
            uint256(reserveBalance),
            oracleDecimals
        );

        if (projectedSupply18 <= oracleReserve18 || oracleReserve18 == 0) return;

        uint256 difference = projectedSupply18 - oracleReserve18;
        uint256 deviationBps = (difference * BPS_DENOMINATOR) / oracleReserve18;

        if (deviationBps > MAX_DEVIATION_BPS) {
            isPaused = true;
            emit AnomalyDetected(projectedSupply18, oracleReserve18, deviationBps);
            emit MintingPaused(msg.sender, block.timestamp);
        }
    }

    function unpauseMinting() external override onlyMultiSig {
        if (!isPaused) revert NotPaused();
        isPaused = false;
        emit MintingUnpaused(msg.sender, block.timestamp);
    }

    function _normalizeTo18(uint256 amount, uint8 decimals)
        internal
        pure
        returns (uint256)
    {
        if (decimals == 18) return amount;
        if (decimals < 18) return amount * (10 ** (18 - decimals));
        return amount / (10 ** (decimals - 18));
    }
}
