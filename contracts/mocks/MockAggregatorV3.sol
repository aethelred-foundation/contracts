// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MockAggregatorV3 {
    uint8 public immutable decimals;

    uint80 private _roundId;
    int256 private _answer;
    uint256 private _startedAt;
    uint256 private _updatedAt;
    uint80 private _answeredInRound;

    constructor(uint8 feedDecimals) {
        decimals = feedDecimals;
        _roundId = 1;
        _answer = 0;
        _startedAt = block.timestamp;
        _updatedAt = block.timestamp;
        _answeredInRound = 1;
    }

    function setRoundData(
        int256 answer_,
        uint256 updatedAt_
    ) external {
        _roundId += 1;
        _answer = answer_;
        _startedAt = block.timestamp;
        _updatedAt = updatedAt_;
        _answeredInRound = _roundId;
    }

    function latestRoundData()
        external
        view
        returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        )
    {
        return (
            _roundId,
            _answer,
            _startedAt,
            _updatedAt,
            _answeredInRound
        );
    }
}

