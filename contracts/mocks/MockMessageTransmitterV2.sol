// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MockMessageTransmitterV2 {
    bool public shouldSucceed = true;

    event MessageReceived(bytes message, bytes attestation, bool success);

    function setShouldSucceed(bool value) external {
        shouldSucceed = value;
    }

    function receiveMessage(
        bytes calldata message,
        bytes calldata attestation
    ) external returns (bool success) {
        success = shouldSucceed;
        emit MessageReceived(message, attestation, success);
    }
}

