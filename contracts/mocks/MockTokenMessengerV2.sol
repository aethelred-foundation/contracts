// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract MockTokenMessengerV2 {
    using SafeERC20 for IERC20;

    uint64 public nonce;

    event BurnDeposited(
        uint64 indexed nonce,
        address indexed token,
        uint256 amount,
        uint32 destinationDomain,
        bytes32 mintRecipient
    );

    function depositForBurn(
        uint256 amount,
        uint32 destinationDomain,
        bytes32 mintRecipient,
        address burnToken
    ) external returns (uint64) {
        IERC20(burnToken).safeTransferFrom(msg.sender, address(this), amount);
        nonce += 1;
        emit BurnDeposited(
            nonce,
            burnToken,
            amount,
            destinationDomain,
            mintRecipient
        );
        return nonce;
    }
}

