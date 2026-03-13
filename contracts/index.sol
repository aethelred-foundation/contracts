// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/**
 * @title @aethelred/contracts
 * @notice Barrel import - pull in all interfaces with a single import.
 *
 * Usage in consumer projects:
 *
 *   import "@aethelred/contracts/contracts/index.sol";
 *
 * Or import individual interfaces:
 *
 *   import {IAethelredTEE} from "@aethelred/contracts/contracts/interfaces/IAethelredTEE.sol";
 *   import {IAethelredBridge} from "@aethelred/contracts/contracts/interfaces/IAethelredBridge.sol";
 *   import {IAethelredOracle} from "@aethelred/contracts/contracts/interfaces/IAethelredOracle.sol";
 *   import {AethelredTypes} from "@aethelred/contracts/contracts/types/AethelredTypes.sol";
 */

import {AethelredTypes} from "./types/AethelredTypes.sol";
import {IAethelredTEE, IAethelredCallback} from "./interfaces/IAethelredTEE.sol";
import {IAethelredBridge} from "./interfaces/IAethelredBridge.sol";
import {IAethelredOracle} from "./interfaces/IAethelredOracle.sol";
