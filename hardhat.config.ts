/**
 * Hardhat Configuration - Aethelred Bridge Contracts
 *
 * Enterprise-grade configuration for development, testing, and deployment
 * of the AethelredBridge smart contracts across multiple networks.
 *
 * Networks Supported:
 * - devnet: Local DevNet (Anvil/Ganache)
 * - sepolia: Ethereum Sepolia testnet
 * - mainnet: Ethereum Mainnet (production)
 *
 * @author Aethelred Team
 * @license Apache-2.0
 */

import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "@openzeppelin/hardhat-upgrades";
import "@nomicfoundation/hardhat-verify";
import "hardhat-gas-reporter";
import "hardhat-contract-sizer";
import "solidity-coverage";
import * as dotenv from "dotenv";

dotenv.config();

// ============================================================================
// Environment Variables
// ============================================================================

// SECURITY FIX H-03: Only allow Anvil default key for local/dev networks.
// Non-local networks (sepolia, mainnet) MUST provide DEPLOYER_PRIVATE_KEY via env var.
const ANVIL_DEFAULT_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

function getAccounts(networkName: string): string[] {
  const key = process.env.DEPLOYER_PRIVATE_KEY;
  if (key) return [key];
  // Only allow Anvil default key for local development networks
  if (
    networkName === "hardhat" ||
    networkName === "devnet" ||
    networkName === "localhost"
  ) {
    return [ANVIL_DEFAULT_KEY];
  }
  // Non-local networks: return empty array - deployment will fail with a clear error
  return [];
}

const SEPOLIA_RPC_URL = process.env.SEPOLIA_RPC_URL ||
  "https://eth-sepolia.g.alchemy.com/v2/demo";

const MAINNET_RPC_URL = process.env.MAINNET_RPC_URL ||
  "https://eth-mainnet.g.alchemy.com/v2/demo";

const ETHERSCAN_API_KEY = process.env.ETHERSCAN_API_KEY || "";

const COINMARKETCAP_API_KEY = process.env.COINMARKETCAP_API_KEY || "";

const REPORT_GAS = process.env.REPORT_GAS === "true";
const ALLOW_UNLIMITED_CONTRACT_SIZE =
  process.env.ALLOW_UNLIMITED_CONTRACT_SIZE === "true";

// DevNet configuration (Docker network)
const DEVNET_RPC_URL = process.env.DEVNET_RPC_URL ||
  "http://localhost:8545";

// ============================================================================
// Hardhat Configuration
// ============================================================================

const config: HardhatUserConfig = {
  // Solidity Compiler Configuration
  solidity: {
    compilers: [
      {
        version: "0.8.20",
        settings: {
          optimizer: {
            enabled: true,
            runs: 200, // Optimized for frequent function calls
            details: {
              yul: true,
              yulDetails: {
                stackAllocation: true,
              },
            },
          },
          viaIR: true, // Enable IR-based code generation for better optimization
          evmVersion: "paris", // Latest stable EVM version
          metadata: {
            bytecodeHash: "ipfs", // Use IPFS for metadata hash
            useLiteralContent: true,
          },
        },
      },
    ],
    overrides: {
      // Size-optimized override for the institutional bridge to stay under EIP-170
      // without altering runtime behavior or ABI.
      "contracts/InstitutionalStablecoinBridge.sol": {
        version: "0.8.20",
        settings: {
          optimizer: {
            enabled: true,
            runs: 1,
            details: {
              yul: true,
              yulDetails: {
                stackAllocation: true,
              },
            },
          },
          viaIR: true,
          evmVersion: "paris",
          metadata: {
            bytecodeHash: "none",
            useLiteralContent: false,
            appendCBOR: false,
          },
        },
      },
    },
  },

  // Network Configuration
  networks: {
    // Local Hardhat Network
    hardhat: {
      chainId: 31337,
      forking: process.env.FORK_MAINNET === "true" ? {
        url: MAINNET_RPC_URL,
        blockNumber: 18800000, // Pin to specific block for deterministic tests
      } : undefined,
      allowUnlimitedContractSize: ALLOW_UNLIMITED_CONTRACT_SIZE,
      mining: {
        auto: true,
        interval: 0,
      },
    },

    // Local DevNet (Anvil in Docker)
    devnet: {
      url: DEVNET_RPC_URL,
      chainId: 31337,
      accounts: getAccounts("devnet"),
      timeout: 60000,
      gas: "auto",
      gasPrice: "auto",
    },

    // Sepolia Testnet
    sepolia: {
      url: SEPOLIA_RPC_URL,
      chainId: 11155111,
      accounts: getAccounts("sepolia"),
      timeout: 120000,
      gas: "auto",
      gasPrice: "auto",
      // Alchemy/Infura rate limiting settings
      httpHeaders: {},
    },

    // Ethereum Mainnet (Production)
    mainnet: {
      url: MAINNET_RPC_URL,
      chainId: 1,
      accounts: getAccounts("mainnet"),
      timeout: 180000,
      gas: "auto",
      gasPrice: "auto",
      // Production safeguards
      verify: {
        etherscan: {
          apiKey: ETHERSCAN_API_KEY,
        },
      },
    },
  },

  // Etherscan Verification
  etherscan: {
    apiKey: {
      mainnet: ETHERSCAN_API_KEY,
      sepolia: ETHERSCAN_API_KEY,
    },
    customChains: [
      {
        network: "devnet",
        chainId: 31337,
        urls: {
          apiURL: "http://localhost:4000/api",
          browserURL: "http://localhost:4000",
        },
      },
    ],
  },

  // Gas Reporter Configuration
  gasReporter: {
    enabled: REPORT_GAS,
    currency: "USD",
    coinmarketcap: COINMARKETCAP_API_KEY,
    token: "ETH",
    gasPriceApi: "https://api.etherscan.io/api?module=proxy&action=eth_gasPrice",
    outputFile: process.env.CI ? "gas-report.txt" : undefined,
    noColors: process.env.CI ? true : false,
    showTimeSpent: true,
    showMethodSig: true,
    excludeContracts: ["Mock", "Test"],
  },

  // Contract Sizer Configuration
  contractSizer: {
    alphaSort: true,
    disambiguatePaths: false,
    runOnCompile: false,
    strict: true,
    only: ["InstitutionalStablecoinBridge"],
  },

  // TypeChain Configuration
  typechain: {
    outDir: "typechain-types",
    target: "ethers-v6",
    alwaysGenerateOverloads: true,
    externalArtifacts: ["node_modules/@openzeppelin/contracts/build/contracts/*.json"],
    dontOverrideCompile: false,
  },

  // Paths Configuration
  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts",
  },

  // Mocha Test Configuration
  mocha: {
    timeout: 120000, // 2 minutes for complex tests
    parallel: false, // Disable parallel for state-dependent tests
    retries: process.env.CI ? 2 : 0,
  },
};

export default config;
