# Aethelred Bridge Test Suite

## Overview

Comprehensive Foundry test suite for the AethelredBridge smart contracts. These tests ensure the security and correctness of the Ethereum <-> Aethelred cross-chain bridge.

## Test Categories

### Unit Tests (`AethelredBridgeTest`)

| Test | Description |
|------|-------------|
| `test_Initialize` | Verifies correct initialization of roles and config |
| `test_CannotReinitialize` | Ensures proxy cannot be re-initialized |
| `test_DepositETH` | Tests ETH deposit functionality |
| `test_DepositETH_EmitsEvent` | Verifies correct event emission |
| `test_DepositETH_MinimumAmount` | Tests minimum deposit enforcement |
| `test_DepositETH_MaximumAmount` | Tests maximum deposit enforcement |
| `test_DepositETH_InvalidRecipient` | Tests zero recipient rejection |
| `test_DepositETH_BlockedAddress` | Tests sanctions compliance |
| `test_DepositETH_WhenPaused` | Tests pause functionality |
| `test_CancelDeposit_ETH` | Tests ETH deposit cancellation |
| `test_DepositERC20` | Tests ERC20 deposit functionality |
| `test_DepositERC20_UnsupportedToken` | Tests token allowlist |
| `test_ProposeWithdrawal` | Tests withdrawal proposal creation |
| `test_VoteWithdrawal` | Tests relayer voting |
| `test_VoteWithdrawal_CannotVoteTwice` | Tests double-voting prevention |
| `test_ProcessWithdrawal_ETH` | Tests complete withdrawal flow |
| `test_ProcessWithdrawal_BeforeChallengePeriod` | Tests challenge period enforcement |
| `test_ProcessWithdrawal_InsufficientVotes` | Tests consensus requirement |
| `test_ChallengeWithdrawal` | Tests fraud proof mechanism |
| `test_RateLimit_Deposit` | Tests rate limiting |
| `test_RateLimit_ResetsAfterPeriod` | Tests period-based rate limit reset |

### Emergency Withdrawal Timelock Tests (`AethelredBridgeEmergencyTest`)

| Test | Description |
|------|-------------|
| `test_QueueEmergencyWithdrawal_StoresRequest` | Queues emergency request and validates timelock metadata |
| `test_ExecuteEmergencyWithdrawal_RevertsBeforeDelay` | Enforces timelock before execution |
| `test_ExecuteEmergencyWithdrawal_AfterDelayTransfers` | Executes after timelock and transfers funds |
| `test_CancelEmergencyWithdrawal_PreventsExecution` | Cancels queued operation and blocks execution |
| `test_SetEmergencyWithdrawalDelay_*` | Validates delay bounds and update path |

### Token Tests (`AethelredTokenTest`)

| Test | Description |
|------|-------------|
| `test_TransferRestrictedByDefault` | Confirms transfer restrictions are fail-closed by default |
| `test_WhitelistedAddressCanTransfer` | Validates whitelist bypass during restricted mode |
| `test_BridgeMintRequiresAuthorizedBridge` | Prevents unauthorized bridge minting |
| `test_AuthorizedBridgeCanMint` | Allows mint from authorized bridge only |
| `test_MinterRespectsSupplyCap` | Enforces total supply cap on mint path |

### Fuzz Tests

| Test | Description |
|------|-------------|
| `testFuzz_DepositETH` | Fuzz tests deposit amounts |
| `testFuzz_VoteCount` | Fuzz tests vote counting |

### Invariant Tests (`AethelredBridgeInvariantTest`)

| Invariant | Description |
|-----------|-------------|
| `invariant_TotalLockedNeverNegative` | Locked amount can never go negative |
| `invariant_BalanceMatchesLocked` | Contract balance matches accounting |

## Running Tests

### Prerequisites

```bash
# Install Foundry
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Install dependencies
cd contracts
forge install OpenZeppelin/openzeppelin-contracts
forge install OpenZeppelin/openzeppelin-contracts-upgradeable
forge install foundry-rs/forge-std
```

### Run All Tests

```bash
forge test
```

### Run with Verbosity

```bash
# Show test names
forge test -v

# Show logs
forge test -vv

# Show traces
forge test -vvv

# Show full traces with storage
forge test -vvvv
```

### Run Specific Tests

```bash
# Run single test
forge test --match-test test_DepositETH

# Run test contract
forge test --match-contract AethelredBridgeTest

# Run fuzz tests only
forge test --match-test testFuzz
```

### Run with Gas Report

```bash
forge test --gas-report
```

### Run with Coverage

```bash
forge coverage
forge coverage --report lcov
```

### Run Invariant Tests

```bash
# Default runs
forge test --match-contract Invariant

# Extended runs for production
forge test --match-contract Invariant -vvv \
  --fuzz-runs 10000 \
  --invariant-runs 1000 \
  --invariant-depth 50
```

## Test Configuration

### Profiles

```bash
# CI profile (faster)
FOUNDRY_PROFILE=ci forge test

# Production profile (thorough)
FOUNDRY_PROFILE=production forge test
```

### Fork Testing

```bash
# Test against mainnet fork
forge test --fork-url $MAINNET_RPC_URL

# Test against specific block
forge test --fork-url $MAINNET_RPC_URL --fork-block-number 18000000
```

## Security Testing

### Slither Analysis

```bash
slither . --config-file slither.config.json
```

### Mythril Analysis

```bash
myth analyze contracts/contracts/AethelredBridge.sol
```

## Test Accounts

| Role | Address |
|------|---------|
| Admin | `0x0000...0001` |
| Guardian | `0x0000...0002` |
| User1 | `0x0000...0003` |
| User2 | `0x0000...0004` |
| Blocked | `0x0000...0005` |
| Relayer1-5 | `0x0000...0010-0014` |

## Contributing

1. Write tests for all new functionality
2. Maintain >95% code coverage
3. Run full test suite before PR
4. Add fuzz tests for numeric inputs
5. Add invariant tests for critical properties
