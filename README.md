<h1 align="center">Aethelred Contracts</h1>

<p align="center">
 <strong>Production Solidity smart contracts for the Aethelred ecosystem</strong><br/>
 Ethereum Bridge · Seal Verifier · Oracle · Governance
</p>

<p align="center">
 <a href="https://github.com/aethelred-foundation/contracts/actions/workflows/contracts-ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/aethelred-foundation/contracts/contracts-ci.yml?branch=main&style=flat-square&label=CI" alt="CI"></a>
 <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square" alt="License"></a>
 <a href="https://docs.aethelred.io/contracts"><img src="https://img.shields.io/badge/docs-contracts-orange?style=flat-square" alt="Docs"></a>
 <img src="https://img.shields.io/badge/audit-in_progress-yellow?style=flat-square" alt="Audit">
 <img src="https://img.shields.io/badge/solidity-^0.8.20-purple?style=flat-square" alt="Solidity">
</p>

---

## Contracts

| Contract | Description | Address (Mainnet) |
|---|---|---|
| `AethelredBridge.sol` | Lock-and-mint ETH ↔ AETHEL bridge (UUPS, guardian multi-sig) | TBD |
| `SealVerifier.sol` | On-chain Digital Seal verification | TBD |
| `AETHELToken.sol` | Wrapped AETHEL ERC-20 (18 decimals) | TBD |

---

## Security

- **Guardian multi-sig**: 2-of-N required for emergency withdrawals
- **Timelock**: 27-day minimum delay on upgrades (UPGRADER_ROLE → timelock contract)
- **Rate limits**: 1000 ETH/hr deposit + withdrawal ceiling
- **EIP-712**: Structured data signing for all relayer messages
- **OFAC screening**: `blockedAddresses` mapping with on-chain enforcement
- **Audited by**: [Audit status pending]

> IMPORTANT: Found a vulnerability? See [SECURITY.md](SECURITY.md) — do NOT open a public issue.

---

## Quick Start

```bash
# Install dependencies
npm install

# Compile
npx hardhat compile

# Run tests
npx hardhat test

# Run Foundry tests
forge test -vvv

# Static analysis (Slither)
slither . --config-file slither.config.json
```

---

## Deployment

```bash
# Deploy to local testnet
npx hardhat run scripts/deploy.ts --network localhost

# Deploy to Ethereum Sepolia testnet
npx hardhat run scripts/deploy.ts --network sepolia
```

Deployed addresses are tracked in `deployments/`:
```
deployments/
├── mainnet.json
├── sepolia.json
└── localhost.json
```

---

## Architecture

```
AethelredBridge (UUPS Upgradeable)
├── Roles: RELAYER_ROLE, GUARDIAN_ROLE, UPGRADER_ROLE
├── deposit(ETH/ERC-20) → locks funds → emits DepositInitiated
├── finalizeDeposit() → RELAYER_ROLE → 64-block confirmation
├── proposeWithdrawal() → RELAYER_ROLE → 7-day challenge period
├── voteWithdrawal() → relayers vote (EIP-712 sig)
└── processWithdrawal() → 67% votes → releases funds

SealVerifier
└── verifySeal(jobId, outputHash, blockHeight) → read Aethelred state
```

---

## Contributing

See [aethelred/aethelred CONTRIBUTING.md](https://github.com/aethelred-foundation/aethelred/blob/main/CONTRIBUTING.md).
