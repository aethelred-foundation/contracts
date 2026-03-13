// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20BurnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20PermitUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20VotesUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/**
 * @title AethelredToken (AETHEL)
 * @author Aethelred Team
 * @notice The native utility and governance token for the Aethelred Protocol
 * @dev Enterprise-grade ERC20 token with:
 *      - Burning capability (for adaptive burn mechanism)
 *      - Pausable (for emergency situations)
 *      - EIP-2612 Permit (gasless approvals)
 *      - ERC20Votes (on-chain governance)
 *      - complianceBurn with SlashEvent audit trail
 *      - UUPS Upgradeable
 * @custom:security-contact security@aethelred.io
 * @custom:audit-status Remediated - all 27 findings addressed (2026-02-28)
 *
 * Token Specification:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                          AETHEL TOKEN                                        │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │  Name:           Aethelred                                                   │
 * │  Symbol:         AETHEL                                                      │
 * │  Decimals:       18                                                          │
 * │  Total Supply:   10,000,000,000 (10 Billion)                                │
 * │                                                                              │
 * │  Features:                                                                   │
 * │  • ERC20 Standard Compliance                                                │
 * │  • Burnable (Deflationary via Adaptive Burn)                                │
 * │  • Permit (EIP-2612 Gasless Approvals)                                      │
 * │  • Votes (ERC20Votes for Governance)                                        │
 * │  • Pausable (Emergency Circuit Breaker)                                     │
 * │  • Blacklist (OFAC/Sanctions Compliance)                                    │
 * │  • complianceBurn with SlashEvent for regulatory audit trail                │
 * │  • Transfer Hooks (Future Extensibility)                                    │
 * │                                                                              │
 * └─────────────────────────────────────────────────────────────────────────────┘
 */
contract AethelredToken is
    Initializable,
    ERC20Upgradeable,
    ERC20BurnableUpgradeable,
    ERC20PausableUpgradeable,
    ERC20PermitUpgradeable,
    ERC20VotesUpgradeable,
    AccessControlUpgradeable,
    UUPSUpgradeable
{
    // =========================================================================
    // CONSTANTS & ROLES
    // =========================================================================

    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");
    bytes32 public constant COMPLIANCE_ROLE = keccak256("COMPLIANCE_ROLE");
    bytes32 public constant COMPLIANCE_BURN_ROLE = keccak256("COMPLIANCE_BURN_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    /// @notice Total supply cap (10 billion tokens)
    /// @dev Cross-layer denomination - Audit fix [C-02]:
    ///      Solidity uses 18-decimal wei. Go/Cosmos L1 uses 6-decimal uaethel.
    ///      Bridging: Solidity wei = uaethel * UAETHEL_TO_WEI_SCALE
    uint256 public constant TOTAL_SUPPLY_CAP = 10_000_000_000 * 1e18;

    /// @notice Scaling factor from Go uaethel (6 dec) to EVM wei (18 dec). Audit fix [C-02].
    uint256 public constant UAETHEL_TO_WEI_SCALE = 1e12;

    /// @notice Decimals (standard 18)
    uint8 private constant DECIMALS = 18;

    // =========================================================================
    // STATE VARIABLES
    // =========================================================================

    /// @notice Total tokens burned (for tracking deflation)
    uint256 public totalBurned;

    /// @notice Blacklisted addresses (sanctions compliance)
    mapping(address => bool) public blacklisted;

    /// @notice Transfer restrictions enabled
    bool public transferRestrictionsEnabled;

    /// @notice Whitelisted addresses (can transfer during restrictions)
    mapping(address => bool) public whitelisted;

    /// @notice Bridge contracts that can mint/burn
    mapping(address => bool) public authorizedBridges;

    // =========================================================================
    // EVENTS
    // =========================================================================

    event AddressBlacklisted(address indexed account, bool blacklisted);
    event AddressWhitelisted(address indexed account, bool whitelisted);
    event TransferRestrictionsUpdated(bool enabled);
    event BridgeAuthorized(address indexed bridge, bool authorized);
    event TokensBurnedByBridge(address indexed bridge, address indexed from, uint256 amount);
    event TokensMintedByBridge(address indexed bridge, address indexed to, uint256 amount);

    /**
     * @notice Emitted when tokens are burned for compliance/slashing reasons.
     * @dev Provides a full audit trail: who was slashed, by whom, how much, and why.
     */
    event ComplianceSlash(
        address indexed account,
        uint256 amount,
        bytes32 indexed reason,
        address indexed authority
    );

    // =========================================================================
    // ERRORS
    // =========================================================================

    error AddressBlacklistedError(address account);
    error TransferRestricted();
    error SupplyCapExceeded();
    error UnauthorizedBridge();
    error ZeroAddress();
    error InvalidAmount();
    error AdminMustBeContract();
    error ComplianceBurnReasonRequired();

    // =========================================================================
    // MODIFIERS
    // =========================================================================

    modifier notBlacklisted(address account) {
        if (blacklisted[account]) revert AddressBlacklistedError(account);
        _;
    }

    modifier onlyAuthorizedBridge() {
        if (!authorizedBridges[msg.sender]) revert UnauthorizedBridge();
        _;
    }

    // =========================================================================
    // INITIALIZATION
    // =========================================================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initialize the token contract
     * @param admin Admin address with all roles
     * @param minter Initial minter (usually vesting contract)
     * @param initialRecipient Address to receive initial supply
     * @param initialAmount Amount to mint initially
     */
    function initialize(
        address admin,
        address minter,
        address initialRecipient,
        uint256 initialAmount
    ) external initializer {
        if (admin == address(0)) revert ZeroAddress();
        if (initialRecipient == address(0)) revert ZeroAddress();
        if (initialAmount > TOTAL_SUPPLY_CAP) revert SupplyCapExceeded();
        _requireContractAdmin(admin);

        __ERC20_init("Aethelred", "AETHEL");
        __ERC20Burnable_init();
        __ERC20Pausable_init();
        __ERC20Permit_init("Aethelred");
        __ERC20Votes_init();
        __AccessControl_init();
        __UUPSUpgradeable_init();

        // Setup roles
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
        _grantRole(BURNER_ROLE, admin);
        _grantRole(COMPLIANCE_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);

        if (minter != address(0)) {
            _grantRole(MINTER_ROLE, minter);
        }

        // Mint initial supply
        if (initialAmount > 0) {
            _mint(initialRecipient, initialAmount);
        }

        // Enable transfer restrictions by default (disabled after TGE)
        transferRestrictionsEnabled = true;
    }

    // =========================================================================
    // ERC20 OVERRIDES
    // =========================================================================

    function decimals() public pure override returns (uint8) {
        return DECIMALS;
    }

    /**
     * @notice Transfer with compliance checks
     */
    function transfer(address to, uint256 amount)
        public
        override
        notBlacklisted(msg.sender)
        notBlacklisted(to)
        returns (bool)
    {
        _checkTransferRestrictions(msg.sender);
        return super.transfer(to, amount);
    }

    /**
     * @notice TransferFrom with compliance checks
     */
    function transferFrom(address from, address to, uint256 amount)
        public
        override
        notBlacklisted(from)
        notBlacklisted(to)
        notBlacklisted(msg.sender)
        returns (bool)
    {
        _checkTransferRestrictions(from);
        return super.transferFrom(from, to, amount);
    }

    function _checkTransferRestrictions(address from) internal view {
        if (transferRestrictionsEnabled && !whitelisted[from]) {
            revert TransferRestricted();
        }
    }

    // =========================================================================
    // MINTING
    // =========================================================================

    /**
     * @notice Mint new tokens (up to supply cap)
     * @param to Recipient address
     * @param amount Amount to mint
     */
    function mint(address to, uint256 amount)
        external
        onlyRole(MINTER_ROLE)
        notBlacklisted(to)
    {
        if (totalSupply() + amount > TOTAL_SUPPLY_CAP) revert SupplyCapExceeded();
        _mint(to, amount);
    }

    // =========================================================================
    // BURNING
    // =========================================================================

    /**
     * @notice Burn tokens from caller
     * @param amount Amount to burn
     */
    function burn(uint256 amount) public override {
        totalBurned += amount;
        super.burn(amount);
    }

    /**
     * @notice Burn tokens from account (with allowance)
     * @param account Account to burn from
     * @param amount Amount to burn
     */
    function burnFrom(address account, uint256 amount) public override {
        totalBurned += amount;
        super.burnFrom(account, amount);
    }

    /**
     * @notice Compliance burn with mandatory reason for audit trail (M-06 hardening).
     * @dev Replaces the generic adminBurn with a transparency-oriented API.
     *      Requires COMPLIANCE_BURN_ROLE (separation from generic BURNER_ROLE),
     *      prior allowance from the target account, and emits a ComplianceSlash event.
     * @param account Account to burn from
     * @param amount Amount to burn
     * @param reason Machine-readable reason code (e.g., keccak256("SANCTIONS"))
     */
    function complianceBurn(address account, uint256 amount, bytes32 reason)
        external
        onlyRole(COMPLIANCE_BURN_ROLE)
    {
        if (reason == bytes32(0)) revert ComplianceBurnReasonRequired();
        _spendAllowance(account, msg.sender, amount);
        totalBurned += amount;
        _burn(account, amount);
        emit ComplianceSlash(account, amount, reason, msg.sender);
    }

    /**
     * @notice Legacy administrative burn - DEPRECATED. Audit fix [M-01].
     * @dev Use complianceBurn() instead, which requires a reason code and emits
     *      a ComplianceSlash event for full audit trail. This function is retained
     *      only for backward compatibility and will be removed in a future version.
     * @param account Account to burn from
     * @param amount Amount to burn
     */
    function adminBurn(address account, uint256 amount)
        external
        onlyRole(BURNER_ROLE)
    {
        _spendAllowance(account, msg.sender, amount);
        totalBurned += amount;
        _burn(account, amount);
        // Audit fix [M-01]: Emit ComplianceSlash with LEGACY_ADMIN_BURN reason
        // so all burns have an on-chain audit trail regardless of entry point.
        emit ComplianceSlash(account, amount, keccak256("LEGACY_ADMIN_BURN"), msg.sender);
    }

    // =========================================================================
    // BRIDGE FUNCTIONS
    // =========================================================================

    /**
     * @notice Mint tokens from bridge (for incoming transfers)
     * @param to Recipient on this chain
     * @param amount Amount to mint
     */
    function bridgeMint(address to, uint256 amount)
        external
        onlyAuthorizedBridge
        notBlacklisted(to)
    {
        if (totalSupply() + amount > TOTAL_SUPPLY_CAP) revert SupplyCapExceeded();
        _mint(to, amount);
        emit TokensMintedByBridge(msg.sender, to, amount);
    }

    /**
     * @notice Burn tokens from bridge (for outgoing transfers)
     * @param from Account burning tokens
     * @param amount Amount to burn
     */
    function bridgeBurn(address from, uint256 amount)
        external
        onlyAuthorizedBridge
    {
        _spendAllowance(from, msg.sender, amount);
        totalBurned += amount;
        _burn(from, amount);
        emit TokensBurnedByBridge(msg.sender, from, amount);
    }

    // =========================================================================
    // COMPLIANCE FUNCTIONS
    // =========================================================================

    /**
     * @notice Add/remove address from blacklist
     * @param account Address to update
     * @param status Blacklist status
     */
    function setBlacklisted(address account, bool status)
        external
        onlyRole(COMPLIANCE_ROLE)
    {
        blacklisted[account] = status;
        emit AddressBlacklisted(account, status);
    }

    /// @notice Maximum batch size for batchSetBlacklisted to prevent block gas limit DoS.
    /// Audit fix [H-02].
    uint256 public constant MAX_BATCH_BLACKLIST_SIZE = 200;

    /**
     * @notice Batch blacklist update
     * @dev Audit fix [H-02]: Bounded to MAX_BATCH_BLACKLIST_SIZE to prevent DoS
     *      via block gas limit exhaustion from unbounded arrays.
     * @param accounts Addresses to update (max 200)
     * @param status Blacklist status
     */
    function batchSetBlacklisted(address[] calldata accounts, bool status)
        external
        onlyRole(COMPLIANCE_ROLE)
    {
        require(accounts.length <= MAX_BATCH_BLACKLIST_SIZE, "Batch too large");
        for (uint256 i = 0; i < accounts.length; i++) {
            blacklisted[accounts[i]] = status;
            emit AddressBlacklisted(accounts[i], status);
        }
    }

    /**
     * @notice Add/remove address from whitelist
     * @param account Address to update
     * @param status Whitelist status
     */
    function setWhitelisted(address account, bool status)
        external
        onlyRole(COMPLIANCE_ROLE)
    {
        whitelisted[account] = status;
        emit AddressWhitelisted(account, status);
    }

    /**
     * @notice Enable/disable transfer restrictions
     * @param enabled Whether restrictions are enabled
     */
    function setTransferRestrictions(bool enabled)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        transferRestrictionsEnabled = enabled;
        emit TransferRestrictionsUpdated(enabled);
    }

    // =========================================================================
    // BRIDGE MANAGEMENT
    // =========================================================================

    /**
     * @notice Authorize/deauthorize bridge contract
     * @param bridge Bridge address
     * @param authorized Authorization status
     */
    function setAuthorizedBridge(address bridge, bool authorized)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        authorizedBridges[bridge] = authorized;
        emit BridgeAuthorized(bridge, authorized);
    }

    // =========================================================================
    // PAUSE FUNCTIONS
    // =========================================================================

    /**
     * @notice Pause all transfers
     */
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause transfers
     */
    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /**
     * @notice Get circulating supply (total minted, including locked/vesting tokens).
     * @dev Audit fix [L-03]: Renamed semantics. totalSupply() already excludes
     *      burned tokens (ERC20 standard). For truly circulating supply excluding
     *      locked/vesting, subtract the vesting contract balance off-chain.
     *      On-chain vesting exclusion would require coupling to the vesting contract
     *      address, which is set post-deployment.
     */
    function circulatingSupply() external view returns (uint256) {
        return totalSupply();
    }

    /**
     * @notice Get remaining mintable supply
     */
    function remainingMintable() external view returns (uint256) {
        return TOTAL_SUPPLY_CAP - totalSupply();
    }

    /**
     * @notice Check if address can transfer
     */
    function canTransfer(address account) external view returns (bool) {
        if (blacklisted[account]) return false;
        if (transferRestrictionsEnabled && !whitelisted[account]) return false;
        if (paused()) return false;
        return true;
    }

    // =========================================================================
    // REQUIRED OVERRIDES
    // =========================================================================

    function _update(address from, address to, uint256 value)
        internal
        override(ERC20Upgradeable, ERC20PausableUpgradeable, ERC20VotesUpgradeable)
    {
        super._update(from, to, value);
    }

    function nonces(address owner)
        public
        view
        override(ERC20PermitUpgradeable, NoncesUpgradeable)
        returns (uint256)
    {
        return super.nonces(owner);
    }

    function _authorizeUpgrade(address newImplementation)
        internal
        override
        onlyRole(UPGRADER_ROLE)
    {}

    function _requireContractAdmin(address admin) internal view {
        if (admin.code.length > 0) {
            return;
        }
        // Preserve local dev tooling ergonomics while enforcing multisig/contract
        // admins on deployed networks.
        if (block.chainid == 31337 || block.chainid == 1337) {
            return;
        }
        revert AdminMustBeContract();
    }

    // =========================================================================
    // VERSION - Audit fix [I-05]
    // =========================================================================

    /// @notice Contract implementation version for upgrade tracking.
    function version() external pure returns (string memory) {
        return "1.0.0";
    }

    // =========================================================================
    // STORAGE GAP
    // =========================================================================

    uint256[50] private __gap;
}
