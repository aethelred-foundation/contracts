// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20BurnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20PermitUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/**
 * @title StAETHEL (Staked AETHEL)
 * @author Aethelred Team
 * @notice Liquid staking token representing staked AETHEL in Cruzible.
 *
 * @dev StAETHEL is a share-based token (similar to Lido's stETH model).
 *      The token balance rebases based on the exchange rate between AETHEL
 *      and stAETHEL. As rewards accrue, the value of each stAETHEL share
 *      increases relative to AETHEL.
 *
 * Design:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                       stAETHEL TOKEN MODEL                             │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                         │
 * │   Exchange Rate = Total Pooled AETHEL / Total stAETHEL Shares          │
 * │                                                                         │
 * │   Day 0:  1 stAETHEL = 1.000 AETHEL                                   │
 * │   Day 30: 1 stAETHEL = 1.008 AETHEL  (after rewards)                  │
 * │   Day 90: 1 stAETHEL = 1.024 AETHEL                                   │
 * │                                                                         │
 * │   Shares are internal accounting units. balanceOf() returns the         │
 * │   user's share of the total pooled AETHEL.                             │
 * │                                                                         │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * @custom:security-contact security@aethelred.io
 */
contract StAETHEL is
    Initializable,
    ERC20Upgradeable,
    ERC20BurnableUpgradeable,
    ERC20PausableUpgradeable,
    ERC20PermitUpgradeable,
    AccessControlUpgradeable,
    UUPSUpgradeable
{
    // =========================================================================
    // CONSTANTS & ROLES
    // =========================================================================

    bytes32 public constant VAULT_ROLE = keccak256("VAULT_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    /// @notice Precision for share calculations (1e27 to avoid rounding issues).
    uint256 internal constant SHARES_PRECISION = 1e27;

    /// @notice Maximum total supply of shares (prevents overflow in calculations).
    uint256 public constant MAX_TOTAL_SHARES = 10_000_000_000 * 1e18;

    // =========================================================================
    // STATE VARIABLES
    // =========================================================================

    /// @notice Total AETHEL pooled in the vault (updated by vault on reward distribution).
    uint256 public totalPooledAethel;

    /// @notice Mapping from user to their share amount (internal accounting).
    mapping(address => uint256) internal _shares;

    /// @notice Total shares outstanding.
    uint256 internal _totalShares;

    /// @notice The Cruzible contract address.
    address public vault;

    /// @notice Blacklisted addresses (compliance).
    mapping(address => bool) public blacklisted;

    /// @notice XOR-based accumulator of keccak256(address, shares) for every
    ///         staker with a non-zero balance.  Updated incrementally on every
    ///         share-changing operation (mint, burn, transfer).
    ///
    /// @dev The accumulator proves the exact per-staker share distribution at
    ///      any point in time.  Cruzible reads this value at snapshot-commit
    ///      time and verifies it against the TEE attestation, eliminating admin
    ///      discretion over reward-recipient selection.
    bytes32 public stakerRegistryRoot;

    // =========================================================================
    // EVENTS
    // =========================================================================

    event SharesMinted(address indexed to, uint256 shares, uint256 aethelAmount);
    event SharesBurned(address indexed from, uint256 shares, uint256 aethelAmount);
    event TotalPooledAethelUpdated(uint256 oldAmount, uint256 newAmount);
    event AddressBlacklisted(address indexed account, bool status);

    // =========================================================================
    // ERRORS
    // =========================================================================

    error ZeroAddress();
    error ZeroAmount();
    error InsufficientShares(uint256 requested, uint256 available);
    error ExceedsMaxShares();
    error AccountBlacklisted(address account);
    error SharesMintingFailed();

    // =========================================================================
    // MODIFIERS
    // =========================================================================

    modifier notBlacklisted(address account) {
        if (blacklisted[account]) revert AccountBlacklisted(account);
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
     * @notice Initialize the stAETHEL token.
     * @param admin Admin address (multisig/contract on mainnet).
     * @param vaultAddress The Cruzible contract.
     */
    function initialize(address admin, address vaultAddress) external initializer {
        if (admin == address(0)) revert ZeroAddress();
        if (vaultAddress == address(0)) revert ZeroAddress();

        __ERC20_init("Staked Aethelred", "stAETHEL");
        __ERC20Burnable_init();
        __ERC20Pausable_init();
        __ERC20Permit_init("Staked Aethelred");
        __AccessControl_init();
        __UUPSUpgradeable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);
        _grantRole(VAULT_ROLE, vaultAddress);

        vault = vaultAddress;
    }

    // =========================================================================
    // SHARE-BASED ERC20 OVERRIDES
    // =========================================================================

    /**
     * @notice Returns the amount of tokens owned by `account`.
     * @dev Calculated from the share balance and current exchange rate.
     *      balanceOf(account) = shares[account] * totalPooledAethel / totalShares
     */
    function balanceOf(address account) public view override returns (uint256) {
        return getAethelByShares(_shares[account]);
    }

    /**
     * @notice Returns the total supply of stAETHEL (in AETHEL-equivalent terms).
     */
    function totalSupply() public view override returns (uint256) {
        return totalPooledAethel;
    }

    /**
     * @notice Transfer stAETHEL tokens.
     * @dev Internally transfers shares proportional to the AETHEL amount.
     */
    function transfer(address to, uint256 amount)
        public
        override
        notBlacklisted(msg.sender)
        notBlacklisted(to)
        whenNotPaused
        returns (bool)
    {
        uint256 sharesToTransfer = getSharesByAethel(amount);
        if (sharesToTransfer == 0) revert ZeroAmount();
        if (_shares[msg.sender] < sharesToTransfer) {
            revert InsufficientShares(sharesToTransfer, _shares[msg.sender]);
        }

        uint256 oldSharesSender = _shares[msg.sender];
        uint256 oldSharesRecipient = _shares[to];
        _shares[msg.sender] -= sharesToTransfer;
        _shares[to] += sharesToTransfer;
        _touchAccumulator(msg.sender, oldSharesSender, _shares[msg.sender]);
        _touchAccumulator(to, oldSharesRecipient, _shares[to]);

        emit Transfer(msg.sender, to, amount);
        return true;
    }

    /**
     * @notice Transfer stAETHEL from one account to another.
     */
    function transferFrom(address from, address to, uint256 amount)
        public
        override
        notBlacklisted(from)
        notBlacklisted(to)
        notBlacklisted(msg.sender)
        whenNotPaused
        returns (bool)
    {
        _spendAllowance(from, msg.sender, amount);

        uint256 sharesToTransfer = getSharesByAethel(amount);
        if (sharesToTransfer == 0) revert ZeroAmount();
        if (_shares[from] < sharesToTransfer) {
            revert InsufficientShares(sharesToTransfer, _shares[from]);
        }

        uint256 oldSharesSender = _shares[from];
        uint256 oldSharesRecipient = _shares[to];
        _shares[from] -= sharesToTransfer;
        _shares[to] += sharesToTransfer;
        _touchAccumulator(from, oldSharesSender, _shares[from]);
        _touchAccumulator(to, oldSharesRecipient, _shares[to]);

        emit Transfer(from, to, amount);
        return true;
    }

    // =========================================================================
    // VAULT-ONLY OPERATIONS
    // =========================================================================

    /**
     * @notice Mint new stAETHEL shares (called by vault on stake).
     * @param to Recipient of the shares.
     * @param sharesAmount Number of shares to mint.
     * @return aethelAmount The AETHEL-equivalent value of minted shares.
     */
    function mintShares(address to, uint256 sharesAmount)
        external
        onlyRole(VAULT_ROLE)
        notBlacklisted(to)
        returns (uint256 aethelAmount)
    {
        if (to == address(0)) revert ZeroAddress();
        if (sharesAmount == 0) revert ZeroAmount();
        if (_totalShares + sharesAmount > MAX_TOTAL_SHARES) revert ExceedsMaxShares();

        uint256 oldShares = _shares[to];
        _totalShares += sharesAmount;
        _shares[to] += sharesAmount;
        _touchAccumulator(to, oldShares, _shares[to]);

        aethelAmount = getAethelByShares(sharesAmount);
        emit SharesMinted(to, sharesAmount, aethelAmount);
        emit Transfer(address(0), to, aethelAmount);
    }

    /**
     * @notice Burn stAETHEL shares (called by vault on unstake).
     * @param from Account whose shares are burned.
     * @param sharesAmount Number of shares to burn.
     * @return aethelAmount The AETHEL-equivalent value of burned shares.
     */
    function burnShares(address from, uint256 sharesAmount)
        external
        onlyRole(VAULT_ROLE)
        returns (uint256 aethelAmount)
    {
        if (from == address(0)) revert ZeroAddress();
        if (sharesAmount == 0) revert ZeroAmount();
        if (_shares[from] < sharesAmount) {
            revert InsufficientShares(sharesAmount, _shares[from]);
        }

        uint256 oldShares = _shares[from];
        aethelAmount = getAethelByShares(sharesAmount);
        _totalShares -= sharesAmount;
        _shares[from] -= sharesAmount;
        _touchAccumulator(from, oldShares, _shares[from]);

        emit SharesBurned(from, sharesAmount, aethelAmount);
        emit Transfer(from, address(0), aethelAmount);
    }

    /**
     * @notice Update the total pooled AETHEL (called by vault on reward distribution).
     * @param newTotalPooled The new total pooled AETHEL amount.
     */
    function setTotalPooledAethel(uint256 newTotalPooled)
        external
        onlyRole(VAULT_ROLE)
    {
        uint256 oldAmount = totalPooledAethel;
        totalPooledAethel = newTotalPooled;
        emit TotalPooledAethelUpdated(oldAmount, newTotalPooled);
    }

    // =========================================================================
    // SHARE CONVERSION FUNCTIONS
    // =========================================================================

    /**
     * @notice Get the number of shares for a given AETHEL amount.
     * @dev shares = aethelAmount * totalShares / totalPooledAethel
     */
    function getSharesByAethel(uint256 aethelAmount) public view returns (uint256) {
        if (totalPooledAethel == 0) return aethelAmount; // 1:1 initial rate
        return (aethelAmount * _totalShares) / totalPooledAethel;
    }

    /**
     * @notice Get the AETHEL amount for a given number of shares.
     * @dev aethelAmount = shares * totalPooledAethel / totalShares
     */
    function getAethelByShares(uint256 sharesAmount) public view returns (uint256) {
        if (_totalShares == 0) return 0;
        return (sharesAmount * totalPooledAethel) / _totalShares;
    }

    /**
     * @notice Get the share balance of an account.
     */
    function sharesOf(address account) external view returns (uint256) {
        return _shares[account];
    }

    /**
     * @notice Get total shares outstanding.
     */
    function getTotalShares() external view returns (uint256) {
        return _totalShares;
    }

    /**
     * @notice Get the current exchange rate (AETHEL per stAETHEL share, scaled 1e18).
     */
    function getExchangeRate() external view returns (uint256) {
        if (_totalShares == 0) return 1e18;
        return (totalPooledAethel * 1e18) / _totalShares;
    }

    // =========================================================================
    // COMPLIANCE
    // =========================================================================

    function setBlacklisted(address account, bool status)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        blacklisted[account] = status;
        emit AddressBlacklisted(account, status);
    }

    // =========================================================================
    // ADMIN FUNCTIONS
    // =========================================================================

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    function version() external pure returns (string memory) {
        return "1.0.0";
    }

    // =========================================================================
    // REQUIRED OVERRIDES
    // =========================================================================

    function _update(address from, address to, uint256 value)
        internal
        override(ERC20Upgradeable, ERC20PausableUpgradeable)
    {
        super._update(from, to, value);
    }

    function _authorizeUpgrade(address newImplementation)
        internal
        override
        onlyRole(UPGRADER_ROLE)
    {}

    // =========================================================================
    // INTERNAL — STAKER REGISTRY ACCUMULATOR
    // =========================================================================

    /**
     * @notice Update the XOR accumulator when a staker's share balance changes.
     * @dev XOR is self-inverse: XOR-ing the old entry removes it, XOR-ing the
     *      new entry adds it.  Zero-share entries are excluded so the
     *      accumulator represents exactly the set of stakers with positive
     *      balances.  Gas cost: two keccak256 calls (~90 gas total).
     */
    function _touchAccumulator(address account, uint256 oldShares, uint256 newShares) internal {
        if (oldShares != 0) {
            stakerRegistryRoot ^= keccak256(abi.encodePacked(account, oldShares));
        }
        if (newShares != 0) {
            stakerRegistryRoot ^= keccak256(abi.encodePacked(account, newShares));
        }
    }

    // =========================================================================
    // STORAGE GAP
    // =========================================================================

    /// @dev Reduced from 50 to 49 to accommodate stakerRegistryRoot.
    uint256[49] private __gap;
}
