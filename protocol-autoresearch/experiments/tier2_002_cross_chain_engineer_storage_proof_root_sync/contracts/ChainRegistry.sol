// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ChainRegistry
/// @notice Registry mapping chainId -> RootRelay address and chainId -> L1 block oracle.
///         Allows governance to add new chains without redeploying core contracts.
contract ChainRegistry {
    // ──────────────────────── Events ────────────────────────
    event ChainRegistered(
        uint256 indexed chainId,
        address rootRelay,
        address l1Oracle
    );
    event ChainRemoved(uint256 indexed chainId);

    // ──────────────────────── Errors ────────────────────────
    error Unauthorized();
    error ZeroAddress();
    error ChainNotRegistered();

    // ──────────────────────── Structs ────────────────────────
    struct ChainConfig {
        address rootRelay;
        address l1Oracle;
        bool active;
    }

    // ──────────────────────── State ────────────────────────
    address public owner;
    mapping(uint256 => ChainConfig) public chains;
    uint256[] public registeredChainIds;

    // ──────────────────────── Constructor ────────────────────────
    constructor(address _owner) {
        if (_owner == address(0)) revert ZeroAddress();
        owner = _owner;
    }

    // ──────────────────────── Modifiers ────────────────────────
    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    // ──────────────────────── Functions ────────────────────────

    /// @notice Register or update a chain's RootRelay and L1 oracle addresses.
    function registerChain(
        uint256 chainId,
        address rootRelay,
        address l1Oracle
    ) external onlyOwner {
        if (rootRelay == address(0)) revert ZeroAddress();
        if (l1Oracle == address(0)) revert ZeroAddress();

        if (!chains[chainId].active) {
            registeredChainIds.push(chainId);
        }

        chains[chainId] = ChainConfig({
            rootRelay: rootRelay,
            l1Oracle: l1Oracle,
            active: true
        });

        emit ChainRegistered(chainId, rootRelay, l1Oracle);
    }

    /// @notice Deactivate a chain.
    function removeChain(uint256 chainId) external onlyOwner {
        if (!chains[chainId].active) revert ChainNotRegistered();
        chains[chainId].active = false;
        emit ChainRemoved(chainId);
    }

    /// @notice Get the RootRelay address for a chain.
    function getRootRelay(uint256 chainId) external view returns (address) {
        ChainConfig memory config = chains[chainId];
        if (!config.active) revert ChainNotRegistered();
        return config.rootRelay;
    }

    /// @notice Get the L1 oracle address for a chain.
    function getL1Oracle(uint256 chainId) external view returns (address) {
        ChainConfig memory config = chains[chainId];
        if (!config.active) revert ChainNotRegistered();
        return config.l1Oracle;
    }

    /// @notice Get all registered chain IDs.
    function getRegisteredChains() external view returns (uint256[] memory) {
        return registeredChainIds;
    }

    /// @notice Transfer ownership.
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        owner = newOwner;
    }
}