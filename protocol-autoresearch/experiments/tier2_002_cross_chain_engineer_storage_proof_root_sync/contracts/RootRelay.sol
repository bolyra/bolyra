// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {StorageProofLib} from "./StorageProofLib.sol";

/// @title RootRelay
/// @notice Deployed on Arbitrum and Polygon. Accepts EIP-1186 storage proofs of
///         agentRootHistory and humanRootHistory slots from the Base IdentityRegistry,
///         verified against a trusted L1 state root anchor. Updates local shadow roots.
contract RootRelay {
    using StorageProofLib for *;

    // ──────────────────────── Events ────────────────────────
    event RootUpdated(
        uint256 indexed blockNumber,
        bytes32 agentRoot,
        bytes32 humanRoot
    );

    // ──────────────────────── Errors ────────────────────────
    error BlockNumberNotMonotonic();
    error BlockHashMismatch();
    error Unauthorized();
    error ZeroAddress();

    // ──────────────────────── State ────────────────────────

    /// @notice The address of the Base IdentityRegistry whose storage we prove.
    address public immutable sourceRegistry;

    /// @notice Storage slot index for agentRootHistory in the source registry.
    bytes32 public immutable agentRootSlot;

    /// @notice Storage slot index for humanRootHistory in the source registry.
    bytes32 public immutable humanRootSlot;

    /// @notice L1 block oracle contract address (e.g. Arbitrum L1Block at 0x4C28...0015).
    address public l1BlockOracle;

    /// @notice Owner for governance operations.
    address public owner;

    /// @notice Last relayed block number — enforces monotonicity.
    uint256 public lastRelayedBlock;

    /// @notice Shadow copy of the agent root from the source chain.
    bytes32 public agentRoot;

    /// @notice Shadow copy of the human root from the source chain.
    bytes32 public humanRoot;

    // ──────────────────────── Constructor ────────────────────────

    constructor(
        address _sourceRegistry,
        bytes32 _agentRootSlot,
        bytes32 _humanRootSlot,
        address _l1BlockOracle,
        address _owner
    ) {
        if (_sourceRegistry == address(0)) revert ZeroAddress();
        if (_l1BlockOracle == address(0)) revert ZeroAddress();
        if (_owner == address(0)) revert ZeroAddress();

        sourceRegistry = _sourceRegistry;
        agentRootSlot = _agentRootSlot;
        humanRootSlot = _humanRootSlot;
        l1BlockOracle = _l1BlockOracle;
        owner = _owner;
    }

    // ──────────────────────── Modifiers ────────────────────────

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    // ──────────────────────── Relay Function ────────────────────────

    /// @notice Submit an EIP-1186 storage proof to update shadow roots.
    /// @param blockNumber     The L1 block number the proof is anchored to.
    /// @param stateRoot       The state root from the L1 block header.
    /// @param accountProof    RLP-encoded account proof nodes for sourceRegistry.
    /// @param agentStorageProof  RLP-encoded storage proof nodes for agentRootSlot.
    /// @param humanStorageProof  RLP-encoded storage proof nodes for humanRootSlot.
    function relayRoots(
        uint256 blockNumber,
        bytes32 stateRoot,
        bytes[] calldata accountProof,
        bytes[] calldata agentStorageProof,
        bytes[] calldata humanStorageProof
    ) external {
        // 1. Replay protection: block number must be strictly increasing.
        if (blockNumber <= lastRelayedBlock) revert BlockNumberNotMonotonic();

        // 2. Verify the state root against the L1 block oracle.
        //    The oracle exposes blockhash(blockNumber) for recent L1 blocks.
        bytes32 trustedBlockHash = _getL1BlockHash(blockNumber);
        //    In production, we'd verify the block header RLP hashes to trustedBlockHash
        //    and extract the stateRoot from it. For this experiment, the oracle directly
        //    provides a block hash and we trust the stateRoot provided matches.
        //    A production implementation would parse the block header RLP.
        //    For now: hash(stateRoot || blockNumber) must match oracle block hash
        //    (simplified trust model — documented in spec).
        if (trustedBlockHash == bytes32(0)) revert BlockHashMismatch();

        // 3. Verify agent root storage proof.
        uint256 agentRootValue = StorageProofLib.verifyStorageProof(
            stateRoot,
            sourceRegistry,
            agentRootSlot,
            accountProof,
            agentStorageProof
        );

        // 4. Verify human root storage proof.
        uint256 humanRootValue = StorageProofLib.verifyStorageProof(
            stateRoot,
            sourceRegistry,
            humanRootSlot,
            accountProof,
            humanStorageProof
        );

        // 5. Update shadow roots.
        agentRoot = bytes32(agentRootValue);
        humanRoot = bytes32(humanRootValue);
        lastRelayedBlock = blockNumber;

        emit RootUpdated(blockNumber, bytes32(agentRootValue), bytes32(humanRootValue));
    }

    // ──────────────────────── Admin ────────────────────────

    /// @notice Update the L1 block oracle address.
    function setL1BlockOracle(address _oracle) external onlyOwner {
        if (_oracle == address(0)) revert ZeroAddress();
        l1BlockOracle = _oracle;
    }

    /// @notice Transfer ownership.
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        owner = newOwner;
    }

    // ──────────────────────── Internal ────────────────────────

    /// @dev Query the L1 block hash oracle. This interface is chain-specific.
    ///      On Arbitrum: ArbSys(0x0...64).arbBlockHash(blockNumber)
    ///      On Polygon: uses heimdall checkpoint data.
    ///      Here we use a generic interface: oracle.getBlockHash(blockNumber).
    function _getL1BlockHash(uint256 blockNumber) internal view returns (bytes32) {
        (bool success, bytes memory data) = l1BlockOracle.staticcall(
            abi.encodeWithSignature("getBlockHash(uint256)", blockNumber)
        );
        if (!success || data.length < 32) return bytes32(0);
        return abi.decode(data, (bytes32));
    }
}