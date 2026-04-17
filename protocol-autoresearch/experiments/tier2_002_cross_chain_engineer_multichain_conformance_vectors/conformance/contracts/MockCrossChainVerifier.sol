// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title MockCrossChainVerifier
 * @notice Reference implementation for running Bolyra cross-chain conformance vectors.
 *         Implements five independently toggleable invariant checks:
 *         1. Chain ID binding
 *         2. Root age TTL
 *         3. Storage proof block hash verification
 *         4. Batch Merkle inclusion
 *         5. Scoped nullifier set
 *
 * @dev This is a MOCK verifier for conformance testing. It does not perform
 *      actual ZK proof verification (Groth16/Plonk). Instead, it validates
 *      the structural invariants that any cross-chain verifier must enforce.
 */
contract MockCrossChainVerifier {
    // ── Errors ───────────────────────────────────────────────────────────
    error ChainIdUnbound();
    error ChainIdMismatch(uint64 expected, uint64 got);
    error RootExpired(uint256 age, uint256 maxAge);
    error InvalidBlockHash(bytes32 blockHash);
    error BlockHashChainMismatch(uint64 declaredChain, uint64 actualChain);
    error BatchInvalidLeaf();
    error BatchRootMismatch(bytes32 expected, bytes32 computed);
    error NullifierAlreadyUsed(bytes32 nullifier);
    error NullifierCrossChainReplay(bytes32 nullifier, uint64 originalChain);
    error RelayTimestampFuture(uint256 relayTs, uint256 blockTs);
    error RelayTimestampMissing();

    // ── Events ───────────────────────────────────────────────────────────
    event ProofVerified(bytes32 indexed nullifier, uint64 chainId);
    event InvariantToggled(string name, bool enabled);

    // ── State ────────────────────────────────────────────────────────────
    address public owner;
    uint64 public immutable selfChainId;
    uint256 public maxRootAge;
    uint256 public futureTolerance;

    // Toggleable invariant checks
    bool public checkChainId = true;
    bool public checkRootAge = true;
    bool public checkStorageProof = true;
    bool public checkBatchInclusion = true;
    bool public checkNullifier = true;

    // Known valid block hashes per chain
    mapping(uint64 => mapping(bytes32 => bool)) public validBlockHashes;

    // Registered batch roots
    mapping(bytes32 => bool) public batchRoots;

    // Nullifier sets: global and chain-scoped
    mapping(bytes32 => bool) public globalNullifiers;
    mapping(uint64 => mapping(bytes32 => bool)) public chainNullifiers;
    mapping(bytes32 => uint64) public nullifierOriginChain;

    // Relayed Merkle roots with timestamps
    mapping(bytes32 => uint256) public rootTimestamps;

    // ── Constructor ──────────────────────────────────────────────────────
    constructor(uint64 _chainId, uint256 _maxRootAge, uint256 _futureTolerance) {
        owner = msg.sender;
        selfChainId = _chainId;
        maxRootAge = _maxRootAge;
        futureTolerance = _futureTolerance;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    // ── Admin Functions ──────────────────────────────────────────────────

    function toggleInvariant(string calldata name, bool enabled) external onlyOwner {
        bytes32 h = keccak256(bytes(name));
        if (h == keccak256("chainId")) checkChainId = enabled;
        else if (h == keccak256("rootAge")) checkRootAge = enabled;
        else if (h == keccak256("storageProof")) checkStorageProof = enabled;
        else if (h == keccak256("batchInclusion")) checkBatchInclusion = enabled;
        else if (h == keccak256("nullifier")) checkNullifier = enabled;
        else revert("unknown invariant");
        emit InvariantToggled(name, enabled);
    }

    function registerBlockHash(uint64 chainId, bytes32 blockHash) external onlyOwner {
        validBlockHashes[chainId][blockHash] = true;
    }

    function registerBatchRoot(bytes32 root) external onlyOwner {
        batchRoots[root] = true;
    }

    function relayRoot(bytes32 root, uint256 timestamp) external onlyOwner {
        rootTimestamps[root] = timestamp;
    }

    function setMaxRootAge(uint256 _maxRootAge) external onlyOwner {
        maxRootAge = _maxRootAge;
    }

    // ── Core Verification ────────────────────────────────────────────────

    struct VerifyParams {
        bytes proof;
        uint256[] publicInputs;
        uint64 sourceChainId;
        uint64 targetChainId;
        uint256 relayTimestamp;
        bool relayTimestampPresent;
        // Storage proof fields (optional)
        bytes32 storageBlockHash;
        bool hasStorageProof;
        // Batch checkpoint fields (optional)
        bytes32 batchRoot;
        bytes32 batchLeaf;
        uint256 batchLeafIndex;
        bytes32[] batchProofPath;
        bool hasBatchCheckpoint;
        // Nullifier fields (optional)
        bytes32 nullifierHash;
        bool isGlobalScope;
        bool hasNullifier;
    }

    /**
     * @notice Verify a cross-chain identity proof against all enabled invariants.
     * @param p The verification parameters struct.
     * @return success True if all checks pass.
     */
    function verify(VerifyParams calldata p) external returns (bool success) {
        // 1. Relay timestamp presence check
        if (!p.relayTimestampPresent) {
            revert RelayTimestampMissing();
        }

        // 2. Relay timestamp future check
        if (p.relayTimestamp > block.timestamp + futureTolerance) {
            revert RelayTimestampFuture(p.relayTimestamp, block.timestamp);
        }

        // 3. Chain ID binding
        if (checkChainId) {
            _checkChainIdBinding(p.publicInputs, p.targetChainId);
        }

        // 4. Root age / staleness
        if (checkRootAge) {
            _checkRootAge(p.relayTimestamp);
        }

        // 5. Storage proof block hash
        if (checkStorageProof && p.hasStorageProof) {
            _checkStorageProof(p.storageBlockHash, p.sourceChainId);
        }

        // 6. Batch checkpoint inclusion
        if (checkBatchInclusion && p.hasBatchCheckpoint) {
            _checkBatchInclusion(
                p.batchRoot, p.batchLeaf, p.batchLeafIndex, p.batchProofPath
            );
        }

        // 7. Nullifier replay
        if (checkNullifier && p.hasNullifier) {
            _checkNullifier(
                p.nullifierHash, p.isGlobalScope, p.sourceChainId, p.targetChainId
            );
        }

        // NOTE: Actual ZK proof verification (pairing check) is omitted.
        // In production, call the Groth16/Plonk verifier here.

        emit ProofVerified(p.nullifierHash, p.targetChainId);
        return true;
    }

    // ── Internal Invariant Checks ────────────────────────────────────────

    function _checkChainIdBinding(
        uint256[] calldata publicInputs,
        uint64 targetChainId
    ) internal pure {
        // Convention: publicInputs[2] is the chain ID commitment
        if (publicInputs.length < 3) {
            revert ChainIdUnbound();
        }
        uint256 committedChainId = publicInputs[2];
        if (committedChainId == 0) {
            revert ChainIdUnbound();
        }
        if (uint64(committedChainId) != targetChainId) {
            revert ChainIdMismatch(targetChainId, uint64(committedChainId));
        }
    }

    function _checkRootAge(uint256 relayTimestamp) internal view {
        uint256 age = block.timestamp - relayTimestamp;
        if (age > maxRootAge) {
            revert RootExpired(age, maxRootAge);
        }
    }

    function _checkStorageProof(
        bytes32 blockHash,
        uint64 sourceChainId
    ) internal view {
        // Check that the block hash is registered for the declared source chain
        if (!validBlockHashes[sourceChainId][blockHash]) {
            // Distinguish between invalid hash and wrong-chain hash
            // Check if hash exists on any other chain
            // (simplified: in production, iterate known chains or use a reverse map)
            if (_blockHashExistsOnAnyChain(blockHash, sourceChainId)) {
                revert BlockHashChainMismatch(sourceChainId, _findBlockHashChain(blockHash));
            }
            revert InvalidBlockHash(blockHash);
        }
    }

    function _checkBatchInclusion(
        bytes32 batchRoot,
        bytes32 leaf,
        uint256 leafIndex,
        bytes32[] calldata proofPath
    ) internal view {
        // Verify the Merkle inclusion proof
        bytes32 computedHash = leaf;
        uint256 index = leafIndex;

        for (uint256 i = 0; i < proofPath.length; i++) {
            if (index % 2 == 0) {
                computedHash = keccak256(abi.encodePacked(computedHash, proofPath[i]));
            } else {
                computedHash = keccak256(abi.encodePacked(proofPath[i], computedHash));
            }
            index = index / 2;
        }

        // Check if the batch root is registered
        if (!batchRoots[batchRoot]) {
            revert BatchRootMismatch(batchRoot, computedHash);
        }

        // Check if the computed root matches
        if (computedHash != batchRoot) {
            revert BatchInvalidLeaf();
        }
    }

    function _checkNullifier(
        bytes32 nullifierHash,
        bool isGlobalScope,
        uint64 sourceChainId,
        uint64 targetChainId
    ) internal {
        if (isGlobalScope) {
            // Global scope: check cross-chain nullifier set
            if (globalNullifiers[nullifierHash]) {
                uint64 originChain = nullifierOriginChain[nullifierHash];
                if (originChain == targetChainId) {
                    revert NullifierAlreadyUsed(nullifierHash);
                } else {
                    revert NullifierCrossChainReplay(nullifierHash, originChain);
                }
            }
            globalNullifiers[nullifierHash] = true;
            nullifierOriginChain[nullifierHash] = targetChainId;
        } else {
            // Chain-scoped: each chain has independent nullifier set
            if (chainNullifiers[targetChainId][nullifierHash]) {
                revert NullifierAlreadyUsed(nullifierHash);
            }
            chainNullifiers[targetChainId][nullifierHash] = true;
        }
    }

    // ── Helper Functions ─────────────────────────────────────────────────

    // Known chain IDs for block hash lookups (simplified for mock)
    uint64[] private knownChains;

    function addKnownChain(uint64 chainId) external onlyOwner {
        knownChains.push(chainId);
    }

    function _blockHashExistsOnAnyChain(
        bytes32 blockHash,
        uint64 excludeChain
    ) internal view returns (bool) {
        for (uint256 i = 0; i < knownChains.length; i++) {
            if (knownChains[i] != excludeChain && validBlockHashes[knownChains[i]][blockHash]) {
                return true;
            }
        }
        return false;
    }

    function _findBlockHashChain(
        bytes32 blockHash
    ) internal view returns (uint64) {
        for (uint256 i = 0; i < knownChains.length; i++) {
            if (validBlockHashes[knownChains[i]][blockHash]) {
                return knownChains[i];
            }
        }
        return 0;
    }
}
