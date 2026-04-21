// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title StorageProofLib
/// @notice Library for verifying EIP-1186 Merkle-Patricia trie proofs against a trusted state root.
/// @dev Decodes RLP-encoded account proof and storage proof, verifies the trie path,
///      and returns the storage slot value as uint256.
library StorageProofLib {
    // ──────────────────────── Errors ────────────────────────
    error InvalidProof();
    error InvalidRLPData();

    // ──────────────────────── Constants ────────────────────────
    uint256 private constant WORD_SIZE = 32;

    // ──────────────────────── Structs ────────────────────────
    struct Account {
        uint256 nonce;
        uint256 balance;
        bytes32 storageRoot;
        bytes32 codeHash;
    }

    // ──────────────────────── External Functions ────────────────────────

    /// @notice Verify an EIP-1186 account + storage proof and return the slot value.
    /// @param stateRoot     Trusted state root (from L1 block header).
    /// @param target        The address whose storage we are proving.
    /// @param slot          The storage slot index.
    /// @param accountProof  RLP-encoded list of trie nodes for the account proof.
    /// @param storageProof  RLP-encoded list of trie nodes for the storage proof.
    /// @return value        The uint256 value stored at `slot`.
    function verifyStorageProof(
        bytes32 stateRoot,
        address target,
        bytes32 slot,
        bytes[] calldata accountProof,
        bytes[] calldata storageProof
    ) internal pure returns (uint256 value) {
        // 1. Verify account proof and extract the account RLP.
        bytes memory accountPath = _addressToPath(target);
        bytes memory accountRLP = _verifyMerklePatricia(
            stateRoot,
            accountPath,
            accountProof
        );
        if (accountRLP.length == 0) revert InvalidProof();

        // 2. Decode account RLP to extract storageRoot.
        Account memory account = _decodeAccount(accountRLP);

        // 3. Verify storage proof against the storageRoot.
        bytes memory storagePath = _slotToPath(slot);
        bytes memory slotRLP = _verifyMerklePatricia(
            account.storageRoot,
            storagePath,
            storageProof
        );

        // 4. Decode the RLP-encoded uint256 value.
        if (slotRLP.length == 0) {
            return 0; // empty slot
        }
        value = _decodeUint256(slotRLP);
    }

    // ──────────────────────── Internal Helpers ────────────────────────

    /// @dev Convert an address to a nibble path for trie traversal (keccak256 of address).
    function _addressToPath(address target) private pure returns (bytes memory) {
        return _toNibbles(abi.encodePacked(keccak256(abi.encodePacked(target))));
    }

    /// @dev Convert a storage slot to a nibble path (keccak256 of slot).
    function _slotToPath(bytes32 slot) private pure returns (bytes memory) {
        return _toNibbles(abi.encodePacked(keccak256(abi.encodePacked(slot))));
    }

    /// @dev Convert bytes to nibbles (each byte -> two nibbles).
    function _toNibbles(bytes memory data) private pure returns (bytes memory nibbles) {
        nibbles = new bytes(data.length * 2);
        for (uint256 i = 0; i < data.length; i++) {
            nibbles[i * 2] = bytes1(uint8(data[i]) >> 4);
            nibbles[i * 2 + 1] = bytes1(uint8(data[i]) & 0x0f);
        }
    }

    /// @dev Verify a Merkle-Patricia trie proof.
    /// @param root       Expected root hash.
    /// @param path       Nibble-encoded path (key).
    /// @param proof      Array of RLP-encoded trie nodes.
    /// @return value     The RLP-encoded value at the leaf, or empty bytes if not found.
    function _verifyMerklePatricia(
        bytes32 root,
        bytes memory path,
        bytes[] calldata proof
    ) private pure returns (bytes memory value) {
        bytes32 expectedHash = root;
        uint256 pathOffset = 0;

        for (uint256 i = 0; i < proof.length; i++) {
            bytes memory node = proof[i];

            // Verify node hash matches expected.
            if (node.length >= 32) {
                if (keccak256(node) != expectedHash) revert InvalidProof();
            } else {
                // For nodes shorter than 32 bytes, the node itself is the hash.
                bytes32 nodeHash;
                assembly {
                    nodeHash := mload(add(node, 32))
                }
                // Shift right to align if shorter.
                if (node.length < 32) {
                    nodeHash = bytes32(uint256(nodeHash) >> (8 * (32 - node.length)));
                    nodeHash = bytes32(uint256(nodeHash) << (8 * (32 - node.length)));
                }
                if (nodeHash != expectedHash) revert InvalidProof();
            }

            // Decode the RLP list to determine node type.
            (uint256 listLen, uint256 listOffset) = _decodeRLPList(node, 0);
            uint256 itemCount = _countRLPItems(node, listOffset, listOffset + listLen);

            if (itemCount == 17) {
                // Branch node: 16 children + value.
                if (pathOffset >= path.length) {
                    // We're at the end of the path: return the 17th item (value).
                    uint256 pos = listOffset;
                    for (uint256 j = 0; j < 16; j++) {
                        pos = _skipRLPItem(node, pos);
                    }
                    return _decodeRLPBytes(node, pos);
                }
                // Follow the child at path[pathOffset].
                uint8 nibble = uint8(path[pathOffset]);
                pathOffset++;
                uint256 pos2 = listOffset;
                for (uint256 j = 0; j < nibble; j++) {
                    pos2 = _skipRLPItem(node, pos2);
                }
                bytes memory child = _decodeRLPBytes(node, pos2);
                if (child.length == 32) {
                    assembly {
                        expectedHash := mload(add(child, 32))
                    }
                } else if (child.length > 0) {
                    expectedHash = keccak256(child);
                } else {
                    return ""; // empty child => key not in trie.
                }
            } else if (itemCount == 2) {
                // Extension or leaf node.
                uint256 pos3 = listOffset;
                bytes memory encodedPath = _decodeRLPBytes(node, pos3);
                pos3 = _skipRLPItem(node, pos3);

                // Decode HP-encoded path.
                (bytes memory nodePath, bool isLeaf) = _decodeHPPath(encodedPath);

                // Check that the node path matches our remaining path.
                for (uint256 j = 0; j < nodePath.length; j++) {
                    if (pathOffset + j >= path.length) revert InvalidProof();
                    if (nodePath[j] != path[pathOffset + j]) {
                        return ""; // path diverges.
                    }
                }
                pathOffset += nodePath.length;

                if (isLeaf) {
                    // Leaf: return the value.
                    return _decodeRLPBytes(node, pos3);
                } else {
                    // Extension: follow to next node.
                    bytes memory nextNode = _decodeRLPBytes(node, pos3);
                    if (nextNode.length == 32) {
                        assembly {
                            expectedHash := mload(add(nextNode, 32))
                        }
                    } else if (nextNode.length > 0) {
                        expectedHash = keccak256(nextNode);
                    } else {
                        return "";
                    }
                }
            } else {
                revert InvalidProof();
            }
        }

        // If we exhaust all proof nodes without resolving, proof is invalid.
        revert InvalidProof();
    }

    /// @dev Decode an RLP-encoded account into its four fields.
    function _decodeAccount(bytes memory data) private pure returns (Account memory account) {
        (uint256 listLen, uint256 offset) = _decodeRLPList(data, 0);
        if (listLen == 0) revert InvalidRLPData();

        // nonce
        (account.nonce, offset) = _decodeRLPUint(data, offset);
        // balance
        (account.balance, offset) = _decodeRLPUint(data, offset);
        // storageRoot (32 bytes)
        bytes memory sr = _decodeRLPBytesAt(data, offset);
        offset = _skipRLPItemMem(data, offset);
        assembly {
            mstore(add(account, 0x40), mload(add(sr, 32)))
        }
        // codeHash (32 bytes)
        bytes memory ch = _decodeRLPBytesAt(data, offset);
        assembly {
            mstore(add(account, 0x60), mload(add(ch, 32)))
        }
    }

    /// @dev Decode hex-prefix (HP) encoded path to nibbles + leaf flag.
    function _decodeHPPath(bytes memory encoded) private pure returns (bytes memory nibbles, bool isLeaf) {
        if (encoded.length == 0) revert InvalidRLPData();
        uint8 prefix = uint8(encoded[0]);
        isLeaf = (prefix >> 4) >= 2;
        bool odd = (prefix & 0x10) != 0;

        uint256 start;
        if (odd) {
            nibbles = new bytes(encoded.length * 2 - 1);
            nibbles[0] = bytes1(prefix & 0x0f);
            start = 1;
        } else {
            nibbles = new bytes((encoded.length - 1) * 2);
            start = 0;
        }

        for (uint256 i = 1; i < encoded.length; i++) {
            uint8 b = uint8(encoded[i]);
            uint256 idx = start + (i - 1) * 2;
            if (!odd) {
                nibbles[idx] = bytes1(b >> 4);
                nibbles[idx + 1] = bytes1(b & 0x0f);
            } else {
                if (idx < nibbles.length) nibbles[idx] = bytes1(b >> 4);
                if (idx + 1 < nibbles.length) nibbles[idx + 1] = bytes1(b & 0x0f);
            }
        }
    }

    // ──────────────────────── RLP Helpers ────────────────────────

    function _decodeRLPList(bytes memory data, uint256 offset)
        private
        pure
        returns (uint256 length, uint256 newOffset)
    {
        uint8 prefix = uint8(data[offset]);
        if (prefix >= 0xf8) {
            uint256 lenLen = prefix - 0xf7;
            length = _readUint(data, offset + 1, lenLen);
            newOffset = offset + 1 + lenLen;
        } else if (prefix >= 0xc0) {
            length = prefix - 0xc0;
            newOffset = offset + 1;
        } else {
            revert InvalidRLPData();
        }
    }

    function _decodeRLPBytes(bytes memory data, uint256 offset)
        private
        pure
        returns (bytes memory result)
    {
        uint8 prefix = uint8(data[offset]);
        if (prefix < 0x80) {
            result = new bytes(1);
            result[0] = data[offset];
        } else if (prefix <= 0xb7) {
            uint256 length = prefix - 0x80;
            result = _slice(data, offset + 1, length);
        } else if (prefix <= 0xbf) {
            uint256 lenLen = prefix - 0xb7;
            uint256 length = _readUint(data, offset + 1, lenLen);
            result = _slice(data, offset + 1 + lenLen, length);
        } else {
            // It's a list — return the whole RLP-encoded list.
            uint256 totalLen;
            if (prefix >= 0xf8) {
                uint256 lenLen = prefix - 0xf7;
                uint256 listLen = _readUint(data, offset + 1, lenLen);
                totalLen = 1 + lenLen + listLen;
            } else {
                totalLen = 1 + (prefix - 0xc0);
            }
            result = _slice(data, offset, totalLen);
        }
    }

    function _decodeRLPBytesAt(bytes memory data, uint256 offset)
        private
        pure
        returns (bytes memory result)
    {
        return _decodeRLPBytes(data, offset);
    }

    function _decodeRLPUint(bytes memory data, uint256 offset)
        private
        pure
        returns (uint256 val, uint256 newOffset)
    {
        uint8 prefix = uint8(data[offset]);
        if (prefix < 0x80) {
            return (uint256(prefix), offset + 1);
        } else if (prefix <= 0xb7) {
            uint256 length = prefix - 0x80;
            if (length == 0) return (0, offset + 1);
            val = _readUint(data, offset + 1, length);
            newOffset = offset + 1 + length;
        } else {
            revert InvalidRLPData();
        }
    }

    function _skipRLPItem(bytes memory data, uint256 offset)
        private
        pure
        returns (uint256 newOffset)
    {
        uint8 prefix = uint8(data[offset]);
        if (prefix < 0x80) {
            return offset + 1;
        } else if (prefix <= 0xb7) {
            return offset + 1 + (prefix - 0x80);
        } else if (prefix <= 0xbf) {
            uint256 lenLen = prefix - 0xb7;
            uint256 length = _readUint(data, offset + 1, lenLen);
            return offset + 1 + lenLen + length;
        } else if (prefix <= 0xf7) {
            return offset + 1 + (prefix - 0xc0);
        } else {
            uint256 lenLen = prefix - 0xf7;
            uint256 length = _readUint(data, offset + 1, lenLen);
            return offset + 1 + lenLen + length;
        }
    }

    function _skipRLPItemMem(bytes memory data, uint256 offset)
        private
        pure
        returns (uint256)
    {
        return _skipRLPItem(data, offset);
    }

    function _countRLPItems(bytes memory data, uint256 start, uint256 end)
        private
        pure
        returns (uint256 count)
    {
        uint256 pos = start;
        while (pos < end) {
            pos = _skipRLPItem(data, pos);
            count++;
        }
    }

    function _decodeUint256(bytes memory rlpEncoded) private pure returns (uint256) {
        (uint256 val, ) = _decodeRLPUint(rlpEncoded, 0);
        return val;
    }

    function _readUint(bytes memory data, uint256 offset, uint256 length)
        private
        pure
        returns (uint256 result)
    {
        require(length <= 32, "RLP: uint overflow");
        for (uint256 i = 0; i < length; i++) {
            result = (result << 8) | uint256(uint8(data[offset + i]));
        }
    }

    function _slice(bytes memory data, uint256 start, uint256 length)
        private
        pure
        returns (bytes memory result)
    {
        result = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            result[i] = data[start + i];
        }
    }
}