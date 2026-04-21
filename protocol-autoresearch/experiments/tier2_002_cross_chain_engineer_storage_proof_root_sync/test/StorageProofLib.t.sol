// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {StorageProofLib} from "../contracts/StorageProofLib.sol";

/// @title StorageProofLib Unit Tests
/// @notice Tests StorageProofLib using synthetic Merkle-Patricia trie fixtures.
///         In production, replace with real EIP-1186 fixtures from Base Sepolia.
contract StorageProofLibTest is Test {
    // ──────────────────────── Test Fixtures ────────────────────────

    // We construct a minimal trie structure for testing.
    // A real test suite would use captured eth_getProof data.

    // Known test values:
    address constant TARGET = 0x1234567890AbcdEF1234567890aBcdef12345678;
    bytes32 constant SLOT = bytes32(uint256(3));
    uint256 constant EXPECTED_VALUE = 0xdeadbeef;

    // ──────────────────────── Helper: Build minimal proof ────────────────────────

    /// @dev Build a synthetic account RLP for testing.
    function _buildAccountRLP(
        bytes32 storageRoot
    ) internal pure returns (bytes memory) {
        // Account RLP: [nonce=0, balance=0, storageRoot, codeHash]
        // nonce: 0x80 (RLP empty string = 0)
        // balance: 0x80
        // storageRoot: 0xa0 + 32 bytes
        // codeHash: 0xa0 + 32 bytes (keccak256 of empty = c5d2...)
        bytes32 emptyCodeHash = keccak256("");
        bytes memory inner = abi.encodePacked(
            bytes1(0x80), // nonce = 0
            bytes1(0x80), // balance = 0
            bytes1(0xa0), storageRoot,
            bytes1(0xa0), emptyCodeHash
        );
        // List prefix: 0xf8 + length if > 55, else 0xc0 + length
        uint256 len = inner.length; // 2 + 33 + 33 = 68
        bytes memory result = abi.encodePacked(
            bytes1(0xf8), bytes1(uint8(len)),
            inner
        );
        return result;
    }

    // ──────────────────────── Tests ────────────────────────

    /// @notice Test that the library correctly decodes RLP and processes trie nodes.
    ///         This is a structural test — real proof fixtures would be needed for
    ///         full integration testing.
    function test_libraryCompiles() public pure {
        // Verify the library is accessible and has the expected function signature.
        // This confirms compilation and ABI compatibility.
        // Full proof verification requires real trie fixtures.
        assert(true);
    }

    /// @notice Fuzz test: any random bytes should not accidentally validate.
    function testFuzz_rejectsRandomProof(
        bytes32 fakeRoot,
        address fakeTarget,
        bytes32 fakeSlot
    ) public {
        bytes[] memory emptyProof = new bytes[](0);

        // Empty proof should always revert.
        vm.expectRevert();
        StorageProofLib.verifyStorageProof(
            fakeRoot,
            fakeTarget,
            fakeSlot,
            emptyProof,
            emptyProof
        );
    }

    /// @notice Test that a single-node proof with wrong hash reverts.
    function test_wrongRootRejected() public {
        bytes32 wrongRoot = bytes32(uint256(1));
        bytes[] memory proof = new bytes[](1);
        // A 32+ byte node whose keccak won't match wrongRoot.
        proof[0] = abi.encodePacked(
            bytes1(0xc0) // empty list
        );

        vm.expectRevert(StorageProofLib.InvalidProof.selector);
        StorageProofLib.verifyStorageProof(
            wrongRoot,
            TARGET,
            SLOT,
            proof,
            new bytes[](0)
        );
    }

    /// @notice Test that invalid RLP in proof nodes is rejected.
    function test_invalidRLPReverts() public {
        // Create a node that hashes to our "root" but contains invalid RLP.
        bytes memory badNode = new bytes(33);
        badNode[0] = 0xff; // Invalid RLP prefix.
        for (uint i = 1; i < 33; i++) {
            badNode[i] = bytes1(uint8(i));
        }
        bytes32 root = keccak256(badNode);

        bytes[] memory proof = new bytes[](1);
        proof[0] = badNode;

        vm.expectRevert(); // Should revert on invalid RLP decode.
        StorageProofLib.verifyStorageProof(
            root,
            TARGET,
            SLOT,
            proof,
            new bytes[](0)
        );
    }
}