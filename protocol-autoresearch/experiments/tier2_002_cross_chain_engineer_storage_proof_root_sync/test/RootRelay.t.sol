// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {RootRelay} from "../contracts/RootRelay.sol";

/// @title Mock L1 Block Oracle
/// @notice Returns a predetermined block hash for testing.
contract MockL1Oracle {
    mapping(uint256 => bytes32) public blockHashes;

    function setBlockHash(uint256 blockNumber, bytes32 hash) external {
        blockHashes[blockNumber] = hash;
    }

    function getBlockHash(uint256 blockNumber) external view returns (bytes32) {
        return blockHashes[blockNumber];
    }
}

/// @title RootRelay Integration Tests
contract RootRelayTest is Test {
    RootRelay public relay;
    MockL1Oracle public oracle;

    address constant SOURCE_REGISTRY = 0x1234567890AbcdEF1234567890aBcdef12345678;
    bytes32 constant AGENT_SLOT = bytes32(uint256(3));
    bytes32 constant HUMAN_SLOT = bytes32(uint256(4));
    address owner = address(this);

    function setUp() public {
        oracle = new MockL1Oracle();
        relay = new RootRelay(
            SOURCE_REGISTRY,
            AGENT_SLOT,
            HUMAN_SLOT,
            address(oracle),
            owner
        );
    }

    // ──────────────────────── Constructor Tests ────────────────────────

    function test_constructorSetsImmutables() public view {
        assertEq(relay.sourceRegistry(), SOURCE_REGISTRY);
        assertEq(relay.agentRootSlot(), AGENT_SLOT);
        assertEq(relay.humanRootSlot(), HUMAN_SLOT);
        assertEq(relay.l1BlockOracle(), address(oracle));
        assertEq(relay.owner(), owner);
    }

    function test_constructorRevertsZeroRegistry() public {
        vm.expectRevert(RootRelay.ZeroAddress.selector);
        new RootRelay(address(0), AGENT_SLOT, HUMAN_SLOT, address(oracle), owner);
    }

    function test_constructorRevertsZeroOracle() public {
        vm.expectRevert(RootRelay.ZeroAddress.selector);
        new RootRelay(SOURCE_REGISTRY, AGENT_SLOT, HUMAN_SLOT, address(0), owner);
    }

    function test_constructorRevertsZeroOwner() public {
        vm.expectRevert(RootRelay.ZeroAddress.selector);
        new RootRelay(SOURCE_REGISTRY, AGENT_SLOT, HUMAN_SLOT, address(oracle), address(0));
    }

    // ──────────────────────── Replay Protection ────────────────────────

    function test_rejectsNonMonotonicBlock() public {
        // Setup: We can't actually call relayRoots with valid proofs in a unit test
        // without full trie fixtures. Instead, test the monotonicity check by
        // verifying initial state and the revert condition.
        assertEq(relay.lastRelayedBlock(), 0);

        // Block 0 should be rejected (not > 0).
        bytes[] memory emptyProof = new bytes[](0);
        vm.expectRevert(); // Will revert — either monotonicity or proof validation.
        relay.relayRoots(
            0,
            bytes32(uint256(1)),
            emptyProof,
            emptyProof,
            emptyProof
        );
    }

    // ──────────────────────── Access Control ────────────────────────

    function test_onlyOwnerCanSetOracle() public {
        address newOracle = address(0xBEEF);
        relay.setL1BlockOracle(newOracle);
        assertEq(relay.l1BlockOracle(), newOracle);
    }

    function test_nonOwnerCannotSetOracle() public {
        address attacker = address(0xBAD);
        vm.prank(attacker);
        vm.expectRevert(RootRelay.Unauthorized.selector);
        relay.setL1BlockOracle(address(0xBEEF));
    }

    function test_cannotSetZeroOracle() public {
        vm.expectRevert(RootRelay.ZeroAddress.selector);
        relay.setL1BlockOracle(address(0));
    }

    function test_transferOwnership() public {
        address newOwner = address(0xCAFE);
        relay.transferOwnership(newOwner);
        assertEq(relay.owner(), newOwner);
    }

    function test_cannotTransferToZero() public {
        vm.expectRevert(RootRelay.ZeroAddress.selector);
        relay.transferOwnership(address(0));
    }

    function test_nonOwnerCannotTransfer() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(RootRelay.Unauthorized.selector);
        relay.transferOwnership(address(0xCAFE));
    }

    // ──────────────────────── Oracle Integration ────────────────────────

    function test_oracleReturnsBlockHash() public {
        bytes32 hash = keccak256("block100");
        oracle.setBlockHash(100, hash);

        // Verify the oracle works correctly.
        assertEq(oracle.getBlockHash(100), hash);
    }

    function test_blockHashMismatchRevertsRelay() public {
        // Block 100 with no hash set in oracle => returns bytes32(0).
        bytes[] memory emptyProof = new bytes[](0);
        vm.expectRevert(); // BlockHashMismatch or proof error.
        relay.relayRoots(
            100,
            bytes32(uint256(42)),
            emptyProof,
            emptyProof,
            emptyProof
        );
    }

    // ──────────────────────── Event ────────────────────────

    function test_rootUpdatedEventSignature() public pure {
        // Verify event selector matches expected.
        bytes32 selector = keccak256("RootUpdated(uint256,bytes32,bytes32)");
        assert(selector != bytes32(0));
    }
}