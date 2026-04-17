// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../contracts/IdentityRegistry.sol";

/**
 * @title IdentityRegistryHumanRootBuffer
 * @notice Foundry fuzz + unit tests for the humanRootHistory ring-buffer.
 *         Covers the five scenarios from the experiment outline plus edge cases:
 *         (1) proof accepted when humanMerkleRoot matches any of 30 historical roots
 *         (2) proof rejected when root is older than buffer window (31st enrollment)
 *         (3) buffer rotation correctness at index wraparound (index 29 → 0)
 *         (4) enrollHuman emits HumanRootAdded event with correct slot
 *         (5) concurrent agent and human enrollments do not corrupt each other's buffers
 */
contract IdentityRegistryHumanRootBuffer is Test {
    IdentityRegistry registry;

    function setUp() public {
        registry = new IdentityRegistry();
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    /// @dev Enroll `count` humans with deterministic roots: root_i = i + 1
    function _enrollHumans(uint256 count) internal {
        for (uint256 i = 0; i < count; i++) {
            uint256 commitment = uint256(keccak256(abi.encodePacked("human", i)));
            uint256 root = i + 1;
            registry.enrollHuman(commitment, root);
        }
    }

    /// @dev Enroll `count` agents with deterministic roots: root_i = 1000 + i + 1
    function _enrollAgents(uint256 count) internal {
        for (uint256 i = 0; i < count; i++) {
            uint256 commitment = uint256(keccak256(abi.encodePacked("agent", i)));
            uint256 root = 1000 + i + 1;
            registry.enrollAgent(commitment, root);
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  (1) Proof accepted when humanMerkleRoot matches any of 30 roots
    // ═══════════════════════════════════════════════════════════════════

    function test_proofAccepted_anyOf30HistoricalRoots() public {
        _enrollHumans(30);
        _enrollAgents(1);

        // Every root from 1..30 should be accepted
        for (uint256 i = 1; i <= 30; i++) {
            assertTrue(
                registry.isValidHumanRoot(i),
                string(abi.encodePacked("root ", vm.toString(i), " should be valid"))
            );
        }

        // Verify handshake with oldest buffered root (1)
        IdentityRegistry.HandshakeProof memory proof = IdentityRegistry.HandshakeProof({
            humanRoot: 1,
            agentRoot: 1001,
            nullifierHash: keccak256("oldest-root-proof"),
            proof: ""
        });
        assertTrue(registry.verifyHandshake(proof));

        // Verify handshake with newest buffered root (30)
        proof = IdentityRegistry.HandshakeProof({
            humanRoot: 30,
            agentRoot: 1001,
            nullifierHash: keccak256("newest-root-proof"),
            proof: ""
        });
        assertTrue(registry.verifyHandshake(proof));

        // Verify handshake with middle buffered root (15)
        proof = IdentityRegistry.HandshakeProof({
            humanRoot: 15,
            agentRoot: 1001,
            nullifierHash: keccak256("middle-root-proof"),
            proof: ""
        });
        assertTrue(registry.verifyHandshake(proof));
    }

    // ═══════════════════════════════════════════════════════════════════
    //  (2) Proof rejected when root is older than buffer window
    // ═══════════════════════════════════════════════════════════════════

    function test_proofRejected_rootOlderThanWindow() public {
        _enrollHumans(31);
        _enrollAgents(1);

        // Root 1 was evicted by root 31
        assertFalse(registry.isValidHumanRoot(1));
        assertFalse(registry.humanRootExists(1));

        // Handshake with evicted root should revert
        IdentityRegistry.HandshakeProof memory proof = IdentityRegistry.HandshakeProof({
            humanRoot: 1,
            agentRoot: 1001,
            nullifierHash: keccak256("stale-proof"),
            proof: ""
        });
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.InvalidHumanRoot.selector, 1));
        registry.verifyHandshake(proof);

        // Roots 2..31 should all be valid
        for (uint256 i = 2; i <= 31; i++) {
            assertTrue(
                registry.isValidHumanRoot(i),
                string(abi.encodePacked("root ", vm.toString(i), " should still be valid"))
            );
        }
    }

    function test_proofRejected_multipleEvictions() public {
        _enrollHumans(75);

        // Roots 1..45 should all be evicted
        for (uint256 i = 1; i <= 45; i++) {
            assertFalse(
                registry.isValidHumanRoot(i),
                string(abi.encodePacked("root ", vm.toString(i), " should be evicted"))
            );
        }
        // Roots 46..75 should be valid
        for (uint256 i = 46; i <= 75; i++) {
            assertTrue(
                registry.isValidHumanRoot(i),
                string(abi.encodePacked("root ", vm.toString(i), " should be valid"))
            );
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  (3) Buffer rotation at index wraparound (29 → 0)
    // ═══════════════════════════════════════════════════════════════════

    function test_bufferWraparound_indexCorrectness() public {
        // Fill all 30 slots (indices 0..29)
        _enrollHumans(30);
        assertEq(registry.humanRootHistoryIndex(), 30);

        // Next enrollment writes to slot 30 % 30 = 0, evicting root 1
        registry.enrollHuman(uint256(keccak256("wrap")), 31);

        assertEq(registry.humanRootHistoryIndex(), 31);
        assertEq(registry.humanRootHistory(0), 31); // slot 0 now holds root 31
        assertFalse(registry.isValidHumanRoot(1));   // root 1 was evicted
        assertTrue(registry.isValidHumanRoot(31));    // root 31 is valid
        assertTrue(registry.isValidHumanRoot(2));     // root 2 still valid (slot 1)
        assertTrue(registry.isValidHumanRoot(30));    // root 30 still valid (slot 29)
    }

    function test_bufferWraparound_secondWrap() public {
        // Enroll 60 humans: buffer wraps at 30, then at 60
        _enrollHumans(60);

        assertEq(registry.humanRootHistoryIndex(), 60);

        // Slot 0 should hold root 31 (first wrap), then root 61 would go there
        // After 60 enrollments: slots hold roots 31..60
        assertEq(registry.humanRootHistory(0), 31); // slot 0: 60 % 30 = 0 → last write was index 59 → slot 29
                                                     // Actually: index 30 wrote slot 0 (root 31)
                                                     //           index 60 would write slot 0 but we only did 60 total
                                                     //           index 59 wrote slot 29 (root 60)

        // Roots 1..30 should be evicted
        for (uint256 i = 1; i <= 30; i++) {
            assertFalse(registry.isValidHumanRoot(i));
        }
        // Roots 31..60 should be valid
        for (uint256 i = 31; i <= 60; i++) {
            assertTrue(registry.isValidHumanRoot(i));
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  (4) enrollHuman emits HumanRootAdded with correct slot
    // ═══════════════════════════════════════════════════════════════════

    function test_enrollHuman_emitsHumanRootAdded() public {
        // First enrollment: slot 0
        vm.expectEmit(true, false, false, true);
        emit IdentityRegistry.HumanRootAdded(42, 0);
        registry.enrollHuman(100, 42);

        // Second enrollment: slot 1
        vm.expectEmit(true, false, false, true);
        emit IdentityRegistry.HumanRootAdded(43, 1);
        registry.enrollHuman(101, 43);
    }

    function test_enrollHuman_emitsCorrectSlotAtWrap() public {
        _enrollHumans(29);

        // 30th enrollment: slot 29
        vm.expectEmit(true, false, false, true);
        emit IdentityRegistry.HumanRootAdded(30, 29);
        registry.enrollHuman(uint256(keccak256("human29")), 30);

        // 31st enrollment: wraps to slot 0
        vm.expectEmit(true, false, false, true);
        emit IdentityRegistry.HumanRootAdded(31, 0);
        registry.enrollHuman(uint256(keccak256("human30")), 31);
    }

    // ═══════════════════════════════════════════════════════════════════
    //  (5) Concurrent agent and human enrollments — no buffer corruption
    // ═══════════════════════════════════════════════════════════════════

    function test_concurrent_noBufferCorruption() public {
        // Interleave human and agent enrollments
        for (uint256 i = 0; i < 30; i++) {
            uint256 hCommit = uint256(keccak256(abi.encodePacked("h", i)));
            uint256 aCommit = uint256(keccak256(abi.encodePacked("a", i)));
            registry.enrollHuman(hCommit, i + 1);
            registry.enrollAgent(aCommit, 1000 + i + 1);
        }

        // Human roots 1..30 should be valid in human buffer only
        for (uint256 i = 1; i <= 30; i++) {
            assertTrue(registry.isValidHumanRoot(i));
            assertFalse(registry.isValidAgentRoot(i));
        }

        // Agent roots 1001..1030 should be valid in agent buffer only
        for (uint256 i = 1001; i <= 1030; i++) {
            assertTrue(registry.isValidAgentRoot(i));
            assertFalse(registry.isValidHumanRoot(i));
        }

        // Both indices should be 30
        assertEq(registry.humanRootHistoryIndex(), 30);
        assertEq(registry.agentRootHistoryIndex(), 30);
    }

    function test_concurrent_handshakeWithBothBuffers() public {
        _enrollHumans(25);
        _enrollAgents(10);

        // Simulate 6 more human enrollments while a proof is in-flight
        uint256 proverHumanRoot = 25;
        for (uint256 i = 25; i < 31; i++) {
            uint256 commitment = uint256(keccak256(abi.encodePacked("human", i)));
            registry.enrollHuman(commitment, i + 1);
        }

        // Prover's root should still be valid (25 is within last 30)
        assertTrue(registry.isValidHumanRoot(proverHumanRoot));

        IdentityRegistry.HandshakeProof memory proof = IdentityRegistry.HandshakeProof({
            humanRoot: proverHumanRoot,
            agentRoot: 1001,
            nullifierHash: keccak256("concurrent-handshake"),
            proof: ""
        });
        assertTrue(registry.verifyHandshake(proof));
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Additional edge cases
    // ═══════════════════════════════════════════════════════════════════

    function test_freshDeploy_zeroSlotsInvalid() public view {
        assertFalse(registry.isValidHumanRoot(0));
        assertFalse(registry.isValidHumanRoot(1));
        assertFalse(registry.isValidHumanRoot(type(uint256).max));
    }

    function test_enrollHuman_zeroRootReverts() public {
        vm.expectRevert(IdentityRegistry.ZeroRoot.selector);
        registry.enrollHuman(123, 0);
    }

    function test_isValidHumanRoot_zeroAlwaysFalse() public {
        _enrollHumans(5);
        assertFalse(registry.isValidHumanRoot(0));
    }

    function test_enrollHuman_nonOperatorReverts() public {
        vm.prank(address(0xdead));
        vm.expectRevert(IdentityRegistry.NotOperator.selector);
        registry.enrollHuman(123, 456);
    }

    function test_nullifierReplayRejected() public {
        _enrollHumans(1);
        _enrollAgents(1);

        bytes32 nullifier = keccak256("shared-nullifier");

        IdentityRegistry.HandshakeProof memory proof1 = IdentityRegistry.HandshakeProof({
            humanRoot: 1,
            agentRoot: 1001,
            nullifierHash: nullifier,
            proof: ""
        });
        registry.verifyHandshake(proof1);

        IdentityRegistry.HandshakeProof memory proof2 = IdentityRegistry.HandshakeProof({
            humanRoot: 1,
            agentRoot: 1001,
            nullifierHash: nullifier,
            proof: ""
        });
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.NullifierAlreadyUsed.selector, nullifier));
        registry.verifyHandshake(proof2);
    }

    function test_historyIndex_incrementsCorrectly() public {
        assertEq(registry.humanRootHistoryIndex(), 0);
        _enrollHumans(5);
        assertEq(registry.humanRootHistoryIndex(), 5);
        _enrollHumans(30);
        assertEq(registry.humanRootHistoryIndex(), 35);
    }

    function test_canonicalRoot_alwaysLatest() public {
        _enrollHumans(5);
        assertEq(registry.humanRoot(), 5);
        _enrollHumans(30);
        assertEq(registry.humanRoot(), 35);
    }

    // ── Fuzz tests ──────────────────────────────────────────────────────

    function testFuzz_enrollAndValidate(uint8 enrollCount) public {
        vm.assume(enrollCount > 0 && enrollCount <= 100);

        for (uint256 i = 0; i < enrollCount; i++) {
            uint256 commitment = uint256(keccak256(abi.encodePacked("fuzz", i)));
            uint256 root = i + 1;
            registry.enrollHuman(commitment, root);
        }

        // Latest root is always valid
        assertTrue(registry.isValidHumanRoot(enrollCount));

        // Boundary check: if more than 30 enrollments, oldest should be evicted
        if (enrollCount > 30) {
            uint256 evictedRoot = uint256(enrollCount) - 30;
            assertFalse(registry.isValidHumanRoot(evictedRoot));
        }

        // All roots in window should be valid
        uint256 windowStart = enrollCount > 30 ? uint256(enrollCount) - 29 : 1;
        for (uint256 i = windowStart; i <= enrollCount; i++) {
            assertTrue(registry.isValidHumanRoot(i));
        }
    }

    function testFuzz_mappingConsistentWithBuffer(uint8 enrollCount) public {
        vm.assume(enrollCount > 0 && enrollCount <= 100);

        for (uint256 i = 0; i < enrollCount; i++) {
            uint256 commitment = uint256(keccak256(abi.encodePacked("fuzz-map", i)));
            registry.enrollHuman(commitment, i + 1);
        }

        // Verify O(1) mapping is consistent: scan all buffer slots
        for (uint256 slot = 0; slot < 30; slot++) {
            uint256 rootInSlot = registry.humanRootHistory(slot);
            if (rootInSlot != 0) {
                assertTrue(registry.humanRootExists(rootInSlot));
                assertTrue(registry.isValidHumanRoot(rootInSlot));
            }
        }
    }
}
