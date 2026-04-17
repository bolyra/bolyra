// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../contracts/IdentityRegistry.sol";

/**
 * @title IdentityRegistryHumanRootHistory
 * @notice Foundry test suite for the humanRootHistory ring-buffer.
 *         Covers: normal fill, wrap-around eviction, stale root rejection,
 *         zero-value guard, and concurrent enroll+verify scenarios.
 */
contract IdentityRegistryHumanRootHistory is Test {
    IdentityRegistry registry;

    function setUp() public {
        registry = new IdentityRegistry();
    }

    // ── Helper ───────────────────────────────────────────────────────────

    /// @dev Enroll `count` humans with deterministic roots: root_i = i + 1
    function _enrollHumans(uint256 count) internal {
        for (uint256 i = 0; i < count; i++) {
            uint256 commitment = uint256(keccak256(abi.encodePacked("human", i)));
            uint256 root = i + 1; // roots: 1, 2, 3, ...
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

    // ── Test: Fresh deploy has no valid roots ────────────────────────────

    function test_freshDeploy_zeroSlotsInvalid() public view {
        assertFalse(registry.isValidHumanRoot(0));
        assertFalse(registry.isValidHumanRoot(1));
        assertFalse(registry.isValidHumanRoot(type(uint256).max));
    }

    // ── Test: Normal buffer fill (≤30 enrollments) ──────────────────────

    function test_normalFill_allRootsValid() public {
        _enrollHumans(30);

        for (uint256 i = 1; i <= 30; i++) {
            assertTrue(
                registry.isValidHumanRoot(i),
                string(abi.encodePacked("root ", vm.toString(i), " should be valid"))
            );
        }

        assertEq(registry.humanRoot(), 30);
    }

    // ── Test: 31 enrollments → oldest root evicted ──────────────────────

    function test_eviction_oldestRootInvalid() public {
        _enrollHumans(31);

        assertFalse(
            registry.isValidHumanRoot(1),
            "root 1 should be evicted after 31 enrollments"
        );

        for (uint256 i = 2; i <= 31; i++) {
            assertTrue(
                registry.isValidHumanRoot(i),
                string(abi.encodePacked("root ", vm.toString(i), " should be valid"))
            );
        }

        assertEq(registry.humanRoot(), 31);
    }

    // ── Test: Ring-buffer wrap-around at index 30+ ──────────────────────

    function test_wrapAround_multipleWraps() public {
        _enrollHumans(75);

        for (uint256 i = 1; i <= 45; i++) {
            assertFalse(
                registry.isValidHumanRoot(i),
                string(abi.encodePacked("root ", vm.toString(i), " should be evicted"))
            );
        }
        for (uint256 i = 46; i <= 75; i++) {
            assertTrue(
                registry.isValidHumanRoot(i),
                string(abi.encodePacked("root ", vm.toString(i), " should be valid"))
            );
        }
    }

    // ── Test: Proof with stale root beyond buffer fails ─────────────────

    function test_verifyHandshake_staleHumanRootFails() public {
        _enrollHumans(31);
        _enrollAgents(1);

        IdentityRegistry.HandshakeProof memory proof = IdentityRegistry.HandshakeProof({
            humanRoot: 1,
            agentRoot: 1001,
            nullifierHash: keccak256("nullifier1"),
            proof: ""
        });

        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.InvalidHumanRoot.selector, 1));
        registry.verifyHandshake(proof);
    }

    // ── Test: Proof with valid buffered root succeeds ───────────────────

    function test_verifyHandshake_validBufferedRootSucceeds() public {
        _enrollHumans(31);
        _enrollAgents(1);

        IdentityRegistry.HandshakeProof memory proof = IdentityRegistry.HandshakeProof({
            humanRoot: 2,
            agentRoot: 1001,
            nullifierHash: keccak256("nullifier2"),
            proof: ""
        });

        bool success = registry.verifyHandshake(proof);
        assertTrue(success);
    }

    // ── Test: Proof with latest root succeeds ───────────────────────────

    function test_verifyHandshake_latestRootSucceeds() public {
        _enrollHumans(5);
        _enrollAgents(1);

        IdentityRegistry.HandshakeProof memory proof = IdentityRegistry.HandshakeProof({
            humanRoot: 5,
            agentRoot: 1001,
            nullifierHash: keccak256("nullifier3"),
            proof: ""
        });

        bool success = registry.verifyHandshake(proof);
        assertTrue(success);
    }

    // ── Test: Nullifier replay rejected ─────────────────────────────────

    function test_verifyHandshake_nullifierReplayRejected() public {
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

    // ── Test: Concurrent enrollment + verify under wrap ─────────────────

    function test_concurrent_enrollAndVerify() public {
        _enrollHumans(25);
        uint256 proverRoot = 25;

        for (uint256 i = 25; i < 31; i++) {
            uint256 commitment = uint256(keccak256(abi.encodePacked("human", i)));
            registry.enrollHuman(commitment, i + 1);
        }

        assertTrue(registry.isValidHumanRoot(proverRoot));

        _enrollAgents(1);

        IdentityRegistry.HandshakeProof memory proof = IdentityRegistry.HandshakeProof({
            humanRoot: proverRoot,
            agentRoot: 1001,
            nullifierHash: keccak256("concurrent-nullifier"),
            proof: ""
        });

        bool success = registry.verifyHandshake(proof);
        assertTrue(success);
    }

    // ── Test: Zero root enrollment reverts ───────────────────────────────

    function test_enrollHuman_zeroRootReverts() public {
        vm.expectRevert(IdentityRegistry.ZeroRoot.selector);
        registry.enrollHuman(123, 0);
    }

    // ── Test: isValidHumanRoot returns false for zero ────────────────────

    function test_isValidHumanRoot_zeroAlwaysFalse() public {
        _enrollHumans(5);
        assertFalse(registry.isValidHumanRoot(0));
    }

    // ── Test: Agent buffer unaffected by human enrollments ──────────────

    function test_agentBuffer_independentFromHuman() public {
        _enrollHumans(10);
        _enrollAgents(5);

        for (uint256 i = 1; i <= 10; i++) {
            assertTrue(registry.isValidHumanRoot(i));
            assertFalse(registry.isValidAgentRoot(i));
        }
        for (uint256 i = 1001; i <= 1005; i++) {
            assertTrue(registry.isValidAgentRoot(i));
            assertFalse(registry.isValidHumanRoot(i));
        }
    }

    // ── Test: Non-operator cannot enroll ─────────────────────────────────

    function test_enrollHuman_nonOperatorReverts() public {
        vm.prank(address(0xdead));
        vm.expectRevert(IdentityRegistry.NotOperator.selector);
        registry.enrollHuman(123, 456);
    }

    // ── Test: humanRootHistoryIndex increments correctly ─────────────────

    function test_historyIndex_incrementsCorrectly() public {
        assertEq(registry.humanRootHistoryIndex(), 0);

        _enrollHumans(5);
        assertEq(registry.humanRootHistoryIndex(), 5);

        _enrollHumans(30);
        assertEq(registry.humanRootHistoryIndex(), 35);
    }
}
