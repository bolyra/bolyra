// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IdentityRegistry} from "../IdentityRegistry.sol";

/// @title TestableIdentityRegistry
/// @notice TEST-ONLY subclass of IdentityRegistry that exposes mutators for
///         the chain-state and nullifier maps so adversarial scenarios can
///         exercise individual guards in isolation.
/// @dev    Do NOT deploy in production. Lives under contracts/test/ so it is
///         excluded from any production deploy script. Used by E2EDelegation
///         to construct the matching-prevScope replay scenario required for
///         Codex P2-3 coverage (the production replay test fires
///         ScopeChainMismatch before reaching the nullifier check).
contract TestableIdentityRegistry is IdentityRegistry {
    constructor(
        address _humanVerifier,
        address _agentVerifier,
        address _delegationVerifier
    ) IdentityRegistry(_humanVerifier, _agentVerifier, _delegationVerifier) {}

    /// @notice Rewind the on-chain chain state for a session so the next
    ///         delegation must once again prove its prevScope against the
    ///         supplied value. Lets tests construct the matching-prevScope
    ///         path that exercises the nullifier guard.
    function __test_setLastScopeCommitment(uint256 sessionNonce, uint256 value)
        external
        onlyOwner
    {
        lastScopeCommitment[sessionNonce] = value;
    }

    /// @notice Rewind the hop counter for a session. Lets the 4th-hop boundary
    ///         test repeatedly submit hop 4 without first running 1-3 with
    ///         real proofs (which would cost three full Groth16 generations).
    function __test_setDelegationHopCount(uint256 sessionNonce, uint256 value)
        external
        onlyOwner
    {
        delegationHopCount[sessionNonce] = value;
    }

    /// @notice Clear a delegation nullifier so the same proof can be submitted
    ///         again. Used to disentangle the nullifier-replay guard from the
    ///         hop-count guard in adversarial tests.
    function __test_setUsedDelegationNullifier(uint256 nullifier, bool used)
        external
        onlyOwner
    {
        usedDelegationNullifiers[nullifier] = used;
    }
}
