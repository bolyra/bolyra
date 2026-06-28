// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title  FieldBoundLib
/// @notice Centralised BN254 scalar field bound check for all Bolyra verifier
///         contracts.  Every public signal passed to a Groth16/PLONK verifier
///         MUST be < FIELD_MODULUS; otherwise the Solidity uint256 value and
///         the value seen inside the circuit (which operates mod r) diverge,
///         enabling nonce-bypass and semantic-mismatch attacks.
library FieldBoundLib {
    /// @notice BN254 scalar field order (aka `r`).
    ///         r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
    uint256 internal constant FIELD_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @notice Reverts when a public signal is >= FIELD_MODULUS.
    /// @param value The out-of-range value that was rejected.
    error FieldModulusExceeded(uint256 value);

    /// @notice Revert if `v` is not a canonical BN254 scalar field element.
    /// @param v The value to check.
    function assertInField(uint256 v) internal pure {
        if (v >= FIELD_MODULUS) {
            revert FieldModulusExceeded(v);
        }
    }
}
