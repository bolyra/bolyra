"""
Per-circuit signal name maps (Python mirror of sdk/src/signals.ts).

Each entry maps a circuit name to an ordered list of public signal field names.
The order matches the snarkjs publicSignals array: outputs first (in declaration
order), then public inputs (in declaration order).
"""

from __future__ import annotations

from typing import Dict, List

# Positional signal name maps keyed by circuit.
SIGNAL_MAPS: Dict[str, List[str]] = {
    "HumanUniqueness": [
        "nullifierHash",       # output 0
        "nonceBinding",        # output 1
        "humanMerkleRoot",     # public input 0
        "externalNullifier",   # public input 1
        "sessionNonce",        # public input 2
    ],
    "AgentPolicy": [
        "credentialHash",       # output 0
        "nonceBinding",         # output 1
        "agentMerkleRoot",      # public input 0
        "currentTimestamp",     # public input 1
        "requiredPermissions",  # public input 2
        "sessionNonce",         # public input 3
    ],
    "Delegation": [
        "delegationHash",        # output 0
        "narrowedPermissions",   # output 1
        "nonceBinding",          # output 2
        "delegationMerkleRoot",  # public input 0
        "currentTimestamp",      # public input 1
        "sessionNonce",          # public input 2
    ],
}

VALID_CIRCUITS = frozenset(SIGNAL_MAPS.keys())
VALID_PROVING_SYSTEMS = frozenset({"groth16", "plonk"})
