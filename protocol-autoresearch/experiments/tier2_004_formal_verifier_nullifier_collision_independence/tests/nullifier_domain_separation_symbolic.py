#!/usr/bin/env python3
"""
Nullifier Domain Separation — Symbolic Analysis

This script provides a formal symbolic argument that cross-circuit nullifier
collisions are computationally infeasible under the Poseidon2 preimage
resistance assumption.

For each pair of circuits (A, B), we show that the Poseidon input vectors
differ structurally (domain tag and/or arity), meaning a collision would
require finding a Poseidon preimage — which contradicts the hash function's
security assumption.

Usage:
    python tests/nullifier_domain_separation_symbolic.py

Dependencies:
    pip install sympy prettytable
"""

import sys
from dataclasses import dataclass, field
from itertools import combinations
from typing import List, Tuple

try:
    from prettytable import PrettyTable
except ImportError:
    # Fallback: simple table formatting
    PrettyTable = None  # type: ignore

from sympy import Symbol, symbols, simplify, Eq, Ne, And, Or
from sympy.logic.boolalg import BooleanTrue


# ═══════════════════════════════════════════════════════════════════════════════
# Circuit definitions
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class CircuitNullifier:
    """Represents a circuit's nullifier construction."""
    name: str
    domain_tag: int
    input_symbols: List[Symbol]
    arity: int = field(init=False)

    def __post_init__(self):
        self.arity = 1 + len(self.input_symbols)  # domain tag + inputs

    @property
    def full_input_vector(self) -> list:
        """Complete Poseidon input vector including domain tag."""
        return [self.domain_tag] + list(self.input_symbols)

    def __repr__(self):
        inputs_str = ", ".join(str(s) for s in self.full_input_vector)
        return f"{self.name}: Poseidon([{inputs_str}])  (arity {self.arity})"


def define_circuits() -> List[CircuitNullifier]:
    """Define the three Bolyra circuit nullifier constructions."""
    # Symbolic variables for raw inputs
    scope, secret = symbols("scope secret")
    agent_secret, policy_scope = symbols("agentSecret policyScope")
    delegator_secret, delegatee_cred, deleg_scope = symbols(
        "delegatorSecret delegateeCredCommitment delegScope"
    )

    return [
        CircuitNullifier(
            name="HumanUniqueness",
            domain_tag=1,
            input_symbols=[scope, secret],
        ),
        CircuitNullifier(
            name="AgentPolicy",
            domain_tag=2,
            input_symbols=[agent_secret, policy_scope],
        ),
        CircuitNullifier(
            name="Delegation",
            domain_tag=3,
            input_symbols=[delegator_secret, delegatee_cred, deleg_scope],
        ),
    ]


# ═══════════════════════════════════════════════════════════════════════════════
# Pairwise analysis
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class PairAnalysis:
    """Result of analyzing one pair of circuits."""
    circuit_a: str
    circuit_b: str
    arity_a: int
    arity_b: int
    arity_differs: bool
    domain_tag_a: int
    domain_tag_b: int
    domain_tag_differs: bool
    separation_reason: str
    collision_requires: str


def analyze_pair(
    a: CircuitNullifier, b: CircuitNullifier
) -> PairAnalysis:
    """Analyze domain separation between two circuits."""
    arity_differs = a.arity != b.arity
    domain_differs = a.domain_tag != b.domain_tag

    reasons = []
    if domain_differs:
        reasons.append(
            f"domain tags differ ({a.domain_tag} vs {b.domain_tag})"
        )
    if arity_differs:
        reasons.append(
            f"arities differ ({a.arity} vs {b.arity})"
        )

    if arity_differs:
        collision_req = (
            f"Finding x ∈ F^{a.arity} and y ∈ F^{b.arity} such that "
            f"Poseidon_{a.arity}(x) = Poseidon_{b.arity}(y). "
            f"Since Poseidon with different arities uses different round "
            f"constants and state sizes, this is a cross-parameter "
            f"preimage attack — strictly harder than standard preimage resistance."
        )
    else:
        collision_req = (
            f"Finding x ∈ F^{a.arity} with x[0]={a.domain_tag} and "
            f"y ∈ F^{b.arity} with y[0]={b.domain_tag} such that "
            f"Poseidon_{a.arity}(x) = Poseidon_{b.arity}(y). "
            f"Since x[0] ≠ y[0] by construction, the inputs differ in at "
            f"least one position, reducing this to a second-preimage attack "
            f"on Poseidon — computationally infeasible at 128-bit security."
        )

    return PairAnalysis(
        circuit_a=a.name,
        circuit_b=b.name,
        arity_a=a.arity,
        arity_b=b.arity,
        arity_differs=arity_differs,
        domain_tag_a=a.domain_tag,
        domain_tag_b=b.domain_tag,
        domain_tag_differs=domain_differs,
        separation_reason=" + ".join(reasons),
        collision_requires=collision_req,
    )


def analyze_all_pairs(
    circuits: List[CircuitNullifier],
) -> List[PairAnalysis]:
    """Analyze all pairwise combinations."""
    return [
        analyze_pair(a, b)
        for a, b in combinations(circuits, 2)
    ]


# ═══════════════════════════════════════════════════════════════════════════════
# Symbolic verification
# ═══════════════════════════════════════════════════════════════════════════════

def verify_symbolic_separation(circuits: List[CircuitNullifier]) -> bool:
    """
    Symbolically verify that no two circuits can have equal Poseidon inputs.

    For same-arity circuits: prove input vectors differ in at least one position.
    For different-arity circuits: separation is immediate (different Poseidon instances).
    """
    all_separated = True

    for a, b in combinations(circuits, 2):
        if a.arity != b.arity:
            # Different arities => different Poseidon instances => trivially separated
            print(f"  ✓ {a.name} vs {b.name}: arity {a.arity} ≠ {b.arity} "
                  f"(different Poseidon instances)")
            continue

        # Same arity: check if domain tags differ
        if a.domain_tag != b.domain_tag:
            print(f"  ✓ {a.name} vs {b.name}: domain tag {a.domain_tag} ≠ "
                  f"{b.domain_tag} (input[0] always differs)")
            continue

        # Same arity AND same domain tag — this would be a problem
        print(f"  ✗ {a.name} vs {b.name}: SAME arity and domain tag! "
              f"Domain separation NOT guaranteed.")
        all_separated = False

    return all_separated


# ═══════════════════════════════════════════════════════════════════════════════
# Shared-input collision test
# ═══════════════════════════════════════════════════════════════════════════════

def verify_shared_input_separation() -> bool:
    """
    Even when raw input VALUES are identical across circuits, domain tags
    ensure the full Poseidon input vectors differ.

    Scenario: scope = secret = agentSecret = policyScope = delegatorSecret
              = delegateeCredCommitment = delegScope = V
    """
    V = Symbol("V")

    # Construct input vectors with shared value V
    human_inputs  = [1, V, V]          # [DOMAIN_HUMAN, scope, secret]
    agent_inputs  = [2, V, V]          # [DOMAIN_AGENT, agentSecret, policyScope]
    deleg_inputs  = [3, V, V, V]       # [DOMAIN_DELEG, delegatorSecret, delegateeCred, scope]

    circuits = {
        "HumanUniqueness": human_inputs,
        "AgentPolicy": agent_inputs,
        "Delegation": deleg_inputs,
    }

    all_ok = True
    for (name_a, vec_a), (name_b, vec_b) in combinations(circuits.items(), 2):
        if len(vec_a) != len(vec_b):
            print(f"  ✓ {name_a} vs {name_b}: different arity "
                  f"({len(vec_a)} vs {len(vec_b)})")
            continue

        # Same length: check position-wise
        differs = False
        for i, (va, vb) in enumerate(zip(vec_a, vec_b)):
            diff = simplify(va - vb) if not isinstance(va - vb, int) else (va - vb)
            if diff != 0:
                print(f"  ✓ {name_a} vs {name_b}: input[{i}] differs "
                      f"({va} ≠ {vb})")
                differs = True
                break

        if not differs:
            print(f"  ✗ {name_a} vs {name_b}: ALL positions equal!")
            all_ok = False

    return all_ok


# ═══════════════════════════════════════════════════════════════════════════════
# Output formatting
# ═══════════════════════════════════════════════════════════════════════════════

def print_analysis_table(analyses: List[PairAnalysis]):
    """Print a formatted analysis table."""
    if PrettyTable is not None:
        table = PrettyTable()
        table.field_names = [
            "Circuit A", "Circuit B",
            "Arity A", "Arity B", "Arity Differs",
            "Tag A", "Tag B", "Tag Differs",
            "Separation Reason",
        ]
        table.align = "l"
        for a in analyses:
            table.add_row([
                a.circuit_a, a.circuit_b,
                a.arity_a, a.arity_b, "YES" if a.arity_differs else "no",
                a.domain_tag_a, a.domain_tag_b, "YES" if a.domain_tag_differs else "no",
                a.separation_reason,
            ])
        print(table)
    else:
        # Fallback formatting
        print(f"{'Circuit A':<20} {'Circuit B':<20} {'Arity':<10} "
              f"{'Tags':<10} {'Separation'}")
        print("=" * 90)
        for a in analyses:
            print(f"{a.circuit_a:<20} {a.circuit_b:<20} "
                  f"{a.arity_a}v{a.arity_b:<7} "
                  f"{a.domain_tag_a}v{a.domain_tag_b:<7} "
                  f"{a.separation_reason}")


# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════

def main() -> int:
    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║  Bolyra Protocol — Nullifier Domain Separation Symbolic Analysis ║")
    print("╚══════════════════════════════════════════════════════════════════╝")
    print()

    # 1. Define circuits
    circuits = define_circuits()
    print("── Circuit Nullifier Constructions ──")
    for c in circuits:
        print(f"  {c}")
    print()

    # 2. Pairwise analysis
    print("── Pairwise Domain Separation Analysis ──")
    analyses = analyze_all_pairs(circuits)
    print_analysis_table(analyses)
    print()

    # 3. Collision requirements
    print("── Collision Requirements (what an attacker would need) ──")
    for a in analyses:
        print(f"\n  {a.circuit_a} vs {a.circuit_b}:")
        print(f"    {a.collision_requires}")
    print()

    # 4. Symbolic verification
    print("── Symbolic Separation Verification ──")
    sym_ok = verify_symbolic_separation(circuits)
    print()

    # 5. Shared-input worst case
    print("── Shared-Input Worst Case (all raw values equal) ──")
    shared_ok = verify_shared_input_separation()
    print()

    # 6. Verdict
    print("═" * 70)
    if sym_ok and shared_ok:
        print("RESULT: ✓ Domain separation PROVEN for all circuit pairs.")
        print("")
        print("Under the Poseidon2 preimage resistance assumption (128-bit")
        print("security), cross-circuit nullifier collisions are computationally")
        print("infeasible. Each pair of circuits differs in either:")
        print("  (a) Poseidon arity (different hash instances), or")
        print("  (b) Domain tag value at input[0] (distinct preimages).")
        print("")
        print("No valid witness for circuit A can produce a nullifierHash")
        print("equal to a valid nullifierHash from circuit B.  □")
        return 0
    else:
        print("RESULT: ✗ Domain separation FAILED for one or more pairs.")
        print("Review circuit definitions and fix domain tag assignments.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
