"""Shared proof-quality and strength classification for VerifiedReqs tooling."""

from __future__ import annotations

from typing import Any

FORMAL_TYPES = frozenset({"fstar", "tamarin", "kani", "everparse", "lowstar", "hacl"})
EMPIRICAL_TYPES = frozenset({"dudect"})


def compute_proof_quality(proof_type: str) -> str:
    """Classify a proof type as formal, empirical, or unknown."""
    if proof_type in FORMAL_TYPES:
        return "formal"
    if proof_type in EMPIRICAL_TYPES:
        return "empirical"
    return "unknown"


def compute_strength(proof: dict[str, Any]) -> str:
    """Derive the evidence strength of a proof block.

    Returns one of: "lemma", "refinement", "semantic".
    """
    if "lemma" in proof or "harness" in proof:
        return "lemma"
    if proof.get("type") == "everparse" and "spec" in proof:
        return "lemma"
    if "refinement" in proof:
        return "refinement"
    return "semantic"
