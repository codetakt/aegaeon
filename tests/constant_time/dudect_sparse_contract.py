"""Explicit new native identity with an immutable mapping to reviewed base rules."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from dudect_candidate import BASE_NUMERICAL_SHA256, NUMERICAL_SHA256, SPARSE_RUNTIME, digest
from dudect_process import load_json
from dudect_sparse import BASE_CONTRACT, BASE_NUMERICAL, POLICY_SHA256
from dudect_support import require


def expected_contract(directory: Path | None = None) -> dict[str, Any]:
    directory = directory or Path(__file__).with_name("contracts")
    raw = (directory / "case-contract-base-v5.json").read_bytes()
    require(digest(raw) == BASE_CONTRACT, "Base case contract changed")
    require(BASE_NUMERICAL_SHA256 == BASE_NUMERICAL, "Base numerical rules changed")
    require(SPARSE_RUNTIME["policy_sha256"] == POLICY_SHA256, "Sparse policy changed")
    base = load_json(raw)
    result: dict[str, Any] = copy.deepcopy(base)
    result["numerical_candidate"]["implementation_sha256"] = NUMERICAL_SHA256
    result["sparse_runtime"] = SPARSE_RUNTIME
    return result


def check_runtime_contract(directory: Path | None = None) -> str:
    directory = directory or Path(__file__).with_name("contracts")
    raw = (directory / "case-contract-candidate.json").read_bytes()
    require(load_json(raw) == expected_contract(directory), "Unreviewed sparse runtime contract")
    return digest(raw)
