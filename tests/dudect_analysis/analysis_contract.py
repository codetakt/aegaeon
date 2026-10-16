# The authenticated source bundle must be selected before native helper imports.
# ruff: noqa: E402
"""Opt-in research analysis contract; original measurement identities survive."""

from __future__ import annotations

import copy
import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "source" if (HERE / "source").is_dir() else HERE.parents[1]
sys.path.insert(0, str(SOURCE / "tests/constant_time"))
from dependencies import runtime_identity
from distributed import POLICY_SHA256 as DISTRIBUTED_SHA256
from dudect_candidate import canonical, digest, significant as original_significant
from dudect_contract import CHARACTERIZATION_ROLES, NONDETECTION_ROLES, POSITIVE_STATISTICS
from dudect_results import NONDETECTION
from dudect_support import require
from enclosed_tail import ALPHA, PRECISIONS, enclose
from sparse_four import POLICY_SHA256 as FOUR_SHA256

NUMERICAL_POLICY = {
    "id": "student-interval-frozen-binary64-pr/research-1",
    "profile": "pr",
    "scope": "all PR Welch tests; existing sparse exact decisions unchanged",
    "target": "mathematical two-sided Student tail at exact binary64 t and df",
    "upstream": "existing binary64 moment/t/df computation; not error-certified",
    "alpha": [ALPHA.numerator, ALPHA.denominator],
    "precisions": list(PRECISIONS),
    "rule": "upper<alpha detected; lower>=alpha nondetected; otherwise unresolved",
    "unresolved": "sticky case failure; cannot be cleared by later non-detection",
    "provenance": "native and numerical/analysis identities remain separate",
    "adopted": False,
}
NUMERICAL_SHA256 = digest(canonical(NUMERICAL_POLICY))

# Bound worker startup independently of the host's potentially large locale archive.
# UTF-8 paths/JSON remain supported; the native and collector environment is unchanged.
WORKER_ENVIRONMENT = {"LC_ALL": "C", "PYTHONUTF8": "1", "PYTHONCOERCECLOCALE": "0"}


def filehash(p):
    with Path(p).open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def identity(mode, packet, unit):
    import flint  # noqa: PLC0415 -- load only for explicit dependency identity

    require(mode in ("interval-only", "distributed"), "Unknown analysis mode")
    require(
        all(isinstance(s, str) and s and "/" not in s for s in (packet, unit)),
        "Unfrozen split domain",
    )
    files = [
        "analysis_contract.py",
        "analysis_runtime.py",
        "run_analysis.py",
        "enclosed_tail.py",
        "distributed.py",
        "dependencies.py",
        "sparse_four.py",
    ]
    dep = Path(flint.__file__).parent
    dependencies = {
        str(p.relative_to(dep.parent)): filehash(p)
        for parent in (dep, dep.parent / "python_flint.libs")
        if parent.exists()
        for p in sorted(parent.rglob("*"))
        if p.is_file() and p.suffix != ".pyc"
    }
    return {
        "schema": "dudect-research-analysis/3",
        "mode": mode,
        "packet": packet,
        "unit": unit,
        "worker_environment": WORKER_ENVIRONMENT.copy(),
        "packaged_runtime": runtime_identity(HERE),
        "numerical_policy_sha256": NUMERICAL_SHA256,
        "four_exception_policy_sha256": FOUR_SHA256,
        "distributed_policy_sha256": DISTRIBUTED_SHA256 if mode == "distributed" else None,
        "implementation": {f: filehash(HERE / f) for f in files},
        "python": {
            "executable": str(Path(sys.executable).resolve()),
            "sha256": filehash(sys.executable),
            "version": sys.version,
        },
        "python_flint": {"version": flint.__version__, "files": dependencies},
        "adopted": False,
    }


def interval_test(test, deadline=None):
    result = copy.deepcopy(test)
    if test["eligible"] and "t" in test:
        cert = enclose(test["t"], test["degrees"], deadline=deadline)
        result["legacy_p"] = result.pop("p")
        result["interval"] = cert
        result["method"] = "student_interval_at_frozen_binary64"
        if cert["decision"] == "numerically_unresolved":
            result["eligible"] = False
            result["reason"] = "numerically_unresolved"
    return result


def significant(test):
    if "interval" not in test:
        return original_significant(test)
    return test["eligible"] and test["interval"]["decision"] == "detected"


class History:
    def __init__(self):
        self.next_look = 1
        self.detected = set()
        self.unresolved = []

    def append(self, row, base, tests):
        require(
            row["look"] == self.next_look and row["profile"] == "pr",
            "Invalid analysis look/profile",
        )
        require(
            base["look"] == row["look"] and base["profile"] == row["profile"],
            "Base analysis look/profile mismatch",
        )
        require([t["id"] for t in tests] == list(range(102)), "Invalid analysis inventory")
        now = [t["id"] for t in tests if significant(t)]
        self.detected.update(now)
        self.unresolved.extend(
            {"look": row["look"], "statistic": t["id"]}
            for t in tests
            if t.get("reason") == "numerically_unresolved"
        )
        final = row["look"] == 8
        outcome = (
            "leakage_detected"
            if self.detected
            else "collecting"
            if not final
            else NONDETECTION
            if not self.unresolved
            and all(t["eligible"] for t in tests)
            and min(base["raw_class_counts"]) >= 200000
            else "inconclusive"
        )
        value = {
            k: copy.deepcopy(base[k])
            for k in ("case", "profile", "look", "raw_count", "raw_class_counts")
        }
        value.update(
            {
                "candidate_statistical_outcome": outcome,
                "collection_complete": final,
                "admission": "research_only",
                "tests": tests,
                "detected_now": now,
                "detected_ever": sorted(self.detected),
                "numerically_unresolved_ever": self.unresolved.copy(),
            }
        )
        self.next_look += 1
        return value


def assess(case_id, role, history):
    require(
        len(history) == 8 and [r["look"] for r in history] == list(range(1, 9)),
        "Incomplete analysis history",
    )
    final = history[-1]
    failure = None
    name = case_id.split("/")[1]
    if not final["collection_complete"] or min(final["raw_class_counts"]) < 200000:
        failure = "incomplete_schedule_or_raw_floor"
    elif final["numerically_unresolved_ever"]:
        failure = "numerically_unresolved"
    elif role in NONDETECTION_ROLES:
        if final["candidate_statistical_outcome"] != NONDETECTION:
            failure = final["candidate_statistical_outcome"]
    elif role == "measurement_positive_control":
        require(name in POSITIVE_STATISTICS, "Unknown positive-control statistic")
        if not any(significant(r["tests"][POSITIVE_STATISTICS[name]]) for r in history):
            failure = f"required_statistic_{POSITIVE_STATISTICS[name]}_not_detected"
    else:
        require(role in CHARACTERIZATION_ROLES, "Unknown role")
    return {
        "case_id": case_id,
        "role": role,
        "requirement_satisfied": failure is None,
        "failure": failure,
        "statistical_outcome": final["candidate_statistical_outcome"],
        "product_assurance": "not_established",
        "adopted": False,
    }
