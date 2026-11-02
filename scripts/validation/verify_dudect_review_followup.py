"""Verify the public contract/source correction, without executing measured code.

This checks file bindings and declared syntax correspondence, not physical
equivalence, statistical assumptions, review approval or CI admission.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import tarfile
from pathlib import Path


def require(condition: bool, reason: str) -> None:
    """Reject an inconsistent public correction."""
    if not condition:
        raise ValueError(reason)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Syntax(ast.NodeTransformer):
    """Ignore docstrings and split imports without changing their execution order."""

    def generic_visit(self, node: ast.AST) -> ast.AST:
        node = super().generic_visit(node)
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                node.body = body[1:]
        return node

    def visit_Import(self, node: ast.Import) -> list[ast.Import]:
        return [ast.Import(names=[name]) for name in node.names]

    def visit_ImportFrom(self, node: ast.ImportFrom) -> list[ast.ImportFrom]:
        if node.module == "__future__":
            return [node]
        return [
            ast.ImportFrom(module=node.module, names=[name], level=node.level)
            for name in node.names
        ]


def syntax(data: bytes) -> str:
    return ast.dump(Syntax().visit(ast.parse(data)), include_attributes=False)


SCHEDULE_SOURCE = "tests/dudect_sensitivity_operations/schedule.py"
SCHEDULE_CORRECTION = "ci/evidence/dudect-schedule-correction-20261023.json"


def schedule_correction(root: Path, original: dict[str, str]) -> tuple[bytes, bytes]:
    """Verify one explicit post-measurement correction, not an AST exception list."""
    receipt = json.loads((root / SCHEDULE_CORRECTION).read_bytes())
    require(
        receipt["schema"] == "dudect-schedule-source-correction/1"
        and receipt["path"] == SCHEDULE_SOURCE,
        "Wrong scheduling correction scope",
    )
    require(
        receipt["new_physical_trials"] == 0
        and receipt["physical_equivalence_asserted"] is False
        and receipt["ci_admission"] is False,
        "Scheduling correction cannot grant physical qualification or admission",
    )
    historical = receipt["historical_publication_source"].encode("utf-8")
    require(
        sha(historical)
        == receipt["historical_publication_sha256"]
        == original["publication_sha256"]
        and receipt["measured_sha256"] == original["measured_sha256"],
        "Historical scheduling correspondence changed",
    )
    current = (root / SCHEDULE_SOURCE).read_bytes()
    require(
        sha(current) == receipt["corrected_publication_sha256"], "Corrected scheduling hash changed"
    )
    require(
        syntax(current) != syntax(historical),
        "Scheduling correction must declare its executable change",
    )
    return historical, current


def verify(root: Path) -> dict[str, object]:
    root = root.resolve()
    folder = root / "ci/contracts/dudect-baremetal-v1"
    contract = json.loads((folder / "contract.json").read_bytes())
    checkpoint_path = root / contract["evidence"]["checkpoint"]["path"]
    require(
        sha(checkpoint_path.read_bytes()) == contract["evidence"]["checkpoint"]["sha256"],
        "Historical checkpoint changed",
    )
    checkpoint = json.loads(checkpoint_path.read_bytes())
    versions = {}
    for name, binding in contract["documents"].items():
        data = (folder / binding["path"]).read_bytes()
        require(sha(data) == binding["sha256"], f"New contract binding changed: {name}")
        versions[name] = json.loads(data)
    scope, sensitivity, roles = (versions[n] for n in ("scope", "sensitivity", "roles"))
    cases = contract["scope"]["cases"]
    require(
        len(cases) == len(set(cases)) == 7
        and cases == scope["cases"] == sensitivity["target_cases"] == roles["scope"]["cases"],
        "Seven-case scope differs between contracts",
    )
    require(
        contract["scope"]["calibrated_cases"] == 7
        and contract["scope"]["unchanged_cases"] == 14
        and "other14cases" in scope["unchanged"]
        and "other14cases" in sensitivity["calibration"]["unchanged"]
        and "other17cases" not in sensitivity["calibration"]["unchanged"],
        "Seven/fourteen calibration scope is inconsistent",
    )
    require(
        roles["base"]["id"] == sensitivity["id"]
        and roles["base"]["file"] == "sensitivity.json"
        and roles["base"]["sha256"] == contract["documents"]["sensitivity"]["sha256"],
        "New role contract inherits a different sensitivity contract",
    )
    for name, binding in contract["execution_contracts"].items():
        require(
            sha((root / binding["path"]).read_bytes())
            == binding["sha256"]
            == versions[name]["creation_state"]["source"]["sha256"],
            f"Historical execution contract changed: {name}",
        )
    original_sensitivity = json.loads(
        (root / contract["execution_contracts"]["sensitivity"]["path"]).read_bytes()
    )
    for field in (
        "profile",
        "compilers",
        "schedule",
        "numeric_contract",
        "signal_obligations",
        "common_qualification",
        "protected_obligations",
        "limits",
        "exclusions",
    ):
        require(sensitivity[field] == original_sensitivity[field], f"Changed obligation: {field}")
    for field, value in original_sensitivity["calibration"].items():
        if field != "unchanged":
            require(sensitivity["calibration"][field] == value, f"Changed calibration: {field}")
    original_roles = json.loads(
        (root / contract["execution_contracts"]["roles"]["path"]).read_bytes()
    )
    for field in (
        "scope",
        "replacement",
        "positive_witness",
        "positive_final_eligibility",
        "numeric_invariants",
    ):
        require(roles[field] == original_roles[field], f"Changed role rule: {field}")
    for document in (contract, *versions.values()):
        require(
            document["formal_adoption"] is False and document["ci_admission"] is False,
            "Correction receipt cannot grant adoption or CI admission",
        )
    require(
        contract["entry"]["analysis_identity"] == "role-live-analysis/3"
        and contract["entry"]["ordinary"] == "tests/dudect_sensitivity_operations/ordinary.py",
        "Wrong limited-monitoring entry",
    )
    archive_path = root / contract["measured_source"]["archive"]
    require(
        sha(archive_path.read_bytes()) == contract["measured_source"]["sha256"],
        "Measured source archive changed",
    )
    inventory = checkpoint["publication_source_correspondence"]["files"]
    expected = {row["path"]: row for row in inventory}
    require(len(expected) == len(inventory) == 54, "Incomplete source correspondence inventory")
    old_schedule, current_schedule = schedule_correction(root, expected[SCHEDULE_SOURCE])
    exceptions = set(contract["measured_source"]["test_only_AST_changes"])
    python_count = equal_count = historical_equal_count = 0
    observed_exceptions = set()
    with tarfile.open(archive_path, "r:gz") as archive:
        members = archive.getmembers()
        require(
            len(members) == len(expected) and {m.name for m in members} == set(expected),
            "Archive member set differs from the original receipt",
        )
        for member in members:
            require(member.isfile(), "Archive contains a non-regular file")
            require(member.size < 1024 * 1024, "Unexpected source file size")
            source = archive.extractfile(member)
            if source is None:
                message = "Missing archived source"
                raise ValueError(message)
            measured = source.read()
            row = expected[member.name]
            current = (
                current_schedule
                if member.name == SCHEDULE_SOURCE
                else (root / member.name).read_bytes()
            )
            published = old_schedule if member.name == SCHEDULE_SOURCE else current
            require(sha(measured) == row["measured_sha256"], f"Measured hash: {member.name}")
            require(sha(published) == row["publication_sha256"], f"Published hash: {member.name}")
            if member.name.endswith(".py"):
                python_count += 1
                same = syntax(measured) == syntax(published)
                if same:
                    historical_equal_count += 1
                else:
                    require(
                        member.name in exceptions and row["test_only"],
                        f"Execution syntax changed: {member.name}",
                    )
                    observed_exceptions.add(member.name)
                if syntax(measured) == syntax(current):
                    equal_count += 1
            elif not member.name.endswith(".md"):
                require(measured == published, f"Non-Python measured input changed: {member.name}")
    require(
        observed_exceptions == exceptions, "Declared test exceptions differ from actual changes"
    )
    require(python_count == 44, "Python inventory differs from actual checkpoint")
    followup = json.loads((root / contract["evidence"]["followup_receipt"]).read_bytes())
    require(
        followup["contract_sha256"] == sha((folder / "contract.json").read_bytes()),
        "Follow-up receipt does not bind the new contract",
    )
    require(followup["new_physical_trials"] == 0, "Recount is not a physical trial")
    require(
        followup["formal_adoption"] is False and followup["ci_admission"] is False,
        "Follow-up receipt grants unreviewed adoption",
    )
    for stage, old in zip(
        followup["decision_breakdown"]["stages"], checkpoint["stages"], strict=True
    ):
        require(stage["source_plan_sha256"] == old["plan_sha256"], "Wrong stage binding")
        require(
            sum(stage["original_detections_by_case_role"].values())
            == old["original_detected_statistic_looks"],
            "Original detection count changed",
        )
    return {
        "source_files": len(expected),
        "python_files": python_count,
        "normalized_AST_equal": equal_count,
        "historical_publication_AST_equal": historical_equal_count,
        "post_measurement_source_corrections": [SCHEDULE_SOURCE],
        "test_only_AST_changes": sorted(observed_exceptions),
        "historical_checkpoint_unchanged": True,
        "new_contracts_scope_consistent": True,
        "physical_equivalence_asserted": False,
        "new_physical_trials": 0,
        "formal_adoption": False,
        "ci_admission": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    print(json.dumps(verify(args.root), indent=2))


if __name__ == "__main__":
    main()
