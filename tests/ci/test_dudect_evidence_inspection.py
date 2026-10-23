"""Receipt correspondence is necessary, and never sufficient, for CI admission."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ci/inspect_dudect_evidence.py"
SPEC = importlib.util.spec_from_file_location("dudect_evidence_inspection", SCRIPT)
assert SPEC
assert SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def encode(value):
    return (json.dumps(value, sort_keys=True) + "\n").encode()


def fixture():
    contract = json.loads(
        (ROOT / "tests/constant_time/contracts/case-contract-candidate.json").read_text()
    )
    roles = {case["stable_id"]: case["proposed_role"] for case in contract["cases"]}
    sha = "1" * 64
    subject = {
        "profile": "pr",
        "event": "merge_group",
        "repository": "owner/example",
        "target_revision": "a" * 40,
        "source_tree_sha256": sha,
        "artifact_manifest_sha256": sha,
        "analysis_sha256": sha,
        "environment_sha256": sha,
        "contract_sha256": sha,
    }
    request = {
        "schema": "external-dudect-request/1",
        "request_id": "fixture-request",
        "subject": subject,
        "issued_at": 10,
        "acquisition_deadline": 100,
        "recovery_deadline": 120,
        "expires_at": 150,
        "inventory": [
            {
                "id": f"{compiler}/{case}/1",
                "case_id": case,
                "compiler": compiler,
                "round": 1,
                "role": role,
                "elf_sha256": sha,
            }
            for compiler in ("gcc", "clang")
            for case, role in roles.items()
        ],
    }
    producer = {
        "schema": "external-dudect-result/1",
        "producer_id": "fixture-producer",
        "request_sha256": MODULE.digest(encode(request)),
        "subject": subject,
        "inventory": copy.deepcopy(request["inventory"]),
        "execution_kind": "fresh_ordinary",
        "operation": "complete",
        "started_at": 20,
        "completed_at": 95,
        "recovered_at": 110,
        "recovery_manifest_sha256": sha,
        "lifecycle_receipt_sha256": sha,
        "observations": [
            {
                "id": row["id"],
                "raw_manifest_sha256": sha,
                "original_decisions_sha256": sha,
                "effective_decisions_sha256": sha,
            }
            for row in request["inventory"]
        ],
    }
    replay = {
        "schema": "external-dudect-replay/1",
        "verifier_id": "fixture-verifier",
        "verifier_runtime_sha256": sha,
        "request_sha256": MODULE.digest(encode(request)),
        "producer_sha256": MODULE.digest(encode(producer)),
        "recovery_manifest_sha256": sha,
        "replayed_at": 115,
        "results": [
            {
                **observation,
                "role": row["role"],
                "collection": "complete",
                "prefix_verification": "complete",
                "numeric_validity": "complete",
                "original_retention": "complete",
                "looks": 8,
                "audit_sha256": sha,
                "qualification": "observation_contract_satisfied",
            }
            for row, observation in zip(request["inventory"], producer["observations"], strict=True)
        ],
    }
    context = {
        "schema": "external-dudect-inspection-context/1",
        "request_id": request["request_id"],
        "request_sha256": MODULE.digest(encode(request)),
        "subject": subject,
        "request_state": "open",
        "producer_id": producer["producer_id"],
        "producer_sha256": MODULE.digest(encode(producer)),
        "verifier_id": replay["verifier_id"],
        "verifier_runtime_sha256": sha,
        "replay_sha256": MODULE.digest(encode(replay)),
        "case_roles": roles,
        "rounds": [1],
    }
    # These are synthetic projections, not signatures or raw timing records.
    return copy.deepcopy(context), {"request": request, "producer": producer, "replay": replay}


def bound_blobs(context, documents):
    """Rebind only private fixtures to reach checks beyond the outer digest gate."""
    documents["producer"]["request_sha256"] = MODULE.digest(encode(documents["request"]))
    documents["replay"]["request_sha256"] = documents["producer"]["request_sha256"]
    documents["replay"]["producer_sha256"] = MODULE.digest(encode(documents["producer"]))
    blobs = {key: encode(value) for key, value in documents.items()}
    for key, value in blobs.items():
        context[key + "_sha256"] = MODULE.digest(value)
    return blobs


class EvidenceInspection(unittest.TestCase):
    def test_full_inventory_never_grants_admission_or_claims_replay(self):
        context, documents = fixture()
        result = MODULE.inspect(context, {key: encode(v) for key, v in documents.items()}, 125)
        assert result["cases"] == 42
        for name in (
            "ci_admission",
            "authentication_performed",
            "raw_replay_performed",
            "request_consumed",
        ):
            assert result[name] is False

    def test_modified_file_rejected_before_semantic_processing(self):
        for name in ("request", "producer", "replay"):
            with self.subTest(name=name):
                context, documents = fixture()
                blobs = {key: encode(v) for key, v in documents.items()}
                blobs[name] += b" "
                with pytest.raises(ValueError, match=f"{name} bytes not bound"):
                    MODULE.inspect(context, blobs, 125)

    def test_rebound_fixture_failures(self):
        conditions = [
            ("producer", "execution_kind", "imported", "not a fresh"),
            ("producer", "operation", "cancelled", "not complete"),
            ("producer", "completed_at", 101, "acquisition deadline"),
            ("producer", "recovered_at", 121, "recovery outside"),
            ("producer", "started_at", True, "integer required"),
            ("producer", "producer_id", "foreign", "producer mismatch"),
            ("replay", "replayed_at", 126, "replay time"),
            ("replay", "verifier_id", "fixture-producer", "verifier identity"),
            ("replay", "verifier_runtime_sha256", "2" * 64, "runtime mismatch"),
            ("replay", "recovery_manifest_sha256", "2" * 64, "recovery mismatch"),
            ("request", "expires_at", 125, "expired or future"),
        ]
        for name, key, value, reason in conditions:
            with self.subTest(name=name, key=key):
                context, documents = fixture()
                documents[name][key] = value
                with pytest.raises(ValueError, match=reason):
                    MODULE.inspect(context, bound_blobs(context, documents), 125)

    def test_incomplete_duplicate_or_extra_inventory(self):
        for name, field in (
            ("request", "inventory"),
            ("producer", "observations"),
            ("replay", "results"),
        ):
            for operation in ("missing", "duplicate", "extra"):
                with self.subTest(name=name, operation=operation):
                    context, documents = fixture()
                    rows = documents[name][field]
                    if operation == "missing":
                        rows.pop()
                    else:
                        row = copy.deepcopy(rows[0])
                        if operation == "extra":
                            row["id"] = "unplanned"
                        rows.append(row)
                    with pytest.raises(ValueError, match=r"inventory|ID|result|mismatch"):
                        MODULE.inspect(context, bound_blobs(context, documents), 125)

    def test_case_compiler_role_round_and_elf_substitution(self):
        for key, value in (
            ("case_id", "nix/unknown"),
            ("compiler", "other"),
            ("round", 2),
            ("round", True),
            ("role", "public_fixture_characterization"),
            ("elf_sha256", "2" * 64),
        ):
            with self.subTest(key=key):
                context, documents = fixture()
                documents["producer"]["inventory"][0][key] = value
                with pytest.raises(
                    ValueError,
                    match=r"mismatch|integer required",
                ):
                    MODULE.inspect(context, bound_blobs(context, documents), 125)

    def test_all_replay_failures_are_retained(self):
        for key, value in (
            ("qualification", "positive_statistic_not_detected"),
            ("qualification", "count_inconclusive"),
            ("collection", "partial"),
            ("prefix_verification", "future_frame"),
            ("numeric_validity", "unresolved"),
            ("original_retention", "missing"),
            ("looks", 7),
            ("looks", True),
            ("raw_manifest_sha256", "2" * 64),
            ("original_decisions_sha256", "2" * 64),
            ("effective_decisions_sha256", "2" * 64),
        ):
            with self.subTest(key=key, value=value):
                context, documents = fixture()
                documents["replay"]["results"][0][key] = value
                with pytest.raises(ValueError, match=r"not met|not complete|schedule|mismatch"):
                    MODULE.inspect(context, bound_blobs(context, documents), 125)

    def test_old_request_and_revision_mix(self):
        for field, value in (("request_id", "old"), ("request_state", "consumed")):
            context, documents = fixture()
            context[field] = value
            with pytest.raises(ValueError, match=r"identity mismatch|not open"):
                MODULE.inspect(context, bound_blobs(context, documents), 125)
        context, documents = fixture()
        documents["request"]["subject"]["target_revision"] = "b" * 40
        with pytest.raises(ValueError, match="subject mismatch"):
            MODULE.inspect(context, bound_blobs(context, documents), 125)

    def test_json_and_capacity_boundaries(self):
        for data in (
            b'{"x":1,"x":2}',
            b'{"x":NaN}',
            b'{"x":Infinity}',
            b"[]",
            b" " * (MODULE.MAX_BYTES + 1),
        ):
            with pytest.raises(
                ValueError, match=r"duplicate JSON|non-integer|object required|size bound"
            ):
                MODULE.decode(data)

    def test_inventory_order_and_regular_files(self):
        context, documents = fixture()
        documents["producer"]["inventory"].reverse()
        with pytest.raises(ValueError, match="ordered inventory mismatch"):
            MODULE.inspect(context, bound_blobs(context, documents), 125)
        with tempfile.TemporaryDirectory() as folder:
            fifo = Path(folder) / "fifo"
            os.mkfifo(fifo)
            with pytest.raises(ValueError, match="regular receipt file required"):
                MODULE.read_bounded(fifo)
            target = Path(folder) / "target"
            target.write_bytes(b"{}")
            link = Path(folder) / "link"
            link.symlink_to(target)
            with pytest.raises(OSError, match="symbolic links"):
                MODULE.read_bounded(link)

    def test_cli_reports_failures_and_shadow_only_success(self):
        context, documents = fixture()
        with tempfile.TemporaryDirectory() as folder:
            paths = {key: Path(folder) / f"{key}.json" for key in ("context", *documents)}
            for key, value in {"context": context, **documents}.items():
                paths[key].write_bytes(encode(value))
            cmd = [sys.executable, str(SCRIPT), "--now", "125"]
            for key, path in paths.items():
                cmd.extend([f"--{key}", str(path)])
            good = subprocess.run(cmd, capture_output=True, check=False, text=True)  # noqa: S603 - fixed local CLI and temporary fixtures
            assert good.returncode == 0, good.stdout + good.stderr
            assert not json.loads(good.stdout)["ci_admission"]
            paths["producer"].unlink()
            bad = subprocess.run(cmd, capture_output=True, check=False, text=True)  # noqa: S603 - fixed local CLI and temporary fixtures
            assert bad.returncode == 1
            assert json.loads(bad.stdout)["status"] == "rejected"


if __name__ == "__main__":
    unittest.main()
