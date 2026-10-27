"""Keep compliance-matrix reference edits on an integrity-containing check lane.

This is a candidate-policy regression guard. Live selection remains controlled
by the existing protected-base planner; no snapshot script is executed here.
"""

# Unittest discovery owns this guard; its assertions also run with Python -O.
# ruff: noqa: PT009, PT027
from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path, PurePosixPath
from unittest.mock import patch

import yaml
from jsonschema import validate
from jsonschema.exceptions import SchemaError, ValidationError
from jsonschema.validators import validator_for

ROOT = Path(__file__).resolve().parents[2]
MATRIX_PATH = "spec/compliance-matrix.yaml"
SCHEMA_PATH = "spec/compliance-matrix.schema.json"
MISSING_PATHS = (
    "docs/policies/oauth-doc-only-rfcs.md",
    "docs/policies/saml-facade-policy.md",
    "docs/policies/verified-crypto-policy.md",
    "docs/program-management/historical/roadmaps/oidc-execution-plan.md",
    "docs/program-management/initiatives/oauth/oauth-formal-verification-plan.md",
    "docs/program-management/roadmaps/active/oauth-rfc-coverage-roadmap.md",
)
REFERENCE_KEYS = {"module", "document", "artefact", "file", "spec"}
COMMIT_ID = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
UNSET = object()


def live_module(name, relative):
    """Import installed/current repository semantics, never Git snapshot scripts."""
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    if spec is None or spec.loader is None:
        message = f"current module unavailable: {relative}"
        raise RuntimeError(message)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


planner = live_module("current_pr_plan", "scripts/ci/pr_plan.py")
validator = live_module(
    "current_matrix_validator", "scripts/validation/validate_compliance_matrix.py"
)
POLICY = json.loads(
    (ROOT / "ci/pr-policy.json").read_text(), object_pairs_hook=planner.unique_json_object
)


def reject(message):
    raise ValueError(message)


class UniqueSafeLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        keys = [self.construct_object(key, deep=deep) for key, _value in node.value]
        if len(set(keys)) != len(keys):
            reject("duplicate YAML mapping key")
        return super().construct_mapping(node, deep=deep)


def matrix_data(raw):
    # SafeLoader disables YAML object construction; duplicate keys cannot erase refs.
    return yaml.load(raw, Loader=UniqueSafeLoader)  # noqa: S506 - duplicate-detecting SafeLoader


def schema_data(raw):
    schema = json.loads(raw, object_pairs_hook=planner.unique_json_object)
    if not isinstance(schema, dict) or not schema:
        reject("missing or empty compliance-matrix schema")
    check_schema_references(schema)
    validator_for(schema).check_schema(schema)
    return schema


def check_schema_references(value):
    """Keep matrix/schema data validation local; do not dereference external inputs."""
    if isinstance(value, dict):
        for key, child in value.items():
            if key in {"$ref", "$dynamicRef", "$recursiveRef"} and (
                not isinstance(child, str) or not child.startswith("#")
            ):
                reject("only local-fragment schema references are supported")
            check_schema_references(child)
    elif isinstance(value, list):
        for child in value:
            check_schema_references(child)


def valid_reference(value):
    if not isinstance(value, str) or not value or value != value.strip():
        reject("empty or non-string matrix reference")
    path = PurePosixPath(value)
    if (
        not path.parts
        or path.is_absolute()
        or ".." in path.parts
        or path.as_posix() != value
        or "\\" in value
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        reject(f"invalid matrix reference representation: {value!r}")


def check_reference_representations(value, active=None):  # noqa: PLR0912 - invalid fields/cycles
    """Reject inputs collect_paths would silently ignore, and recursive YAML aliases."""
    if not isinstance(value, (dict, list)):
        return
    active = set() if active is None else active
    if id(value) in active:
        reject("recursive matrix data")
    active.add(id(value))
    if isinstance(value, dict):
        for key, child in value.items():
            if key in REFERENCE_KEYS:
                valid_reference(child)
            elif key == "tests":
                if not isinstance(child, list):
                    reject("matrix tests must be a list of paths")
                for item in child:
                    valid_reference(item)
            check_reference_representations(child, active)
    else:
        for child in value:
            check_reference_representations(child, active)
    active.remove(id(value))


def validated_paths(data, schema):
    if not isinstance(data, dict) or not data:
        reject("missing or empty compliance matrix")
    check_reference_representations(data)
    check_schema_references(schema)
    validate(instance=data, schema=schema)
    paths = set(validator.collect_paths(data))
    if not paths:
        reject("compliance matrix has no collected references")
    return paths


def assert_reference_selection(base_data, candidate_data, base_schema, candidate_schema, policy):
    planner.validate_policy(policy)
    paths = validated_paths(base_data, base_schema) | validated_paths(
        candidate_data, candidate_schema
    )
    for path in sorted(paths):
        result = planner.classify([change(path)], policy)
        if "integrity" not in result["selected"]:
            reject(f"matrix reference selects no integrity checks: {path}")
    return paths


def change(path, status="M", old_mode="100644", new_mode="100644"):
    return {"path": path, "status": status, "old_mode": old_mode, "new_mode": new_mode}


def guard_base(repo, environment):
    if environment.get("GITHUB_ACTIONS") == "true":
        base = environment.get("PR_BASE_SHA")
        if not isinstance(base, str) or not COMMIT_ID.fullmatch(base):
            reject("hosted guard requires planner's full PR_BASE_SHA commit ID")
    else:
        # This is an inspected local reference; it is not live selection authority.
        base = planner.git(repo, "rev-parse", "refs/remotes/origin/main^{commit}").decode().strip()
    if (
        not COMMIT_ID.fullmatch(base)
        or planner.git(repo, "cat-file", "-t", base).strip() != b"commit"
    ):
        reject("matrix guard base is not a full real commit")
    return base


def repository_guard(repo, environment):
    base = guard_base(repo, environment)
    base_matrix = matrix_data(planner.git(repo, "show", f"{base}:{MATRIX_PATH}"))
    base_schema = schema_data(planner.git(repo, "show", f"{base}:{SCHEMA_PATH}"))
    candidate_matrix = matrix_data((repo / MATRIX_PATH).read_bytes())
    candidate_schema = schema_data((repo / SCHEMA_PATH).read_bytes())
    policy = json.loads(
        (repo / "ci/pr-policy.json").read_bytes(), object_pairs_hook=planner.unique_json_object
    )
    return base, assert_reference_selection(
        base_matrix, candidate_matrix, base_schema, candidate_schema, policy
    )


def fixture_matrix(document="docs/policies/oauth-doc-only-rfcs.md"):
    return {
        "metadata": {"description": "selection regression fixture", "standards": ["fixture"]},
        "global": [
            {
                "id": "fixture",
                "requirement": "MUST",
                "description": "fixture",
                "module": "src/reference.rs",
                "status": "planned",
                "proof": [{"type": "policy", "document": document}],
            }
        ],
    }


class MatrixCheckSelectionTests(unittest.TestCase):
    def setUp(self):
        self.schema = schema_data((ROOT / SCHEMA_PATH).read_bytes())
        self.base = matrix_data((ROOT / MATRIX_PATH).read_bytes())
        self.policy = deepcopy(POLICY)

    def guard(self, base=UNSET, candidate=UNSET, policy=UNSET):
        return assert_reference_selection(
            self.base if base is UNSET else base,
            self.base if candidate is UNSET else candidate,
            self.schema,
            self.schema,
            self.policy if policy is UNSET else policy,
        )

    def test_actual_base_and_candidate_reference_union_selects_integrity(self):
        _base, paths = repository_guard(ROOT, os.environ)
        self.assertTrue(paths)

    def test_actual_collect_paths_semantics_not_arbitrary_yaml_strings(self):
        data = fixture_matrix()
        data["global"][0]["proof"][0].update(
            {
                "file": "proofs/check.c",
                "spec": "spec/check.json",
                "artefact": "output/check.bin",
            }
        )
        data["global"][0]["tests"] = ["tests/check.rs"]
        data["global"][0]["notes"] = ["docs/uncategorized-prose.md"]
        paths = validated_paths(data, self.schema)
        self.assertEqual(paths, set(validator.collect_paths(data)))
        self.assertNotIn("docs/uncategorized-prose.md", paths)
        for field in REFERENCE_KEYS:
            self.assertTrue(
                any(field in item for item in [data["global"][0], data["global"][0]["proof"][0]])
            )

    def test_six_registrations_preserve_original_lanes_and_legacy_failure(self):
        self.assertTrue(set(MISSING_PATHS).issubset(POLICY["integrity_paths"]))
        self.assertEqual(POLICY["scopes"]["full"], list(planner.ORIGINAL_LANES))
        self.assertEqual(POLICY["supplemental_lanes"], {"components": "pending"})
        legacy = deepcopy(POLICY)
        legacy["integrity_paths"] = [p for p in legacy["integrity_paths"] if p not in MISSING_PATHS]
        for path in MISSING_PATHS:
            self.assertIn("integrity", planner.classify([change(path)], POLICY)["selected"])
            self.assertEqual(planner.classify([change(path)], legacy)["scope"], "docs")
        # A protected base that already includes the correction remains valid.
        self.guard()

    def test_new_document_reference_requires_registration_and_unknown_path_keeps_full(self):
        base = fixture_matrix()
        candidate = fixture_matrix("docs/new-evidence-reference.md")
        with self.assertRaises(ValueError):
            self.guard(base, candidate)
        self.policy["integrity_paths"].append("docs/new-evidence-reference.md")
        self.guard(base, candidate)
        unknown = fixture_matrix("unknown/reference.dat")
        self.guard(base, unknown)
        self.assertEqual(
            planner.classify([change("unknown/reference.dat")], self.policy)["scope"], "full"
        )

    def test_coherent_rename_and_deletion_keep_base_references(self):
        old, new = MISSING_PATHS[0], "docs/policies/renamed-evidence.md"
        base, candidate = fixture_matrix(old), fixture_matrix(new)
        self.policy["integrity_paths"].append(new)
        self.guard(base, candidate)
        self.policy["integrity_paths"].remove(old)
        with self.assertRaises(ValueError):
            self.guard(base, candidate)
        deleted = fixture_matrix()
        deleted["global"][0]["proof"] = []
        with self.assertRaises(ValueError):
            self.guard(base, deleted)
        self.policy["integrity_paths"].append(old)
        self.guard(base, deleted)

    def test_no_reference_existence_filter(self):
        candidate = fixture_matrix("docs/policies/nonexistent-evidence.md")
        self.policy["integrity_paths"].append("docs/policies/nonexistent-evidence.md")
        paths = self.guard(fixture_matrix(), candidate)
        self.assertIn("docs/policies/nonexistent-evidence.md", paths)
        self.policy["integrity_paths"].remove("docs/policies/nonexistent-evidence.md")
        with self.assertRaises(ValueError):
            self.guard(fixture_matrix(), candidate)

    def test_malformed_empty_or_unsafe_matrix_and_schema_fail(self):
        for raw in (
            b"",
            b"[]",
            b"null",
            b"not: [yaml",
            b"!!python/object/apply:os.system ['false']",
            b"metadata: {}\nmetadata: {}\n",
        ):
            with (
                self.subTest(raw=raw),
                self.assertRaises((ValueError, yaml.YAMLError, ValidationError)),
            ):
                self.guard(candidate=matrix_data(raw))
        for data in (
            {},
            {"metadata": {"description": "empty", "standards": ["fixture"]}},
            {"metadata": {"standards": []}},
        ):
            with self.subTest(data=data), self.assertRaises((ValueError, ValidationError)):
                assert_reference_selection(self.base, data, self.schema, self.schema, self.policy)
        for raw in (
            b"",
            b"{}",
            b"[]",
            b"{broken",
            b'{"type":"object","type":"string"}',
            b'{"type":7}',
        ):
            with self.subTest(schema=raw), self.assertRaises((ValueError, SchemaError)):
                schema_data(raw)

    def test_invalid_reference_representations_cannot_shrink_collection(self):
        for value in (
            "",
            "../outside.md",
            "/absolute.md",
            "docs//same.md",
            "docs/../escape.md",
            "docs/control\n.md",
            " docs/space.md",
            None,
            {},
            [],
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.guard(candidate=fixture_matrix(value))
        for value in ({"file": "docs/hidden.md"}, [None], [{"file": "docs/hidden.md"}]):
            candidate = fixture_matrix()
            candidate["global"][0]["tests"] = value
            with self.subTest(tests=value), self.assertRaises(ValueError):
                self.guard(candidate=candidate)
        recursive = fixture_matrix()
        recursive["metadata"]["cycle"] = recursive
        with self.assertRaises(ValueError):
            self.guard(candidate=recursive)

    def test_external_schema_references_fail_before_validation(self):
        for keyword in ("$ref", "$dynamicRef", "$recursiveRef"):
            for reference in (
                "https://schema.example.test/input.json",
                "file:///tmp/schema.json",
                "relative/schema.json",
                "",
                None,
            ):
                schema = deepcopy(self.schema)
                schema["definitions"]["requirement"][keyword] = reference
                with self.subTest(keyword=keyword, reference=reference):
                    with self.assertRaises(ValueError):
                        schema_data(json.dumps(schema))
                    with patch(f"{__name__}.validate") as validation:
                        with self.assertRaises(ValueError):
                            validated_paths(fixture_matrix(), schema)
                        validation.assert_not_called()
        # The existing internal definitions remain supported by real validation.
        self.guard()

    def test_candidate_policy_tampering_cannot_authorize_live_selection(self):
        tampered = deepcopy(self.policy)
        tampered["integrity_paths"] = []
        with self.assertRaises(ValueError):
            self.guard(policy=tampered)
        tampered = deepcopy(self.policy)
        tampered["scopes"]["full"].remove("integrity")
        with self.assertRaises(ValueError):
            self.guard(policy=tampered)
        # Editing the candidate policy or guard selects full under protected policy.
        original = json.loads(
            planner.git(ROOT, "show", f"{guard_base(ROOT, {})}:ci/pr-policy.json")
        )
        for path in ("ci/pr-policy.json", "tests/ci/test_matrix_check_selection.py"):
            self.assertEqual(planner.classify([change(path)], original)["scope"], "full")

    def test_hosted_base_requires_full_real_planner_commit_and_local_ref_is_inspected(self):
        base = guard_base(ROOT, {})
        self.assertEqual(guard_base(ROOT, {"GITHUB_ACTIONS": "true", "PR_BASE_SHA": base}), base)
        for value in (None, "", "main", "HEAD", base[:12], "0" * len(base)):
            with (
                self.subTest(value=value),
                self.assertRaises((ValueError, subprocess.CalledProcessError)),
            ):
                guard_base(ROOT, {"GITHUB_ACTIONS": "true", "PR_BASE_SHA": value})
        tree = planner.git(ROOT, "rev-parse", f"{base}^{{tree}}").decode().strip()
        with self.assertRaises(ValueError):
            guard_base(ROOT, {"GITHUB_ACTIONS": "true", "PR_BASE_SHA": tree})
        self.assertEqual(guard_base(ROOT, {"PR_BASE_SHA": "candidate-override"}), base)
        with (
            patch.object(planner, "git", side_effect=subprocess.CalledProcessError(128, "git")),
            self.assertRaises(subprocess.CalledProcessError),
        ):
            guard_base(ROOT, {})

    def test_hosted_base_transport_is_from_protected_planner(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/pr.yml").read_text())
        docs = workflow["jobs"]["docs"]
        self.assertEqual(docs["needs"], "plan")
        self.assertEqual(docs["uses"], "./.github/workflows/documentation.yml")
        self.assertEqual(docs["with"]["base"], "${{ needs.plan.outputs.base }}")
        self.assertEqual(docs["with"]["source-head"], "${{ needs.plan.outputs.source_head }}")
        self.assertEqual(docs["with"]["test-sha"], "${{ needs.plan.outputs.test_sha }}")
        reusable = yaml.safe_load((ROOT / ".github/workflows/documentation.yml").read_text())
        for name in ("base", "source-head", "test-sha"):
            self.assertEqual(
                reusable[True]["workflow_call"]["inputs"][name],
                {"required": True, "type": "string"},
            )
        helper = next(
            step
            for step in reusable["jobs"]["helpers"]["steps"]
            if "run_ci_helpers.py run" in step.get("run", "")
        )
        self.assertEqual(helper["env"]["PR_BASE_SHA"], "${{ inputs.base }}")
        metadata = next(
            step
            for step in reusable["jobs"]["metadata"]["steps"]
            if "PR_BASE_SHA" in step.get("env", {})
        )
        self.assertEqual(metadata["env"]["PR_BASE_SHA"], "${{ inputs.base }}")
        self.assertEqual(metadata["env"]["PR_HEAD_SHA"], "${{ inputs.source-head }}")
        for job in reusable["jobs"].values():
            checkout = next(
                step
                for step in job["steps"]
                if step.get("uses", "").startswith("actions/checkout@")
            )
            self.assertEqual(
                checkout["with"],
                {"ref": "${{ inputs.test-sha }}", "fetch-depth": 0, "persist-credentials": False},
            )
        source = (ROOT / "scripts/ci/validate_change.py").read_text()
        self.assertIn('git("merge-base", "--is-ancestor", ancestor, test_sha)', source)
        self.assertNotIn("import yaml", (ROOT / "scripts/ci/pr_plan.py").read_text())

    def test_actual_git_no_renames_keeps_deleted_and_added_evidence_paths(self):
        base = guard_base(ROOT, {})
        old, new = MISSING_PATHS[0], "docs/policies/renamed-evidence.md"
        blob = planner.git(ROOT, "rev-parse", f"{base}:{old}").decode().strip()
        with tempfile.TemporaryDirectory() as temporary:
            environment = {**os.environ, "GIT_INDEX_FILE": str(Path(temporary) / "index")}

            def indexed_git(*args):
                return subprocess.check_output(  # noqa: S603 - fixed Git argv and existing objects
                    ["git", "-C", str(ROOT), *args],  # noqa: S607 - pinned shell Git
                    env=environment,
                )

            indexed_git("read-tree", base)
            indexed_git("update-index", "--force-remove", "--", old)
            indexed_git("update-index", "--add", "--cacheinfo", "100644", blob, new)
            raw = indexed_git(
                "diff", "--cached", "--raw", "-z", "--no-renames", "--no-ext-diff", base, "--"
            )
            changes = planner.parse_changes(raw)
            self.assertEqual(
                {(item["path"], item["status"]) for item in changes}, {(old, "D"), (new, "A")}
            )
            self.assertIn("integrity", planner.classify(changes, self.policy)["selected"])
            indexed_git("update-index", "--force-remove", "--", new)
            deleted = planner.parse_changes(
                indexed_git(
                    "diff", "--cached", "--raw", "-z", "--no-renames", "--no-ext-diff", base, "--"
                )
            )
            self.assertEqual([(item["path"], item["status"]) for item in deleted], [(old, "D")])
            self.assertIn("integrity", planner.classify(deleted, self.policy)["selected"])


if __name__ == "__main__":
    unittest.main()
