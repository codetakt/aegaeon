"""Diagnostic mappings preserve historical obligations and full CI execution."""

from __future__ import annotations

# ruff: noqa: PT009, PT027 - unittest discovery and assertions remain active under -O.
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))
import ci_shadow_inputs as model_lib  # noqa: E402 - standalone discovery import
import report_input_selection as reporter  # noqa: E402 - standalone discovery import
from verify_ci_plan import load, tree_entries  # noqa: E402 - standalone discovery import

INVENTORY_BYTES = (ROOT / model_lib.INVENTORY_PATH).read_bytes()
INVENTORY = load(INVENTORY_BYTES)
AUTHORITY = load((ROOT / model_lib.AUTHORITY_PATH).read_bytes())
MODEL = load((ROOT / model_lib.MODEL_PATH).read_bytes())
BASELINE = "dcfffc73c5efb8c4ff621e4f60b50a0b9e9861fc"


class ModelTests(unittest.TestCase):
    def validate(self, value):
        model_lib.validate_model(value, INVENTORY_BYTES, INVENTORY, AUTHORITY)

    def test_current_model_and_historical_inventory_are_bound(self):
        self.validate(MODEL)
        self.assertEqual(len(MODEL["correspondence"]), 20)
        self.assertEqual(len(AUTHORITY["holds"]), 11)
        self.assertFalse(AUTHORITY["narrowing_adopted"])

    def test_changed_inventory_cannot_rebase_obligations_silently(self):
        with self.assertRaisesRegex(ValueError, "binding differs"):
            model_lib.validate_model(MODEL, INVENTORY_BYTES + b" ", INVENTORY, AUTHORITY)

    def test_empty_authority_cannot_produce_an_empty_full_plan(self):
        for key in ("producers", "holds"):
            authority = deepcopy(AUTHORITY)
            authority[key] = []
            with self.subTest(key=key), self.assertRaises(ValueError):
                model_lib.validate_model(MODEL, INVENTORY_BYTES, INVENTORY, authority)

    def test_model_cannot_claim_adoption_or_coverage_equivalence(self):
        for key, value in (
            ("mode", "adopted"),
            ("version", True),
            ("coverage_equivalence_claimed", True),
        ):
            candidate = deepcopy(MODEL)
            candidate[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.validate(candidate)

    def test_unknown_or_missing_fields_are_rejected(self):
        for field in ("unexpected", "mode"):
            candidate = deepcopy(MODEL)
            if field == "unexpected":
                candidate[field] = True
            else:
                del candidate[field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(candidate)

    def test_unknown_and_duplicate_old_test_ids_are_rejected(self):
        for operation in ("unknown", "duplicate"):
            candidate = deepcopy(MODEL)
            if operation == "unknown":
                candidate["correspondence"][0]["old"]["method"] = "test_unknown"
            else:
                candidate["correspondence"].append(candidate["correspondence"][0])
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                self.validate(candidate)

    def test_missing_and_duplicate_successor_ids_are_rejected(self):
        for related in ([], [MODEL["correspondence"][0]["related_current_tests"][0]] * 2):
            candidate = deepcopy(MODEL)
            candidate["correspondence"][0]["related_current_tests"] = related
            with self.subTest(related=related), self.assertRaises(ValueError):
                self.validate(candidate)

    def test_unknown_producers_complete_coverage_and_empty_holds_are_rejected(self):
        for key, value in (
            ("producer", "unregistered"),
            ("coverage", "complete"),
            ("holds", []),
            ("holds", ["unknown"]),
        ):
            candidate = deepcopy(MODEL)
            candidate["consumers"][0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.validate(candidate)

    def test_noncanonical_paths_are_not_selection_rules(self):
        for name in (
            "",
            "/absolute",
            "../outside",
            "a/../b",
            "a//b",
            "./a",
            "a\\b",
            "a\nb",
            "a/",
            "a\ud800b",
        ):
            candidate = deepcopy(MODEL)
            candidate["consumers"][0]["inputs"][0]["path"] = name
            with self.subTest(name=repr(name)), self.assertRaises(ValueError):
                self.validate(candidate)

    def test_output_exclusions_and_duplicate_rules_are_not_authorized(self):
        candidate = deepcopy(MODEL)
        candidate["consumers"][0]["inputs"][0]["kind"] = "exclude-output"
        with self.assertRaises(ValueError):
            self.validate(candidate)
        candidate = deepcopy(MODEL)
        candidate["consumers"][0]["inputs"].append(candidate["consumers"][0]["inputs"][0])
        with self.assertRaises(ValueError):
            self.validate(candidate)

    def test_additional_check_cannot_replace_a_historical_check(self):
        candidate = deepcopy(MODEL)
        candidate["additional_checks"][0]["name"] = INVENTORY["nix_static_checks"][0]
        with self.assertRaises(ValueError):
            self.validate(candidate)

    def test_all_historical_records_have_present_or_related_definitions(self):
        result = model_lib.inventory_report(
            MODEL, INVENTORY, lambda path: (ROOT / path).read_bytes()
        )
        self.assertEqual(result["historical_records"], 755)
        self.assertEqual(
            result["counts"], {"present": 735, "related-definitions-present": 20, "unresolved": 0}
        )
        self.assertEqual(result["source_errors"], {})
        self.assertEqual(result["historical_nix_checks"], INVENTORY["nix_static_checks"])
        self.assertFalse(result["coverage_equivalence_claimed"])

    def test_missing_current_source_is_unresolved_not_retired(self):
        def read(path):
            if path == "tests/ci/test_dudect_runner.py":
                model_lib.require(False, "source deliberately missing")
            return (ROOT / path).read_bytes()

        result = model_lib.inventory_report(MODEL, INVENTORY, read)
        self.assertEqual(result["historical_records"], 755)
        self.assertGreaterEqual(result["counts"]["unresolved"], 14)
        self.assertIn("tests/ci/test_dudect_runner.py", result["source_errors"])

    def test_renamed_successor_is_not_implicitly_equivalent(self):
        candidate = deepcopy(MODEL)
        candidate["correspondence"][0]["related_current_tests"][0]["method"] = (
            "test_missing_successor"
        )
        result = model_lib.inventory_report(
            candidate, INVENTORY, lambda path: (ROOT / path).read_bytes()
        )
        self.assertEqual(result["counts"]["unresolved"], 1)

    def test_lexical_inspection_never_executes_candidate_source(self):
        value = (
            b'raise RuntimeError("must not execute")\nclass Example:\n def test_one(self): pass\n'
        )
        self.assertEqual(model_lib.python_definitions(value), {("Example", "test_one")})
        result = model_lib.inventory_report(MODEL, INVENTORY, lambda _path: b"invalid Python !")
        self.assertEqual(result["counts"]["unresolved"], 755)
        self.assertTrue(result["source_errors"])


class ShadowSelectionTests(unittest.TestCase):
    def evaluate(self, *names):
        changes = [{"decoded_path": name, "snapshots": {}} for name in names]
        result = model_lib.selection_report(changes, MODEL, AUTHORITY)
        self.assertEqual(result["authoritative_scope"], "full")
        self.assertEqual(result["conservative_producers"], AUTHORITY["producers"])
        self.assertEqual(result["unresolved_holds"], AUTHORITY["holds"])
        self.assertIs(result["omissions_enabled"], False)
        self.assertIs(result["adoption_eligible"], False)
        return result

    def test_workflow_only_change_retains_its_rust_guard(self):
        result = self.evaluate(".github/workflows/performance.yml")
        self.assertEqual(
            result["changes"][0]["known_matches"][0]["consumer"], "retired-runtime-fixture"
        )
        self.assertIn(".github/workflows/ci.yml::ci", result["directly_affected_producers"])

    def test_absence_paths_include_new_directory_descendants(self):
        result = self.evaluate(
            "crates/server/build.rs",
            "crates/server/build.rs/unexpected-directory-child",
            "crates/server/src/runtime_fixture_seed/new.rs",
        )
        for row in result["changes"]:
            guard = next(
                item
                for item in row["known_matches"]
                if item["consumer"] == "retired-runtime-fixture"
            )
            self.assertTrue(any(item["kind"].startswith("absent-") for item in guard["rules"]))

    def test_tree_matching_does_not_capture_adjacent_names(self):
        self.assertTrue(model_lib.matches("fuzz/input", {"kind": "tree", "path": "fuzz"}))
        self.assertFalse(model_lib.matches("fuzz-new/input", {"kind": "tree", "path": "fuzz"}))

    def test_unknown_docs_outputs_and_invalid_paths_keep_full_selection(self):
        for name in (
            "docs/new.md",
            "artifacts/security-upload/new",
            "unknown.txt",
            None,
            "bad\npath",
        ):
            with self.subTest(name=name):
                result = self.evaluate(name)
                self.assertEqual(result["unclassified_change_count"], 1)

    def test_empty_diff_does_not_authorize_an_empty_plan(self):
        result = self.evaluate()
        self.assertEqual(result["changes"], [])
        self.assertEqual(result["directly_affected_producers"], [])

    def test_model_edit_is_not_permission_to_omit_checks(self):
        result = self.evaluate(model_lib.MODEL_PATH)
        self.assertEqual(result["unclassified_change_count"], 1)

    def test_live_transport_and_workflows_do_not_consume_shadow_output(self):
        transport = (ROOT / "scripts/ci/verify_ci_plan.py").read_text()
        self.assertIn('"scope": "full"', transport)
        self.assertIn('"selected": LANES', transport)
        for path in (ROOT / ".github/workflows").glob("*.yml"):
            self.assertNotIn("report_input_selection", path.read_text())
            self.assertNotIn("directly_affected_producers", path.read_text())


class GitInputTests(unittest.TestCase):
    def setUp(self):
        self.repo = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.command("init", "--quiet")

    def command(self, *args, data=None):
        return subprocess.check_output(  # noqa: S603 - commitless fixed Git fixture
            ["git", "-C", str(self.repo), *args],  # noqa: S607 - fixed Git tool
            input=data,
            stderr=subprocess.PIPE,
        )

    def tree(self, values):
        rows = []
        for path, mode, content in values:
            oid = self.command("hash-object", "-w", "--stdin", data=content).strip()
            rows.append(mode.encode() + b" blob " + oid + b"\t" + path + b"\0")
        return self.command("mktree", "-z", data=b"".join(rows)).strip().decode()

    def nested_tree(self, files):
        rows = []
        directories = {}
        for name, content in sorted(files.items()):
            if "/" in name:
                directory, rest = name.split("/", 1)
                directories.setdefault(directory, {})[rest] = content
            else:
                oid = self.command("hash-object", "-w", "--stdin", data=content).strip()
                rows.append(b"100644 blob " + oid + b"\t" + name.encode() + b"\0")
        for name, children in directories.items():
            oid = self.nested_tree(children).encode()
            rows.append(b"040000 tree " + oid + b"\t" + name.encode() + b"\0")
        return self.command("mktree", "-z", data=b"".join(rows)).strip().decode()

    def test_report_reads_immutable_model_and_test_source_without_execution(self):
        old = {"path": "test.py", "class": "Example", "method": "test_old"}
        new = {**old, "method": "test_new"}
        inventory = {
            "source_candidates": {"python_test_methods": [old]},
            "nix_static_checks": ["tests"],
        }
        raw = json.dumps(inventory).encode()
        model = deepcopy(MODEL)
        model["inventory_sha256"] = hashlib.sha256(raw).hexdigest()
        model["correspondence"] = [
            {
                "old": old,
                "disposition": "execution-path-changed",
                "related_current_tests": [new],
                "reason": "controlled correspondence fixture",
            }
        ]
        files = {
            model_lib.INVENTORY_PATH: raw,
            model_lib.AUTHORITY_PATH: json.dumps(AUTHORITY).encode(),
            "test.py": b"class Example:\n def test_new(self): pass\n",
        }
        base = self.nested_tree(files)
        model_tree = self.nested_tree({**files, model_lib.MODEL_PATH: json.dumps(model).encode()})
        (self.repo / "test.py").write_text('raise RuntimeError("working tree must not be used")')
        original_git = reporter.git

        def git_call(repo, *args):
            if args[:2] == ("merge-base", "--is-ancestor"):
                return b""  # Commit ancestry is tested separately; this fixture creates only trees.
            return original_git(repo, *args)

        revisions = {"base": base, "head": base, "tested": base, "model": model_tree}
        with (
            patch.object(reporter, "commit", side_effect=lambda _repo, oid: oid),
            patch.object(reporter, "git", side_effect=git_call),
        ):
            result = reporter.report(self.repo, revisions)
        self.assertFalse(result["model_is_protected_base"])
        self.assertFalse(result["adoption_eligible"])
        self.assertEqual(result["inventory"]["counts"]["related-definitions-present"], 1)
        self.assertEqual(result["conservative_producers"], AUTHORITY["producers"])
        self.assertEqual(
            result["model_sha256"], hashlib.sha256(json.dumps(model).encode()).hexdigest()
        )

    def changes(self, base, head, tested):
        snapshots = {
            name: tree_entries(self.repo, tree)
            for name, tree in zip(("base", "head", "tested"), (base, head, tested), strict=True)
        }
        return reporter.changed_entries(snapshots)

    def test_rename_records_both_removed_and_added_paths(self):
        base = self.tree([(b"old", "100644", b"same")])
        head = self.tree([(b"new", "100644", b"same")])
        changes = self.changes(base, head, head)
        self.assertEqual([row["decoded_path"] for row in changes], ["new", "old"])

    def test_tested_only_changes_and_reverted_head_are_retained(self):
        base = self.tree([(b"input", "100644", b"old")])
        head = self.tree([(b"input", "100644", b"head")])
        tested = self.tree([(b"input", "100644", b"tested")])
        self.assertEqual(len(self.changes(base, base, tested)), 1)
        self.assertEqual(len(self.changes(base, head, base)), 1)
        self.assertEqual(len(self.changes(base, head, tested)), 1)

    def test_mode_symlink_and_nonutf8_paths_are_literal_changes(self):
        base = self.tree([(b"input", "100644", b"same")])
        tested = self.tree(
            [
                (b"input", "100755", b"same"),
                (b"link", "120000", b"/outside"),
                (b"bad\xff", "100644", b"unknown"),
            ]
        )
        changes = self.changes(base, base, tested)
        self.assertEqual(len(changes), 3)
        self.assertIsNone(changes[0]["decoded_path"])
        self.assertEqual(changes[2]["snapshots"]["tested"]["type"], "symlink")
        with self.assertRaisesRegex(ValueError, "nonregular"):
            reporter.source_blob(self.repo, tree_entries(self.repo, tested), "link")

    def test_source_size_and_absence_are_rejected_before_reading(self):
        tree = self.tree([(b"input", "100644", b"long input")])
        entries = tree_entries(self.repo, tree)
        with (
            patch.object(reporter, "MAX_SOURCE", 3),
            self.assertRaisesRegex(ValueError, "size limit"),
        ):
            reporter.source_blob(self.repo, entries, "input")
        with self.assertRaisesRegex(ValueError, "missing"):
            reporter.source_blob(self.repo, entries, "missing")

    def test_inherited_git_override_and_unbound_revisions_are_rejected(self):
        with patch.dict(os.environ, {"GIT_DIR": "/unrelated"}), self.assertRaises(ValueError):
            reporter.commit(ROOT, BASELINE)
        for value in ("HEAD", "main", "--help", BASELINE[:8]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                reporter.commit(ROOT, value)

    def test_cli_failure_has_no_success_report(self):
        result = subprocess.run(  # noqa: S603 - fixed diagnostic CLI
            [
                sys.executable,
                str(ROOT / "scripts/ci/report_input_selection.py"),
                "--repo",
                str(ROOT),
                "--base",
                "HEAD",
                "--head",
                BASELINE,
                "--tested",
                BASELINE,
            ],
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"full commit identity", result.stderr)


if __name__ == "__main__":
    unittest.main()
