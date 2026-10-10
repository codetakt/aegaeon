"""Synthetic original-discovery, fixture and complete-worker accounting controls."""
# ruff: noqa: PT009, PT027 - unittest assertions remain active independently of pytest

from __future__ import annotations

import copy
import io
import json
import sys
import tempfile
import unittest
from collections import Counter
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

import run_ci_helpers as helpers
from run_ci_helpers import GROUPS, aggregate, partition, suite_leaves

BOUND = {
    "source": "a" * 40,
    "tree": "b" * 40,
    "run_id": "123",
    "attempt": "1",
    "configuration": "c" * 64,
}
DEPENDENCIES = {"metadata": {"result": "success"}, "helpers": {"result": "success"}}


class HelperShardTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.start = self.root / "tests/ci"
        self.start.mkdir(parents=True)
        self.modules = (
            "test_sanitizer_shard_fixture",
            "test_security_fuzz_shard_fixture",
            "test_other_shard_fixture",
        )
        self.original_path = list(sys.path)
        self.addCleanup(self.clean_modules)
        for name in self.modules:
            self.write(
                name,
                """import unittest
marks = []
def setUpModule():
    marks.append("module")
class Cases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        marks.append("class")
    def test_pass(self):
        marks.append("test")
""",
            )

    def clean_modules(self):
        sys.path[:] = self.original_path
        for name, module in list(sys.modules.items()):
            filename = vars(module).get("__file__") if module is not None else None
            if filename and str(filename).startswith(str(self.root)):
                del sys.modules[name]

    def write(self, name, text):
        (self.start / (name + ".py")).write_text(text)

    def load(self):
        loader = unittest.TestLoader()
        return loader, loader.discover(start_dir=str(self.start), pattern="test_*.py")

    def receipts(self):
        receipts = []
        for group in GROUPS:
            _, suite = self.load()
            with (
                mock.patch.object(helpers, "ROOT", self.root),
                mock.patch.object(helpers, "context", return_value=BOUND),
                mock.patch.object(unittest.TestLoader, "discover", return_value=suite),
                redirect_stderr(io.StringIO()),
            ):
                receipts.append(helpers.run_group(group))
        return receipts

    def test_original_discovery_complete_union_and_module_class_fixtures(self):
        receipts = self.receipts()
        aggregate(receipts, BOUND, DEPENDENCIES)
        self.assertEqual({row["mode"] for row in receipts}, {"normal"})
        self.assertEqual(sum(row["tests_run"] for row in receipts), 3)
        for name in self.modules:
            self.assertEqual(sys.modules[name].marks, ["module", "class", "test"])

    def test_added_modules_methods_and_inherited_cases_remain_in_complete_union(self):
        self.write(
            "test_new_helper_shard_fixture",
            """import unittest
class Base(unittest.TestCase):
    def test_inherited(self): pass
class Derived(Base):
    def test_added(self): pass
""",
        )
        receipts = self.receipts()
        aggregate(receipts, BOUND, DEPENDENCIES)
        other = next(row for row in receipts if row["group"] == "other")
        self.assertEqual(other["tests_run"], 4)
        self.assertEqual(sum(row["tests_run"] for row in receipts), 6)

    def test_duplicate_original_occurrences_are_preserved_without_deduplication(self):
        _, suite = self.load()
        leaves = suite_leaves(suite)
        duplicate = leaves[0]
        suite.addTest(duplicate)
        # Repeated defining modules are a fixture boundary: retain full route.
        selected, full, mode = partition(suite, "other", self.start)
        self.assertIs(selected, suite)
        self.assertEqual(mode, "full-fallback")
        self.assertEqual(Counter(row["id"] for row in full)[duplicate.id()], 2)

    def test_unresolvable_foreign_cases_use_original_full_suite(self):
        suite = unittest.TestSuite([unittest.FunctionTestCase(lambda: None)])
        selected, full, mode = partition(suite, "sanitizer", self.start)
        self.assertIs(selected, suite)
        self.assertEqual((len(full), mode), (1, "full-fallback"))

    def test_custom_discovery_hook_retains_original_suite(self):
        self.write(
            self.modules[0],
            (self.start / (self.modules[0] + ".py")).read_text()
            + """
def load_tests(loader, tests, pattern):
    return tests
""",
        )
        receipts = self.receipts()
        self.assertEqual({row["mode"] for row in receipts}, {"full-fallback"})
        self.assertTrue(all(row["tests_run"] == 3 for row in receipts))
        aggregate(receipts, BOUND, DEPENDENCIES)

    def test_import_error_cannot_become_an_empty_successful_shard(self):
        self.write(
            "test_broken_helper_shard_fixture", "raise RuntimeError('synthetic import failure')\n"
        )
        loader, suite = self.load()
        self.assertTrue(loader.errors)
        selected, full, mode = partition(suite, "sanitizer", self.start, discovery_errors=True)
        self.assertIs(selected, suite)
        self.assertEqual((len(full), mode), (4, "full-fallback"))
        result = unittest.TextTestRunner(stream=io.StringIO()).run(selected)
        self.assertFalse(result.wasSuccessful())
        self.assertEqual(result.testsRun, 4)

    def test_custom_suite_and_unknown_group_fail_before_selected_effects(self):
        effects = []

        class CustomSuite(unittest.TestSuite):
            def run(self, result, debug=False):
                effects.append("run")
                return super().run(result, debug)

        with self.assertRaisesRegex(ValueError, "custom suite"):
            partition(CustomSuite(), "other", self.start)
        _, suite = self.load()
        with self.assertRaisesRegex(ValueError, "unknown helper group"):
            partition(suite, "unknown", self.start)
        self.assertEqual(effects, [])

    def test_missing_duplicate_foreign_partial_or_mixed_receipts_fail(self):
        valid = self.receipts()
        mutations = [valid[:-1], [valid[0], valid[0], valid[2]]]
        for field, value in [
            ("context", {**BOUND, "attempt": "2"}),
            ("mode", "full-fallback"),
            ("started", {}),
            ("tests_run", 0),
            ("successful", False),
            ("errors", 1),
            ("skipped", True),
            ("full", []),
        ]:
            changed = copy.deepcopy(valid)
            changed[0][field] = value
            mutations.append(changed)
        for index, receipts in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(ValueError):
                aggregate(receipts, BOUND, DEPENDENCIES)

    def test_failed_skipped_cancelled_missing_dependencies_never_succeed(self):
        receipts = self.receipts()
        for job in DEPENDENCIES:
            for result in ["failure", "skipped", "cancelled", None]:
                needs = copy.deepcopy(DEPENDENCIES)
                needs[job]["result"] = result
                with self.subTest(job=job, result=result), self.assertRaises(ValueError):
                    aggregate(receipts, BOUND, needs)
        with self.assertRaises(ValueError):
            aggregate(receipts, BOUND, {"helpers": DEPENDENCIES["helpers"]})

    def test_skips_expected_failure_and_subtests_keep_original_unittest_semantics(self):
        self.write(
            self.modules[2],
            """import unittest
class Cases(unittest.TestCase):
    @unittest.skip("original synthetic skip")
    def test_skip(self): pass
    @unittest.expectedFailure
    def test_expected(self): self.fail("original expected failure")
    def test_subtests(self):
        for value in range(2):
            with self.subTest(value=value): self.assertGreaterEqual(value,0)
""",
        )
        receipts = self.receipts()
        aggregate(receipts, BOUND, DEPENDENCIES)
        other = next(row for row in receipts if row["group"] == "other")
        self.assertEqual(
            (other["tests_run"], other["skipped"], other["expected_failures"]), (3, 1, 1)
        )

    def test_cli_artifact_inventory_and_duplicate_json_keys_reject(self):
        receipts = self.receipts()
        directory = self.root / "receipts"
        directory.mkdir()
        for row in receipts:
            (directory / f"ci-helper-{row['group']}.json").write_text(json.dumps(row))
        argv = ["run_ci_helpers.py", "aggregate", "--directory", str(directory)]
        with (
            mock.patch.object(sys, "argv", argv),
            mock.patch.object(helpers, "context", return_value=BOUND),
            mock.patch.dict("os.environ", {"CI_HELPER_NEEDS": json.dumps(DEPENDENCIES)}),
        ):
            self.assertEqual(helpers.main(), 0)
            (directory / "unexpected.json").write_text("{}")
            with self.assertRaises(ValueError):
                helpers.main()
            (directory / "unexpected.json").unlink()
            (directory / "ci-helper-other.json").write_text('{"group":"other","group":"other"}')
            with self.assertRaises(ValueError):
                helpers.main()

    def test_setup_fixture_skips_cover_original_occurrences_without_inflating_runs(self):
        for fixture in ("module", "class"):
            source = "import unittest\n"
            if fixture == "module":
                source += "def setUpModule(): raise unittest.SkipTest('module unavailable')\n"
            source += "class Cases(unittest.TestCase):\n"
            if fixture == "class":
                source += (
                    "    @classmethod\n"
                    "    def setUpClass(cls): raise unittest.SkipTest('class unavailable')\n"
                )
            source += "    def test_a(self): pass\n    def test_b(self): pass\n"
            self.write(self.modules[2], source)
            sys.modules.pop(self.modules[2], None)
            receipts = self.receipts()
            aggregate(receipts, BOUND, DEPENDENCIES)
            other = next(row for row in receipts if row["group"] == "other")
            self.assertEqual((other["tests_run"], other["skipped"]), (0, 1))
            self.assertEqual(len(other["fixture_skipped_slots"]), 2)
            self.assertEqual(len(other["fixture_events"]), 1)

    def test_setup_cleanup_duplicate_skip_events_only_cover_fixture_once(self):
        for fixture in ("class", "module"):
            registration = (
                "cls.addClassCleanup" if fixture == "class" else "unittest.addModuleCleanup"
            )
            if fixture == "class":
                setup = (
                    "    @classmethod\n    def setUpClass(cls):\n"
                    f"        {registration}(skip)\n        skip()\n"
                )
                source = (
                    "import unittest\ndef skip(): raise unittest.SkipTest('fixture')\n"
                    "class Cases(unittest.TestCase):\n" + setup
                )
            else:
                source = (
                    "import unittest\ndef skip(): raise unittest.SkipTest('fixture')\n"
                    f"def setUpModule():\n    {registration}(skip)\n    skip()\n"
                    "class Cases(unittest.TestCase):\n"
                )
            source += "    def test_a(self): pass\n    def test_b(self): pass\n"
            self.write(self.modules[2], source)
            sys.modules.pop(self.modules[2], None)
            receipts = self.receipts()
            aggregate(receipts, BOUND, DEPENDENCIES)
            other = next(row for row in receipts if row["group"] == "other")
            self.assertEqual((other["tests_run"], other["skipped"]), (0, 2))
            self.assertEqual([len(event["slots"]) for event in other["fixture_events"]], [2, 0])

    def test_setup_error_with_cleanup_skip_never_rescues_success(self):
        self.write(
            self.modules[2],
            """import unittest
class Cases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.addClassCleanup(lambda: (_ for _ in ()).throw(unittest.SkipTest("cleanup")))
        raise RuntimeError("setup failed")
    def test_a(self): pass
""",
        )
        receipts = self.receipts()
        other = next(row for row in receipts if row["group"] == "other")
        self.assertEqual((other["errors"], other["skipped"], other["tests_run"]), (1, 1, 0))
        self.assertEqual(other["fixture_skipped_slots"], [])
        with self.assertRaises(ValueError):
            aggregate(receipts, BOUND, DEPENDENCIES)

    def test_teardown_skips_do_not_account_for_missing_cases(self):
        self.write(
            self.modules[2],
            """import unittest
def tearDownModule(): raise unittest.SkipTest("module teardown")
class Cases(unittest.TestCase):
    @classmethod
    def tearDownClass(cls): raise unittest.SkipTest("class teardown")
    def test_a(self): pass
""",
        )
        receipts = self.receipts()
        aggregate(receipts, BOUND, DEPENDENCIES)
        other = next(row for row in receipts if row["group"] == "other")
        self.assertEqual((other["tests_run"], other["skipped"]), (1, 2))
        self.assertEqual(other["fixture_skipped_slots"], [])
        self.assertTrue(all(not event["slots"] for event in other["fixture_events"]))

    def test_repeated_instances_and_class_blocks_are_occurrence_specific(self):
        _, discovered = self.load()
        original = suite_leaves(discovered)
        module = sys.modules[self.modules[0]]

        class Skipping(unittest.TestCase):
            @classmethod
            def setUpClass(cls):
                reason = "original skip"
                raise unittest.SkipTest(reason)

            def test_a(self):
                pass

        Skipping.__module__ = module.__name__
        repeated = Skipping("test_a")
        ordinary = next(case for case in original if type(case).__module__ == module.__name__)
        others = [case for case in original if case is not ordinary]
        suite = unittest.TestSuite([repeated, ordinary, repeated, *others])
        with (
            mock.patch.object(helpers, "ROOT", self.root),
            mock.patch.object(helpers, "context", return_value=BOUND),
            mock.patch.object(unittest.TestLoader, "discover", return_value=suite),
            redirect_stderr(io.StringIO()),
        ):
            receipt = helpers.run_group("sanitizer")
        self.assertEqual(receipt["started_slots"], [1])
        self.assertEqual(receipt["fixture_skipped_slots"], [0, 2])
        self.assertEqual([event["slots"] for event in receipt["fixture_events"]], [[0], [2]])
        helpers.validate_coverage(receipt, receipt["full"], receipt["planned_slots"])

    def test_forged_skip_or_unstarted_success_never_establishes_coverage(self):
        case = unittest.FunctionTestCase(lambda: None)
        result = helpers.RecordingResult(
            unittest.runner._WritelnDecorator(io.StringIO()), True, 0, [case], [0]
        )
        with self.assertRaisesRegex(ValueError, "unbound"):
            result.addSkip(unittest.suite._ErrorHolder("setUpClass (forged)"), "forged")
        with self.assertRaisesRegex(ValueError, "next planned"):
            result.startTest(unittest.FunctionTestCase(lambda: None))
        valid = self.receipts()
        other = next(row for row in valid if row["group"] == "other")
        other["started_slots"] = []
        other["started"] = {}
        other["tests_run"] = 0
        with self.assertRaises(ValueError):
            aggregate(valid, BOUND, DEPENDENCIES)

    def test_fixture_receipt_partial_spans_wrong_owners_and_old_schema_fail(self):
        self.write(
            self.modules[2],
            """import unittest
class Cases(unittest.TestCase):
    @classmethod
    def setUpClass(cls): raise unittest.SkipTest("fixture")
    def test_a(self): pass
    def test_b(self): pass
""",
        )
        valid = self.receipts()
        aggregate(valid, BOUND, DEPENDENCIES)
        for change in ("owner", "span", "schema", "overlap", "event_count"):
            rows = copy.deepcopy(valid)
            row = next(item for item in rows if item["group"] == "other")
            if change == "owner":
                row["fixture_events"][0]["owner"] = "wrong.Owner"
            elif change == "span":
                row["fixture_events"][0]["slots"] = row["fixture_events"][0]["slots"][:1]
            elif change == "schema":
                row["schema_version"] = 1
            elif change == "event_count":
                row["skipped"] = 0
            else:
                row["started_slots"] = row["fixture_skipped_slots"][:1]
            with self.subTest(change=change), self.assertRaises(ValueError):
                aggregate(rows, BOUND, DEPENDENCIES)

    def test_reentrant_module_full_fallback_keeps_separate_skip_spans(self):
        self.write(
            self.modules[2],
            """import unittest
def setUpModule(): raise unittest.SkipTest("module")
class Cases(unittest.TestCase):
    def test_a(self): pass
""",
        )
        receipts = []
        for group in GROUPS:
            _, discovered = self.load()
            leaves = suite_leaves(discovered)
            skipped = next(case for case in leaves if type(case).__module__ == self.modules[2])
            others = [case for case in leaves if case is not skipped]
            suite = unittest.TestSuite([skipped, *others, skipped])
            with (
                mock.patch.object(helpers, "ROOT", self.root),
                mock.patch.object(helpers, "context", return_value=BOUND),
                mock.patch.object(unittest.TestLoader, "discover", return_value=suite),
                redirect_stderr(io.StringIO()),
            ):
                receipts.append(helpers.run_group(group))
        aggregate(receipts, BOUND, DEPENDENCIES)
        for receipt in receipts:
            self.assertEqual(receipt["mode"], "full-fallback")
            self.assertEqual(receipt["started_slots"], [1, 2])
            self.assertEqual(receipt["fixture_skipped_slots"], [0, 3])
            self.assertEqual([event["slots"] for event in receipt["fixture_events"]], [[0], [3]])

    def test_subtest_skip_is_an_actual_started_case(self):
        self.write(
            self.modules[2],
            """import unittest
class Cases(unittest.TestCase):
    def test_a(self):
        with self.subTest(part="skip"):
            self.skipTest("subtest")
""",
        )
        receipts = self.receipts()
        aggregate(receipts, BOUND, DEPENDENCIES)
        row = next(item for item in receipts if item["group"] == "other")
        self.assertEqual((row["tests_run"], row["skipped"]), (1, 1))
        self.assertEqual(row["fixture_events"], [])

    def test_distinct_classes_with_equal_names_and_ids_remain_distinct_occurrences(self):
        def make_class():
            class Cases(unittest.TestCase):
                @classmethod
                def setUpClass(cls):
                    reason = "fixture"
                    raise unittest.SkipTest(reason)

                def test_a(self):
                    pass

            Cases.__module__ = self.modules[0]
            return Cases

        receipts = []
        for group in GROUPS:
            _, discovered = self.load()
            others = [
                case
                for case in suite_leaves(discovered)
                if type(case).__module__ != self.modules[0]
            ]
            suite = unittest.TestSuite([make_class()("test_a"), make_class()("test_a"), *others])
            with (
                mock.patch.object(helpers, "ROOT", self.root),
                mock.patch.object(helpers, "context", return_value=BOUND),
                mock.patch.object(unittest.TestLoader, "discover", return_value=suite),
                redirect_stderr(io.StringIO()),
            ):
                receipts.append(helpers.run_group(group))
        aggregate(receipts, BOUND, DEPENDENCIES)
        row = next(item for item in receipts if item["group"] == "sanitizer")
        self.assertEqual(row["full"][0]["id"], row["full"][1]["id"])
        self.assertNotEqual(row["full"][0]["class_slot"], row["full"][1]["class_slot"])
        self.assertEqual([event["slots"] for event in row["fixture_events"]], [[0], [1]])

    def test_cli_run_rejects_partial_success_after_preserving_receipt(self):
        receipt = self.receipts()[0]
        receipt["started_slots"] = []
        receipt["started"] = {}
        receipt["tests_run"] = 0
        destination = self.root / "partial.json"
        argv = [
            "run_ci_helpers.py",
            "run",
            "--group",
            receipt["group"],
            "--receipt",
            str(destination),
        ]
        with (
            mock.patch.object(sys, "argv", argv),
            mock.patch.object(helpers, "run_group", return_value=receipt),
            self.assertRaisesRegex(ValueError, "coverage differs"),
        ):
            helpers.main()
        self.assertEqual(json.loads(destination.read_bytes()), receipt)

    def test_direct_fixture_exception_callback_cannot_forge_coverage(self):
        case = unittest.FunctionTestCase(lambda: None)
        result = helpers.RecordingResult(
            unittest.runner._WritelnDecorator(io.StringIO()), True, 0, [case], [0]
        )
        suite = helpers.ObservedSuite(unittest.TestSuite([case]))
        with self.assertRaisesRegex(ValueError, "unbound fixture exception"):
            suite._createClassOrModuleLevelException(
                result, unittest.SkipTest("forged"), "setUpClass", "forged.Owner"
            )
        self.assertEqual((result.testsRun, len(result.skipped)), (0, 0))
        self.assertEqual(result.fixture_skipped_slots, [])
        self.assertEqual(result.fixture_events, [])
