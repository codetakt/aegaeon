"""Run complete unittest discovery in whole-module groups and account for coverage."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import unittest
from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, cast
from unittest.suite import _ErrorHolder  # type: ignore[attr-defined]
from unittest.util import strclass

from pr_plan import unique_json_object

if TYPE_CHECKING:
    from collections.abc import Mapping

if TYPE_CHECKING:
    ResultBase = unittest.TextTestResult[Any]
else:
    ResultBase = unittest.TextTestResult

GROUPS = ("sanitizer", "security-fuzz", "other")
ROOT = Path(__file__).resolve().parents[2]
PATTERN = "test_*.py"
FIXTURE_CALLERS = frozenset(
    getattr(unittest.TestSuite, name).__code__
    for name in (
        "_handleClassSetUp",
        "_handleModuleFixture",
        "_tearDownPreviousClass",
        "_handleModuleTearDown",
    )
)


def require(condition: object, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def module_group(module: str) -> str:
    name = module.rsplit(".", 1)[-1]
    if name.startswith("test_sanitizer"):
        return "sanitizer"
    if name.startswith("test_security_fuzz"):
        return "security-fuzz"
    return "other"


def suite_leaves(suite: unittest.TestSuite) -> list[unittest.TestCase]:
    """Only ordinary suite containers can be inspected without changing behavior."""
    require(type(suite) is unittest.TestSuite, "custom suite cannot be safely partitioned")
    leaves = []
    for child in suite:
        if isinstance(child, unittest.TestSuite):
            leaves.extend(suite_leaves(child))
        else:
            require(isinstance(child, unittest.TestCase), "foreign suite leaf cannot be inspected")
            leaves.append(child)
    return leaves


def partition(  # noqa: C901, PLR0915 - preserve full fixture/discovery fallbacks
    suite: unittest.TestSuite, group: str, start: Path, *, discovery_errors: bool = False
) -> tuple[unittest.TestSuite, list[dict[str, Any]], str]:
    """Retain fixture order; unsupported discovery uses the original complete suite."""
    require(group in GROUPS, "unknown helper group")
    leaves = suite_leaves(suite)
    require(leaves, "complete helper discovery is empty")
    classes: dict[type[unittest.TestCase], int] = {}
    full: list[dict[str, Any]] = []
    for slot, case in enumerate(leaves):
        classes.setdefault(type(case), len(classes))
        full.append(
            {
                "slot": slot,
                "id": case.id(),
                "module": type(case).__module__,
                "class": strclass(type(case)),
                "class_slot": classes[type(case)],
            }
        )
    require(all(type(row["id"]) is str and row["id"] for row in full), "invalid helper ID")
    fallback = discovery_errors
    seen: set[str] = set()
    previous = None
    for row in full:
        module = row["module"]
        loaded = sys.modules.get(module)
        filename = vars(loaded).get("__file__") if loaded is not None else None
        try:
            relative = Path(filename).resolve().relative_to(start.resolve()) if filename else None
        except ValueError:
            relative = None
        fallback |= relative is None or relative.stem != module.rsplit(".", 1)[-1]
        fallback |= module in seen and module != previous
        seen.add(module)
        previous = module
    for loaded in list(sys.modules.values()):
        filename = vars(loaded).get("__file__") if loaded is not None else None
        if filename and callable(vars(loaded).get("load_tests")):
            try:
                Path(filename).resolve().relative_to(start.resolve())
            except ValueError:
                continue
            fallback = True
    fallback |= any(not any(module_group(row["module"]) == name for row in full) for name in GROUPS)
    if fallback:
        return suite, full, "full-fallback"

    def selected(container: unittest.TestSuite) -> unittest.TestSuite:
        retained = unittest.TestSuite()
        for child in container:
            if isinstance(child, unittest.TestSuite):
                nested = selected(child)
                if nested.countTestCases():
                    retained.addTest(nested)
            elif module_group(type(child).__module__) == group:
                retained.addTest(child)
        return retained

    return selected(suite), full, "normal"


def context() -> dict[str, str]:
    """Bind receipts to the validated actual checkout, run and pinned configuration."""

    def git(*arguments: str) -> str:
        return subprocess.check_output(["git", *arguments], cwd=ROOT).decode().strip()

    head = git("rev-parse", "HEAD")
    require(
        head == os.environ["CI_HELPER_TEST_SHA"], "helper checkout differs from validated source"
    )
    require(re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", head), "helper source SHA malformed")
    subprocess.run(["git", "diff", "--quiet", "HEAD", "--"], cwd=ROOT, check=True)
    require(sys.flags.optimize == 0, "helper tests require ordinary Python assertion semantics")
    configuration = {
        "pattern": PATTERN,
        "start_dir": "tests/ci",
        "python": sys.version,
        "runner": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "flake_lock": hashlib.sha256((ROOT / "flake.lock").read_bytes()).hexdigest(),
        "pyproject": hashlib.sha256((ROOT / "pyproject.toml").read_bytes()).hexdigest(),
    }
    return {
        "source": head,
        "tree": git("rev-parse", "HEAD^{tree}"),
        "run_id": os.environ["GITHUB_RUN_ID"],
        "attempt": os.environ["GITHUB_RUN_ATTEMPT"],
        "configuration": hashlib.sha256(
            json.dumps(configuration, sort_keys=True).encode()
        ).hexdigest(),
    }


class RecordingResult(ResultBase):
    # Initialized by the original TestSuite module-fixture handler before use.
    _moduleSetUpFailed: bool  # noqa: N815 - original unittest fixture state

    def __init__(
        self,
        stream: object,
        descriptions: bool,  # noqa: FBT001 - unittest result interface
        verbosity: int,
        cases: list[unittest.TestCase],
        slots: list[int],
    ) -> None:
        super().__init__(stream, descriptions, verbosity)
        self.cases, self.slots, self.cursor = cases, slots, 0
        self.started: Counter[str] = Counter()
        self.started_slots: list[int] = []
        self.fixture_skipped_slots: list[int] = []
        self.fixture_events: list[dict[str, Any]] = []
        self.pending_fixture: str | None = None
        self.active: unittest.TestCase | None = None

    def startTest(self, test: unittest.TestCase) -> None:  # noqa: N802
        require(
            self.cursor < len(self.cases) and self.cases[self.cursor] is test,
            "helper start differs from next planned occurrence",
        )
        self.started_slots.append(self.slots[self.cursor])
        self.cursor += 1
        self.started[test.id()] += 1
        self.active = test
        super().startTest(test)

    def stopTest(self, test: unittest.TestCase) -> None:  # noqa: N802
        super().stopTest(test)
        self.active = None

    def addSkip(self, test: unittest.TestCase, reason: str) -> None:  # noqa: N802
        require(
            (
                self.pending_fixture is not None
                and type(test) is _ErrorHolder
                and test.id() == self.pending_fixture
            )
            or (test is self.active and self.active is not None)
            or (getattr(test, "test_case", None) is self.active and self.active is not None),
            "unbound helper skip callback",
        )
        super().addSkip(test, reason)

    def fixture_skip(self, kind: str, test: unittest.TestCase) -> list[int]:
        require(
            self.cursor < len(self.cases) and self.cases[self.cursor] is test,
            "fixture skip differs from next planned occurrence",
        )
        start = self.cursor
        while self.cursor < len(self.cases):
            candidate = self.cases[self.cursor]
            if (
                type(candidate) is not type(test)
                if kind == "setUpClass"
                else type(candidate).__module__ != type(test).__module__
            ):
                break
            self.cursor += 1
        covered = self.slots[start : self.cursor]
        self.fixture_skipped_slots.extend(covered)
        return covered


class _FixtureSuite(Protocol):
    """Typed view of CPython fixtures; typeshed also omits the exact _ErrorHolder type."""

    _cleanup: bool

    def _handleClassSetUp(self, test: unittest.TestCase, result: RecordingResult) -> None: ...  # noqa: N802
    def _handleModuleFixture(self, test: unittest.TestCase, result: RecordingResult) -> None: ...  # noqa: N802
    def _createClassOrModuleLevelException(  # noqa: N802
        self,
        result: RecordingResult,
        exc: BaseException,
        method_name: str,
        parent: str,
        info: object = None,
    ) -> None: ...


class ObservedSuite(unittest.TestSuite):
    """Observe original stdlib fixture callbacks without replacing its run loop."""

    def __init__(self, original: unittest.TestSuite) -> None:
        super().__init__(
            ObservedSuite(child) if isinstance(child, unittest.TestSuite) else child
            for child in original
        )
        self._cleanup = cast("_FixtureSuite", original)._cleanup  # noqa: SLF001 - preserve standard suite setting
        self.phase: tuple[str, unittest.TestCase, str] | None = None
        self.reported = False

    def _handleClassSetUp(self, test: unittest.TestCase, result: RecordingResult) -> None:  # noqa: N802
        previous = self.phase, self.reported
        self.phase = ("setUpClass", test, strclass(type(test)))
        self.reported = False
        try:
            cast("_FixtureSuite", super())._handleClassSetUp(test, result)  # noqa: SLF001 - original handler
        finally:
            self.phase, self.reported = previous

    def _handleModuleFixture(self, test: unittest.TestCase, result: RecordingResult) -> None:  # noqa: N802
        previous = self.phase, self.reported
        self.phase = ("setUpModule", test, type(test).__module__)
        self.reported = False
        try:
            cast("_FixtureSuite", super())._handleModuleFixture(test, result)  # noqa: SLF001 - original handler
        finally:
            self.phase, self.reported = previous

    def _createClassOrModuleLevelException(  # noqa: N802
        self,
        result: RecordingResult,
        exc: BaseException,
        method_name: str,
        parent: str,
        info: object = None,
    ) -> None:
        caller = sys._getframe(1).f_code  # noqa: SLF001 - bind the actual CPython caller frame
        require(caller in FIXTURE_CALLERS, "unbound fixture exception callback")
        covered: list[int] = []
        phase = self.phase
        if phase is not None and (method_name, parent) == (phase[0], phase[2]):
            first = not self.reported
            self.reported = True
            failed = (
                getattr(type(phase[1]), "_classSetupFailed", False)
                if method_name == "setUpClass"
                else result._moduleSetUpFailed  # noqa: SLF001 - original fixture failure flag
            )
            if first and info is None and failed and isinstance(exc, unittest.SkipTest):
                covered = result.fixture_skip(method_name, phase[1])
        if isinstance(exc, unittest.SkipTest):
            result.fixture_events.append(
                {"phase": method_name, "owner": parent, "slots": covered, "reason": str(exc)}
            )
            result.pending_fixture = f"{method_name} ({parent})"
        try:
            cast("_FixtureSuite", super())._createClassOrModuleLevelException(  # noqa: SLF001 - original helper
                result, exc, method_name, parent, info
            )
        finally:
            result.pending_fixture = None


def run_group(group: str) -> dict[str, Any]:
    bound = context()
    loader = unittest.TestLoader()
    complete = loader.discover(start_dir="tests/ci", pattern=PATTERN)
    selected, full, mode = partition(
        complete, group, ROOT / "tests/ci", discovery_errors=bool(loader.errors)
    )
    cases = suite_leaves(selected)
    slots = [
        row["slot"]
        for row in full
        if mode == "full-fallback" or module_group(row["module"]) == group
    ]
    planned = Counter(case.id() for case in cases)
    result = unittest.TextTestRunner(
        verbosity=2,
        resultclass=lambda stream, descriptions, verbosity: RecordingResult(
            stream, descriptions, verbosity, cases, slots
        ),
    ).run(ObservedSuite(selected))
    if not isinstance(result, RecordingResult):
        raise TypeError("helper result recorder unavailable")
    require(context() == bound, "helper source/configuration changed during execution")
    return {
        "schema_version": 2,
        "group": group,
        "mode": mode,
        "context": bound,
        "full": full,
        "planned": dict(planned),
        "started": dict(result.started),
        "planned_slots": slots,
        "started_slots": result.started_slots,
        "fixture_skipped_slots": result.fixture_skipped_slots,
        "fixture_events": result.fixture_events,
        "tests_run": result.testsRun,
        "errors": len(result.errors),
        "failures": len(result.failures),
        "skipped": len(result.skipped),
        "expected_failures": len(result.expectedFailures),
        "unexpected_successes": len(result.unexpectedSuccesses),
        "successful": result.wasSuccessful() and not loader.errors,
    }


def counts(value: object) -> Counter[str]:
    if not isinstance(value, dict):
        raise TypeError("helper counters are not an object")
    require(
        all(
            type(key) is str and key and type(count) is int and count > 0
            for key, count in value.items()
        ),
        "invalid helper counter",
    )
    return Counter(value)


def validate_coverage(row: dict[str, Any], full: list[dict[str, Any]], slots: list[int]) -> None:
    require(
        isinstance(row["planned_slots"], list)
        and all(type(slot) is int for slot in row["planned_slots"])
        and row["planned_slots"] == slots,
        "helper planned occurrence inventory differs",
    )
    started, skipped = row["started_slots"], row["fixture_skipped_slots"]
    require(
        all(
            isinstance(value, list) and all(type(slot) is int for slot in value)
            for value in (started, skipped)
        ),
        "helper occurrence lists malformed",
    )
    require(
        started == sorted(set(started))
        and skipped == sorted(set(skipped))
        and not set(started) & set(skipped)
        and sorted(started + skipped) == slots,
        "helper occurrence coverage differs",
    )
    require(
        counts(row["started"]) == Counter(full[slot]["id"] for slot in started),
        "helper started counters differ",
    )
    require(
        type(row["tests_run"]) is int and row["tests_run"] == len(started),
        "helper actual test count differs",
    )
    events = row["fixture_events"]
    require(isinstance(events, list), "helper fixture events malformed")
    covered: list[int] = []
    for event in events:
        require(
            isinstance(event, dict)
            and set(event) == {"phase", "owner", "slots", "reason"}
            and event["phase"] in {"setUpClass", "setUpModule", "tearDownClass", "tearDownModule"}
            and type(event["owner"]) is str
            and event["owner"]
            and type(event["reason"]) is str
            and isinstance(event["slots"], list),
            "helper fixture event malformed",
        )
        span = event["slots"]
        if not span:
            continue
        require(
            event["phase"] in {"setUpClass", "setUpModule"}
            and all(type(slot) is int and slot in slots for slot in span),
            "helper fixture coverage phase differs",
        )
        offset = slots.index(span[0])
        field = "class_slot" if event["phase"] == "setUpClass" else "module"
        label = "class" if event["phase"] == "setUpClass" else "module"
        require(full[span[0]][label] == event["owner"], "helper fixture owner differs")
        identity = full[span[0]][field]
        require(
            offset == 0 or full[slots[offset - 1]][field] != identity,
            "helper fixture skip is not at an owner boundary",
        )
        expected = []
        for slot in slots[offset:]:
            if full[slot][field] != identity:
                break
            expected.append(slot)
        require(span == expected and not set(span) & set(covered), "helper fixture span differs")
        covered.extend(span)
    require(
        covered == skipped and type(row["skipped"]) is int and row["skipped"] >= len(events),
        "helper fixture skip accounting differs",
    )


def aggregate(
    receipts: list[dict[str, Any]], bound: Mapping[str, str], dependencies: Mapping[str, Any]
) -> None:
    require(set(dependencies) == {"metadata", "helpers"}, "helper dependency inventory differs")
    require(
        all(row.get("result") == "success" for row in dependencies.values()),
        "helper dependency did not succeed",
    )
    require(len(receipts) == len(GROUPS), "helper receipt inventory incomplete")
    by_group = {row.get("group"): row for row in receipts}
    require(set(by_group) == set(GROUPS), "helper shard inventory duplicated or unknown")
    first = receipts[0]
    full, mode = first["full"], first["mode"]
    require(mode in {"normal", "full-fallback"}, "unknown helper execution mode")
    require(isinstance(full, list) and full, "complete helper discovery missing")
    require(
        all(
            isinstance(row, dict)
            and set(row) == {"slot", "id", "module", "class", "class_slot"}
            and type(row["class_slot"]) is int
            and 0 <= row["class_slot"] <= index
            and type(row["slot"]) is int
            and row["slot"] == index
            and all(type(row[key]) is str and row[key] for key in ("id", "module", "class"))
            for index, row in enumerate(full)
        ),
        "helper full inventory malformed",
    )
    total = Counter(row["id"] for row in full)
    observed: Counter[str] = Counter()
    for group, row in by_group.items():
        require(
            type(row["schema_version"]) is int and row["schema_version"] == 2,
            "helper receipt version differs",
        )
        require(
            row["context"] == dict(bound) and row["full"] == full and row["mode"] == mode,
            "helper source/discovery/mode differs",
        )
        planned = (
            total
            if mode == "full-fallback"
            else Counter(item["id"] for item in full if module_group(item["module"]) == group)
        )
        slots = [
            item["slot"]
            for item in full
            if mode == "full-fallback" or module_group(item["module"]) == group
        ]
        validate_coverage(row, full, slots)
        require(planned and counts(row["planned"]) == planned, "helper planned counters differ")
        require(
            all(
                type(row[key]) is int and row[key] >= 0
                for key in (
                    "errors",
                    "failures",
                    "skipped",
                    "expected_failures",
                    "unexpected_successes",
                )
            ),
            "helper outcome counters malformed",
        )
        require(
            row["successful"] is True
            and row["errors"] == row["failures"] == row["unexpected_successes"] == 0,
            "helper tests unsuccessful",
        )
        observed.update(planned)
    require(
        observed
        == (
            total
            if mode == "normal"
            else Counter({key: count * len(GROUPS) for key, count in total.items()})
        ),
        "complete helper union differs",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    run = subcommands.add_parser("run")
    run.add_argument("--group", choices=GROUPS, required=True)
    run.add_argument("--receipt", type=Path, required=True)
    collect = subcommands.add_parser("aggregate")
    collect.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "run":
        receipt = run_group(args.group)
        with args.receipt.open("x") as stream:
            json.dump(receipt, stream, sort_keys=True)
        validate_coverage(receipt, receipt["full"], receipt["planned_slots"])
        return 0 if receipt["successful"] else 1
    expected = {f"ci-helper-{name}.json" for name in GROUPS}
    require(
        {path.name for path in args.directory.iterdir()} == expected,
        "helper artifact inventory differs",
    )
    receipts = [
        json.loads((args.directory / name).read_bytes(), object_pairs_hook=unique_json_object)
        for name in sorted(expected)
    ]
    aggregate(
        receipts,
        context(),
        json.loads(os.environ["CI_HELPER_NEEDS"], object_pairs_hook=unique_json_object),
    )
    print("Complete CI-helper discovery and execution accounted for.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
