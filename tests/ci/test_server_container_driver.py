# ruff: noqa: PT009, S603, S607 - unittest with fixed repository argv and mock tools
"""Check service requirements and selection for mixed database integration tests."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
URL_KEYS = [
    f"AEGAEON_{name}_REDIS_URL"
    for name in (
        "PAR",
        "AUTH_CODE",
        "DEVICE_CODE",
        "AUTH_SESSION",
        "STEPUP",
        "OIDC_LOGOUT_SESSION",
        "TOKEN_STORE",
        "REQUEST_OBJECT_JTI",
    )
]
CASES = ("redis_code_case", "postgres_case", "http_par_jar_shared_redis_refresh")
PRE_MIGRATION = "pre_migration_ownership_case"
MOCK = r"""
import json, os, sys
from pathlib import Path
name = Path(sys.argv[0]).name
args = sys.argv[1:]
recorded = "CONFIRM_CLEANUP_STATUS" in os.environ
cleanup_control = (recorded and name == "python3" and len(args) >= 2
    and args[0].endswith("database_execution.py") and args[1] in ("run", "confirm-cleanup"))
if (recorded and name == "python3" and len(args) >= 2
    and args[0].endswith("subject_ownership_fixture.py") and args[1] == "cleanup"):
    with open(os.environ["DRIVER_LOG"], "a") as f:
        f.write(json.dumps({"tool":"subject-cleanup", "args":args}) + "\n")
if (name == "python3" and args[:1] != ["scripts/tests/check_postgresql_version.py"]
    and not cleanup_control):
    os.execv(sys.executable, [sys.executable, *args])
record = {"tool": name, "args": args,
          "urls": {k: os.environ.get(k) for k in json.loads(os.environ["URL_KEYS"])}}
with open(os.environ["DRIVER_LOG"], "a") as f:
    f.write(json.dumps(record) + "\n")
if "POSTGRES_TCP_READY_AFTER" in os.environ:
    rows = [json.loads(line) for line in Path(os.environ["DRIVER_LOG"]).read_text().splitlines()]
    tcp_attempts = sum(
        row["tool"] == "docker" and "pg_isready" in row["args"]
        and "-h" in row["args"] and "127.0.0.1" in row["args"]
        for row in rows
    )
    tcp_ready = tcp_attempts > int(os.environ["POSTGRES_TCP_READY_AFTER"])
    if name == "docker" and "pg_isready" in args:
        # The image's initialization server already accepts Unix-socket probes.
        sys.exit(0 if "-h" not in args or tcp_ready else 2)
    if name == "python3" and not tcp_ready:
        sys.exit(21)
if name == "python3":
    if cleanup_control:
        sys.exit(int(os.environ["CONFIRM_CLEANUP_STATUS"]) if args[1] == "confirm-cleanup" else 0)
    sys.exit(int(os.environ.get("POSTGRES_VERSION_STATUS", "0")))
if name == "docker" and "ping" in args:
    print("PONG")
if name == "docker" and "down" in args:
    sys.exit(int(os.environ.get("COMPOSE_DOWN_STATUS", "0")))
if name == "psql":
    sys.exit(int(os.environ.get("PSQL_FIXTURE_STATUS", "0")))
if name == "cargo":
    if recorded and ("dcr_database_test" in args or "shared_redis_" in args):
        print("test result: ok. 1 passed; 0 failed; 0 ignored;")
        status = os.environ.get("CARGO_LAST_STATUS", os.environ.get("CARGO_FIXTURE_STATUS", "0"))
        sys.exit(int(status))
    if "pre_migration_" in args and "CARGO_PRE_MIGRATION_OUTPUT" in os.environ:
        print(os.environ["CARGO_PRE_MIGRATION_OUTPUT"])
        sys.exit(int(os.environ.get("CARGO_PRE_MIGRATION_STATUS", "0")))
    print(os.environ.get("CARGO_FIXTURE_OUTPUT", "test result: ok. 1 passed; 0 failed; 0 ignored;"))
    sys.exit(int(os.environ.get("CARGO_FIXTURE_STATUS", "0")))
"""


class ServerContainerDriverTests(unittest.TestCase):
    def run_scope(self, scope: str, *, expected_status: int = 0, **overrides: str) -> list[dict]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "commands.jsonl"
            for name in ("docker", "cargo", "atlas", "psql", "python3"):
                path = root / name
                path.write_text(f"#!{sys.executable}\n" + MOCK)
                path.chmod(0o755)
            env = dict(
                os.environ,
                PATH=f"{root}:{os.environ['PATH']}",
                DRIVER_LOG=str(log),
                TMPDIR=str(root),
                URL_KEYS=json.dumps(URL_KEYS),
                AEGAEON_TEST_REDIS_URL="redis://127.0.0.1:16579/0",
                AEGAEON_SERVER_CONTAINER_SKIP_UP="0",
                AEGAEON_SERVER_CONTAINER_DOWN="0",
            )
            env.pop("AEGAEON_DATABASE_TEST_PACKAGE", None)
            env.pop("JOSE_SERVER_TEST_PACKAGE", None)
            env.update(overrides)
            for key in URL_KEYS:
                env[key] = "redis://unrelated.invalid/0"
            result = subprocess.run(
                ["bash", str(ROOT / "scripts/tests/run_server_container_integration.sh"), scope],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, expected_status, result.stdout + result.stderr)
            return [json.loads(line) for line in log.read_text().splitlines()]

    def test_version_probe_runs_after_readiness_and_before_any_tests(self) -> None:
        for scope in ("all", "postgres", "mixed"):
            with self.subTest(scope=scope):
                rows = self.run_scope(scope)
                probes = [i for i, row in enumerate(rows) if row["tool"] == "python3"]
                self.assertEqual(len(probes), 1)
                ready = next(i for i, row in enumerate(rows) if "pg_isready" in row["args"])
                self.assertLess(ready, probes[0])
                for i, row in enumerate(rows):
                    if row["tool"] in {"atlas", "cargo", "psql"}:
                        self.assertLess(probes[0], i)
        self.assertFalse(any(row["tool"] == "python3" for row in self.run_scope("redis")))

    def test_version_probe_failure_stops_migrations_and_tests(self) -> None:
        for scope in ("all", "postgres", "mixed"):
            with self.subTest(scope=scope):
                rows = self.run_scope(scope, expected_status=29, POSTGRES_VERSION_STATUS="29")
                self.assertFalse(any(row["tool"] in {"atlas", "cargo", "psql"} for row in rows))

    def test_socket_only_initialization_waits_for_tcp_before_version_probe(self) -> None:
        for scope in ("all", "postgres", "mixed"):
            with self.subTest(scope=scope):
                rows = self.run_scope(scope, POSTGRES_TCP_READY_AFTER="2")
                probes = [i for i, row in enumerate(rows) if row["tool"] == "python3"]
                ready = [i for i, row in enumerate(rows) if "pg_isready" in row["args"]]
                self.assertEqual(len(probes), 1)
                self.assertEqual(len(ready), 3)
                self.assertLess(ready[-1], probes[0])

    def test_version_failure_preserves_status_and_attempts_requested_teardown(self) -> None:
        for scope in ("all", "postgres", "mixed"):
            for cleanup_status in ("0", "42"):
                with self.subTest(scope=scope, cleanup_status=cleanup_status):
                    rows = self.run_scope(
                        scope,
                        expected_status=29,
                        POSTGRES_VERSION_STATUS="29",
                        AEGAEON_SERVER_CONTAINER_DOWN="1",
                        COMPOSE_DOWN_STATUS=cleanup_status,
                    )
                    downs = [r for r in rows if r["tool"] == "docker" and "down" in r["args"]]
                    self.assertEqual(len(downs), 1)
                    self.assertFalse(any(r["tool"] in {"atlas", "cargo", "psql"} for r in rows))

    def test_empty_or_failed_required_execution_stops_the_driver(self) -> None:
        for output, status, expected in (
            ("test result: ok. 0 passed; 0 failed; 0 ignored;", "0", 1),
            ("test result: ok. 0 passed; 0 failed; 2 ignored;", "0", 1),
            ("test result: ok. 1 passed; 0 failed; 0 ignored;", "37", 37),
        ):
            with self.subTest(output=output, status=status):
                rows = self.run_scope(
                    "all",
                    expected_status=expected,
                    CARGO_FIXTURE_OUTPUT=output,
                    CARGO_FIXTURE_STATUS=status,
                )
                self.assertEqual(len([r for r in rows if r["tool"] == "cargo"]), 1)
                self.assertFalse(any(r["tool"] == "atlas" for r in rows))

    def selected(self, record: dict, cases: tuple[str, ...] = (*CASES, PRE_MIGRATION)) -> list[str]:
        args = record["args"]
        if record["tool"] != "cargo" or "--lib" not in args:
            return []
        index = args.index("--")
        front, back = args[:index], args[index + 1 :]
        patterns = [arg for arg in front if arg in ("redis_", "shared_redis_", "pre_migration_")]
        skips = [back[i + 1] for i, arg in enumerate(back) if arg == "--skip"]
        return [
            case
            for case in cases
            if all(pattern in case for pattern in patterns)
            and not any(skip in case for skip in skips)
        ]

    def test_all_selects_every_case_once_after_its_services_are_ready(self) -> None:
        records = self.run_scope("all")
        selected = [case for record in records for case in self.selected(record)]
        self.assertCountEqual(selected, (*CASES, PRE_MIGRATION))
        migrations = [i for i, r in enumerate(records) if r["tool"] == "atlas"]
        self.assertEqual(len(migrations), 2)
        before, migration = migrations
        provisioning = [
            i
            for i, r in enumerate(records)
            if r["tool"] == "psql"
            and "scripts/operations/provision-subject-ownership.sql" in r["args"]
        ]
        self.assertEqual(len(provisioning), 3)
        self.assertLess(provisioning[0], before)
        self.assertGreater(provisioning[1], migration)
        for index in provisioning:
            self.assertIn("ON_ERROR_STOP=1", records[index]["args"])
        predecessor_count = next(
            i
            for i, p in enumerate(sorted((ROOT / "db/migrations").glob("*.sql")))
            if p.name == "20261029050000_subject_ownership.sql"
        )
        command = [
            "migrate",
            "apply",
            "--dir",
            "file://db/migrations",
            "--revisions-schema",
            "public",
            "--env",
            "local",
        ]
        self.assertEqual(records[before]["args"], [*command, str(predecessor_count)])
        self.assertEqual(records[migration]["args"], command)
        for i, record in enumerate(records):
            if PRE_MIGRATION in self.selected(record):
                self.assertLess(before, i)
                self.assertLess(i, migration)
            if any(case in CASES[1:] for case in self.selected(record)):
                self.assertGreater(i, migration)

    def test_revision_ledger_failure_stops_migration_and_database_tests(self) -> None:
        # The legacy standalone ledger initializer is now part of owned database
        # provisioning. Preserve the gate's identity and refuse its first SQL failure.
        rows = self.run_scope("postgres", expected_status=1, PSQL_FIXTURE_STATUS="17")
        # A failed prepare also attempts cleanup of the recorded owned fixture.
        self.assertEqual(len([row for row in rows if row["tool"] == "psql"]), 2)
        self.assertFalse(any(row["tool"] in {"atlas", "cargo"} for row in rows))

    def test_recorded_fixture_cleanup_requires_confirmation_on_normal_and_exit_paths(self) -> None:
        for scope in ("postgres", "mixed"):
            for test_status, confirmation in ((0, 0), (0, 19), (37, 0), (37, 19)):
                with self.subTest(scope=scope, test_status=test_status, confirmation=confirmation):
                    rows = self.run_scope(
                        scope,
                        expected_status=test_status or confirmation,
                        AEGAEON_DATABASE_EXECUTION_PLAN="fixture-plan",
                        AEGAEON_DATABASE_EXECUTION_RESULTS="fixture-results",
                        AEGAEON_SERVER_CONTAINER_DOWN="1",
                        CONFIRM_CLEANUP_STATUS=str(confirmation),
                        CARGO_LAST_STATUS=str(test_status),
                    )
                    checks = [r for r in rows if "confirm-cleanup" in r["args"]]
                    self.assertTrue(checks)
                    for check in checks:
                        self.assertEqual(
                            check["args"][1:], ["confirm-cleanup", "--lane", scope, "--require-all"]
                        )
                    cleaned = [r for r in rows if r["tool"] == "subject-cleanup"]
                    self.assertEqual(len(cleaned), 0 if confirmation else 1)
                    downs = [r for r in rows if r["tool"] == "docker" and "down" in r["args"]]
                    self.assertEqual(len(downs), int(not test_status and not confirmation))

    def test_mixed_uses_only_the_selected_test_redis(self) -> None:
        records = self.run_scope("all")
        mixed = [r for r in records if CASES[2] in self.selected(r)]
        self.assertEqual(len(mixed), 1)
        self.assertEqual(mixed[0]["urls"], dict.fromkeys(URL_KEYS, "redis://127.0.0.1:16579/0"))

    def test_empty_or_failed_pre_migration_run_stops_schema_advancement(self) -> None:
        for output, status in (
            ("test result: ok. 0 passed; 0 failed; 0 ignored;", "0"),
            ("test result: ok. 1 passed; 0 failed; 0 ignored;", "37"),
        ):
            with self.subTest(output=output, status=status):
                records = self.run_scope(
                    "postgres",
                    expected_status=1,
                    CARGO_PRE_MIGRATION_OUTPUT=output,
                    CARGO_PRE_MIGRATION_STATUS=status,
                )
                self.assertEqual(len([r for r in records if r["tool"] == "atlas"]), 1)
                self.assertEqual([c for r in records for c in self.selected(r)], [PRE_MIGRATION])

    def test_standalone_mixed_prepares_its_own_database_without_repeating_preflight(self) -> None:
        records = self.run_scope("mixed")
        self.assertEqual([c for row in records for c in self.selected(row)], [CASES[2]])
        up = [r["args"] for r in records if r["tool"] == "docker" and "up" in r["args"]]
        self.assertEqual(up[0][-2:], ["postgres", "redis"])
        self.assertTrue(any(r["tool"] == "atlas" for r in records))

    def test_scopes_keep_their_selection_and_required_suppliers(self) -> None:
        for scope, expected in (("redis", [CASES[0]]), ("postgres", [PRE_MIGRATION, CASES[1]])):
            with self.subTest(scope=scope):
                records = self.run_scope(scope)
                self.assertEqual([c for r in records for c in self.selected(r)], expected)
                up = [r["args"] for r in records if r["tool"] == "docker" and "up" in r["args"]]
                self.assertEqual(len(up), 1)
                self.assertEqual(
                    up[0][-1:] if scope == "redis" else up[0][-2:],
                    ["redis"] if scope == "redis" else ["postgres", "redis"],
                )

    def test_redis_uses_only_the_selected_test_redis(self) -> None:
        records = self.run_scope("redis")
        calls = [r for r in records if CASES[0] in self.selected(r)]
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["urls"], dict.fromkeys(URL_KEYS, "redis://127.0.0.1:16579/0"))

    def organization_namespace_cases(self) -> list[str]:
        runner = (ROOT / "tests/organizations/production_runtime.py").read_text()
        runner += (ROOT / "tests/organizations/store_restart.py").read_text()
        selectors = set(re.findall(r'"(organization_(?:production|packaged)_[a-z_]+)"', runner))
        declaration = re.compile(r'#\[ignore\s*=\s*"[^\"]*"\]\s*(?:async\s+)?fn\s+(\w+)')
        cases = [
            f"server_runtime::organization_runtime::tests::{source.stem}::{name}"
            for source in (ROOT / "crates/server/src/main/organization_runtime/tests").glob("*.rs")
            for name in declaration.findall(source.read_text())
        ]
        self.assertEqual(len(cases), 9, "all nine isolated runtime fixtures must remain registered")
        self.assertCountEqual([case.rsplit("::", 1)[-1] for case in cases], selectors)
        return cases

    def test_organizations_fixtures_are_left_to_their_dedicated_runner(self) -> None:
        cases = self.organization_namespace_cases()
        for scope in ("all", "redis", "postgres"):
            with self.subTest(scope=scope):
                records = self.run_scope(scope)
                self.assertEqual(
                    [case for record in records for case in self.selected(record, cases)], []
                )

    def test_declared_mixed_tests_use_the_mixed_lane(self) -> None:
        declaration = re.compile(r'#\[ignore\s*=\s*"([^\"]*)"\]\s*(?:async\s+)?fn\s+(\w+)')
        isolated = {case.rsplit("::", 1)[-1] for case in self.organization_namespace_cases()}
        mixed = []
        for source in (ROOT / "crates/server/src").rglob("*.rs"):
            for reason, name in declaration.findall(source.read_text()):
                description = reason.lower()
                if "redis" in description and any(
                    word in description for word in ("postgres", "database_url")
                ):
                    if name in isolated:
                        # Independent TLS clusters/control ownership cannot use Compose suppliers.
                        self.assertTrue(
                            source.is_relative_to(
                                ROOT / "crates/server/src/main/organization_runtime/tests"
                            )
                        )
                        continue
                    mixed.append(name)
                    self.assertIn("shared_redis_", name, f"{source}: {reason}")
        self.assertTrue(mixed, "mixed test inventory must not be empty")

    def test_namespace_fixtures_are_left_to_their_dedicated_runners(self) -> None:
        declaration = re.compile(
            r'#\[ignore\s*=\s*"requires scripts/validation/(test_\w+\.py)"\]'
            r"\s*(?:async\s+)?fn\s+(\w+)"
        )
        source_root = ROOT / "crates/server/src"
        declared: dict[str, list[str]] = {
            "test_client_jwks_cache.py": [],
            "test_jwks_fingerprint_ledger.py": [],
        }
        for source in (source_root / "client_registry").rglob("*.rs"):
            for runner, name in declaration.findall(source.read_text()):
                self.assertIn(runner, declared, f"unrecognized namespace runner in {source}")
                declared[runner].append(
                    "::".join((*source.relative_to(source_root).with_suffix("").parts, name))
                )
        for runner, fixtures in declared.items():
            self.assertTrue(fixtures, f"{runner}: namespace fixture inventory must not be empty")
        cases = tuple(case for fixtures in declared.values() for case in fixtures)
        for scope in ("all", "redis", "postgres"):
            with self.subTest(scope=scope):
                records = self.run_scope(scope)
                self.assertEqual(
                    [case for record in records for case in self.selected(record, cases)], []
                )

    def test_postgres_jwks_fixtures_remain_in_the_service_lanes(self) -> None:
        declaration = re.compile(r'#\[ignore\s*=\s*"([^\"]*)"\]\s*(?:async\s+)?fn\s+(\w+)')
        cases = tuple(
            f"client_registry::jwks_fixture::{name}"
            for source in (ROOT / "crates/server/src/client_registry").rglob("*.rs")
            for reason, name in declaration.findall(source.read_text())
            if "postgres" in reason.lower() or "database_url" in reason.lower()
        )
        self.assertTrue(cases, "PostgreSQL JWKS inventory must not be empty")
        records = self.run_scope("all")
        self.assertCountEqual(
            [case for record in records for case in self.selected(record, cases)], cases
        )
        redis_records = self.run_scope("redis")
        self.assertEqual(
            [case for record in redis_records for case in self.selected(record, cases)], []
        )


if __name__ == "__main__":
    unittest.main()
