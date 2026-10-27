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
MOCK = r"""
import json, os, sys
from pathlib import Path
name = Path(sys.argv[0]).name
args = sys.argv[1:]
record = {"tool": name, "args": args,
          "urls": {k: os.environ.get(k) for k in json.loads(os.environ["URL_KEYS"])}}
with open(os.environ["DRIVER_LOG"], "a") as f:
    f.write(json.dumps(record) + "\n")
if name == "docker" and "ping" in args:
    print("PONG")
if name == "psql":
    sys.exit(int(os.environ.get("PSQL_FIXTURE_STATUS", "0")))
if name == "cargo":
    print(os.environ.get("CARGO_FIXTURE_OUTPUT", "test result: ok. 1 passed; 0 failed; 0 ignored;"))
    sys.exit(int(os.environ.get("CARGO_FIXTURE_STATUS", "0")))
"""


class ServerContainerDriverTests(unittest.TestCase):
    def run_scope(self, scope: str, *, expected_status: int = 0, **overrides: str) -> list[dict]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "commands.jsonl"
            for name in ("docker", "cargo", "atlas", "psql"):
                path = root / name
                path.write_text(f"#!{sys.executable}\n" + MOCK)
                path.chmod(0o755)
            env = dict(
                os.environ,
                PATH=f"{root}:{os.environ['PATH']}",
                DRIVER_LOG=str(log),
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

    def selected(self, record: dict, cases: tuple[str, ...] = CASES) -> list[str]:
        args = record["args"]
        if record["tool"] != "cargo" or "--lib" not in args:
            return []
        index = args.index("--")
        front, back = args[:index], args[index + 1 :]
        patterns = [arg for arg in front if arg in ("redis_", "shared_redis_")]
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
        self.assertCountEqual(selected, CASES)
        migration = next(i for i, r in enumerate(records) if r["tool"] == "atlas")
        ledger = next(i for i, r in enumerate(records) if r["tool"] == "psql")
        self.assertLess(ledger, migration)
        self.assertIn("--set=ON_ERROR_STOP=1", records[ledger]["args"])
        self.assertEqual(
            records[ledger]["args"][-1], "scripts/tests/prepare_atlas_revision_ledger.sql"
        )
        self.assertEqual(
            records[migration]["args"],
            ["migrate", "apply", "--env", "local", "--revisions-schema", "public"],
        )
        for i, record in enumerate(records):
            if any(case != "redis_code_case" for case in self.selected(record)):
                self.assertGreater(i, migration)

    def test_revision_ledger_failure_stops_migration_and_database_tests(self) -> None:
        rows = self.run_scope("postgres", expected_status=17, PSQL_FIXTURE_STATUS="17")
        self.assertEqual(len([row for row in rows if row["tool"] == "psql"]), 1)
        self.assertFalse(any(row["tool"] in {"atlas", "cargo"} for row in rows))

    def test_mixed_uses_only_the_selected_test_redis(self) -> None:
        records = self.run_scope("all")
        mixed = [r for r in records if CASES[2] in self.selected(r)]
        self.assertEqual(len(mixed), 1)
        self.assertEqual(mixed[0]["urls"], dict.fromkeys(URL_KEYS, "redis://127.0.0.1:16579/0"))

    def test_single_service_scopes_do_not_select_mixed_cases(self) -> None:
        for scope, expected in (("redis", CASES[0]), ("postgres", CASES[1])):
            with self.subTest(scope=scope):
                records = self.run_scope(scope)
                self.assertEqual([c for r in records for c in self.selected(r)], [expected])
                up = [r["args"] for r in records if r["tool"] == "docker" and "up" in r["args"]]
                self.assertEqual(len(up), 1)
                self.assertEqual(up[0][-1], scope)

    def test_redis_uses_only_the_selected_test_redis(self) -> None:
        records = self.run_scope("redis")
        calls = [r for r in records if CASES[0] in self.selected(r)]
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["urls"], dict.fromkeys(URL_KEYS, "redis://127.0.0.1:16579/0"))

    def test_declared_mixed_tests_use_the_mixed_lane(self) -> None:
        declaration = re.compile(r'#\[ignore\s*=\s*"([^\"]*)"\]\s*(?:async\s+)?fn\s+(\w+)')
        mixed = []
        for source in (ROOT / "crates/server/src").rglob("*.rs"):
            for reason, name in declaration.findall(source.read_text()):
                description = reason.lower()
                if "redis" in description and any(
                    word in description for word in ("postgres", "database_url")
                ):
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


if __name__ == "__main__":
    unittest.main()
