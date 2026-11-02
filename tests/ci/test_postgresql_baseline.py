"""Keep independently supplied PostgreSQL defaults and runtime checks aligned."""

# ruff: noqa: PT009, PT027 - unittest keeps these checks available without pytest
from __future__ import annotations

import importlib.util
import re
import runpy
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "check_postgresql_version", ROOT / "scripts/tests/check_postgresql_version.py"
)
assert SPEC is not None
assert SPEC.loader is not None
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)
VERSION = (ROOT / "ci/postgresql-version").read_text().strip()


class PostgresqlDeclarations(unittest.TestCase):
    def test_ci_services_pin_the_complete_version_and_observe_the_server(self) -> None:
        found = []
        for path in sorted((ROOT / ".github/workflows").glob("*.yml")):
            jobs = yaml.safe_load(path.read_text()).get("jobs", {})
            for name, job in jobs.items():
                for service in job.get("services", {}).values():
                    image = service.get("image", "")
                    if image.startswith(("postgres:", "postgres@")):
                        found.append((path.name, name))
                        self.assertEqual(image, f"postgres:{VERSION}", found[-1])
                        self.assertTrue(
                            any(
                                "scripts/tests/check_postgresql_version.py" in step.get("run", "")
                                for step in job.get("steps", [])
                            ),
                            found[-1],
                        )
        self.assertGreaterEqual(len(found), 3)

    def test_compose_defaults_match_the_baseline(self) -> None:
        found = []
        for directory in (ROOT / "scripts", ROOT / "tests"):
            for path in sorted(directory.rglob("*compose*.yml")):
                document = yaml.safe_load(path.read_text()) or {}
                for service in document.get("services", {}).values():
                    image = service.get("image", "")
                    if image.startswith(("postgres:", "postgres@")):
                        found.append(str(path.relative_to(ROOT)))
                        self.assertEqual(
                            image, f"postgres:${{AEGAEON_POSTGRES_IMAGE_TAG:-{VERSION}}}", found[-1]
                        )
        self.assertGreaterEqual(len(found), 3)

    def test_ledger_fixture_uses_the_same_image(self) -> None:
        fixture = runpy.run_path(str(ROOT / "scripts/tests/test_atlas_revision_ledger.py"))
        self.assertEqual(fixture["POSTGRES_IMAGE"], f"postgres:{VERSION}")

    def test_rds_default_matches_without_enabling_major_upgrades(self) -> None:
        directory = ROOT / "infra/tofu/aegaeon-aws-staging"
        block = re.search(
            r'(?ms)^variable "db_engine_version" \{\n(.*?)^\}',
            (directory / "variables.tf").read_text(),
        )
        self.assertIsNotNone(block)
        default = re.search(r'default\s*=\s*"([^\"]+)"', block[1])
        self.assertIsNotNone(default)
        self.assertEqual(default[1], VERSION)
        self.assertRegex(
            (directory / "rds.tf").read_text(), r"allow_major_version_upgrade\s*=\s*false"
        )
        self.assertRegex(
            (directory / "rds.tf").read_text(), r"auto_minor_version_upgrade\s*=\s*false"
        )


class PostgresqlRuntime(unittest.TestCase):
    def test_routing_overrides_are_rejected_before_connecting(self) -> None:
        for name in ("PGHOSTADDR", "PGSERVICE"):
            with (
                self.subTest(name=name),
                patch.dict(runtime.os.environ, {name: "unrelated-target"}),
                patch.object(
                    runtime.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess([], 0, "180006\n", ""),
                ) as call,
                self.assertRaisesRegex(ValueError, "routing overrides"),
            ):
                runtime.check("18.6", "postgresql://localhost:5432/fixture")
            call.assert_not_called()

    def test_complete_stable_version_is_required(self) -> None:
        self.assertEqual(runtime.version_number("18.6"), 180006)
        for value in ("18", "18.6-rc1", "18.6.1", " 18.6", "9.6", "18.10000"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                runtime.version_number(value)

    def test_matching_server_is_observed_without_exposing_credentials_in_argv(self) -> None:
        result = subprocess.CompletedProcess([], 0, "180006\n", "")
        url = "postgresql://fixture:private@127.0.0.1/fixture"
        with patch.object(runtime.subprocess, "run", return_value=result) as call:
            self.assertEqual(runtime.check("18.6", url), 180006)
        self.assertNotIn(url, call.call_args.args[0])
        self.assertEqual(call.call_args.kwargs["env"]["AEGAEON_PG_VERSION_DATABASE_URL"], url)
        self.assertTrue(call.call_args.kwargs["check"])
        self.assertLessEqual(call.call_args.kwargs["timeout"], 15)

    def test_wrong_missing_or_malformed_version_is_rejected(self) -> None:
        for output in ("180001\n", "170011\n", "", "18.6\n", "180006\n180006\n"):
            result = subprocess.CompletedProcess([], 0, output, "")
            with (
                self.subTest(output=output),
                patch.object(runtime.subprocess, "run", return_value=result),
                self.assertRaises(ValueError),
            ):
                runtime.check("18.6", "postgresql://127.0.0.1/fixture")

    def test_no_default_connection_or_failure_fallback(self) -> None:
        with patch.object(runtime.subprocess, "run") as call:
            with self.assertRaises(ValueError):
                runtime.check("18.6", "")
            call.assert_not_called()
        for error in (
            subprocess.CalledProcessError(2, ["psql"]),
            subprocess.TimeoutExpired(["psql"], 15),
        ):
            with (
                self.subTest(error=type(error).__name__),
                patch.object(runtime.subprocess, "run", side_effect=error),
                self.assertRaises(RuntimeError),
            ):
                runtime.check("18.6", "postgresql://127.0.0.1/fixture")

    def test_probe_failure_diagnostics_do_not_include_credentials_or_stderr(self) -> None:
        url = "postgresql://fixture:private@127.0.0.1/fixture"
        for code, reason in (
            (20, "dependency unavailable"),
            (21, "connection or authentication failed"),
            (22, "version query failed"),
            (99, "unexpected child failure"),
        ):
            error = subprocess.CalledProcessError(code, ["python3"], stderr=url)
            with (
                self.subTest(code=code),
                patch.object(runtime.subprocess, "run", side_effect=error),
                self.assertRaisesRegex(RuntimeError, reason) as raised,
            ):
                runtime.check("18.6", url)
            self.assertNotIn("private", str(raised.exception))
            self.assertNotIn(url, str(raised.exception))


if __name__ == "__main__":
    unittest.main()
