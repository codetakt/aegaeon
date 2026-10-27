"""Direct scheduled performance caller prerequisite guards."""

from __future__ import annotations

# ruff: noqa: PT009 - assertions must remain active under Python -O.
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class PerformanceWorkflowTests(unittest.TestCase):
    def test_coverage_threshold_without_optional_host_tools(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/performance.yml").read_text())
        step = next(
            step
            for step in workflow["jobs"]["coverage"]["steps"]
            if step.get("name") == "Check coverage threshold"
        )
        script = step["run"].split("<<'EOF'\n", 1)[1].rsplit("\nEOF", 1)[0]
        bash, awk = shutil.which("bash"), shutil.which("awk")
        self.assertIsNotNone(bash)
        self.assertIsNotNone(awk)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tools = root / "bin"
            tools.mkdir()
            (tools / "awk").symlink_to(awk)
            environment = {**os.environ, "PATH": str(tools)}
            for hits, found, accepted in [
                (3999, 10000, False),
                (40, 100, True),
                (4001, 10000, True),
                (0, 0, False),
            ]:
                with self.subTest(hits=hits, found=found):
                    (root / "lcov.info").write_text(f"LF:{found}\nLH:{hits}\n")
                    result = subprocess.run(  # noqa: S603 - checked-in workflow and synthetic LCOV
                        [bash, "-c", script],
                        cwd=root,
                        env=environment,
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertEqual(
                        result.returncode == 0, accepted, result.stdout + result.stderr
                    )
            (root / "lcov.info").unlink()
            result = subprocess.run(  # noqa: S603 - checked-in workflow with missing LCOV
                [bash, "-c", script],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0, "missing LCOV must fail")

    def test_coverage_cache_never_substitutes_execution_or_cleaning(self):
        job = yaml.safe_load((ROOT / ".github/workflows/performance.yml").read_text())["jobs"][
            "coverage"
        ]
        steps = {step.get("name"): step for step in job["steps"]}
        run = steps["Run tests with coverage"]
        self.assertNotIn("if", run)
        self.assertNotIn("continue-on-error", run)
        self.assertIn("cargo llvm-cov --workspace --lcov", run["run"])
        self.assertNotIn("--no-clean", run["run"])
        self.assertNotIn("--no-run", run["run"])
        cache = steps["Restore coverage dependencies"]
        self.assertNotIn("restore-keys", cache["with"])
        self.assertEqual(cache["with"]["path"], "target/coverage")
        names = list(steps)
        self.assertLess(
            names.index("Restore coverage dependencies"), names.index("Run tests with coverage")
        )
        self.assertLess(
            names.index("Check coverage threshold"),
            names.index("Prepare dependency-only coverage cache"),
        )

    def test_coverage_cache_refuses_retained_profiles_and_cleanup_failure(self):
        job = yaml.safe_load((ROOT / ".github/workflows/performance.yml").read_text())["jobs"][
            "coverage"
        ]
        step = next(
            row
            for row in job["steps"]
            if row.get("name") == "Prepare dependency-only coverage cache"
        )
        bash = shutil.which("bash")
        self.assertIsNotNone(bash)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tools, target = root / "bin", root / "coverage"
            tools.mkdir()
            target.mkdir()
            (tools / "nix").write_text(f'#!{bash}\nexit "${{CLEANUP_EXIT:-0}}"\n')
            (tools / "nix").chmod(0o755)
            env = {
                **os.environ,
                "PATH": str(tools) + os.pathsep + os.environ["PATH"],
                "CARGO_TARGET_DIR": str(target),
            }
            for name, status, success in [
                ("dep.rlib", "0", True),
                ("old.profraw", "0", False),
                ("old.profdata", "0", False),
                ("old.lcov", "0", False),
                ("dep.rlib", "17", False),
            ]:
                with self.subTest(name=name, cleanup_status=status):
                    path = target / name
                    path.write_bytes(b"retained")
                    result = subprocess.run(  # noqa: S603 - actual workflow with controlled cleanup
                        [bash, "-euo", "pipefail", "-c", step["run"]],
                        env=env | {"CLEANUP_EXIT": status},
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
                    path.unlink()

    def test_direct_http_policy_is_scoped_to_public_smoke(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/performance.yml").read_text())
        flags = {"AEGAEON_POLICY_REQUIRE_TRUSTED_PROXY", "AEGAEON_REQUIRE_TLS_PROXY"}
        self.assertTrue(flags.isdisjoint(workflow.get("env", {})))
        for job in workflow["jobs"].values():
            self.assertTrue(flags.isdisjoint(job.get("env", {})))
            for step in job["steps"]:
                environment = step.get("env", {})
                if step.get("name") == "Run public smoke load test":
                    for flag in flags:
                        self.assertEqual(environment[flag], "0")
                    self.assertEqual(environment["PERF_SCENARIO"], "smoke")
                    self.assertEqual(environment["PERF_MANAGE_SERVER"], "1")
                    self.assertEqual(environment["AEGAEON_RUNTIME_ISSUER_HOST"], "127.0.0.1:18095")
                else:
                    self.assertTrue(flags.isdisjoint(environment))
        consumer = (ROOT / "crates/loadtest/src/scenarios/mod.rs").read_text()
        self.assertNotIn("X-Forwarded-Proto", consumer)
        self.assertNotIn('header("Forwarded"', consumer)

    def test_public_smoke_has_shared_stores_and_healthy_services(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/performance.yml").read_text())
        job = workflow["jobs"]["load-test"]
        inventory = (
            ROOT / "crates/server/src/config/runtime_boundary/shared_store/inventory.rs"
        ).read_text()
        names = set(re.findall(r'"(AEGAEON_[A-Z_]+_REDIS_URL)"', inventory))
        self.assertEqual(len(names), 20)
        self.assertEqual({key for key in job["env"] if key.endswith("_REDIS_URL")}, names)
        for name in names:
            self.assertEqual(job["env"][name], "redis://127.0.0.1:6379/0")
        services = job["services"]
        self.assertEqual(services["redis"]["image"], "redis:7-alpine")
        self.assertEqual(services["redis"]["ports"], ["6379:6379"])
        self.assertIn('--health-cmd "redis-cli ping"', services["redis"]["options"])
        self.assertEqual(services["postgres"]["ports"], ["5432:5432"])
        self.assertEqual(job["env"]["DATABASE_URL"], job["env"]["AEGAEON_DATABASE_URL"])

    def test_public_smoke_prepares_active_runtime_before_load(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/performance.yml").read_text())
        job = workflow["jobs"]["load-test"]
        names = [step.get("name") for step in job["steps"]]
        steps = {step.get("name"): step for step in job["steps"]}
        self.assertLess(
            names.index("Prepare public smoke runtime"), names.index("Run public smoke load test")
        )
        prepare = steps["Prepare public smoke runtime"]
        self.assertNotIn("if", prepare)
        command = prepare["run"]
        self.assertIn("set -euo pipefail", command)
        self.assertLess(command.index("atlas migrate apply"), command.index("cargo build"))
        self.assertLess(
            command.index("cargo build"),
            command.index("./target/release/aegaeon-observability-seed"),
        )
        self.assertIn("--release --locked --bin aegaeon-observability-seed", command)
        self.assertIn('echo "::add-mask::${api_key}"', command)
        self.assertIn("runtime-seed.json", command)
        self.assertIn('RUST_LOG=off AEGAEON_OBSERVABILITY_API_KEY="${api_key}"', command)
        self.assertIn(
            "python3 -m json.tool artifacts/perf/ci-load-smoke/runtime-seed.json", command
        )
        self.assertNotIn("GITHUB_ENV", command)
        smoke = steps["Run public smoke load test"]
        self.assertEqual(
            job["env"]["AEGAEON_RUNTIME_ISSUER_HOST"], smoke["env"]["AEGAEON_RUNTIME_ISSUER_HOST"]
        )
        self.assertEqual(smoke["env"]["PERF_APPLY_DATABASE_MIGRATIONS"], "0")
        self.assertIn("--functional-only", smoke["run"])
        self.assertIn("ci/validate_load_smoke.py", steps["Validate public functional smoke"]["run"])

    def test_runtime_shell_starts_outside_checkout_but_commands_use_checkout(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/performance.yml").read_text())
        prepare = next(
            step
            for step in workflow["jobs"]["load-test"]["steps"]
            if step.get("name") == "Prepare public smoke runtime"
        )
        script = prepare["run"].split("# The loopback OIDC-off fixture", 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkout, tools = root / "aegaeon", root / "bin"
            checkout.mkdir()
            tools.mkdir()
            bash = shutil.which("bash")
            self.assertIsNotNone(bash)
            (tools / "nix").write_text(
                f"#!{bash}\nset -euo pipefail\n"
                'test "$PWD" != "$EXPECTED_SOURCE"\n'
                'test "$1" = develop\ntest "$2" = "$EXPECTED_SOURCE#ci"\n'
                'test "$3" = --command\nshift 3\nexec "$@"\n'
            )
            for name in ("atlas", "cargo"):
                (tools / name).write_text(
                    f"#!{bash}\nset -euo pipefail\n"
                    'test "$PWD" = "$EXPECTED_SOURCE"\n'
                    f'printf "%s\\n" "{name} $*" >> "$CALLS"\n'
                )
            for path in tools.iterdir():
                path.chmod(0o755)
            calls = root / "calls"
            result = subprocess.run(  # noqa: S603 - actual workflow with synthetic commands
                [bash, "-c", script],
                cwd=checkout,
                env={
                    **os.environ,
                    "PATH": str(tools) + os.pathsep + os.environ["PATH"],
                    "EXPECTED_SOURCE": str(checkout),
                    "CALLS": str(calls),
                    "TMPDIR": str(root),
                },
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(
                calls.read_text().splitlines(),
                [
                    "atlas migrate apply --env local --revisions-schema public",
                    "cargo build --release --locked --bin aegaeon-observability-seed",
                ],
            )
            self.assertEqual(list(checkout.iterdir()), [])
            self.assertEqual({path.name for path in root.iterdir()}, {"aegaeon", "bin", "calls"})

    def test_policy_mixed_execution_and_acceptance_share_pending_prerequisite(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/performance.yml").read_text())
        job = workflow["jobs"]["load-test"]
        self.assertEqual(workflow["env"]["POLICY_MIXED_PREREQUISITES"], "pending")
        for job_name, workflow_job in workflow["jobs"].items():
            with self.subTest(job=job_name):
                self.assertNotIn("POLICY_MIXED_PREREQUISITES", workflow_job.get("env", {}))
                for step in workflow_job["steps"]:
                    self.assertNotIn("POLICY_MIXED_PREREQUISITES", step.get("env", {}))
        steps = {step.get("name"): step for step in job["steps"]}
        self.assertNotIn("validate-kpis", workflow["jobs"])
        expected = "${{ env.POLICY_MIXED_PREREQUISITES == 'accepted' }}"
        for name, selected_steps in [
            ("Run policy-mixed load smoke", steps),
            ("Validate policy-mixed functional smoke", steps),
        ]:
            with self.subTest(guard=name):
                self.assertEqual(selected_steps[name]["if"], expected)
        for name, selected_steps in [
            ("Report pending policy-mixed prerequisites", steps),
        ]:
            with self.subTest(notice=name):
                pending = selected_steps[name]
                self.assertEqual(
                    pending["if"],
                    "${{ always() && env.POLICY_MIXED_PREREQUISITES != 'accepted' }}",
                )
                for prerequisite in [
                    "activated HTTPS",
                    "client profile",
                    "public-login session",
                    "supplier",
                ]:
                    self.assertIn(prerequisite, pending["run"])
                self.assertIn("pending", pending["run"])
                self.assertIn("skipped", pending["run"])
                self.assertIn("$GITHUB_STEP_SUMMARY", pending["run"])
        self.assertNotIn("AEG_LOADTEST_PROOF_ORIGIN", steps["Run policy-mixed load smoke"]["run"])
        self.assertNotIn("if", steps["Run public smoke load test"])
        self.assertNotIn("if", steps["Validate public functional smoke"])
        self.assertIn("nix run .#perf-load", steps["Run public smoke load test"]["run"])


if __name__ == "__main__":
    unittest.main()
