# Security assertions remain active under Python -O.
# ruff: noqa: PT009
"""Exercise the full shell entry point with controlled tool availability."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class WasmSuiteRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.bin = self.root / "bin"
        self.pinned = self.root / "pinned"
        self.suite = self.root / "tests/verified_core_wasm"
        for directory in (self.bin, self.pinned, self.suite):
            directory.mkdir(parents=True)
        bash = shutil.which("bash")
        self.assertIsNotNone(bash)
        self.bash = bash
        (self.bin / "bash").symlink_to(bash)
        self.script(self.bin / "git", 'printf "%s\\n" "$FIXTURE_ROOT"')
        self.script(self.bin / "npm", "exit 0")
        for tool in ("wasm-objdump", "xxd"):
            self.script(self.bin / tool, "exit 0")
        self.script(self.suite / "smoke_test.sh", "exit 0")
        self.script(
            self.suite / "test_equivalence.sh",
            'node --experimental-strip-types equivalence.ts "$@"',
        )
        self.runner = self.suite / "run_all.sh"
        shutil.copyfile(ROOT / "tests/verified_core_wasm/run_all.sh", self.runner)
        self.log = self.root / "calls"
        self.env = {
            **os.environ,
            "PATH": str(self.bin),
            "FIXTURE_ROOT": str(self.root),
            "CALL_LOG": str(self.log),
            "NODE_KIND": "ambient",
            "NODE_SUPPORTED": "0",
            "PINNED_PATH": f"{self.pinned}:{self.bin}",
            "PINNED_SUPPORTED": "1",
            "FAIL_STAGE": "",
        }
        self.env.pop("AEGAEON_WASM_NIX_REENTRY", None)
        node = """
if [[ ${1:-} == -e ]]; then
    [[ $NODE_SUPPORTED == 1 ]]
    exit $?
fi
printf '%s|%s\\n' "$NODE_KIND" "$*" >> "$CALL_LOG"
if [[ -n $FAIL_STAGE && $* == *"$FAIL_STAGE"* ]]; then exit 9; fi
"""
        self.script(self.bin / "node", node)
        self.script(self.pinned / "node", node)

    def script(self, path, body):
        path.write_text(f"#!{self.bash}\n{body}\n")
        path.chmod(0o700)

    def fallback(self, *, broken=False):
        self.script(
            self.bin / "nix",
            "exit 42"
            if broken
            else """
while [[ $# -gt 0 && $1 != --command ]]; do shift; done
[[ $# -gt 0 ]] || exit 43
shift
export PATH="$PINNED_PATH" NODE_KIND=pinned NODE_SUPPORTED="$PINNED_SUPPORTED"
exec "$@"
""",
        )

    def run_suite(self):
        # The executable and all command arguments are fixed, repository-owned inputs.
        return subprocess.run(  # noqa: S603
            [self.bash, str(self.runner), "selected.wasm"],
            env=self.env,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def test_unsupported_runtime_without_fallback_fails(self):
        result = self.run_suite()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertNotIn("ALL TESTS PASSED", result.stdout)

    def test_failed_fallback_cannot_report_success(self):
        self.fallback(broken=True)
        result = self.run_suite()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertNotIn("ALL TESTS PASSED", result.stdout)

    def test_pinned_fallback_covers_every_node_stage_including_equivalence(self):
        self.fallback()
        result = self.run_suite()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = [call for call in self.calls() if "--experimental-strip-types" in call]
        self.assertEqual(len(calls), 12, calls)
        self.assertTrue(all(call.startswith("pinned|") for call in calls), calls)
        self.assertIn("pinned|--experimental-strip-types equivalence.ts selected.wasm", calls)

    def test_invalid_pinned_runtime_fails_without_reentry_loop(self):
        self.fallback()
        self.env["PINNED_SUPPORTED"] = "0"
        result = self.run_suite()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertNotIn("ALL TESTS PASSED", result.stdout)

    def test_supported_runtime_runs_all_stages(self):
        self.env["NODE_SUPPORTED"] = "1"
        result = self.run_suite()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(self.calls()), 12)
        self.assertTrue(all(call.startswith("ambient|") for call in self.calls()))

    def test_stage_failure_remains_a_suite_failure(self):
        self.env.update(NODE_SUPPORTED="1", FAIL_STAGE="package_dist_test.ts")
        result = self.run_suite()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertNotIn("ALL TESTS PASSED", result.stdout)
        self.assertEqual(len(self.calls()), 12)
