# ruff: noqa: PT009, PT027 - unittest assertions remain active under Python -O
"""Check receipt admission, terminal status and later evidence-write boundaries."""

from __future__ import annotations

import io
import json
import os
import runpy
import unittest
from unittest.mock import patch

import test_sanitizers as fixture


class BrokenOutput(io.StringIO):
    def write(self, _text):
        message = "controlled terminal failure"
        raise OSError(message)


class SanitizerBoundaryTests(fixture.SanitizerLoggingFixture, unittest.TestCase):
    def namespace(self):
        return runpy.run_path(str(fixture.ROOT / "scripts/sanitizers/sanitizer_runner.py"))

    def test_receipt_replay_uses_shared_orchestration_without_spawning(self):
        binding = runpy.run_path(str(fixture.ROOT / "scripts/sanitizers/sanitizer_binding.py"))
        namespace = binding["main"].__globals__
        evidence = self.root / "evidence"
        evidence.mkdir()
        original = b'{"status":"failed","stage":"preflight","commands":[],"units":[]}'
        summary = evidence / "run-summary.json"
        summary.write_bytes(original)
        info = summary.stat()
        snapshot = {"identity": [info.st_dev, info.st_ino], "content": original.hex()}
        directory = namespace["Directory"](evidence)
        invocation = {**directory.binding(), "initial_summary": snapshot}
        result = self.run_wrapper(SANITIZER_INVOCATION_BINDING=json.dumps(invocation))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        raw = summary.read_bytes()
        process_module = self.namespace()["Supervisor"].command.__globals__["subprocess"]
        with (
            patch.object(process_module, "Popen") as spawn,
            patch.dict(os.environ, self.environment, clear=True),
            patch("pathlib.Path.cwd", return_value=self.root),
        ):
            namespace["validate_completed"](
                directory, json.dumps(snapshot), self.root / "suite-target"
            )
        spawn.assert_not_called()
        self.assertEqual(summary.read_bytes(), raw)

    def test_terminal_failure_records_failure_and_preserves_primary_status(self):
        runner = self.namespace()
        for status in (0, 71, 143):
            with self.subTest(status=status):
                summary = {"status": "failed" if status else "completed", "error": "primary"}
                supervisor = runner["Supervisor"](self.root, summary)
                with patch("sys.stderr" if status else "sys.stdout", BrokenOutput()):
                    observed = runner["finish"](supervisor, status)
                self.assertEqual(observed, status or 1)
                saved = json.loads((self.root / "run-summary.json").read_text())
                self.assertEqual(saved["status"], "failed")
                self.assertEqual(saved["exit_code"], status or 1)
                self.assertEqual(saved["logging_exit_code"], 1)

    def test_later_directory_replacement_cannot_redirect_summary(self):
        runner = self.namespace()
        artifacts = self.root / "bound"
        artifacts.mkdir()
        supervisor = runner["Supervisor"](artifacts, {"status": "failed", "commands": []})
        supervisor.save()
        artifacts.rename(self.root / "held")
        external = self.root / "external"
        external.mkdir()
        sentinel = external / "run-summary.json"
        sentinel.write_bytes(b"external receipt remains exact\n")
        artifacts.symlink_to(external, target_is_directory=True)
        with self.assertRaises(OSError):
            supervisor.save()
        self.assertEqual(sentinel.read_bytes(), b"external receipt remains exact\n")
        self.assertEqual(
            json.loads((self.root / "held/run-summary.json").read_text())["status"], "failed"
        )

    def test_future_raw_log_alias_rejects_before_truncation_or_spawn(self):
        runner = self.namespace()
        for alias in ("symlink", "hardlink"):
            with self.subTest(alias=alias):
                artifacts = self.root / alias
                artifacts.mkdir()
                supervisor = runner["Supervisor"](artifacts, {"commands": []})
                external = self.root / f"external-{alias}"
                external.write_bytes(b"preserve raw bytes\n")
                leaf = artifacts / "001-probe.stdout.log"
                if alias == "symlink":
                    leaf.symlink_to(external)
                else:
                    leaf.hardlink_to(external)
                with (
                    patch.object(supervisor.command.__globals__["subprocess"], "Popen") as spawn,
                    self.assertRaises(runner["Failure"]),
                ):
                    supervisor.command(["unused"], os.environ.copy(), 1, "probe")
                self.assertEqual(external.read_bytes(), b"preserve raw bytes\n")
                self.assertEqual(supervisor.summary["commands"][0]["status"], "failed")
                self.assertNotIn("pid", supervisor.summary["commands"][0])
                spawn.assert_not_called()

    def test_zero_launcher_without_execution_fails_and_cleans_prepared_target(self):
        self.make_tool("nix", "raise SystemExit(0)")
        result = self.run_suite()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("sanitizer smoke: ok", result.stdout)
        self.assertFalse((self.root / "suite-target").exists())
        receipt = self.shared_receipt()
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["preflight_phase"], "launcher")

    def test_incomplete_or_unrelated_receipts_cannot_pass_zero_launcher(self):
        mutations = {
            "empty": 'receipt["commands"] = []; receipt["units"] = []',
            "invocation": 'receipt["invocation"]["initial_summary"]["identity"][1] += 1',
            "package": 'receipt["packages"] = ["another"]',
            "target": 'receipt["units"][0]["targets"].pop()',
            "command": 'receipt["commands"][-1]["status"] = "failed"',
            "named": 'receipt["units"][0]["targets"][0]["completed"] = ["invented"]',
        }
        source = (self.bin / "nix").read_text()
        for name, mutation in mutations.items():
            with self.subTest(name=name):
                # A genuine model-controller receipt is mutated at one boundary;
                # empty fabricated success is never a positive fixture.
                code = (
                    "import json\nsummary = evidence / 'run-summary.json'\n"
                    "receipt = json.loads(summary.read_text())\n"
                    + mutation
                    + "\nsummary.write_text(json.dumps(receipt))\n"
                )
                (self.bin / "nix").write_text(
                    source.replace('print("inert modeled sanitizer output")', code)
                )
                result = self.run_suite()
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertNotIn("sanitizer smoke: ok", result.stdout)
                self.assertFalse((self.root / "suite-target").exists())
                receipt = self.shared_receipt()
                self.assertEqual(receipt["status"], "failed")
                archived = self.shared / "sanitizers" / receipt["rejected_summary"]
                self.assertEqual(json.loads(archived.read_text())["status"], "completed")
                self.assertIn("invalid completion receipt", result.stdout)

    def test_owned_no_run_is_emitted_once_through_both_entrypoints(self):
        for flags in ("--no-run", "--no-run --no-run"):
            for route in ("standalone", "suite"):
                with self.subTest(flags=flags, route=route):
                    result = (
                        self.run_wrapper(SANITIZER_CARGO_FLAGS=flags)
                        if route == "standalone"
                        else self.run_suite(SANITIZER_CARGO_FLAGS=flags)
                    )
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    receipt = self.summary() if route == "standalone" else self.shared_receipt()
                    build = next(
                        command
                        for command in receipt["commands"]
                        if command["phase"].startswith("build-")
                    )
                    self.assertEqual(build["args"].count("--no-run"), 1)


if __name__ == "__main__":
    unittest.main()
