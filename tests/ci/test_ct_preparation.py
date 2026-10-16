"""Evidence integrity, fixed schedules, and deadline cleanup for preparation research."""

# ruff: noqa: PT009, PT027, E402, S603 -- unittest and fixed local child fixtures
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/diagnostics"))
from build_ct_preparation import PROVIDER, replace_once
from collect_ct_preparation import ordered_bindings
from ct_preparation_plan import check_unit, overlay_unit, schedule, wait_owned
from verify_dudect_analysis_matrix import sha256


class PreparationTests(unittest.TestCase):
    def test_unique_source_anchor(self):
        self.assertEqual(replace_once("abc", "b", "X"), "aXc")
        for source in ("ac", "abbc"):
            with self.assertRaises(ValueError):
                replace_once(source, "b", "X")

    def test_schedule_covers_original_provider_and_controls(self):
        for compiler in ("gcc", "clang"):
            order = schedule(compiler)
            self.assertEqual(len(order), 8)
            self.assertEqual(
                set(order),
                {"O", "S", "P", "U", "nix-controls", "legacy-controls", "signal0", "signal16"},
            )
            self.assertEqual(order[0], "nix-controls")
            self.assertEqual(order[5], "legacy-controls")
        self.assertEqual(schedule("gcc")[1:5], list(reversed(schedule("clang")[1:5])))
        with self.assertRaises(ValueError):
            schedule("unknown")

    def test_shared_elf_and_full_inventory(self):
        build = {
            "source": "source",
            "sources": {},
            "binary": "native",
            "binary_sha256": "hash",
            "variant": "normal",
            "contract_sha256": "contract",
            "build_sha256": "build",
            "numerical_sha256": "numeric",
        }
        units = [overlay_unit(build, PROVIDER, mode) for mode in ("baseline", "class0", "uniform")]
        for unit in units:
            self.assertEqual(list(unit["bindings"]), PROVIDER)
            self.assertEqual(unit["binary"], "native")
            self.assertEqual(unit["maximum_seconds"], 2100)
            self.assertNotIn("AEGAEON_DUDECT_PREPARATION_SIGNAL", unit["environment"])
        self.assertEqual(units[0]["bindings"], units[2]["bindings"])
        with self.assertRaises(ValueError):
            overlay_unit(build, PROVIDER, "unknown")
        with self.assertRaises(ValueError):
            overlay_unit(build, PROVIDER, "uniform", 17)

    def test_changed_inputs_fail_before_acquisition(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "native").write_bytes(b"native")
            (root / "source").write_bytes(b"source")
            unit = {
                "binary": str(root / "native"),
                "binary_sha256": sha256(root / "native"),
                "source": str(root),
                "sources": {"source": sha256(root / "source")},
                "maximum_seconds": 2100,
            }
            check_unit(unit)
            with self.assertRaises(ValueError):
                check_unit({**unit, "maximum_seconds": 2200})
            for field in ("native", "source"):
                path = root / field
                old = path.read_bytes()
                path.write_bytes(b"changed")
                with self.assertRaises(ValueError):
                    check_unit(unit)
                path.write_bytes(old)

    def test_wait_cancels_and_reaps_owned_process(self):
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True
        )
        with self.assertRaises(subprocess.TimeoutExpired):
            wait_owned(child, 0.05)
        self.assertIsNotNone(child.poll())
        with self.assertRaises(ProcessLookupError):
            os.kill(child.pid, 0)

    def test_collector_alarm_cleans_separate_native_session(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source/tests/constant_time"
            source.mkdir(parents=True)
            # Inject only a lifecycle fixture: real child in a separate session,
            # collector cancellation must execute collect's cleanup and save failure.
            (source / "dudect_candidate.py").write_text("significant = bool\n")
            (source / "dudect_contract.py").write_text(
                "class ObservationError(ValueError): pass\nassess_case = contract_roles = bool\n"
            )
            (source / "dudect_support.py").write_text(
                "def require(c,m):\n if not c: raise ValueError(m)\n"
            )
            (source / "run.py").write_text(
                "import json\ndef write_json(p,v): p.write_text(json.dumps(v))\n"
            )
            (source / "run_candidate.py").write_text(
                "import os,signal,subprocess,sys,time\n"
                "def collect(source,evidence,binary,profile,bindings):\n"
                ' p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(60)"],'
                "start_new_session=True)\n"
                ' (evidence/"child.pid").write_text(str(p.pid))\n'
                " try: time.sleep(60)\n"
                " finally: os.killpg(p.pid,signal.SIGTERM);p.wait()\n"
            )
            unit = root / "unit.json"
            unit.write_text(
                json.dumps(
                    {
                        "source": str(root / "source"),
                        "environment": {},
                        "binary": "unused",
                        "cases": ["test"],
                        "bindings": {"test": {}},
                    }
                )
            )
            result = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(ROOT / "scripts/diagnostics/collect_ct_preparation.py"),
                    "--unit",
                    str(unit),
                    "--output",
                    str(root / "observations"),
                    "--seconds",
                    ".5",
                    "--cpus",
                    ",".join(map(str, os.sched_getaffinity(0))),
                ],
                capture_output=True,
                timeout=10,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue((root / "observations/execution-failure.json").is_file())
            pid = int((root / "observations/child.pid").read_text())
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)

    def test_sorted_json_retains_explicit_native_order(self):
        unit = {"cases": PROVIDER, "bindings": {n: {"case_id": "nix/" + n} for n in PROVIDER}}
        saved = json.loads(json.dumps(unit, sort_keys=True))
        self.assertNotEqual(list(saved["bindings"]), PROVIDER)
        self.assertEqual(list(ordered_bindings(saved)), PROVIDER)
        for names in ([], PROVIDER[:-1], [*PROVIDER, PROVIDER[0]]):
            with self.assertRaises(ValueError):
                ordered_bindings({**saved, "cases": names})


if __name__ == "__main__":
    unittest.main()
