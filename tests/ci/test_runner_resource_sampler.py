from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts/ci"))
import pytest
import sample_runner_resources as subject


class ObservationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ("kernel_oom", "runner_events", "cgroups"):
            stub = patch.object(subject, name, side_effect=FileNotFoundError())
            stub.start()
            self.addCleanup(stub.stop)

    def test_missing_readings_are_not_zero_or_success(self):
        result = subject.sample(self.root)
        assert result["meminfo_kib"]["unavailable"] == "FileNotFoundError"
        assert "value" not in result["vmstat"]

    def test_units_and_unknown_fields_do_not_leak_contents(self):
        p = self.root / "meminfo"
        p.write_text("MemAvailable: 123 kB\nPrivate: secret-value\n")
        assert subject.integers(p, subject.MEMORY, colon=True) == {"MemAvailable": 123}
        p.write_text("MemAvailable: 3 GB\n")
        with pytest.raises(ValueError, match="unexpected_unit"):
            subject.integers(p, subject.MEMORY, colon=True)

    def test_malformed_and_oversized_input_refuse(self):
        p = self.root / "vmstat"
        for content in ["oom_kill -1\n", "oom_kill nan\n", "x" * 65537]:
            p.write_text(content)
            with pytest.raises(ValueError, match=r"invalid_numeric_field|read_bound_exceeded"):
                subject.integers(p, subject.VMSTAT)

    def test_process_identity_and_private_fields(self):
        p = self.root / "42"
        p.mkdir()
        p.joinpath("stat").write_text("42 (private command)) S " + " ".join(["0"] * 18 + ["77"]))
        p.joinpath("status").write_text("Name: private-process\nVmRSS: 123 kB\nThreads: 2\n")
        p.joinpath("environ").write_text("SECRET=must-not-be-read")
        p.joinpath("cmdline").write_text("private-argument")
        result = subject.processes(self.root)
        assert result["top_rss"] == [
            {"pid": 42, "start_ticks": 77, "class": "other", "VmRSS": 123, "Threads": 2}
        ]
        assert "private" not in json.dumps(result)
        assert "SECRET" not in json.dumps(result)

    def test_vanished_process_is_retained_as_unknown(self):
        (self.root / "42").mkdir()
        result = subject.processes(self.root)
        assert result["seen"] == 1
        assert result["error_count"] == 1
        assert result["read"] == 0

    def test_pid_reuse_is_not_a_valid_sample(self):
        (self.root / "42").mkdir()

        def stat(value):
            return "42 (worker) S " + " ".join(["0"] * 18 + [str(value)])

        with patch.object(subject, "read", side_effect=[stat(77), "VmRSS: 8 kB\n", stat(78)]):
            result = subject.processes(self.root)
        assert result["error_count"] == 1
        assert result["top_rss"] == []

    def test_inventory_and_runtime_budgets(self):
        with patch.object(subject, "MAX_PIDS", 0):
            (self.root / "42").mkdir()
            with pytest.raises(ValueError, match="pid_inventory_bound_exceeded"):
                subject.processes(self.root)
        for interval, duration in [(0, 1), (61, 1), (1, 0), (1, 7201)]:
            with pytest.raises(ValueError, match="outside fixed budget"):
                subject.monitor(self.root, interval, duration)

    def test_each_output_flushes_before_completion(self):
        records = []

        def emit(value, *, flush):
            records.append((value, flush))

        with patch.object(subject.time, "monotonic", side_effect=[0, 2, 2]):
            subject.monitor(self.root, 1, 1, emit)
        assert len(records) == 2
        assert all(flush for _, flush in records)
        assert records[0][0].startswith("AEGAEON_RESOURCE ")
        assert records[1][0].startswith("AEGAEON_RESOURCE_END ")

    def test_failed_or_timed_out_reader_is_unknown(self):
        for error in (
            subprocess.TimeoutExpired("journalctl", 2),
            subprocess.CalledProcessError(1, "journalctl"),
        ):

            def failure(error=error):
                raise error

            result = subject.observed(failure)
            assert "value" not in result

    def test_cgroup_unlimited_and_missing_values_are_distinct(self):
        (self.root / "memory.max").write_text("max\n")
        (self.root / "memory.current").write_text("123\n")
        (self.root / "memory.events").write_text("oom 2\noom_kill 1\n")
        result = subject.cgroup_values(self.root)
        assert result["memory.max"] == {"value": "max"}
        assert result["memory.current"] == {"value": 123}
        assert result["memory.events"]["value"]["oom_kill"] == 1
        assert "value" not in result["memory.peak"]

    def test_cgroup_malformed_values_do_not_pass(self):
        (self.root / "memory.current").write_text("private nonnumeric text\n")
        result = subject.cgroup_values(self.root)
        assert "value" not in result["memory.current"]
        assert "private" not in json.dumps(result)


class KernelTests(unittest.TestCase):
    def test_oom_evidence_keeps_victim_without_private_message(self):
        rows = [
            {"MESSAGE": "normal private message", "__MONOTONIC_TIMESTAMP": "100"},
            {
                "MESSAGE": "Out of memory: Killed process 42 (private-command)",
                "__MONOTONIC_TIMESTAMP": "200",
            },
        ]
        completed = subprocess.CompletedProcess(
            [], 0, "\n".join(json.dumps(r) for r in rows).encode(), b""
        )
        with patch.object(subject.subprocess, "run", return_value=completed):
            result = subject.kernel_oom()
        assert result["events"] == [{"timestamp": "200", "victim_pid": 42}]
        assert "private" not in json.dumps(result)


class RunnerLogTests(unittest.TestCase):
    def test_saved_hosted_layout_is_read_without_emitting_log_contents(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "actions-runner/cached"
            log = root / "2.338.2/_diag/Runner_one.log"
            log.parent.mkdir(parents=True)
            log.write_text("[2026-11-03 11:11:05Z INFO Listener] renew private-job-id\n")
            result = subject.runner_events((root,))
            assert result["events"] == [{"timestamp": "2026-11-03 11:11:05Z", "kinds": ["renew"]}]
            assert "private" not in json.dumps(result)

    def test_newest_log_across_known_layouts_is_selected(self):
        with tempfile.TemporaryDirectory() as directory:
            roots = tuple(Path(directory) / name for name in ("cached", "runners"))
            for index, root in enumerate(roots):
                log = root / "2.338.2/_diag/Runner_one.log"
                log.parent.mkdir(parents=True)
                kind = "renew" if index == 0 else "shutdown"
                log.write_text(f"[2026-11-03 11:11:05Z INFO Listener] {kind}\n")
                os.utime(log, (index + 1, index + 1))
            result = subject.runner_events(roots)
            assert result["events"][0]["kinds"] == ["shutdown"]


if __name__ == "__main__":
    unittest.main()
