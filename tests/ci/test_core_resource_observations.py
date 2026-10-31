"""Diagnostics retain limited observations without changing check outcomes."""

from __future__ import annotations

import io
import json
import sys
import tempfile
import threading
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))

import core_resource_observations as observer  # noqa: E402


def test_allowlisted_counters_and_missing_file():
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "memory"
        path.write_text("MemTotal: 1024 kB\nMemAvailable: 50 kB\nPrivateValue: 987 kB\n")
        assert observer.counters(path, observer.MEMORY_FIELDS) == {
            "MemTotal": 1024,
            "MemAvailable": 50,
        }
        path.unlink()
        assert "error" in observer.counters(path, observer.MEMORY_FIELDS)


def test_oversized_and_invalid_counters_are_errors():
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "memory"
        for data in ["x" * 65537, "MemTotal: invalid"]:
            path.write_text(data)
            assert "error" in observer.counters(path, observer.MEMORY_FIELDS)


def test_streamed_observation_and_worker_stops_after_failure():
    observed = threading.Event()
    output = io.StringIO()

    def sample():
        observed.set()
        return {"retained": True}

    error = ValueError("original failure")

    def failing_check():
        with observer.observations():
            assert observed.wait(2)
            raise error

    with (
        patch.object(observer, "sample", sample),
        patch.object(observer.sys, "stderr", output),
        pytest.raises(ValueError, match="original failure"),
    ):
        failing_check()
    rows = output.getvalue().splitlines()
    assert len(rows) == 1
    assert json.loads(rows[0].removeprefix("core-resource-observation ")) == {"retained": True}
    assert not any(thread.name == "core-resource-observer" for thread in threading.enumerate())


def test_failed_output_does_not_override_checks():
    with patch("builtins.print", side_effect=OSError("closed output")):
        observer.report()


def test_observer_start_failure_still_runs_and_preserves_check_failure():
    error = ValueError("actual check")
    with (
        patch.object(observer.threading.Thread, "start", side_effect=RuntimeError("no thread")),
        pytest.raises(ValueError, match="actual check"),
        observer.observations(),
    ):
        raise error
