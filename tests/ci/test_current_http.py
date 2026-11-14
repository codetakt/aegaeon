"""HTTP ownership mechanics use fixed Python children; no network supplier runs."""

from __future__ import annotations

# ruff: noqa: PT009, PT027 - unittest assertions also work without pytest.
import importlib.util
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/validation"))
import database_execution as execution  # noqa: E402 - fixed repository helper.


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class HttpOwnershipTests(unittest.TestCase):
    def setUp(self):
        owner = tempfile.TemporaryDirectory(prefix="aeg-http-unit-")
        self.addCleanup(owner.cleanup)
        self.directory = Path(owner.name)
        self.process = load("http_test_process", ROOT / "tests/organizations/current_process.py")
        self.worker = load("http_test_worker", ROOT / "tests/organizations/current_http_probe.py")
        with mock.patch.dict(
            sys.modules, {"current_process": self.process, "current_http_probe": self.worker}
        ):
            self.http = load("http_test_owner", ROOT / "tests/organizations/current_http.py")
        self.base = "http://127.0.0.1:12345"
        self.children = []
        self.real_popen = subprocess.Popen
        self.addCleanup(self.reclaim)

    def reclaim(self):
        for child in self.children:
            execution.stop_process_group(child, grace=0.1)

    def sleeper(self, _argv, **kwargs):
        child = self.real_popen(
            [str(Path("/proc/self/exe").resolve()), "-c", "import time; time.sleep(10)"], **kwargs
        )
        self.children.append(child)
        return child

    def assert_stopped(self):
        self.assertEqual(self.process.unconfirmed_groups(), [])
        for child in self.children:
            self.assertFalse(execution.group_running(child.pid))
            self.assertIsNotNone(child.returncode)

    def test_request_method_body_header_proxy_and_status_preserved(self):
        for path in ("/health", "/ready", "/token"):
            with self.subTest(path=path):
                result = mock.MagicMock()
                result.__enter__.return_value.status = 204
                opener = mock.Mock()
                opener.open.return_value = result
                with mock.patch.object(
                    self.worker.urllib.request, "build_opener", return_value=opener
                ) as build:
                    self.assertEqual(self.worker.request_status(self.base, path, 2), 204)
                request = opener.open.call_args.args[0]
                self.assertEqual(request.full_url, self.base + path)
                self.assertEqual(request.get_header("X-forwarded-proto"), "https")
                self.assertEqual(request.get_method(), "POST" if path == "/token" else "GET")
                self.assertEqual(
                    request.data, b"grant_type=client_credentials" if path == "/token" else None
                )
                self.assertEqual(build.call_args.args[0].proxies, {})
                redirect = build.call_args.args[1]
                self.assertIsNone(
                    redirect.redirect_request(
                        request, None, 302, "redirect", {}, "https://example.test/unknown"
                    )
                )
                self.assertEqual(opener.open.call_args.kwargs, {"timeout": 2})
        error = self.worker.urllib.error.HTTPError(self.base, 503, "unavailable", {}, None)
        with mock.patch.object(self.worker.urllib.request, "build_opener") as build:
            build.return_value.open.side_effect = error
            self.assertEqual(self.worker.request_status(self.base, "/ready", 2), 503)

    def test_request_and_result_reject_unowned_malformed_or_nonregular_inputs(self):
        for base, path in (
            ("https://127.0.0.1:1", "/ready"),
            ("http://localhost:1", "/ready"),
            (self.base + "/", "/ready"),
            (self.base, "/unknown"),
        ):
            with self.subTest(base=base, path=path), self.assertRaises(ValueError):
                self.worker.validate_request(base, path)
        output = self.directory / "result.json"
        good = {"base": self.base, "path": "/ready", "status": 503, "completed_at": 2}
        output.write_text(json.dumps(good))
        self.assertEqual(self.http.read_result(output, self.base, "/ready", (1, 3)), 503)
        for change in (
            {"status": True},
            {"status": "503"},
            {"status": 99},
            {"status": 600},
            {"base": self.base + "/"},
            {"path": "/health"},
            {"extra": 1},
            {"completed_at": None},
            {"completed_at": True},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                output.write_text(json.dumps(good | change))
                self.http.read_result(output, self.base, "/ready", (1, 3))
        for value in (0, 3, 4):
            output.write_text(json.dumps(good | {"completed_at": value}))
            with self.assertRaises(TimeoutError):
                self.http.read_result(output, self.base, "/ready", (1, 3))
        for raw in ('{"status":503,"status":200}', "null", "{", "x" * 4097):
            output.write_text(raw)
            with self.assertRaises(ValueError):
                self.http.read_result(output, self.base, "/ready", (1, 3))
        output.unlink()
        with self.assertRaises(FileNotFoundError):
            self.http.read_result(output, self.base, "/ready", (1, 3))
        os.mkfifo(output)
        with self.assertRaises(ValueError):
            self.http.read_result(output, self.base, "/ready", (1, 3))
        output.unlink()
        output.symlink_to(self.directory / "unknown")
        with self.assertRaises(OSError):
            self.http.read_result(output, self.base, "/ready", (1, 3))

    def test_total_deadline_stops_a_child_that_never_returns(self):
        started = time.monotonic()
        with (
            mock.patch.object(self.http.subprocess, "Popen", side_effect=self.sleeper),
            self.assertRaisesRegex(TimeoutError, "total deadline"),
        ):
            self.http.response(self.base, "/ready", self.directory, timeout=0.05)
        self.assertLess(time.monotonic() - started, 5)
        self.assert_stopped()

    def test_cancellation_stops_both_concurrent_probes(self):
        with (
            mock.patch.object(self.http.subprocess, "Popen", side_effect=self.sleeper),
            self.assertRaisesRegex(RuntimeError, "signal 15"),
            self.http.probes(self.base, ("/ready", "/token"), self.directory) as owned,
        ):
            self.assertEqual(len(self.process.unconfirmed_groups()), 2)
            self.process.interrupted(signal.SIGTERM, None)
            self.http.poll_all(owned)
        self.assert_stopped()

    def test_one_failed_stop_does_not_skip_other_probe_or_replace_primary(self):
        primary = ValueError("original work error")
        real_stop = self.http.stop_owned

        def stop(child):
            if child is self.children[0]:
                raise TimeoutError("stop confirmation failed")  # noqa: EM101, TRY003
            real_stop(child)

        with (
            mock.patch.object(self.http.subprocess, "Popen", side_effect=self.sleeper),
            mock.patch.object(self.http, "stop_owned", side_effect=stop),
            self.assertRaises(ValueError) as caught,
            self.http.probes(self.base, ("/ready", "/token"), self.directory),
        ):
            raise primary
        self.assertIs(caught.exception, primary)
        self.assertIn("unconfirmed", primary.__notes__[0])
        self.assertEqual(self.process.unconfirmed_groups(), [self.children[0].pid])
        self.assertFalse(execution.group_running(self.children[1].pid))
        # Independent fixture cleanup follows the tested failed confirmation.
        real_stop(self.children[0])
        self.assert_stopped()

    def test_pending_deadlines_are_polled_during_health_and_completed_probe_stays_done(self):
        pending = mock.Mock()
        pending.poll.side_effect = TimeoutError("pending request expired")
        with (
            mock.patch.object(self.http.subprocess, "Popen", side_effect=self.sleeper),
            self.assertRaisesRegex(TimeoutError, "pending request"),
        ):
            self.http.response(self.base, "/health", self.directory, timeout=2, pending=[pending])
        self.assert_stopped()
        probe = self.http.Probe(self.base, "/ready", self.directory, 1)
        probe.child = types.SimpleNamespace(poll=lambda: 0)
        probe.deadline = 2
        probe.result.write_text(
            json.dumps({"base": self.base, "path": "/ready", "status": 503, "completed_at": 1.5})
        )
        with (
            mock.patch.object(self.http, "stop_owned"),
            mock.patch.object(self.http.time, "monotonic", return_value=120),
        ):
            probe.poll()
            probe.poll()
        self.assertEqual(probe.status, 503)

    def test_readiness_does_not_retry_missing_private_result(self):
        with mock.patch.dict(
            sys.modules,
            {
                "current_process": self.process,
                "current_http": self.http,
                "current_database": types.SimpleNamespace(connect=mock.Mock()),
                "psycopg": types.ModuleType("psycopg"),
            },
        ):
            outage = load("http_test_outage", ROOT / "tests/organizations/current_outage.py")
        fixture = object.__new__(outage.OutageFixture)
        fixture.base, fixture.directory = self.base, self.directory
        with (
            mock.patch.object(
                outage, "response", side_effect=FileNotFoundError("missing result")
            ) as response,
            self.assertRaises(FileNotFoundError),
        ):
            fixture.ready(types.SimpleNamespace(poll=lambda: None))
        response.assert_called_once()


if __name__ == "__main__":
    unittest.main()
