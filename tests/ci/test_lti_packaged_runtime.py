"""LTI fixture addresses must remain distinct before services are started."""

from __future__ import annotations

# ruff: noqa: PT009, PT027 - unittest also runs without pytest and under Python -O.
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "lti_packaged_runtime", ROOT / "tests/lti/packaged_runtime.py"
)
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)


class PortAllocator:
    """Deterministically reuse the lowest port as soon as its socket closes."""

    def __init__(self, failure=None):
        self.failure = failure
        self.opened = []
        self.bound = set()
        self.peak_bound = 0

    def socket(self):
        index = len(self.opened)
        if self.failure == "create" and index == 2:
            message = "injected socket creation failure"
            raise OSError(message)
        listener = mock.MagicMock()
        listener.__enter__.return_value = listener
        selected = []

        def bind(address):
            if address != ("127.0.0.1", 0):
                message = "unexpected fixture address"
                raise ValueError(message)
            if self.failure == "bind" and index == 2:
                message = "injected socket bind failure"
                raise OSError(message)
            number = next(port for port in range(40000, 40005) if port not in self.bound)
            selected.append(number)
            self.bound.add(number)
            self.peak_bound = max(self.peak_bound, len(self.bound))

        def close(*_args):
            self.bound.difference_update(selected)

        listener.bind.side_effect = bind
        listener.getsockname.side_effect = lambda: ("127.0.0.1", selected[0])
        listener.__exit__.side_effect = close
        self.opened.append(listener)
        return listener


class PackagedRuntimePortTests(unittest.TestCase):
    def test_database_allocates_five_distinct_addresses_before_startup(self):
        allocator = PortAllocator()
        fixture = runtime.Fixture.__new__(runtime.Fixture)
        fixture.temporary = Path(self.enterContext(tempfile.TemporaryDirectory()))
        fixture.run = mock.Mock(side_effect=RuntimeError("stop before initdb"))
        with (
            mock.patch.object(runtime.socket, "socket", side_effect=allocator.socket),
            self.assertRaisesRegex(RuntimeError, "stop before initdb"),
        ):
            fixture.database()
        self.assertEqual(
            (fixture.pg_port, fixture.redis_port, fixture.backend, fixture.public, fixture.tool),
            (40000, 40001, 40002, 40003, 40004),
        )
        self.assertEqual(allocator.peak_bound, 5)
        self.assertFalse(allocator.bound)
        self.assertEqual(fixture.run.call_count, 1)
        for listener in allocator.opened:
            listener.__exit__.assert_called_once()

    def test_real_sockets_are_distinct_and_closed_after_selection(self):
        socket = runtime.socket.socket
        opened = []

        def create():
            listener = socket()
            self.addCleanup(listener.close)
            opened.append(listener)
            return listener

        with mock.patch.object(runtime.socket, "socket", side_effect=create):
            ports = runtime.fixture_ports()
        self.assertEqual(len(ports), 5)
        self.assertEqual(len(set(ports)), 5)
        self.assertTrue(all(0 < port < 65536 for port in ports))
        self.assertTrue(all(listener.fileno() == -1 for listener in opened))

    def test_creation_failure_closes_previously_bound_sockets(self):
        allocator = PortAllocator("create")
        with (
            mock.patch.object(runtime.socket, "socket", side_effect=allocator.socket),
            self.assertRaisesRegex(OSError, "injected socket creation failure"),
        ):
            runtime.fixture_ports()
        self.assertEqual(len(allocator.opened), 2)
        self.assertFalse(allocator.bound)
        for listener in allocator.opened:
            listener.__exit__.assert_called_once()

    def test_bind_failure_closes_the_failed_and_previous_sockets(self):
        allocator = PortAllocator("bind")
        with (
            mock.patch.object(runtime.socket, "socket", side_effect=allocator.socket),
            self.assertRaisesRegex(OSError, "injected socket bind failure"),
        ):
            runtime.fixture_ports()
        self.assertEqual(len(allocator.opened), 3)
        self.assertFalse(allocator.bound)
        for listener in allocator.opened:
            listener.__exit__.assert_called_once()


if __name__ == "__main__":
    unittest.main()
