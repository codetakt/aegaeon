"""Exercise query deadlines and cancellation without a database supplier."""

from __future__ import annotations

# ruff: noqa: PT009, PT027 - unittest assertions also work without pytest.
import importlib.util
import os
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "organizations/current_database.py"


class DatabaseDeadlineTests(unittest.TestCase):
    def setUp(self):
        self.params = {
            "host": "/fixture/owned-socket",
            "user": "postgres",
            "dbname": "owned",
            "port": "5432",
            "sslmode": "disable",
        }
        self.cancel = mock.Mock()
        self.parent_wait = mock.Mock(side_effect=AssertionError("unbounded parent wait"))
        self.base = type("Connection", (), {"wait": self.parent_wait, "connect": mock.Mock()})
        self.waiting = types.SimpleNamespace(wait_selector=self.drive)
        modules = {
            "current_process": types.SimpleNamespace(check_cancellation=self.cancel),
            "psycopg": types.SimpleNamespace(Connection=self.base, waiting=self.waiting),
            "psycopg.conninfo": types.SimpleNamespace(conninfo_to_dict=lambda _: dict(self.params)),
        }
        with mock.patch.dict(sys.modules, modules):
            spec = importlib.util.spec_from_file_location("bounded_database", SOURCE)
            self.module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self.module)
        self.connection = types.SimpleNamespace(
            pgconn=types.SimpleNamespace(socket=17), close=mock.Mock()
        )

    def drive(self, gen, socket, *, interval):
        self.assertEqual((socket, interval), (17, 0.1))
        try:
            while True:
                gen.send(None)
        except StopIteration as completed:
            return completed.value

    def wait(self, gen):
        return self.module.LocalConnection.wait(self.connection, gen)

    def test_success_and_sql_error_keep_result_and_original_error(self):
        def success():
            yield 1
            return "selected generation"

        self.assertEqual(self.wait(success()), "selected generation")
        self.connection.close.assert_not_called()
        failure = RuntimeError("stand-in SQLSTATE 55006")

        def refused():
            yield 1
            raise failure

        with self.assertRaises(RuntimeError) as caught:
            self.wait(refused())
        self.assertIs(caught.exception, failure)
        self.connection.close.assert_called_once()
        self.parent_wait.assert_not_called()

    def test_deadline_after_every_advance_including_completion_closes(self):
        for finishes in (False, True):
            with self.subTest(finishes=finishes):
                clock = [0]

                def advance(clock=clock, finishes=finishes):
                    clock[0] = 6
                    if finishes:
                        return "late completion"
                    yield 1

                self.connection.close.reset_mock()
                with (
                    mock.patch.object(
                        self.module.time, "monotonic", side_effect=lambda clock=clock: clock[0]
                    ),
                    self.assertRaisesRegex(TimeoutError, "deadline"),
                ):
                    self.wait(advance())
                self.connection.close.assert_called_once()

    def test_cancellation_before_after_yield_and_completion_preserves_primary(self):
        for point in ("before", "yield", "completion"):
            with self.subTest(point=point):
                failure = RuntimeError("recorded cancellation")
                self.cancel.side_effect = failure if point == "before" else None
                advanced = []

                def operation(advanced=advanced, failure=failure, point=point):
                    advanced.append(True)
                    self.cancel.side_effect = failure
                    if point == "completion":
                        return "cancelled completion"
                    yield 1

                self.connection.close.reset_mock()
                self.connection.close.side_effect = OSError("close failed")
                with self.assertRaises(RuntimeError) as caught:
                    self.wait(operation())
                self.assertIs(caught.exception, failure)
                self.assertEqual(advanced, [] if point == "before" else [True])
                self.connection.close.assert_called_once()
                self.assertIn("close failed", failure.__notes__[0])

    def test_timeout_is_checked_while_waiting_for_readiness(self):
        clock = [0]
        sends = []

        def pending():
            while True:
                sends.append(clock[0])
                yield 1

        def waiter(gen, _socket, *, interval):
            self.assertEqual(interval, 0.1)
            next(gen)
            clock[0] = 6
            gen.send(0)

        with (
            mock.patch.object(self.module.time, "monotonic", side_effect=lambda: clock[0]),
            mock.patch.object(self.waiting, "wait_selector", side_effect=waiter),
            self.assertRaises(TimeoutError),
        ):
            self.wait(pending())
        self.assertEqual(sends, [0])
        self.connection.close.assert_called_once()

    def test_local_parameters_reject_network_multi_host_and_ambient_settings(self):
        original = dict(self.params)
        mutations = (
            {"host": "localhost"},
            {"host": "/fixture/a,/fixture/b"},
            {"host": "/fixture/../a"},
            {"host": "/fixture//a"},
            {"hostaddr": "127.0.0.1"},
            {"service": "other"},
            {"port": "0"},
            {"port": "1,2"},
            {"port": "\uff16"},  # Reject a non-ASCII digit accepted by isdigit.
            {"sslmode": "require"},
            {"user": "other"},
            {"dbname": ""},
        )
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(self.module.local_parameters("opaque private URL"), original)
            for mutation in mutations:
                with self.subTest(mutation=mutation):
                    self.params = original | mutation
                    with self.assertRaises(ValueError):
                        self.module.connect("opaque private URL")
            self.params = original
            with (
                mock.patch.dict(os.environ, {"PGSERVICE": "ambient"}),
                self.assertRaises(ValueError),
            ):
                self.module.connect("opaque private URL")
        self.base.connect.assert_not_called()

    def test_connect_handoff_closes_on_pending_cancellation(self):
        failure = RuntimeError("recorded during connect")

        def connected(**kwargs):
            self.assertTrue(kwargs["autocommit"])
            self.assertEqual(kwargs["connect_timeout"], 5)
            self.assertEqual(kwargs["host"], "/fixture/owned-socket")
            self.cancel.side_effect = failure
            return self.connection

        self.base.connect.side_effect = connected
        with mock.patch.dict(os.environ, {}, clear=True), self.assertRaises(RuntimeError) as caught:
            self.module.connect("private URL")
        self.assertIs(caught.exception, failure)
        self.connection.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
