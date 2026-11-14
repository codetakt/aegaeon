"""Bounded synchronous queries for the fixture's single local PostgreSQL session."""

from __future__ import annotations

import os
import time
from pathlib import Path

import psycopg
from current_process import check_cancellation
from psycopg import waiting
from psycopg.conninfo import conninfo_to_dict

QUERY_TIMEOUT = 5
CONNECT_TIMEOUT = 5


def checkpoint(deadline):
    check_cancellation()
    if time.monotonic() >= deadline:
        message = "local fixture database operation deadline"
        raise TimeoutError(message)


def guarded(generator, deadline):
    value = None
    while True:
        checkpoint(deadline)
        try:
            state = generator.send(value)
        except StopIteration as completed:
            checkpoint(deadline)
            return completed.value
        checkpoint(deadline)
        value = yield state


def close_after_error(connection, failure):
    try:
        connection.close()
    except BaseException as cleanup_error:  # noqa: BLE001 - retain the original operation error.
        failure.add_note(f"local database close failed: {type(cleanup_error).__name__}")


class LocalConnection(psycopg.Connection):
    def wait(self, gen, interval=0.1):
        # Never enter Connection.wait's cancel-and-drain recovery: its second
        # wait has no total deadline. This fixture uses nonblocking Unix libpq.
        deadline = time.monotonic() + QUERY_TIMEOUT
        try:
            checkpoint(deadline)
            result = waiting.wait_selector(guarded(gen, deadline), self.pgconn.socket, interval=0.1)
            checkpoint(deadline)
        except BaseException as failure:
            close_after_error(self, failure)
            raise
        else:
            return result


def local_parameters(url):
    params = conninfo_to_dict(url)
    expected = {"user", "host", "port", "dbname", "sslmode"}
    host = params.get("host", "")
    if (
        set(params) != expected
        or not host.startswith("/")
        or "," in host
        or str(Path(host)) != host
        or ".." in Path(host).parts
        or params["sslmode"] != "disable"
        or params["user"] != "postgres"
        or not params["dbname"]
        or not params["port"].isascii()
        or not params["port"].isdigit()
        or not 0 < int(params["port"]) < 65536
        or any(name.startswith("PG") for name in os.environ)
    ):
        message = "bounded database access requires the generated single Unix administrator URL"
        raise ValueError(message)
    return params


def connect(url):
    params = local_parameters(url)
    check_cancellation()
    # One Unix host: no DNS or multi-host timeout multiplication. libpq bounds
    # connection establishment; cancellation is checked again before handoff.
    connection = LocalConnection.connect(
        autocommit=True, connect_timeout=CONNECT_TIMEOUT, gssencmode="disable", **params
    )
    try:
        check_cancellation()
    except BaseException as failure:
        close_after_error(connection, failure)
        raise
    return connection
