"""Single bounded verified-TLS Redis connection; no reconnect or retry."""

from __future__ import annotations

import socket
import ssl
from typing import Any

from organization_recovery_store import require

MAX_REQUEST = 65536
MAX_REPLY = 1024 * 1024
MAX_ARRAY = 4096
MAX_DEPTH = 8


class Resp:
    def __init__(self, host: str, port: int, ca: str, user: str, password: str) -> None:
        context = ssl.create_default_context(cadata=ca)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        connection = socket.create_connection((host, port), timeout=5)
        try:
            self.socket = context.wrap_socket(connection, server_hostname=host)
        except BaseException:
            connection.close()
            raise
        self.file = self.socket.makefile("rb")
        self.failed = False
        try:
            require(self.call("AUTH", user, password) == "OK", "Redis authentication refused")
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        self.failed = True
        self.file.close()
        self.socket.close()

    def take(self, size: int) -> bytes:
        require(0 <= size <= self.remaining, "Redis reply budget exceeded")
        self.remaining -= size
        value = self.file.read(size)
        require(len(value) == size, "incomplete Redis reply")
        return value

    def line(self) -> bytes:
        value = self.file.readline(min(4096, self.remaining) + 1)
        require(len(value) <= min(4096, self.remaining), "Redis line budget exceeded")
        self.remaining -= len(value)
        require(value.endswith(b"\r\n"), "incomplete Redis line")
        return value[:-2]

    def read(self, depth: int = 0) -> Any:  # noqa: PLR0911 — fixed RESP2 variants
        require(depth <= MAX_DEPTH, "Redis reply nesting exceeded")
        kind = self.take(1)
        value = self.line()
        if kind == b"+":
            return value.decode("utf-8", "strict")
        require(kind != b"-", "Redis command refused")
        require(kind in (b":", b"$", b"*"), "unexpected Redis reply kind")
        number = int(value)
        if kind == b":":
            return number
        if number == -1:
            return None
        require(number >= 0, "invalid Redis reply length")
        if kind == b"$":
            data = self.take(number)
            require(self.take(2) == b"\r\n", "invalid Redis bulk terminator")
            return data.decode("utf-8", "strict")
        require(number <= MAX_ARRAY, "Redis array budget exceeded")
        return [self.read(depth + 1) for _ in range(number)]

    def call(self, *arguments: str) -> Any:
        require(not self.failed, "failed Redis connection cannot be reused")
        values = [item.encode("utf-8", "strict") for item in arguments]
        require(sum(map(len, values)) <= MAX_REQUEST, "Redis request budget exceeded")
        message = b"*" + str(len(values)).encode() + b"\r\n"
        for value in values:
            message += b"$" + str(len(value)).encode() + b"\r\n" + value + b"\r\n"
        self.remaining = MAX_REPLY
        try:
            self.socket.sendall(message)
            return self.read()
        except BaseException:
            self.close()
            raise
