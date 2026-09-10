#!/usr/bin/env python3
"""Compare the shared F* trace fixtures with production Lua on isolated Redis.

This is finite test-and-review correspondence. It does not certify arbitrary
Redis state, Lua translation, Rust serialization, or HTTP response handling.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, BinaryIO

from authcode_redis_fixtures import (
    FIXTURE,
    GENERATED,
    LUA_SOURCE,
    MODEL,
    canonical,
    load_cases,
    lua_script,
    render,
)


class RedisError(Exception):
    """A complete Redis error reply, distinct from a disconnected caller."""


def frame(parts: list[Any]) -> bytes:
    encoded = [str(part).encode() for part in parts]
    return b"*%d\r\n" % len(encoded) + b"".join(b"$%d\r\n" % len(v) + v + b"\r\n" for v in encoded)


def read_reply(stream: BinaryIO) -> tuple[Any, bytes]:
    line = stream.readline()
    if not line.endswith(b"\r\n"):
        raise ConnectionError("Redis closed before a complete reply")
    tag, body = line[:1], line[1:-2]
    if tag in [b"+", b"-"]:
        return (RedisError(body.decode()) if tag == b"-" else body.decode()), line
    if tag == b":":
        return int(body), line
    if tag == b"$":
        length = int(body)
        if length == -1:
            return None, line
        data = stream.read(length + 2)
        if len(data) != length + 2 or not data.endswith(b"\r\n"):
            raise ConnectionError("truncated bulk reply")
        return data[:-2].decode(), line + data
    if tag == b"*":
        count = int(body)
        if count == -1:
            return None, line
        values = []
        raw = line
        for _ in range(count):
            value, chunk = read_reply(stream)
            values.append(value)
            raw += chunk
        return values, raw
    raise ValueError("unsupported Redis response type")


class Connection:
    def __init__(self, port: int):
        self.socket = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.stream = self.socket.makefile("rb")

    def command(self, *parts: Any) -> Any:
        self.socket.sendall(frame(list(parts)))
        value, _ = read_reply(self.stream)
        if isinstance(value, RedisError):
            raise value
        return value

    def close(self) -> None:
        self.stream.close()
        self.socket.close()


def normalize_reply(error: RedisError) -> str:
    message = str(error)
    if message.startswith("WRONGTYPE"):
        return "WRONGTYPE"
    if "integer" in message or "overflow" in message:
        return "INTEGER"
    if "valid float" in message:
        return "NUMBER"
    raise error


def children_record(payload: str) -> dict[str, Any]:
    def unique_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate children field: " + key)
            result[key] = value
        return result

    value = json.loads(payload, object_pairs_hook=unique_fields)
    if not isinstance(value, dict) or set(value) != {"access_tokens", "refresh_token"}:
        raise ValueError("children object must contain exactly the two recorded fields")
    children = value["access_tokens"]
    if (
        not isinstance(value["refresh_token"], str)
        or not isinstance(children, list)
        or len(children) != 1
        or not isinstance(children[0], str)
    ):
        raise ValueError("outside the singleton children encoding domain")
    return value


def snapshot(
    conn: Connection, json_keys: set[str], raw_json: dict[str, str] | None = None
) -> tuple[dict[str, Any], dict[str, int]]:
    state = {}
    expiry = {}
    # The runner owns the entire ephemeral Redis instance. Looking at all keys
    # detects unanticipated keys/effects rather than trusting expected keys.
    for key in sorted(conn.command("KEYS", "*")):
        kind = conn.command("TYPE", key)
        expires = conn.command("PEXPIRETIME", key)
        expiry[key] = expires
        if kind == "string":
            value = conn.command("GET", key)
            if key in json_keys:
                if raw_json is not None:
                    raw_json[key] = value
                kind, value = "json", children_record(value)
        elif kind == "set":
            value = sorted(conn.command("SMEMBERS", key))
        elif kind == "hash":
            flat = conn.command("HGETALL", key)
            value = dict(zip(flat[::2], flat[1::2], strict=True))
        elif kind == "zset":
            flat = conn.command("ZRANGE", key, 0, -1, "WITHSCORES")
            value = {k: int(v) for k, v in zip(flat[::2], flat[1::2], strict=True)}
        else:
            raise ValueError("unmodelled residual Redis type: " + kind)
        state[key] = {"type": kind, "value": value, "expiring": expires >= 0}
    return state, expiry


def server_identity(info: str) -> tuple[str, str]:
    fields = dict(line.split(":", 1) for line in info.splitlines() if ":" in line)
    return fields["process_id"], fields["run_id"]


def seed(conn: Connection, state: dict[str, Any], identity: tuple[str, str]) -> None:
    if server_identity(conn.command("INFO", "server")) != identity:
        raise RuntimeError("refusing to write to Redis not owned by this run")
    conn.command("FLUSHDB")  # This process's isolated, disposable Redis only.
    for key, entry in state.items():
        value = entry["value"]
        kind = entry["type"]
        if kind in ["string", "json"]:
            conn.command("SET", key, canonical(value) if kind == "json" else value)
        elif kind == "set":
            conn.command("SADD", key, *value)
        elif kind == "hash":
            conn.command("HSET", key, *[part for pair in value.items() for part in pair])
        elif kind == "zset":
            conn.command("ZADD", key, *[part for k, v in value.items() for part in (v, k)])
        else:
            raise ValueError("unmodelled initial key type")
        if entry["expiring"]:
            conn.command("PEXPIRE", key, 600_000)


def lose_reply(port: int, command: list[Any], identity: tuple[str, str]) -> dict[str, Any]:
    evidence: dict[str, Any] = {}
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(5)
        proxy_port = listener.getsockname()[1]

        def proxy() -> None:
            try:
                with (
                    listener.accept()[0] as caller,
                    socket.create_connection(("127.0.0.1", port), timeout=5) as backend,
                ):
                    caller.settimeout(5)
                    with caller.makefile("rb") as incoming, backend.makefile("rb") as returned:
                        received, raw_request = read_reply(incoming)
                        if received != [str(v) for v in command] or raw_request != frame(command):
                            raise ValueError("proxy did not receive the exact invocation")
                        backend.sendall(frame(["INFO", "server"]))
                        info, _ = read_reply(returned)
                        if server_identity(info) != identity:
                            raise RuntimeError("proxy target is not the owned Redis process")
                        backend.sendall(raw_request)
                        value, raw_reply = read_reply(returned)
                        if value != "ok":
                            raise ValueError("reply loss requires a completed successful grant")
                        evidence.update(
                            server_reply=value,
                            request_sha256=hashlib.sha256(raw_request).hexdigest(),
                            reply_sha256=hashlib.sha256(raw_reply).hexdigest(),
                        )
                        # Deliberately close without sending any response bytes.
            except Exception as error:
                evidence["fault"] = str(error)

        worker = threading.Thread(target=proxy)
        worker.start()
        client = Connection(proxy_port)
        try:
            client.command(*command)
            raise ValueError("proxy unexpectedly delivered a reply")
        except ConnectionError:
            evidence["caller_observation"] = "disconnected_before_reply"
        finally:
            client.close()
            worker.join(timeout=10)
        if worker.is_alive() or "fault" in evidence or evidence.get("server_reply") != "ok":
            raise ValueError("proxy evidence incomplete: " + repr(evidence))
    return evidence


def run_cases(
    port: int, script: str, out: Path, cases: list[dict[str, Any]], identity: tuple[str, str]
) -> list[dict[str, Any]]:
    records = []
    conn = Connection(port)
    try:
        for case in cases:
            seed(conn, case["initial"], identity)
            json_keys = {
                k
                for state in [case["initial"], case["expected"]]
                for k, v in state.items()
                if v["type"] == "json"
            }
            initial, initial_expiry = snapshot(conn, json_keys)
            if initial != case["initial"]:
                raise ValueError("seed observation mismatch: " + case["name"])
            observations = []
            replies = []
            for index, request in enumerate(case["requests"]):
                command = ["EVAL", script, 18, *request["keys"], *request["args"]]
                event: dict[str, Any] = {
                    "invocation_sha256": hashlib.sha256(frame(command)).hexdigest()
                }
                if case.get("drop_first_reply") and index == 0:
                    event["reply_loss"] = lose_reply(port, command, identity)
                    reply = event["reply_loss"]["server_reply"]
                else:
                    try:
                        reply = conn.command(*command)
                    except RedisError as error:
                        event["raw_error"] = str(error)
                        reply = normalize_reply(error)
                raw_json: dict[str, str] = {}
                state, expiry = snapshot(conn, json_keys, raw_json)
                event["raw_json_values"] = raw_json
                replies.append(reply)
                event.update(reply=reply, state=state, expiry=expiry)
                observations.append(event)
            if replies != case["expected_replies"] or state != case["expected"]:
                (out / (case["name"].replace(":", "_") + ".failure.json")).write_text(
                    json.dumps({"case": case, "observations": observations}, indent=2) + "\n"
                )
                raise ValueError("trace/state mismatch: " + case["name"])
            for key, entry in state.items():
                if entry["expiring"] and expiry[key] != initial_expiry[key]:
                    raise ValueError("expiry was not preserved: " + case["name"])
            if case.get("drop_first_reply") and (
                observations[0]["state"],
                observations[0]["expiry"],
            ) != (state, expiry):
                raise ValueError("lost-reply retry changed state or absolute expiration")
            records.append(
                {
                    "name": case["name"],
                    "initial_expiry": initial_expiry,
                    "observations": observations,
                    "accepted": True,
                }
            )
            (out / "records.json").write_text(json.dumps(records, indent=2) + "\n")
            print(case["name"] + ": accepted", flush=True)
    finally:
        conn.close()
    return records


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", required=True, type=Path)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=False)
    sources = [
        FIXTURE,
        GENERATED,
        MODEL,
        LUA_SOURCE,
        Path(__file__),
        Path(__file__).with_name("authcode_redis_fixtures.py"),
    ]
    source_bytes = {str(p): p.read_bytes() for p in sources}
    source_digests = {p: hashlib.sha256(content).hexdigest() for p, content in source_bytes.items()}
    cases = load_cases(source_bytes[str(FIXTURE)])
    if source_bytes[str(GENERATED)].decode() != render(cases, source_digests[str(FIXTURE)]):
        raise ValueError("F* case source does not match the exact fixture selection")
    executable = shutil.which("redis-server")
    if executable is None:
        raise RuntimeError("redis-server is required")
    executable = str(Path(executable).resolve(strict=True))
    redis_digest = hashlib.sha256(Path(executable).read_bytes()).hexdigest()
    script = lua_script(source_bytes[str(LUA_SOURCE)].decode())
    with tempfile.TemporaryDirectory(prefix="aegaeon-lua-correspondence-") as temporary:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        command = [
            executable,
            "--bind",
            "127.0.0.1",
            "--port",
            str(port),
            "--save",
            "",
            "--appendonly",
            "no",
            "--dir",
            temporary,
        ]
        with (args.out_dir / "redis.log").open("wb") as log:
            server = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
            try:
                for _ in range(100):
                    if server.poll() is not None:
                        raise RuntimeError("isolated Redis terminated")
                    try:
                        conn = Connection(port)
                        version = conn.command("INFO", "server")
                        conn.close()
                        identity = server_identity(version)
                        if identity[0] != str(server.pid):
                            raise RuntimeError(
                                "port is owned by a different Redis process; no writes allowed"
                            )
                        break
                    except OSError:
                        time.sleep(0.05)
                else:
                    raise RuntimeError("isolated Redis never became ready")
                records = run_cases(port, script, args.out_dir, cases, identity)
            finally:
                server.terminate()
                server.wait(timeout=10)
    expected = [case["name"] for case in cases]
    if not records or [record["name"] for record in records] != expected:
        raise ValueError("incomplete or reordered result set")
    if source_digests != {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}:
        raise ValueError("source changed during trace execution")
    if redis_digest != hashlib.sha256(Path(executable).read_bytes()).hexdigest():
        raise ValueError("Redis executable changed during trace execution")
    manifest = {
        "grade": "finite test-and-review correspondence",
        "case_count": len(records),
        "case_names": expected,
        "redis_info": version,
        "redis_executable": executable,
        "redis_sha256": redis_digest,
        "lua_sha256": hashlib.sha256(script.encode()).hexdigest(),
        "inputs": source_digests,
        "records_sha256": hashlib.sha256((args.out_dir / "records.json").read_bytes()).hexdigest(),
    }
    (args.out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
