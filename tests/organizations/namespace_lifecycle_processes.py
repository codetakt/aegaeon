"""Census only a qualification's exact Nix clients and private builder directories."""

from __future__ import annotations

# ruff: noqa: EM101, TRY003 - fixed CLI rejection diagnostics, as in CI controllers.
import argparse
import hashlib
import json
import os
import re
import selectors
import signal
import stat
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterator
    from contextlib import AbstractContextManager

NONCE = re.compile(r"[0-9a-f]{32}")
PROFILE = re.compile(r"aegaeon-userns-[0-9a-f]{32}")
STOP = False
PROFILES = Path("/sys/kernel/security/apparmor/profiles")


def interrupted(_signum: int, _frame: object) -> None:
    global STOP  # noqa: PLW0603 - record-only cancellation preserves descriptor cleanup.
    STOP = True


def requests(deadline: float):
    buffer = bytearray()
    with selectors.DefaultSelector() as watcher:
        watcher.register(sys.stdin, selectors.EVENT_READ)
        while not STOP and time.monotonic() < deadline:
            if not watcher.select(timeout=max(0, min(0.1, deadline - time.monotonic()))):
                continue
            data = os.read(sys.stdin.fileno(), 4097)
            if not data:
                return
            buffer.extend(data)
            if len(buffer) > 4096:
                raise ValueError("census request exceeds its bound")
            while b"\n" in buffer:
                line, _, buffer = buffer.partition(b"\n")
                yield json.loads(line)


def process_fields(pid: int) -> list[str]:
    path = Path("/proc") / str(pid) / "stat"
    parts = path.read_text().rsplit(") ", 1)
    fields = parts[1].split() if len(parts) == 2 else []
    if len(fields) < 20:
        # Only confirmed disappearance permits the callers' missing-process path.
        # A malformed observation of a present or unreadable process is uncertainty.
        path.stat()
        raise ValueError("incomplete process stat")
    return fields


class Census:
    """Keep scratch/cwd inodes pinned; never interpret a common /build path as ownership."""

    def __init__(self, binding: dict[str, Any]):
        self.binding = binding
        self.scratch = Path(binding["scratch"])
        self.scratch.mkdir(mode=0o755)
        self.descriptor = os.open(self.scratch, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        value = os.fstat(self.descriptor)
        self.identity = (value.st_dev, value.st_ino)
        self.pins: dict[tuple[int, int], tuple[int, Path]] = {}
        self.known: dict[tuple[int, str], dict[str, Any]] = {}

    def close(self) -> None:
        for descriptor, _ in self.pins.values():
            os.close(descriptor)
        os.close(self.descriptor)

    def scan_directory(
        self, parent: Path
    ) -> AbstractContextManager[Iterator[os.DirEntry[str]]] | None:
        try:
            return os.scandir(parent)
        except FileNotFoundError:
            if parent == self.scratch:
                raise
            # Nix can remove a finished build after it was queued for scanning.
            # A missing/replaced pinned root is still an ownership failure.
            current = self.scratch.lstat()
            if (current.st_dev, current.st_ino) != self.identity:
                raise ValueError("private build directory was replaced") from None
            return None

    def directories(self) -> dict[tuple[int, int], Path]:
        current = self.scratch.lstat()
        if (current.st_dev, current.st_ino) != self.identity or not stat.S_ISDIR(current.st_mode):
            raise ValueError("private build directory was replaced")
        result = {self.identity: self.scratch}
        pending = [(self.scratch, 0)]
        count = 0
        while pending:
            parent, depth = pending.pop()
            entries = self.scan_directory(parent)
            if entries is None:
                continue
            with entries as directory:
                for entry in directory:
                    count += 1
                    if count > 256:
                        raise ValueError("private build directory inventory exceeds its bound")
                    try:
                        info = entry.stat(follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    if stat.S_ISDIR(info.st_mode):
                        result[(info.st_dev, info.st_ino)] = Path(entry.path)
                        if depth < 2 and entry.name not in {"proc", "sys", "dev", "nix"}:
                            pending.append((Path(entry.path), depth + 1))
        return result

    def classify(  # noqa: PLR0911 - disjoint exact client/probe/payload identities.
        self, environment: list[bytes], executable: str, uid: int
    ) -> str | None:
        marker = f"AEGAEON_NAMESPACE_LIFECYCLE_CASE={self.binding['nonce']}".encode()
        if (
            marker in environment
            and executable == self.binding["nix_executable"]
            and uid == self.binding["caller_uid"]
        ):
            return "client"
        for kind, output in self.binding["outputs"].items():
            if ("out=" + output).encode() in environment:
                payload = f"AEGAEON_NAMESPACE_LIFECYCLE_NONCE={self.binding['nonce']}".encode()
                if kind == "payload" and payload not in environment:
                    return None
                return str(kind)
        return None

    def inspect(  # noqa: PLR0911 - refuse before reading or authorizing unrelated work.
        self, pid: int, directories: dict[tuple[int, int], Path]
    ) -> dict[str, Any] | None:
        process = Path("/proc") / str(pid)
        try:
            fields = process_fields(pid)
            if int(fields[19]) < self.binding["owner_starttime"]:
                return None
            # Read internally to select exact identities; do not emit unrelated environment data.
            with (process / "environ").open("rb") as stream:
                data = stream.read(1024 * 1024 + 1)
            if len(data) > 1024 * 1024:
                return None
            executable = str((process / "exe").readlink())
            uid = process.stat().st_uid
            kind = self.classify(data.split(b"\0"), executable, uid)
            if kind is None:
                return None
            if fields[0] in {"Z", "X"}:
                return None
            cwd = (process / "cwd").stat()
            identity = (cwd.st_dev, cwd.st_ino)
            # A fixed probe output may also be built elsewhere; that does not confer ownership.
            if kind != "client" and identity not in directories:
                return None
            if kind != "client" and identity not in self.pins:
                descriptor = os.open(process / "cwd", os.O_RDONLY | os.O_DIRECTORY)
                pinned = os.fstat(descriptor)
                if (pinned.st_dev, pinned.st_ino) != identity:
                    os.close(descriptor)
                    raise ValueError("builder cwd changed during ownership capture")
                self.pins[identity] = (descriptor, directories[identity])
            return {
                "pid": pid,
                "starttime": fields[19],
                "uid": uid,
                "group": int(fields[2]),
                "session": int(fields[3]),
                "kind": kind,
                "executable": executable,
                "argv_sha256": hashlib.sha256((process / "cmdline").read_bytes()).hexdigest(),
                "cwd_device": identity[0],
                "cwd_inode": identity[1],
            }
        except (FileNotFoundError, ProcessLookupError):
            return None

    def snapshot(self) -> dict[str, Any]:
        directories = self.directories()
        rows = []
        for item in Path("/proc").iterdir():
            if item.name.isdigit():
                row = self.inspect(int(item.name), directories)
                if row is not None:
                    rows.append(row)
                    self.known[(row["pid"], row["starttime"])] = row
        remaining = []
        for pid, starttime in self.known:
            try:
                fields = process_fields(pid)
                if fields[19] == starttime:
                    remaining.append({"pid": pid, "starttime": starttime, "state": fields[0]})
            except (FileNotFoundError, ProcessLookupError):
                continue
        return {"rows": sorted(rows, key=lambda row: row["pid"]), "known_remaining": remaining}

    def stop(self, signum: int) -> list[dict[str, Any]]:
        if signum not in {signal.SIGTERM, signal.SIGKILL}:
            raise ValueError("unsupported owned recovery signal")
        actions = []
        for row in self.snapshot()["rows"]:
            try:
                pidfd = os.pidfd_open(row["pid"])
            except ProcessLookupError:
                continue
            try:
                if row["kind"] != "client":
                    descriptor, path = self.pins[(row["cwd_device"], row["cwd_inode"])]
                    current, pinned = path.lstat(), os.fstat(descriptor)
                    if (current.st_dev, current.st_ino) != (pinned.st_dev, pinned.st_ino):
                        raise ValueError("builder directory identity changed before recovery")
                if self.inspect(row["pid"], self.directories()) != row:
                    continue
                try:
                    # The checked task may exit now; the FD cannot target a reused PID.
                    signal.pidfd_send_signal(pidfd, signum)
                    actions.append({"identity": row, "signal": signum})
                except ProcessLookupError:
                    continue
            finally:
                os.close(pidfd)
        return actions


def profile_present(name: str) -> bool:
    if PROFILE.fullmatch(name) is None:
        raise ValueError("invalid owned profile name")
    return any(line.startswith(name + " (") for line in PROFILES.read_text().splitlines())


def observed_snapshot(census: Census, profile: str | None) -> dict[str, Any]:
    # When absence is observed, only subsequently observed live work can
    # establish unsafe ordering. Earlier live rows may describe work already stopped.
    presence = {} if profile is None else {"profile_present": profile_present(profile)}
    return {**presence, **census.snapshot()}


def serve(binding: dict[str, Any]) -> None:
    census = Census(binding)
    try:
        print(
            json.dumps({"ready": True, "pid": os.getpid(), "scratch_identity": census.identity}),
            flush=True,
        )
        for request in requests(binding["deadline"]):
            operation = request["operation"]
            if operation == "snapshot":
                result = observed_snapshot(census, request.get("profile"))
            elif operation == "stop":
                result = {"actions": census.stop(request["signal"]), **census.snapshot()}
            elif operation == "finish":
                print(json.dumps({"ok": True, **census.snapshot()}), flush=True)
                break
            else:
                raise ValueError("unknown census operation")
            print(json.dumps({"ok": True, "monotonic": time.monotonic(), **result}), flush=True)
    finally:
        census.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binding", required=True, type=Path)
    args = parser.parse_args()
    binding = json.loads(args.binding.read_text())
    if (
        os.geteuid() != 0
        or NONCE.fullmatch(binding["nonce"]) is None
        or binding["scratch"] != "/run/aegaeon-namespace-" + binding["nonce"]
        or set(binding["outputs"]) != {"probe", "payload"}
        or type(binding["caller_uid"]) is not int
        or binding["caller_uid"] <= 0
        or type(binding["owner_starttime"]) is not int
        or binding["owner_starttime"] <= 0
        or type(binding["deadline"]) not in (int, float)
        or not time.monotonic() < binding["deadline"] <= time.monotonic() + 180
    ):
        raise ValueError("invalid private census binding")
    # No raising asynchronous handler can interrupt descriptor cleanup.
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, interrupted)
    serve(binding)


if __name__ == "__main__":
    main()
