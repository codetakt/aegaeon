"""Sample CI filesystem capacity without changing cleanup or check decisions."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path


def observe(path: str) -> dict[str, str | int]:
    """Retain the resolved path/device: Nix may be mounted during the job."""
    target = Path(path).absolute()
    try:
        while not target.exists() and target != target.parent:
            target = target.parent
        info = target.stat()
        fs = os.statvfs(target)
        return {
            "requested": path,
            "resolved": str(target),
            "device": info.st_dev,
            "available_bytes": fs.f_bavail * fs.f_frsize,
            "total_bytes": fs.f_blocks * fs.f_frsize,
            "available_inodes": fs.f_favail,
        }
    except OSError as exc:
        return {"requested": path, "error": str(exc)}


def monitor(directory: Path, paths: list[str], interval: float, duration: float) -> None:
    started = time.monotonic()
    count = 0
    with (directory / "samples.jsonl").open("x", encoding="utf-8") as output:
        while True:
            elapsed = time.monotonic() - started
            stopped = (directory / "stop").exists()
            expired = elapsed >= duration
            row = {
                "elapsed_seconds": elapsed,
                "unix_time": time.time(),
                "filesystems": [observe(path) for path in paths],
            }
            output.write(json.dumps(row) + "\n")
            output.flush()
            count += 1
            (directory / "ready").touch(exist_ok=True)
            if stopped or expired:
                break
            next_sample = min(started + duration, time.monotonic() + interval)
            while not (directory / "stop").exists() and time.monotonic() < next_sample:
                time.sleep(min(0.1, max(0, next_sample - time.monotonic())))
    temporary = directory / "completion.json.tmp"
    temporary.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "reason": "requested_stop" if stopped else "deadline",
                "samples": count,
                "interval_seconds": interval,
                "elapsed_seconds": time.monotonic() - started,
                "note": (
                    "Sampled capacity; minima between samples may be missed. "
                    "Not a cleanup authorization."
                ),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    temporary.replace(directory / "completion.json")


def stop(directory: Path) -> int:
    if not directory.is_dir():
        raise ValueError("observation directory is missing")
    (directory / "stop").touch()
    deadline = time.monotonic() + 10
    while not (directory / "completion.json").is_file():
        if time.monotonic() >= deadline:
            print("Disk observation incomplete; retain partial samples.", file=sys.stderr)
            return 1
        time.sleep(0.1)
    print((directory / "completion.json").read_text(encoding="utf-8"))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("start", "monitor", "stop"))
    parser.add_argument("directory", type=Path)
    parser.add_argument("--paths", nargs="+", default=[])
    parser.add_argument("--interval", type=float, default=5)
    parser.add_argument("--duration", type=float, default=7200)
    args = parser.parse_args()
    if not (0 < args.interval <= 60 and 0 < args.duration <= 7200):
        parser.error("interval must be in (0, 60] and duration in (0, 7200]")
    directory = args.directory.absolute()
    if args.mode == "stop":
        return stop(directory)
    if not args.paths:
        parser.error("observation paths are required")
    if args.mode == "monitor":
        monitor(directory, args.paths, args.interval, args.duration)
        return 0
    directory.mkdir(parents=True, exist_ok=False)
    with (directory / "observer.log").open("x", encoding="utf-8") as log:
        child = subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "monitor",
                str(directory),
                "--interval",
                str(args.interval),
                "--duration",
                str(args.duration),
                "--paths",
                *args.paths,
            ],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=log,
            start_new_session=True,
        )
    deadline = time.monotonic() + 10
    while not (directory / "ready").is_file():
        if child.poll() is not None or time.monotonic() >= deadline:
            (directory / "stop").touch()
            print("Disk observer did not become ready.", file=sys.stderr)
            return 1
        time.sleep(0.1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
