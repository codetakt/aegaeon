# Preserve import/annotation behavior of the measured checkpoint.
# ruff: noqa: I001, I002
"""Bounded current-prefix integration; ordinary and positive roles stay separate."""

import contextlib
import copy
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import time

import analysis_runtime
from analysis_contract import WORKER_ENVIRONMENT, identity as baseline_identity, significant  # noqa: F401 -- retain imported-module initialization in this measured checkpoint
from candidate import Reader as ScopeReader, CONTRACT_SHA256 as SCOPE_SHA256
from contract import identity as qualification_identity, PROFILES, TARGETS  # noqa: F401 -- retain imported-module initialization in this measured checkpoint
from dudect_candidate import canonical, digest
from dudect_sparse_runtime import Worker as BaseWorker, MAX_MESSAGE
from dudect_support import require
from qualification import inspect_crop
import run_candidate

HERE = Path(__file__).resolve().parent


def identity(packet, unit, profile):
    require(profile in PROFILES, "Unknown sensitivity profile")
    files = {}
    for folder in (HERE, HERE.parent / "dudect_calibration_scope"):
        for p in sorted(folder.iterdir()):
            if p.suffix in (".py", ".json", ".inc"):
                files[str(p.relative_to(HERE.parent))] = digest(p.read_bytes())
    return {
        "schema": "role-live-analysis/3",
        "profile": profile,
        "baseline": baseline_identity("distributed", packet, unit),
        "scope_sha256": SCOPE_SHA256,
        "qualification": qualification_identity(),
        "implementation": files,
        "adopted": False,
    }


def validate_identity(a):
    b = a["baseline"]
    require(
        a == identity(b["packet"], b["unit"], a["profile"]), "Live analysis implementation changed"
    )


class Reader(ScopeReader):
    def __init__(self, path, bindings, analysis):
        super().__init__(path, bindings, analysis["baseline"])
        self.live_analysis = analysis
        self.crop_seen = {n: set() for n in bindings}

    def push(self, row, deadline=None):
        require(deadline is not None and time.monotonic() < deadline, "Expired live prefix")
        proof = super().push(row, deadline)
        cr = None
        if proof["distributed"] is not None:
            d = proof["distributed"]
            tests = proof["effective"]["tests"][1:101]
            now = []
            for test, pair in zip(tests, d["moments"], strict=True):
                check = inspect_crop(test, pair, d["test_counts"], deadline)
                if check["detected"]:
                    now.append(test["id"])
            self.crop_seen[row["case"]].update(now)
            cr = {
                k: copy.deepcopy(d[k])
                for k in (
                    "look",
                    "through_batch",
                    "reserved_counts",
                    "test_counts",
                    "cutoffs",
                    "moments",
                )
            }
            cr.update(
                tests=copy.deepcopy(tests),
                raw_class_counts=proof["effective"]["raw_class_counts"],
                detected_now=now,
                detected_ever=sorted(self.crop_seen[row["case"]]),
            )
        proof.update(
            schema="role-live-prefix/3",
            analysis_sha256=digest(canonical(self.live_analysis)),
            crop_record=cr,
        )
        require(time.monotonic() < deadline, "Live prefix exceeded deadline")
        return proof


class Worker(analysis_runtime.Worker):
    def __init__(self, path, bindings, errors, *, analysis):
        self.buffer = b""
        self.analysis = analysis
        self.analysis_journal = None
        self.process = subprocess.Popen(  # noqa: S603 -- explicit argv; artifact validation precedes execution
            [sys.executable, "-B", "-u", str(HERE / "live_runtime.py"), "--worker", str(path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=errors,
            start_new_session=True,
            env=os.environ | WORKER_ENVIRONMENT | {"PYTHONDONTWRITEBYTECODE": "1"},
        )
        try:
            BaseWorker.exchange(
                self,
                {"bindings": bindings, "case_order": list(bindings), "analysis": analysis},
                time.monotonic() + 10,
            )
        except BaseException:
            self.close()
            raise


@contextlib.contextmanager
def installed(analysis):
    old_worker, old_stream = run_candidate.Worker, run_candidate.RuntimeStream
    run_candidate.Worker = lambda path, bindings, errors: Worker(
        path, bindings, errors, analysis=analysis
    )
    run_candidate.RuntimeStream = analysis_runtime.Stream
    try:
        yield
    finally:
        run_candidate.Worker, run_candidate.RuntimeStream = old_worker, old_stream


def replay(output, bindings, rows, analysis):
    validate_identity(analysis)
    old = analysis_runtime.Worker
    analysis_runtime.Worker = Worker
    try:
        return analysis_runtime.replay(output, bindings, rows, analysis)
    finally:
        analysis_runtime.Worker = old


def serve(path):  # noqa: PLR0915 -- ordered evidence checks retain each rejection boundary
    resource.setrlimit(resource.RLIMIT_AS, (268435456, 268435456))
    reader = None
    try:
        require(
            all(os.environ.get(k) == v for k, v in WORKER_ENVIRONMENT.items()),
            "Worker environment changed",
        )
        config = json.loads(sys.stdin.buffer.readline(MAX_MESSAGE + 1))
        a = config["analysis"]
        validate_identity(a)
        bindings, order = config["bindings"], config["case_order"]
        require(len(order) == len(bindings) and set(order) == set(bindings), "Wrong case order")
        reader = Reader(Path(path), {n: bindings[n] for n in order}, a)
        print(json.dumps({"ok": True, "value": {"address_space_ceiling": 268435456}}), flush=True)
        while True:
            data = sys.stdin.buffer.readline(MAX_MESSAGE + 1)
            require(data and len(data) <= MAX_MESSAGE, "Missing/unbounded worker request")
            req = json.loads(data)
            deadline = req["deadline"]
            require(time.monotonic() < deadline, "Expired request")
            final = req.get("finish") is True
            value = reader.finish() if final else reader.push(req["row"], deadline)
            encoded = canonical({"ok": True, "value": value})
            require(len(encoded) < MAX_MESSAGE and time.monotonic() < deadline, "Reply limit")
            sys.stdout.buffer.write(encoded + b"\n")
            sys.stdout.buffer.flush()
            if final:
                break
    except (OSError, ValueError, KeyError, MemoryError) as e:
        print(json.dumps({"ok": False, "error": type(e).__name__ + ": " + str(e)}), flush=True)
    finally:
        if reader is not None:
            reader.close()


if __name__ == "__main__":
    require(len(sys.argv) == 3 and sys.argv[1] == "--worker", "Explicit worker invocation required")
    serve(sys.argv[2])
