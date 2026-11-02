# Preserve import/annotation behavior of the measured checkpoint.
# ruff: noqa: I001, I002
"""Bounded offline replay process; no native execution or ACK integration."""

import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import time

from analysis_contract import WORKER_ENVIRONMENT, identity
from candidate import Reader, CONTRACT_SHA256, HERE
from dudect_candidate import canonical
from dudect_sparse_runtime import Worker as BaseWorker, MAX_MESSAGE
from dudect_support import require


def implementation():
    import hashlib  # noqa: PLC0415 -- retain initialization order of the measured analysis

    return {
        name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
        for name in ("candidate.py", "worker.py", "scope_contract.json")
    }


class Worker(BaseWorker):
    def __init__(self, path, bindings, analysis, errors):
        self.buffer = b""
        self.process = subprocess.Popen(  # noqa: S603 -- explicit argv; artifact validation precedes execution
            [sys.executable, "-B", "-u", str(Path(__file__).resolve()), "--worker", str(path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=errors,
            start_new_session=True,
            env={**os.environ, **WORKER_ENVIRONMENT, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        try:
            self.exchange(
                {
                    "bindings": bindings,
                    "case_order": list(bindings),
                    "analysis": analysis,
                    "scope": CONTRACT_SHA256,
                    "implementation": implementation(),
                },
                time.monotonic() + 10,
            )
        except BaseException:
            self.close()
            raise

    def exchange(self, request, deadline):
        return super().exchange({**request, "deadline": deadline}, deadline)


def serve(path):  # noqa: PLR0915 -- ordered evidence checks retain each rejection boundary
    resource.setrlimit(resource.RLIMIT_AS, (268435456, 268435456))
    reader = None
    try:
        config = json.loads(sys.stdin.buffer.readline(MAX_MESSAGE + 1))
        require(
            config["scope"] == CONTRACT_SHA256 and config["implementation"] == implementation(),
            "Wrong scope/implementation binding",
        )
        a = config["analysis"]
        require(a == identity(a["mode"], a["packet"], a["unit"]), "Wrong baseline analysis binding")
        order, bindings = config["case_order"], config["bindings"]
        require(len(order) == len(bindings) and set(order) == set(bindings), "Wrong case order")
        reader = Reader(Path(path), {n: bindings[n] for n in order}, a)
        print(json.dumps({"ok": True, "value": {"address_space_bytes": 268435456}}), flush=True)
        while True:
            data = sys.stdin.buffer.readline(MAX_MESSAGE + 1)
            require(data and len(data) <= MAX_MESSAGE, "Missing or unbounded request")
            request = json.loads(data)
            require(time.monotonic() < request["deadline"], "Expired replay deadline")
            final = request.get("finish") is True
            result = reader.finish() if final else reader.push(request["row"], request["deadline"])
            encoded = canonical({"ok": True, "value": result})
            require(len(encoded) < MAX_MESSAGE, "Unbounded replay evidence")
            require(time.monotonic() < request["deadline"], "Replay exceeded deadline")
            sys.stdout.buffer.write(encoded + b"\n")
            sys.stdout.buffer.flush()
            if final:
                break
    except (ValueError, OSError, MemoryError, KeyError) as error:
        print(
            json.dumps({"ok": False, "error": type(error).__name__ + ": " + str(error)}), flush=True
        )
    finally:
        if reader is not None:
            reader.close()


if __name__ == "__main__":
    require(len(sys.argv) == 3 and sys.argv[1] == "--worker", "Explicit offline worker required")
    serve(sys.argv[2])
