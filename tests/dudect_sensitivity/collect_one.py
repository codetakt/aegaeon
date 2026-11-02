# Preserve import/annotation behavior of the measured checkpoint.
# Inline validation reasons remain part of the evidence error protocol.
# ruff: noqa: EM101, I001, I002, TRY003
"""Give only the collector child the two-core launch mask; supervisor stays put."""

import hashlib
import json
import os
from pathlib import Path
import signal
import sys


def inherited_runtime_environment():
    # -B applies only to this interpreter; the native affinity launcher also
    # imports Python modules and must inherit the same no-write contract.
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    sys.dont_write_bytecode = True


def main():
    inherited_runtime_environment()
    path = Path(sys.argv[1])
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != sys.argv[2]:
        raise ValueError("Invocation changed")
    invocation = json.loads(raw)
    cpus = invocation["cpus"]
    if len(cpus) != 2 or cpus != sorted(set(cpus)):
        raise ValueError("Two explicit launch CPUs required")
    os.sched_setaffinity(0, set(cpus))
    if os.sched_getaffinity(0) != set(cpus):
        raise ValueError("Collector launch mask mismatch")
    output = Path(invocation["output"])
    (output / "collector-launch.json").write_text(
        json.dumps({"pid": os.getpid(), "cpus": cpus}) + "\n"
    )
    sys.path.insert(0, invocation["analysis_path"])
    from run_analysis import SOURCE, installed, interrupted  # noqa: PLC0415 -- retain initialization order of the measured analysis
    from analysis_contract import identity, filehash  # noqa: PLC0415 -- retain initialization order of the measured analysis
    import run_candidate  # noqa: PLC0415 -- retain initialization order of the measured analysis

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, interrupted)
    a = invocation["analysis"]
    if a != identity(a["mode"], a["packet"], a["unit"]):
        raise ValueError("Analysis changed")
    if filehash(invocation["binary"]) != invocation["binary_sha256"]:
        raise ValueError("Native changed")
    order = invocation["case_order"]
    if len(order) != len(set(order)) or set(order) != set(invocation["bindings"]):
        raise ValueError("Incomplete or duplicate case order")
    bindings = {name: invocation["bindings"][name] for name in order}
    with installed(a):
        run_candidate.collect(SOURCE, output, Path(invocation["binary"]), "pr", bindings)


if __name__ == "__main__":
    main()
