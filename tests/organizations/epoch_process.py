"""Actual process/output budgets for the fixed epoch preparer's owned invocation."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operations", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.operations))
    import organization_cutover_epoch_native as native  # noqa: PLC0415
    from organization_recovery_store import RecoveryRefusedError  # noqa: PLC0415

    def invoke(code):
        return native.bounded([sys.executable, "-c", code], {"PATH": os.defpath})

    value = "x" * 100_000
    assert invoke("import json; print(json.dumps({'value':'x'*100000}))") == {"value": value}
    for stream in ("stdout", "stderr"):
        with pytest.raises(RecoveryRefusedError, match="output budget"):
            invoke(f"import sys; sys.{stream}.write('x'*{native.MAX_OUTPUT + 1})")
    with pytest.raises(RecoveryRefusedError, match="preparation refused"):
        invoke("raise SystemExit(7)")
    with pytest.raises(json.JSONDecodeError):
        invoke("print('invalid JSON')")
    started = time.monotonic()
    with patch.object(native, "DEADLINE", 0.25):
        with pytest.raises(RecoveryRefusedError, match="deadline"):
            invoke("import time; time.sleep(10)")
        # Parent exits; descendant retains the pipes. Deadline must kill the
        # still-owned group and reap its original leader, not wait for EOF forever.
        with pytest.raises(RecoveryRefusedError, match="deadline"):
            invoke("import os,time; child=os.fork(); time.sleep(10) if child==0 else os._exit(0)")
    assert time.monotonic() - started < 5
    # A successful wait relinquishes PID ownership; no later killpg is permitted.
    with patch.object(native.os, "killpg", side_effect=AssertionError("signalled reaped PID")):
        assert invoke("print('{}')") == {}
    args.output.write_text(
        json.dumps({"passed": True, "cases": 8, "deadlineFixtureSeconds": 0.25}) + "\n"
    )


if __name__ == "__main__":
    main()
