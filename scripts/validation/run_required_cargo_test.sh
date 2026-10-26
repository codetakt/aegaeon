#!/usr/bin/env bash
# A successful Cargo command with an empty filter is not a completed test.
set -euo pipefail

log="$(mktemp)"
trap 'rm -f -- "$log"' EXIT

# Keep the original Cargo arguments, streaming output, and pipeline failure.
if cargo test "$@" 2>&1 | tee "$log"; then
	:
else
	exit "$?"
fi

python3 - "$log" <<'PY'
import re
import sys
from pathlib import Path

summaries = re.findall(
    r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;",
    Path(sys.argv[1]).read_text(errors="replace"),
    flags=re.MULTILINE,
)
if (
    not summaries
    or any(status != "ok" or int(failed) for status, _, failed, _ in summaries)
    or sum(int(passed) for _, passed, _, _ in summaries) == 0
):
    raise SystemExit("required Cargo test did not report any passing executed tests")
PY
