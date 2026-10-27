#!/usr/bin/env bash
# A successful Cargo command with an empty filter is not a completed test.
set -euo pipefail

log="$(mktemp)"
trap 'rm -f -- "$log"' EXIT

# Only explicitly prepared test packages reuse compilation. Keep
# every invocation, runtime argument, output and failure; never reuse results.
command=(cargo test "$@")
if [[ -n ${AEGAEON_RFC_TEST_PACKAGE:-} ]]; then
	command=(python3 scripts/validation/rfc_test_package.py run "$AEGAEON_RFC_TEST_PACKAGE" "$@")
elif [[ -n ${AEGAEON_DATABASE_TEST_PACKAGE:-} ]]; then
	command=(python3 scripts/validation/database_test_package.py run "$AEGAEON_DATABASE_TEST_PACKAGE" "$@")
elif [[ -n ${JOSE_SERVER_TEST_PACKAGE:-} && ${1:-} == -p && ${2:-} == aegaeon-server && ${3:-} == --lib ]]; then
	command=(python3 scripts/validation/jose_server_test_package.py run "$JOSE_SERVER_TEST_PACKAGE" "$@")
fi
if "${command[@]}" 2>&1 | tee "$log"; then
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
