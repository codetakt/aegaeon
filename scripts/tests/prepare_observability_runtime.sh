#!/usr/bin/env bash
# Fresh restricted runtime for ordinary functional smoke, not a test substitute.
set -euo pipefail
fixture_directory="${1:?new private fixture directory required}"
python3 scripts/tests/subject_ownership_fixture.py prepare-runtime "$fixture_directory"
python3 - "$fixture_directory" <<'PY'
import json
import os
import secrets
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

fixture = Path(sys.argv[1])
url = json.loads((fixture / "suppliers.json").read_text())["urls"]["runtime"]
# The database-backed browser session store requires an envelope key even when
# this fixture only exercises telemetry. Keep it scoped to the disposable runtime.
with (fixture / "runtime-env.sh").open("r+") as output:
    if os.fstat(output.fileno()).st_mode & 0o077:
        raise SystemExit("runtime environment must be private before adding its key")
    key = secrets.token_urlsafe(32)
    output.seek(0, os.SEEK_END)
    output.write("export AEGAEON_KEY_ENCRYPTION_KEY=" + key + "\n")
# A CI workflow explicitly selects this helper; local execution need not export.
if "GITHUB_ENV" in os.environ:
    print("::add-mask::" + unquote(urlsplit(url).password or ""))
    print("::add-mask::" + url)
    print("::add-mask::" + key)
    with Path(os.environ["GITHUB_ENV"]).open("a") as output:
        output.write("AEGAEON_DATABASE_URL=" + url + "\nDATABASE_URL=" + url + "\n")
        output.write("AEGAEON_KEY_ENCRYPTION_KEY=" + key + "\n")
PY
