#!/usr/bin/env bash
# Fresh restricted runtime for ordinary functional smoke, not a test substitute.
set -euo pipefail
fixture_directory="${1:?new private fixture directory required}"
python3 scripts/tests/subject_ownership_fixture.py prepare-runtime "$fixture_directory"
python3 - "$fixture_directory" <<'PY'
import json
import os
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

fixture = Path(sys.argv[1])
url = json.loads((fixture / "suppliers.json").read_text())["urls"]["runtime"]
# A CI workflow explicitly selects this helper; local execution need not export.
if "GITHUB_ENV" in os.environ:
    print("::add-mask::" + unquote(urlsplit(url).password or ""))
    print("::add-mask::" + url)
    with Path(os.environ["GITHUB_ENV"]).open("a") as output:
        output.write("AEGAEON_DATABASE_URL=" + url + "\nDATABASE_URL=" + url + "\n")
PY
