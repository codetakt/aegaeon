#!/usr/bin/env bash
set -euo pipefail

# Generate non-interactive cargo-vet inspect links for the Phase 1 backlog.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${VET_INSPECT_DIR:-$ROOT_DIR/artifacts/security/latest/vet/inspect}"
DOC_PATH="${VET_INSPECT_DOC:-$ROOT_DIR/docs/policies/dependency-policy.md}"

if [ ! -f "$DOC_PATH" ]; then
	echo "Dependency policy doc not found: $DOC_PATH" >&2
	exit 1
fi
if ! command -v cargo >/dev/null 2>&1; then
	echo "cargo not found in PATH" >&2
	exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
	echo "python3 not found in PATH" >&2
	exit 1
fi

mkdir -p "$OUT_DIR"

python3 - "$DOC_PATH" >"$OUT_DIR/targets.txt" <<'PY'
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text()
pattern = re.compile(r"`([^`@]+)@([^`]+)`")
seen = []
for name, ver in pattern.findall(text):
    key = (name.strip(), ver.strip())
    if key not in seen:
        seen.append(key)
for name, ver in seen:
    print(f"{name} {ver}")
PY

while read -r crate ver; do
	[ -z "${crate:-}" ] && continue
	echo "[vet] inspect ${crate} ${ver}"
	out="$OUT_DIR/${crate}-${ver}.txt"
	log="$OUT_DIR/${crate}-${ver}.log"
	if cargo vet inspect "$crate" "$ver" --mode diff.rs --output-file "$out" --log-file "$log" --output-format human; then
		:
	else
		if ! rg -q "You can inspect the crate here:" "$out"; then
			echo "[vet] ERROR: no inspect URL emitted for ${crate}@${ver}" >&2
		fi
	fi
done <"$OUT_DIR/targets.txt"

python3 - "$OUT_DIR" <<'PY'
import re
import sys
from pathlib import Path

out_dir = Path(sys.argv[1])
targets = out_dir.joinpath("targets.txt").read_text().splitlines()
summary = out_dir / "summary.md"
lines = [
    "# cargo-vet inspect links",
    "",
    "Generated via `cargo vet inspect --mode diff.rs` (non-interactive).",
    "",
    "| crate | version | url |",
    "| --- | --- | --- |",
]
for line in targets:
    if not line.strip():
        continue
    crate, ver = line.split(maxsplit=1)
    out = out_dir / f"{crate}-{ver}.txt"
    url = ""
    if out.exists():
        m = re.search(r"You can inspect the crate here:\\s*(\\S+)", out.read_text())
        if m:
            url = m.group(1)
    lines.append(f"| {crate} | {ver} | {url} |")
summary.write_text("\n".join(lines) + "\n")
PY
