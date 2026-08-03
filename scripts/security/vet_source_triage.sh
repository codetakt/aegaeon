#!/usr/bin/env bash
set -euo pipefail

# Download and triage cargo-vet inspection targets for manual review.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${VET_INSPECT_DIR:-$ROOT_DIR/artifacts/security/latest/vet/inspect}"
SRC_DIR="${VET_SOURCE_DIR:-$OUT_DIR/sources}"
TARGETS_FILE="${VET_TARGETS_FILE:-$OUT_DIR/targets.txt}"

if [ ! -f "$TARGETS_FILE" ]; then
	echo "Targets file not found: $TARGETS_FILE" >&2
	exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
	echo "curl not found in PATH" >&2
	exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
	echo "python3 not found in PATH" >&2
	exit 1
fi

mkdir -p "$SRC_DIR"

python3 - "$TARGETS_FILE" "$SRC_DIR" "$OUT_DIR" <<'PY'
import json
import re
import shutil
import tarfile
from pathlib import Path
from urllib.request import urlopen
import sys

targets_file = Path(sys.argv[1])
src_dir = Path(sys.argv[2])
out_dir = Path(sys.argv[3])

def safe_extract(tar: tarfile.TarFile, path: Path) -> None:
	path = path.resolve()
	for member in tar.getmembers():
		member_path = (path / member.name).resolve()
		if not str(member_path).startswith(str(path)):
			raise RuntimeError(f"blocked path traversal: {member.name}")
	try:
		tar.extractall(path, filter="data")
	except TypeError:
		tar.extractall(path)

def read_text(path: Path) -> str:
	try:
		return path.read_text(encoding="utf-8", errors="ignore")
	except Exception:
		return ""

rows = []

for line in targets_file.read_text().splitlines():
	if not line.strip():
		continue
	crate, ver = line.split(maxsplit=1)
	archive = src_dir / f"{crate}-{ver}.crate"
	extract_dir = src_dir / f"{crate}-{ver}"
	url = f"https://crates.io/api/v1/crates/{crate}/{ver}/download"
	if not archive.exists():
		with urlopen(url) as resp:
			archive.write_bytes(resp.read())
	if not extract_dir.exists():
		extract_dir.mkdir(parents=True, exist_ok=True)
		with tarfile.open(archive, "r:gz") as tar:
			safe_extract(tar, extract_dir)

	# Some crates unpack with a top-level directory, some do not.
	root = extract_dir
	children = list(extract_dir.iterdir())
	if len(children) == 1 and children[0].is_dir():
		root = children[0]

	cargo_toml = root / "Cargo.toml"
	if not cargo_toml.exists():
		# Re-extract if we previously created an empty or incomplete directory.
		if extract_dir.exists():
			shutil.rmtree(extract_dir)
		extract_dir.mkdir(parents=True, exist_ok=True)
		with tarfile.open(archive, "r:gz") as tar:
			safe_extract(tar, extract_dir)
		children = list(extract_dir.iterdir())
		root = extract_dir
		if len(children) == 1 and children[0].is_dir():
			root = children[0]
		cargo_toml = root / "Cargo.toml"
	build_rs = root / "build.rs"
	has_build_rs = build_rs.exists()
	cargo_toml_text = read_text(cargo_toml)
	is_proc_macro = bool(re.search(r"(?m)^\\s*proc-macro\\s*=\\s*true\\s*$", cargo_toml_text))

	unsafe_count = 0
	extern_c_count = 0
	asm_count = 0
	for path in root.rglob("*.rs"):
		text = read_text(path)
		unsafe_count += len(re.findall(r"\bunsafe\b", text))
		extern_c_count += len(re.findall(r'extern\s+"C"', text))
		asm_count += len(re.findall(r"\basm!\b", text))

	rows.append({
		"crate": crate,
		"version": ver,
		"proc_macro": is_proc_macro,
		"build_rs": has_build_rs,
		"unsafe_count": unsafe_count,
		"extern_c_count": extern_c_count,
		"asm_count": asm_count,
	})

summary_md = out_dir / "source_triage.md"
summary_json = out_dir / "source_triage.json"
summary_csv = out_dir / "source_triage.csv"

summary_json.write_text(json.dumps(rows, indent=2))

lines = [
	"# cargo-vet source triage",
	"",
	"Generated via `scripts/security/vet_source_triage.sh`.",
	"",
	"| crate | version | proc-macro | build.rs | unsafe count | extern \"C\" | asm! |",
	"| --- | --- | --- | --- | --- | --- | --- |",
]
for row in rows:
	lines.append(
		f"| {row['crate']} | {row['version']} | {row['proc_macro']} | {row['build_rs']} | "
		f"{row['unsafe_count']} | {row['extern_c_count']} | {row['asm_count']} |"
	)
summary_md.write_text("\n".join(lines) + "\n")

csv_lines = [
	"crate,version,proc_macro,build_rs,unsafe_count,extern_c_count,asm_count",
]
for row in rows:
	csv_lines.append(
		f"{row['crate']},{row['version']},{row['proc_macro']},{row['build_rs']},"
		f"{row['unsafe_count']},{row['extern_c_count']},{row['asm_count']}"
	)
summary_csv.write_text("\n".join(csv_lines) + "\n")
PY
