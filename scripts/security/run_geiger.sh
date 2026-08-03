#!/usr/bin/env bash

set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
export ROOT
cd "$ROOT"

# Ensure native compiler for build scripts.
if [[ ${CC:-} == *"wasm32-unknown-wasi"* ]]; then
	unset CC
fi
if [[ ${CXX:-} == *"wasm32-unknown-wasi"* ]]; then
	unset CXX
fi
if [[ -z ${CC:-} ]] && command -v cc >/dev/null 2>&1; then
	export CC="$(command -v cc)"
fi
if [[ -z ${CXX:-} ]] && command -v c++ >/dev/null 2>&1; then
	export CXX="$(command -v c++)"
fi
if [[ -z ${CC_x86_64_unknown_linux_gnu:-} ]]; then
	if command -v clang >/dev/null 2>&1; then
		export CC_x86_64_unknown_linux_gnu="$(command -v clang)"
	elif [[ -n ${CC:-} ]]; then
		export CC_x86_64_unknown_linux_gnu="$CC"
	fi
fi
if [[ -z ${CXX_x86_64_unknown_linux_gnu:-} ]]; then
	if command -v clang++ >/dev/null 2>&1; then
		export CXX_x86_64_unknown_linux_gnu="$(command -v clang++)"
	elif [[ -n ${CXX:-} ]]; then
		export CXX_x86_64_unknown_linux_gnu="$CXX"
	fi
fi

export CARGO_REGISTRIES_CRATES_IO_PROTOCOL="${CARGO_REGISTRIES_CRATES_IO_PROTOCOL:-git}"
export CARGO_NET_GIT_FETCH_WITH_CLI="${CARGO_NET_GIT_FETCH_WITH_CLI:-true}"

if ! command -v cargo-geiger >/dev/null 2>&1; then
	echo "cargo-geiger not installed" >&2
	exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
	echo "jq not installed" >&2
	exit 1
fi

GEIGER_ARTIFACT_DIR="${GEIGER_ARTIFACT_DIR:-${SECURITY_ARTIFACT_DIR:-artifacts/security/latest}/geiger}"
mkdir -p "$GEIGER_ARTIFACT_DIR"
log="$GEIGER_ARTIFACT_DIR/run.log"
: >"$log"

GEIGER_CARGO_HOME="${GEIGER_CARGO_HOME:-$GEIGER_ARTIFACT_DIR/cargo-home}"
mkdir -p "$GEIGER_CARGO_HOME"
export CARGO_HOME="$GEIGER_CARGO_HOME"

GEIGER_CARGO_CONFIG="${GEIGER_CARGO_CONFIG:-$GEIGER_CARGO_HOME/config.toml}"
cat >"$GEIGER_CARGO_CONFIG" <<'EOF'
[registries.crates-io]
protocol = "git"
index = "https://github.com/rust-lang/crates.io-index"

[net]
git-fetch-with-cli = true
EOF

GEIGER_FILTER_RAW="${GEIGER_FILTER_RAW:-1}"
GEIGER_KEEP_FULL="${GEIGER_KEEP_FULL:-1}"

pattern='^(Failed to match \(ignoring source\) package:|Failed to parse file:|WARNING: Dependency file was never scanned:|error: Found [0-9]+ warnings$|Exception: cargo exited with [0-9]+$)'
status=0

manifest_path=""
extra_args=()
while [[ $# -gt 0 ]]; do
	case "$1" in
	--manifest-path)
		manifest_path="$2"
		shift 2
		;;
	*)
		extra_args+=("$1")
		shift
		;;
	esac
done

if [[ -n $manifest_path ]]; then
	manifests="$manifest_path"
else
	manifests=$(cargo metadata --format-version 1 --no-deps | jq -r '.packages[].manifest_path')
fi

tmpdir="$(mktemp -d)"
trap 'if [ -n "${tmpdir:-}" ]; then rm -rf "$tmpdir"; fi' RETURN

write_raw_output() {
	local output="$1"
	local raw_path="$2"
	local full_path="$3"

	if [[ $GEIGER_FILTER_RAW == "1" ]]; then
		if [[ $GEIGER_KEEP_FULL == "1" && -n $full_path ]]; then
			printf "%s\n" "$output" >"$full_path"
		fi
		printf "%s\n" "$output" | grep -vE "$pattern" >"$raw_path"
	else
		printf "%s\n" "$output" >"$raw_path"
	fi
}

gate_exclude=("$ROOT/crates/ffi/Cargo.toml")
gate_manifests=()
while IFS= read -r manifest; do
	case "$manifest" in
	"$ROOT"/*) ;;
	*) continue ;;
	esac
	[ -f "$manifest" ] || continue
	skip=0
	for excluded in "${gate_exclude[@]}"; do
		if [[ $manifest == "$excluded" ]]; then
			skip=1
			break
		fi
	done
	if ((skip == 0)); then
		gate_manifests+=("$manifest")
	fi
done <<<"$manifests"

echo "[geiger] Gate: first-party crates (no dependencies)" | tee -a "$log"
for manifest in "${gate_manifests[@]}"; do
	pkg_dir="$(dirname "$manifest")"
	pkg_name="$(basename "$pkg_dir")"
	echo "[geiger] Gate scan $pkg_name" | tee -a "$log"
	pkg_log="$GEIGER_ARTIFACT_DIR/${pkg_name}.gate.txt"
	pkg_log_raw="$GEIGER_ARTIFACT_DIR/${pkg_name}.gate.raw.txt"
	pkg_log_full=""
	if [[ $GEIGER_FILTER_RAW == "1" && $GEIGER_KEEP_FULL == "1" ]]; then
		pkg_log_full="$GEIGER_ARTIFACT_DIR/${pkg_name}.gate.full.txt"
	fi
	pkg_target_dir="$tmpdir/$pkg_name-gate"
	geiger_output=""
	geiger_status=0
	if ! geiger_output=$(CARGO_TARGET_DIR="$pkg_target_dir" cargo geiger --all-targets --all-features --no-deps --manifest-path "$manifest" "${extra_args[@]}" 2>&1); then
		geiger_status=$?
	fi
	write_raw_output "$geiger_output" "$pkg_log_raw" "$pkg_log_full"
	printf "%s\n" "$geiger_output" | grep -vE "$pattern" | tee "$pkg_log"
	if ((geiger_status != 0)); then
		status=1
	fi
	rm -rf "$pkg_target_dir" || true
done

echo "[geiger] Report: dependencies included (non-blocking)" | tee -a "$log"
while IFS= read -r manifest; do
	case "$manifest" in
	"$ROOT"/*) ;;
	*) continue ;;
	esac
	[ -f "$manifest" ] || continue
	pkg_dir="$(dirname "$manifest")"
	pkg_name="$(basename "$pkg_dir")"
	echo "[geiger] Report scan $pkg_name" | tee -a "$log"
	pkg_log="$GEIGER_ARTIFACT_DIR/${pkg_name}.report.txt"
	pkg_log_raw="$GEIGER_ARTIFACT_DIR/${pkg_name}.report.raw.txt"
	pkg_log_full=""
	if [[ $GEIGER_FILTER_RAW == "1" && $GEIGER_KEEP_FULL == "1" ]]; then
		pkg_log_full="$GEIGER_ARTIFACT_DIR/${pkg_name}.report.full.txt"
	fi
	pkg_target_dir="$tmpdir/$pkg_name-report"
	geiger_output=""
	if ! geiger_output=$(CARGO_TARGET_DIR="$pkg_target_dir" cargo geiger --all-targets --all-features --manifest-path "$manifest" "${extra_args[@]}" 2>&1); then
		write_raw_output "$geiger_output" "$pkg_log_raw" "$pkg_log_full"
		printf "%s\n" "$geiger_output" | grep -vE "$pattern" | tee "$pkg_log"
		echo "[geiger] Non-fatal: dependency scan reported warnings/errors." | tee -a "$log"
		rm -rf "$pkg_target_dir" || true
		continue
	fi
	write_raw_output "$geiger_output" "$pkg_log_raw" "$pkg_log_full"
	printf "%s\n" "$geiger_output" | grep -vE "$pattern" | tee "$pkg_log"
	rm -rf "$pkg_target_dir" || true
done <<<"$manifests"

exit "$status"
