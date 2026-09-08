#!/usr/bin/env bash

set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
export ROOT
# Anchor the caller's Cargo home before any tool changes working directories.
if [[ -n ${CARGO_HOME:-} ]]; then
	mkdir -p "$CARGO_HOME"
	CARGO_HOME="$(cd "$CARGO_HOME" && pwd)"
	export CARGO_HOME
fi
cd "$ROOT"

# Ensure native compiler for build scripts.
if [[ ${CC:-} == *"wasm32-unknown-wasi"* ]]; then
	unset CC
fi
if [[ ${CXX:-} == *"wasm32-unknown-wasi"* ]]; then
	unset CXX
fi
if [[ -z ${CC:-} ]] && command -v cc >/dev/null 2>&1; then
	CC="$(command -v cc)"
	export CC
fi
if [[ -z ${CXX:-} ]] && command -v c++ >/dev/null 2>&1; then
	CXX="$(command -v c++)"
	export CXX
fi
if [[ -z ${CC_x86_64_unknown_linux_gnu:-} ]]; then
	if command -v clang >/dev/null 2>&1; then
		CC_x86_64_unknown_linux_gnu="$(command -v clang)"
		export CC_x86_64_unknown_linux_gnu
	elif [[ -n ${CC:-} ]]; then
		export CC_x86_64_unknown_linux_gnu="$CC"
	fi
fi
if [[ -z ${CXX_x86_64_unknown_linux_gnu:-} ]]; then
	if command -v clang++ >/dev/null 2>&1; then
		CXX_x86_64_unknown_linux_gnu="$(command -v clang++)"
		export CXX_x86_64_unknown_linux_gnu
	elif [[ -n ${CXX:-} ]]; then
		export CXX_x86_64_unknown_linux_gnu="$CXX"
	fi
fi

# Cargo's normal configuration (including Nix vendoring) remains authoritative.
# Do not create a private CARGO_HOME or force a fresh crates.io git index.
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for tool in cargo cargo-geiger jq python3; do
	command -v "$tool" >/dev/null || {
		echo "$tool not installed" >&2
		exit 1
	}
done

manifest_path=""
network_args=()
while [[ $# -gt 0 ]]; do
	case "$1" in
	--manifest-path)
		[[ $# -ge 2 ]] || {
			echo "--manifest-path needs a value" >&2
			exit 1
		}
		manifest_path="$2"
		shift 2
		;;
	--offline)
		network_args+=(--offline)
		export CARGO_NET_OFFLINE=true
		shift
		;;
	*)
		echo "Unsupported Geiger gate argument: $1" >&2
		exit 1
		;;
	esac
done

GEIGER_ARTIFACT_DIR="${GEIGER_ARTIFACT_DIR:-${SECURITY_ARTIFACT_DIR:-artifacts/security/latest}/geiger}"
mkdir -p "$GEIGER_ARTIFACT_DIR"
artifact_dir="$(cd "$GEIGER_ARTIFACT_DIR" && pwd)"
rm -f "$artifact_dir/gate.json"
run_dir="$(mktemp -d "$artifact_dir/run.XXXXXX")"
metadata_args=(--format-version 1 --no-deps --locked)
if [[ -n $manifest_path ]]; then
	metadata_args+=(--manifest-path "$manifest_path")
fi
cargo metadata "${metadata_args[@]}" "${network_args[@]}" >"$run_dir/metadata.json"
python3 "$script_dir/../validation/geiger_report.py" manifests \
	"$run_dir/metadata.json" "$manifest_path" >"$run_dir/manifests.txt"

# cargo-geiger 0.13 requires a package manifest and cleans its compilation
# inputs itself. One invocation per member supplies both views of the report.
# A disposable target protects the caller's ordinary Cargo build outputs.
target_dir="$(mktemp -d)"
trap 'rm -rf "$target_dir"' EXIT
export CARGO_TARGET_DIR="$target_dir"
status=0
while IFS=$'\t' read -r package_name manifest; do
	echo "[geiger] Analyze $package_name (report: $run_dir/$package_name.json)"
	if cargo geiger --all-targets --all-features --include-tests --locked \
		--output-format Json --manifest-path "$manifest" "${network_args[@]}" \
		>"$run_dir/$package_name.json" 2>"$run_dir/$package_name.stderr"; then
		if ! python3 "$script_dir/../validation/geiger_report.py" check \
			"$run_dir/metadata.json" "$manifest" \
			"$run_dir/$package_name.json" "$run_dir/$package_name.stderr"; then
			status=1
		fi
	else
		scan_status=$?
		echo "[geiger] $package_name failed (exit $scan_status); see diagnostics" >&2
		status=1
	fi
done <"$run_dir/manifests.txt"

if ((status != 0)); then
	echo "[geiger] Analysis incomplete; evidence: $run_dir" >&2
	exit "$status"
fi
jq -Rn --arg evidence "$run_dir" \
	'[inputs | split("\t")[0]] as $members |
	{status: "complete", members: $members, evidence: $evidence, claim: "scan completeness only"}' \
	<"$run_dir/manifests.txt" \
	>"$artifact_dir/gate.json"
echo "[geiger] Analysis complete; evidence: $run_dir"
