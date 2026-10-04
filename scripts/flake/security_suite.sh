#!/usr/bin/env bash

# Reject inherited functions before even `set`: they can shadow builtins or
# promote an explicit nonfuzz selection into fuzz dispatch after admission.
# Use only shell syntax until an explicit external interpreter path.
security_function_path="${PATH-}"
security_function_pending=1
security_function_python=""
while [[ $security_function_pending -eq 1 && -z $security_function_python ]]; do
	case "$security_function_path" in
	*:*)
		security_function_directory="${security_function_path%%:*}"
		security_function_path="${security_function_path#*:}"
		;;
	*)
		security_function_directory="$security_function_path"
		security_function_pending=0
		;;
	esac
	security_function_candidate="${security_function_directory:-.}/python3"
	if [[ -f $security_function_candidate && -x $security_function_candidate ]]; then
		security_function_python="$security_function_candidate"
	fi
done
security_function_status=1
if [[ -n $security_function_python ]]; then
	# Bash cannot import slash-named functions. Inspect keys only, never bodies.
	if "$security_function_python" -I -c 'import os, sys; sys.exit(any(key.startswith("BASH_FUNC_") and key.endswith("%%") for key in os.environ))'; then
		security_function_status=0
	fi
fi
if [[ $security_function_status -ne 0 ]]; then
	security_function_error=""
	# Expansion fails before dispatch even if exit, exec or : was imported.
	"${security_function_error:?[security] security suite requires external Python and no inherited shell functions}"
fi

set -euo pipefail

# The Nix app runs from the store, so reject inherited identity overrides here
# before Git can select the repository and inner wrapper. Preserve its arguments.
security_outer_arguments=("$@")
security_outer_stages=()
security_outer_index=0
while [[ $security_outer_index -lt ${#security_outer_arguments[@]} ]]; do
	case "${security_outer_arguments[security_outer_index]}" in
	--fuzz-long) ;;
	--stage)
		security_outer_index=$((security_outer_index + 1))
		if [[ $security_outer_index -ge ${#security_outer_arguments[@]} ]]; then
			echo "[security] --stage requires a value" >&2
			exit 1
		fi
		security_outer_stages+=("${security_outer_arguments[security_outer_index]}")
		;;
	-- | *) break ;;
	esac
	security_outer_index=$((security_outer_index + 1))
done
for security_outer_stage in "${security_outer_stages[@]}"; do
	case "$security_outer_stage" in
	supply-chain | runtime-tests | jose-boundaries | cargo-vet | fuzz | sanitizers | sbom | geiger | udeps) ;;
	*)
		echo "[security] unknown stage" >&2
		exit 1
		;;
	esac
done
security_fuzz_entry=1
if [[ ${#security_outer_stages[@]} -gt 0 ]]; then
	security_fuzz_entry=0
	for security_outer_stage in "${security_outer_stages[@]}"; do
		if [[ $security_outer_stage == fuzz ]]; then
			security_fuzz_entry=1
		fi
	done
fi
if [[ $security_fuzz_entry -eq 1 ]]; then
	for security_compiler_override in RUSTC RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER CARGO_ENCODED_RUSTFLAGS \
		CARGO_BUILD_RUSTC CARGO_BUILD_RUSTC_WRAPPER CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER; do
		if [[ -v $security_compiler_override ]]; then
			echo "[security] inherited compiler overrides are not supported for fuzz execution or cleanup" >&2
			exit 1
		fi
	done
	for security_git_identity in \
		GIT_DIR \
		GIT_WORK_TREE \
		GIT_COMMON_DIR \
		GIT_INDEX_FILE \
		GIT_OBJECT_DIRECTORY \
		GIT_ALTERNATE_OBJECT_DIRECTORIES \
		GIT_CEILING_DIRECTORIES \
		GIT_DISCOVERY_ACROSS_FILESYSTEM \
		GIT_NAMESPACE \
		GIT_SHALLOW_FILE \
		GIT_REPLACE_REF_BASE \
		GIT_NO_REPLACE_OBJECTS \
		GIT_CONFIG \
		GIT_CONFIG_PARAMETERS \
		GIT_CONFIG_COUNT \
		GIT_CONFIG_SYSTEM \
		GIT_CONFIG_GLOBAL \
		GIT_CONFIG_NOSYSTEM \
		"${!GIT_CONFIG_KEY_@}" "${!GIT_CONFIG_VALUE_@}"; do
		if [[ -n $security_git_identity && -v $security_git_identity ]]; then
			echo "[security] inherited Git identity overrides are not supported for fuzz execution or cleanup" >&2
			exit 1
		fi
	done
fi

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
cd "$ROOT"

cc_path="$(command -v cc || true)"
cxx_path="$(command -v c++ || true)"

if [[ -z $cc_path || -z $cxx_path ]]; then
	echo "[security] cc/c++ not found in PATH" >&2
	exit 1
fi

export CC="$cc_path"
export CXX="$cxx_path"
export CC_x86_64_unknown_linux_gnu="$cc_path"
export CXX_x86_64_unknown_linux_gnu="$cxx_path"

cc_root="$(cd "$(dirname "$cc_path")/.." && pwd)"
cc_support="$cc_root/nix-support"

if [[ -d $cc_support ]]; then
	cc_cflags="$(cat "$cc_support/cc-cflags" 2>/dev/null || true)"
	libc_cflags="$(cat "$cc_support/libc-cflags" 2>/dev/null || true)"
	NIX_CFLAGS_COMPILE="$cc_cflags $libc_cflags"
	export NIX_CFLAGS_COMPILE
	cc_ldflags="$(cat "$cc_support/cc-ldflags" 2>/dev/null || true)"
	libc_ldflags="$(cat "$cc_support/libc-ldflags" 2>/dev/null || true)"
	NIX_LDFLAGS="$cc_ldflags $libc_ldflags"
	export NIX_LDFLAGS
else
	echo "[security] nix-support not found under $cc_root; continuing without NIX_* flags" >&2
fi

exec "$ROOT/scripts/security/run_security_suite.sh" "$@"
