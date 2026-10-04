#!/usr/bin/env bash

set -euo pipefail

info() { printf '[INFO] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*"; }
fail() { printf '[FAIL] %s\n' "$*" >&2; }

SANITIZER_LIST=${SANITIZERS:-address}
SANITIZER_TARGETS=${SANITIZER_TARGETS:-ffi}
SANITIZER_TARGET_ROOT=${SANITIZER_TARGET_DIR:-target/sanitizers}
EXTRA_CARGO_FLAGS=${SANITIZER_CARGO_FLAGS:-}
SANITIZER_TIMEOUT=${SANITIZER_TIMEOUT:-120}
SANITIZER_TIMEOUT_KILL=${SANITIZER_TIMEOUT_KILL:-130}
ASAN_VERIFY_LINK_ORDER=${ASAN_VERIFY_LINK_ORDER:-0}
SANITIZER_EXEC_FORCE_PRELOAD=${SANITIZER_EXEC_FORCE_PRELOAD:-0}
SANITIZER_BUILD_EXTRA_ARGS=${SANITIZER_BUILD_EXTRA_ARGS:-}
SANITIZER_ADD_DYNAMIC_RT=${SANITIZER_ADD_DYNAMIC_RT:-1}
SANITIZER_EXEC_LD_PRELOAD=${SANITIZER_EXEC_LD_PRELOAD:-}
SANITIZER_ARTIFACT_DIR=${SANITIZER_ARTIFACT_DIR:-}

# Both standalone execution and destructive outer cleanup use one source policy.
# shellcheck source=scripts/sanitizers/sanitizer_paths.sh
source "${BASH_SOURCE[0]%/*}/sanitizer_paths.sh"
workspace=$(pwd -P)
preflight_route "${SANITIZER_ARTIFACT_DIR:-${SANITIZER_TARGET_ROOT}/artifacts}" || exit 1
SANITIZER_ARTIFACT_DIR=$PREFLIGHT_ROUTE
sanitizer_validate_output "$SANITIZER_ARTIFACT_DIR" "$workspace" || exit 1
# Safe owned evidence is failed before any later target or tool preflight fails.
# Unsafe evidence is never initialized or archived.
sanitizer_initialize_evidence || exit 1
PREFLIGHT_PHASE=target
preflight_exit() {
	local status=$?
	trap - EXIT
	if [[ $status -ne 0 ]]; then
		preflight_receipt "$PREFLIGHT_PHASE" "$status" || fail "Failed to update sanitizer preflight evidence"
	fi
	exit "$status"
}
trap preflight_exit EXIT
PREFLIGHT_PHASE=cargo-flags
sanitizer_validate_cargo_flags "$EXTRA_CARGO_FLAGS" "$SANITIZER_BUILD_EXTRA_ARGS" || exit 1
preflight_route "$SANITIZER_TARGET_ROOT" || exit 1
SANITIZER_TARGET_ROOT=$PREFLIGHT_ROUTE
sanitizer_validate_output "$SANITIZER_TARGET_ROOT" "$workspace" || exit 1
# A standalone evidence descendant is supported: standalone has no outer cleanup.
sanitizer_validate_pair "$SANITIZER_TARGET_ROOT" "$SANITIZER_ARTIFACT_DIR" runner || exit 1
PREFLIGHT_PHASE=rustc

if ! command -v rustc >/dev/null 2>&1; then
	fail "rustc not found; enter the devShell first"
	exit 1
fi

PREFLIGHT_PHASE=cargo
if ! command -v cargo >/dev/null 2>&1; then
	fail "cargo not found; enter the devShell first"
	exit 1
fi

RUSTC_BIN=${RUSTC:-$(command -v rustc)}
CARGO_BIN=${CARGO:-$(command -v cargo)}

PREFLIGHT_PHASE=rustc-version
rustc_version="$("${RUSTC_BIN}" --version)"
PREFLIGHT_PHASE=rustc-host
host_triple="$("${RUSTC_BIN}" -vV | awk '/^host:/{print $2}')"

PREFLIGHT_PHASE=clang
clang_path=$(command -v clang || true)
if [[ -z ${clang_path} ]]; then
	fail "clang not found; sanitizers require an LLVM toolchain"
	exit 1
fi

PREFLIGHT_PHASE=runtime
if [[ -n ${SANITIZER_RUNTIME_DIR:-} ]]; then
	clang_resource_dir=""
	clang_lib_dir="${SANITIZER_RUNTIME_DIR}"
else
	clang_resource_dir="$(${clang_path} --print-resource-dir 2>/dev/null || true)"
	clang_lib_dir="${clang_resource_dir}/lib/linux"
fi
if [[ ! -d ${clang_lib_dir} ]]; then
	fail "Unable to locate sanitizer runtime directory (expected ${clang_lib_dir})"
	exit 1
fi

PREFLIGHT_PHASE=host
if [[ -z ${host_triple} ]]; then
	fail "Unable to determine host triple from rustc"
	exit 1
fi

asan_suffix="${host_triple%%-*}"
asan_runtime="${clang_lib_dir}/libclang_rt.asan-${asan_suffix}.so"
if [[ ! -f ${asan_runtime} ]]; then
	fail "ASan runtime not found at ${asan_runtime}"
	exit 1
fi

asan_preinit=""
asan_preinit_ext=""
for candidate_ext in so a; do
	candidate="${clang_lib_dir}/libclang_rt.asan-preinit-${asan_suffix}.${candidate_ext}"
	if [[ -f ${candidate} ]]; then
		asan_preinit="${candidate}"
		asan_preinit_ext="${candidate_ext}"
		break
	fi
done
have_asan_preinit=0
if [[ -n ${asan_preinit} ]]; then
	have_asan_preinit=1
else
	warn "ASan preinit runtime not found under ${clang_lib_dir}; interceptor coverage may remain incomplete"
fi

libcxxabi_path=""
if [[ ${SANITIZER_EXEC_FORCE_PRELOAD} == "1" ]]; then
	libcxxabi_path="${LIBCXXABI_PATH:-}"
	if [[ -z ${libcxxabi_path} || ! -f ${libcxxabi_path} ]]; then
		search_roots=(
			"$(dirname "${clang_lib_dir}")"
			"${clang_lib_dir}"
		)
		for root in "${search_roots[@]}"; do
			[[ -d ${root} ]] || continue
			libcxxabi_path=$(find "${root}" -maxdepth 3 -name 'libc++abi.so' -print -quit 2>/dev/null || true)
			[[ -n ${libcxxabi_path} ]] && break
		done
	fi
	if [[ -z ${libcxxabi_path} || ! -f ${libcxxabi_path} ]]; then
		libcxxabi_path=$(find /nix/store -maxdepth 3 -name 'libc++abi.so' -print -quit 2>/dev/null || true)
	fi
	if [[ -z ${libcxxabi_path} || ! -f ${libcxxabi_path} ]]; then
		warn "libc++abi.so not found; ASan may miss C++ exception interceptors (set LIBCXXABI_PATH to override)"
	fi
fi

# Build LD_PRELOAD list for optional test execution override
ld_preload_parts=()
if [[ ${have_asan_preinit} -eq 1 && ${asan_preinit_ext} == "so" ]]; then
	ld_preload_parts+=("${asan_preinit}")
fi
ld_preload_parts+=("${asan_runtime}")
if [[ ${SANITIZER_EXEC_FORCE_PRELOAD} == "1" && -n ${libcxxabi_path} && -f ${libcxxabi_path} ]]; then
	ld_preload_parts+=("${libcxxabi_path}")
fi
ld_preload_base_exec=$(
	IFS=:
	printf '%s' "${ld_preload_parts[*]}"
)

info "Using rustc toolchain (${rustc_version})"
info "Detected ASan runtime dir: ${clang_lib_dir}"

export LD_LIBRARY_PATH="${clang_lib_dir}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"

sanitize_flags_base=()
if [[ -n ${SANITIZER_RUSTFLAGS:-} ]]; then
	# shellcheck disable=SC2206 # word splitting intentional for flag parsing
	sanitizer_env_flags=(${SANITIZER_RUSTFLAGS})
	sanitize_flags_base+=("${sanitizer_env_flags[@]}")
fi
if [[ ${SANITIZER_ADD_DYNAMIC_RT} == "1" ]]; then
	# Dynamic linking: add library paths and explicit runtime linking
	sanitize_flags_base+=(
		"-L" "native=${clang_lib_dir}"
		"-C" "link-args=-Wl,-rpath,${clang_lib_dir}"
	)
	sanitize_flags_base+=(
		"-C" "link-arg=-l:libclang_rt.asan-${asan_suffix}.so"
	)
	if [[ ${have_asan_preinit} -eq 1 ]]; then
		if [[ ${asan_preinit_ext} == "so" ]]; then
			sanitize_flags_base+=(
				"-C" "link-arg=-l:libclang_rt.asan-preinit-${asan_suffix}.so"
			)
		else
			sanitize_flags_base+=(
				"-C" "link-arg=-Wl,-whole-archive"
				"-C" "link-arg=-l:libclang_rt.asan-preinit-${asan_suffix}.${asan_preinit_ext}"
				"-C" "link-arg=-Wl,-no-whole-archive"
			)
		fi
		sanitize_flags_base+=(
			"-C" "link-arg=-Wl,-u,__asan_preinit"
		)
	fi
fi
curve_flags=(
	"--cfg" 'curve25519_dalek_backend="serial"'
	"-C" "target-feature=-avx2,-avx512ifma,-avx512vl,-avx512f,-avx512bw,-avx512dq,-avx512cd"
)

PREFLIGHT_PHASE=tools
for tool in python3 nm readelf; do
	if ! command -v "$tool" >/dev/null 2>&1; then
		fail "$tool not found; sanitizer execution and evidence require it"
		exit 1
	fi
done

if [[ ${SANITIZER_EXEC_FORCE_PRELOAD} == "1" ]]; then
	exec_ld_preload="${ld_preload_base_exec}"
else
	exec_ld_preload="${SANITIZER_EXEC_LD_PRELOAD}"
fi

exec python3 -I "${BASH_SOURCE[0]%/*}/sanitizer_runner.py" "$SANITIZER_LIST" "$SANITIZER_TARGETS" "$SANITIZER_TARGET_ROOT" \
	"${SANITIZER_ARTIFACT_DIR:-${SANITIZER_TARGET_ROOT}/artifacts}" \
	"$CARGO_BIN" "$host_triple" "${sanitize_flags_base[*]}" "${curve_flags[*]}" \
	"$EXTRA_CARGO_FLAGS" "$SANITIZER_BUILD_EXTRA_ARGS" \
	"${SANITIZER_BUILD_TIMEOUT:-$SANITIZER_TIMEOUT}" \
	"${SANITIZER_RUN_TIMEOUT:-$SANITIZER_TIMEOUT}" "$SANITIZER_TIMEOUT_KILL" \
	"$clang_lib_dir" "$ASAN_VERIFY_LINK_ORDER" "$exec_ld_preload"
