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
SANITIZER_FORCE_PRELOAD=${SANITIZER_FORCE_PRELOAD:-0}
SANITIZER_EXEC_FORCE_PRELOAD=${SANITIZER_EXEC_FORCE_PRELOAD:-0}
SANITIZER_BUILD_EXTRA_ARGS=${SANITIZER_BUILD_EXTRA_ARGS:-}
SANITIZER_ADD_DYNAMIC_RT=${SANITIZER_ADD_DYNAMIC_RT:-1}
SANITIZER_EXEC_LD_PRELOAD=${SANITIZER_EXEC_LD_PRELOAD:-}
SANITIZER_ARTIFACT_DIR=${SANITIZER_ARTIFACT_DIR:-}

if ! command -v rustc >/dev/null 2>&1; then
	fail "rustc not found; enter the devShell first"
	exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
	fail "cargo not found; enter the devShell first"
	exit 1
fi

RUSTC_BIN=${RUSTC:-$(command -v rustc)}
CARGO_BIN=${CARGO:-$(command -v cargo)}

BASE_RUSTFLAGS=${RUSTFLAGS:-}
BASE_RUSTDOCFLAGS=${RUSTDOCFLAGS:-}

rustc_version="$(${RUSTC_BIN} --version 2>/dev/null || true)"
host_triple="$(${RUSTC_BIN} -vV 2>/dev/null | awk '/^host:/{print $2}')"

clang_path=$(command -v clang || true)
if [[ -z ${clang_path} ]]; then
	fail "clang not found; sanitizers require an LLVM toolchain"
fi

if [[ -n ${SANITIZER_RUNTIME_DIR:-} ]]; then
	clang_resource_dir=""
	clang_lib_dir="${SANITIZER_RUNTIME_DIR}"
else
	clang_resource_dir="$(${clang_path} --print-resource-dir 2>/dev/null || true)"
	clang_lib_dir="${clang_resource_dir}/lib/linux"
fi
if [[ ! -d ${clang_lib_dir} ]]; then
	fail "Unable to locate sanitizer runtime directory (expected ${clang_lib_dir})"
fi

if [[ -z ${host_triple} ]]; then
	fail "Unable to determine host triple from rustc"
	exit 1
fi

asan_suffix="${host_triple%%-*}"
asan_runtime="${clang_lib_dir}/libclang_rt.asan-${asan_suffix}.so"
if [[ ! -f ${asan_runtime} ]]; then
	fail "ASan runtime not found at ${asan_runtime}"
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

libasan_path="${LIBASAN_PATH:-}"
if [[ -z ${libasan_path} || ! -f ${libasan_path} ]]; then
	libasan_path=$(gcc -print-file-name=libasan.so 2>/dev/null || true)
fi
if [[ -z ${libasan_path} || ! -f ${libasan_path} ]]; then
	warn "libasan.so not found; relying on clang ASan runtime only (set LIBASAN_PATH to override)"
	libasan_path=""
fi

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

# Build-phase LD_PRELOAD (rarely used; off by default)
ld_preload_base=""
if [[ ${SANITIZER_FORCE_PRELOAD} == "1" ]]; then
	ld_preload_base="${ld_preload_base_exec}"
	if [[ -n ${libasan_path} && -f ${libasan_path} ]]; then
		ld_preload_base="${ld_preload_base}:${libasan_path}"
	fi
	if [[ -n ${LD_PRELOAD:-} ]]; then
		ld_preload_base="${ld_preload_base}:${LD_PRELOAD}"
	fi
	info "Build phase LD_PRELOAD enabled (SANITIZER_FORCE_PRELOAD=1): ${ld_preload_base}"
fi

info "Using rustc toolchain (${rustc_version})"
info "Detected ASan runtime dir: ${clang_lib_dir}"

export LD_LIBRARY_PATH="${clang_lib_dir}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"

IFS=',' read -ra sanitizer_array <<<"${SANITIZER_LIST// /,}"
IFS=',' read -ra package_array <<<"${SANITIZER_TARGETS// /,}"

read -r -a build_extra_array <<<"${SANITIZER_BUILD_EXTRA_ARGS}"

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

info "Running sanitizer-backed tests (SANITIZERS=${SANITIZER_LIST}; TARGETS=${SANITIZER_TARGETS})..."
info "ASAN verify link order set to ${ASAN_VERIFY_LINK_ORDER}"

for sanitizer in "${sanitizer_array[@]}"; do
	[[ -z ${sanitizer} ]] && continue
	for package in "${package_array[@]}"; do
		[[ -z ${package} ]] && continue

		info "Running cargo test with ${sanitizer} sanitizer for package ${package}..."

		run_target_dir="${SANITIZER_TARGET_ROOT}/${sanitizer}-${package}"
		mkdir -p "${run_target_dir}"

		rustflags=("${sanitize_flags_base[@]}")
		rustflags+=("-Z" "sanitizer=${sanitizer}")
		rustflags+=("${curve_flags[@]}")
		rustflags_str="${rustflags[*]}"

		tmp_log=$(mktemp)

		# Build only (`cargo test --no-run`) to produce sanitized binaries.
		timeout_bin=$(command -v timeout || true)
		cargo_args=("${CARGO_BIN}")
		if [[ ${#build_extra_array[@]} -gt 0 ]]; then
			cargo_args+=("${build_extra_array[@]}")
		fi
		cargo_args+=("test" ${EXTRA_CARGO_FLAGS} "-p" "${package}" "--lib" "--tests" "--no-run")

		if [[ -n ${timeout_bin} ]]; then
			build_cmd=("${timeout_bin}" --foreground --kill-after "${SANITIZER_TIMEOUT_KILL}" "${SANITIZER_TIMEOUT}" "${cargo_args[@]}")
		else
			warn "timeout not available; running build without timeout"
			build_cmd=("${cargo_args[@]}")
		fi

		# Ignore BASE_RUSTFLAGS to avoid conflicts with dynamic linking flags from flake.nix
		combined_rustflags="${rustflags_str}"
		combined_rustdocflags="${rustflags_str}"

		info "Using RUSTFLAGS=${combined_rustflags}"
		build_env=(
			"ASAN_OPTIONS=abort_on_error=1:detect_stack_use_after_return=1:detect_leaks=0:verify_asan_link_order=0:verbosity=0"
			"LSAN_OPTIONS=abort_on_error=1:detect_leaks=0"
			"UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1"
			"RUSTFLAGS=${combined_rustflags}"
			"RUSTDOCFLAGS=${combined_rustdocflags}"
			"CARGO_TARGET_DIR=${run_target_dir}"
		)
		# Note: LD_PRELOAD is NOT used during build phase to avoid severe performance degradation
		# The -Z sanitizer flag instruments generated code; build tools (rustc/cargo) emit warnings
		# but these warnings don't affect the correctness of the instrumented test binaries

		set +e
		# Use env -u to unset environment RUSTFLAGS that may come from flake.nix
		env -u RUSTFLAGS -u RUSTDOCFLAGS "${build_env[@]}" "${build_cmd[@]}" 2>&1 | tee "${tmp_log}"
		status=$?
		set -e
		if [[ ${status} -ne 0 ]]; then
			log_dest="${tmp_log}.build.fail"
			mv "${tmp_log}" "${log_dest}"
			if [[ -n ${SANITIZER_ARTIFACT_DIR} ]]; then
				mkdir -p "${SANITIZER_ARTIFACT_DIR}"
				cp "${log_dest}" "${SANITIZER_ARTIFACT_DIR}/$(basename "${log_dest}")"
			fi
			fail "Sanitizer build failed (package ${package}, sanitizer ${sanitizer})"
			info "Sanitizer log retained at ${log_dest}"
			exit ${status}
		fi
		rm -f "${tmp_log}"

		# Locate sanitized test binaries.
		if [[ -d "${run_target_dir}/debug/deps" ]]; then
			mapfile -t test_bins < <(find "${run_target_dir}/debug/deps" -maxdepth 1 -type f -perm -111 \( -name "${package}-*" -o -name "*_${package}-*" \))
		else
			test_bins=()
		fi
		if [[ ${#test_bins[@]} -eq 0 ]]; then
			warn "No sanitized test binaries found for ${package}; skipping execution stage"
			continue
		fi

		for test_bin in "${test_bins[@]}"; do
			info "Executing sanitized binary $(basename "${test_bin}")"
			if [[ -n ${timeout_bin} ]]; then
				exec_cmd=("${timeout_bin}" --foreground --kill-after "${SANITIZER_TIMEOUT_KILL}" "${SANITIZER_TIMEOUT}" "${test_bin}" --nocapture)
			else
				exec_cmd=("${test_bin}" --nocapture)
			fi

			run_env=(
				"ASAN_OPTIONS=abort_on_error=1:detect_stack_use_after_return=1:detect_leaks=0:verify_asan_link_order=${ASAN_VERIFY_LINK_ORDER}:verbosity=0"
				"LSAN_OPTIONS=abort_on_error=1:detect_leaks=0"
				"UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1"
				"LD_LIBRARY_PATH=${clang_lib_dir}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
			)
			# For test execution, use LD_PRELOAD to ensure ASan runtime loads before libc
			# This fixes "failed to intercept" warnings and ensures proper symbol interposition
			if [[ ${SANITIZER_EXEC_FORCE_PRELOAD} == "1" ]]; then
				exec_ld_preload="${ld_preload_base_exec}"
			else
				exec_ld_preload="${SANITIZER_EXEC_LD_PRELOAD:-}"
			fi
			if [[ -n ${exec_ld_preload} ]]; then
				if [[ -n ${LD_PRELOAD:-} ]]; then
					run_env+=("LD_PRELOAD=${exec_ld_preload}:${LD_PRELOAD}")
				else
					run_env+=("LD_PRELOAD=${exec_ld_preload}")
				fi
				info "Test execution with LD_PRELOAD: ${exec_ld_preload}"
			fi

			tmp_log=$(mktemp)
			set +e
			env "${run_env[@]}" "${exec_cmd[@]}" 2>&1 | tee "${tmp_log}"
			status=$?
			set -e

			if [[ ${status} -ne 0 ]]; then
				log_dest="${tmp_log}.exec.fail"
				mv "${tmp_log}" "${log_dest}"
				if [[ -n ${SANITIZER_ARTIFACT_DIR} ]]; then
					mkdir -p "${SANITIZER_ARTIFACT_DIR}"
					cp "${log_dest}" "${SANITIZER_ARTIFACT_DIR}/$(basename "${log_dest}")"
				fi
				fail "Sanitized binary failed: ${test_bin}"
				info "Sanitizer log retained at ${log_dest}"
				ps -o pid,ppid,etime,cmd -u "$USER" | grep -E 'cargo|rustc' || true
				exit ${status}
			fi
			rm -f "${tmp_log}"
		done

	done
done

info "Sanitizer-backed tests completed"
