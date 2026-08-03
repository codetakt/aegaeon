#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
cd "$ROOT"

PROJECT_ROOT="$ROOT/dev-tools/sanitizer-smoke"
if [[ ! -f "$PROJECT_ROOT/Cargo.toml" ]]; then
	echo "sanitizer-smoke project not found at $PROJECT_ROOT" >&2
	exit 1
fi

if [[ -z ${SANITIZER_RUNTIME_DIR:-} ]]; then
	if command -v clang >/dev/null 2>&1; then
		resource_dir="$(clang --print-resource-dir 2>/dev/null || true)"
		if [[ -n $resource_dir ]]; then
			if [[ -d "$resource_dir/lib/linux" ]]; then
				SANITIZER_RUNTIME_DIR="$resource_dir/lib/linux"
			elif [[ -d "$resource_dir/lib" ]]; then
				SANITIZER_RUNTIME_DIR="$resource_dir/lib"
			fi
		fi
	fi
fi

if [[ -z ${SANITIZER_RUNTIME_DIR:-} ]]; then
	echo "SANITIZER_RUNTIME_DIR not set and clang resource dir not found" >&2
	exit 1
fi

export SANITIZER_RUNTIME_DIR
export ASAN_DIR="$SANITIZER_RUNTIME_DIR"
default_sanitizer_target_features='-avx2,-avx512ifma,-avx512vl,-avx512f,-avx512bw,-avx512dq'
if [[ -z ${SANITIZER_RUSTFLAGS:-} ]]; then
	export SANITIZER_RUSTFLAGS="-C target-feature=$default_sanitizer_target_features"
else
	export SANITIZER_RUSTFLAGS
fi

SANITIZER_SMOKE_VERIFY="${SANITIZER_SMOKE_VERIFY:-0}"
SANITIZER_FORCE_PRELOAD="${SANITIZER_FORCE_PRELOAD:-0}"
SANITIZER_SMOKE_OFFLINE="${SANITIZER_SMOKE_OFFLINE:-0}"

host_triple="$(rustc -vV 2>/dev/null | awk '/^host:/{print $2}')"
if [[ -z $host_triple ]]; then
	echo "Unable to determine host triple from rustc" >&2
	exit 1
fi

asan_suffix="${host_triple%%-*}"
clang_lib_dir="$SANITIZER_RUNTIME_DIR"

if [[ ! -d $clang_lib_dir ]]; then
	echo "Sanitizer runtime directory not found (expected $clang_lib_dir)" >&2
	exit 1
fi

asan_runtime="$clang_lib_dir/libclang_rt.asan-${asan_suffix}.so"
if [[ ! -f $asan_runtime ]]; then
	echo "ASan runtime not found at $asan_runtime" >&2
	exit 1
fi

asan_preinit=""
asan_preinit_ext=""
for candidate_ext in so a; do
	candidate="$clang_lib_dir/libclang_rt.asan-preinit-${asan_suffix}.${candidate_ext}"
	if [[ -f $candidate ]]; then
		asan_preinit="$candidate"
		asan_preinit_ext="$candidate_ext"
		break
	fi
done

have_asan_preinit=0
if [[ -n $asan_preinit ]]; then
	have_asan_preinit=1
fi

libasan_path="$(gcc -print-file-name=libasan.so 2>/dev/null || true)"
if [[ $SANITIZER_FORCE_PRELOAD == "1" ]]; then
	preload_parts=()
	if [[ $have_asan_preinit -eq 1 && $asan_preinit_ext == "so" ]]; then
		preload_parts+=("$asan_preinit")
	fi
	preload_parts+=("$asan_runtime")
	if [[ -n $libasan_path && -f $libasan_path ]]; then
		preload_parts+=("$libasan_path")
	fi
	ld_preload="$(
		IFS=:
		printf '%s' "${preload_parts[*]}"
	)"
	export LD_PRELOAD="$ld_preload"
else
	unset LD_PRELOAD
fi

export LD_LIBRARY_PATH="$clang_lib_dir${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

rustflags_parts=()
if [[ -n ${SANITIZER_RUSTFLAGS:-} ]]; then
	# shellcheck disable=SC2206 # word splitting intentional for flag parsing
	sanitizer_env_flags=(${SANITIZER_RUSTFLAGS})
	rustflags_parts+=("${sanitizer_env_flags[@]}")
fi
rustflags_parts+=(
	"-Z" "sanitizer=address"
	"-L" "native=$clang_lib_dir"
	"-C" "link-args=-Wl,-rpath,$clang_lib_dir"
	"-C" "link-arg=-l:libclang_rt.asan-${asan_suffix}.so"
)
if [[ $have_asan_preinit -eq 1 ]]; then
	if [[ $asan_preinit_ext == "so" ]]; then
		rustflags_parts+=("-C" "link-arg=-l:libclang_rt.asan-preinit-${asan_suffix}.so")
	else
		rustflags_parts+=(
			"-C" "link-arg=-Wl,-whole-archive"
			"-C" "link-arg=-l:libclang_rt.asan-preinit-${asan_suffix}.${asan_preinit_ext}"
			"-C" "link-arg=-Wl,-no-whole-archive"
		)
	fi
	rustflags_parts+=("-C" "link-arg=-Wl,-u,__asan_preinit")
fi
export RUSTFLAGS="${rustflags_parts[*]}"
export RUSTDOCFLAGS="$RUSTFLAGS"

asan_options='abort_on_error=1:detect_stack_use_after_return=1:detect_leaks=0:'
asan_options+="verify_asan_link_order=$SANITIZER_SMOKE_VERIFY:verbosity=0"
export ASAN_OPTIONS="$asan_options"
export LSAN_OPTIONS='abort_on_error=1:detect_leaks=0'
export UBSAN_OPTIONS='print_stacktrace=1:halt_on_error=1'
export RUST_BACKTRACE=1

cargo_args=(test --locked --manifest-path "$PROJECT_ROOT/Cargo.toml" -- --nocapture)
if [[ $SANITIZER_SMOKE_OFFLINE == "1" ]]; then
	cargo_args=(test --locked --offline --manifest-path "$PROJECT_ROOT/Cargo.toml" -- --nocapture)
fi

timeout 120s cargo "${cargo_args[@]}"
