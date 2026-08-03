#!/usr/bin/env bash
set -euo pipefail

ASAN_DIR=${ASAN_DIR:-$($(command -v clang) --print-resource-dir 2>/dev/null)/lib/linux}
if [[ ! -d ${ASAN_DIR} ]]; then
	echo "[FAIL] Unable to locate ASan runtime dir at ${ASAN_DIR}" >&2
	exit 1
fi

export RUSTFLAGS="-Z sanitizer=address -C link-self-contained=no -C prefer-dynamic -C link-arg=-Wl,-rpath,${ASAN_DIR} -L native=${ASAN_DIR} -C target-feature=-avx2,-avx512ifma,-avx512vl,-avx512f,-avx512bw,-avx512dq --cfg curve25519_dalek_backend=\"serial\" ${RUSTFLAGS:-}"
export RUSTDOCFLAGS="${RUSTFLAGS}"
export SANITIZER_BUILD_EXTRA_ARGS="-Zbuild-std=std"
export SANITIZER_FORCE_PRELOAD=0
export SANITIZER_ADD_DYNAMIC_RT=1
export SANITIZER_TARGET_DIR=${SANITIZER_TARGET_DIR:-target/sanitizers/build-std}

exec "$(dirname "$0")/run_sanitizers.sh" "$@"
