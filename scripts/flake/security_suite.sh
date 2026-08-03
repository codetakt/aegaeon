#!/usr/bin/env bash
set -euo pipefail

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
