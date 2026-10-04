#!/usr/bin/env bash

# Enter POSIX mode using an assignment so exec precedes any imported function.
# Delegate admission and tool/runtime preflight before invoking any helper.
# The main runner supplies sanitizer flags; this route selects build-std only.
POSIXLY_CORRECT=1
SANITIZER_BUILD_EXTRA_ARGS="-Zbuild-std=std" \
	SANITIZER_ADD_DYNAMIC_RT=1 \
	SANITIZER_TARGET_DIR="${SANITIZER_TARGET_DIR:-target/sanitizers/build-std}" \
	exec "${BASH_SOURCE[0]%/*}/run_sanitizers.sh" "$@"
