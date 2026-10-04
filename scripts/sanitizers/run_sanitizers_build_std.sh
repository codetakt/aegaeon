#!/usr/bin/env bash

# Special builtins precede imported functions in POSIX mode. Prove builtin is
# unshadowed before using it to resolve the delegate; the main runner performs
# the full inherited-function admission before invoking tools or helpers.
POSIXLY_CORRECT=1
if readonly -f builtin 2>/dev/null; then
	sanitizer_entry_error=""
	"${sanitizer_entry_error:?[FAIL] sanitizer execution requires external Python and no inherited shell functions}"
fi
# Reject lexical file aliases before they can select an unrelated sibling.
if [[ -L ${BASH_SOURCE[0]} ]]; then
	sanitizer_entry_error=""
	"${sanitizer_entry_error:?[FAIL] Sanitizer script entrypoint must not be a file symlink}"
fi
sanitizer_script_dir=${BASH_SOURCE[0]%/*}
[[ ${BASH_SOURCE[0]} == */* ]] || sanitizer_script_dir=.
sanitizer_script_dir=$(builtin cd -- "$sanitizer_script_dir" && builtin pwd -P && builtin printf .) || exit 1
sanitizer_script_dir=${sanitizer_script_dir%$'\n'.}
if [[ -L $sanitizer_script_dir/run_sanitizers.sh ]]; then
	sanitizer_entry_error=""
	"${sanitizer_entry_error:?[FAIL] Sanitizer script entrypoint must not be a file symlink}"
fi
# The main runner supplies sanitizer flags; this route selects build-std only.
SANITIZER_BUILD_EXTRA_ARGS="-Zbuild-std=std" \
	SANITIZER_ADD_DYNAMIC_RT=1 \
	SANITIZER_TARGET_DIR="${SANITIZER_TARGET_DIR:-target/sanitizers/build-std}" \
	exec "$sanitizer_script_dir/run_sanitizers.sh" "$@"
