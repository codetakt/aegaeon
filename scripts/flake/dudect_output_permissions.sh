# shellcheck shell=bash
# Sourced by Dudect gates. Failed Nix builds do not normalize output modes.
# Only the declared Nix output is shared; ordinary local run directories stay
# private. Run this in the builder, before its distinct user loses ownership.
if [[ -z ${OUT_DIR:-} || $OUT_DIR != "${out:-}" ]]; then
	return 0
fi

retain_dudect_output_permissions() {
	local status=$?
	trap - EXIT
	if [[ -L $OUT_DIR || ! -d $OUT_DIR ]]; then
		echo "Dudect Nix output is not a regular directory" >&2
		if [[ $status -eq 0 ]]; then status=1; fi
	else
		# Do not follow output symlinks or grant write permission. Publish partial
		# evidence even when the gate failed, preserving that original exit code.
		if ! find -P "$OUT_DIR" -type d -exec chmod a+rx -- {} + ||
			! find -P "$OUT_DIR" -type f -exec chmod a+r -- {} +; then
			echo "Could not make Dudect Nix evidence readable" >&2
			if [[ $status -eq 0 ]]; then status=1; fi
		fi
	fi
	exit "$status"
}

trap retain_dudect_output_permissions EXIT
