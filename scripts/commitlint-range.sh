#!/usr/bin/env bash
set -euo pipefail

: "${COMMITLINT_BIN:=commitlint}"
: "${COMMITLINT_BASELINE_FILE:=.commitlint-baseline}"

baseline_sha=""

load_baseline_sha() {
	if [ ! -f "$COMMITLINT_BASELINE_FILE" ]; then
		return 0
	fi

	local raw
	raw="$(
		sed -e 's/#.*$//' -e '/^[[:space:]]*$/d' "$COMMITLINT_BASELINE_FILE" |
			head -n 1 |
			tr -d '[:space:]'
	)"

	if [ -z "$raw" ]; then
		return 0
	fi

	if ! git rev-parse --verify --quiet "${raw}^{commit}" >/dev/null; then
		echo "commitlint baseline is not a valid commit: $raw" >&2
		return 1
	fi

	baseline_sha="$raw"
}

lint_commit_message() {
	local commit_sha="$1"
	local tmp_msg

	tmp_msg="$(mktemp)"
	git log -1 --format=%B "$commit_sha" >"$tmp_msg"
	"$COMMITLINT_BIN" --edit "$tmp_msg"
	rm -f "$tmp_msg"
}

main() {
	local from_sha=""
	local to_sha=""

	while [ $# -gt 0 ]; do
		case "$1" in
		--from)
			from_sha="${2:-}"
			shift 2
			;;
		--to)
			to_sha="${2:-}"
			shift 2
			;;
		*)
			echo "unknown argument: $1" >&2
			exit 2
			;;
		esac
	done

	if [ -z "$to_sha" ]; then
		echo "commitlint-range requires --to <commit>" >&2
		exit 2
	fi

	if ! git rev-parse --verify --quiet "${to_sha}^{commit}" >/dev/null; then
		echo "commitlint target is not a valid commit: $to_sha" >&2
		exit 1
	fi

	if [ -n "$from_sha" ] && ! git rev-parse --verify --quiet "${from_sha}^{commit}" >/dev/null; then
		echo "commitlint start is not a valid commit: $from_sha" >&2
		exit 1
	fi

	load_baseline_sha

	if [ -n "$baseline_sha" ] && git merge-base --is-ancestor "$baseline_sha" "$to_sha"; then
		if [ -z "$from_sha" ] || git merge-base --is-ancestor "$from_sha" "$baseline_sha"; then
			from_sha="$baseline_sha"
		fi
	fi

	if [ -n "$from_sha" ] && [ "$from_sha" != "$to_sha" ]; then
		"$COMMITLINT_BIN" --from "$from_sha" --to "$to_sha"
		return 0
	fi

	lint_commit_message "$to_sha"
}

main "$@"
