#!/usr/bin/env bash
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
range_script="${script_dir}/commitlint-range.sh"

while read -r _ local_sha _ remote_sha; do
	if [ "$local_sha" = "0000000000000000000000000000000000000000" ]; then
		continue
	fi

	if [ "$remote_sha" = "0000000000000000000000000000000000000000" ]; then
		base_ref=""
		if git show-ref --verify --quiet refs/remotes/origin/HEAD; then
			base_ref="refs/remotes/origin/HEAD"
		elif git show-ref --verify --quiet refs/remotes/origin/main; then
			base_ref="refs/remotes/origin/main"
		elif git show-ref --verify --quiet refs/remotes/origin/master; then
			base_ref="refs/remotes/origin/master"
		fi

		if [ -n "$base_ref" ]; then
			base_sha="$(git merge-base "$local_sha" "$base_ref" || true)"
		else
			base_sha=""
		fi

		"${range_script}" --from "$base_sha" --to "$local_sha"
	else
		"${range_script}" --from "$remote_sha" --to "$local_sha"
	fi
done
