#!/usr/bin/env bash
set -euo pipefail

mapfile -t workflows < <(
	find .github/workflows -type f \( -name '*.yml' -o -name '*.yaml' \) | sort
)

if [ "${#workflows[@]}" -eq 0 ]; then
	echo "No workflow files found under .github/workflows" >&2
	exit 0
fi

actionlint "${workflows[@]}"
