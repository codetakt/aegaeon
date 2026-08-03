#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
cd "$repo_root"

declare -a tracked_files=()
declare -a markdown_files=()

mapfile -d '' tracked_files < <(git ls-files -z -- "*.md")

for file in "${tracked_files[@]}"; do
	case "$file" in
	artifacts/* | generated/* | result/* | result-*/* | target/* | c/* | include/* | proofs/* | vendor/* | */node_modules/*)
		continue
		;;
	esac
	markdown_files+=("$file")
done

if ((${#markdown_files[@]} == 0)); then
	echo "No tracked Markdown files found."
	exit 0
fi

markdownlint-cli2 "${markdown_files[@]}" \
	--config .markdownlint.json
