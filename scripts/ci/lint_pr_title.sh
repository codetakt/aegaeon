#!/usr/bin/env bash
set -euo pipefail

: "${PR_TITLE:?Pull request title is required}"
printf '%s\n' "$PR_TITLE" | commitlint --config commitlint-pr-title.config.cjs
