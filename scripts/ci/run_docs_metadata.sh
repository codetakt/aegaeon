#!/usr/bin/env bash
set -euo pipefail

python3 scripts/validation/check_docs_structure.py
bash scripts/lint/lint_markdown.sh
python3 scripts/ci/check_doc_links.py --base "$PR_BASE_SHA" --head HEAD
bash scripts/commitlint-range.sh --from "$PR_BASE_SHA" --to "$PR_HEAD_SHA"
if [[ $GITHUB_EVENT_NAME == pull_request ]]; then
	printf '%s\n' "$PR_TITLE" >"$RUNNER_TEMP/pr-title"
	commitlint --edit "$RUNNER_TEMP/pr-title"
fi
