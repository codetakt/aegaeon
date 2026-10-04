#!/usr/bin/env bash
set -euo pipefail

PYTHONUNBUFFERED=1 PYTHONPATH="scripts/ci${PYTHONPATH:+:$PYTHONPATH}" python3 -m unittest discover -s tests/ci -p 'test_*.py' -v
python3 scripts/validation/check_docs_structure.py
bash scripts/lint/lint_markdown.sh
python3 scripts/ci/check_doc_links.py --base "$PR_BASE_SHA" --head HEAD
bash scripts/commitlint-range.sh --from "$PR_BASE_SHA" --to "$PR_HEAD_SHA"
if [[ $GITHUB_EVENT_NAME == pull_request ]]; then
	printf '%s\n' "$PR_TITLE" >"$RUNNER_TEMP/pr-title"
	commitlint --edit "$RUNNER_TEMP/pr-title"
fi
