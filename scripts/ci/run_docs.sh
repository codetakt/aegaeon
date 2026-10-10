#!/usr/bin/env bash
set -euo pipefail

PYTHONUNBUFFERED=1 PYTHONPATH="scripts/ci${PYTHONPATH:+:$PYTHONPATH}" python3 -m unittest discover -s tests/ci -p 'test_*.py' -v
bash scripts/ci/run_docs_metadata.sh
