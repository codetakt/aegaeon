#!/usr/bin/env bash
set -euo pipefail

exec python3 scripts/validation/validate_compliance_matrix.py --check
