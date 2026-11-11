#!/usr/bin/env bash
set -euo pipefail

python3 -m unittest discover -s scripts/tests -p test_subject_ownership_fixture.py
python3 -m unittest discover -s scripts/tests -p 'test_organization_audit_*.py'
python3 -m unittest discover -s scripts/tests -p test_organization_snapshot.py
python3 -m unittest discover -s scripts/tests -p test_organization_snapshot_receive.py
