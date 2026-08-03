#!/bin/bash
# Quick test to verify all RFC tests work

cargo test --package aegaeon-server --lib rfc_tests --quiet 2>&1 | tail -5
