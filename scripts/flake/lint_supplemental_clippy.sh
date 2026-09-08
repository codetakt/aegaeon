#!/usr/bin/env bash
set -euo pipefail

export CARGO_INCREMENTAL=0
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$script_dir/../.."

cargo clippy --locked --profile "${CARGO_PROFILE:-dev}" --workspace --all-targets -- \
	-W clippy::suspicious \
	-D clippy::suspicious_else_formatting \
	-D clippy::suspicious_operation_groupings
