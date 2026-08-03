#!/usr/bin/env bash
set -euo pipefail

export CARGO_INCREMENTAL=0

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"

cd "$repo_root"

cargo clippy \
	--locked \
	-p aegaeon-server \
	--lib \
	--bin aegaeon-server \
	--no-deps \
	-- \
	-D clippy::map_unwrap_or \
	-D clippy::ref_option \
	-D clippy::needless_pass_by_value \
	-D clippy::too_many_lines \
	-D clippy::too_many_arguments

"$script_dir/lint_server_unwrap_or_default_inventory.sh"
