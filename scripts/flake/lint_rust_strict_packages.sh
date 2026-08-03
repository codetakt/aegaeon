#!/usr/bin/env bash
set -euo pipefail

export CARGO_INCREMENTAL=0

cargo clippy \
	--locked \
	-p aegaeon-client \
	-p aegaeon-core \
	-p aegaeon-crypto \
	-p aegaeon-jose \
	-p aegaeon-jose-tlv \
	-p aegaeon-loadtest \
	-p aegaeon-observability \
	-p aegaeon-server \
	-p ffi \
	-p xtask \
	--all-targets \
	--all-features \
	-- \
	-D warnings \
	-W clippy::pedantic \
	-W clippy::cargo \
	-A clippy::multiple_crate_versions \
	-D clippy::unwrap_used \
	-D clippy::expect_used \
	-D clippy::panic \
	-D clippy::todo \
	-D clippy::unimplemented
