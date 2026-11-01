#!/usr/bin/env bash
set -euo pipefail

# Compile dummy workspace targets only. Cargo selects reusable dependencies by
# their own profile/features/toolchain fingerprints; no test result is cached.
# Keep feature combinations separate: their union is a different build.
cargo test --locked -p aegaeon-jose --no-run
cargo test --locked -p ffi --no-run
cargo test --locked -p aegaeon-jose --features everparse_jose_header_entry --no-run
cargo test --locked -p aegaeon-jose --features verified-claim --no-run
cargo test --locked -p aegaeon-jose --features ffi_jose_header_tlv --no-run
cargo test --locked -p aegaeon-jose --features ffi_jose_header_tlv,verified-claim --no-run
cargo test --locked -p aegaeon-server --no-run
cargo test --locked -p ffi --features verified-claim --no-run
cargo test --locked -p aegaeon-server --features verified-claim --no-run
cargo test --locked -p ffi --features verified-claim,idtoken_runtime --no-run
