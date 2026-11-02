#!/usr/bin/env bash
# This fixed inventory validates the PR228 security patch without native timing.
set -euo pipefail
mkdir -p artifacts/rustls-ci-exception
exec > >(tee artifacts/rustls-ci-exception/checks.log) 2>&1
export CARGO_INCREMENTAL=0

ruff check scripts/ci/rustls_exception.py tests/ci/test_rustls_exception.py
mypy --no-incremental scripts/ci/rustls_exception.py
actionlint .github/workflows/pr.yml
shellcheck scripts/ci/run_rustls_exception.sh
python3 -m unittest discover -s tests/ci -p test_rustls_exception.py -v
cargo fmt --all --check
cargo metadata --locked --format-version 1 >artifacts/rustls-ci-exception/workspace-metadata.json
cargo metadata --manifest-path fuzz/Cargo.toml --locked --format-version 1 >artifacts/rustls-ci-exception/fuzz-metadata.json
cargo deny --locked check
cargo deny --manifest-path fuzz/Cargo.toml --locked check
cargo audit --file Cargo.lock --json >artifacts/rustls-ci-exception/workspace-audit.json
cargo audit --file fuzz/Cargo.lock --json >artifacts/rustls-ci-exception/fuzz-audit.json
cargo nextest run -p aegaeon-client -p aegaeon-crypto -p aegaeon-loadtest -p aegaeon-server --all-targets --locked
RUSTFLAGS='--cfg fuzzing -Clink-self-contained=no' cargo check --manifest-path fuzz/Cargo.toml --bins --locked
git diff --exit-code HEAD --
printf 'All scoped security checks passed. Native timing and full CI are outside this exception.\n'
