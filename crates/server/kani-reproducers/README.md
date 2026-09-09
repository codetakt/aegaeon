# Kani Reproducers

These files are retained as historical Kani design inputs and upstream/toolchain
reproducers. They are not Cargo integration tests and they are not counted as
current claim-bearing Kani evidence.

Claim-bearing server properties must live in `crates/server/src/kani_test.rs`
and be listed in the `server-regressions` group of the repository-level `spec/kani-evidence.json` (every proof site must be selected or excluded there).
