# Kani Reproducers

These files are retained as historical Kani design inputs and upstream/toolchain
reproducers. They are not Cargo integration tests and they are not counted as
current claim-bearing Kani evidence.

Claim-bearing server properties must live in `crates/server/src/kani_test.rs`
and be listed under `[server].harnesses` in the repository-level `kani.toml`.
