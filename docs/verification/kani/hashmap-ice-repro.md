# Kani HashMap ICE Reproducer

Last updated: 2026-07-07

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, contributors

This note preserves the current `HashMap`-based harness that triggers the Kani
0.65.0 internal compiler error (`kani_middle/transform/mod.rs:124`) so that we
can provide a ready-made testcase when filing or updating the upstream issue.

## Harness (as of 2025-10-15)

```rust
// crates/kani-harness/src/lib.rs

#[cfg(kani)]
pub fn proof_kid_reuse_violation_detected() {
    use std::collections::HashMap;
    let mut prev = HashMap::new();
    prev.insert("k1".into(), "fp1".into());
    let mut newm = HashMap::new();
    newm.insert("k1".into(), "fp2".into());
    assert!(pure::kid_reuse_changed(&prev, &newm));
}
```

Other harnesses in the same module (e.g. `proof_select_jwk_by_kid_or_first`) also used to go
through `HashMap`, but for normal operation we replaced them with an **array-based simplified model**
and ordinary unit tests. This file keeps only the minimal reproducer for upstream reporting.

## Reproduction Steps

```text
# Ensure Kani 0.65.0 is installed and on PATH.
cargo kani --manifest-path crates/kani-harness/Cargo.toml \
           --harness proof_kid_reuse_violation_detected
```

Expected failure (abridged):

```text
thread 'rustc' panicked at kani-compiler/src/kani_middle/transform/mod.rs:124:48:
called `Option::unwrap()` on a `None` value
...
```

## Notes for Upstream Report

- The panic occurs during MIR → GOTO transformation, before CBMC is invoked.
- Reproducers should avoid enabling `--restrict-module` or other flags that
  might strip the harness; the command above mirrors our CI invocation.
- In production CI, `scripts/run_kani.sh` runs only simplified models that avoid `HashMap`; the
  harness in this file is kept **for reproduction only**.
- The same properties (kid reuse detection / JWK selection) are covered by ordinary unit tests
  (see `crates/server/src/client_registry.rs` tests `test_kid_reuse_changed_detected` and
  `test_select_jwk_prefers_requested_kid`).

## Additional ICE: String Slice Loop (2025-10-15)

The same Kani release also panics on a much smaller example that only walks a
byte slice and writes into an `Option`. This confirms the issue is broader than
`HashMap` alone:

```rust
#[cfg(kani)]
pub fn proof_parse_cache_control_no_panic() {
    let bytes = b"public, max-age=120, must-revalidate";
    let mut start = 0usize;
    let mut i = 0usize;
    let mut res = None;
    while i <= bytes.len() {
        if i == bytes.len() || bytes[i] == b',' {
            let mut seg_start = start;
            let mut seg_end = i;
            while seg_start < seg_end && bytes[seg_start].is_ascii_whitespace() {
                seg_start += 1;
            }
            while seg_end > seg_start && bytes[seg_end - 1].is_ascii_whitespace() {
                seg_end -= 1;
            }
            if seg_end - seg_start >= 8 {
                res = Some(1u64);
            }
            start = i + 1;
        }
        i += 1;
    }
    if let Some(n) = res {
        assert!(n <= 86400);
    }
}
```

Running `cargo kani --manifest-path crates/kani-harness/Cargo.toml --harness proof_parse_cache_control_no_panic`
immediately crashes with the same `kani_middle/transform::BodyTransformation::body`
unwrap. Capture this snippet as a secondary reproducer when filing upstream issues.
