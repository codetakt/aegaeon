# Redis boolean argument encoding

Last updated: 2026-09-15

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, maintainers

The authorization-code grant and refresh rotation builders call the production
`redis_bool` helper in
`crates/server/src/authcode/store/redis_backend/scripts/contract.rs`.
It maps `false` to the one-byte ASCII string `0` and `true` to `1`.

The `redis-boolean-encoding` Kani group calls that function directly for an
unrestricted `kani::any::<bool>()`. It checks the output length, exact byte
`0x30 + u8::from(value)`, and equality with the literal `"1"`. There are no
stubs or input assumptions; the two possible booleans are the complete input
type. An unwind failure rejects the run.

`AuthCode.RedisFlag` specifies the same two pairs and proves total encoding,
the character-list representation of its text encoding, and recovery of the
boolean by equality. `TestAuthCodeRedisFlag` requires rejection of reversed,
spelled-out, empty and extra-byte candidates against that exact relation.
The model is selected by the normal five-pass verification lane. The negative
fixture is a separate required gate without detailed-error expansion; its log
and source hashes are retained along with recorded verifier/solver identities
checked against proof pass 1. The [control record contract](../fstar/module-admission.md#expected-rejection-controls)
supports replay without the original sources or tools. It is not an admitted proof pass or an SMT
counterexample proof. The model's classification is `simplified`: it specifies
this representation, not a Redis implementation. The test fixture lives under
`tests/fstar/property`, outside the `fstar/` model-fidelity catalog.

The source-bound Kani result establishes the Rust helper's relation. The F*
theorems establish properties of the stated relation. This is a correspondence
leaf for a complete two-value domain, not an automatic translation or a proof
of the whole grant transition. F* string primitives, Kani's Rust model and the
verification toolchain remain explicit trusted dependencies.

These results do not establish the input boolean's provenance, its ARGV slot,
Redis serialization, the actual Lua comparison, key isolation, CAS,
partial-write behavior, reply loss, recovery, or composition with authority
and sender binding. A separate `redis_bool` in `authcode/code_store/scripts.rs`
is not the subject of this harness. No compliance row is promoted by this change.

Run the partial Kani selection with:

```sh
env -u PYTHONPATH nix develop .#verification -c python3 \
  scripts/validation/run_kani_evidence.py --scope partial \
  --groups redis-boolean-encoding --output artifacts/redis-boolean-evidence
```

`nix build .#verify-kani` includes the group in the full registered selection;
`nix build .#verify-fstar` includes the model and the separate control gate.
A partial group result does not admit the full Kani gate. Retain source/tool
hashes and rejected control results when using this leaf in a larger
correspondence argument.
