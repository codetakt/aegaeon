# FFI source drift check inputs

Last updated: 2026-10-24

Status: current implementation baseline

Owner: CI / Automation

Audience: contributors, reviewers, repository administrators

The `ffi-contracts` package and flake check use the same Nix derivation. The
workflow still invokes the check; Nix can reuse its computation when all of its
source inputs and tools are unchanged. A documentation or unrelated server
change no longer invalidates this lexical check.

The source boundary in `nix/ffi-contract-check.nix` includes:

| Input | Reason |
| --- | --- |
| Entire `fstar/` tree | Discover first-party `.fst` and `.fsti` foreign declarations, including newly added modules |
| Entire `crates/ffi/` tree | Retain the Rust declarations inspected by the existing FFI checker |
| Entire `c/`, `generated/`, and `artifacts/karamel/` trees | Preserve handwritten and generated symbol searches and EverParse artifact checks |
| Entire `scripts/validation/` tree | Retain the drift checker, lexical scanner, assumption-register validator and their local imports |
| `scripts/flake/verify_ffi_contracts.sh` | Preserve the original regression-test and validation order and log handling |
| `spec/assumption-register.json` and `spec/assumption-register.schema.json` | Bind declaration identities and statement hashes to the existing register schema |
| `tests/ci/test_foreign_assumption_inventory.py` | Execute the original foreign-assumption regression suite |

Directory inputs include new files without a file-by-file allowlist. The check
uses Bash, coreutils, GNU grep, Perl, and the pinned Python environment with
JSON Schema and YAML support. Nix definitions and the complete tool closures
also contribute to its derivation identity.

The boundary excludes unrelated Rust crates, Cargo locks, documentation, other
workflow controllers, and proof-execution tools. It does not remove those inputs
from their own checks. No CI lane, test, proof obligation, protected-input hold,
or full-selection fallback is removed.

Missing explicit Nix inputs fail evaluation. Missing validator imports, required
generated artifacts, and registered `F*` declarations fail the existing execution
path. An empty `F*` tree cannot satisfy the nonempty registered declaration set.
New unregistered foreign declarations and Rust externs without a corresponding
source symbol remain failures. The validator is unchanged: this boundary does
not strengthen its source-symbol search into a compiler or linker check.

This check establishes lexical source/register correspondence and required
source-artifact presence. It does not execute `F*` proofs, accept assumptions,
prove ABI or functional contracts, or establish that a binary is correctly
linked. `F*` proof input narrowing and component-based CI omission remain separate
designs under the existing protected-input holds.

Boundary validation must include actual sandbox execution, matching package and
check derivation identities, relevant-file mutations and additions, missing-input
rejections, and unchanged identities for unrelated edits. Those tests verify
reuse of this check's computation; they do not authorize reuse of another event's
CI success or omission of the current invocation.
