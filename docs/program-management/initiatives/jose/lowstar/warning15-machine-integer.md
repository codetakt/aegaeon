# Jose.LowStar KaRaMeL Warning 15 (Machine Integers)

Last updated: 2026-07-07

Status: active plan

Owner: Program Management

Audience: maintainers, planning contributors

**Status**: Resolved for the JOSE JSON Stack module (Phase 3.2.4); retained as a design note for
future extraction work.

This document explains why KaRaMeL Warning 15 matters on the extraction surface and what posture
Aegaeon follows to keep the system “verified” rather than “best-effort extracted”.

## What Warning 15 means

KaRaMeL emits Warning 15 when extracted code depends on:

- Mathematical integers (`int`, `nat`) instead of machine integers, and/or
- High-level data structures such as `Prims.list`.

On the extraction surface, these warnings are not cosmetic; they typically imply:

1. Implicit abort paths (fail-open/DoS risk if not handled carefully),
2. Heap allocations via `KRML_HOST_MALLOC` with unclear ownership/freeing rules, and
3. A traceability gap between the proved F* model and the semantics of the emitted C.

## Security and verification risks

1. **32-bit conversion assumptions can break**: if `nat`/`int` conversions are not guaranteed by
   proofs, the C path may abort on overflow or accept invalid states.
2. **Memory leaks / lifetime ambiguity**: list-based data structures are hard to bound and free
   deterministically across the Rust FFI boundary.
3. **Verification gap**: auditors cannot rely on “formally verified” claims when extracted artefacts
   depend on runtime semantics outside the verified story.

## Aegaeon posture (rule of thumb)

- Extraction-facing modules use machine integers (`UInt32.t`/`UInt64.t`) and explicit, bounded
  representations.
- List-heavy helpers live in Pure/Tot layers and remain `noextract` (proof-only).
- The C runtime layer must have explicit ownership and freeing rules for any allocation crossing the
  FFI boundary.

## Implementation pattern (used today)

The JOSE JSON header Stack module migrated to a `bytes_block`/`raw_member_stack` model:

- `bytes_block = { buf: buffer UInt8.t; len: UInt32.t }`
- All counting/indexing uses `UInt32.t` plus explicit bounds lemmas (`Jose.Arith.Bounds`).
- The extraction pipeline compiles the Stack module and runtime together and exposes a stable C ABI
  to Rust.

## Evidence / primary sources

- Status + verification summary: `docs/verification/jose/phase4-verification-summary.md`
- Extraction plan and milestones: `docs/program-management/initiatives/jose/lowstar/lowstar-extraction-plan.md`
- F* / KaRaMeL failure-mode memo: `docs/verification/fstar/troubleshooting.md`
- FFI boundary contracts: `docs/verification/jose/json-lowstar-ffi-contracts.md`
- Backlog for remaining work: `docs/program-management/roadmaps/future/future-projects.md`

## Policy for future extraction work

When introducing new Low*/C modules (e.g., additional JOSE surfaces), treat “Warning 15 = 0 on the
extraction surface” as the default acceptance criterion. If a warning is unavoidable, document:

- The exact runtime semantics introduced
- Memory ownership/freeing rules
- Bounds/overflow guarantees
- How CI detects drift/regressions
