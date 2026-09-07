# Assumption Boundary Overview

Last updated: 2026-09-07

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, maintainers

This overview summarizes the assumption categories that bound the formal claim.
The authoritative inventory remains the [assumption register details](assumptions/README.md).

## Scope

- cryptographic hardness and runtime trust boundaries
- remaining WASM host and linkage assumptions
- pointers to the detailed register and mitigation strategy

## Boundary Summary

The project does not prove external host behaviour, OS entropy, third-party
storage, computational hardness, or every runtime dependency from first
principles. These are explicit assumptions or TCB boundaries.

The [server assurance contract](assurance-case/assurance-contract.md) requires
auditing these premises before activation. Some current entries combine
cryptographic hardness with unverified implementation correctness; some crypto
axioms require repair. Own-code FFI, encoding, configuration and state
orchestration remain verification obligations even when they use external
interfaces. The detailed registers inventory current premises and historical
reductions, not an already accepted foundation trust boundary.

## Canonical Documents

- `[index]` [Detailed assumption register](assumptions/README.md)
- `[claim]` [Runtime contract register](assumptions/runtime-contract-register.md)
- `[claim]` [Formal claim overview](formal-claim-overview.md)
- `[claim]` [Crypto allowlist](crypto-allowlist.md)
- `[security]` [TCB inventory](../../security/tcb-inventory.md)

## Reading Rule of Thumb

1. Use this overview to decide whether a topic is inside or outside the claim.
2. Use [assumptions/current-register.md](assumptions/current-register.md) for exact assumption IDs and categories.
3. Use [crypto-allowlist.md](crypto-allowlist.md) before changing algorithm wording.
