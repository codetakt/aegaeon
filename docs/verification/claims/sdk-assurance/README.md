# SDK Assurance Contract Documents

Last updated: 2026-09-07

Status: current implementation baseline

Owner: Verification / SDK Engineering / Security

Audience: SDK implementers, verification reviewers, release managers

This is the normative SDK companion to the server assurance contract. It fixes
obligations for client/RP behavior, management-client behavior, and distributed
implementations independently of existing proof coverage. The SDK claim is not
active merely because these documents have been adopted.

## Scope

- client/RP protocol, state and security obligations
- management API client operations and trust boundaries
- emitted JavaScript/WASM, declarations and package identity
- release-specific proof, security testing and activation criteria

## Canonical Documents

- `[spec]` [SDK assurance contract](assurance-contract.md): mandatory guarantees and
  release decision criteria.
- `[spec]` [Standards and output baseline](standards-baseline.md): roles, source editions,
  packages, and runtime/output profiles.
- `[snapshot]` [Contract status](contract-status.md): remaining activation work.
- `[spec]` [Machine-readable register](../../../../spec/sdk-assurance-contract.v1.json):
  source pins, profile/package assignments, and guarantee references.

The [client/RP assurance case](../client-rp-assurance-case.md) and existing
promotion records are evidence inventories. The
[server contract](../assurance-case/assurance-contract.md) governs Aegaeon's own
server-side broker. Neither contract automatically establishes the other.

## Reading Rule of Thumb

1. Read the contract and baseline to determine obligations independently of evidence.
2. Check contract status before using qualified SDK release wording.
3. Use the register and client-core inventories to map requirements to actual outputs.
