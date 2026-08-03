# SDK Initiative Overview

Last updated: 2026-07-07

Status: active plan

Owner: Program Management / Engineering

Audience: implementation contributors, maintainers

This initiative groups backend-owned SDK and client-delivery planning. It keeps
cross-repository handoff, scaffold, source-language, and client-claim work out of
`docs/design/`, while preserving runtime and Verified Core design notes there.

## Scope

- backend-owned SDK scaffold and handoff contracts
- SDK repository boundary, CI companion responsibilities, and release-readiness gates
- TypeScript source convergence and post-TypeScript language rollout sequencing
- client/runtime claim support that depends on backend artefacts or evidence contracts

This directory does not replace the separate `aegaeon-sdk` repository's package
CI, publish runbooks, or operational release procedures.

## Canonical Documents

- `[design]` [Client SDK architecture](client-sdk-architecture.md)
- `[plan]` [SDK repository boundary plan](sdk-repository-plan.md)
- `[plan]` [SDK CI companion plan](sdk-ci-plan.md)
- `[guide]` [SDK implementation guide](sdk-implementation-guide.md)
- `[workplan]` [SDK source language plan](sdk-source-language-plan.md)

## Related Operational Documents

- [SDK release runbook](../../../operations/sdk-release.md)

## Reading Rule of Thumb

1. Start here when changing SDK handoff contracts, scaffold generation, or client-claim gates.
2. Use `../../../design/README.md` for runtime adapter and Verified Core design details.
3. Use the SDK repository for package-local CI, publish, and release operations.
