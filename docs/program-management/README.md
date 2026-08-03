# Program Management Overview

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Program Management

Audience: maintainers, planning contributors

This directory captures planning artefacts for the Aegaeon programme.

## Scope

- active workstreams and sequencing
- cross-program roadmaps and execution plans
- historical delivery records for completed sprints / phases

## Directory Layout

- `roadmaps/` — future or not-yet-complete plans, dependency governance, and compliance action
  items. Start here for remaining OAuth/OIDC, management-platform, and proof work.
- `historical/` — curated delivery records and DoD criteria for completed workstreams.
- `initiatives/` — active sub-programmes such as JOSE header / JSON-TLV work,
  OAuth coverage expansion, SDK handoff planning, and quality-profile rollout.
- `../publication/` — outward-facing launch assets, event collateral, and public-readiness drafts.
- No `archive/` directory for transient notes: promote durable decisions into permanent documentation and rely on Git history / CI artefacts for raw snapshots.

## Canonical Documents

- `[roadmap]` `roadmaps/summary/program-master-plan.md` - top-level programme state.
- `[roadmap]` `roadmaps/active/current-execution-plan.md` - current remaining execution sequencing.
- `[index]` `roadmaps/README.md` - active, future, and summary roadmap entrypoints.
- `[index]` `initiatives/README.md` - active sub-programme entrypoints.
- `[index]` `historical/README.md` - read-only delivery records and completed work.
- `[publication]` `../publication/launch-assets/README.md` - launch-material entrypoint.
- `[policy]` `../product-positioning.md` - canonical outward-facing wording.

## Reading Rule of Thumb

1. Start with the current execution plan or roadmap index for remaining work.
2. Use `historical/` only for read-only delivery context.
3. Use `../product-positioning.md` for released product wording; roadmap language may describe future capability.
4. Refer to `../verification/claims/assumptions/current-register.md` when plan language intersects the formal trust boundary.
