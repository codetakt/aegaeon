# Server Environment Variables

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

This compatibility entrypoint preserves the historical `docs/configurations/environment.md` path. The maintained environment-variable reference now lives in `environment/` so settings can be reviewed by runtime boundary.

Retained for: temporary compatibility with historical links, generated evidence, and release artifacts that still reference this moved path.

Review after: 2026-10-08

If you add a new environment variable in the codebase, update the owning split file in the same change. The server-side documentation tests read the split files under `environment/`; this page is retained for link compatibility only.

## Scope

- compatibility pointer for server environment-variable documentation
- navigation to the split environment reference files
- reminder that PostgreSQL-backed management state is the runtime configuration authority

## Canonical Documents

- `[index]` [Environment reference overview](environment/README.md)
- `[configuration]` [Core system settings](environment/core-system.md)
- `[configuration]` [Management plane settings](environment/management-plane.md)
- `[configuration]` [Network and runtime policy settings](environment/network-and-policy.md)
- `[configuration]` [OAuth and OIDC runtime settings](environment/oauth-oidc-runtime.md)
- `[configuration]` [Federation, observability, and test settings](environment/federation-observability-and-test.md)

## Reading Rule of Thumb

1. Use [environment/README.md](environment/README.md) as the maintained reference map.
2. Update the split files directly; do not add new normative setting details to this compatibility page.
3. New issuer-scoped knobs should be database-backed Environment configuration, not startup environment fallbacks.
