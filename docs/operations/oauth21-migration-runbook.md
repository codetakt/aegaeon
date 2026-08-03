# OAuth Modern Flow Runbook

Last updated: 2026-07-07

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

This project no longer supports an operator-selectable migration mode from legacy OAuth flows.
Aegaeon is unreleased, so the server uses the final intended posture directly.

## Required Posture

- Authorization response type is `code`.
- PKCE is required for OAuth profiles.
- Password grant is not supported.
- Implicit and hybrid response types are not supported.
- Environment policy, OAuth profile, and client rows do not carry a configurable response-type
  allowlist; `code` is the only supported authorization response type.

## Operator Checks

Use the management API or direct read-only database inspection to confirm:

```sql
SELECT id, name, profile_type, require_pkce, allowed_grant_types
FROM aegaeon.oauth_profiles
WHERE NOT require_pkce
   OR 'password' = ANY(allowed_grant_types);
```

The query must return zero rows.

```sql
SELECT environment_id, allowed_grant_types
FROM aegaeon.environment_policies
WHERE 'password' = ANY(allowed_grant_types);
```

The query must return zero rows.

## Migration Note

`db/migrations/20260630162000_remove_legacy_oauth_profile_fields.sql` removes the old profile
compatibility columns. `db/migrations/20260630165000_drop_internal_allowed_response_types.sql`
then drops the redundant internal response-type allowlist columns.
