# @aegaeon/management-client

Alpha management-plane SDK for the Aegaeon control-plane API.

Current alpha scope:

- OpenAPI-backed operation metadata from `Aegaeon Management API v1`
- generic request helper with automatic `teamId` path insertion
- CSRF / Origin / cookie handling helpers for browser and Node runtimes
- convenience methods for:
  - authentication session create/delete
  - owner bootstrap
  - system health and version
  - teams / tenants / environments / clients CRUD
  - client secret lifecycle
  - configuration version lifecycle
  - policy read / patch
  - key store and signing key management
  - user session controls
  - team / environment audit queries
- bundled TypeScript declarations for management-plane UIs

Current non-goals:

- no React hooks yet
- no full OpenAPI code generation pipeline yet
- no OIDC browser login helpers (those belong in `@aegaeon/issuer-spa` / `@aegaeon/rp-core`)

Use this package as the canonical control-plane transport for admin UIs and automation. Management
UIs should depend on `@aegaeon/management-client`; OIDC client execution belongs in the runtime /
RP packages.
