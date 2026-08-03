# Thread Handoff: aegaeon-server Self-Review Fixes

Last updated: 2026-06-18

Status: historical record

Owner: Engineering

Audience: contributors, maintainers

This is a historical compact handoff from the May 2026 server self-review work.
It intentionally avoids repeating the full program history. Read `AGENTS.md`
and `docs/development/current-delivery-context.md` first, then use this note only
as historical context for the completed `aegaeon-server` fix pass.

## Operating Constraints

- Repository: `/home/claude/Workspaces/conceptual/aegaeon`
- Scope: `aegaeon-server` only unless the user explicitly widens scope.
- Supported local workflow:
  - `nix develop .#default --command bash -c '...'`
- Do not revert existing dirty worktree changes unless explicitly requested.
- Treat repository state and fresh command outputs as authoritative; docs alone
  are not sufficient evidence.
- Code comments and developer documentation should remain English.

## Current Commit State

The original `aegaeon-server` fix pass was split into focused commits:

- `7ccf933 refactor(server): retire legacy warp endpoint implementations`
- `25a877d fix(server): harden OAuth runtime policy boundaries`
- `d0fb1bd test(server): cover hardened OAuth runtime boundaries`

Subsequent cleanup passes also retired the legacy demo token endpoint and narrowed
remaining JOSE raw-JSON compatibility to test-only builds. Treat fresh
`git status` / `git diff` output as authoritative before editing; do not infer
dirty-worktree ownership from this note.

## Latest Self-Review Findings Fixed

The latest fix pass addressed these `aegaeon-server` review findings:

- Revocation owner bypass for rotated or expired refresh tokens.
- Subject-wide revocation missing refresh successor chains.
- Refresh token grant policy not bound at issue/use boundaries.
- Local/admin password authentication timing oracle.
- Kani proof mismatch for refresh-token reuse semantics.

Key implementation points:

- `TokenStore::known_token_client_id(...)` now treats inactive/rotated records
  still present in the store as known for revocation ownership checks.
- `TokenStore::revoke_token_for_client(...)` now:
  - no-ops unknown tokens without adding unbounded tombstones
  - rejects cross-client revocation with `OwnerMismatch`
  - revokes only known tokens owned by the requester or tokens without a
    requester context
- Subject-wide revocation now uses refresh-family revocation so successor
  chains are revoked.
- Authorization-code exchange now has explicit grant-policy inputs:
  - `authorization_code_grant_allowed`
  - `issue_refresh_tokens`
- The token endpoint resolves authorization-code and refresh-token grant policy
  before issuing tokens, but the authorization-code grant policy is enforced
  after code/client binding validation. This preserves `invalid_client` for
  wrong-client code redemption while still returning `unauthorized_client` for
  a legitimate client whose authorization-code grant is not allowed.
- Refresh token issuance now requires exact `offline_access` scope membership
  and the resolved refresh-grant policy; it no longer uses substring matching.
- Local end-user password login and management admin login run a dummy Argon2
  verification on missing/non-unique records to reduce user-existence timing
  differences.
- Kani refresh-token rotation expectation now matches the intended security
  model: reuse of the original rotated refresh token revokes the whole successor
  family.

## Tests Added or Updated

Added/updated tests cover:

- Client-bound revocation rejects rotated-refresh owner mismatch.
- Unknown revocation is a no-op and does not tombstone arbitrary token strings.
- Subject-wide revocation revokes refresh successor chains.
- Authorization-code policy rejection does not consume the authorization code.
- Kani refresh-token reuse semantics match family revocation.

## Verification Evidence

The following commands passed in the Nix dev shell on 2026-05-21:

```sh
nix develop .#default --command bash -c 'cargo test -p aegaeon-server --all-targets --all-features'
nix develop .#default --command bash -c 'cargo clippy -p aegaeon-server --all-targets --all-features --no-deps -- -D warnings'
```

The targeted regression also passed:

```sh
nix develop .#default --command bash -c 'cargo test -p aegaeon-server --test jar_par_binding_test jar_par_binding_wrong_client_rejected'
```

Note: a previous attempt to pass two individual test names to `cargo test` failed
because Cargo accepts only one positional test filter. That was a command syntax
mistake, not a code failure.

## Resolved Follow-Up Findings

Legacy endpoint hygiene is resolved for the token path. `token_with_metrics`
and its `demo-token-endpoint` feature have been retired; production HTTP routes
remain registered by the Axum router in `crate::web`. PAR metrics support now
lives in `crate::par::ParEndpoint`; the legacy endpoint marker module has been
retired.

The previously listed residual review findings are now resolved in the current
tree:

- PAR no longer injects registered client secrets into stored requests.
  `AEGAEON_REQUIRE_CLIENT_AUTH_PAR=0` still rejects unauthenticated
  confidential clients, covered by
  `par_auth_optional_still_rejects_unauthenticated_confidential_client`.
- JWT access-token validation enforces `exp` / `iat` presence, current-time
  validity with leeway, and `exp > iat`, covered under
  `authcode::token::tests::jwt_access::temporal_and_alg`.
- DCR no longer generates or echoes `client_secret` for `private_key_jwt`
  clients, covered by `dcr_private_key_jwt_response_does_not_issue_client_secret`
  and `register_update_to_private_key_jwt_drops_existing_client_secret`.
- `private_key_jwt` client authentication is covered on `/token`, device
  authorization, PAR, introspection, and revocation paths.
- Request-URI credential rejection covers bearer and assertion material such as
  `assertion`, `refresh_token`, `subject_token`, `token`, `code`, and
  `device_code`, with route-level guardrail tests in `request_guardrails_test`.
- Local and management password-login paths now share a rate-limiting boundary
  backed by `VerificationRateLimiter`.

## Current Residual Review Findings

No server-only code finding from the May handoff remains open. Current follow-up
work should come from fresh review output or from the broader delivery context:
hosted / production KMS-HSM parity evidence, release-candidate evidence
archives, and continued lint-specific cleanup.

## Suggested New Thread Prompt

Use this as the first message in a new thread:

```text
Repo: /home/claude/Workspaces/conceptual/aegaeon
Use devShell: nix develop .#default --command bash -c '...'

Please read AGENTS.md, docs/development/current-delivery-context.md, and
docs/program-management/historical/thread-handoff-2026-05-21-aegaeon-server-review.md.

Scope is aegaeon-server only. Do not revert existing dirty worktree changes
unless explicitly requested.

Current status:
- Recent self-review fixes for revocation ownership, refresh successor-chain
  revocation, token grant-policy issue/use boundaries, password timing oracle
  mitigation, Kani refresh reuse semantics, PAR/client-auth hardening, JWT
  access-token temporal checks, DCR private_key_jwt secret handling, request-URI
  credential guardrails, login rate limits, demo endpoint retirement, and JOSE
  generic-object test-only isolation are committed.
- The following passed:
  nix develop .#default --command bash -c 'cargo test -p aegaeon-server --all-targets --all-features'
  nix develop .#default --command bash -c 'cargo clippy -p aegaeon-server --all-targets --all-features --no-deps -- -D warnings'
- Check the current worktree before relying on this note.

First actions:
1. Run git status --short.
2. Inspect relevant diffs before editing.
3. Start from fresh review output; do not re-open the resolved May residual
   list without current code evidence.
```
