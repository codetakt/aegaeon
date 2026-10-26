# Upstream endpoint query integration: Task 3 handoff

Last updated: 2026-10-27

Status: historical record

Owner: Engineering

Audience: maintainers and product-assurance reviewers

Local integration validation is complete. Remote CI and merge are pending. Task 3 remains paused.

## Scope and continuity

PR #88 preserves upstream endpoint query bytes for authorization, logout, code exchange,
refresh and JWKS retrieval. It integrates the original query change from `8be68d463`
with main `39b154d02`; the issuer-identity prerequisite in PR #79 is already merged.
The compliance identifier remains `6749-016`, separate from Basic credential encoding
(`6749-017`) and form parameter admission. This integration does not change any
requirement's status or claim new formal proof discharge.

The governing behavior is in [the RP brokering specification](../specs/oidc-rp-brokering-spec.md#upstream-endpoint-query-retention).
Query retention is required by RFC 6749 sections 3.1 and 3.2. Reusing one equal generated
value, rejecting duplicates/conflicts and token-form fields, and rejecting unprocessed
Request Object parameters are Aegaeon's ambiguity policy.

## Review correction and integration boundaries

The original relay builder returned no redirect on a query collision, but local logout
could retry through the non-relay builder and emit the rejected endpoint. The non-relay
builder now rejects `state` and `post_logout_redirect_uri`, including encoded names,
with or without a logout hint. Local logout can complete at `/auth/login`, clear the
session and avoid creating an incident or relay. Valid vendor queries remain intact.
The required formatter also fixes the reported test formatting issue.

Main's Basic credential encoding, original refresh-authentication context, configuration
identity, refresh clock checks, and JWKS coordination/admission remain in force.
The JWKS regression uses the current header/candidate-admission path and checks fresh
HTTP targets, exact query cache keys and the absence of another request on a cache hit.

## Validation record

The integrated candidate passes 294 upstream tests with fresh, dedicated PostgreSQL and
Redis fixtures: 294 expected names, each executed once, no failures or ignored tests.
This includes the actual local logout handler, relay incident creation ordering, encoded
query aliases, no-hint fallback refusal, HTTP code/refresh requests, JWKS query/cache
identity, and the inherited issuer, Basic, Federation and refresh-context regressions.
The dedicated containers and volume were removed after execution.

The test executable was newly built by `nix build .#database-tests` and checked against
its package/source identity before direct serial execution of
`upstream --include-ignored --test-threads=1`. Executable SHA256:
`bb754ab864a711110e6da00a91d7daee3fe0dc387caad5c085c6d2c888817361`.

Supplemental all-targets Clippy, server development inventory Clippy, formatting,
runtime-manifest checking and strict verified-reference checking pass. The original
203-test execution remains historical evidence and is not relabelled as validation of
this integrated source. Remote CI and merge outcomes remain separate acceptance steps.

## Remaining assurance work

- Establish the complete URI, parsing, parameter-collision and resource-bound domains;
  finite Rust tests do not establish exhaustive protocol or supplier correctness.
- Verify composition of endpoint-query behavior with issuer identity, OAuth Basic,
  ID-token validation, refresh context, Federation binding, and logout recovery on the
  same accepted product artifact and configuration.
- Preserve the distinction between local HTTP/handler observations and browser, TLS,
  concurrent shared-store and deployed end-to-end acceptance. Confirm compatible rollout
  across every instance handling query-bearing transactions.
- Retain the original requirement meanings and historical evidence identities. This
  merge preparation neither resumes Task 3 nor changes its accepted obligation count.
