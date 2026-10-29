# Identifier representation

Last updated: 2026-10-29

Status: current implementation baseline

Owner: Product / Engineering

Audience: implementers, API consumers, reviewers

## Owned object IDs

Aegaeon's UUID object identifiers use the UUID string itself in payloads and
URLs. Object kind belongs in the resource path, field or schema, rather than a
prefix in the value. Generated UUIDs use lowercase hyphenated text. A management
URL therefore uses `/teams/{teamId}`, where `teamId` is the UUID returned by the
Team API. Knowing an ID never grants authority; every reference is checked in
its authenticated Team, Environment and target domain.

Existing UUID parsers continue to accept their existing lexical aliases and
resolve them to the same typed UUID. Schema precision does not introduce a new
canonical-input rejection policy or rename stored objects.

## Separate namespaces

| Value | Contract |
| --- | --- |
| Organization internal object ID | Aegaeon-owned UUID; never inferred from an external selector. |
| Native organization external selector | Exact nonempty UTF-8 string, at most 256 bytes, without control characters, owned within one Environment/domain. No prefix parsing, case folding, Unicode normalization or trimming. Output preserves the stored string. |
| OIDC subject | Stable issuer-local protocol identity. Newly generated local subjects use a plain random UUIDv4; existing and explicitly supplied valid subjects keep their identity. This profile is separate from OIDC format conformance and permanent ownership enforcement. |
| OAuth client identifier and JOSE key identifier | Opaque protocol values distinct from client/key object UUIDs. Preserve their existing generation and import contracts. |
| Session, grant and refresh-token inventory handles | Opaque fingerprints, not UUID objects or credentials. |
| API key secret, storage key and internal revocation key | Distinct secret/internal namespaces, not public object ID formats. |

New subject generation must not rewrite historical `(iss, sub)` assignments,
adopt an existing account on collision, or infer ownership from a prefix. Explicit
management/import inputs retain their accepted format and validation. See the
[subject upgrade contract](../operations/oidc-subject-format.md).

## Existing application-profile compatibility

The existing application authorization profile requires `organization_` followed
by a canonical UUID. Its validator, membership query, stored grants, JWT and
introspection use that same contract. It remains an explicitly documented
compatibility exception until a coordinated migration is available. Neither
removing the prefix from a serializer nor accepting both forms as implicit
aliases is an authorized migration.

The native external selector is independent: an external value that happens to
look like a prefixed ID remains an exact external string in its own scope.
Migration must establish an explicit mapping, one authority writer, preserved
old credential semantics and same-version API/token/introspection/revocation
tests before cutover. Tombstones and permanent ownership survive export,
import and restore; an ID-format change cannot release an identity for reuse.

## Delivery order and evidence

Shared schema/documentation and new-subject generation are separately reviewable
prerequisites. Permanent subject ownership is one foundation; related candidate
PRs are not independent guarantees. Native organization selector repair proceeds
against the external-ID contract. Legacy profile cutover follows working native
flows and migration validation. Existing IDs are not renamed as a prerequisite.

Schema checks establish API description correspondence. Runtime regression tests,
permanent ownership/catalog validation, formal proof discharge and product
release acceptance remain separate obligations.
