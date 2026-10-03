# OpenID subject format and existing identities

Last updated: 2026-10-02

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

OIDC End-User subjects must contain 1–255 ASCII characters. Case and accepted
bytes are preserved. The check does not impose a printable-only alphabet.
Management creation, invitations, CSV import and subject PATCH retain their
existing surrounding whitespace trim, then reject invalid subjects with
`400 invalid_request`. CSV rejection leaves the batch unchanged.

New users provisioned through an upstream OIDC connection receive an opaque
local subject, `upstream:` followed by a random UUIDv4. Upstream issuer, subject
and email are not embedded in it. Existing account links and explicitly enabled
email reuse preserve the existing local subject. A database collision refuses
provisioning; it never selects another user because the generated text matches.
Concurrent first logins can produce one success and one refusal; a later request
can use the committed account link.

With the reject-existing-email policy, an unlinked matching email is rejected,
even if its local subject resembles an old concatenated upstream identifier.
Use the audited account-link management operation when an association is intended.
There is no fallback lookup by an old generated subject and no automatic renaming
of existing users. JIT enablement, verified email, domain and blocked-user policy
checks still apply.

ID Token construction and both public OIDC signing helpers reject invalid
subjects. Signing also rejects an exact duplicate `sub` in additional claims.
The incoming OIDC validation path rejects a malformed subject even when the
signature is valid. The UserInfo endpoint checks the metadata and final subject
and requires exact agreement. Invalid server-held subject data returns the
existing generic `500 server_error` response without a successful UserInfo body.
These checks do not apply a new OIDC End-User constraint to other JWT subject roles.

Before upgrading, run the [read-only inventory](../../scripts/operations/inventory-oidc-subject-format.sql)
against the intended database using `psql -X -v ON_ERROR_STOP=1 -f` and a read-only
operator role. The script uses a repeatable read, read-only transaction and rolls
it back. It reports counts and protected environment/user UUID locations for
empty, non-ASCII and overlength values, across every environment and status,
including deleted users. Retain the output privately; do not attach identity
locations or raw subject values to public logs. The UTF-8 byte test distinguishes
non-ASCII characters without normalizing stored values.

The format change alone supplies no automatic repair. The subsequent
[permanent ownership upgrade](subject-ownership.md) includes a strict migration,
stopped history inventory and adoption. Existing invalid subjects,
sessions and tokens cannot produce a successful nonconforming ID Token/UserInfo
after upgrading. Decide identity repair explicitly with the affected relying
parties. Do not truncate, transliterate, trim on output or silently replace old
identifiers. Previously issued artifacts retain their original bytes; this
change does not erase or revoke them remotely.

The inventory describes current rows only. It cannot reconstruct previous
renames, physical deletion, prior issuer history or historical reassignment.
Subject PATCH, deletion and restore retain their existing permission and audit
contracts. The [permanent ownership procedure](subject-ownership.md) covers enforcement and
legacy-history reconciliation. Format validation and random new identifiers by
themselves do not establish that lifetime guarantee.

Protocol references: [OIDC Core §2](https://openid.net/specs/openid-connect-core-1_0.html#IDToken),
[§5.7](https://openid.net/specs/openid-connect-core-1_0.html#ClaimStability),
and [§8](https://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes).
