# Configure an LTI resource-link Platform

Last updated: 2026-11-03

Status: current implementation baseline

Owner: Engineering

Audience: operators, integrators, reviewers

Aegaeon exposes LTI as an explicit capability of an existing OAuth/OIDC client.
This release implements authenticated top-level `LtiResourceLinkRequest` launches.
It does not advertise Advantage services, dynamic Tool registration, anonymous
launches or iframe support. See the [design contract](../design/lti-platform-launch.md).

## Upgrade and identity prerequisites

Stop and drain serving runtimes before applying the pending migrations. Apply the
local attribute migration, permanent subject ownership and audit authority
migrations, then the LTI tables and exact subject inventory extension, in Atlas
order. Restart only binaries compiled with the resulting complete `atlas.sum`.
PostgreSQL 18 is required by the permanent subject inventory implementation.
Follow [subject ownership provisioning and historical adoption](subject-ownership.md)
before starting an existing issuer. No migration treats existing subject history
as complete merely because current user rows are unique.

Published main `05cec388039bc7e14c7e609ba0f8f0fd8e65c0fe` is the supported
predecessor. After its complete history, apply all four LTI migrations in order:

1. `20261102100000_lti_platform.sql`: LTI configuration and launch tables.
2. `20261102101000_lti_subject_inventory.sql`: subject catalog extension.
3. `20261102102000_lti_admission_index.sql`: Environment/time admission index.
4. `20261102103000_lti_admission_inventory.sql`: catalog covering that index.

This linear upgrade preserves all 20 preceding SQL files and Atlas ledger rows.
Stopping after either of the first two migrations is incomplete: the compiled
Atlas inventory requires the final revision, so startup refuses the database even
when LTI is disabled. Keep runtimes stopped through the complete sequence and
retain the failure instead of changing revision metadata or weakening preflight.
The generated schema and compiled checker use the same final inventory. An earlier
unmerged LTI or ownership candidate has a different installation history and needs
an explicit migration assessment; never relabel its revisions or bypass checks.

The schema adds immutable configuration history and identity reservations, plus
expiring launch state. There is no automatic LTI registration, authority grant,
legacy attribute adoption or launch activation. DCR does not confer LTI capability.

## Register the capability

Use the existing browser management session as a human team OWNER or
ADMINISTRATOR, with its Origin and CSRF protection. Team API keys do not authorize
these endpoints. Under `/api/v1/teams/{teamId}/environments/{environmentId}/lti`:

| Method and path | Operation |
| --- | --- |
| `PUT /registrations` | Save `{clientId, baseRevision, configuration}`; use `0` for initial creation. |
| `POST /registrations/activate` | Activate exactly `{clientId, revision}` for the maximum saved revision number. |
| `GET /registrations?clientId=...` | Return the maximum saved registration revision and Platform issuer/endpoints. |

Stale revisions and identity reuse return `409`. Saving and activation require a
successful audit write in the same transaction. Historical documents are retained;
`activeRevision` identifies the currently effective revision. A saved draft has no
runtime effect until activated unless `stagedActivation` is explicitly false.

An example `configuration` is:

```json
{
  "schemaVersion": 1,
  "name": "Example Tool",
  "status": "active",
  "initiateLoginUri": "https://tool.example/login",
  "redirectUris": ["https://tool.example/launch"],
  "security": {
    "requireConsent": true,
    "requireDpop": true,
    "stagedActivation": true
  },
  "deployments": [{
    "id": "deployment-1",
    "status": "active",
    "producers": ["context-producer"],
    "allowedRoles": ["http://purl.imsglobal.org/vocab/lis/v2/membership#Learner"],
    "resourceLinks": [{
      "id": "resource-1",
      "status": "active",
      "targetLinkUri": "https://tool.example/resource/1",
      "context": {
        "id": "context-1",
        "types": ["http://purl.imsglobal.org/vocab/lis/v2/course#CourseSection"]
      }
    }]
  }]
}
```

All three security options default to true when omitted. Omitting an object's
status defaults it to disabled. An administrator may explicitly relax each extra
security option; base OAuth sender constraints still apply. `retired` is terminal.
Keep existing deployment and resource-link entries in subsequent documents, using
`disabled` or `retired`; their identifiers and parent/context ownership cannot be
removed or reassigned. A copy requires a fresh identifier. Disabling an existing
capability remains possible after its OAuth client becomes inactive.

The registration's LTI redirect allowlist is separate from ordinary OAuth grant
settings. Registration does not enable an ordinary implicit grant. Tool settings
use the exported `issuer`, `/lti/authorize`, and `/jwks` with RS256. `/token` is the
existing OAuth endpoint; exported endpoints do not imply any Advantage permission.

Login initiation, redirect and target-link URIs require an explicit `https://`
authority delimiter (scheme case is insensitive). Abbreviations such as
`https:tool.example/launch` or `https:/tool.example/launch` are rejected: a browser
can resolve them against the issuer instead of the Tool origin. Previously saved
abbreviations also fail configuration validation when read or activated. Repair
them with `PUT /registrations`, supplying the maximum saved `baseRevision` from the
registration receipt and a complete configuration with explicit absolute URLs.
Replacement compares the previous document's identities and lifecycle states
without requiring its old destinations to pass current validation; the submitted
configuration must pass all current checks. Prior revisions remain immutable.
With staged activation, activate the newly saved revision explicitly: the old
active revision remains unusable until then. Accepted URI strings are preserved
rather than silently rewritten.

Mapped `profile`, `picture` and `website` claims must contain absolute HTTPS
resource URLs. The final disclosed values are checked at issuance, including
stored attribute changes after launch initiation. An invalid value refuses the
launch without issuing a token; repair the source value before retrying an
unexpired intent. Resource URLs may contain queries and fragments; they must not
contain user information, control characters, spaces or backslashes. This check
does not rewrite the value or change role vocabulary identifiers.

## Produce and complete a launch

Authorize a confidential context producer using the existing `clientCredentials`
policy with scope `lti:launch` and the exact canonical audience
`{issuer}/lti/launches`. Enroll that URI in the policy's resource target catalog;
resource aliases alone do not change the audience checked at this API. Ordinary
client authentication, scope ceilings and sender constraints still apply. A
producer must also be explicitly listed on the selected deployment.

Send `POST /lti/launches` with its access token and, by default, a fresh DPoP proof
bound to this URL, HTTP method, token hash and the same key used at issuance:

```json
{
  "clientId": "tool-client",
  "deploymentId": "deployment-1",
  "resourceLinkId": "resource-1",
  "userId": "00000000-0000-4000-8000-000000000001",
  "roles": ["http://purl.imsglobal.org/vocab/lis/v2/membership#Learner"]
}
```

`userId` is the internal user UUID, not an editable profile attribute. The producer
asserts the user's membership facts; the deployment limits that authority. The
API does not accept arbitrary targets, context objects or identity claims.

The `201` response contains `launchUrl`. Navigate the authenticated user's
browser to it as a top-level GET. The session must belong to that exact owner;
this initial capability does not start an interactive login on their behalf.
Default consent occurs before Tool login initiation. On approval Aegaeon sends
`iss`, opaque `login_hint`/`lti_message_hint`, `client_id`, `lti_deployment_id`, and
`target_link_uri` to the registered Tool initiation URL.

The Tool sends GET or form POST to `/lti/authorize`, with the hints,
`scope=openid`, `response_type=id_token`, `response_mode=form_post`, `prompt=none`,
a nonce and preferably state. Opaque values are preserved exactly. A cross-site
POST without a SameSite=Lax session cookie can use one stored-request GET
continuation. A missing or mismatched authenticated session produces
`login_required`; the silent request never opens a consent/login screen.

The Tool may send `max_age` as an unsigned decimal number of seconds. Aegaeon
checks the authenticated session's original `auth_time` before signing and again
after the final session read. An exceeded limit, or `max_age=0` requiring fresh
interactive authentication, returns `login_required` without consuming the intent.
Malformed or overflowing values return `invalid_request` after redirect admission.
The limit is retained through the POST continuation, and the ID Token includes
`auth_time`. Optional `acr_values` preferences are accepted without adding an
unachieved `acr` claim. These behaviors implement OIDC Core sections 3.1.2.1 and
15.1 within LTI's required silent flow.

An optional `id_token_hint` constrains the existing browser session. Its RS256
signature and issuer must validate against the Platform's published signing keys,
its audience must contain the requesting Tool, any authorized party must match,
and its subject must equal the authenticated intent owner. A token from a past
session may have expired; it never creates or restores authentication. Future
validity, another Tool or issuer, invalid signatures and Logout Tokens are refused.
A different subject or an absent current session cannot complete the silent flow.
GET requests and stored POST continuations apply the same checks.

This profile does not support Request Objects, request-URI retrieval or inline
registration. After admitting the exact registered response URI it returns
`request_not_supported`, `request_uri_not_supported` or
`registration_not_supported`, respectively (OIDC Core sections 6.1, 6.2 and 7.2.1).
Supplying both request-object forms returns `invalid_request`. It never retrieves
an unsupported request URI. The optional `claims` parameter does not grant
disclosure: only independently configured mapping outputs are returned, following
OIDC Core section 5.5 for providers without claims-parameter support.

Each intent lasts at most five minutes and never beyond the producer token's
original expiry. After creation it is a distinct short-lived authorization:
producer client/grant, user, session and registration authority are rechecked;
revoking the original access token alone does not revoke an already-created
intent. To revoke these intents, disable the deployment/producer authority or
change the active registration. Runtime configuration changes also invalidate
outstanding intents. The producer token itself is never retained in launch state.

The RS256 ID token lasts at most 60 seconds, further bounded by intent expiry.
It includes the user's permanent subject, issuer, exact Tool audience, nonce,
required LTI resource-link claims and explicitly released attributes. Issuance
consumes the intent and writes its audit record before returning the form. If the
response is lost after commit, create a new launch; retrying cannot issue another
token. A commit error never releases the prepared signed response.

Admission allows at most 32 launches per producer/user and 4,096 per environment
within five minutes. Completed/cancelled launches still count until that window
ends, including when the producer token expires earlier. Capacity exhaustion
returns `429`. Expired state whose five-minute admission window has ended is
removed in bounded batches by admission and periodic cleanup; durable audit and identity records
remain. Failed dependencies return `503`, with no permissive fallback.

## Release local attributes

Local attributes come from the existing user attribute management API. A
registration's optional `mapping` adds explicitly admitted outputs through the
common mapping engine. For example, to release a local nickname:

```json
{
  "inputs": [{"source": "local", "name": "nickname"}],
  "sourceGrants": [{"source": "local", "name": "nickname"}],
  "outputs": {
    "nickname": {
      "expression": {"op": "read", "attribute": {"source": "local", "name": "nickname"}, "path": []},
      "schema": {"type": "string"},
      "required": false
    }
  },
  "releasedOutputs": ["nickname"]
}
```

Input admission, source disclosure and output release are separate decisions.
Missing inputs do not bypass their disclosure requirement, including through
fallback expressions. `null` and absence remain distinct. Protocol-owned claims,
identity, deployment, roles and resource context cannot be overridden by custom
rules. LTI custom parameters are string-valued properties under the standard
`custom` claim. Other structured extensions use namespaced HTTPS claim names.
Unimplemented custom substitution variables remain literal strings; this
implementation does not advertise a substitution registry. Legacy/external
attributes are not silently imported or released.

Audit records identify actions, revisions and response digests, excluding raw
attributes, access tokens and launch tickets. Configure reverse-proxy/access-log
redaction for `/lti/launch/*`, `/lti/continue/*` and authorization query/body values.
Session storage and PostgreSQL are separate consistency domains; session validity
is checked again after signing, while database authority and consumption remain
under transaction locks. This is not a claim of distributed atomic revocation.

The optional `state` parameter is returned exactly when present. Its accepted
domain follows [RFC 6749 Appendix A.5](https://www.rfc-editor.org/rfc/rfc6749#appendix-A.5):
a nonempty printable ASCII string, bounded here to 4,096 bytes. Invalid encoding,
control characters and duplicate parameter names are rejected before reflection.
An empty optional `state` value is treated as omitted, as required by RFC 6749
section 3.1; it is not emitted as an empty response field.
The nonce remains opaque and is copied without trimming or normalization.

LTI requires two serving PostgreSQL logins on the same database. Set
`AEGAEON_DATABASE_URL` to the runtime login and `AEGAEON_MANAGEMENT_DATABASE_URL`
to the management login. Both pools use the configured connection count and
acquisition deadline; capacity planning must include both pools. The runtime
login needs `SELECT` on `aegaeon.user_attribute_sources`; revoke table and column
`INSERT`/`UPDATE`, `DELETE`, `TRUNCATE` and `TRIGGER`. The management login needs
`SELECT`, `INSERT` and `UPDATE` on that table, plus the ordinary management API
grants. Neither serving login may own the table, create objects in `aegaeon`,
or reach an administrative role. Keep migration and maintenance credentials
separate, using the existing subject-ownership provisioning procedure.

Neither serving login may administer role memberships, directly or indirectly.
`ADMIN OPTION` can allow a login to grant itself privileges even when its existing
membership has both `SET FALSE` and `INHERIT FALSE`. Startup, activation and the
runtime reader check use PostgreSQL's administrative-membership predicate before
evaluating effective privileges. An ordinary membership with all three options
false remains permitted. Keep role administration on separate stopped-operation
credentials; removing `CREATEROLE` alone is insufficient.

Startup validates the actual sessions, including authority reachable through
`SET ROLE` followed by inheritance. A transaction-lock challenge checks that
both pools reach the same live database. Activation repeats this validation;
each launch transaction rechecks the runtime login's read restriction. Missing
credentials prevent LTI activation and startup with an active registration.
An explicitly configured management pool never falls back to the runtime pool
on failure. Non-LTI installations may retain their existing single pool.

These checks do not qualify arbitrary proxies or restored clusters. Suppliers
must route both credentials to the same stable database, preserve grants and
exclude serving credentials from migration/maintenance roles. Revalidate this
boundary after failover, restoration or credential rotation. Existing migration
files and permanent subject ownership remain unchanged.

## Conformance and assurance target

1EdTech LTI Core 1.3 Platform responsibilities are adopted into Aegaeon's formal
and security assurance scope. This registration does not establish full conformance,
proof discharge or certification. The [assurance record](../verification/claims/assurance-case/lti-platform.md)
tracks exact sources, feature scope, and criteria for implementation and assurance.

## Migration and catalog regression

The restricted catalog admission covers local attribute sources and all four LTI
tables, their constraints, indexes and immutable-trigger definitions. Missing
foreign keys, disabled guards, altered trigger functions, row security and excess
runtime or maintenance privileges refuse admission. The successor retains every
published predecessor migration and the existing Atlas rows.

The reproducible PostgreSQL fixture in `tests/lti/catalog_upgrade.py` seeds
attribute values, provenance and permanent identities before applying the linear
main-to-LTI upgrade. It also compares fresh/schema installations and exercises
old checkers and deliberate catalog corruption. Run it through
`nix/tests/lti-catalog-upgrade.nix` with the pinned flake's PostgreSQL and Atlas.
This is migration/caller evidence; whole-provider, supplier and formal acceptance
remain tracked in the LTI assurance obligations.

## Packaged launch regression

Run `nix build path:.#checks.x86_64-linux.lti-packaged-runtime` to exercise the
distributed server through an owned HTTPS ingress, a separate Tool and Chromium.
The check uses PostgreSQL 18, real Redis, actual local password login and secure
defaults. It validates signed GET/POST launches, SameSite continuation, independent
JWKS verification, DPoP challenges/replay, token binding, consumed-intent replay,
session-store denial/recovery and logout of a pending launch. It removes its
temporary stores, credentials and certificate on completion or handled signals.

The fixture's certificate trust and loopback backend are explicit test inputs.
Production still requires an authenticated trusted-proxy boundary, protected store
connections and credentials, clock synchronization, key retention and the stopped
migration/restore procedure. Passing this check does not qualify those suppliers
or establish complete conformance or formal proof discharge.

## Signing-key rotation overlap

LTI tokens have a profile lifetime of at most 60 seconds. Rotation retains the
previous OIDC signing public key for at least that lifetime plus the configured
clock leeway, even when the ordinary OIDC TTL is shorter or has just been reduced.
This retention does not extend token validity. Explicit revocation still removes
the key from service. Keep the shared ordinary-OIDC lifetime/history obligations
separate from this LTI minimum; this check does not qualify cluster rollback.

Retirement uses the clock after acquiring the Environment lock. Time spent
waiting for an in-flight launch cannot shorten the public-key overlap. The
regression holds that lock across a transaction-start time boundary before
allowing the real management activation to complete.

## Protected management database authority

The explicit management writer must preserve the same permanent identity and
append-only audit boundaries as the serving role. Startup and LTI activation
reject permission to change `session_replication_role`, protected table or column
mutations, competing triggers, audit-history rewriting, and reachable owner or
maintenance authority. Checks include the audit parent and attached descendants
in every schema, and role paths that combine `SET ROLE` with inheritance. Private
history helpers and the runtime-only namespace validator remain unavailable to
the management login. No existing migration or function ACL is widened.

Neither serving login may own, inherit ownership of, or reach through `SET ROLE`
any trigger function attached to a protected relation or audit partition. A
function owner can remove dependent triggers with `DROP FUNCTION ... CASCADE`
even when the function body still matches its fingerprint and the login cannot
create schema objects. The runtime reader rechecks this ownership on each launch.
Both logins also reject reachable `pg_read_server_files`, `pg_write_server_files`
and `pg_execute_server_program` authority, which can bypass database permissions.
Membership with ADMIN, SET and INHERIT all false grants none of these capabilities.

Changing database grants or attaching audit partitions is a stopped administrative
operation: drain serving and management processes, validate the resulting catalog
and both credentials, then restart. These checks do not authorize administrators
to change the authority graph concurrently with serving requests.

## Optional standard claim values

Mapping output for `email`, `locale` and `zoneinfo` is checked immediately before
signing, including source changes after launch initiation. Refusal leaves the
intent unconsumed so a corrected value can be used before its deadline. Accepted
strings are preserved exactly; neither normalization nor guessed values are used.

The email generation profile emits RFC 5322 section 3.4.1 addr-spec syntax with a
dot-atom or quoted local part and a dot-atom or address-literal domain. It excludes
display names, comments, folding, obsolete syntax and non-ASCII input, with a
4,096-byte admission limit. It does not establish mailbox control or delivery.
`email_verified` remains unavailable to custom mapping.

Locale uses the existing [dated BCP47 admission profile](../specs/language-metadata.md).
Zoneinfo accepts exact Zone and Link names from the bundled IANA tzdata 2026f,
including historical aliases. That check validates identifiers only; it performs
no time conversion and makes no statement that a user's asserted zone is true.
A later registry update is a separate source update, not an automatic runtime
network lookup. Run `nix build path:.#checks.x86_64-linux.lti-claim-sources` to check
the byte-pinned source and compiled table correspondence.
