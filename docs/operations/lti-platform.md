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
The nonce remains opaque and is copied without trimming or normalization.

The current server bootstrap shares its database pool between management and
protocol handlers. LTI issuance reads local attributes, while their mutation API
requires a human management role. This is application-level separation; separate
runtime-read and management-write database principals remain an integration
obligation before production application. A restricted non-owner test login does
not establish that stronger separation.

## Conformance and assurance target

1EdTech LTI Core 1.3 Platform responsibilities are adopted into Aegaeon's formal
and security assurance scope. This registration does not establish full conformance,
proof discharge or certification. The [assurance record](../verification/claims/assurance-case/lti-platform.md)
tracks exact sources, implementation scope and Task1b/Task3 exit conditions.

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
