# Organizations introspection recipients

Last updated: 2026-10-30

Status: active plan

Owner: Engineering

Audience: implementers, operators, resource server integrators

## Explicit resource server authorization

This refines ORG-R09/R10/R21/R22/R23, ORG-G03/G06/G07/G11/G14 and
ORG-P01/P03/P08/P12/P13/P14. It does not discharge their composite obligations.
An audience string identifies a target; it does not authenticate its operator.
The ordinary OAuth client holding an organization token has no implicit right
to introspect it. Selected organization tokens require an explicitly configured
resource server registration for their exact target in the authenticated
Environment. Even when the audience equals a client ID, configuration is required.

Each registered target has zero to eight introspection recipients. A recipient
binds both the immutable internal client registration UUID and the exact public
client ID. Registration must be active, undeleted, confidential, use `client_secret_basic`, `client_secret_post` or `private_key_jwt` and belong to the Environment's active configuration.
DPoP possession by the presenting application remains the resource server's
responsibility; recipient authentication does not prove application possession.
No client secret, grant or bearer credential appears in configuration responses.
New and migrated targets have an empty recipient set. The target's `management`
flag is not a recipient grant or administrator bypass.

## Configuration and cancellation

The existing authenticated configuration API gains two POST operations under
`organization-domains/{domain}/targets/introspection-recipients`:

- `/replace`: `{audience, clientRegistrationIds, reason}` with one to eight
  distinct registration UUIDs, replacing the complete set.
- `/revoke`: `{audience, reason}`, removing all recipients for that target.

Both require the existing interactive management session, CSRF, explicit current
`configure` capability, domain If-Match, idempotency key and audit reason. The
audience stays in the JSON body so arbitrary exact audience strings do not
become path structure. Domain configuration GET returns the retained public
recipient bindings. Replacing with the same set and revoking an empty set
return conflict without an event or receipt. A successful change increments the
domain revision, invalidating original ceilings that captured the old revision.
An authorized retry returns its original receipt without restoring removed
recipients. Current actor authorization precedes receipt lookup.

Replace uses ordinary admission and receipt capacity. Revoke uses reserved
admission and can operate after recipients become invalid or are deleted.
The retained receipt reserve grows from 129 to 161: 64 operator revocations,
64 client-binding revocations, 32 target recipient-set revocations and one
domain disable. Only nonempty-to-empty recipient changes use this reserve.
Reactivation requires ordinary capacity. The existing 32-target, 48-KiB target
configuration, 64-KiB HTTP body/response, finite database/request deadlines,
transaction, audit and outbox limits remain enforced. A terminal domain revision
(`i64::MAX`) permits no new original authorization; the final cancellation
invalidates old ceilings and the exhausted domain cannot issue new authority.
Runtime authentication also requires its method to be globally enabled.

## Token-use boundary

At each introspection request, authenticate the resource server using the
existing OAuth client authentication path. Resolve its current registration
and exact target recipient binding under the same primary authority transaction
as the selected token's current-state check. A deleted/recreated client with
the same public ID has no inherited recipient authority. Missing configuration,
wrong target, stale registration or revoked authority yields inactive without
membership disclosure; authority-store failure yields an explicit service error.
JSON and signed introspection use this same recipient decision. No positive cache
or offline fallback is permitted. The private token metadata, verified JWT and
public authorization details must agree before any active response.

Configuration implementation alone does not enable the Organizations RAR types
or establish this token-use boundary. Complete exchange, current-state checking,
DPoP, revocation races, restore protection and artifact correspondence remain
mandatory delivery work.

## Evidence

Test exact audience scoping, cross-Environment/domain refusals, duplicate and
oversized recipients, active confidential registration, same-ID re-registration,
CAS and replay, actor cancellation, full ordinary capacity with successful
revocation, atomic outbox rollback, physical catalog and preserved migration
history. Retain an actual missing-registration-check negative control. The
subsequent protocol tests must exercise the complete HTTP recipient decision.
