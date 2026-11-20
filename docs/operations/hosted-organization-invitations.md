# Hosted Organization invitations

Last updated: 2026-11-20

Status: active plan

Owner: Engineering

Audience: deployment operators and security reviewers

The first-party browser, its confidential OAuth client and the organization
recipient API are part of Aegaeon. The deployment supplies the HTTPS notification
adapter and its mail provider. Existing custom recipient applications can keep
their own adapter and recipient contract.

## Prepare the installation

1. During the stopped upgrade, apply the display migration and ordinary serving
   grants. Give the domain's provision operator an organization name to publish.
   The configure operator sets labels for every offered role. The management
   resources, ETags and writer grants are specified in [role policy](../design/organizations/role-policy.md).
2. Create a dedicated PostgreSQL database and a dedicated serving login for the
   BFF. As its separate schema owner run
   `psql -X -v serving_role=HOSTED_LOGIN -f db/hosted-invitations/setup.sql` in
   that database. Use a verified TLS connection for a remote database. Replicas
   of the same Environment must use the same writable primary.
3. Register the Environment/domain confidential client through team client
   creation with `hostedInvitationDomainId`. Set the fixed HTTPS callback to
   `{issuer}/organization-invitations/hosted/callback`. The source resource is
   `{issuer}/userinfo` and the code scopes are `openid read offline_access`.
   Configure the sole exchange to `{issuer}/organization-invitations` for
   `organization.invitation.accept` from `read`. Enable explicit consent, DPoP,
   public subject identifiers and retained refresh-family revocation. The issuer
   must be reachable by HTTPS from each server. A deployment with a private CA
   can supply the PEM bundle in `AEGAEON_HOSTED_INVITATION_CA_FILE`.
4. On each server, point `AEGAEON_HOSTED_INVITATION_CONFIG_FILE` to the same
   private configuration, readable only by the service account (mode 0600 or
   0400). Supply a fresh random 32-byte flow key in unpadded base64url. Keep the
   OAuth client secret, flow key, issuer signing keys and adapter dispatch
   credential separate. The file has this shape, with placeholder values.

   ```json
   {
     "database_url": "postgresql://HOSTED_LOGIN@db.example/hosted?sslmode=verify-full",
     "key": "FLOW_KEY",
     "clients": {"DOMAIN_UUID": "DEDICATED_OAUTH_CLIENT_SECRET"}
   }
   ```

5. Run a dedicated v2 adapter with its fixed recipient UI at
   `{issuer}/organization-invitations/hosted`. Retain each existing custom
   adapter endpoint and its original destination. Register the domain delivery
   catalog, pinned client registration UUID, encryption key and optional exact
   HTTPS application return destination. Install the matching worker key and
   credential for each enabled route. The selection and upgrade rules are in
   [invitation delivery](../design/organizations/invitation-delivery.md).
6. Before selecting hosted for production issuance, send a first-admin invitation
   and a delegated invitation through the intended adapter and a test mailbox.
   Open the mail links in a real browser. Register or sign in, confirm the
   source and purpose on consent, explicitly request the address check, open the
   second message in the same browser profile, and verify the account, issuer,
   organization UUID and roles before accepting. Check the actual membership,
   the single acceptance event and the new application's authorization. Exercise
   password recovery separately. Record the deployment, generation, browser,
   mail provider, result and delivery times without storing proof-bearing URLs.

## Operation

Serve the landing URL directly, including for signed-out users. A proxy must
preserve the 200 response and its CSP, no-store and no-referrer headers. Exclude
the hosted paths, authorization query strings, cookies, request bodies and
provider mail content from access logs, analytics, caching and tracing.
Configure no redirect or tracking wrapper around a proof-bearing mail link.
See the [adapter contract](../design/organizations/notification-adapter-v2.md).

When checking step 6, look up the durable message for the relevant Environment,
invitation and delivery revision in `aegaeon.notification_messages`. Adapter
acceptance records `state=terminal`, `terminal_reason=accepted` and
`last_outcome=accepted`. The invitation's legacy `delivery_outcome` can still
read `uncertain`. Use the provider's delivery event and the actual mailbox to
confirm receipt.

For `organization.identity_requested` and `organization.identity_completed`,
the event's top-level `actor_kind` and `client_id` identify the original
inviter. In `data.authorityBasis`, `originatingPrincipal` records that
principal and `executor.kind` identifies the proof used for the operation.
The request uses `invitation_capability` and completion uses
`recipient_identity_proof`. The later `organization.recipient_challenge_requested`
event identifies the authenticated recipient and client.

An address challenge costs one of five shared slots and can last at most five
minutes. A retry of the same send after a lost response keeps its key. When the
parent access token expires the recipient signs in and consents again before
requesting a replacement. No refresh-token redemption occurs in the BFF.
A different browser can start from the original invitation and explicitly
request its own challenge. Opening an already delivered child link in that
browser cannot establish the original flow.

On a revocation outage, restore issuer connectivity and the dedicated client
credential. Each server processes the durable cleanup queue. An acknowledged
revoke removes the cleanup handle. Issuer family deadlines bound authority even
during outages. Monitor `hosted invitation cleanup unavailable` and the count
and oldest retry time in `hosted_invitation.cleanup`; restrict access to the
encrypted payloads. On restore, activate the fresh runtime generation before
traffic and restart every replica with the selected client and flow keys.
Successful historical confirmation is limited to the established BFF session
and five minutes. If the BFF could not confirm a response before expiry, check
membership through an independently authorized application.
