# Organization invitation delivery operations

Last updated: 2026-10-30

Status: active plan

Owner: Engineering

Audience: implementers, operators and security reviewers

The delivery channel defaults to disabled. After the stopped schema upgrade and
runtime grant checks, configure the exact domain endpoint and credential digest
through the authenticated management API. The endpoint must implement the fixed
[delivery contract](../design/organizations/invitation-delivery.md). Provision a
random 32-byte base64url credential without padding independently to that adapter
and the worker; configure SHA-256 of its exact 43 ASCII bytes. Do not reuse OAuth
client credentials. Never put the credential in process arguments or logs.

Run the schema-guarded `aegaeon-organization-delivery` executable with the same
validated Environment runtime configuration and restricted database credentials
as the server. Supply a private JSON document on stdin with `domainId`,
`invitationId`, optional `challengeId` or `identityRequestId`, and `credential`.
The two optional IDs are mutually exclusive. `identityRequestId` delivers a
registration or recovery proof under the separately enabled Environment identity
policy. It never selects a recipient address from stdin. The invocation attempts
one named item, then emits only its IDs and `idle`, `acknowledged`, `rejected`,
`uncertain` or `superseded`. Runtime startup is bounded to 60 seconds and the
operation to 45 seconds. The input is limited to 4KiB. The transport makes at
most one request with 3-second connect and 10-second response limits.

Schedule pending object IDs from authorized audit/outbox consumption. Concurrent
workers cannot claim the same revision. An uncertain result or lost worker must
remain uncertain: do not mark it delivered manually. A later invocation after
60 seconds may rotate and retry within the five-attempt bound. Earlier links and
challenges are invalidated by invitation resend; deadlines never extend. An
acknowledged item is not automatically resent. A definite refusal needs operator
investigation and a new authorized invitation; do not clear counters or rewrite
stored outcomes. Rotate the independent credential and channel digest together;
configuration revision changes refuse previously claimed but unadmitted sends.

A transport acknowledgment is not receipt by the human. Verify the actual
provider's authenticated adapter, fixed template, fragment-only capability
handling, redacted access logs and bounded retention before deployment. No email
claim or delivery acknowledgment authorizes membership. Acceptance still needs
current authenticated DPoP credentials and a fresh address challenge. The tested
owned TLS adapter establishes Aegaeon's interface behavior, not an unspecified
provider's delivery or retention guarantees.

For invitation-linked registration or recovery, enable the current Environment
identity policy through the management `identity-policy` resource with a human
Team owner and explicit domain configure authority. Use its Environment UUID
version tag for changes; disabling invalidates previously issued requests.
The browser form is `/organization-invitations/{domain}/{invitation}/identity`.
Enter invitation codes, proof codes and passwords only in form fields. No query
parameter accepts a credential. A completed credential change returns the login
subject and requires a new ordinary sign-in before the separate DPoP invitation
acceptance flow. The exact verified address is distinct from a lowercase login
alias; uppercase local parts do not attest the lowercase mailbox.
