# Original Organizations authorization

Last updated: 2026-10-30

Status: active plan

Owner: Engineering

Audience: implementers, security reviewers, integrators

## Request and approval

The [public grant schema](../../../spec/organization-grant.schema.json) describes
the wire structure. Semantic and byte-bound checks remain mandatory.

This refines ORG-R06/R07/R08/R21/R22, ORG-G05/G06/G14 and
ORG-P01/P04/P08/P12/P13. It does not discharge those composite obligations.
The original authorization uses a different RAR type from the selected
organization access token. A parent authorization can select several explicitly
approved organizations; it is not itself a selected organization credential.

```json
[
  {
    "type": "https://github.com/codetakt/aegaeon/spec/organization-grant/v1",
    "locations": ["https://documents.example/api"],
    "organizations": [
      {"identifier": "school-01", "privileges": ["documents.read"]}
    ]
  }
]
```

The first profile accepts exactly one detail and one registered audience,
1–16 distinct external organization IDs, and an explicit nonempty privilege
set for each organization. Canonically serialized request JSON is at most
16 KiB, in addition to the existing raw HTTP admission limit before parsing.
The union of requested privilege keys has at most 256 distinct keys. Unknown members, duplicate JSON members,
duplicate IDs/privileges, empty values and privilege expansion are rejected.
Identifiers retain exact UTF-8 bytes; the audience determines the domain inside
the authenticated Environment. No caller-supplied internal binding is accepted.

This uses RFC 9396 sections 2, 3, 6 and 7 for structured requests and responses;
the type, limits and consent requirements are Aegaeon profile rules. The existing
RFC 8693 target/scope policy and refresh-lineage requirement also apply. The
original request requires authorization code, `prompt=consent`, `offline_access`,
a confidential client, mandatory DPoP and `dpop_jkt`. No existing login grant is
upgraded. Other RAR types remain unsupported. Metadata and configuration must
not advertise this type until the complete consuming paths are implemented.

Before showing consent, read the primary store under finite transaction and
request deadlines. Require enabled domain, current active client registration,
explicit active client binding, current active subject, organizations and
memberships, and applicable role definitions. Store the exact displayed IDs,
audience and privileges with the internal user/registration UUIDs, domain and
client-binding revisions, membership incarnations/generations and role versions.
The server-only consent snapshot is at most 64 KiB and retains the existing
five-minute, session-bound, one-use consent transaction. Escape all displayed
values. The user approves the whole displayed set or denies it.

At approval, recheck the same request and authority. Any changed snapshot
requires a new consent transaction; newly added authority cannot enter the old
display. Only the successful server-side approval supplies the issuer input.
The code issuer requires an original exchange root and binds this snapshot to
its exact root ID and horizon, capped at 24 hours from the original snapshot.
The original `auth_time` and DPoP key remain fixed. A caller's serialized RAR
request alone is insufficient to produce a ceiling.

## Persistence and use

The private Organizations ceiling travels inside the existing server-side
exchange grant, through code, root publication, refresh rotation and access-token
metadata. It is not placed in JWTs or client responses. Absence remains absence;
malformed or inconsistent bindings fail closed. Root cancellation and original
publication guards continue to apply. Refresh cannot change the ceiling,
original authentication time or root horizon.

The parent token response may carry only the approved public grant detail. An
organization access token instead carries the existing organization-access/v1
detail. Resource servers must not interpret a parent grant detail as selected
organization authority. Token Exchange selects one originally approved
organization and intersects its ceiling with current client, target, membership
and role authority. Domain disable/re-enable or client binding revision changes
invalidate the old Organizations ceiling; reauthorization is required.

The initial original grant profile covers ordinary membership. Administrative
access needs its separately specified original permission and fresh MFA contract;
it cannot be inferred from this grant or an operator session.

## Required evidence

Exercise the actual browser consent → code → refresh root → exchange path,
including denial, consent replay, consent/session mismatch, missing or forged
approval, changes between display and submission, old login grants, promotion,
rejoin, client re-registration, DPoP mismatch, root cancellation races and store
faults. Retain a guard-removal negative control. Native capture tests are a
component of this evidence, not completion of ORG-G05 or product assurance.

See [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396.html) and
[the adopted access design](design.md).
