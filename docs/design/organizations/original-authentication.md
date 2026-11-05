# Original authentication for temporary support access

Last updated: 2026-10-30

Status: active plan

Owner: Engineering

Audience: implementers, operators and security reviewers

This boundary implements the authentication evidence prerequisite of ORG-R12,
ORG-G08 and ORG-P09. It does not activate temporary support access or discharge
that composite obligation. Domain support permission alone remains insufficient.

Retain an immutable server-side record from the validated upstream OIDC callback:
managed Environment/connection/configuration UUIDs, exact issuer and client ID,
hashed upstream subject, local user UUID/subject/identity revision, account-link
UUID/revision/provenance, explicit signed `auth_time`, signed `acr` and `amr`, and
the callback observation time. Capture the account-link and user facts in the
same transaction as callback persistence, after profile updates. No raw ID Token,
nonce, access token, credential or upstream subject is retained in this record.

The signature, issuer, audience, nonce, time and code/access-token hash checks
must succeed before evidence capture. Missing explicit `auth_time`, missing
local ownership, malformed or over-budget claims produce no support evidence.
Ordinary authentication keeps its existing behavior. Requested or default ACR,
token `iat`, callback time, session creation, refresh and Token Exchange cannot
replace or advance the signed authentication facts. Local password login and
legacy sessions carry no upstream assurance evidence.

Persist the record with the browser session in one store operation. Before the
original organization consent, bind it to the same local identity, Environment
and authentication time. Retain it unchanged in that consent and its OAuth root;
later approval rechecks the same snapshot. A malformed stored record refuses
decoding; an absent legacy record remains absent. Optional evidence does not
broaden ordinary membership authority.

Support authorization must additionally check the current primary connection,
configuration, account-link and identity revisions, a separately configured
accepted provider/assurance policy, original authentication age at most 300
seconds, explicit operator-to-business-user binding, support entitlement and
original approval ceiling. The exact accepted ACR and concrete authentication
methods must satisfy that policy; the string `mfa` alone is insufficient. Policy
changes cannot upgrade an existing root. Support issuance, online checks and
revocation remain separate implementation work.

OIDC Core section 2 defines authentication time and optional assurance claims;
RFC 8176 defines AMR values and distinguishes method references from assurance
context. The 300-second condition and evidence bindings above are the Aegaeon
Organizations profile, not additional OIDC conformance requirements:

- <https://openid.net/specs/openid-connect-core-1_0.html#IDToken>
- <https://www.rfc-editor.org/rfc/rfc8176.html#section-2>

Evidence is private authentication state, not an API response or token claim.
Bound issuer/client/subject strings to 2,048 bytes, ACR to 256 bytes, and AMR to
16 unique strings of at most 128 bytes each. No empty/control-bearing values are
accepted. Storage errors fail closed; evidence is never reconstructed from
editable profile fields, email matches or the OAuth request body.
