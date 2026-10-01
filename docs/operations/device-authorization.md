# Device Authorization Confirmation

Last updated: 2026-10-02

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

## Browser approval

A device client receives a user code and a verification URI from
`/device_authorization`. The user opens `/device` in an authenticated browser,
enters the code and continues to the confirmation page. A
`verification_uri_complete` link prefills the same entry form; opening the link
never approves a device.

The confirmation page displays the canonical `XXXX-XXXX` code, client identifier,
requested scope and resource. Approve only when the device is in your possession
and the code on its screen matches. The approval form has an initially unchecked,
required checkbox: “I have this device and its displayed code matches the code
above.” Deny requests you do not recognize; the separate denial form does not
require this checkbox.

`POST /device/approve` requires exactly one `confirm_device=yes` form value.
Missing, empty, duplicate, differently cased or whitespace-padded values are
rejected with HTTP 400 before approval. The server also enforces the existing
session, CSRF, rate-limit and code-state checks. HTML validation alone is not the
security boundary. `POST /device/deny` keeps those checks without requiring
possession confirmation.

## Compatibility and limits

Already open approval pages from before this change lack the confirmation field.
After upgrade, reopen `/device` and repeat the confirmation step. Codes retain
their existing expiry and single-use rules; no database or Redis migration is
needed.

Code lookup still uppercases ASCII letters and removes hyphens and whitespace.
Successful lookups display the canonical formatted code. The existing
20-character generation alphabet and entropy are unchanged. Confusable aliases
such as `O`/`0` or `I`/`1`, Unicode case folding and transliteration are not added.

The prompt follows RFC 8628 sections 3.3.1 and 5.4 recommendations. The exact
checkbox requirement is Aegaeon's browser policy. It records a user assertion;
it does not cryptographically prove device possession, attest hardware, or
establish that phishing is impossible. The client identifier, scope and resource
are request context, not evidence that the user has the device.
