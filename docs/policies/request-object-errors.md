# Request Object Error Responses

Last updated: 2026-10-29

Status: current implementation baseline

Owner: Engineering

Audience: OAuth client developers, operators, reviewers

## Cryptographic rejection

Authorization and PAR return HTTP 400 `invalid_request_object` when the Request
Object envelope cannot be decrypted into a signed JWT, its selected verification
key is unavailable, its signing algorithm is unsupported, or signature validation
fails. Rejection does not issue a code, create a pushed request, or retry another
decryption key. Responses retain the existing no-store policy and do not redirect
to an unverified destination.

This implements the cryptographic-error requirements of
[RFC 9101 sections 6.1 and 6.2](https://www.rfc-editor.org/rfc/rfc9101.html#section-6.1).
[RFC 9126 sections 2.3 and 3](https://www.rfc-editor.org/rfc/rfc9126.html#section-2.3)
apply the JAR processing rules at PAR and allow extension error codes.

Parameter validation, outer client identification, authorization details and
target validation retain their own error classifications. A missing signed
request where one is required remains a separate PAR admission error. Internal
verification failures remain server errors, never a permission fallback.

## Compatibility and evidence

Clients that previously matched only `invalid_request` must also handle
`invalid_request_object` for these rejected inputs. Successful request processing
and cryptographic admission rules are unchanged. The management key-rotation
regressions exercise real signed/encrypted requests, successful active and
retiring keys, key substitution, invalid inner signatures and revoked keys at
both public endpoints. These finite tests establish neither full RFC coverage nor
a new formal-proof discharge.
