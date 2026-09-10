mod jwt_bearer;
mod private_key_jwt;
mod request_object;

fn request_object_used_as_assertion(
    header: &jsonwebtoken::Header,
    claims: &aegaeon_jose::jwt::JwtClaims,
) -> bool {
    // RFC 8725 section 3.12: audiences can overlap. Every admitted Request
    // Object has response_type, including legacy objects without explicit typ.
    header.typ.as_deref().is_some_and(|typ| {
        typ.eq_ignore_ascii_case("oauth-authz-req+jwt")
            || typ.eq_ignore_ascii_case("application/oauth-authz-req+jwt")
    }) || claims
        .custom
        .as_object()
        .is_none_or(|custom| custom.contains_key("response_type"))
}
