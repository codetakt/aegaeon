const TEST_RSA_PRIVATE_KEY_PEM: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/rsa2048-private.pk8.pem"
));

fn upstream_signing_key() -> Result<crate::oidc::OidcSigningKey, String> {
    crate::oidc::OidcSigningKey::from_rsa_pem("upstream-kid".to_string(), TEST_RSA_PRIVATE_KEY_PEM)
        .map_err(|err| err.to_string())
}

fn upstream_jwks(signing_key: &crate::oidc::OidcSigningKey) -> Result<JwkSet, String> {
    let value = serde_json::to_value(signing_key.jwks()).map_err(|err| err.to_string())?;
    JwkSet::from_value(value).map_err(|err| err.to_string())
}

fn upstream_jwks_with_alg(
    signing_key: &crate::oidc::OidcSigningKey,
    alg: &str,
) -> Result<JwkSet, String> {
    let mut value = serde_json::to_value(signing_key.jwks()).map_err(|err| err.to_string())?;
    value["keys"][0]["alg"] = json!(alg);
    JwkSet::from_value(value).map_err(|err| err.to_string())
}

fn sign_raw_upstream_id_token(
    signing_key: &crate::oidc::OidcSigningKey,
    alg: jsonwebtoken::Algorithm,
    payload: &[u8],
) -> Result<String, String> {
    let alg_name = jwt_alg_name(alg).ok_or_else(|| "unsupported test alg".to_string())?;
    let header = json!({
        "alg": alg_name,
        "kid": signing_key.kid(),
        "typ": "JWT",
    });
    let header = serde_json::to_vec(&header).map_err(|err| err.to_string())?;
    let header = URL_SAFE_NO_PAD.encode(header);
    let payload = URL_SAFE_NO_PAD.encode(payload);
    let signing_input = format!("{header}.{payload}");
    let encoding_key = signing_key
        .local_encoding_key()
        .ok_or_else(|| "test signing key must be local".to_string())?;
    let signature = jsonwebtoken::crypto::sign(signing_input.as_bytes(), encoding_key, alg)
        .map_err(|err| err.to_string())?;
    Ok(format!("{signing_input}.{signature}"))
}

fn sign_upstream_id_token(
    signing_key: &crate::oidc::OidcSigningKey,
    request: &crate::upstream::UpstreamAuthRequest,
    access_token: &str,
    code: &str,
) -> Result<String, String> {
    let claims = crate::oidc::IdTokenBuilder::try_new(
        request.issuer.clone(),
        "subject-123".to_string(),
        request.client_id.clone(),
    )
    .map_err(|err| err.to_string())?
    .nonce(request.nonce.clone())
    .access_token_hash(
        access_token,
        crate::oidc::required_rs256::REQUIRED_SIGNING_ALG,
    )
    .map_err(|err| err.to_string())?
    .code_hash(code, crate::oidc::required_rs256::REQUIRED_SIGNING_ALG)
    .map_err(|err| err.to_string())?
    .build()
    .claims;
    crate::oidc::required_rs256::sign_required_id_token(&claims, signing_key)
        .map_err(|err| err.to_string())
}

fn use_raw_json_backend(
    surface: aegaeon_jose::raw_json::RawJsonSurface,
    backend: &str,
) -> EnvVarGuard {
    EnvVarGuard::new(
        aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(surface),
        Some(backend),
    )
}

fn use_jose_header_verified_structural_backend() -> EnvVarGuard {
    use_raw_json_backend(
        aegaeon_jose::raw_json::RawJsonSurface::JoseHeader,
        "verified-structural-v1",
    )
}

fn use_oidc_id_token_payload_verified_structural_backend() -> EnvVarGuard {
    use_raw_json_backend(
        aegaeon_jose::raw_json::RawJsonSurface::OidcIdTokenPayload,
        "verified-structural-v1",
    )
}

fn id_token_structure_parser_unavailable(token: &str) -> bool {
    matches!(
        ffi::id_token::check_id_token_jwt(token.as_bytes()),
        Err(ffi::id_token::IdTokenParserError::ParserUnavailable)
    )
}

#[path = "id_token/auth_material.rs"]
mod auth_material;
#[path = "id_token/decode.rs"]
mod decode;
#[path = "id_token/hint.rs"]
mod hint;
#[path = "id_token/selection.rs"]
mod selection;
#[path = "id_token/validation.rs"]
mod validation;
