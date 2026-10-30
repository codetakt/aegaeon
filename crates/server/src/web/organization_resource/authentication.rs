use super::*;

/// Primary Organizations authority must still be checked in the consuming transaction.
pub(super) async fn authenticate(
    state: &AppState,
    admission: &ResourceAdmission,
    parts: axum::http::request::Parts,
) -> Result<BearerTokenMeta, Response> {
    for_audience(
        state,
        admission,
        parts,
        &format!("{}/organizations", state.issuer),
    )
    .await
}

pub(super) async fn for_audience(
    state: &AppState,
    admission: &ResourceAdmission,
    parts: axum::http::request::Parts,
    audience: &str,
) -> Result<BearerTokenMeta, Response> {
    let authorization = oauth_errors::authorization_header(&parts.headers)
        .map_err(|_| error(state, StatusCode::BAD_REQUEST, "invalid_request"))?;
    let credentials = crate::web::resource_authentication::admit_resource_presentation(
        authorization,
        state.issuer.as_str(),
    )
    .map_err(|response| {
        error(
            state,
            response.status(),
            if response.status() == StatusCode::BAD_REQUEST {
                "invalid_request"
            } else {
                "invalid_token"
            },
        )
    })?;
    if credentials.scheme != ResourceScheme::Dpop {
        return Err(error(state, StatusCode::UNAUTHORIZED, "invalid_token"));
    }
    let authorization = credentials.normalized_authorization();
    let proof = verify_proof(state, admission, parts).await?;
    let (access, meta) = state
        .tokens
        .validator
        .validate_bearer_token_with_meta_async(authorization)
        .await
        .map_err(|failure| {
            if failure.is_internal() {
                unavailable(state)
            } else {
                error(state, StatusCode::UNAUTHORIZED, "invalid_token")
            }
        })?;
    let meta = meta.ok_or_else(|| error(state, StatusCode::UNAUTHORIZED, "invalid_token"))?;
    crate::authcode::store::bearer_metadata_matches_access_token(&access, &meta)
        .map_err(|_| error(state, StatusCode::UNAUTHORIZED, "invalid_token"))?;
    state
        .tokens
        .validator
        .validate_stored_access_token_jwt(&access, Some(&meta))
        .map_err(|failure| {
            if failure.is_internal() {
                unavailable(state)
            } else {
                error(state, StatusCode::UNAUTHORIZED, "invalid_token")
            }
        })?;
    let sender_matches = matches!(&meta.sender_binding, Some(SenderBinding::DPoP { jkt })
        if crate::util::jwk_thumbprint_matches(jkt, &proof.jkt));
    if !sender_matches
        || meta.audience != audience
        || meta.application_grant.is_some()
        || meta.client_credentials_grant.is_some()
    {
        return Err(error(state, StatusCode::UNAUTHORIZED, "invalid_token"));
    }
    Ok(meta)
}
