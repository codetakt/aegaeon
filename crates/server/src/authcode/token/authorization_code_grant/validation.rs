use super::super::{scope_contains, validate_optional_resource_indicator, verify_pkce};
use super::error::{TokenGrantError, TokenGrantErrorCode};
use crate::authcode::types::{AuthorizationCode, TokenRequest};
use aegaeon_jose::RequestObjectClaims;

pub(super) struct ValidatedCodeGrantRequest {
    pub(super) selected_resource: Option<String>,
    pub(super) openid_requested: bool,
}

pub(super) fn validate_code_grant_request(
    req: &TokenRequest,
    code: &AuthorizationCode,
    authorization_code_grant_allowed: bool,
    oidc_enabled: bool,
) -> Result<ValidatedCodeGrantRequest, TokenGrantError> {
    let selected_resource =
        select_authorized_resource(code.resource.as_deref(), req.resource.as_deref())?;
    validate_request_object_binding(
        req.request_object_claims.as_ref(),
        &code.client_id,
        code.redirect_uri.as_deref(),
    )?;
    validate_client_grant(
        &req.client_id,
        &code.client_id,
        authorization_code_grant_allowed,
    )?;
    validate_redirect_uri(req.redirect_uri.as_deref(), code.redirect_uri.as_deref())?;
    validate_pkce_binding(
        req.code_verifier.as_deref(),
        code.code_challenge.as_deref(),
        code.code_challenge_method.as_deref(),
    )?;
    let openid_requested = validate_openid_scope(code.scope.as_deref(), oidc_enabled)?;

    Ok(ValidatedCodeGrantRequest {
        selected_resource,
        openid_requested,
    })
}

pub(super) fn select_authorized_resource(
    stored_resource: Option<&str>,
    requested_resource: Option<&str>,
) -> Result<Option<String>, TokenGrantError> {
    let stored = validate_optional_resource_indicator(stored_resource).map_err(|err| {
        error(
            TokenGrantErrorCode::InvalidTarget,
            format!("stored resource invalid: {err}"),
        )
    })?;
    let requested = validate_optional_resource_indicator(requested_resource)
        .map_err(|err| error(TokenGrantErrorCode::InvalidTarget, err))?;

    match (&stored, &requested) {
        (Some(grant), Some(requested)) if grant != requested => Err(error(
            TokenGrantErrorCode::InvalidTarget,
            "requested resource is not permitted by the grant",
        )),
        _ => Ok(requested.or(stored)),
    }
}

pub(super) fn validate_request_object_binding(
    claims: Option<&RequestObjectClaims>,
    stored_client_id: &str,
    stored_redirect_uri: Option<&str>,
) -> Result<(), TokenGrantError> {
    let Some(claims) = claims else {
        return Ok(());
    };

    if claims
        .client_id
        .as_ref()
        .is_some_and(|claim_client_id| claim_client_id != stored_client_id)
    {
        return Err(error(
            TokenGrantErrorCode::InvalidGrant,
            "Request Object client_id mismatch",
        ));
    }
    if claims
        .redirect_uri
        .as_ref()
        .is_some_and(|claim_redirect_uri| Some(claim_redirect_uri.as_str()) != stored_redirect_uri)
    {
        return Err(error(
            TokenGrantErrorCode::InvalidGrant,
            "Request Object redirect_uri mismatch",
        ));
    }

    Ok(())
}

pub(super) fn validate_client_grant(
    client_id: &str,
    stored_client_id: &str,
    authorization_code_grant_allowed: bool,
) -> Result<(), TokenGrantError> {
    if client_id != stored_client_id {
        return Err(error(TokenGrantErrorCode::InvalidClient, "Client mismatch"));
    }
    if !authorization_code_grant_allowed {
        return Err(error(
            TokenGrantErrorCode::UnauthorizedClient,
            "client is not allowed to use authorization_code grant",
        ));
    }
    Ok(())
}

pub(super) fn validate_redirect_uri(
    request_redirect_uri: Option<&str>,
    stored_redirect_uri: Option<&str>,
) -> Result<(), TokenGrantError> {
    if request_redirect_uri == stored_redirect_uri {
        Ok(())
    } else {
        Err(error(
            TokenGrantErrorCode::InvalidGrant,
            "Redirect URI mismatch",
        ))
    }
}

pub(super) fn validate_pkce_binding(
    verifier: Option<&str>,
    challenge: Option<&str>,
    challenge_method: Option<&str>,
) -> Result<(), TokenGrantError> {
    let Some(challenge) = challenge else {
        return Ok(());
    };
    if challenge_method != Some("S256") {
        return Err(error(
            TokenGrantErrorCode::InvalidGrant,
            "Unsupported PKCE method",
        ));
    }

    match verifier {
        Some(verifier) if verify_pkce(verifier, challenge) => Ok(()),
        Some(_) => Err(error(
            TokenGrantErrorCode::InvalidGrant,
            "PKCE verification failed",
        )),
        None => Err(error(
            TokenGrantErrorCode::InvalidGrant,
            "PKCE verifier missing",
        )),
    }
}

pub(super) fn validate_openid_scope(
    scope: Option<&str>,
    oidc_enabled: bool,
) -> Result<bool, TokenGrantError> {
    let openid_requested = scope_contains(scope, "openid");
    if openid_requested && !oidc_enabled {
        Err(error(
            TokenGrantErrorCode::InvalidScope,
            "openid scope is not enabled for this server",
        ))
    } else {
        Ok(openid_requested)
    }
}

fn error(code: TokenGrantErrorCode, description: impl Into<String>) -> TokenGrantError {
    TokenGrantError::described(code, description)
}
