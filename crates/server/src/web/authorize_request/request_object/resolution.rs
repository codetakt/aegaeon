use aegaeon_jose::RequestObjectError;

use crate::client_registry::RequestObjectValidationError;

use super::claims::{
    require_request_object_field, validate_request_object_authorization_details,
    validate_request_object_client_id, validate_request_object_resource,
};
use super::error::RequestObjectResolutionError;
use super::replay::apply_request_object_replay_policy;
use super::types::{
    OwnedRequestObjectAuthorizeDeps, RequestObjectAuthorizeDeps, RequestObjectReplayPolicy,
    ResolvedAuthorizeRequestObject,
};

pub(in crate::web) fn resolve_authorize_request_object(
    deps: &RequestObjectAuthorizeDeps<'_>,
    client_id: &str,
    request_jwt: &str,
    authorize_audience: &str,
    supported_authorization_details: &[String],
    replay_policy: RequestObjectReplayPolicy,
) -> Result<ResolvedAuthorizeRequestObject, RequestObjectResolutionError> {
    let request_jwt_for_verification =
        crate::request_object::normalize_request_object_for_verification(
            request_jwt,
            deps.request_object_decryption_key_pkcs8_der,
            deps.jose_header_max_len,
        )
        .map_err(|err| {
            RequestObjectResolutionError::invalid_request(format!(
                "request object envelope validation failed: {err}"
            ))
        })?;

    let claims = deps
        .clients
        .verify_request_object(
            client_id,
            &request_jwt_for_verification,
            authorize_audience,
            deps.crypto_profile,
        )
        .map_err(|err| request_object_validation_error_to_resolution_error(&err))?
        .claims;

    validate_request_object_client_id(&claims, client_id)?;
    apply_request_object_replay_policy(deps, client_id, &claims, replay_policy)?;

    let redirect_uri = require_request_object_field(claims.redirect_uri.as_ref(), "redirect_uri")?;
    let response_type =
        require_request_object_field(claims.response_type.as_ref(), "response_type")?;
    let scope = require_request_object_field(claims.scope.as_ref(), "scope")?;
    let code_challenge =
        require_request_object_field(claims.code_challenge.as_ref(), "code_challenge")?;
    let code_challenge_method = require_request_object_field(
        claims.code_challenge_method.as_ref(),
        "code_challenge_method",
    )?;

    crate::request_object::everparse_self_check_request_object_claims_with_runtime(
        &claims,
        authorize_audience,
        deps.request_object_everparse_runtime_enabled,
    )
    .map_err(|err| {
        RequestObjectResolutionError::invalid_request(format!(
            "request object everparse self-check failed: {err}"
        ))
    })?;

    let authorization_details =
        validate_request_object_authorization_details(&claims, supported_authorization_details)?;
    let resource = validate_request_object_resource(&claims)?;

    Ok(ResolvedAuthorizeRequestObject {
        redirect_uri,
        response_type,
        scope,
        state: claims.state.clone(),
        nonce: claims.nonce.clone(),
        acr_values: claims.acr_values.clone(),
        max_age: claims.max_age,
        code_challenge,
        code_challenge_method,
        resource,
        authorization_details,
        request_object: request_jwt.to_string(),
        request_object_claims: claims,
    })
}

pub(in crate::web) async fn resolve_authorize_request_object_blocking(
    deps: OwnedRequestObjectAuthorizeDeps,
    client_id: String,
    request_jwt: String,
    authorize_audience: String,
    supported_authorization_details: Vec<String>,
    replay_policy: RequestObjectReplayPolicy,
) -> Result<ResolvedAuthorizeRequestObject, RequestObjectResolutionError> {
    tokio::task::spawn_blocking(move || {
        let deps = deps.as_borrowed();
        resolve_authorize_request_object(
            &deps,
            &client_id,
            &request_jwt,
            &authorize_audience,
            &supported_authorization_details,
            replay_policy,
        )
    })
    .await
    .map_err(|_| RequestObjectResolutionError::internal_error("request object worker failed"))?
}

fn request_object_validation_error_to_resolution_error(
    err: &RequestObjectValidationError,
) -> RequestObjectResolutionError {
    match err {
        RequestObjectValidationError::Jose(RequestObjectError::Internal(msg)) => {
            RequestObjectResolutionError::internal_error(msg.clone())
        }
        _ => RequestObjectResolutionError::invalid_request(format!(
            "request object validation failed: {err}"
        )),
    }
}
