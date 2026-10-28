use super::super::RESOURCE_SCOPES;
use super::outcome::{
    map_policy_error, resource_error_with_mode, resource_internal_error_with_mode,
    resource_success, ResourceOutcome,
};
use super::sender::ResourceSenderContext;
use axum::http::StatusCode;

use crate::authcode::types::{BearerTokenMeta, SenderBinding};
use crate::authcode::{TokenPolicyContext, TokenValidator};
use crate::middleware::DpopBinding;

pub(super) fn admit_resource_authorization<'a>(
    auth_header: Option<&'a str>,
    issuer_base: &str,
) -> Result<crate::resource_authentication::ResourceCredentials<'a>, ResourceOutcome> {
    use crate::resource_authentication::{classify_resource_presentation, ResourcePresentation};
    let reason = match classify_resource_presentation(auth_header) {
        ResourcePresentation::Missing if auth_header.is_none() => "authorization header required",
        ResourcePresentation::Missing | ResourcePresentation::Malformed(_) => {
            "malformed authorization header"
        }
        ResourcePresentation::Unsupported => "authorization scheme must be Bearer or DPoP",
        ResourcePresentation::Credentials(credentials) => return Ok(credentials),
    };
    match super::super::resource_authentication::admit_resource_presentation(
        auth_header,
        issuer_base,
    ) {
        Ok(credentials) => Ok(credentials),
        Err(response) => Err(ResourceOutcome::early_presentation_failure(
            response, reason,
        )),
    }
}

async fn validate_resource_bearer_metadata(
    validator: &TokenValidator,
    normalized_auth: String,
    issuer_base: &str,
    mode_hint: &str,
) -> Result<BearerTokenMeta, ResourceOutcome> {
    let (_, meta_opt) = match validator
        .validate_bearer_token_with_meta_async(normalized_auth)
        .await
    {
        Ok(result) => result,
        Err(err) => {
            if err.is_internal() {
                tracing::error!(
                    target: "oauth",
                    error = %err,
                    "resource bearer token validation failed internally"
                );
                return Err(resource_internal_error_with_mode(
                    issuer_base,
                    err.public_description(),
                    mode_hint.to_string(),
                ));
            }
            return Err(resource_error_with_mode(
                issuer_base,
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                &err.to_string(),
                mode_hint.to_string(),
            ));
        }
    };

    meta_opt.ok_or_else(|| {
        resource_error_with_mode(
            issuer_base,
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "bearer token metadata unavailable",
            mode_hint.to_string(),
        )
    })
}

fn resource_mode(meta: &BearerTokenMeta, sender: &ResourceSenderContext<'_>) -> String {
    match &meta.sender_binding {
        Some(SenderBinding::DPoP { .. }) => "dpop".to_string(),
        Some(SenderBinding::Mtls { .. }) => "mtls".to_string(),
        None => sender.mode_hint.clone(),
    }
}

async fn enforce_resource_policy(
    validator: &TokenValidator,
    normalized_auth: &str,
    meta_preview: &BearerTokenMeta,
    sender: &ResourceSenderContext<'_>,
    issuer_base: &str,
) -> ResourceOutcome {
    let mode = resource_mode(meta_preview, sender);
    let resource_audience = crate::resource_audience::protected_resource(issuer_base);
    let context = TokenPolicyContext {
        requested_scopes: &RESOURCE_SCOPES,
        resource_audience: Some(resource_audience.as_str()),
        sender_dpop_jkt: sender.binding_jkt,
        sender_mtls_fingerprint: sender.mtls_ref(),
    };

    if meta_preview.refresh_parent.is_some() {
        match validator
            .validate_with_policy_async(normalized_auth.to_string(), context)
            .await
        {
            Ok((_, meta)) => resource_success(&meta, issuer_base, mode),
            Err(err) => map_policy_error(&err, issuer_base, mode),
        }
    } else {
        match validator
            .enforce_with_meta_async(meta_preview, context)
            .await
        {
            Ok(()) => resource_success(meta_preview, issuer_base, mode),
            Err(err) => map_policy_error(&err, issuer_base, mode),
        }
    }
}

pub(in crate::web) async fn process_resource_request(
    validator: &TokenValidator,
    auth_header: Option<String>,
    binding: Option<&DpopBinding>,
    mtls_fingerprint: Option<&str>,
    issuer_base: &str,
) -> ResourceOutcome {
    let credentials = match admit_resource_authorization(auth_header.as_deref(), issuer_base) {
        Ok(credentials) => credentials,
        Err(outcome) => return outcome,
    };
    let dpop_scheme = credentials.scheme == crate::resource_authentication::ResourceScheme::Dpop;
    let normalized_auth = credentials.normalized_authorization();
    let sender = ResourceSenderContext::from_request(binding, mtls_fingerprint);
    let meta_preview = match validate_resource_bearer_metadata(
        validator,
        normalized_auth.clone(),
        issuer_base,
        sender.mode_hint.as_str(),
    )
    .await
    {
        Ok(meta) => meta,
        Err(outcome) => return outcome.with_presentation(credentials.scheme),
    };
    if matches!(
        meta_preview.sender_binding,
        Some(SenderBinding::DPoP { .. })
    ) != dpop_scheme
    {
        return resource_error_with_mode(
            issuer_base,
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "authorization scheme does not match the token binding",
            if dpop_scheme { "dpop" } else { "bearer" }.into(),
        );
    }
    enforce_resource_policy(
        validator,
        &normalized_auth,
        &meta_preview,
        &sender,
        issuer_base,
    )
    .await
    .with_presentation(credentials.scheme)
}
