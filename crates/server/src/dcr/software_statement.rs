use aegaeon_jose::jwt::{JwtClaims, ValidationContext};
use aegaeon_jose::raw_json::RawJsonSurface;
use serde_json::Value;
use std::collections::HashSet;
use std::fmt;
use std::time::Duration;

use super::registration::{
    apply_client_registration_field, client_registration_field_for_key, ClientRegistration,
    ClientRegistrationField, ClientRegistrationParseError,
};
use super::validation::SoftwareStatementValidationConfig;
use crate::util::{
    decode_compact_jwt_header_without_duplicate_keys_with_max_len,
    verify_signed_assertion_registered_claims, JsonObjectParseError, SignedAssertionClaimsError,
};

#[derive(Debug)]
pub struct SoftwareStatementProfileV1 {
    pub claims: JwtClaims,
    pub metadata: ClientRegistration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SoftwareStatementVerificationError {
    Invalid(String),
    BackendPolicy(&'static str),
}

impl SoftwareStatementVerificationError {
    fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }

    const fn backend_policy(surface: RawJsonSurface) -> Self {
        Self::BackendPolicy(surface.as_str())
    }
}

impl fmt::Display for SoftwareStatementVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => f.write_str(message),
            Self::BackendPolicy(surface) => {
                write!(f, "unsupported raw JSON backend for {surface}")
            }
        }
    }
}

impl std::error::Error for SoftwareStatementVerificationError {}

fn map_software_statement_metadata_error(err: ClientRegistrationParseError) -> String {
    match err {
        ClientRegistrationParseError::InvalidMetadata(message) => {
            format!("ssa metadata invalid: {message}")
        }
        ClientRegistrationParseError::PolicyViolation(_) => {
            "ssa metadata alias collision".to_string()
        }
        ClientRegistrationParseError::InvalidJson | ClientRegistrationParseError::Internal(_) => {
            "ssa metadata invalid".to_string()
        }
    }
}

fn decode_software_statement_metadata_profile_v1(
    claims: &JwtClaims,
) -> Result<ClientRegistration, SoftwareStatementVerificationError> {
    let metadata = claims
        .custom
        .as_object()
        .ok_or_else(|| SoftwareStatementVerificationError::invalid("ssa claims invalid"))?;
    let mut registration = ClientRegistration::default();
    let mut seen = HashSet::with_capacity(metadata.len());

    for (key, value) in metadata {
        let Some(field) = client_registration_field_for_key(key.as_str()) else {
            continue;
        };
        if field == ClientRegistrationField::SoftwareStatement {
            return Err(SoftwareStatementVerificationError::invalid(
                "ssa metadata invalid: nested software_statement is not allowed",
            ));
        }
        if !seen.insert(field) {
            return Err(SoftwareStatementVerificationError::invalid(
                "ssa metadata alias collision",
            ));
        }
        apply_client_registration_field(&mut registration, field, key, value)
            .map_err(map_software_statement_metadata_error)
            .map_err(SoftwareStatementVerificationError::invalid)?;
    }

    Ok(registration)
}

/// Verify a software statement assertion using an immutable validation snapshot.
///
/// # Errors
///
/// Returns an error when SSA verification is not configured, the compact JWT is malformed, the
/// signature check fails, validated claims violate local policy, or recognized metadata claims
/// violate the SSA Profile v1 typed subset.
pub fn verify_software_statement_profile_v1_with_config(
    ssa: &str,
    config: &SoftwareStatementValidationConfig,
) -> Result<SoftwareStatementProfileV1, SoftwareStatementVerificationError> {
    let claims = verify_software_statement_registered_claims(ssa, config)?;
    let metadata = decode_software_statement_metadata_profile_v1(&claims)?;
    Ok(SoftwareStatementProfileV1 { claims, metadata })
}

fn verify_software_statement_registered_claims(
    ssa: &str,
    config: &SoftwareStatementValidationConfig,
) -> Result<JwtClaims, SoftwareStatementVerificationError> {
    let pem = config.public_key_pem.as_deref().ok_or_else(|| {
        SoftwareStatementVerificationError::invalid("ssa verification not configured")
    })?;
    let header = decode_compact_jwt_header_without_duplicate_keys_with_max_len(
        ssa,
        config.jose_header_max_len,
    )
    .map_err(|err| match err {
        JsonObjectParseError::BackendPolicy => {
            SoftwareStatementVerificationError::backend_policy(RawJsonSurface::JoseHeader)
        }
        JsonObjectParseError::DuplicateKey
        | JsonObjectParseError::InvalidJson
        | JsonObjectParseError::TrailingBytes
        | JsonObjectParseError::InvalidShape => {
            SoftwareStatementVerificationError::invalid("bad ssa header")
        }
    })?;
    if header.alg != jsonwebtoken::Algorithm::RS256 {
        return Err(SoftwareStatementVerificationError::invalid(
            "unsupported ssa alg",
        ));
    }
    let key = jsonwebtoken::DecodingKey::from_rsa_pem(pem.as_bytes())
        .map_err(|_| SoftwareStatementVerificationError::invalid("bad ssa key"))?;
    let mut val = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    val.validate_exp = true;
    let claims = verify_signed_assertion_registered_claims(
        ssa,
        &key,
        &val,
        RawJsonSurface::SoftwareStatement,
    )
    .map_err(|err| match err {
        SignedAssertionClaimsError::VerificationFailed => {
            SoftwareStatementVerificationError::invalid("ssa verify failed")
        }
        SignedAssertionClaimsError::ClaimsInvalid => {
            SoftwareStatementVerificationError::invalid("ssa claims invalid")
        }
        SignedAssertionClaimsError::BackendPolicy => {
            SoftwareStatementVerificationError::backend_policy(RawJsonSurface::SoftwareStatement)
        }
    })?;

    let now = crate::util::now_unix_epoch_secs()
        .ok()
        .and_then(|secs| i64::try_from(secs).ok())
        .ok_or_else(|| SoftwareStatementVerificationError::invalid("time_error"))?;
    let mut ctx_builder = ValidationContext::builder()
        .now(now)
        .leeway(Duration::from_secs(config.leeway_secs))
        .require_exp(true);
    if let Some(issuer) = config.expected_issuer.as_deref() {
        ctx_builder = ctx_builder
            .expected_issuer(issuer.to_string())
            .require_issuer(true);
    }
    if let Some(aud) = config.expected_audience.as_deref() {
        ctx_builder = ctx_builder
            .allowed_audiences([aud.to_string()])
            .require_audience(true);
    }
    claims.validate(&ctx_builder.build()).map_err(|e| {
        SoftwareStatementVerificationError::invalid(format!("ssa claim validation failed: {e}"))
    })?;
    Ok(claims)
}

#[must_use]
pub fn software_statement_profile_redirect_uris(
    profile: &SoftwareStatementProfileV1,
) -> Option<Vec<String>> {
    profile.metadata.redirect_uris.clone()
}

fn metadata_field_conflict<T: PartialEq>(
    field: &'static str,
    registration: Option<&T>,
    statement: Option<&T>,
) -> Option<&'static str> {
    matches!((registration, statement), (Some(left), Some(right)) if left != right).then_some(field)
}

/// Check that recognized SSA metadata does not conflict with request metadata.
///
/// Unknown SSA extension claims remain outside the promoted profile claim and are intentionally not
/// compared here. Recognized DCR metadata fields are fail-closed when both the request body and the
/// signed software statement provide different values.
///
/// # Errors
///
/// Returns an error naming the first conflicting metadata field.
pub fn validate_software_statement_metadata_consistency(
    registration: &ClientRegistration,
    statement: &ClientRegistration,
) -> Result<(), String> {
    let conflict = [
        metadata_field_conflict(
            "client_id",
            registration.client_id.as_ref(),
            statement.client_id.as_ref(),
        ),
        metadata_field_conflict(
            "token_endpoint_auth_method",
            registration.token_endpoint_auth_method.as_ref(),
            statement.token_endpoint_auth_method.as_ref(),
        ),
        metadata_field_conflict(
            "token_endpoint_auth_signing_alg",
            registration.token_endpoint_auth_signing_alg.as_ref(),
            statement.token_endpoint_auth_signing_alg.as_ref(),
        ),
        metadata_field_conflict(
            "id_token_signed_response_alg",
            registration.id_token_signed_response_alg.as_ref(),
            statement.id_token_signed_response_alg.as_ref(),
        ),
        metadata_field_conflict(
            "redirect_uris",
            registration.redirect_uris.as_ref(),
            statement.redirect_uris.as_ref(),
        ),
        metadata_field_conflict(
            "post_logout_redirect_uris",
            registration.post_logout_redirect_uris.as_ref(),
            statement.post_logout_redirect_uris.as_ref(),
        ),
        metadata_field_conflict(
            "backchannel_logout_uri",
            registration.backchannel_logout_uri.as_ref(),
            statement.backchannel_logout_uri.as_ref(),
        ),
        metadata_field_conflict(
            "backchannel_logout_session_required",
            registration.backchannel_logout_session_required.as_ref(),
            statement.backchannel_logout_session_required.as_ref(),
        ),
        metadata_field_conflict(
            "jwks_uri",
            registration.jwks_uri.as_ref(),
            statement.jwks_uri.as_ref(),
        ),
        metadata_field_conflict("jwks", registration.jwks.as_ref(), statement.jwks.as_ref()),
        metadata_field_conflict(
            "grant_types",
            registration.grant_types.as_ref(),
            statement.grant_types.as_ref(),
        ),
        metadata_field_conflict(
            "response_types",
            registration.response_types.as_ref(),
            statement.response_types.as_ref(),
        ),
        metadata_field_conflict(
            "scope",
            registration.scope.as_ref(),
            statement.scope.as_ref(),
        ),
        metadata_field_conflict(
            "pkce_required",
            registration.pkce_required.as_ref(),
            statement.pkce_required.as_ref(),
        ),
        metadata_field_conflict(
            "require_sender_constrained_tokens",
            registration.require_sender_constrained_tokens.as_ref(),
            statement.require_sender_constrained_tokens.as_ref(),
        ),
        metadata_field_conflict(
            "sender_constrained_methods",
            registration.sender_constrained_methods.as_ref(),
            statement.sender_constrained_methods.as_ref(),
        ),
        metadata_field_conflict(
            "require_dpop",
            registration.require_dpop.as_ref(),
            statement.require_dpop.as_ref(),
        ),
        metadata_field_conflict(
            "require_mtls",
            registration.require_mtls.as_ref(),
            statement.require_mtls.as_ref(),
        ),
    ]
    .into_iter()
    .flatten()
    .next();

    match conflict {
        Some(field) => Err(format!(
            "software_statement metadata conflicts with {field}"
        )),
        None => Ok(()),
    }
}

/// Extract software statement redirect URIs from extension claims.
///
/// The registered JWT claims remain typed in [`JwtClaims`]; software statement
/// metadata stays isolated in the `custom` object.
///
/// # Errors
///
/// Returns an error when the custom-claim bag is not an object or
/// `redirect_uris` is present with a non-array / non-string shape.
pub fn software_statement_redirect_uris(claims: &JwtClaims) -> Result<Option<Vec<String>>, String> {
    let metadata = claims
        .custom
        .as_object()
        .ok_or_else(|| "ssa claims invalid".to_string())?;

    match metadata.get("redirect_uris") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(uris)) => {
            let mut redirect_uris = Vec::with_capacity(uris.len());
            for uri in uris {
                let uri = uri
                    .as_str()
                    .ok_or_else(|| "ssa redirect_uris must be an array of strings".to_string())?;
                redirect_uris.push(uri.to_string());
            }
            Ok(Some(redirect_uris))
        }
        Some(_) => Err("ssa redirect_uris must be an array of strings".to_string()),
    }
}
