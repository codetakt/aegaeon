use aegaeon_jose::raw_json::{self, RawJsonObjectError, RawJsonSurface};
use serde_json::Value;
use std::collections::HashSet;
use std::fmt;

#[derive(serde::Deserialize, Clone, Debug, Default)]
pub struct ClientRegistration {
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    pub token_endpoint_auth_signing_alg: Option<String>,
    #[serde(default)]
    pub id_token_signed_response_alg: Option<String>,
    #[serde(default)]
    pub redirect_uris: Option<Vec<String>>,
    #[serde(default)]
    pub post_logout_redirect_uris: Option<Vec<String>>,
    #[serde(default)]
    pub backchannel_logout_uri: Option<String>,
    #[serde(default)]
    pub backchannel_logout_session_required: Option<bool>,
    #[serde(default)]
    pub jwks_uri: Option<String>,
    #[serde(default)]
    pub jwks: Option<Value>,
    #[serde(default)]
    pub software_statement: Option<String>,
    #[serde(default)]
    pub grant_types: Option<Vec<String>>,
    #[serde(default)]
    pub response_types: Option<Vec<String>>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default, alias = "require_pkce", alias = "oauth_pkce_required")]
    pub pkce_required: Option<bool>,
    #[serde(
        default,
        alias = "require_sender_constrained_tokens",
        alias = "sender_constrained_tokens",
        alias = "tls_client_certificate_bound_access_tokens"
    )]
    pub require_sender_constrained_tokens: Option<bool>,
    #[serde(default, alias = "sender_constrained_token_methods")]
    pub sender_constrained_methods: Option<Vec<String>>,
    #[serde(default, alias = "dpop_required", alias = "dpop_bound_access_tokens")]
    pub require_dpop: Option<bool>,
    #[serde(default, alias = "mtls_required", alias = "mtls_bound_access_tokens")]
    pub require_mtls: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientRegistrationParseError {
    InvalidJson,
    InvalidMetadata(String),
    PolicyViolation(String),
    Internal(String),
}

impl fmt::Display for ClientRegistrationParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientRegistrationParseError::InvalidJson => f.write_str("invalid json body"),
            ClientRegistrationParseError::InvalidMetadata(msg)
            | ClientRegistrationParseError::PolicyViolation(msg)
            | ClientRegistrationParseError::Internal(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for ClientRegistrationParseError {}

#[must_use]
pub fn empty_client_registration() -> ClientRegistration {
    ClientRegistration::default()
}

fn map_raw_json_object_error(err: RawJsonObjectError) -> ClientRegistrationParseError {
    match err {
        RawJsonObjectError::InvalidBackendPolicy(err) => {
            ClientRegistrationParseError::Internal(err.to_string())
        }
        RawJsonObjectError::DuplicateKey => {
            ClientRegistrationParseError::PolicyViolation("duplicate-key".to_string())
        }
        RawJsonObjectError::InvalidJson(_)
        | RawJsonObjectError::TrailingBytes(_)
        | RawJsonObjectError::InvalidShape(_) => ClientRegistrationParseError::InvalidJson,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum ClientRegistrationField {
    ClientId,
    TokenEndpointAuthMethod,
    TokenEndpointAuthSigningAlg,
    IdTokenSignedResponseAlg,
    RedirectUris,
    PostLogoutRedirectUris,
    BackchannelLogoutUri,
    BackchannelLogoutSessionRequired,
    JwksUri,
    Jwks,
    SoftwareStatement,
    GrantTypes,
    ResponseTypes,
    Scope,
    PkceRequired,
    RequireSenderConstrainedTokens,
    SenderConstrainedMethods,
    RequireDpop,
    RequireMtls,
}

pub(super) fn client_registration_field_for_key(key: &str) -> Option<ClientRegistrationField> {
    match key {
        "client_id" => Some(ClientRegistrationField::ClientId),
        "token_endpoint_auth_method" => Some(ClientRegistrationField::TokenEndpointAuthMethod),
        "token_endpoint_auth_signing_alg" => {
            Some(ClientRegistrationField::TokenEndpointAuthSigningAlg)
        }
        "id_token_signed_response_alg" => Some(ClientRegistrationField::IdTokenSignedResponseAlg),
        "redirect_uris" => Some(ClientRegistrationField::RedirectUris),
        "post_logout_redirect_uris" => Some(ClientRegistrationField::PostLogoutRedirectUris),
        "backchannel_logout_uri" => Some(ClientRegistrationField::BackchannelLogoutUri),
        "backchannel_logout_session_required" => {
            Some(ClientRegistrationField::BackchannelLogoutSessionRequired)
        }
        "jwks_uri" => Some(ClientRegistrationField::JwksUri),
        "jwks" => Some(ClientRegistrationField::Jwks),
        "software_statement" => Some(ClientRegistrationField::SoftwareStatement),
        "grant_types" => Some(ClientRegistrationField::GrantTypes),
        "response_types" => Some(ClientRegistrationField::ResponseTypes),
        "scope" => Some(ClientRegistrationField::Scope),
        "pkce_required" | "require_pkce" | "oauth_pkce_required" => {
            Some(ClientRegistrationField::PkceRequired)
        }
        "require_sender_constrained_tokens"
        | "sender_constrained_tokens"
        | "tls_client_certificate_bound_access_tokens" => {
            Some(ClientRegistrationField::RequireSenderConstrainedTokens)
        }
        "sender_constrained_methods" | "sender_constrained_token_methods" => {
            Some(ClientRegistrationField::SenderConstrainedMethods)
        }
        "require_dpop" | "dpop_required" | "dpop_bound_access_tokens" => {
            Some(ClientRegistrationField::RequireDpop)
        }
        "require_mtls" | "mtls_required" | "mtls_bound_access_tokens" => {
            Some(ClientRegistrationField::RequireMtls)
        }
        _ => None,
    }
}

fn invalid_client_registration_claim_type(
    key: &str,
    expected: &str,
) -> ClientRegistrationParseError {
    ClientRegistrationParseError::InvalidMetadata(format!(
        "malformed metadata: `{key}` must be {expected}"
    ))
}

fn parse_client_registration_members_raw(
    bytes: &[u8],
) -> Result<Vec<raw_json::RawJsonObjectMember>, ClientRegistrationParseError> {
    let report = raw_json::parse_json_object_members_with_report_for_surface(
        RawJsonSurface::ClientRegistration,
        bytes,
    )
    .map_err(map_raw_json_object_error)?;
    raw_json::ensure_unique_object_keys(&report.value).map_err(map_raw_json_object_error)?;
    Ok(report.value)
}

fn parse_optional_registration_string(
    key: &str,
    value: &Value,
) -> Result<Option<String>, ClientRegistrationParseError> {
    match value {
        Value::Null => Ok(None),
        Value::String(value) => Ok(Some(value.clone())),
        _ => Err(invalid_client_registration_claim_type(
            key,
            "a string or null",
        )),
    }
}

fn parse_optional_registration_bool(
    key: &str,
    value: &Value,
) -> Result<Option<bool>, ClientRegistrationParseError> {
    match value {
        Value::Null => Ok(None),
        Value::Bool(value) => Ok(Some(*value)),
        _ => Err(invalid_client_registration_claim_type(
            key,
            "a boolean or null",
        )),
    }
}

fn parse_optional_registration_string_vec(
    key: &str,
    value: &Value,
) -> Result<Option<Vec<String>>, ClientRegistrationParseError> {
    match value {
        Value::Null => Ok(None),
        Value::Array(values) => {
            let mut parsed = Vec::with_capacity(values.len());
            for value in values {
                let Value::String(value) = value else {
                    return Err(invalid_client_registration_claim_type(
                        key,
                        "an array of strings or null",
                    ));
                };
                parsed.push(value.clone());
            }
            Ok(Some(parsed))
        }
        _ => Err(invalid_client_registration_claim_type(
            key,
            "an array of strings or null",
        )),
    }
}

fn parse_optional_registration_open_json(value: &Value) -> Option<Value> {
    if value.is_null() {
        None
    } else {
        Some(value.clone())
    }
}

pub(super) fn apply_client_registration_field(
    registration: &mut ClientRegistration,
    field: ClientRegistrationField,
    key: &str,
    value: &Value,
) -> Result<(), ClientRegistrationParseError> {
    match field {
        ClientRegistrationField::ClientId => {
            registration.client_id = parse_optional_registration_string(key, value)?;
        }
        ClientRegistrationField::TokenEndpointAuthMethod => {
            registration.token_endpoint_auth_method =
                parse_optional_registration_string(key, value)?;
        }
        ClientRegistrationField::TokenEndpointAuthSigningAlg => {
            registration.token_endpoint_auth_signing_alg =
                parse_optional_registration_string(key, value)?;
        }
        ClientRegistrationField::IdTokenSignedResponseAlg => {
            registration.id_token_signed_response_alg =
                parse_optional_registration_string(key, value)?;
        }
        ClientRegistrationField::RedirectUris => {
            registration.redirect_uris = parse_optional_registration_string_vec(key, value)?;
        }
        ClientRegistrationField::PostLogoutRedirectUris => {
            registration.post_logout_redirect_uris =
                parse_optional_registration_string_vec(key, value)?;
        }
        ClientRegistrationField::BackchannelLogoutUri => {
            registration.backchannel_logout_uri = parse_optional_registration_string(key, value)?;
        }
        ClientRegistrationField::BackchannelLogoutSessionRequired => {
            registration.backchannel_logout_session_required =
                parse_optional_registration_bool(key, value)?;
        }
        ClientRegistrationField::JwksUri => {
            registration.jwks_uri = parse_optional_registration_string(key, value)?;
        }
        ClientRegistrationField::Jwks => {
            registration.jwks = parse_optional_registration_open_json(value);
        }
        ClientRegistrationField::SoftwareStatement => {
            registration.software_statement = parse_optional_registration_string(key, value)?;
        }
        ClientRegistrationField::GrantTypes => {
            registration.grant_types = parse_optional_registration_string_vec(key, value)?;
        }
        ClientRegistrationField::ResponseTypes => {
            registration.response_types = parse_optional_registration_string_vec(key, value)?;
        }
        ClientRegistrationField::Scope => {
            registration.scope = parse_optional_registration_string(key, value)?;
        }
        ClientRegistrationField::PkceRequired => {
            registration.pkce_required = parse_optional_registration_bool(key, value)?;
        }
        ClientRegistrationField::RequireSenderConstrainedTokens => {
            registration.require_sender_constrained_tokens =
                parse_optional_registration_bool(key, value)?;
        }
        ClientRegistrationField::SenderConstrainedMethods => {
            registration.sender_constrained_methods =
                parse_optional_registration_string_vec(key, value)?;
        }
        ClientRegistrationField::RequireDpop => {
            registration.require_dpop = parse_optional_registration_bool(key, value)?;
        }
        ClientRegistrationField::RequireMtls => {
            registration.require_mtls = parse_optional_registration_bool(key, value)?;
        }
    }
    Ok(())
}

fn decode_client_registration_from_members(
    members: &[raw_json::RawJsonObjectMember],
) -> Result<ClientRegistration, ClientRegistrationParseError> {
    let mut registration = ClientRegistration::default();
    let mut seen = HashSet::with_capacity(members.len());

    for member in members {
        let Some(field) = client_registration_field_for_key(member.key.as_str()) else {
            continue;
        };
        if !seen.insert(field) {
            return Err(ClientRegistrationParseError::PolicyViolation(
                "duplicate-key".to_string(),
            ));
        }

        apply_client_registration_field(
            &mut registration,
            field,
            member.key.as_str(),
            &member.value,
        )?;
    }

    Ok(registration)
}

/// Parse a client registration document while rejecting duplicate JSON object keys
/// and decoding recognized metadata fields without whole-object materialization.
///
/// # Errors
///
/// Returns an error when raw JSON policy gating fails, the body is malformed, or duplicate keys
/// violate DCR admission rules.
pub fn parse_client_registration(
    bytes: &[u8],
) -> Result<ClientRegistration, ClientRegistrationParseError> {
    let members = parse_client_registration_members_raw(bytes)?;
    decode_client_registration_from_members(&members)
}
