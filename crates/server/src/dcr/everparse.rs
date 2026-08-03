use ffi::dcr_parser::{self, DcrParseError};
use std::fmt;

use super::registration::ClientRegistration;
use super::{JWT_BEARER_GRANT_TYPE, TOKEN_EXCHANGE_GRANT_TYPE};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DcrEverparseSelfCheckError {
    Encode(String),
    ParserUnavailable,
    BufferTooLarge,
    InvalidPayload,
}

impl fmt::Display for DcrEverparseSelfCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DcrEverparseSelfCheckError::Encode(msg) => write!(f, "encode error: {msg}"),
            DcrEverparseSelfCheckError::ParserUnavailable => {
                f.write_str("everparse DCR parser unavailable in this build")
            }
            DcrEverparseSelfCheckError::BufferTooLarge => {
                f.write_str("everparse DCR buffer exceeds u32 length")
            }
            DcrEverparseSelfCheckError::InvalidPayload => {
                f.write_str("everparse DCR self-check rejected canonical buffer")
            }
        }
    }
}

impl std::error::Error for DcrEverparseSelfCheckError {}

pub(super) fn should_run_dcr_everparse_self_check(runtime_enabled: bool) -> bool {
    runtime_enabled || cfg!(feature = "verified-claim")
}

pub(super) fn finalize_dcr_everparse_self_check(
    required: bool,
    parser_result: Result<(), DcrParseError>,
) -> Result<(), DcrEverparseSelfCheckError> {
    if !required {
        return Ok(());
    }

    match parser_result {
        Ok(()) => Ok(()),
        Err(DcrParseError::ParserUnavailable) => Err(DcrEverparseSelfCheckError::ParserUnavailable),
        Err(DcrParseError::BufferTooLarge) => Err(DcrEverparseSelfCheckError::BufferTooLarge),
        Err(DcrParseError::InvalidPayload) => Err(DcrEverparseSelfCheckError::InvalidPayload),
    }
}

fn push_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

fn push_u32_le(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_bytes_with_u32_len(
    out: &mut Vec<u8>,
    bytes: &[u8],
) -> Result<(), DcrEverparseSelfCheckError> {
    let len = u32::try_from(bytes.len()).map_err(|_| DcrEverparseSelfCheckError::BufferTooLarge)?;
    push_u32_le(out, len);
    out.extend_from_slice(bytes);
    Ok(())
}

fn optional_bytes(
    out: &mut Vec<u8>,
    bytes: Option<&[u8]>,
) -> Result<(), DcrEverparseSelfCheckError> {
    match bytes {
        Some(value) if !value.is_empty() => {
            push_u8(out, 1);
            push_bytes_with_u32_len(out, value)?;
        }
        _ => {
            push_u8(out, 0);
            push_u32_le(out, 0);
        }
    }
    Ok(())
}

fn nul_separated_utf8(
    values: &[String],
    label: &'static str,
) -> Result<Vec<u8>, DcrEverparseSelfCheckError> {
    let mut out = Vec::new();
    for (idx, value) in values.iter().enumerate() {
        if value.as_bytes().contains(&0) {
            return Err(DcrEverparseSelfCheckError::Encode(format!(
                "{label} contains NUL byte"
            )));
        }
        if idx > 0 {
            out.push(0);
        }
        out.extend_from_slice(value.as_bytes());
    }
    Ok(out)
}

fn token_auth_method_tag(method: &str) -> u32 {
    match method {
        "client_secret_basic" => 1,
        "client_secret_post" => 2,
        "private_key_jwt" => 3,
        "tls_client_auth" => 4,
        "self_signed_tls_client_auth" => 5,
        _ => 0,
    }
}

fn grant_type_bit(grant: &str) -> Result<u32, DcrEverparseSelfCheckError> {
    match grant {
        "authorization_code" => Ok(0x1),
        "refresh_token" => Ok(0x2),
        "client_credentials" => Ok(0x4),
        JWT_BEARER_GRANT_TYPE => Ok(0x8),
        TOKEN_EXCHANGE_GRANT_TYPE => Ok(0x10),
        other => Err(DcrEverparseSelfCheckError::Encode(format!(
            "unsupported grant_type for EverParse encoding: {other}"
        ))),
    }
}

fn grant_types_mask(grants: &[String]) -> Result<u32, DcrEverparseSelfCheckError> {
    grants
        .iter()
        .try_fold(0u32, |mask, grant| Ok(mask | grant_type_bit(grant)?))
}

fn response_type_bit(response: &str) -> Result<u32, DcrEverparseSelfCheckError> {
    match response {
        "code" => Ok(0x1),
        "token" => Ok(0x2),
        other => Err(DcrEverparseSelfCheckError::Encode(format!(
            "unsupported response_type for EverParse encoding: {other}"
        ))),
    }
}

fn response_types_mask(responses: &[String]) -> Result<u32, DcrEverparseSelfCheckError> {
    responses.iter().try_fold(0u32, |mask, response| {
        Ok(mask | response_type_bit(response)?)
    })
}

/// Optional defense-in-depth: encode the already-parsed metadata into the
/// `EverParse` DCR binary schema and validate it.
///
/// Notes:
/// - This does **not** validate raw RFC 7591 JSON input. It validates a
///   canonical binary encoding derived from Rust-decoded fields.
/// - Enabled by the caller's database-backed runtime policy snapshot, and mandatory in the
///   `verified-claim` profile.
///
/// # Errors
///
/// Returns an error when canonical encoding fails or the `EverParse` self-check rejects the
/// resulting payload.
pub fn everparse_self_check_registration_with_runtime(
    meta: &ClientRegistration,
    runtime_enabled: bool,
) -> Result<(), DcrEverparseSelfCheckError> {
    let required = should_run_dcr_everparse_self_check(runtime_enabled);
    if !required {
        return Ok(());
    }

    let buf = encode_dcr_registration_request(meta)?;
    finalize_dcr_everparse_self_check(required, dcr_parser::check_registration_request(&buf))
}

/// Encode parsed DCR metadata into the canonical `EverParse` binary request shape.
///
/// # Errors
///
/// Returns an error when a field cannot be represented in the binary schema or the resulting
/// buffer would exceed the supported size.
pub(super) fn encode_dcr_registration_request(
    meta: &ClientRegistration,
) -> Result<Vec<u8>, DcrEverparseSelfCheckError> {
    let mut out = Vec::new();

    // registration_request.version
    push_u32_le(&mut out, 1);

    // client_metadata.redirect_uris
    let redirect_uris = match &meta.redirect_uris {
        Some(redirect_uris) => redirect_uris.clone(),
        None => Vec::new(),
    };
    let redirect_bytes = nul_separated_utf8(&redirect_uris, "redirect_uris")?;
    push_bytes_with_u32_len(&mut out, &redirect_bytes)?;

    // client_metadata.token_endpoint_auth_method
    let raw_method = meta
        .token_endpoint_auth_method
        .as_deref()
        .unwrap_or("client_secret_basic");
    let method = raw_method.trim().to_ascii_lowercase();
    push_u8(
        &mut out,
        u8::from(meta.token_endpoint_auth_method.is_some()),
    );
    push_u32_le(&mut out, token_auth_method_tag(&method));

    // client_metadata.grant_types (bitmask)
    let grants = meta.grant_types.clone().unwrap_or_else(|| {
        vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ]
    });
    push_u8(&mut out, u8::from(meta.grant_types.is_some()));
    push_u32_le(&mut out, grant_types_mask(&grants)?);

    // client_metadata.response_types (bitmask)
    let responses = meta
        .response_types
        .clone()
        .unwrap_or_else(|| vec!["code".to_string()]);
    push_u8(&mut out, u8::from(meta.response_types.is_some()));
    push_u32_le(&mut out, response_types_mask(&responses)?);

    // Optional string fields (unused by the current server): encode as absent.
    optional_bytes(&mut out, None)?; // client_name
    optional_bytes(&mut out, None)?; // client_uri
    optional_bytes(&mut out, None)?; // logo_uri

    // client_metadata.scopes
    let scopes = meta
        .scope
        .as_deref()
        .map(crate::oauth_scope::parse_scope_string)
        .transpose()
        .map_err(|err| DcrEverparseSelfCheckError::Encode(format!("invalid scope: {err}")))?
        .unwrap_or_default();
    let scope_bytes = nul_separated_utf8(&scopes, "scope")?;
    push_bytes_with_u32_len(&mut out, &scope_bytes)?;

    // contacts / tos_uri / policy_uri (absent)
    optional_bytes(&mut out, None)?; // contacts
    optional_bytes(&mut out, None)?; // tos_uri
    optional_bytes(&mut out, None)?; // policy_uri

    // jwks_uri (optional)
    let jwks_uri_bytes = meta
        .jwks_uri
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::as_bytes);
    optional_bytes(&mut out, jwks_uri_bytes)?;

    // software_id / software_version (absent)
    optional_bytes(&mut out, None)?; // software_id
    optional_bytes(&mut out, None)?; // software_version

    // OAuth 2.1 / RFC 9700 additions (as booleans)
    push_u8(&mut out, u8::from(meta.pkce_required == Some(true)));
    push_u8(&mut out, u8::from(meta.require_dpop == Some(true)));
    push_u8(&mut out, 0); // requires_par (not modeled in ClientRegistration)

    // Sender-constrained support
    push_u8(
        &mut out,
        u8::from(meta.require_sender_constrained_tokens.is_some()),
    );
    push_u8(
        &mut out,
        u8::from(meta.require_sender_constrained_tokens == Some(true)),
    );

    let sender_methods = match &meta.sender_constrained_methods {
        Some(sender_methods) => sender_methods.clone(),
        None => Vec::new(),
    };
    let sender_methods_bytes = nul_separated_utf8(&sender_methods, "sender_constrained_methods")?;
    push_u8(
        &mut out,
        u8::from(meta.sender_constrained_methods.is_some()),
    );
    push_bytes_with_u32_len(&mut out, &sender_methods_bytes)?;

    push_u8(&mut out, u8::from(meta.require_mtls.is_some()));
    push_u8(&mut out, u8::from(meta.require_mtls == Some(true)));

    // registration_request.initial_access_token (unused)
    push_u8(&mut out, 0);
    push_u32_le(&mut out, 0);

    Ok(out)
}
