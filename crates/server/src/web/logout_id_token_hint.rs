use super::upstream_id_token::{
    verify_compact_jwt_payload_with_key, UpstreamIdTokenSignatureError,
};
use axum::http::StatusCode;

use crate::oidc::{required_rs256, Audience, IdTokenClaims, OidcConfig};
use crate::util;

pub(super) fn client_id_from_id_token_hint(claims: &IdTokenClaims) -> Result<String, String> {
    match &claims.aud {
        Audience::Single(client_id) if !client_id.trim().is_empty() => Ok(client_id.clone()),
        Audience::Multiple(_) => claims
            .azp
            .clone()
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| "azp is required when aud contains multiple audiences".to_string()),
        Audience::Single(_) => Err("invalid aud claim in id_token_hint".to_string()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct IdTokenHintDecodeError {
    pub(super) status: StatusCode,
    pub(super) error: &'static str,
    public_description: String,
}

impl IdTokenHintDecodeError {
    fn invalid(description: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error: "invalid_request",
            public_description: description.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        let message = message.into();
        tracing::error!(
            target: "oauth",
            error = %message,
            "id_token_hint processing failed internally"
        );
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            error: "server_error",
            public_description: "id_token_hint processing failed internally".to_string(),
        }
    }

    pub(super) fn public_description(&self) -> &str {
        &self.public_description
    }
}

pub(super) fn decode_id_token_hint(
    cfg: &OidcConfig,
    token: &str,
    jose_header_max_len: usize,
) -> Result<IdTokenClaims, IdTokenHintDecodeError> {
    let header = util::decode_compact_jwt_header_without_duplicate_keys_with_max_len(
        token,
        jose_header_max_len,
    )
    .map_err(|err| match err {
        util::JsonObjectParseError::BackendPolicy => {
            IdTokenHintDecodeError::internal("unsupported raw JSON backend for jose-header")
        }
        util::JsonObjectParseError::DuplicateKey
        | util::JsonObjectParseError::InvalidJson
        | util::JsonObjectParseError::TrailingBytes
        | util::JsonObjectParseError::InvalidShape => {
            IdTokenHintDecodeError::invalid("invalid id_token_hint")
        }
    })?;
    if header.alg != jsonwebtoken::Algorithm::RS256 {
        return Err(IdTokenHintDecodeError::invalid(
            "id_token_hint must be signed with RS256",
        ));
    }
    let kid = header
        .kid
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| IdTokenHintDecodeError::invalid("id_token_hint missing kid"))?;

    let jwks = cfg.signing_key.jwks();
    let jwk = jwks
        .keys
        .iter()
        .find(|k| k.kid == kid)
        .ok_or_else(|| IdTokenHintDecodeError::invalid("unknown id_token_hint kid"))?;
    let n = jwk
        .n
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| IdTokenHintDecodeError::invalid("id_token_hint jwk missing n"))?;
    let e = jwk
        .e
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| IdTokenHintDecodeError::invalid("id_token_hint jwk missing e"))?;
    let decoding_key = jsonwebtoken::DecodingKey::from_rsa_components(n, e)
        .map_err(|_| IdTokenHintDecodeError::invalid("invalid id_token_hint decoding key"))?;

    let payload =
        verify_compact_jwt_payload_with_key(token, &decoding_key, jsonwebtoken::Algorithm::RS256)
            .map_err(|err| match err {
            UpstreamIdTokenSignatureError::PayloadInvalid => {
                IdTokenHintDecodeError::invalid("id_token_hint payload invalid")
            }
            UpstreamIdTokenSignatureError::Internal(message) => {
                IdTokenHintDecodeError::internal(message)
            }
            _ => IdTokenHintDecodeError::invalid("id_token_hint signature invalid"),
        })?;
    let claims = required_rs256::decode_id_token_payload_claims_without_duplicate_keys(&payload)
        .map_err(|err| match err {
            required_rs256::RequiredRs256Error::Internal(message) => {
                IdTokenHintDecodeError::internal(message)
            }
            _ => IdTokenHintDecodeError::invalid("id_token_hint payload invalid"),
        })?;
    validate_id_token_hint_claims(cfg, &claims).map_err(IdTokenHintDecodeError::invalid)?;
    Ok(claims)
}

fn validate_id_token_hint_claims(cfg: &OidcConfig, claims: &IdTokenClaims) -> Result<(), String> {
    if claims.iss != cfg.issuer {
        return Err("id_token_hint issuer mismatch".to_string());
    }
    let now = util::now_unix_epoch_secs_i64().map_err(|err| {
        util::log_clock_error("id_token_hint validation clock", &err);
        "invalid id_token_hint".to_string()
    })?;
    let leeway = 60_i64;
    let exp_with_leeway = claims
        .exp
        .checked_add(leeway)
        .ok_or_else(|| "id_token_hint is expired".to_string())?;
    if exp_with_leeway < now {
        return Err("id_token_hint is expired".to_string());
    }
    if let Some(nbf) = claims.nbf {
        let now_with_leeway = now
            .checked_add(leeway)
            .ok_or_else(|| "invalid id_token_hint".to_string())?;
        if nbf > now_with_leeway {
            return Err("id_token_hint is not yet valid".to_string());
        }
    }
    Ok(())
}
