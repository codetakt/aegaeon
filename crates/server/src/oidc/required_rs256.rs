use super::config::{OidcSigningError, OidcSigningKey};
use super::id_token::{IdTokenBuilder, IdTokenClaims, Result as IdTokenResult};

mod payload;
#[cfg(test)]
mod tests;
mod verification;

pub(crate) use payload::decode_id_token_payload_claims_without_duplicate_keys;
pub use verification::verify_required_id_token_claims;

pub const REQUIRED_SIGNING_ALG: &str = "RS256";

#[derive(Debug, thiserror::Error)]
pub enum RequiredRs256Error {
    #[error("id_token structure invalid")]
    InvalidStructure,
    #[error("id_token rsa key invalid")]
    InvalidKey,
    #[error("id_token signature invalid")]
    InvalidSignature,
    #[error("id_token payload invalid")]
    InvalidPayload,
    #[error("id_token internal error: {0}")]
    Internal(String),
    #[error("id_token signing failed: {0}")]
    Signing(#[from] OidcSigningError),
}

pub fn apply_required_hashes(
    builder: IdTokenBuilder,
    access_token: &str,
    code: &str,
) -> IdTokenResult<IdTokenBuilder> {
    builder
        .access_token_hash(access_token, REQUIRED_SIGNING_ALG)?
        .code_hash(code, REQUIRED_SIGNING_ALG)
}

pub fn sign_required_id_token(
    claims: &IdTokenClaims,
    signing_key: &OidcSigningKey,
) -> Result<String, RequiredRs256Error> {
    validate_output_subject(claims)?;
    signing_key.sign_rs256_jwt(claims).map_err(Into::into)
}

pub async fn sign_required_id_token_async(
    claims: &IdTokenClaims,
    signing_key: &OidcSigningKey,
) -> Result<String, RequiredRs256Error> {
    validate_output_subject(claims)?;
    signing_key
        .sign_rs256_jwt_async(claims)
        .await
        .map_err(Into::into)
}

fn validate_output_subject(claims: &IdTokenClaims) -> Result<(), RequiredRs256Error> {
    if !super::subject::is_valid_subject(&claims.sub)
        || claims.additional_claims.contains_key("sub")
    {
        return Err(RequiredRs256Error::InvalidPayload);
    }
    Ok(())
}
