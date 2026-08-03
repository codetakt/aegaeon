mod jwt;

use axum::response::Response;

use crate::oidc::config::OidcRequestObjectEncryptionKey;
use crate::oidc::OidcSigningKey;

use super::super::super::super::management_internal_error;
use super::super::types::RuntimeKeyUsageInput;
use super::super::validation::runtime_key_bad_request;
use jwt::jwt_eddsa_public_jwk;

pub(in crate::web::management::runtime_keys::input) fn runtime_key_public_jwk(
    usage: RuntimeKeyUsageInput,
    algorithm: &str,
    kid: &str,
    pkcs8_der: &[u8],
    request_id: &str,
) -> Result<serde_json::Value, Response> {
    let public_jwk = match usage {
        RuntimeKeyUsageInput::OidcIdTokenSigning => {
            let signing_key = OidcSigningKey::from_rsa_pkcs8_der(kid.to_string(), pkcs8_der)
                .map_err(|_| {
                    runtime_key_bad_request(
                        request_id,
                        "privateKeyPem is not usable as an RS256 OIDC signing key",
                        None,
                    )
                })?;
            signing_key
                .jwks()
                .keys
                .into_iter()
                .next()
                .ok_or_else(|| management_internal_error(request_id, "Failed to derive JWK"))?
        }
        RuntimeKeyUsageInput::OidcRequestObjectDecryption => {
            let encryption_key =
                OidcRequestObjectEncryptionKey::from_rsa_pkcs8_der(kid.to_string(), pkcs8_der)
                    .map_err(|_| {
                        runtime_key_bad_request(
                            request_id,
                            "privateKeyPem is not usable as an OIDC request-object decryption key",
                            None,
                        )
                    })?;
            encryption_key.public_jwk().clone()
        }
        RuntimeKeyUsageInput::JwtAccessTokenSigning
        | RuntimeKeyUsageInput::JwtIntrospectionSigning => match algorithm {
            "EdDSA" => jwt_eddsa_public_jwk(kid, pkcs8_der, request_id)?,
            _ => {
                return Err(runtime_key_bad_request(
                    request_id,
                    "Unsupported algorithm for JWT runtime signing key",
                    None,
                ));
            }
        },
    };

    serde_json::to_value(public_jwk)
        .map_err(|_| management_internal_error(request_id, "Failed to serialize public JWK"))
}
