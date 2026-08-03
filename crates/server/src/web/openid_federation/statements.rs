use axum::{http::StatusCode, response::Response};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::{json, Value};
use url::Url;

use super::super::oauth_errors::json_error_with_iss;
use crate::client_registry::RegisteredClient;
use crate::kms::{FederationKeyManager, KeyManagerError};
use crate::util;

/// Maximum entity configuration JWT lifetime (seconds).
const MAX_FEDERATION_ENTITY_EXP_SECS: u64 = 86400;

struct FederationSigningMaterial {
    alg: &'static str,
    public_jwk: Value,
    kid: String,
}

pub(in crate::web) fn validate_federation_sub_entity_id(
    sub: &str,
    issuer: &str,
) -> Result<(), Response> {
    crate::federation::validate_entity_url(sub)
        .map(|_| ())
        .map_err(|_| {
            json_error_with_iss(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some("invalid 'sub' query parameter; expected an HTTPS entity_id without userinfo, query, or fragment"),
                issuer,
            )
        })
}

fn validate_federation_entity_id_for_signing(entity_id: &str) -> Result<Url, KeyManagerError> {
    crate::federation::validate_entity_url(entity_id).map_err(|_| KeyManagerError::OperationFailed)
}

fn validate_distinct_federation_subjects(
    issuer_entity_id: &str,
    subject_entity_id: &str,
) -> Result<(), KeyManagerError> {
    let issuer_url = validate_federation_entity_id_for_signing(issuer_entity_id)?;
    let subject_url = validate_federation_entity_id_for_signing(subject_entity_id)?;
    if issuer_url == subject_url {
        return Err(KeyManagerError::OperationFailed);
    }
    Ok(())
}

fn openid_relying_party_metadata(
    sub_entity_id: &str,
    client: &RegisteredClient,
) -> Result<Value, KeyManagerError> {
    if client.client_id != sub_entity_id {
        return Err(KeyManagerError::OperationFailed);
    }

    let mut metadata = serde_json::Map::new();
    metadata.insert("client_id".to_string(), json!(client.client_id));
    metadata.insert("redirect_uris".to_string(), json!(client.redirect_uris));
    metadata.insert("response_types".to_string(), json!(["code"]));
    metadata.insert("grant_types".to_string(), json!(client.allowed_grant_types));
    metadata.insert(
        "token_endpoint_auth_method".to_string(),
        json!(client.token_endpoint_auth_method),
    );

    if let Some(scope) = crate::oauth_scope::scope_string(&client.allowed_scopes) {
        metadata.insert("scope".to_string(), json!(scope));
    }
    if !client.post_logout_redirect_uris.is_empty() {
        metadata.insert(
            "post_logout_redirect_uris".to_string(),
            json!(client.post_logout_redirect_uris),
        );
    }
    if let Some(uri) = client.backchannel_logout_uri.as_ref() {
        metadata.insert("backchannel_logout_uri".to_string(), json!(uri));
    }
    if client.backchannel_logout_session_required {
        metadata.insert(
            "backchannel_logout_session_required".to_string(),
            json!(true),
        );
    }
    if let Some(uri) = client.jwks_uri.as_ref() {
        metadata.insert("jwks_uri".to_string(), json!(uri));
    }
    if let Some(jwks) = client.inline_jwks.as_ref() {
        metadata.insert("jwks".to_string(), jwks.as_value().clone());
    }
    if let Some(alg) = client.token_endpoint_auth_signing_alg.as_ref() {
        metadata.insert("token_endpoint_auth_signing_alg".to_string(), json!(alg));
    }

    Ok(Value::Object(metadata))
}

fn validate_federation_authority_hints_for_signing(
    entity_id: &str,
    authority_hints: &[String],
) -> Result<(), KeyManagerError> {
    let entity_url = validate_federation_entity_id_for_signing(entity_id)?;
    authority_hints.iter().try_for_each(|hint| {
        let authority_url = validate_federation_entity_id_for_signing(hint)?;
        if authority_url == entity_url {
            return Err(KeyManagerError::OperationFailed);
        }
        Ok(())
    })
}

fn required_federation_jwk_kid(jwk: &Value) -> Result<String, KeyManagerError> {
    jwk.get("kid")
        .and_then(Value::as_str)
        .filter(|kid| !kid.trim().is_empty())
        .map(ToString::to_string)
        .ok_or(KeyManagerError::KeyNotFound)
}

fn federation_signing_material(
    key_manager: &dyn FederationKeyManager,
) -> Result<FederationSigningMaterial, KeyManagerError> {
    let public_jwk = key_manager
        .federation_public_jwk()
        .ok_or(KeyManagerError::KeyNotFound)?;
    let kid = required_federation_jwk_kid(&public_jwk)?;
    Ok(FederationSigningMaterial {
        alg: key_manager.federation_alg(),
        public_jwk,
        kid,
    })
}

/// Build a self-signed Entity Configuration for this OP.
///
/// Security properties (matching Tamarin: `op_entity_configuration.spthy)`:
/// - EC-1: iss == sub (self-signed requirement)
/// - EC-2: JWKS embedded (verifiers can validate the signature)
/// - EC-3: exp bounded (limits stale configuration window)
/// - EC-4: iat present (temporal ordering)
/// - EC-5: `entity_id` is HTTPS (no HTTP downgrade)
#[cfg(test)]
pub(in crate::web) fn build_entity_configuration(
    entity_id: &str,
    issuer: &str,
    authority_hints: &[String],
    exp_secs: u64,
    key_manager: &dyn FederationKeyManager,
) -> Result<String, KeyManagerError> {
    build_entity_configuration_with_openid_provider_metadata(
        entity_id,
        issuer,
        authority_hints,
        exp_secs,
        key_manager,
        default_openid_provider_metadata(issuer),
    )
}

pub(in crate::web) fn build_entity_configuration_with_openid_provider_metadata(
    entity_id: &str,
    issuer: &str,
    authority_hints: &[String],
    exp_secs: u64,
    key_manager: &dyn FederationKeyManager,
    openid_provider_metadata: Value,
) -> Result<String, KeyManagerError> {
    validate_federation_entity_id_for_signing(entity_id)?;
    validate_federation_entity_id_for_signing(issuer)?;
    validate_federation_authority_hints_for_signing(entity_id, authority_hints)?;
    if !openid_provider_metadata.is_object() {
        return Err(KeyManagerError::OperationFailed);
    }

    let now = util::now_unix_epoch_secs().map_err(|_| KeyManagerError::OperationFailed)?;

    let clamped_exp = exp_secs.min(MAX_FEDERATION_ENTITY_EXP_SECS);
    let exp = now
        .checked_add(clamped_exp)
        .ok_or(KeyManagerError::OperationFailed)?;

    let signing_material = federation_signing_material(key_manager)?;

    let jwks = json!({ "keys": [signing_material.public_jwk.clone()] });
    let federation_metadata = json!({
        "federation_fetch_endpoint": format!("{}/.well-known/openid-federation/fetch", entity_id.trim_end_matches('/')),
        "federation_resolve_endpoint": format!("{}/.well-known/openid-federation/resolve", entity_id.trim_end_matches('/')),
        "federation_list_endpoint": format!("{}/.well-known/openid-federation/list", entity_id.trim_end_matches('/')),
    });

    let payload = json!({
        "iss": entity_id,
        "sub": entity_id,
        "iat": now,
        "exp": exp,
        "jwks": jwks,
        "metadata": {
            "openid_provider": openid_provider_metadata,
            "federation_entity": federation_metadata,
        },
        "authority_hints": authority_hints,
    });

    sign_federation_jwt(
        key_manager,
        &signing_material,
        "entity-statement+jwt",
        &payload,
    )
}

#[cfg(test)]
fn default_openid_provider_metadata(issuer: &str) -> Value {
    json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{}/authorize", issuer.trim_end_matches('/')),
        "token_endpoint": format!("{}/token", issuer.trim_end_matches('/')),
        "jwks_uri": format!("{}/jwks", issuer.trim_end_matches('/')),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    })
}

/// Build a subordinate statement JWT for a registered client.
///
/// Security properties (matching Tamarin: `OP_Issue_Subordinate)`:
/// - SS-1: iss = OP `entity_id` (issuer is the OP)
/// - SS-2: sub = client `entity_id` (subject is the subordinate RP)
/// - SS-3: iss != sub (not self-signed)
/// - SS-4: signed with OP's federation key
pub(in crate::web) fn build_subordinate_statement(
    op_entity_id: &str,
    sub_entity_id: &str,
    client: &RegisteredClient,
    exp_secs: u64,
    key_manager: &dyn FederationKeyManager,
) -> Result<String, KeyManagerError> {
    validate_distinct_federation_subjects(op_entity_id, sub_entity_id)?;
    let signing_material = federation_signing_material(key_manager)?;
    let rp_metadata = openid_relying_party_metadata(sub_entity_id, client)?;

    let now = util::now_unix_epoch_secs().map_err(|_| KeyManagerError::OperationFailed)?;

    let clamped_exp = exp_secs.min(MAX_FEDERATION_ENTITY_EXP_SECS);
    let exp = now
        .checked_add(clamped_exp)
        .ok_or(KeyManagerError::OperationFailed)?;

    let payload = json!({
        "iss": op_entity_id,
        "sub": sub_entity_id,
        "iat": now,
        "exp": exp,
        "metadata": {
            "openid_relying_party": rp_metadata,
        },
        "metadata_policy": {},
    });

    sign_federation_jwt(
        key_manager,
        &signing_material,
        "entity-statement+jwt",
        &payload,
    )
}

pub(in crate::web) fn build_resolve_response(
    issuer: &str,
    subject: &str,
    issued_at: i64,
    expires_at: i64,
    metadata: Value,
    trust_chain: Vec<String>,
    key_manager: &dyn FederationKeyManager,
) -> Result<String, KeyManagerError> {
    validate_federation_entity_id_for_signing(issuer)?;
    validate_federation_entity_id_for_signing(subject)?;
    if trust_chain.is_empty() || expires_at <= issued_at {
        return Err(KeyManagerError::OperationFailed);
    }

    let signing_material = federation_signing_material(key_manager)?;
    let payload = json!({
        "iss": issuer,
        "sub": subject,
        "iat": issued_at,
        "exp": expires_at,
        "metadata": metadata,
        "trust_chain": trust_chain,
    });

    sign_federation_jwt(
        key_manager,
        &signing_material,
        "resolve-response+jwt",
        &payload,
    )
}

fn sign_federation_jwt(
    key_manager: &dyn FederationKeyManager,
    signing_material: &FederationSigningMaterial,
    typ: &'static str,
    payload: &Value,
) -> Result<String, KeyManagerError> {
    let header = json!({
        "alg": signing_material.alg,
        "typ": typ,
        "kid": signing_material.kid,
    });
    let header_b64 = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&header).map_err(|_| KeyManagerError::OperationFailed)?);
    let payload_b64 = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(payload).map_err(|_| KeyManagerError::OperationFailed)?);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig = key_manager.sign_federation(signing_input.as_bytes())?;
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig);
    Ok(format!("{signing_input}.{sig_b64}"))
}
