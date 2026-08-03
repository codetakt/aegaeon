use super::super::oauth_errors::json_error_with_iss;
use super::super::{normalize_issuer, now_epoch_secs, AppState};
use super::validate_upstream_endpoint;
use aegaeon_jose::jwk::{JwkSet, KeyMaterial};
use axum::{http::StatusCode, response::Response};
use serde_json::Value;
use std::collections::HashSet;

use crate::oidc::OidcDiscovery;

fn upstream_federation_gateway_error(issuer_base: &str, description: &'static str) -> Response {
    json_error_with_iss(
        StatusCode::BAD_GATEWAY,
        "server_error",
        Some(description),
        issuer_base,
    )
}

fn federation_metadata_string<'a>(metadata: &'a Value, key: &str) -> Result<&'a str, String> {
    metadata
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("federation openid_provider metadata missing {key}"))
}

fn validate_federation_endpoint_match(
    metadata: &Value,
    discovery_value: &str,
    key: &str,
) -> Result<(), String> {
    let metadata_value = federation_metadata_string(metadata, key)?;
    validate_upstream_endpoint(metadata_value, key)?;
    if metadata_value == discovery_value {
        Ok(())
    } else {
        Err(format!(
            "upstream discovery {key} does not match federation metadata"
        ))
    }
}

pub(in crate::web) fn validate_upstream_discovery_matches_federation_metadata(
    discovery: &OidcDiscovery,
    expected_issuer: &str,
    metadata: &Value,
) -> Result<(), String> {
    if !metadata.is_object() {
        return Err("federation openid_provider metadata must be an object".to_string());
    }

    let expected_issuer = normalize_issuer(expected_issuer)
        .ok_or_else(|| "expected upstream issuer invalid".to_string())?;
    let metadata_issuer = normalize_issuer(federation_metadata_string(metadata, "issuer")?)
        .ok_or_else(|| "federation openid_provider issuer invalid".to_string())?;
    if metadata_issuer != expected_issuer {
        return Err("federation openid_provider issuer mismatch".to_string());
    }

    let discovery_issuer = normalize_issuer(&discovery.issuer)
        .ok_or_else(|| "upstream discovery issuer invalid".to_string())?;
    if discovery_issuer != metadata_issuer {
        return Err("upstream discovery issuer does not match federation metadata".to_string());
    }

    [
        (
            "authorization_endpoint",
            discovery.authorization_endpoint.as_str(),
        ),
        ("token_endpoint", discovery.token_endpoint.as_str()),
        ("jwks_uri", discovery.jwks_uri.as_str()),
    ]
    .into_iter()
    .try_for_each(|(key, discovery_value)| {
        validate_federation_endpoint_match(metadata, discovery_value, key)
    })
}

fn jwk_signature_key_identity(key: &aegaeon_jose::jwk::Jwk) -> String {
    let kid = key.kid.as_deref().unwrap_or("");
    match &key.material {
        KeyMaterial::Rsa { n, e } => format!("kid={kid}\0kty=RSA\0n={n}\0e={e}"),
        KeyMaterial::Ec { crv, x, y } => {
            format!("kid={kid}\0kty=EC\0crv={crv}\0x={x}\0y={y}")
        }
    }
}

fn jwks_signature_key_identities(jwks: &JwkSet) -> HashSet<String> {
    jwks.signature_keys()
        .map(jwk_signature_key_identity)
        .collect()
}

pub(in crate::web) fn validate_upstream_jwks_matches_federation_metadata(
    fetched_jwks: &JwkSet,
    metadata: &Value,
) -> Result<(), String> {
    let Some(inline_jwks) = metadata.get("jwks").filter(|value| !value.is_null()) else {
        return Ok(());
    };

    let metadata_jwks = JwkSet::from_value(inline_jwks.clone())
        .map_err(|err| format!("federation openid_provider jwks invalid: {err}"))?;
    metadata_jwks
        .ensure_unique_kid()
        .map_err(|err| format!("federation openid_provider jwks invalid: {err}"))?;
    fetched_jwks
        .ensure_unique_kid()
        .map_err(|err| format!("upstream jwks invalid: {err}"))?;
    let expected = jwks_signature_key_identities(&metadata_jwks);
    if expected.is_empty() {
        return Err("federation openid_provider jwks has no signature keys".to_string());
    }
    let fetched = jwks_signature_key_identities(fetched_jwks);
    if fetched == expected {
        Ok(())
    } else {
        Err("upstream JWKS does not match federation openid_provider metadata".to_string())
    }
}

async fn resolve_upstream_federation_metadata(
    state: &AppState,
    upstream_issuer: &str,
    environment_id: uuid::Uuid,
    issuer_base: &str,
) -> Result<Option<Value>, Response> {
    let anchor_repo = state.federation.trust_anchors.as_ref();
    let chain_cache = state.federation.chain_cache.as_ref();

    let now_epoch_secs = now_epoch_secs().map_err(|_| {
        upstream_federation_gateway_error(issuer_base, "failed to read system clock")
    })?;
    let leaf_entity_id = upstream_issuer.to_string();
    let now_epoch = now_epoch_secs.cast_signed();
    let outbound_allowed_domains = state
        .federation
        .cache_config
        .outbound_allowed_domains
        .clone();
    let chain_result = crate::federation::resolve_trust_chain_cached_with(
        upstream_issuer,
        environment_id,
        anchor_repo,
        chain_cache,
        &state.federation.cache_config,
        now_epoch,
        move |trust_anchors| {
            let outbound_allowed_domains = outbound_allowed_domains.clone();
            let leaf_entity_id = leaf_entity_id.clone();
            async move {
                let fetcher =
                    crate::federation::HttpFederationFetcher::try_with_optional_allowed_domains(
                        &outbound_allowed_domains,
                    )?;
                crate::federation::resolve_trust_chain_with_jwts(
                    &leaf_entity_id,
                    &trust_anchors,
                    &fetcher,
                    now_epoch,
                )
                .await
            }
        },
    )
    .await;
    let chain = match chain_result {
        Ok(chain) => chain,
        Err(crate::federation::FederationError::ChainResolution(reason))
            if reason == "no trust anchors configured for this environment" =>
        {
            return Ok(None);
        }
        Err(_) => {
            return Err(upstream_federation_gateway_error(
                issuer_base,
                "federation trust chain verification failed",
            ));
        }
    };

    let resolved_metadata = chain.resolved_metadata().map_err(|_| {
        upstream_federation_gateway_error(
            issuer_base,
            "federation metadata policy validation failed",
        )
    })?;
    let openid_provider = resolved_metadata
        .as_ref()
        .and_then(|metadata| metadata.get("openid_provider"))
        .cloned()
        .ok_or_else(|| {
            upstream_federation_gateway_error(
                issuer_base,
                "federation trust chain missing openid_provider metadata",
            )
        })?;
    if openid_provider.is_object() {
        Ok(Some(openid_provider))
    } else {
        Err(upstream_federation_gateway_error(
            issuer_base,
            "federation openid_provider metadata must be an object",
        ))
    }
}

pub(in crate::web) async fn verify_upstream_federation_metadata(
    state: &AppState,
    upstream_issuer: &str,
    environment_id: uuid::Uuid,
    discovery: &OidcDiscovery,
    jwks: Option<&JwkSet>,
    issuer_base: &str,
) -> Result<(), Response> {
    let Some(metadata) =
        resolve_upstream_federation_metadata(state, upstream_issuer, environment_id, issuer_base)
            .await?
    else {
        return Ok(());
    };

    validate_upstream_discovery_matches_federation_metadata(discovery, upstream_issuer, &metadata)
        .map_err(|_| {
            upstream_federation_gateway_error(
                issuer_base,
                "upstream discovery does not match federation metadata",
            )
        })?;

    if let Some(jwks) = jwks {
        validate_upstream_jwks_matches_federation_metadata(jwks, &metadata).map_err(|_| {
            upstream_federation_gateway_error(
                issuer_base,
                "upstream JWKS does not match federation metadata",
            )
        })?;
    }

    Ok(())
}

pub(in crate::web) async fn verify_upstream_federation_metadata_blocking(
    state: AppState,
    upstream_issuer: String,
    environment_id: uuid::Uuid,
    discovery: OidcDiscovery,
    jwks: Option<JwkSet>,
    issuer_base: String,
) -> Result<(), Response> {
    verify_upstream_federation_metadata(
        &state,
        &upstream_issuer,
        environment_id,
        &discovery,
        jwks.as_ref(),
        &issuer_base,
    )
    .await
}
