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

    normalize_issuer(expected_issuer)
        .ok_or_else(|| "expected upstream issuer invalid".to_string())?;
    let metadata_issuer = federation_metadata_string(metadata, "issuer")?;
    normalize_issuer(metadata_issuer)
        .ok_or_else(|| "federation openid_provider issuer invalid".to_string())?;
    if metadata_issuer != expected_issuer {
        return Err("federation openid_provider issuer mismatch".to_string());
    }

    if discovery.issuer != metadata_issuer {
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

async fn resolve_upstream_federation_metadata<F, Fut>(
    state: &AppState,
    upstream_issuer: &str,
    environment_id: uuid::Uuid,
    issuer_base: &str,
    mut acquire: F,
) -> Result<Option<Value>, Response>
where
    F: FnMut(Vec<crate::federation::TrustAnchor>, i64) -> Fut,
    Fut: std::future::Future<
        Output = Result<crate::federation::ResolvedTrustChain, crate::federation::FederationError>,
    >,
{
    let anchor_repo = state.federation.trust_anchors.as_ref();
    let chain_cache = state.federation.chain_cache.as_ref();
    let stored = anchor_repo
        .list_for_environment(environment_id)
        .await
        .map_err(|_| {
            upstream_federation_gateway_error(
                issuer_base,
                "failed to load federation trust anchors",
            )
        })?;
    // Only an actual empty repository result permits ordinary Discovery.
    // A downstream error with similar wording is never an absence signal.
    if stored.is_empty() {
        return Ok(None);
    }
    let anchors = stored
        .iter()
        .map(crate::federation::StoredTrustAnchor::to_trust_anchor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            upstream_federation_gateway_error(issuer_base, "invalid federation trust anchor")
        })?;

    let now_epoch_secs = now_epoch_secs().map_err(|_| {
        upstream_federation_gateway_error(issuer_base, "failed to read system clock")
    })?;
    let now_epoch = now_epoch_secs.cast_signed();
    let chain_result = crate::federation::resolve_trust_chain_jwts_cached_with(
        upstream_issuer,
        environment_id,
        anchors,
        chain_cache,
        &state.federation.cache_config,
        now_epoch,
        |anchors| acquire(anchors, now_epoch),
    )
    .await;
    admit_upstream_federation_metadata(chain_result, issuer_base)
}

pub(crate) fn admit_upstream_federation_metadata(
    chain_result: Result<crate::federation::ResolvedTrustChain, crate::federation::FederationError>,
    issuer_base: &str,
) -> Result<Option<Value>, Response> {
    let chain = match chain_result {
        Ok(chain) => chain,
        Err(_) => {
            return Err(upstream_federation_gateway_error(
                issuer_base,
                "federation trust chain verification failed",
            ));
        }
    };

    crate::federation::validate_oidc_upstream_chain(&chain).map_err(|_| {
        upstream_federation_gateway_error(
            issuer_base,
            "federation chain does not satisfy ordinary OIDC context",
        )
    })?;
    let resolved_metadata = chain.trust_chain.resolved_metadata().map_err(|_| {
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

// Discovery section 3 requires RS256 in complete OP signing capabilities.
// This does not select an individual token's algorithm or validate partial C/S metadata.
fn validate_id_token_signing_capabilities(
    discovery: &OidcDiscovery,
    issuer_base: &str,
) -> Result<(), Response> {
    if !discovery
        .id_token_signing_alg_values_supported
        .iter()
        .any(|algorithm| algorithm == "RS256")
    {
        return Err(upstream_federation_gateway_error(
            issuer_base,
            "upstream OP signing capabilities must include RS256",
        ));
    }
    Ok(())
}

/// Selected metadata and its inline-key constraint belong to one operation.
/// Construction is private; raw signed chain admission remains the authority.
pub(in crate::web) struct EffectiveUpstreamMetadata {
    pub(in crate::web) discovery: OidcDiscovery,
    federation_metadata: Option<Value>,
}

impl EffectiveUpstreamMetadata {
    pub(in crate::web) fn validate_signing_keys(
        &self,
        jwks: &JwkSet,
        issuer_base: &str,
    ) -> Result<(), Response> {
        if let Some(metadata) = self.federation_metadata.as_ref() {
            validate_upstream_jwks_matches_federation_metadata(jwks, metadata).map_err(|_| {
                upstream_federation_gateway_error(
                    issuer_base,
                    "upstream JWKS does not match federation metadata",
                )
            })?;
        }
        Ok(())
    }
}

pub(in crate::web) async fn resolve_upstream_metadata_with<F, Fut>(
    state: &AppState,
    upstream_issuer: &str,
    environment_id: uuid::Uuid,
    discovery: OidcDiscovery,
    issuer_base: &str,
    acquire: F,
) -> Result<EffectiveUpstreamMetadata, Response>
where
    F: FnMut(Vec<crate::federation::TrustAnchor>, i64) -> Fut,
    Fut: std::future::Future<
        Output = Result<crate::federation::ResolvedTrustChain, crate::federation::FederationError>,
    >,
{
    crate::oidc::provider_urls::validate_typed(&discovery).map_err(|_| {
        upstream_federation_gateway_error(issuer_base, "upstream discovery URL metadata invalid")
    })?;
    // Ordinary source admission still applies when signed metadata replaces it.
    crate::oidc::capabilities::validate_typed(&discovery).map_err(|_| {
        upstream_federation_gateway_error(
            issuer_base,
            "upstream discovery authentication signing capabilities invalid",
        )
    })?;
    let metadata = resolve_upstream_federation_metadata(
        state,
        upstream_issuer,
        environment_id,
        issuer_base,
        acquire,
    )
    .await?;
    let Some(metadata) = metadata else {
        validate_id_token_signing_capabilities(&discovery, issuer_base)?;
        return Ok(EffectiveUpstreamMetadata {
            discovery,
            federation_metadata: None,
        });
    };
    validate_upstream_discovery_matches_federation_metadata(&discovery, upstream_issuer, &metadata)
        .map_err(|_| {
            upstream_federation_gateway_error(
                issuer_base,
                "upstream discovery does not match federation metadata",
            )
        })?;
    crate::federation::validate_complete_op_registration(&metadata).map_err(|_| {
        upstream_federation_gateway_error(
            issuer_base,
            "resolved federation OP registration declarations invalid",
        )
    })?;
    // Deserialize only the resolved signed OP object: missing/deleted fields are
    // not restored from independently fetched Discovery.
    let effective: OidcDiscovery = serde_json::from_value(metadata.clone()).map_err(|_| {
        upstream_federation_gateway_error(issuer_base, "resolved federation OP metadata invalid")
    })?;
    crate::oidc::capabilities::validate_typed(&effective).map_err(|_| {
        upstream_federation_gateway_error(issuer_base, "resolved federation OP metadata invalid")
    })?;
    crate::oidc::provider_urls::validate_typed(&effective).map_err(|_| {
        upstream_federation_gateway_error(
            issuer_base,
            "resolved federation OP URL metadata invalid",
        )
    })?;
    validate_id_token_signing_capabilities(&effective, issuer_base)?;
    Ok(EffectiveUpstreamMetadata {
        discovery: effective,
        federation_metadata: Some(metadata),
    })
}

/// Only transport acquisition is replaceable. The common cache boundary still
/// checks every raw signed path independently before effective metadata exists.
pub(in crate::web) async fn acquire_upstream_federation_chain(
    state: &AppState,
    issuer: &str,
    anchors: Vec<crate::federation::TrustAnchor>,
    now: i64,
) -> Result<crate::federation::ResolvedTrustChain, crate::federation::FederationError> {
    let fetcher = crate::federation::HttpFederationFetcher::try_with_optional_allowed_domains(
        &state.federation.cache_config.outbound_allowed_domains,
    )?;
    crate::federation::resolve_trust_chain_with_jwts(issuer, &anchors, &fetcher, now).await
}
