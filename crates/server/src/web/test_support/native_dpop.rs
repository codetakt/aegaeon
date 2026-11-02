//! Real Ed25519 proofs and isolated Redis replay entries for token HTTP tests.
use super::{AppState, TestResult};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};

pub(crate) fn install(state: &mut AppState) -> TestResult {
    let namespace = crate::config::RuntimeStateNamespace::from_environment_id(state.environment_id);
    let replay = crate::middleware::replay_store::RedisReplayStore::new(
        &std::env::var("AEGAEON_TEST_REDIS_URL")?,
        &namespace,
        "client-minimum-test",
    )?;
    state.dpop = Arc::new(
        crate::middleware::DpopMiddleware::new(
            state.environment_id.to_string(),
            state.issuer.as_str(),
            Arc::new(replay),
            Duration::from_secs(360),
        )
        .with_native_verifier_for_tests(),
    );
    Ok(())
}

pub(crate) fn proof(
    state: &AppState,
    material: &aegaeon_crypto::signing::Ed25519KeyData,
    overrides: Value,
) -> TestResult<String> {
    let key = aegaeon_crypto::signing::Ed25519SigningKey::from_pkcs8(&material.pkcs8)?;
    let header = json!({"typ":"dpop+jwt","alg":"EdDSA","jwk":{"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(&material.public_key)}});
    let mut claims = json!({"htm":"POST","htu":format!("{}/token",state.issuer),"iat":crate::util::now_unix_epoch_secs()?,"jti":uuid::Uuid::new_v4().to_string()});
    if let Some(overrides) = overrides.as_object() {
        for (name, value) in overrides {
            claims[name] = value.clone();
        }
    }
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?)
    );
    Ok(format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes())?)
    ))
}

pub(crate) async fn set_minimum(
    state: &AppState,
    client_id: &str,
    token: &str,
    minimum: bool,
) -> TestResult {
    let host = url::Url::parse(state.issuer.as_str())?
        .host_str()
        .ok_or("issuer host")?
        .to_owned();
    let stored = crate::dcr_persistence::load_dynamic_registration_by_token(
        &state.db_pool,
        &host,
        client_id,
        token,
    )
    .await?
    .ok_or("stored owner")?;
    let previous = state.clients.try_runtime_snapshot_fingerprint()?;
    let mut client = stored.client.clone();
    client.dpop_bound_access_tokens = minimum;
    crate::dcr_persistence::update_dynamic_registration(
        &state.db_pool,
        &stored,
        &client,
        &stored.response_types,
        token,
        crate::dcr_persistence::DcrClientSecretChange::Preserve,
        None,
        "minimum-test",
    )
    .await?;
    state
        .runtime_authority
        .try_synchronize_client_projection_from_database(&state.db_pool, state.clients.as_ref())
        .await?;
    assert_eq!(
        state
            .clients
            .try_get(client_id)?
            .ok_or("runtime client")?
            .dpop_bound_access_tokens,
        minimum
    );
    if stored.client.dpop_bound_access_tokens != minimum {
        assert_ne!(previous, state.clients.try_runtime_snapshot_fingerprint()?);
    }
    Ok(())
}
