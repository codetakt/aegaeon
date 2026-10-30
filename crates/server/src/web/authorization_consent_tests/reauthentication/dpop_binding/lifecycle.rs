use super::*;
const OBSERVER_SECRET: &str = "binding-introspection-test-secret";

pub(super) async fn prepare(state: &AppState) -> TestResult {
    let issuer = url::Url::parse(state.issuer.as_str())?;
    let host = issuer.host_str().ok_or("host")?;
    for id in [format!("{}/userinfo", state.issuer), "internal-api".into()] {
        let mut client = sample_registered_client(&id);
        client.client_secret = Some(OBSERVER_SECRET.into());
        client.token_endpoint_auth_method = "client_secret_post".into();
        crate::dcr_persistence::create_dynamic_registration(
            &state.db_pool,
            host,
            &client,
            &["code".into()],
            &format!("observer-registration-{id}"),
            "binding-introspection",
        )
        .await?;
    }
    sqlx::query("UPDATE aegaeon.oauth_profiles SET token_endpoint_auth_methods_allowed=ARRAY['none','client_secret_basic','client_secret_post'] WHERE environment_id=$1").bind(state.environment_id).execute(&state.db_pool).await?;
    state
        .runtime_authority
        .try_synchronize_client_projection_from_database(&state.db_pool, state.clients.as_ref())
        .await?;
    Ok(())
}
pub(super) async fn observe(
    state: &AppState,
    token: &str,
    audience: &str,
    key: &Key,
    active: bool,
) -> TestResult {
    // A registered confidential resource observer authenticates independently
    // of the issuing public/confidential OAuth client.
    let headers = form_headers(None)?;
    let (status, body) = json_reply(
        raw(
            state,
            "",
            Method::POST,
            "/introspect",
            serde_urlencoded::to_string([
                ("token", token),
                ("client_id", audience),
                ("client_secret", OBSERVER_SECRET),
            ])?,
            headers,
        )
        .await?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["active"], active, "{body}");
    if active {
        assert_eq!(body["cnf"]["jkt"], key.jkt);
    } else {
        assert_eq!(body, json!({"active":false}));
    }
    Ok(())
}
pub(super) async fn revoke_and_observe(
    state: &AppState,
    refresh: &str,
    tokens: &[(&str, &str)],
    key: &Key,
) -> TestResult {
    assert!(state
        .tokens
        .store
        .try_revoke_refresh_token_for_subject("consent-user", refresh)?);
    for (token, audience) in tokens {
        assert!(validate(state, token, audience, key).is_err());
        observe(state, token, audience, key, false).await?;
    }
    Ok(())
}

pub(super) fn validate(
    state: &AppState,
    token: &str,
    audience: &str,
    key: &Key,
) -> Result<(), crate::authcode::TokenPolicyError> {
    // The policy-aware API includes refresh-parent lifecycle, audience and
    // sender constraints. Crypto/record validation alone omits that policy.
    state
        .tokens
        .validator
        .validate_with_policy(
            &format!("Bearer {token}"),
            crate::authcode::TokenPolicyContext {
                requested_scopes: &[],
                resource_audience: Some(audience),
                sender_dpop_jkt: Some(&key.jkt),
                sender_mtls_fingerprint: None,
            },
        )
        .map(|_| ())
}
