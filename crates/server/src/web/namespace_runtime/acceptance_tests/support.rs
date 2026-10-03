use crate::web::{self, test_support, AppState};
use axum::{body::to_bytes, http::StatusCode, response::Response};
use serde_json::Value;
pub(super) use test_support::TestResult;

pub(super) async fn fixture() -> TestResult<(AppState, test_support::TestEnvironment)> {
    let pool = test_support::test_pg_pool()
        .await?
        .ok_or("isolated restricted PostgreSQL is required")?;
    let env = test_support::setup_test_environment(&pool).await?;
    let state = test_support::test_app_state(pool, &env).await?;
    assert!(state.require_subject_namespace().is_ok());
    Ok((state, env))
}

/// Both negative states retain the exact stores of the validated control.
pub(super) fn unavailable_states(state: &AppState) -> [AppState; 2] {
    let mut absent = state.clone();
    absent.subject_namespace = None;
    let mut mismatched = state.clone();
    mismatched.environment_id = uuid::Uuid::new_v4();
    [absent, mismatched]
}

pub(super) async fn unavailable(response: Response) -> TestResult {
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["pragma"], "no-cache");
    assert!(!response.headers().contains_key("set-cookie"));
    assert!(!response.headers().contains_key("location"));
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?;
    assert_eq!(body["error"], "server_error");
    assert_eq!(body["error_description"], "Subject namespace unavailable");
    for name in [
        "access_token",
        "id_token",
        "logout_token",
        "sub",
        "code",
        "request_uri",
    ] {
        assert!(body.get(name).is_none(), "identity publication: {name}");
    }
    Ok(())
}

pub(super) fn remote() -> axum::extract::ConnectInfo<std::net::SocketAddr> {
    axum::extract::ConnectInfo(([127, 0, 0, 1], 12345).into())
}

pub(super) fn context(
    state: &AppState,
    grant: &str,
    extra: &[(&str, &str)],
) -> TestResult<web::token_endpoint::TokenEndpointContext> {
    let mut params = vec![
        ("grant_type".to_owned(), grant.to_owned()),
        ("client_id".to_owned(), "namespace-client".to_owned()),
    ];
    params.extend(
        extra
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
    );
    let form = web::token_form::token_form_from_params(&params, state.issuer.as_str())
        .map_err(|_| "token form rejected")?;
    let issuer_req = serde_json::from_value(serde_json::to_value(
        params
            .iter()
            .cloned()
            .collect::<std::collections::BTreeMap<_, _>>(),
    )?)?;
    Ok(web::token_endpoint::TokenEndpointContext {
        request_id: "namespace-acceptance".into(),
        params,
        form,
        grant_type: grant.into(),
        client_id: "namespace-client".into(),
        resource: None,
        sender_constraint: crate::policy::SenderConstraint::None,
        enforce_refresh_sender_binding: true,
        authorization_code_grant_allowed: true,
        refresh_grant_allowed: true,
        sender_binding: None,
        issuer_req,
        cnf_for_at: None,
    })
}
