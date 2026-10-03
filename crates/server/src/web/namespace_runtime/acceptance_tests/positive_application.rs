use super::{
    positive_support as p,
    support::{unavailable, unavailable_states, TestResult},
};
use crate::{
    management::types::{PolicyDocument, PolicySenderConstraint},
    web::test_support as t,
};
use axum::http::StatusCode;
use serde_json::json;
use std::sync::Arc;

async fn fixture() -> TestResult<(
    crate::web::AppState,
    String,
    crate::application_authorization::inorii::Grant,
)> {
    let (pool, env) = p::pool_environment().await?;
    t::seed_oidc_configuration(
        &pool,
        &env,
        PolicyDocument {
            sender_constraint: PolicySenderConstraint::None,
            oidc_enabled: true,
            ..PolicyDocument::default()
        },
        "namespace-positive-application",
    )
    .await?;
    let audience = crate::resource_audience::userinfo(&env.issuer_url);
    t::seed_test_projection(
        &pool,
        &env,
        "namespace-app-client",
        "namespace-app-user",
        json!([audience]),
        json!({"roles":["USER"],"organization_roles":[]}),
    )
    .await?;
    let mut state = t::test_app_state(pool, &env).await?;
    state.application_authority = Some(Arc::new(crate::application_authorization::Authority {
        projections: state.db_pool.clone(),
        memberships: None,
    }));
    let state = p::bind_policy(state).await?;
    let grant = crate::application_authorization::store::capture(
        &state.db_pool,
        env.environment_id,
        &env.issuer_url,
        "namespace-app-client",
        "namespace-app-user",
    )
    .await?
    .ok_or("projection")?;
    let token = p::bearer(
        &state,
        "namespace-app-client",
        "namespace-app-user",
        audience,
        "openid",
        Some(grant.clone()),
    )
    .await?;
    Ok((state, token, grant))
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL"]
async fn namespace_positive_application_authorization_preserves_current_grant() -> TestResult {
    let (state, token, grant) = fixture().await?;
    let authorization = format!("Bearer {token}");
    for denied in unavailable_states(&state) {
        unavailable(
            p::send(
                &denied,
                "GET",
                "/application/authorization",
                None,
                Some(&authorization),
                String::new(),
            )
            .await?,
        )
        .await?;
    }
    let response = p::json(
        p::send(
            &state,
            "GET",
            "/application/authorization",
            None,
            Some(&authorization),
            String::new(),
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    assert_eq!(response["iss"], state.issuer.as_str());
    assert_eq!(response["sub"], "namespace-app-user");
    assert_eq!(response["client_id"], "namespace-app-client");
    assert_eq!(
        response[crate::application_authorization::inorii::CLAIM_NAME],
        serde_json::to_value(grant.claims)?
    );
    sqlx::query("UPDATE aegaeon.application_authorizations SET enabled=false,revision=2,source_revision=2 WHERE environment_id=$1")
        .bind(state.environment_id).execute(&state.db_pool).await?;
    let refused = p::json(
        p::send(
            &state,
            "GET",
            "/application/authorization",
            None,
            Some(&authorization),
            String::new(),
        )
        .await?,
        StatusCode::UNAUTHORIZED,
    )
    .await?;
    assert_eq!(refused["error"], "invalid_token");
    assert!(refused.get("sub").is_none());
    Ok(())
}
