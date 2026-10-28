use super::{
    positive_support as p,
    positive_upstream_supplier::{Supplier, CLIENT},
    support::TestResult,
};
use crate::{
    management::types::{PolicyDocument, PolicySenderConstraint},
    web::{test_support as t, AppState},
};
use serde_json::json;

pub(super) const CONNECTION: &str = "namespace-positive-upstream";

pub(super) async fn fixture(supplier: &Supplier) -> TestResult<(AppState, uuid::Uuid, String)> {
    let (pool, env) = p::pool_environment().await?;
    let policy = PolicyDocument {
        sender_constraint: PolicySenderConstraint::None,
        ..PolicyDocument::default()
    };
    sqlx::query("UPDATE aegaeon.configuration_versions SET configuration_document=jsonb_set(jsonb_set(configuration_document,'{policy}',$1),'{federation}',$2) WHERE environment_id=$3 AND status='ACTIVE'")
        .bind(serde_json::to_value(policy)?).bind(json!({"upstreamIssuer":supplier.issuer,"clientId":CLIENT,"redirectUri":format!("{}/oauth/upstream/{CONNECTION}/callback",env.issuer_url),"jitProvisioning":{"enabled":true,"requireVerifiedEmail":false}}))
        .bind(env.environment_id).execute(&pool).await?;
    let connection: uuid::Uuid = sqlx::query_scalar("INSERT INTO aegaeon.connections(environment_id,configuration_version_id,connection_identifier,name,issuer_url,client_id,client_auth_method,status) SELECT id,active_configuration_version_id,$2,$2,$3,$4,'none','ACTIVE' FROM aegaeon.environments WHERE id=$1 RETURNING id")
        .bind(env.environment_id).bind(CONNECTION).bind(&supplier.issuer).bind(CLIENT).fetch_one(&pool).await?;
    sqlx::query("INSERT INTO aegaeon.oauth_profiles(environment_id,configuration_version_id,name,profile_type,is_default,require_pkce,require_state_parameter,require_iss_parameter,sender_constrained,allowed_grant_types,token_endpoint_auth_methods_allowed,status) SELECT id,active_configuration_version_id,'namespace-upstream','UPSTREAM',true,true,true,true,'NONE',ARRAY['authorization_code','refresh_token'],ARRAY['none'],'ACTIVE' FROM aegaeon.environments WHERE id=$1")
        .bind(env.environment_id).execute(&pool).await?;
    let caller = format!("namespace-refresh-{}", env.environment_id);
    let mut client = t::sample_registered_client(&caller);
    client.allowed_scopes = vec!["openid".into(), "read".into()];
    crate::dcr_persistence::create_dynamic_registration(
        &pool,
        &env.issuer_host,
        &client,
        &["code".into()],
        "namespace-upstream-registration",
        "namespace-upstream-fixture",
    )
    .await?;
    let state = p::bind_policy(t::test_app_state(pool, &env).await?).await?;
    // Exercise supported cached Discovery. All endpoint/profile/issuer checks still run;
    // token and JWKS responses are obtained through actual loopback HTTP requests.
    state
        .upstream
        .discovery_cache
        .try_insert(&supplier.issuer, supplier.discovery()?)?;
    Ok((state, connection, caller))
}
