use super::support::{context, fixture, remote, unavailable, unavailable_states, TestResult};
use crate::web::{self, AppState};
use axum::{
    extract::{OriginalUri, Path, Query, State},
    http::HeaderMap,
    response::Response,
    Form,
};
use serde_json::json;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL with restricted runtime"]
async fn pg_namespace_all_direct_handlers_refuse_missing_and_mismatched_permits() -> TestResult {
    let (state, _) = fixture().await?;
    for denied in unavailable_states(&state) {
        direct_protocol(&denied).await?;
        direct_browser(&denied).await?;
        direct_device(&denied).await?;
        direct_upstream(&denied).await?;
        direct_registration(&denied).await?;
    }
    Ok(())
}

async fn direct_protocol(s: &AppState) -> TestResult {
    let st = || State(s.clone());
    let uri = || OriginalUri("/token".parse().unwrap());
    let h = HeaderMap::new;
    let form = || {
        Ok(Form(vec![(
            "grant_type".into(),
            "client_credentials".into(),
        )]))
    };
    unavailable(web::authorize_endpoint::authorize(st(), remote(), h(), uri()).await).await?;
    unavailable(web::token_endpoint::token(st(), remote(), uri(), h(), form()).await).await?;
    unavailable(web::par_endpoint::par(st(), remote(), uri(), h(), form()).await).await?;
    unavailable(web::userinfo::userinfo_get(st(), remote(), uri(), h()).await).await?;
    unavailable(web::userinfo::userinfo_post(st(), remote(), uri(), h(), form()).await).await?;
    unavailable(web::token_lifecycle::introspect(st(), remote(), uri(), h(), form()).await).await?;
    unavailable(web::resource_endpoint::resource(st(), remote(), uri(), h()).await).await?;
    unavailable(
        web::application_authorization::authorization_context(st(), remote(), uri(), h()).await,
    )
    .await?;
    unavailable(web::logout_endpoint::logout(st(), remote(), uri(), h()).await).await?;
    Ok(())
}

async fn direct_browser(s: &AppState) -> TestResult {
    let st = || State(s.clone());
    let uri = || OriginalUri("/auth/login".parse().unwrap());
    let h = HeaderMap::new;
    let form = || Ok(Form(vec![]));
    unavailable(
        web::local_auth::local_login_get(
            st(),
            uri(),
            h(),
            Query(serde_json::from_value(json!({}))?),
        )
        .await,
    )
    .await?;
    unavailable(web::local_auth::local_login_post(st(), remote(), h(), form()).await).await?;
    unavailable(web::local_auth::local_logout_post(st(), h()).await).await?;
    unavailable(
        web::local_auth_recovery::local_activate_get(st(), uri(), Query(Default::default())).await,
    )
    .await?;
    unavailable(web::local_auth_recovery::local_activate_post(st(), h(), form()).await).await?;
    unavailable(
        web::local_auth_recovery::local_password_reset_get(st(), uri(), Query(Default::default()))
            .await,
    )
    .await?;
    unavailable(web::local_auth_recovery::local_password_reset_post(st(), h(), form()).await)
        .await?;
    unavailable(web::authorize_endpoint::consent_submit(st(), h(), form()).await).await?;
    Ok(())
}

async fn direct_device(s: &AppState) -> TestResult {
    let st = || State(s.clone());
    let uri = || OriginalUri("/device".parse().unwrap());
    let h = HeaderMap::new;
    let form = || Ok(Form(vec![]));
    unavailable(web::device_flow::device_authorization(st(), remote(), uri(), h(), form()).await)
        .await?;
    unavailable(web::device_flow::device_verify_get(st(), uri()).await).await?;
    unavailable(web::device_flow::device_verify_post(st(), remote(), uri(), h(), form()).await)
        .await?;
    unavailable(web::device_flow::device_approve(st(), remote(), uri(), h(), form()).await).await?;
    unavailable(web::device_flow::device_deny(st(), remote(), uri(), h(), form()).await).await?;
    Ok(())
}

async fn direct_upstream(s: &AppState) -> TestResult {
    let st = || State(s.clone());
    let uri = || OriginalUri("/oauth/upstream/example/callback".parse().unwrap());
    let h = HeaderMap::new;
    unavailable(
        web::upstream_authorize::upstream_authorize(
            st(),
            remote(),
            h(),
            uri(),
            Path("example".into()),
            Query(serde_json::from_value(json!({}))?),
        )
        .await,
    )
    .await?;
    unavailable(
        web::upstream_callback::upstream_callback(
            st(),
            remote(),
            h(),
            uri(),
            Path("example".into()),
            Query(serde_json::from_value(
                json!({"state":"retained", "code":"code"}),
            )?),
        )
        .await,
    )
    .await?;
    unavailable(
        web::upstream_refresh::upstream_refresh(
            st(),
            remote(),
            uri(),
            h(),
            Query(serde_json::from_value(json!({}))?),
        )
        .await,
    )
    .await?;
    unavailable(
        web::logout_endpoint::upstream_logout_callback(
            st(),
            remote(),
            h(),
            Query(serde_json::from_value(json!({"state":"retained"}))?),
        )
        .await,
    )
    .await?;
    Ok(())
}

async fn direct_registration(s: &AppState) -> TestResult {
    let st = || State(s.clone());
    let uri = || OriginalUri("/register/namespace-client".parse().unwrap());
    let h = HeaderMap::new;
    let client = || Path("namespace-client".into());
    unavailable(web::dcr_registration::register(st(), uri(), h(), "{}".into()).await).await?;
    unavailable(web::dcr_configuration::register_read(st(), client(), uri(), h()).await).await?;
    unavailable(
        web::dcr_configuration::register_update(st(), client(), uri(), h(), "{}".into()).await,
    )
    .await?;
    unavailable(web::dcr_configuration::register_delete(st(), client(), uri(), h()).await).await?;
    Ok(())
}

pub(super) async fn grant(
    s: &AppState,
    grant_type: &str,
    extra: &[(&str, &str)],
) -> TestResult<Response> {
    let ctx = context(s, grant_type, extra)?;
    Ok(match grant_type {
        "authorization_code" => {
            web::token_authorization_code::handle_token_authorization_code_grant(s, &ctx).await
        }
        "refresh_token" => web::token_refresh::handle_token_refresh_grant(s, &ctx).await,
        "client_credentials" => {
            web::token_client_credentials::handle_token_client_credentials_grant(s, &ctx).await
        }
        "urn:ietf:params:oauth:grant-type:device_code" => {
            web::token_device_code::handle_token_device_code_grant(s, &ctx).await
        }
        "urn:ietf:params:oauth:grant-type:jwt-bearer" => {
            web::token_jwt_bearer::handle_token_jwt_bearer_grant(s, &ctx).await
        }
        "urn:ietf:params:oauth:grant-type:token-exchange" => {
            web::token_exchange::handle_token_exchange_grant(s, &ctx, s.issuer.as_str()).await
        }
        _ => return Err("unknown acceptance grant".into()),
    })
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL with restricted runtime"]
async fn pg_namespace_all_six_direct_grants_refuse_missing_and_mismatched_permits() -> TestResult {
    let (state, _) = fixture().await?;
    for denied in unavailable_states(&state) {
        for kind in [
            "authorization_code",
            "refresh_token",
            "client_credentials",
            "urn:ietf:params:oauth:grant-type:device_code",
            "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ] {
            unavailable(grant(&denied, kind, &[]).await?).await?;
        }
    }
    Ok(())
}
