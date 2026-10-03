use super::{
    positive_support as p,
    positive_upstream_supplier::{Supplier, SUBJECT},
    support::{unavailable, unavailable_states, TestResult},
};
use crate::web::AppState;
use axum::http::StatusCode;
use uuid::Uuid;

pub(super) type Link = (Uuid, String, String, i64, Vec<u8>);

pub(super) async fn link(state: &AppState) -> TestResult<Link> {
    Ok(sqlx::query_as("SELECT u.id,u.subject,al.upstream_sub_hash,al.upstream_refresh_token_generation,al.upstream_refresh_token_encrypted FROM aegaeon.account_links al JOIN aegaeon.end_users u ON u.id=al.end_user_id WHERE al.environment_id=$1 AND u.environment_id=al.environment_id")
        .bind(state.environment_id).fetch_one(&state.db_pool).await?)
}

pub(super) async fn assert_callback(
    state: &AppState,
    supplier: &Supplier,
    connection: Uuid,
    cookie: &str,
) -> TestResult<Link> {
    let row = link(state).await?;
    assert!(row.1.starts_with("upstream:"));
    assert_ne!(row.1, SUBJECT);
    assert_eq!(
        row.2,
        crate::upstream::upstream_subject_link_hash(&supplier.issuer, SUBJECT)
    );
    assert_eq!(row.3, 1);
    let opened = crate::web::upstream_refresh_token_envelope::open_upstream_refresh_token(
        &row.4,
        state.environment_id,
        &supplier.issuer,
        &row.2,
        connection,
        row.3,
    )
    .map_err(|error| format!("{error:?}"))?;
    assert_eq!(opened, "namespace-refresh-initial");
    assert!(
        crate::web::upstream_refresh_token_envelope::open_upstream_refresh_token(
            &row.4,
            Uuid::new_v4(),
            &supplier.issuer,
            &row.2,
            connection,
            row.3,
        )
        .is_err()
    );
    assert!(
        crate::web::upstream_refresh_token_envelope::open_upstream_refresh_token(
            &row.4,
            state.environment_id,
            &supplier.issuer,
            &row.2,
            Uuid::new_v4(),
            row.3,
        )
        .is_err()
    );
    let audits: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.audit_events WHERE environment_id=$1 AND event_type='upstream_auth' AND outcome='success'")
        .bind(state.environment_id).fetch_one(&state.db_pool).await?;
    assert_eq!(audits, 1);
    let sessions = state.browser_auth.auth_sessions.try_list_for_user(&row.1)?;
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].1.user_id, row.1);
    assert!(cookie.starts_with(&format!("aegaeon_auth_session={};", sessions[0].0)));
    Ok(row)
}

pub(super) async fn refresh(
    state: &AppState,
    supplier: &Supplier,
    connection: Uuid,
    original: Link,
    caller: &str,
) -> TestResult {
    let token = p::bearer(
        state,
        caller,
        &original.1,
        crate::resource_audience::upstream_refresh(&state.issuer),
        "read",
        None,
    )
    .await?;
    let auth = format!("Bearer {token}");
    let path = format!(
        "/oauth/upstream/refresh?{}",
        p::form(&[("upstream_issuer", &supplier.issuer)])
    );
    for denied in unavailable_states(state) {
        unavailable(p::send(&denied, "POST", &path, None, Some(&auth), String::new()).await?)
            .await?;
    }
    assert_eq!(link(state).await?, original);
    assert_eq!(
        supplier
            .observed
            .lock()
            .map_err(|e| std::io::Error::other(e.to_string()))?
            .refresh_exchanges,
        0
    );
    let response = p::json(
        p::send(state, "POST", &path, None, Some(&auth), String::new()).await?,
        StatusCode::OK,
    )
    .await?;
    assert_eq!(response["upstream_issuer"], supplier.issuer);
    assert_eq!(
        response["upstream_access_token"],
        "namespace-upstream-access-refreshed"
    );
    assert_eq!(response["token_type"], "Bearer");
    assert_eq!(response["refresh_token_rotated"], true);
    assert!(response["upstream_id_token"].as_str().is_some());
    assert!(response.get("refresh_token").is_none());
    let rotated = link(state).await?;
    assert_eq!(rotated.0, original.0);
    assert_eq!(rotated.1, original.1);
    assert_eq!(rotated.2, original.2);
    assert_eq!(rotated.3, 2);
    assert_ne!(rotated.4, original.4);
    let opened = crate::web::upstream_refresh_token_envelope::open_upstream_refresh_token(
        &rotated.4,
        state.environment_id,
        &supplier.issuer,
        &rotated.2,
        connection,
        rotated.3,
    )
    .map_err(|error| format!("{error:?}"))?;
    assert_eq!(opened, "namespace-refresh-rotated");
    let seen = supplier
        .observed
        .lock()
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    assert_eq!(seen.code_exchanges, 1);
    assert_eq!(seen.refresh_exchanges, 1);
    assert!(seen.jwks_requests >= 1);
    assert_eq!(seen.rejected, 0);
    Ok(())
}
