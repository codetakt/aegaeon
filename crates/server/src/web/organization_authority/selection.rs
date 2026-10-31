use super::*;
use crate::organizations::{consent::RootAuthority, AccessRequest, Binding};

pub(in crate::web) async fn select(
    state: &AppState,
    original: &RootAuthority,
    authenticated: &Binding,
    request: &AccessRequest,
    audience: &str,
    parent_expires_at: i64,
) -> Result<selected::SelectedAuthority, Response> {
    state.require_subject_namespace()?;
    let invalid = || {
        super::super::token_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_authorization_details",
            Some("organization selection is not authorized"),
        )
    };
    let now = crate::util::now_unix_epoch_secs()
        .ok()
        .and_then(|v| i64::try_from(v).ok())
        .ok_or_else(|| unavailable(state))?;
    // Access-token TTL is an additional upper bound; never replace the source horizon.
    let ttl = i64::try_from(state.tokens.issuer.access_token_ttl_secs())
        .map_err(|_| unavailable(state))?;
    let maximum = now.checked_add(ttl).ok_or_else(|| unavailable(state))?;
    let expected = projection(state)?;
    let admission =
        crate::organizations::request_work::async_store::current_epoch_owner(state.environment_id)
            .map_err(|_| unavailable(state))?;
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let mut connection = admission
            .connection(&state.db_pool)
            .await
            .map_err(|_| unavailable(state))?;
        let mut tx = connection
            .as_mut()
            .map_err(|_| unavailable(state))?
            .begin()
            .await
            .map_err(|_| unavailable(state))?;
        let value = selected::authorize(
            &mut tx,
            selected::SelectionInput {
                original,
                authenticated,
                request,
                audience,
                parent_expires_at: parent_expires_at.min(maximum),
                now,
            },
        )
        .await
        .map_err(|e| match e {
            crate::organizations::repository::RepositoryError::Authority(_) => invalid(),
            _ => unavailable(state),
        })?;
        recheck_projection(state, &mut tx, &expected).await?;
        admission.admit_commit().map_err(|_| unavailable(state))?;
        tx.commit().await.map_err(|_| unavailable(state))?;
        connection.release().await;
        Ok(value)
    })
    .await
    .map_err(|_| unavailable(state))?
}
