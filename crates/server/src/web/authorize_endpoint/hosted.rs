//! Resolve first-party invitation authorization from the encrypted pending BFF
//! transaction at both consent rendering and code issuance.
use super::session::AuthorizeSessionState;
use crate::{
    organizations::{operators::mutations::delivery, request_work::async_store, Scope},
    web::{
        authorize_context::AuthorizeRequestContext,
        hosted_oauth::{self, Authorization, Error},
        AppState,
    },
};
use std::time::Duration;

pub(super) async fn authorization(
    state: &AppState,
    ctx: &AuthorizeRequestContext,
    session: &AuthorizeSessionState,
) -> Result<Option<Authorization>, Error> {
    let Some(domain) = hosted_oauth::domain_for_client(&ctx.req.client_id) else {
        return Ok(None);
    };
    if !ctx.reauthenticated
        || !ctx.prompt.contains("login")
        || !ctx.prompt.contains("consent")
        || ctx.response_mode != crate::form_post::ResponseMode::Query
        || !state.cfg.strict_authorize_redirect
        || !state.cfg.security_policy.retain_refresh_chain()
    {
        return Err(Error::Refused);
    }
    let oauth_state = ctx
        .req
        .state
        .as_deref()
        .filter(|s| s.len() == 43)
        .ok_or(Error::Refused)?;
    let auth = crate::web::hosted::authorization_for_state(state, oauth_state)
        .await
        .map_err(|_| Error::Unavailable)?
        .ok_or(Error::Refused)?;
    auth.matches(&ctx.req, &state.issuer, session.auth_time_epoch_secs)?;
    if auth.domain != domain
        || !state
            .cfg
            .token_exchange
            .hosted_invitation_rule(&state.issuer, &ctx.req.client_id)
    {
        return Err(Error::Refused);
    }
    let admission =
        async_store::current_epoch_owner(state.environment_id).map_err(|_| Error::Unavailable)?;
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut connection = admission
            .connection(&state.db_pool)
            .await
            .map_err(|_| Error::Unavailable)?;
        let mut tx = connection.begin().await.map_err(|_| Error::Unavailable)?;
        let scope = Scope {
            environment_id: state.environment_id,
            domain_id: domain,
        };
        let reg = delivery::hosted_current(&mut tx, scope)
            .await
            .map_err(|_| Error::Refused)?;
        if reg.issuer != auth.issuer || reg.client_id != ctx.req.client_id {
            return Err(Error::Refused);
        }
        tx.commit().await.map_err(|_| Error::Unavailable)?;
        connection.release().await;
        Ok(Some(auth))
    })
    .await
    .map_err(|_| Error::Unavailable)?
}
