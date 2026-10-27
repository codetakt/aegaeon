use super::{rendering, unavailable, Browser};
use crate::web::{
    form_helpers::apply_auth_session_clear_cookie,
    logout_context::LogoutQuery,
    logout_dispatch::dispatch_backchannel_logout_if_enabled,
    upstream_logout_sessions::{
        build_upstream_logout_redirect_target, build_upstream_logout_redirect_target_with_relay,
    },
    AppState,
};
use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};

async fn target(
    state: &AppState,
    browser: &Browser,
    query: &LogoutQuery,
    client: Option<&str>,
    request_id: &str,
) -> Result<Option<String>, Response> {
    let upstream = browser
        .0
        .as_ref()
        .and_then(|(_, s)| s.upstream_logout.as_ref());
    if let (Some(upstream), Some(redirect)) = (upstream, query.post_logout_redirect_uri.as_deref())
    {
        if let Some(relay) = build_upstream_logout_redirect_target_with_relay(
            state,
            upstream,
            client,
            redirect,
            query.state.as_deref(),
            browser.subject(),
            request_id,
        )
        .await?
        {
            return Ok(Some(relay));
        }
    }
    if let Some(redirect) = query.post_logout_redirect_uri.as_deref() {
        return Ok(Some(crate::util::append_state(
            redirect,
            query.state.as_deref(),
        )));
    }
    Ok(upstream.and_then(|s| {
        build_upstream_logout_redirect_target(s, state.cfg.upstream().outbound_allowed_domains())
    }))
}

pub(super) async fn complete(
    state: &AppState,
    browser: &Browser,
    query: &LogoutQuery,
    client: Option<&str>,
    request_id: &str,
) -> Result<Response, Response> {
    // Prepare every return target (including relay persistence) before deleting
    // either session. This is reached only after the one-use approval wins.
    let mut response = match target(state, browser, query, client, request_id).await? {
        Some(location) => {
            let value = HeaderValue::from_str(&location)
                .map_err(|_| unavailable("redirect_preparation"))?;
            let mut response = StatusCode::SEE_OTHER.into_response();
            response.headers_mut().insert(header::LOCATION, value);
            response
        }
        None => rendering::result(false),
    };
    if let Some((sid, _)) = &browser.0 {
        let sessions = state
            .oidc
            .sessions
            .as_ref()
            .ok_or_else(|| unavailable("oidc_session_store_missing"))?;
        let event = sessions
            .try_logout_by_auth_session_id_async(sid.clone())
            .await
            .map_err(|_| unavailable("oidc_session_logout"))?;
        state
            .browser_auth
            .auth_sessions
            .try_delete_async(sid.clone())
            .await
            .map_err(|_| unavailable("auth_session_delete"))?;
        let cfg = state
            .oidc
            .config
            .as_ref()
            .ok_or_else(|| unavailable("oidc_configuration"))?;
        dispatch_backchannel_logout_if_enabled(state, cfg, event.into_iter().collect()).await;
    }
    crate::util::apply_no_cache_headers(&mut response);
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    apply_auth_session_clear_cookie(&mut response);
    Ok(response)
}
