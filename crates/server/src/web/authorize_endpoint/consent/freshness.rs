use super::{error, storage, AppState, AuthorizeRequestContext, AuthorizeSessionState};
use crate::organizations::{repository::RepositoryError, AuthorityError};
use crate::web::{
    authorize_login_redirect::build_local_login_redirect, authorize_reauthentication,
};
use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};

pub(super) enum Failure {
    Response(Response),
    StaleAuthentication,
}
impl From<Response> for Failure {
    fn from(value: Response) -> Self {
        Self::Response(value)
    }
}
impl Failure {
    pub(super) fn from_repository(
        value: &RepositoryError,
        denied: impl FnOnce() -> Response,
    ) -> Self {
        match value {
            RepositoryError::Authority(AuthorityError::StaleAuthentication) => {
                Self::StaleAuthentication
            }
            RepositoryError::Authority(_) => Self::Response(denied()),
            _ => Self::Response(storage::unavailable()),
        }
    }
}

pub(super) async fn consume_login(
    state: &AppState,
    ctx: &mut AuthorizeRequestContext,
) -> Result<(), Response> {
    if let Some(login) = ctx.pending_organization_login.take() {
        login
            .consume(state, ctx.reauthentication_session.as_ref())
            .await?;
    }
    Ok(())
}

pub(super) async fn after_submission<T>(
    result: Result<T, Failure>,
    state: &AppState,
    ctx: &AuthorizeRequestContext,
    session: &AuthorizeSessionState,
    pending: &storage::Pending,
) -> Result<T, Response> {
    match result {
        Ok(value) => Ok(value),
        Err(Failure::Response(response)) => Err(response),
        Err(Failure::StaleAuthentication) => Err(retry(state, ctx, session, Some(pending)).await),
    }
}

pub(super) async fn retry(
    state: &AppState,
    ctx: &AuthorizeRequestContext,
    session: &AuthorizeSessionState,
    pending: Option<&storage::Pending>,
) -> Response {
    if ctx.prompt.contains("none")
        || (session.is_federated
            && (session.original_authentication.is_none() || ctx.reauthenticated))
    {
        if let Some(login) = &ctx.pending_organization_login {
            if let Err(response) = login
                .consume(state, ctx.reauthentication_session.as_ref())
                .await
            {
                return response;
            }
        }
        return error(
            state,
            ctx,
            "login_required",
            "fresh authentication is required",
        );
    }
    let Some(sid) = session.session_id.as_deref() else {
        return storage::invalid();
    };
    let consent = pending.map(|previous| authorize_reauthentication::PreviousConsent {
        id: previous.id,
        sid,
        subject: &session.user_id,
        snapshot: &previous.snapshot,
    });
    let acr = match super::super::authorize_selected_acr(state, ctx, &state.issuer) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let upstream_path = match session.original_authentication.as_ref() {
        Some(prior) => {
            match authorize_reauthentication::federated::sign_in_path(state, prior).await {
                Ok(path) => Some(path),
                Err(response) => return response,
            }
        }
        None => None,
    };
    let (resume, cookie) = match authorize_reauthentication::start_fresh_organization_login(
        state,
        ctx,
        consent.as_ref(),
        session.original_authentication.as_ref(),
    )
    .await
    {
        Ok(handles) => handles,
        Err(response) => return response,
    };
    let login = match upstream_path {
        Some(path) => {
            let mut query = url::form_urlencoded::Serializer::new(String::new());
            query.append_pair("return_to", &resume);
            if let Some(acr) = &acr {
                query.append_pair("acr_values", acr);
            }
            format!("{path}?{}", query.finish())
        }
        None => build_local_login_redirect(&resume, acr.as_deref()),
    };
    let mut response = if ctx.reauthenticated {
        crate::web::local_auth_support::local_auth_response(StatusCode::OK,
            crate::web::render_local_result_page("Sign in again",
                "Your sign-in was too early for this request. Continue when you are ready to sign in again.", Some(&login)))
    } else {
        let mut response = StatusCode::FOUND.into_response();
        let Ok(location) = HeaderValue::from_str(&login) else {
            return storage::invalid();
        };
        response.headers_mut().insert(header::LOCATION, location);
        response
    };
    let Ok(value) = HeaderValue::from_str(&cookie) else {
        return storage::invalid();
    };
    response.headers_mut().append(header::SET_COOKIE, value);
    crate::util::apply_no_cache_headers(&mut response);
    response
}
