//! Store admission precedes every application middleware. Route scope comes from
//! Axum's matched route, never an untrusted request's replacement issuer/epoch.
use super::AppState;
use crate::organizations::{
    request_work::CapacityClass,
    witness::{
        deployment::dispatch::{Dispatcher, Target},
        work::ResponseLimit,
    },
};
use axum::{
    body::Body,
    extract::{FromRequestParts, MatchedPath, RawPathParams, State},
    http::{Method, Request, StatusCode},
    middleware::Next,
    response::Response,
};
use uuid::Uuid;

#[derive(Clone)]
pub(super) struct Boundary {
    pub state: AppState,
    pub dispatcher: Dispatcher,
}

#[derive(Clone)]
struct Management;

pub(super) fn is_management(req: &Request<Body>) -> bool {
    req.extensions().get::<Management>().is_some()
}

fn unavailable(state: &AppState) -> Response {
    super::no_cache_json_error_with_iss(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        Some("runtime admission unavailable"),
        &state.issuer,
    )
}

fn organization(path: &str) -> bool {
    path.contains("/organization-domains/")
        || path.starts_with("/organizations/")
        || path.starts_with("/organization-support/")
        || path.starts_with("/organization-invitations/")
}

fn classification(path: &str) -> (CapacityClass, ResponseLimit) {
    let management = path.starts_with("/api/v1/") && path.contains("/organization-domains/");
    let class = if management && path.ends_with("/snapshot") {
        CapacityClass::Snapshot
    } else if (management
        && ["/revoke", "/disable", "/suspend", "/delete"]
            .iter()
            .any(|s| path.ends_with(s)))
        || matches!(
            path,
            super::organization_resource::support::REVOKE
                | super::organization_resource::delegated_invitations::REVOKE
        )
    {
        CapacityClass::Revocation
    } else {
        CapacityClass::Ordinary
    };
    (
        class,
        if organization(path) {
            ResponseLimit::Organization
        } else {
            ResponseLimit::General
        },
    )
}

pub(super) async fn outer(
    State(boundary): State<Boundary>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    let Some(path) = req
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_owned())
    else {
        return super::no_cache_json_error_with_iss(
            StatusCode::NOT_FOUND,
            "not_found",
            None,
            &boundary.state.issuer,
        );
    };
    if path == "/health" {
        return next.run(req).await;
    }
    if boundary.state.runtime_restart.is_requested() {
        return unavailable(&boundary.state);
    }
    let target = if path.starts_with("/api/v1/") {
        req.extensions_mut().insert(Management);
        Target::Deployment
    } else {
        Target::Environment(boundary.state.environment_id)
    };
    let (class, limit) = classification(&path);
    let method = req.method().clone();
    let response =
        boundary
            .dispatcher
            .start_serving_http(target, class, method, limit, move || next.run(req));
    match response {
        Ok(execution) => match execution.response().await {
            Ok(response) => response,
            Err(error) => {
                crate::metrics_integration::record_organization_refusal(&error, true);
                unavailable(&boundary.state)
            }
        },
        Err(error) => {
            crate::metrics_integration::record_organization_refusal(&error, false);
            unavailable(&boundary.state)
        }
    }
}

/// Runs inside the parent and after transport validation, before body/database
/// middleware. Global management is already scoped; issuer work already has a child.
pub(super) async fn management_target(
    State(boundary): State<Boundary>,
    req: Request<Body>,
    next: Next,
) -> Response {
    if !is_management(&req) || req.method() == Method::OPTIONS {
        return next.run(req).await;
    }
    if !req.extensions().get::<MatchedPath>().is_some_and(|path| {
        path.as_str()
            .split('/')
            .any(|part| matches!(part, ":environment" | ":environmentId"))
    }) {
        return next.run(req).await;
    }
    let request_id = super::request_id::request_id_from_headers(req.headers());
    let (mut parts, body) = req.into_parts();
    let params = match RawPathParams::from_request_parts(&mut parts, &()).await {
        Ok(params) => params,
        Err(_) => return unavailable(&boundary.state),
    };
    let environment = params
        .iter()
        .find(|(k, _)| matches!(*k, "environment" | "environmentId"));
    let Some((_, environment)) = environment else {
        return next.run(Request::from_parts(parts, body)).await;
    };
    let team = params
        .iter()
        .find(|(k, _)| matches!(*k, "team" | "teamId"))
        .and_then(|(_, value)| Uuid::parse_str(value).ok())
        .filter(|id| !id.is_nil());
    let environment = Uuid::parse_str(environment).ok().filter(|id| !id.is_nil());
    let (Some(team), Some(environment)) = (team, environment) else {
        return super::no_cache_json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            None,
            &boundary.state.issuer,
        );
    };
    if let Err(response) = super::management::authenticate_observed_environment(
        &boundary.state,
        &parts.headers,
        team,
        &request_id,
    )
    .await
    {
        return response;
    }
    if !boundary.dispatcher.contains_environment(environment) {
        return super::management::unselected_observed_environment(&request_id);
    }
    let (_, limit) = classification(
        parts
            .extensions
            .get::<MatchedPath>()
            .map_or("", MatchedPath::as_str),
    );
    let method = parts.method.clone();
    let req = Request::from_parts(parts, body);
    match boundary
        .dispatcher
        .start_child_http(environment, method, limit, move || next.run(req))
    {
        Ok(execution) => execution.response().await.unwrap_or_else(|error| {
            crate::metrics_integration::record_organization_refusal(&error, true);
            unavailable(&boundary.state)
        }),
        Err(error) => {
            crate::metrics_integration::record_organization_refusal(&error, false);
            unavailable(&boundary.state)
        }
    }
}
