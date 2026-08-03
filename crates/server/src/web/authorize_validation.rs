use super::no_cache_redirect_response;
use super::oauth_errors::registry_state_error_response;
use crate::authcode::types::AuthorizationRequest as AuthzReq;
use crate::client_registry::ClientRegistry;
use crate::config::ServerConfig;
use crate::oidc::OidcConfig;
use crate::util;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(Clone, Copy)]
pub(super) struct AuthorizeErrorContext<'a> {
    pub(super) cfg: &'a ServerConfig,
    pub(super) clients: &'a ClientRegistry,
    pub(super) req: &'a AuthzReq,
    pub(super) response_mode: crate::form_post::ResponseMode,
    pub(super) issuer_base: &'a str,
    pub(super) state_for_echo: Option<&'a str>,
}

impl<'a> AuthorizeErrorContext<'a> {
    pub(super) fn for_request(
        cfg: &'a ServerConfig,
        clients: &'a ClientRegistry,
        req: &'a AuthzReq,
        response_mode: crate::form_post::ResponseMode,
        issuer_base: &'a str,
    ) -> Self {
        Self::with_state_for_echo(
            cfg,
            clients,
            req,
            response_mode,
            issuer_base,
            req.state.as_deref(),
        )
    }

    pub(super) fn with_state_for_echo(
        cfg: &'a ServerConfig,
        clients: &'a ClientRegistry,
        req: &'a AuthzReq,
        response_mode: crate::form_post::ResponseMode,
        issuer_base: &'a str,
        state_for_echo: Option<&'a str>,
    ) -> Self {
        Self {
            cfg,
            clients,
            req,
            response_mode,
            issuer_base,
            state_for_echo,
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct AuthorizeValidationContext<'a> {
    pub(super) error: AuthorizeErrorContext<'a>,
    pub(super) oidc: Option<&'a OidcConfig>,
    pub(super) require_state: bool,
}

pub(super) fn authorize_error_response(
    ctx: AuthorizeErrorContext<'_>,
    error: &str,
    description: Option<&str>,
) -> Response {
    if ctx.response_mode == crate::form_post::ResponseMode::FormPost {
        if let Some(ref ru) = ctx.req.redirect_uri {
            let redirect_uri_valid = match ctx
                .clients
                .try_validate_redirect_uri(&ctx.req.client_id, ru)
            {
                Ok(valid) => valid,
                Err(error) => {
                    return registry_state_error_response(
                        ctx.issuer_base,
                        "authorize_error_validate_redirect_uri",
                        error,
                    );
                }
            };
            if redirect_uri_valid {
                if let Ok(resp) = crate::form_post::authorization_error(
                    ru,
                    error,
                    description,
                    ctx.state_for_echo,
                    ctx.issuer_base,
                ) {
                    return resp;
                }
            }
        }
    }

    if ctx.cfg.strict_authorize_redirect {
        if let Some(ref ru) = ctx.req.redirect_uri {
            let redirect_uri_valid = match ctx
                .clients
                .try_validate_redirect_uri(&ctx.req.client_id, ru)
            {
                Ok(valid) => valid,
                Err(error) => {
                    return registry_state_error_response(
                        ctx.issuer_base,
                        "authorize_error_validate_redirect_uri",
                        error,
                    );
                }
            };
            if redirect_uri_valid {
                let url = util::append_error_and_state(
                    ru,
                    error,
                    description,
                    ctx.state_for_echo,
                    ctx.issuer_base,
                );
                return no_cache_redirect_response(&url);
            }
        }
    }

    let mut body = json!({ "error": error, "iss": ctx.issuer_base });
    if let Some(desc) = description {
        body["error_description"] = json!(desc);
    }
    if let Some(state) = ctx.state_for_echo {
        body["state"] = json!(state);
    }

    let mut response = (StatusCode::BAD_REQUEST, Json(body)).into_response();
    util::apply_no_cache_headers(&mut response);
    response
}

pub(super) fn validate_authorize_request(
    ctx: AuthorizeValidationContext<'_>,
) -> Result<(), Response> {
    let req = ctx.error.req;
    let clients = ctx.error.clients;

    if req.response_type != "code" {
        return Err(authorize_error_response(
            ctx.error,
            "unsupported_response_type",
            Some("response_type must be 'code'"),
        ));
    }

    if ctx.require_state {
        let missing_state = req.state.as_ref().is_none_or(|s| s.trim().is_empty());
        if missing_state {
            return Err(authorize_error_response(
                AuthorizeErrorContext {
                    state_for_echo: None,
                    ..ctx.error
                },
                "invalid_request",
                Some("state is required"),
            ));
        }
    }

    if let Some(ref ru) = req.redirect_uri {
        let redirect_uri_valid = clients
            .try_validate_redirect_uri(&req.client_id, ru)
            .map_err(|error| {
                registry_state_error_response(
                    ctx.error.issuer_base,
                    "authorize_validate_redirect_uri",
                    error,
                )
            })?;
        if !redirect_uri_valid {
            let mut err = json!({ "error": "invalid_redirect_uri", "iss": ctx.error.issuer_base });
            if let Some(ref s) = req.state {
                err["state"] = json!(s);
            }
            return Err((StatusCode::BAD_REQUEST, Json(err)).into_response());
        }
    }

    if !clients
        .try_allows_grant(&req.client_id, "authorization_code")
        .map_err(|error| {
            registry_state_error_response(ctx.error.issuer_base, "authorize_allows_grant", error)
        })?
    {
        return Err(authorize_error_response(
            ctx.error,
            "unauthorized_client",
            Some("client is not allowed to use authorization_code grant"),
        ));
    }

    if let Some(ref scope) = req.scope {
        let requested = crate::oauth_scope::parse_scope_string(scope).map_err(|error| {
            authorize_error_response(ctx.error, "invalid_scope", Some(&error.to_string()))
        })?;

        if requested.iter().any(|s| s == "openid") {
            match ctx.oidc {
                Some(oidc_cfg) => {
                    if oidc_cfg.require_nonce
                        && req
                            .nonce
                            .as_ref()
                            .is_none_or(|nonce| nonce.trim().is_empty())
                    {
                        return Err(authorize_error_response(
                            ctx.error,
                            "invalid_request",
                            Some("nonce is required when requesting the openid scope"),
                        ));
                    }
                }
                None => {
                    return Err(authorize_error_response(
                        ctx.error,
                        "invalid_scope",
                        Some("openid scope is not enabled"),
                    ));
                }
            }
        }

        if !clients
            .try_validate_scope_subset(&req.client_id, &requested)
            .map_err(|error| {
                registry_state_error_response(
                    ctx.error.issuer_base,
                    "authorize_validate_scope_subset",
                    error,
                )
            })?
        {
            return Err(authorize_error_response(
                ctx.error,
                "invalid_scope",
                Some("requested scope is not permitted"),
            ));
        }
    }

    Ok(())
}
