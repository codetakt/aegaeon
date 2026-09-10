use crate::web::{
    authorize_context::AuthorizeRequestContext, local_auth_support::local_auth_response,
};
use axum::{http::StatusCode, response::Response};

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub(super) fn form(ctx: &AuthorizeRequestContext, transaction: &str, issuer: &str) -> Response {
    let scope = ctx.req.scope.as_deref().unwrap_or("");
    let target = ctx.req.resource.clone().unwrap_or_else(|| {
        if scope.split(' ').any(|s| s == "openid") {
            format!("{}/userinfo", issuer.trim_end_matches('/'))
        } else {
            ctx.req.client_id.clone()
        }
    });
    let offline = if scope.split(' ').any(|s| s == "offline_access") {
        "<p>This application can continue to access these resources when you are not signed in. Approve only if you want to allow that access.</p>"
    } else {
        ""
    };
    local_auth_response(
        StatusCode::OK,
        format!(
            r#"<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Allow application access</title><main><h1>Allow application access</h1>
<p>Application: <strong>{client}</strong></p><p>Resource: {target}</p>
<p>Requested permissions: {scope}</p>{offline}
<form method="post" action="/auth/consent">
<input type="hidden" name="transaction" value="{transaction}">
<button type="submit" name="decision" value="approve">Allow access</button>
<button type="submit" name="decision" value="deny">Deny access</button>
</form></main></html>"#,
            client = escape(&ctx.req.client_id),
            target = escape(&target),
            scope = escape(scope),
            transaction = escape(transaction)
        ),
    )
}
