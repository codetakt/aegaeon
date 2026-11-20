use crate::web::hosted::Action;

#[utoipa::path(get, path = "/organization-invitations/hosted", tag = "Organizations",
    description = "First-party invitation landing. Returns no-store HTML to a signed-out browser. Mail proofs travel only in the URL fragment and are removed before any network request. A flow handle may resume an existing session. Navigation has no membership effect.",
    params(("flow" = Option<String>, Query, format = "uuid", description = "Opaque public flow handle")),
    responses((status = 200, description = "Invitation landing", content_type = "text/html")))]
pub(super) fn landing() {}

#[utoipa::path(post, path = "/organization-invitations/hosted/actions", tag = "Organizations",
    description = "Same-origin browser protocol. The anonymous landing establishes CSRF protection before import. Signed-in operations additionally require the per-flow BFF cookie. Send and confirmation require the value issued for that specific decision. Only explicit confirmation can create membership. Return uses an exact destination registered by the domain operator.",
    params(("Origin" = String, Header), ("X-CSRF-Token" = String, Header)),
    security(("hostedBrowserCookie" = [])),
    request_body(content = Action, content_type = "application/json"),
    responses((status = 200, description = "Current screen or explicitly authorized navigation", content_type = "application/json"),
        (status = 400, description = "Invalid request"), (status = 403, description = "Invitation or browser binding refused"),
        (status = 503, description = "Required service unavailable")))]
pub(super) fn action() {}

#[utoipa::path(get, path = "/organization-invitations/hosted/callback", tag = "Organizations",
    description = "Fixed callback for the dedicated invitation client. A successful code or an authorization denial must match a live browser flow, issuer and state. Successful authorization rotates the BFF session.",
    params(("state" = String, Query), ("iss" = String, Query), ("code" = Option<String>, Query),
        ("error" = Option<String>, Query), ("error_description" = Option<String>, Query)),
    security(("hostedBrowserCookie" = [])),
    responses((status = 303, description = "Continue at the local invitation landing without the code"),
        (status = 400, description = "Invalid authorization response"), (status = 403, description = "Browser or authorization refused"),
        (status = 503, description = "Required service unavailable")))]
pub(super) fn callback() {}
