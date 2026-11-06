use super::*;

#[derive(serde::Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct IdentityForm {
    /// request or complete; unknown fields and duplicates are refused.
    action: String,
    csrf_token: String,
    /// Required for request: registration or password_recovery.
    purpose: Option<crate::organizations::invitations::enrollment::Purpose>,
    invitation_capability: Option<String>,
    /// Required only for password recovery. No implicit account selection.
    login_identifier: Option<String>,
    request_key: Option<String>,
    #[schema(format = "uuid")]
    request_id: Option<String>,
    proof: Option<String>,
    password: Option<String>,
    password_confirmation: Option<String>,
}

#[utoipa::path(get, path="/organization-invitations/{domain}/{invitation}/identity",tag="Organizations",
    description="Browser form only. No query or body; never consumes an invitation or proof. Issues a fresh single-use CSRF token and Secure HttpOnly SameSite cookie. Explicit profile activation required.",
    params(("domain"=String,Path,format="uuid"),("invitation"=String,Path,format="uuid")),
    responses((status=200,description="No-store enrollment form",content_type="text/html"),(status=400,description="Malformed request"),(status=404,description="Profile disabled"),(status=503,description="Supplier unavailable")))]
pub(super) fn form() {}

#[utoipa::path(head,path="/organization-invitations/{domain}/{invitation}/identity",tag="Organizations",
    description="Same checks and headers as GET; no response body.",
    params(("domain"=String,Path,format="uuid"),("invitation"=String,Path,format="uuid")),
    responses((status=200,description="No-store form headers"),(status=400,description="Malformed request"),(status=404,description="Profile disabled"),(status=503,description="Supplier unavailable")))]
pub(super) fn head() {}

#[utoipa::path(post,path="/organization-invitations/{domain}/{invitation}/identity",tag="Organizations",
    description="Invitation-linked registration/password recovery, not an OAuth grant. Exact same-origin Origin, matching dedicated CSRF cookie/token, fresh single-use CSRF state, explicit current Environment policy and inviter authority required. Exact application/x-www-form-urlencoded <=8192 bytes, no query. Request action requires purpose, invitation_capability and request_key; recovery also requires login_identifier. Complete action requires request_id, proof, password and password_confirmation. Proof expires within 600 seconds. A consumed request can only replay the same current credential; no login session or membership is created. Successful recovery invalidates earlier identity authority. Response loss can precede a committed effect; acquire fresh CSRF before retrying the same request.",
    params(("domain"=String,Path,format="uuid"),("invitation"=String,Path,format="uuid"),("Origin"=String,Header)),
    request_body(content=IdentityForm,content_type="application/x-www-form-urlencoded"),
    security(("identityCsrfCookie"=[])),
    responses((status=200,description="Opaque requestId or completed login subject; no-store"),(status=400,description="Malformed or mismatched request"),(status=403,description="CSRF or current authority refused"),(status=409,description="Conflicting completion or finite capacity exhausted"),(status=503,description="Supplier unavailable; never permits fallback")))]
pub(super) fn submit() {}
