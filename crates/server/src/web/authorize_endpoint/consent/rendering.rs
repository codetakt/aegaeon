use crate::web::{
    authorize_context::AuthorizeRequestContext, local_auth_support::local_auth_response,
    presentation::Page,
};
use axum::{
    http::{header::REFERRER_POLICY, HeaderValue, StatusCode},
    response::Response,
};

pub(super) use crate::web::presentation::escape;

pub(super) fn form(
    ctx: &AuthorizeRequestContext,
    transaction: &str,
    issuer: &str,
    organization: Option<&crate::organizations::consent::Consent>,
    hosted: Option<(&str, &str, i64)>,
) -> Response {
    let scope = ctx.req.scope.as_deref().unwrap_or("");
    let target = ctx.req.resource.clone().unwrap_or_else(|| {
        if scope.split(' ').any(|s| s == "openid") {
            format!("{}/userinfo", issuer.trim_end_matches('/'))
        } else {
            ctx.req.client_id.clone()
        }
    });
    let invitation = hosted.map_or_else(String::new, |(account, subject, seconds)| format!(
        "<section><h2>Invitation access</h2><dl><dt>Signed-in account</dt><dd><bdi>{}</bdi></dd><dt>Account subject</dt><dd><bdi>{}</bdi></dd></dl><p>Allow this client to verify your invitation at <bdi>{}</bdi> with permission <code>organization.invitation.accept</code> for up to {} seconds. It keeps a refresh token to close this invitation grant. It never uses it to renew access. You will review the organization and roles before choosing whether to join.</p></section>",
        escape(account), escape(subject), escape(&format!("{issuer}/organization-invitations")), seconds.max(0)));
    let offline = if hosted.is_none() && scope.split(' ').any(|s| s == "offline_access") {
        "<p>This application can continue to access these resources when you are not signed in. Approve only if you want to allow that access.</p>"
    } else {
        ""
    };
    let organizations = organization.map_or_else(String::new, |consent| {
        let mut html = format!("<section><h2>Organization access</h2><dl><dt>Resource</dt><dd><bdi>{}</bdi></dd></dl><ul>", escape(&consent.request.locations[0]));
        for selected in &consent.request.organizations {
            if selected.administrative_access {
                html.push_str("<li>Temporary administrative access: this approval permits a separately activated, audited support grant lasting at most five minutes after the original authentication.</li>");
            }
            html.push_str(&format!("<li><strong><bdi>{}</bdi></strong>: {}</li>", escape(&selected.identifier), escape(&selected.privileges.join(", "))));
        }
        html.push_str("</ul><p>Access is limited to these organizations and permissions. Changes may require your approval again.</p></section>");
        html
    });
    let main = format!(
        r#"<h1>Allow application access</h1>
<dl><dt>Application</dt><dd><strong><bdi>{client}</bdi></strong></dd><dt>Resource</dt><dd><bdi>{target}</bdi></dd><dt>Requested permissions</dt><dd><bdi>{scope}</bdi></dd></dl>
{offline}{organizations}{invitation}
<form method="post" action="/auth/consent">
<input type="hidden" name="transaction" value="{transaction}">
<div class="actions"><button type="submit" name="decision" value="approve">Allow access</button>
<button type="submit" name="decision" value="deny" class="secondary">Deny access</button></div>
</form>"#,
        client = escape(&ctx.req.client_id),
        target = escape(&target),
        scope = escape(scope),
        transaction = escape(transaction)
    );
    let mut response = local_auth_response(
        StatusCode::OK,
        Page::new("Allow application access", &main).render(),
    );
    // Chromium otherwise sends Origin: null for this same-origin form POST.
    // Keep cross-origin referrers suppressed and the exact issuer Origin gate.
    response
        .headers_mut()
        .insert(REFERRER_POLICY, HeaderValue::from_static("same-origin"));
    response
}
