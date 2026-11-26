use crate::web::{
    authorize_context::AuthorizeRequestContext,
    local_auth_support::local_auth_response,
    presentation::{fill, text, Page, Presentation},
};
use axum::{
    http::{header::REFERRER_POLICY, HeaderValue, StatusCode},
    response::Response,
};

pub(super) use crate::web::presentation::escape;

pub(super) fn form(
    presentation: Presentation<'_>,
    ctx: &AuthorizeRequestContext,
    transaction: &str,
    issuer: &str,
    organization: Option<&crate::organizations::consent::Consent>,
    hosted: Option<(&str, &str, i64)>,
) -> Response {
    let messages = presentation.messages();
    let scope = ctx.req.scope.as_deref().unwrap_or("");
    let target = ctx.req.resource.clone().unwrap_or_else(|| {
        if scope.split(' ').any(|s| s == "openid") {
            format!("{}/userinfo", issuer.trim_end_matches('/'))
        } else {
            ctx.req.client_id.clone()
        }
    });
    let invitation = hosted.map_or_else(String::new, |(account, subject, seconds)| {
        let notice = fill(
            messages.invitation_access_notice,
            &[
                (
                    "endpoint",
                    &format!("<bdi>{}</bdi>", escape(&format!("{issuer}/organization-invitations"))),
                ),
                ("permission", "<code>organization.invitation.accept</code>"),
                ("seconds", &seconds.max(0).to_string()),
            ],
        );
        format!(
            "<section><h2>{}</h2><dl><dt>{}</dt><dd><bdi>{}</bdi></dd><dt>{}</dt><dd><bdi>{}</bdi></dd></dl><p>{notice}</p></section>",
            text(messages.invitation_access_heading),
            text(messages.signed_in_account_label),
            escape(account),
            text(messages.account_subject_label),
            escape(subject),
        )
    });
    let offline = if hosted.is_none() && scope.split(' ').any(|s| s == "offline_access") {
        format!("<p>{}</p>", text(messages.offline_notice))
    } else {
        String::new()
    };
    let organizations = organization.map_or_else(String::new, |consent| {
        let mut html = format!(
            "<section><h2>{}</h2><dl><dt>{}</dt><dd><bdi>{}</bdi></dd></dl><ul>",
            text(messages.organization_access_heading),
            text(messages.resource_label),
            escape(&consent.request.locations[0])
        );
        for selected in &consent.request.organizations {
            if selected.administrative_access {
                html.push_str(&format!(
                    "<li>{}</li>",
                    text(messages.administrative_access_notice)
                ));
            }
            html.push_str(&format!(
                "<li><strong><bdi>{}</bdi></strong>: {}</li>",
                escape(&selected.identifier),
                escape(&selected.privileges.join(", "))
            ));
        }
        html.push_str(&format!(
            "</ul><p>{}</p></section>",
            text(messages.organization_scope_notice)
        ));
        html
    });
    let main = format!(
        r#"<h1>{heading}</h1>
<dl><dt>{application}</dt><dd><strong><bdi>{client}</bdi></strong></dd><dt>{resource}</dt><dd><bdi>{target}</bdi></dd><dt>{permissions}</dt><dd><bdi>{scope}</bdi></dd></dl>
{offline}{organizations}{invitation}
<form method="post" action="/auth/consent">
<input type="hidden" name="transaction" value="{transaction}">
<div class="actions"><button type="submit" name="decision" value="approve">{allow}</button>
<button type="submit" name="decision" value="deny" class="secondary">{deny}</button></div>
</form>"#,
        heading = text(messages.consent_heading),
        application = text(messages.application_label),
        resource = text(messages.resource_label),
        permissions = text(messages.permissions_label),
        allow = text(messages.allow_access),
        deny = text(messages.deny_access),
        client = escape(&ctx.req.client_id),
        target = escape(&target),
        scope = escape(scope),
        transaction = escape(transaction)
    );
    let mut response = local_auth_response(
        StatusCode::OK,
        Page::new(presentation, messages.consent_heading, &main).render(),
    );
    // Chromium otherwise sends Origin: null for this same-origin form POST.
    // Keep cross-origin referrers suppressed and the exact issuer Origin gate.
    response
        .headers_mut()
        .insert(REFERRER_POLICY, HeaderValue::from_static("same-origin"));
    response
}
