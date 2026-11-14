//! Server-held selection continuation; choosing an entry is not grant consent.
use super::{organizations, rendering, storage};
use crate::organizations::{
    consent::GrantRequest,
    discovery,
    selection::{InvalidSelection, SelectionRequest},
};
use crate::web::{
    authorize_context::AuthorizeRequestContext, authorize_endpoint::session::AuthorizeSessionState,
    AppState,
};
use axum::{
    http::{header::REFERRER_POLICY, HeaderValue, StatusCode},
    response::Response,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub(super) const URI: &str = "/authorize/organization-selection";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Pending {
    version: u8,
    pub authorization: Value,
    created_at: i64,
    cursor: Option<String>,
    page: discovery::Page,
}

pub(super) fn now() -> Result<i64, Response> {
    crate::util::now_unix_epoch_secs()
        .ok()
        .and_then(|v| i64::try_from(v).ok())
        .ok_or_else(storage::unavailable)
}

pub(super) fn decode(value: &Value) -> Result<Pending, Response> {
    let value: Pending = serde_json::from_value(value.clone()).map_err(|_| storage::invalid())?;
    let current = now()?;
    if value.version != 1
        || current < value.created_at
        || current >= value.created_at.saturating_add(300)
    {
        return Err(storage::invalid());
    }
    Ok(value)
}

pub(super) fn request(ctx: &AuthorizeRequestContext) -> Result<SelectionRequest, InvalidSelection> {
    let details = ctx
        .req
        .authorization_details
        .as_ref()
        .ok_or(InvalidSelection)?;
    let request = SelectionRequest::parse(details)?;
    if ctx.req.code_challenge.is_none()
        || ctx.req.code_challenge_method.as_deref() != Some("S256")
        || ctx.req.dpop_jkt.is_none()
        || ctx.req.response_type != "code"
        || !super::has_prompt(ctx, "consent")
        || !ctx
            .req
            .scope
            .as_deref()
            .is_some_and(|s| s.split(' ').any(|p| p == "offline_access"))
    {
        return Err(InvalidSelection);
    }
    Ok(request)
}

pub(super) async fn page(
    state: &AppState,
    ctx: &AuthorizeRequestContext,
    session: &AuthorizeSessionState,
    cursor: Option<&str>,
) -> Result<discovery::Page, Response> {
    let request = request(ctx).map_err(|_| storage::invalid())?;
    let owner =
        crate::organizations::request_work::async_store::current_epoch_owner(state.environment_id)
            .map_err(|_| storage::unavailable())?;
    let mut connection = owner
        .connection(&state.db_pool)
        .await
        .map_err(|_| storage::unavailable())?;
    let mut tx = connection
        .begin()
        .await
        .map_err(|_| storage::unavailable())?;
    let mut page = discovery::page(
        &mut tx,
        &discovery::Query {
            environment_id: state.environment_id,
            issuer: &state.issuer,
            client_id: &ctx.req.client_id,
            subject: &session.user_id,
            auth_time: session.auth_time_epoch_secs,
            dpop_jkt: ctx
                .req
                .dpop_jkt
                .as_ref()
                .ok_or_else(storage::invalid)?
                .as_str(),
            audience: &request.locations[0],
            privileges: Some(&request.privileges),
            discovery_audience: None,
            cursor,
        },
    )
    .await
    .map_err(|e| match e {
        crate::organizations::repository::RepositoryError::Authority(_) => super::error(
            state,
            ctx,
            "invalid_authorization_details",
            "organization selection is unavailable",
        ),
        _ => storage::unavailable(),
    })?;
    let mut representable = Vec::with_capacity(page.organizations.len());
    for entry in page.organizations {
        if request
            .resolve_if_representable(&entry.identifier, &entry.authority.privileges)
            .map_err(|_| storage::invalid())?
            .is_some()
        {
            representable.push(entry);
        }
    }
    // Keep the repository's cursor after all scanned memberships, including
    // valid choices that cannot fit the explicit grant format.
    page.organizations = representable;
    tx.commit().await.map_err(|_| storage::unavailable())?;
    connection.release().await;
    Ok(page)
}

pub(super) async fn prepare(
    state: &AppState,
    ctx: &AuthorizeRequestContext,
    session: &AuthorizeSessionState,
) -> Result<Response, Response> {
    let pending = Pending {
        version: 1,
        authorization: super::snapshot(ctx).map_err(|_| storage::unavailable())?,
        created_at: now()?,
        cursor: None,
        page: page(state, ctx, session, None).await?,
    };
    display(state, ctx, session, &pending).await
}

async fn display(
    state: &AppState,
    ctx: &AuthorizeRequestContext,
    session: &AuthorizeSessionState,
    pending: &Pending,
) -> Result<Response, Response> {
    let value = serde_json::to_value(pending).map_err(|_| storage::unavailable())?;
    let token = storage::create(state, session, URI, &value).await?;
    let mut entries = String::new();
    for (index, entry) in pending.page.organizations.iter().enumerate() {
        entries.push_str(&format!(
            "<li><button name=\"decision\" value=\"select:{index}\">{}</button></li>",
            rendering::escape(&entry.identifier)
        ));
    }
    if entries.is_empty() {
        entries.push_str("<li>No eligible organizations on this page.</li>");
    }
    let next = if pending.page.next_cursor.is_some() {
        "<button name=\"decision\" value=\"next\">Next page</button>"
    } else {
        ""
    };
    let mut response = crate::web::local_auth_support::local_auth_response(StatusCode::OK,format!(
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Select organization</title><main><h1>Select organization</h1><p>Application: {}</p><p>Select an organization, then review the exact permissions before allowing access.</p><form method=\"post\" action=\"/auth/consent\"><input type=\"hidden\" name=\"transaction\" value=\"{}\"><ul>{entries}</ul>{next}<button name=\"decision\" value=\"deny\">Cancel</button></form></main></html>",
        rendering::escape(&ctx.req.client_id),rendering::escape(&token)));
    response
        .headers_mut()
        .insert(REFERRER_POLICY, HeaderValue::from_static("same-origin"));
    Ok(response)
}

pub(super) fn valid_action(choice: &str) -> bool {
    choice == "next"
        || choice
            .strip_prefix("select:")
            .is_some_and(|v| !v.is_empty() && v.len() <= 2 && v.bytes().all(|b| b.is_ascii_digit()))
}

pub(super) async fn select(
    state: &AppState,
    ctx: &AuthorizeRequestContext,
    session: &AuthorizeSessionState,
    stored: &storage::Pending,
    pending: Pending,
    choice: &str,
) -> Result<Response, Response> {
    let current = page(state, ctx, session, pending.cursor.as_deref()).await?;
    if current != pending.page {
        return Err(storage::rejected(
            "organization_selection_authority_changed",
        ));
    }
    if choice == "next" {
        let cursor = pending
            .page
            .next_cursor
            .as_deref()
            .ok_or_else(storage::invalid)?;
        let next = page(state, ctx, session, Some(cursor)).await?;
        storage::decide(state, session, stored, "deny").await?;
        return display(
            state,
            ctx,
            session,
            &Pending {
                version: 1,
                authorization: pending.authorization,
                created_at: pending.created_at,
                cursor: Some(cursor.to_owned()),
                page: next,
            },
        )
        .await;
    }
    let index: usize = choice
        .strip_prefix("select:")
        .and_then(|v| v.parse().ok())
        .ok_or_else(storage::invalid)?;
    let entry = pending
        .page
        .organizations
        .get(index)
        .ok_or_else(storage::invalid)?;
    let resolved = request(ctx)
        .map_err(|_| storage::invalid())?
        .resolve(&entry.identifier, &entry.authority.privileges)
        .map_err(|_| storage::invalid())?;
    let explicit = GrantRequest::parse(&resolved).map_err(|_| storage::invalid())?;
    let consent =
        organizations::capture_request(state, ctx, session, pending.created_at, &explicit).await?;
    if consent.memberships.values().next() != Some(&entry.authority) {
        return Err(storage::rejected(
            "organization_selection_membership_changed",
        ));
    }
    // Consume this picker before creating a distinct approval. A storage failure
    // can require restart but cannot replay selection or silently approve a grant.
    storage::decide(state, session, stored, "deny").await?;
    let value = organizations::pack(pending.authorization, &consent)?;
    let token = storage::create(state, session, "/authorize", &value).await?;
    Ok(rendering::form(ctx, &token, &state.issuer, Some(&consent)))
}
