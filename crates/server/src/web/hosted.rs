//! The hosted client owns browser correlation. Only the recipient API may
//! allocate an address challenge or commit membership.
use super::{
    hosted_oauth as oauth, hosted_page, organization_resource::ResourceAdmission, AppState,
};
use axum::{
    body::{to_bytes, Body},
    extract::{RawQuery, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgTransaction;
use uuid::Uuid;

mod actions;
mod authority;
mod callback;
mod cookies;
mod flow;
mod store;
use flow::{Flow, Generation};
pub(crate) use store::Store;
use store::{generation, Find};

pub(crate) const LANDING: &str = "/organization-invitations/hosted";
pub(crate) const ACTION: &str = "/organization-invitations/hosted/actions";
pub(crate) use crate::organizations::operators::mutations::delivery::registration::HOSTED_CALLBACK as CALLBACK;
type Result<T> = std::result::Result<T, Error>;
#[derive(Debug)]
enum Error {
    Invalid,
    Refused,
    Unavailable,
    Service(Box<Response>),
}
impl From<Response> for Error {
    fn from(response: Response) -> Self {
        Self::Service(Box::new(response))
    }
}
impl From<sqlx::Error> for Error {
    fn from(_: sqlx::Error) -> Self {
        Self::Unavailable
    }
}
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        match self {
            Self::Service(r) => *r,
            Self::Invalid => reply(StatusCode::BAD_REQUEST, json!({"step":"unavailable"})),
            Self::Refused => reply(StatusCode::FORBIDDEN, json!({"step":"unavailable"})),
            Self::Unavailable => reply(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"step":"unavailable"}),
            ),
        }
    }
}
fn now() -> Result<i64> {
    crate::util::now_unix_epoch_secs()
        .ok()
        .and_then(|n| i64::try_from(n).ok())
        .ok_or(Error::Unavailable)
}
fn reply(status: StatusCode, body: Value) -> Response {
    let mut r = super::token_json_response(status, body);
    r.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    r
}
pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route(LANDING, get(landing))
        .route(ACTION, post(action))
        .route(
            CALLBACK,
            get(callback::callback).head(|| async {
                // Axum otherwise dispatches HEAD through the state-changing OAuth callback.
                (
                    StatusCode::METHOD_NOT_ALLOWED,
                    [(header::ALLOW, "GET"), (header::CACHE_CONTROL, "no-store")],
                )
            }),
        )
}
async fn landing(
    State(state): State<AppState>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    // The invitation screens are English until their states move into the
    // catalogs; the landing keeps the configured identity.
    let presentation = super::presentation::Presentation {
        locale: super::Locale::En,
        service_name: state.presentation.service_name(),
    };
    let Some(store) = state.hosted.as_ref() else {
        return hosted_page::landing(
            presentation,
            &state.issuer,
            state.environment_id,
            "",
            now().unwrap_or(0),
        );
    };
    let browser = cookies::browser(store, &headers).unwrap_or_else(|| cookies::new_browser(store));
    let clock = now().unwrap_or(0);
    let handle = query
        .as_deref()
        .and_then(|v| v.strip_prefix("flow="))
        .and_then(|h| Uuid::parse_str(h).ok());
    let mut r = hosted_page::landing(
        presentation,
        &state.issuer,
        state.environment_id,
        &cookies::landing_csrf(store, &browser, handle, clock),
        clock,
    );
    cookies::set(&mut r, cookies::BROWSER, &browser, 3600);
    r
}

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "openapi", schema(as = HostedInvitationAction))]
#[serde(rename_all = "camelCase", tag = "action", deny_unknown_fields)]
pub(crate) enum Action {
    Import {
        fragment: String,
    },
    Resume {
        #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
        flow: Uuid,
    },
    Login {
        #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
        flow: Uuid,
    },
    Switch {
        #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
        flow: Uuid,
    },
    Status {
        #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
        flow: Uuid,
    },
    Send {
        #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
        flow: Uuid,
        confirmation: String,
    },
    Preview {
        #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
        flow: Uuid,
    },
    Confirm {
        #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
        flow: Uuid,
        confirmation: String,
    },
    Cancel {
        #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
        flow: Uuid,
    },
    Restart {
        #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
        flow: Uuid,
    },
    Return {
        #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
        flow: Uuid,
    },
    IdentityRequest {
        #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
        flow: Uuid,
        purpose: crate::organizations::invitations::enrollment::Purpose,
        #[serde(rename = "loginIdentifier")]
        login_identifier: Option<String>,
    },
    IdentityComplete {
        #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
        flow: Uuid,
        password: String,
        #[serde(rename = "passwordConfirmation")]
        password_confirmation: String,
    },
}
impl Action {
    fn handle(&self) -> Result<Uuid> {
        match self {
            Self::Import { .. } => Err(Error::Invalid),
            Self::Resume { flow }
            | Self::Login { flow }
            | Self::Switch { flow }
            | Self::Status { flow }
            | Self::Send { flow, .. }
            | Self::Preview { flow }
            | Self::Confirm { flow, .. }
            | Self::Cancel { flow }
            | Self::Restart { flow }
            | Self::Return { flow }
            | Self::IdentityRequest { flow, .. }
            | Self::IdentityComplete { flow, .. } => Ok(*flow),
        }
    }
}
async fn action(
    State(state): State<AppState>,
    Extension(admission): Extension<ResourceAdmission>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    body: Body,
) -> Response {
    execute(&state, &admission, query, &headers, body)
        .await
        .unwrap_or_else(IntoResponse::into_response)
}
async fn execute(
    state: &AppState,
    admission: &ResourceAdmission,
    query: Option<String>,
    headers: &HeaderMap,
    body: Body,
) -> Result<Response> {
    let environment = state.environment_id;
    let store = state.hosted.as_deref().ok_or(Error::Unavailable)?;
    let (browser, csrf) =
        cookies::post_credentials(store, &state.issuer, headers, query.as_deref())?;
    let bytes = tokio::time::timeout(std::time::Duration::from_secs(3), to_bytes(body, 16384))
        .await
        .map_err(|_| Error::Invalid)?
        .map_err(|_| Error::Invalid)?;
    let action: Action = crate::util::deserialize_json_without_duplicate_object_keys(&bytes)
        .map_err(|_| Error::Invalid)?;
    let clock = now()?;
    let may_retire = matches!(
        action,
        Action::Import { .. }
            | Action::Switch { .. }
            | Action::Cancel { .. }
            | Action::Confirm { .. }
            | Action::Status { .. }
            | Action::Send { .. }
    );
    if matches!(action, Action::Import { .. })
        && !cookies::valid_landing(store, &browser, None, csrf, clock)
    {
        return Err(Error::Refused);
    }
    let browser_tag = store.mac("binding", &browser);
    let mut tx = store.begin().await?;
    let (mut flow, mut extra) = match action {
        Action::Import { fragment } => {
            let link = hosted_page::parse_fragment(&fragment, &state.issuer, environment, clock)
                .ok_or(Error::Invalid)?;
            actions::import(
                state,
                admission,
                store,
                &mut tx,
                &browser_tag,
                headers,
                link,
            )
            .await?
        }
        _ => {
            let handle = action.handle()?;
            let mut flow = store
                .find(&mut tx, Find::Handle(handle))
                .await?
                .ok_or(Error::Refused)?;
            flow.bound(&generation(environment)?, &browser_tag, headers, now()?)?;
            let valid_csrf = cookies::equal(csrf, &flow.csrf(store))
                || matches!(action, Action::Resume { .. })
                    && cookies::valid_landing(store, &browser, Some(handle), csrf, clock);
            if !valid_csrf {
                return Err(Error::Refused);
            }
            if actions::record_intent(store, &mut flow, &action, clock)? {
                store.save(&mut tx, &flow).await?;
                admission.0.admit_commit().map_err(|_| Error::Unavailable)?;
                tx.commit().await?;
                tx = store.begin().await?;
                flow = store
                    .find(&mut tx, Find::Handle(handle))
                    .await?
                    .ok_or(Error::Refused)?;
                flow.bound(&generation(environment)?, &browser_tag, headers, now()?)?;
            }
            let response =
                actions::act(state, admission, store, &mut tx, &mut flow, action, clock).await?;
            (flow, response)
        }
    };
    flow.finish_interaction(store, &mut tx, now()?).await?;
    let value = match extra.take() {
        Some(r) => r,
        None => flow.view(store, now()?),
    };
    store.save(&mut tx, &flow).await?;
    admission.0.admit_commit().map_err(|_| Error::Unavailable)?;
    tx.commit().await?;
    if may_retire && flow.grant.is_none() {
        store.wake_cleanup();
    }
    Ok(reply(StatusCode::OK, value))
}

/// Used by the issuer only for its reserved confidential invitation clients.
/// A nonlocking lookup permits the issuer to verify state from another replica.
pub(crate) async fn authorization_for_state(
    state: &AppState,
    opaque: &str,
) -> std::result::Result<Option<oauth::Authorization>, ()> {
    let Some(store) = state.hosted.as_ref() else {
        return Ok(None);
    };
    pending_authorization(store, state.environment_id, opaque).await
}

async fn pending_authorization(
    store: &Store,
    environment: Uuid,
    opaque: &str,
) -> std::result::Result<Option<oauth::Authorization>, ()> {
    if opaque.is_empty() || opaque.len() > 512 {
        return Ok(None);
    }
    let mut tx = store.begin().await.map_err(|_| ())?;
    let Some(flow) = store
        .find(&mut tx, Find::OAuth(opaque, false))
        .await
        .map_err(|_| ())?
    else {
        return Ok(None);
    };
    if flow.generation != generation(environment).map_err(|_| ())?
        || now().map_err(|_| ())? >= flow.deadline
    {
        return Ok(None);
    }
    Ok(flow.authorization)
}
