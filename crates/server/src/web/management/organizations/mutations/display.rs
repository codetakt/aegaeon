use super::*;
use crate::organizations::{
    http_input::display::{PatchRoleDisplay, SetOrganizationDisplayName},
    operators::mutations::display::{Change, Target},
};

pub(in crate::web::management::organizations) async fn organization(
    State(state): State<AppState>,
    Path((team, environment_id, domain_id, id)): Path<(Uuid, Uuid, Uuid, Uuid)>,
    Extension(admission): Extension<Admission>,
    Extension(context): Extension<RequestContext>,
    Query(_query): Query<NoQuery>,
    parts: axum::http::request::Parts,
    body: Bytes,
) -> Response {
    let scope = Scope {
        environment_id,
        domain_id,
    };
    let target = Target::Organization(id);
    let headers = parts.headers;
    let action = match parts.method {
        axum::http::Method::GET | axum::http::Method::HEAD => Action::ReadDisplay {
            team,
            scope,
            target,
        },
        axum::http::Method::PUT => {
            let input: SetOrganizationDisplayName = match http_input::decode_json(&body) {
                Ok(v) => v,
                Err(e) => return input_error(e, &context.request_id),
            };
            let expected = match http_input::display::expected(&headers, target, id) {
                Ok(v) => v,
                Err(e) => return input_error(e, &context.request_id),
            };
            Action::WriteDisplay {
                team,
                scope,
                expected,
                reason: input.reason,
                change: Change::Name(id, input.display_name),
            }
        }
        _ => {
            return failure(
                StatusCode::METHOD_NOT_ALLOWED,
                "invalid_request",
                &context.request_id,
            )
        }
    };
    execute_with_organization_management_session(&state, &headers, &admission, &context, action)
        .await
}

pub(in crate::web::management::organizations) async fn roles(
    State(state): State<AppState>,
    Path((team, environment_id, domain_id)): Path<(Uuid, Uuid, Uuid)>,
    Extension(admission): Extension<Admission>,
    Extension(context): Extension<RequestContext>,
    Query(_query): Query<NoQuery>,
    parts: axum::http::request::Parts,
    body: Bytes,
) -> Response {
    let scope = Scope {
        environment_id,
        domain_id,
    };
    let target = Target::Roles;
    let headers = parts.headers;
    let action = match parts.method {
        axum::http::Method::GET | axum::http::Method::HEAD => Action::ReadDisplay {
            team,
            scope,
            target,
        },
        axum::http::Method::PATCH => {
            let input: PatchRoleDisplay = match http_input::decode_json(&body) {
                Ok(v) => v,
                Err(e) => return input_error(e, &context.request_id),
            };
            let expected = match http_input::display::expected(&headers, target, domain_id) {
                Ok(v) => v,
                Err(e) => return input_error(e, &context.request_id),
            };
            Action::WriteDisplay {
                team,
                scope,
                expected,
                reason: input.reason,
                change: Change::Labels(input.labels),
            }
        }
        _ => {
            return failure(
                StatusCode::METHOD_NOT_ALLOWED,
                "invalid_request",
                &context.request_id,
            )
        }
    };
    execute_with_organization_management_session(&state, &headers, &admission, &context, action)
        .await
}

pub(super) async fn dispatch(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    actor: &AuditActor,
    key: &str,
    action: Action,
) -> Result<(Vec<u8>, VersionTag), Response> {
    let request_id = &actor.request_id;
    let (id, display) = match action {
        Action::ReadDisplay {
            team,
            scope,
            target,
        } => {
            let display = mutations::display::read(tx, scope, team, actor.id, target)
                .await
                .map_err(|e| storage_error(&e, request_id))?;
            (target.id(scope), display)
        }
        Action::WriteDisplay {
            team,
            scope,
            expected,
            change,
            ..
        } => {
            let display = mutations::display::apply(tx, scope, team, actor, key, expected, &change)
                .await
                .map_err(|e| storage_error(&e, request_id))?;
            (change.target().id(scope), display)
        }
        _ => {
            return Err(failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                request_id,
            ))
        }
    };
    let tag =
        VersionTag::display(id, display.revision()).map_err(|e| input_error(e, request_id))?;
    super::dispatch::encode_with_tag(&display, tag, request_id)
}
