use super::*;
use crate::organizations::invitations as service;

pub(super) enum Command {
    Issue(service::FirstAdminRequest),
    Revoke { id: Uuid, expected_revision: i64 },
}

pub(in crate::web::management::organizations) async fn issue_invitation(
    State(state): State<AppState>,
    Path((team, environment_id, domain_id, organization_id)): Path<(Uuid, Uuid, Uuid, Uuid)>,
    Extension(admission): Extension<Admission>,
    Extension(context): Extension<RequestContext>,
    Query(_query): Query<NoQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let input: http_input::invitations::IssueInvitationRequest =
        match http_input::decode_json(&body) {
            Ok(value) => value,
            Err(e) => return input_error(e, &context.request_id),
        };
    let roles = match input.roles() {
        Ok(value) => value,
        Err(e) => return input_error(e, &context.request_id),
    };
    let expected_revision = match version(&headers, organization_id, &context.request_id) {
        Ok(value) => value,
        Err(e) => return e,
    };
    execute(
        &state,
        &headers,
        &admission,
        &context,
        Action::Invitation {
            team,
            scope: Scope {
                environment_id,
                domain_id,
            },
            reason: input.reason,
            command: Command::Issue(service::FirstAdminRequest {
                organization_id,
                expected_revision,
                recipient: input.recipient,
                roles,
                lifetime_seconds: input.lifetime_seconds,
            }),
        },
    )
    .await
}

pub(in crate::web::management::organizations) async fn revoke_invitation(
    State(state): State<AppState>,
    Path((team, environment_id, domain_id, id)): Path<(Uuid, Uuid, Uuid, Uuid)>,
    Extension(admission): Extension<Admission>,
    Extension(context): Extension<RequestContext>,
    Query(_query): Query<NoQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let input: Reason = match http_input::decode_json(&body) {
        Ok(value) => value,
        Err(e) => return input_error(e, &context.request_id),
    };
    let expected_revision = match version(&headers, id, &context.request_id) {
        Ok(value) => value,
        Err(e) => return e,
    };
    execute(
        &state,
        &headers,
        &admission,
        &context,
        Action::Invitation {
            team,
            scope: Scope {
                environment_id,
                domain_id,
            },
            reason: input.reason,
            command: Command::Revoke {
                id,
                expected_revision,
            },
        },
    )
    .await
}

pub(in crate::web::management::organizations) async fn read_invitation(
    State(state): State<AppState>,
    Path((team, environment_id, domain_id, id)): Path<(Uuid, Uuid, Uuid, Uuid)>,
    Extension(admission): Extension<Admission>,
    Extension(context): Extension<RequestContext>,
    Query(_query): Query<NoQuery>,
    headers: HeaderMap,
) -> Response {
    execute(
        &state,
        &headers,
        &admission,
        &context,
        Action::ReadInvitation {
            team,
            scope: Scope {
                environment_id,
                domain_id,
            },
            id,
        },
    )
    .await
}

pub(super) async fn dispatch(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    actor: &AuditActor,
    key: &str,
    action: Action,
) -> Result<(Vec<u8>, VersionTag), Response> {
    let request_id = &actor.request_id;
    let result = match action {
        Action::Invitation {
            team,
            scope,
            command,
            ..
        } => match command {
            Command::Issue(request) => {
                let now = crate::web::now_epoch_secs().map_err(|_| {
                    failure(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "temporarily_unavailable",
                        request_id,
                    )
                })?;
                let now = i64::try_from(now).map_err(|_| {
                    failure(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "temporarily_unavailable",
                        request_id,
                    )
                })?;
                service::issue_first_admin(
                    tx,
                    service::Issuance {
                        scope,
                        team,
                        actor,
                        key,
                        request: &request,
                        now,
                    },
                )
                .await
            }
            Command::Revoke {
                id,
                expected_revision,
            } => {
                service::revoke(
                    tx,
                    service::Revocation {
                        scope,
                        team,
                        actor,
                        key,
                        id,
                        expected_revision,
                    },
                )
                .await
            }
        },
        Action::ReadInvitation { team, scope, id } => {
            service::read(tx, scope, team, actor.id, id).await
        }
        _ => {
            return Err(failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                request_id,
            ))
        }
    }
    .map_err(|e| storage_error(&e, request_id))?;
    dispatch::encode(&result, result.id, result.revision, request_id)
}
