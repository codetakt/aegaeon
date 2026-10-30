use super::*;
use crate::organizations::{commands::Command, OrganizationState};

pub(in crate::web::management::organizations) async fn create_organization(
    State(state): State<AppState>,
    Path((team, environment_id, domain_id)): Path<(Uuid, Uuid, Uuid)>,
    Extension(admission): Extension<Admission>,
    Extension(context): Extension<RequestContext>,
    Query(_query): Query<NoQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let input: http_input::objects::CreateOrganizationRequest = match http_input::decode_json(&body)
    {
        Ok(value) => value,
        Err(error) => return input_error(error, &context.request_id),
    };
    execute(
        &state,
        &headers,
        &admission,
        &context,
        Action::Organization {
            team,
            scope: Scope {
                environment_id,
                domain_id,
            },
            reason: input.reason,
            command: Command::Create {
                external_id: input.external_id,
            },
        },
    )
    .await
}

pub(in crate::web::management::organizations) async fn read_organization(
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
        Action::ReadOrganization {
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

pub(in crate::web::management::organizations) async fn prepare_administrator_recovery(
    State(state): State<AppState>,
    Path(path): Path<(Uuid, Uuid, Uuid, Uuid)>,
    Extension(admission): Extension<Admission>,
    Extension(context): Extension<RequestContext>,
    Query(_query): Query<NoQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    transition(
        &state,
        path,
        &admission,
        &context,
        &headers,
        &body,
        OrganizationState::Provisioning,
    )
    .await
}

pub(in crate::web::management::organizations) async fn suspend_organization(
    State(state): State<AppState>,
    Path(path): Path<(Uuid, Uuid, Uuid, Uuid)>,
    Extension(admission): Extension<Admission>,
    Extension(context): Extension<RequestContext>,
    Query(_query): Query<NoQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    transition(
        &state,
        path,
        &admission,
        &context,
        &headers,
        &body,
        OrganizationState::Suspended,
    )
    .await
}

pub(in crate::web::management::organizations) async fn delete_organization(
    State(state): State<AppState>,
    Path(path): Path<(Uuid, Uuid, Uuid, Uuid)>,
    Extension(admission): Extension<Admission>,
    Extension(context): Extension<RequestContext>,
    Query(_query): Query<NoQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    transition(
        &state,
        path,
        &admission,
        &context,
        &headers,
        &body,
        OrganizationState::Deleted,
    )
    .await
}

async fn transition(
    state: &AppState,
    (team, environment_id, domain_id, organization_id): (Uuid, Uuid, Uuid, Uuid),
    admission: &Admission,
    context: &RequestContext,
    headers: &HeaderMap,
    body: &[u8],
    next: OrganizationState,
) -> Response {
    let input: Reason = match http_input::decode_json(body) {
        Ok(value) => value,
        Err(error) => return input_error(error, &context.request_id),
    };
    let expected_revision = match version(headers, organization_id, &context.request_id) {
        Ok(value) => value,
        Err(error) => return error,
    };
    execute(
        state,
        headers,
        admission,
        context,
        Action::Organization {
            team,
            scope: Scope {
                environment_id,
                domain_id,
            },
            reason: input.reason,
            command: if next == OrganizationState::Provisioning {
                Command::PrepareAdministratorRecovery {
                    organization_id,
                    expected_revision,
                }
            } else {
                Command::SetState {
                    organization_id,
                    expected_revision,
                    state: next,
                }
            },
        },
    )
    .await
}
