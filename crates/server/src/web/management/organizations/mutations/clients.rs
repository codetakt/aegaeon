use super::*;
use mutations::clients::ClientCommand;

pub(in crate::web::management::organizations) async fn create_client(
    State(state): State<AppState>,
    Path((team, environment_id, domain_id)): Path<(Uuid, Uuid, Uuid)>,
    Extension(admission): Extension<Admission>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let input: http_input::CreateOrganizationClientRequest = match http_input::decode_json(&body) {
        Ok(value) => value,
        Err(error) => return input_error(error, &context.request_id),
    };
    let expected_revision = match version(&headers, domain_id, &context.request_id) {
        Ok(value) => value,
        Err(error) => return error,
    };
    execute(
        &state,
        &headers,
        &admission,
        &context,
        Action::Client {
            team,
            scope: Scope {
                environment_id,
                domain_id,
            },
            reason: input.reason,
            command: ClientCommand::Create {
                client_registration_id: input.client_registration_id,
                expected_revision,
                active: input.active,
                targets: input.targets,
            },
        },
    )
    .await
}

pub(in crate::web::management::organizations) async fn update_client(
    State(state): State<AppState>,
    Path((team, environment_id, domain_id, id)): Path<(Uuid, Uuid, Uuid, Uuid)>,
    Extension(admission): Extension<Admission>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let input: http_input::UpdateOrganizationClientRequest = match http_input::decode_json(&body) {
        Ok(value) => value,
        Err(error) => return input_error(error, &context.request_id),
    };
    let expected_revision = match version(&headers, id, &context.request_id) {
        Ok(value) => value,
        Err(error) => return error,
    };
    execute(
        &state,
        &headers,
        &admission,
        &context,
        Action::Client {
            team,
            scope: Scope {
                environment_id,
                domain_id,
            },
            reason: input.reason,
            command: ClientCommand::Update {
                id,
                expected_revision,
                active: input.active,
                targets: input.targets,
            },
        },
    )
    .await
}

pub(in crate::web::management::organizations) async fn revoke_client(
    State(state): State<AppState>,
    Path((team, environment_id, domain_id, id)): Path<(Uuid, Uuid, Uuid, Uuid)>,
    Extension(admission): Extension<Admission>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let input: Reason = match http_input::decode_json(&body) {
        Ok(value) => value,
        Err(error) => return input_error(error, &context.request_id),
    };
    let expected_revision = match version(&headers, id, &context.request_id) {
        Ok(value) => value,
        Err(error) => return error,
    };
    execute(
        &state,
        &headers,
        &admission,
        &context,
        Action::Client {
            team,
            scope: Scope {
                environment_id,
                domain_id,
            },
            reason: input.reason,
            command: ClientCommand::Revoke {
                id,
                expected_revision,
            },
        },
    )
    .await
}
