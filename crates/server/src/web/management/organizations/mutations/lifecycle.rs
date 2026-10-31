use super::*;

pub(in crate::web::management::organizations) async fn enable_domain(
    State(state): State<AppState>,
    Path((team, environment_id, domain_id)): Path<(Uuid, Uuid, Uuid)>,
    Extension(admission): Extension<Admission>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    transition(
        &state,
        &headers,
        &admission,
        &context,
        Transition {
            team,
            scope: Scope {
                environment_id,
                domain_id,
            },
            enabled: true,
        },
        &body,
    )
    .await
}

pub(in crate::web::management::organizations) async fn disable_domain(
    State(state): State<AppState>,
    Path((team, environment_id, domain_id)): Path<(Uuid, Uuid, Uuid)>,
    Extension(admission): Extension<Admission>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    transition(
        &state,
        &headers,
        &admission,
        &context,
        Transition {
            team,
            scope: Scope {
                environment_id,
                domain_id,
            },
            enabled: false,
        },
        &body,
    )
    .await
}

struct Transition {
    team: Uuid,
    scope: Scope,
    enabled: bool,
}
async fn transition(
    state: &AppState,
    headers: &HeaderMap,
    admission: &Admission,
    context: &RequestContext,
    transition: Transition,
    body: &[u8],
) -> Response {
    let Transition {
        team,
        scope,
        enabled,
    } = transition;
    let input: Reason = match http_input::decode_json(body) {
        Ok(value) => value,
        Err(error) => return input_error(error, &context.request_id),
    };
    let expected_revision = match version(headers, scope.domain_id, &context.request_id) {
        Ok(value) => value,
        Err(error) => return error,
    };
    execute_with_organization_management_session(
        state,
        headers,
        admission,
        context,
        Action::Domain {
            team,
            scope,
            reason: input.reason,
            expected_revision,
            enabled,
        },
    )
    .await
}
