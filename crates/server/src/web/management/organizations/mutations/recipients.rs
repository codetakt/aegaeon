use super::*;

pub(in crate::web::management::organizations) async fn replace_recipients(
    State(state): State<AppState>,
    Path((team, environment_id, domain_id)): Path<(Uuid, Uuid, Uuid)>,
    Extension(admission): Extension<Admission>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let input: http_input::ReplaceIntrospectionRecipientsRequest =
        match http_input::decode_json(&body) {
            Ok(value) => value,
            Err(e) => return input_error(e, &context.request_id),
        };
    let expected_revision = match version(&headers, domain_id, &context.request_id) {
        Ok(value) => value,
        Err(e) => return e,
    };
    execute_with_organization_management_session(
        &state,
        &headers,
        &admission,
        &context,
        Action::Recipients {
            team,
            scope: Scope {
                environment_id,
                domain_id,
            },
            reason: input.reason,
            command: mutations::targets::recipients::ConfigureRecipients {
                expected_revision,
                audience: input.audience,
                registrations: Some(input.client_registration_ids),
            },
        },
    )
    .await
}

pub(in crate::web::management::organizations) async fn revoke_recipients(
    State(state): State<AppState>,
    Path((team, environment_id, domain_id)): Path<(Uuid, Uuid, Uuid)>,
    Extension(admission): Extension<Admission>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let input: http_input::RevokeIntrospectionRecipientsRequest =
        match http_input::decode_json(&body) {
            Ok(value) => value,
            Err(e) => return input_error(e, &context.request_id),
        };
    let expected_revision = match version(&headers, domain_id, &context.request_id) {
        Ok(value) => value,
        Err(e) => return e,
    };
    execute_with_organization_management_session(
        &state,
        &headers,
        &admission,
        &context,
        Action::Recipients {
            team,
            scope: Scope {
                environment_id,
                domain_id,
            },
            reason: input.reason,
            command: mutations::targets::recipients::ConfigureRecipients {
                expected_revision,
                audience: input.audience,
                registrations: None,
            },
        },
    )
    .await
}
