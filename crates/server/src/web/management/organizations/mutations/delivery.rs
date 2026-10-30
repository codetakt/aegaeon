use super::*;

pub(in crate::web::management::organizations) async fn read_delivery(
    State(state): State<AppState>,
    Path((team, environment_id, domain_id)): Path<(Uuid, Uuid, Uuid)>,
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
        Action::ReadDelivery {
            team,
            scope: Scope {
                environment_id,
                domain_id,
            },
        },
    )
    .await
}

pub(in crate::web::management::organizations) async fn configure_delivery(
    State(state): State<AppState>,
    Path((team, environment_id, domain_id)): Path<(Uuid, Uuid, Uuid)>,
    Extension(admission): Extension<Admission>,
    Extension(context): Extension<RequestContext>,
    Query(_query): Query<NoQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let input: http_input::delivery::ConfigureInvitationDeliveryRequest =
        match http_input::decode_json(&body) {
            Ok(v) => v,
            Err(e) => return input_error(e, &context.request_id),
        };
    let expected_revision = match version(&headers, domain_id, &context.request_id) {
        Ok(v) => v,
        Err(e) => return e,
    };
    execute(
        &state,
        &headers,
        &admission,
        &context,
        Action::Delivery {
            team,
            scope: Scope {
                environment_id,
                domain_id,
            },
            reason: input.reason,
            change: mutations::delivery::Change {
                expected_revision,
                channel: Some(input.channel),
            },
        },
    )
    .await
}

pub(in crate::web::management::organizations) async fn disable_delivery(
    State(state): State<AppState>,
    Path((team, environment_id, domain_id)): Path<(Uuid, Uuid, Uuid)>,
    Extension(admission): Extension<Admission>,
    Extension(context): Extension<RequestContext>,
    Query(_query): Query<NoQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let input: Reason = match http_input::decode_json(&body) {
        Ok(v) => v,
        Err(e) => return input_error(e, &context.request_id),
    };
    let expected_revision = match version(&headers, domain_id, &context.request_id) {
        Ok(v) => v,
        Err(e) => return e,
    };
    execute(
        &state,
        &headers,
        &admission,
        &context,
        Action::Delivery {
            team,
            scope: Scope {
                environment_id,
                domain_id,
            },
            reason: input.reason,
            change: mutations::delivery::Change {
                expected_revision,
                channel: None,
            },
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
    let result = match action {
        Action::ReadDelivery { team, scope } => {
            mutations::delivery::read(tx, scope, team, actor.id).await
        }
        Action::Delivery {
            team,
            scope,
            change,
            ..
        } => mutations::delivery::apply(tx, scope, team, actor, key, &change).await,
        _ => {
            return Err(failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                &actor.request_id,
            ))
        }
    }
    .map_err(|e| storage_error(&e, &actor.request_id))?;
    super::dispatch::encode(&result, result.id, result.revision, &actor.request_id)
}
