use super::*;
use crate::lti::{
    claims::{self, ClaimContext},
    model::TOKEN_TTL_SECONDS,
    request::AuthorizationRequest,
};
use axum::{
    body::{to_bytes, Body},
    extract::{OriginalUri, Path, State},
    http::{Method, Request},
};
use serde_json::json;

fn protocol_error(state: &AppState, request: &AuthorizationRequest, code: &str) -> Response {
    crate::form_post::authorization_error(
        &request.redirect_uri,
        code,
        None,
        request.state.as_deref(),
        &state.issuer,
    )
    .unwrap_or_else(|_| failure(state, &LtiError::Unavailable))
}

async fn issue(
    state: &AppState,
    tx: &mut Transaction<'_, Postgres>,
    intent: &intents::Intent,
    registration: &store::Registration,
    request: &AuthorizationRequest,
    headers: &HeaderMap,
) -> Result<Response, Response> {
    let (sid, auth_session) = session(state, headers).await.map_err(|response| {
        if response.status().is_server_error() {
            response
        } else {
            protocol_error(state, request, "login_required")
        }
    })?;
    if intent.session_hash.as_deref() != Some(intents::digest(&sid).as_str())
        || auth_session.user_id != intent.subject
    {
        return Err(protocol_error(state, request, "login_required"));
    }
    let (fields, now) = message_fields(state, tx, intent, registration).await?;
    let mut builder = crate::oidc::id_token::IdTokenBuilder::try_new(
        state.issuer.to_string(),
        intent.subject.clone(),
        intent.client_id.clone(),
    )
    .map_err(|_| failure(state, &LtiError::Unavailable))?
    .nonce(request.nonce.clone())
    .auth_time(
        i64::try_from(auth_session.auth_time_epoch_secs)
            .map_err(|_| failure(state, &LtiError::Unavailable))?,
    );
    for (name, value) in fields {
        builder = builder.claim(name, value);
    }
    let mut token = builder.build();
    token.claims.iat = now;
    token.claims.nbf = Some(now);
    token.claims.exp = now
        .checked_add(TOKEN_TTL_SECONDS)
        .ok_or_else(|| failure(state, &LtiError::Unavailable))?
        .min(intent.expires_at);
    if token.claims.exp <= now || token.claims.auth_time.is_some_and(|time| time > now) {
        return Err(protocol_error(state, request, "login_required"));
    }
    let config = state
        .oidc
        .config
        .as_ref()
        .filter(|config| config.issuer == *state.issuer)
        .ok_or_else(|| failure(state, &LtiError::Unavailable))?;
    let signed = crate::oidc::required_rs256::sign_required_id_token_async(
        &token.claims,
        &config.signing_key,
    )
    .await
    .map_err(|_| failure(state, &LtiError::Unavailable))?;
    let response = crate::form_post::id_token_success(
        &request.redirect_uri,
        &signed,
        request.state.as_deref(),
    )
    .map_err(|_| failure(state, &LtiError::Unavailable))?;
    let final_now = intents::now(tx)
        .await
        .map_err(|error| failure(state, &error))?;
    if final_now >= token.claims.exp {
        return Err(failure(state, &LtiError::Denied));
    }
    // Check the shared session again after signing. Session revocation and
    // database authority have separate consistency domains; no stale fallback.
    let (_, current) = session(state, headers).await.map_err(|response| {
        if response.status().is_server_error() {
            response
        } else {
            protocol_error(state, request, "login_required")
        }
    })?;
    if current != auth_session {
        return Err(protocol_error(state, request, "login_required"));
    }
    let result=sqlx::query("UPDATE aegaeon.lti_launch_intents SET status='consumed',consumed_at=$2,response_digest=$3,authorization_request=NULL,continuation_hash=NULL,csrf_hash=NULL WHERE id=$1 AND status='initiated'")
        .bind(intent.id).bind(final_now).bind(intents::digest(&signed)).execute(&mut **tx).await.map_err(|_|failure(state, &LtiError::Unavailable))?;
    if result.rows_affected() != 1 {
        return Err(failure(state, &LtiError::Denied));
    }
    store::audit(tx,state.environment_id,&intent.owner.to_string(),"END_USER",intent.id,"lti.launch.issued.v1",
        json!({"registrationId":intent.registration_id,"revision":intent.revision,"responseDigest":intents::digest(&signed)}))
        .await.map_err(|error|failure(state, &error))?;
    Ok(response)
}

async fn process(
    state: &AppState,
    request: AuthorizationRequest,
    headers: &HeaderMap,
    post: bool,
) -> Result<Response, Response> {
    let _namespace = state.require_subject_namespace()?;
    let mut tx = state
        .db_pool
        .begin()
        .await
        .map_err(|_| failure(state, &LtiError::Unavailable))?;
    let runtime = current_runtime(state, &mut tx)
        .await
        .map_err(|error| failure(state, &error))?;
    let registration = store::load(&mut tx, state.environment_id, &request.client_id, true)
        .await
        .map_err(|error| failure(state, &error))?
        .ok_or_else(|| failure(state, &LtiError::Denied))?;
    // Exact registered URI admission precedes every protocol error response.
    if !registration
        .configuration
        .redirect_uris
        .contains(&request.redirect_uri)
        || store::current_client(&mut tx, state.environment_id, &request.client_id)
            .await
            .map_err(|error| failure(state, &error))?
            != registration.client_record_id
    {
        return Err(failure(state, &LtiError::Denied));
    }
    request
        .validate()
        .map_err(|code| protocol_error(state, &request, code))?;
    let intent = intents::load(
        &mut tx,
        state.environment_id,
        &request.lti_message_hint,
        intents::Ticket::Message,
    )
    .await
    .map_err(|error| match error {
        LtiError::Denied => protocol_error(state, &request, "invalid_request"),
        other => failure(state, &other),
    })?;
    if intent.client_id != request.client_id
        || intent.login_hint_hash.as_deref() != Some(intents::digest(&request.login_hint).as_str())
        || intent.message_hint_hash.as_deref()
            != Some(intents::digest(&request.lti_message_hint).as_str())
        || intent.status != "initiated"
    {
        return Err(protocol_error(state, &request, "invalid_request"));
    }
    let registration = current_intent(state, &mut tx, &intent, &runtime).await?;
    let snapshot =
        serde_json::to_value(&request).map_err(|_| failure(state, &LtiError::Unavailable))?;
    if intent
        .authorization_request
        .as_ref()
        .is_some_and(|value| value != &snapshot)
    {
        return Err(protocol_error(state, &request, "invalid_request"));
    }
    let cookie = super::super::form_helpers::auth_session_cookie(headers)
        .map_err(|_| protocol_error(state, &request, "invalid_request"))?;
    let response = if post && cookie.is_none() {
        if intent.authorization_request.is_some() {
            return Err(protocol_error(state, &request, "login_required"));
        }
        // SameSite=Lax may withhold the session on a Tool's cross-site POST.
        // Preserve the admitted request server-side, then make one same-origin GET.
        let continuation = intents::random();
        sqlx::query("UPDATE aegaeon.lti_launch_intents SET continuation_hash=$2,authorization_request=$3 WHERE id=$1")
            .bind(intent.id).bind(intents::digest(&continuation)).bind(snapshot).execute(&mut *tx).await.map_err(|_|failure(state, &LtiError::Unavailable))?;
        rendering::redirect(&format!("/lti/continue/{continuation}"))
            .map_err(|error| failure(state, &error))?
    } else {
        issue(state, &mut tx, &intent, &registration, &request, headers).await?
    };
    // A lost/uncertain COMMIT never releases a signed response. Retrying a
    // consumed intent cannot issue another token, even if HTTP delivery was lost.
    tx.commit()
        .await
        .map_err(|_| failure(state, &LtiError::Unavailable))?;
    Ok(response)
}

pub(in crate::web) async fn authorize(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    request: Request<Body>,
) -> Response {
    let result = async {
        let _namespace = state.require_subject_namespace()?;
        let post = request.method() == Method::POST;
        if !post && request.method() != Method::GET {
            return Err(failure(&state, &LtiError::Invalid));
        }
        let headers = request.headers().clone();
        let raw = if post {
            if uri.query().is_some_and(|value| !value.is_empty()) {
                return Err(failure(&state, &LtiError::Invalid));
            }
            super::super::request_admission::enforce_content_type(
                &headers,
                "application/x-www-form-urlencoded",
                &state.issuer,
            )?;
            let bytes = to_bytes(request.into_body(), crate::lti::request::MAX_REQUEST_BYTES)
                .await
                .map_err(|_| failure(&state, &LtiError::Invalid))?;
            String::from_utf8(bytes.to_vec()).map_err(|_| failure(&state, &LtiError::Invalid))?
        } else {
            uri.query().unwrap_or("").to_owned()
        };
        let parsed = AuthorizationRequest::parse(&raw).map_err(|error| failure(&state, &error))?;
        process(&state, parsed, &headers, post).await
    }
    .await;
    match result {
        Ok(response) | Err(response) => response,
    }
}

pub(in crate::web) async fn resume(
    State(state): State<AppState>,
    Path(ticket): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    let result = async {
        let _namespace = state.require_subject_namespace()?;
        if method != Method::GET {
            return Err(failure(&state, &LtiError::Invalid));
        }
        let mut tx = state
            .db_pool
            .begin()
            .await
            .map_err(|_| failure(&state, &LtiError::Unavailable))?;
        let runtime = current_runtime(&state, &mut tx)
            .await
            .map_err(|error| failure(&state, &error))?;
        let intent = intents::load(
            &mut tx,
            state.environment_id,
            &ticket,
            intents::Ticket::Continuation,
        )
        .await
        .map_err(|error| failure(&state, &error))?;
        let registration = current_intent(&state, &mut tx, &intent, &runtime).await?;
        let request: AuthorizationRequest = serde_json::from_value(
            intent
                .authorization_request
                .clone()
                .ok_or_else(|| failure(&state, &LtiError::Denied))?,
        )
        .map_err(|_| failure(&state, &LtiError::Unavailable))?;
        if request.client_id != intent.client_id
            || intent.status != "initiated"
            || !registration
                .configuration
                .redirect_uris
                .contains(&request.redirect_uri)
        {
            return Err(failure(&state, &LtiError::Denied));
        }
        request
            .validate()
            .map_err(|code| protocol_error(&state, &request, code))?;
        let response = issue(&state, &mut tx, &intent, &registration, &request, &headers).await?;
        tx.commit()
            .await
            .map_err(|_| failure(&state, &LtiError::Unavailable))?;
        Ok::<_, Response>(response)
    }
    .await;
    match result {
        Ok(response) | Err(response) => response,
    }
}

async fn message_fields(
    state: &AppState,
    tx: &mut Transaction<'_, Postgres>,
    intent: &intents::Intent,
    registration: &store::Registration,
) -> Result<(std::collections::BTreeMap<String, serde_json::Value>, i64), Response> {
    let (deployment, link) = registration
        .configuration
        .placement(&intent.deployment_id, &intent.resource_link_id)
        .map_err(|error| failure(state, &error))?;
    let now = intents::now(tx)
        .await
        .map_err(|error| failure(state, &error))?;
    let local = crate::attribute_mapping::load_attribute_sources(
        &mut **tx,
        state.environment_id,
        intent.owner,
    )
    .await
    .map_err(|_| failure(state, &LtiError::Unavailable))?;
    let mapped = claims::evaluate(
        &registration.configuration,
        deployment,
        link,
        &intent.roles,
        &local,
        &ClaimContext {
            environment_id: &state.environment_id.to_string(),
            user_id: &intent.owner.to_string(),
            client_id: &intent.client_id,
            revision: &intent.revision.to_string(),
            producer: &intent.producer.client_id,
            observed_at: intent.created_at,
            expires_at: intent.expires_at,
            now,
        },
    )
    .map_err(|error| failure(state, &error))?;
    let fields = claims::message_claims(mapped, deployment, link);
    Ok((fields, now))
}
