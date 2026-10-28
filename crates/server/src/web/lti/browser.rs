use super::*;
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, Method},
};
use serde_json::json;

async fn initiate(
    state: &AppState,
    tx: &mut Transaction<'_, Postgres>,
    intent: &intents::Intent,
    registration: &store::Registration,
    sid: &str,
) -> Result<Response, Response> {
    let login = intents::random();
    let message = intents::random();
    let (_, link) = registration
        .configuration
        .placement(&intent.deployment_id, &intent.resource_link_id)
        .map_err(|error| failure(state, &error))?;
    let mut url = url::Url::parse(&registration.configuration.initiate_login_uri)
        .map_err(|_| failure(state, &LtiError::Unavailable))?;
    url.query_pairs_mut().extend_pairs([
        ("iss", state.issuer.as_str()),
        ("client_id", intent.client_id.as_str()),
        ("login_hint", login.as_str()),
        ("lti_message_hint", message.as_str()),
        ("lti_deployment_id", intent.deployment_id.as_str()),
        ("target_link_uri", link.target_link_uri.as_str()),
    ]);
    let response = rendering::redirect(url.as_str()).map_err(|error| failure(state, &error))?;
    let updated = sqlx::query("UPDATE aegaeon.lti_launch_intents SET status='initiated',login_hint_hash=$2,message_hint_hash=$3,session_hash=$4,csrf_hash=NULL WHERE id=$1 AND status IN ('pending','confirmed')")
        .bind(intent.id).bind(intents::digest(&login)).bind(intents::digest(&message)).bind(intents::digest(sid))
        .execute(&mut **tx).await.map_err(|_|failure(state, &LtiError::Unavailable))?;
    if updated.rows_affected() != 1 {
        return Err(failure(state, &LtiError::Denied));
    }
    store::audit(
        tx,
        state.environment_id,
        &intent.owner.to_string(),
        "END_USER",
        intent.id,
        "lti.launch.initiated.v1",
        json!({"revision":intent.revision}),
    )
    .await
    .map_err(|error| failure(state, &error))?;
    Ok(response)
}

pub(in crate::web) async fn present(
    State(state): State<AppState>,
    Path(ticket): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    let result = async {
        let _namespace = state.require_subject_namespace()?;
        if method == Method::HEAD {
            return Err(failure(&state, &LtiError::Invalid));
        }
        let (sid, session) = session(&state, &headers).await?;
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
            intents::Ticket::Browser,
        )
        .await
        .map_err(|error| failure(&state, &error))?;
        let registration = current_intent(&state, &mut tx, &intent, &runtime).await?;
        if intent.status != "pending"
            || session.user_id != intent.subject
            || intent
                .session_hash
                .as_ref()
                .is_some_and(|value| *value != intents::digest(&sid))
        {
            return Err(failure(&state, &LtiError::Denied));
        }
        let response = if registration.configuration.security.require_consent {
            let csrf = intents::random();
            sqlx::query(
                "UPDATE aegaeon.lti_launch_intents SET session_hash=$2,csrf_hash=$3 WHERE id=$1",
            )
            .bind(intent.id)
            .bind(intents::digest(&sid))
            .bind(intents::digest(&csrf))
            .execute(&mut *tx)
            .await
            .map_err(|_| failure(&state, &LtiError::Unavailable))?;
            rendering::confirmation(&ticket, &csrf, &registration.configuration.name)
        } else {
            initiate(&state, &mut tx, &intent, &registration, &sid).await?
        };
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

pub(in crate::web) async fn confirm(
    State(state): State<AppState>,
    Path(ticket): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let result=async {
        let _namespace=state.require_subject_namespace()?;
        super::super::request_admission::enforce_content_type(&headers,"application/x-www-form-urlencoded",&state.issuer)?;
        let origin=url::Url::parse(&state.issuer).map_err(|_|failure(&state, &LtiError::Unavailable))?.origin().ascii_serialization();
        if headers.get_all(header::ORIGIN).iter().count()!=1
            || headers.get(header::ORIGIN).and_then(|value|value.to_str().ok())!=Some(origin.as_str()) {
            return Err(failure(&state, &LtiError::Denied));
        }
        let form=std::str::from_utf8(&body).map_err(|_|failure(&state, &LtiError::Invalid))?;
        let fields=crate::lti::request::form(form).map_err(|error|failure(&state, &error))?;
        let csrf=fields.get("csrf").ok_or_else(||failure(&state, &LtiError::Invalid))?;
        let decision=fields.get("decision").ok_or_else(||failure(&state, &LtiError::Invalid))?;
        if fields.len()!=2 || !matches!(decision.as_str(),"approve"|"deny") {return Err(failure(&state, &LtiError::Invalid));}
        let (sid,session)=session(&state,&headers).await?;
        let mut tx=state.db_pool.begin().await.map_err(|_|failure(&state, &LtiError::Unavailable))?;
        let runtime=current_runtime(&state,&mut tx).await.map_err(|error|failure(&state, &error))?;
        let intent=intents::load(&mut tx,state.environment_id,&ticket,intents::Ticket::Browser).await.map_err(|error|failure(&state, &error))?;
        let registration=current_intent(&state,&mut tx,&intent,&runtime).await?;
        if intent.status!="pending" || session.user_id!=intent.subject
            || intent.session_hash.as_deref()!=Some(intents::digest(&sid).as_str())
            || intent.csrf_hash.as_deref()!=Some(intents::digest(csrf).as_str()) {
            return Err(failure(&state, &LtiError::Denied));
        }
        let response=if decision=="deny" {
            sqlx::query("UPDATE aegaeon.lti_launch_intents SET status='cancelled',csrf_hash=NULL WHERE id=$1")
                .bind(intent.id).execute(&mut *tx).await.map_err(|_|failure(&state, &LtiError::Unavailable))?;
            store::audit(&mut tx,state.environment_id,&intent.owner.to_string(),"END_USER",intent.id,"lti.launch.cancelled.v1",json!({"revision":intent.revision}))
                .await.map_err(|error|failure(&state, &error))?;
            rendering::cancelled()
        } else {initiate(&state,&mut tx,&intent,&registration,&sid).await?};
        tx.commit().await.map_err(|_|failure(&state, &LtiError::Unavailable))?;
        Ok::<_,Response>(response)
    }.await;
    match result {
        Ok(response) | Err(response) => response,
    }
}
