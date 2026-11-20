use super::*;
use axum::response::Redirect;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Query {
    state: String,
    code: Option<String>,
    error: Option<String>,
    iss: Option<String>,
    error_description: Option<String>,
}
pub(super) async fn callback(
    State(state): State<AppState>,
    Extension(admission): Extension<ResourceAdmission>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    complete(&state, &admission, query, &headers)
        .await
        .unwrap_or_else(IntoResponse::into_response)
}
async fn complete(
    state: &AppState,
    admission: &ResourceAdmission,
    query: Option<String>,
    headers: &HeaderMap,
) -> Result<Response> {
    let raw = query.filter(|q| q.len() <= 8192).ok_or(Error::Invalid)?;
    let q: Query = serde_urlencoded::from_str(&raw).map_err(|_| Error::Invalid)?;
    if q.state.len() > 512
        || q.code.is_some() == q.error.is_some()
        || q.iss.as_deref() != Some(state.issuer.as_str())
        || q.error_description.is_some() && q.error.is_none()
    {
        return Err(Error::Invalid);
    }
    let store = state.hosted.as_deref().ok_or(Error::Unavailable)?;
    let browser = cookies::browser(store, headers).ok_or(Error::Refused)?;
    let mut tx = store.begin().await?;
    let mut f = store
        .find(&mut tx, Find::OAuth(&q.state, true))
        .await?
        .ok_or(Error::Refused)?;
    f.bound(
        &generation(state.environment_id)?,
        &store.mac("binding", &browser),
        headers,
        now()?,
    )?;
    if now()? >= f.deadline {
        return Err(Error::Refused);
    }
    authority::current_for_flow(state, admission, &f).await?;
    let auth = f.authorization.take().ok_or(Error::Refused)?;
    let new_session = redeem_callback(
        state,
        headers,
        store,
        &mut tx,
        &mut f,
        &auth,
        q.code.as_deref(),
    )
    .await?;
    store.save(&mut tx, &f).await?;
    admission.0.admit_commit().map_err(|_| Error::Unavailable)?;
    tx.commit().await?;
    if f.grant.is_none() {
        store.wake_cleanup()
    }
    let mut response = Redirect::to(&format!("{LANDING}?flow={}", f.handle)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    if let Some(token) = new_session {
        cookies::set(
            &mut response,
            &cookies::session(f.id),
            &token,
            f.session_until - now()?,
        )
    }
    Ok(response)
}

async fn redeem_callback(
    state: &AppState,
    headers: &HeaderMap,
    store: &Store,
    tx: &mut PgTransaction<'_>,
    f: &mut Flow,
    auth: &oauth::Authorization,
    code: Option<&str>,
) -> Result<Option<String>> {
    let mut new_session = None;
    if let Some(code) = code {
        let issuer_cookie =
            cookies::cookie(headers, crate::web::AUTH_SESSION_COOKIE_NAME).ok_or(Error::Refused)?;
        let session = state
            .browser_auth
            .auth_sessions
            .try_get_async(issuer_cookie.into())
            .await
            .map_err(|_| Error::Unavailable)?
            .ok_or(Error::Refused)?;
        match oauth::redeem(state, auth, code, store.secret(f.domain)?).await {
            Ok(grant) => {
                let live_until = i64::try_from(session.expires_at_epoch_secs)
                    .map_err(|_| Error::Refused)?
                    .min(f.deadline);
                if session.user_id != grant.subject
                    || f.session_subject
                        .as_ref()
                        .is_some_and(|sub| sub != &grant.subject)
                    || live_until <= now()?
                    || f.expected_subject
                        .as_ref()
                        .is_some_and(|(subject, cutoff)| {
                            subject != &grant.subject || grant.auth_time <= *cutoff
                        })
                {
                    store.cleanup(tx, f.domain, &grant.cleanup).await?;
                    f.step = flow::Step::Invitation;
                } else {
                    let token = aegaeon_crypto::rand::random_base64url(32);
                    f.handle = Uuid::new_v4();
                    f.session = Some(store::hash(&token));
                    f.session_until = live_until;
                    f.session_subject = Some(grant.subject.clone());
                    f.step = flow::Step::SignedIn;
                    f.grant = Some(grant);
                    new_session = Some(token);
                }
            }
            Err(err) => {
                let retry = err.reason == oauth::Error::Unavailable;
                if let Some(cleanup) = err.cleanup {
                    store.cleanup(tx, f.domain, &cleanup).await?
                }
                f.step = if retry {
                    flow::Step::LoginUnavailable
                } else {
                    flow::Step::Invitation
                };
            }
        }
    } else {
        f.step = flow::Step::Invitation
    }
    Ok(new_session)
}
