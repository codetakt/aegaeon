use super::*;
#[cfg(test)]
use crate::oidc::session::delivery::{self, Parent, VERSION};
use crate::oidc::session::delivery::{Outcome, Request, STORAGE_ERROR};

impl OidcSessionStore {
    pub(crate) fn delivery_transition(&self, request: &Request) -> Result<Outcome, String> {
        match &self.backend {
            OidcSessionBackend::Redis(backend) => backend.delivery_transition(request),
            #[cfg(test)]
            OidcSessionBackend::InMemory(store) => {
                let time = request.time_override().map_or_else(
                    || {
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map_err(|_| STORAGE_ERROR.to_string())
                    },
                    |now| Ok(std::time::Duration::from_secs(now)),
                )?;
                let now = time.as_secs();
                let mut store = store.write().map_err(|_| STORAGE_ERROR.to_string())?;
                let Some(session) = store.sessions.get_mut(&request.identity.sid) else {
                    return Ok(Outcome::Missing);
                };
                if session.user_id != request.identity.subject
                    || session.logout_jti.as_deref() != Some(&request.identity.event_jti)
                    || !session.clients.contains(&request.identity.client_id)
                {
                    return Err(STORAGE_ERROR.to_string());
                }
                let logged_out_at = session
                    .logged_out_at_epoch_secs
                    .ok_or_else(|| STORAGE_ERROR.to_string())?;
                if now < logged_out_at {
                    return Err(STORAGE_ERROR.to_string());
                }
                if session.delivery_version.is_none() {
                    return Ok(Outcome::LegacyUnknown);
                }
                if session.delivery_version.as_deref() != Some(VERSION) {
                    return Err(STORAGE_ERROR.to_string());
                }
                let parent = Parent {
                    user_id: session.user_id.clone(),
                    event_jti: request.identity.event_jti.clone(),
                    logged_out_at,
                    deadline: session
                        .delivery_deadline
                        .ok_or_else(|| STORAGE_ERROR.to_string())?,
                };
                let field = delivery::recipient_field(&request.identity.client_id);
                let result = delivery::transition(
                    &parent,
                    session.deliveries.get(&field).map(String::as_str),
                    request,
                    now,
                    time.subsec_nanos() != 0,
                )?;
                if now < result.valid_before {
                    if let Some(record) = result.record {
                        session.deliveries.insert(field, record);
                    }
                }
                Ok(result.outcome)
            }
        }
    }

    pub(crate) async fn delivery_transition_async(
        &self,
        request: Request,
    ) -> Result<Outcome, String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.delivery_transition(&request))
            .await
            .map_err(|_| STORAGE_ERROR.to_string())?
    }
}
