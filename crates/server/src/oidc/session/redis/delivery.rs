use super::RedisOidcSessionBackend;
use crate::oidc::session::delivery::{self, Outcome, Parent, Request, STORAGE_ERROR, VERSION};

const SCRIPT: &str = include_str!("delivery.lua");

impl RedisOidcSessionBackend {
    pub(crate) fn delivery_transition(&self, request: &Request) -> Result<Outcome, String> {
        let mut connection = self.connection().map_err(|_| STORAGE_ERROR.to_string())?;
        let session_key = self.keyspace.session_key(&request.identity.sid);
        let clients_key = self.keyspace.clients_key(&request.identity.sid);
        let field = delivery::recipient_field(&request.identity.client_id);
        let override_time = request
            .time_override()
            .map_or_else(String::new, |now| now.to_string());
        for attempt in 0..4 {
            #[cfg(not(test))]
            let _ = attempt;
            let snapshot: Vec<Option<String>> = redis::Script::new(SCRIPT)
                .key(&session_key)
                .key(&clients_key)
                .arg("read")
                .arg(&override_time)
                .arg(&request.identity.client_id)
                .arg(&field)
                .invoke(&mut connection)
                .map_err(|_| STORAGE_ERROR.to_string())?;
            if snapshot.first().and_then(|s| s.as_deref()) == Some("missing") {
                return Ok(Outcome::Missing);
            }
            if snapshot.len() != 8 {
                return Err(STORAGE_ERROR.to_string());
            }
            let get = |n: usize| {
                snapshot[n]
                    .as_deref()
                    .ok_or_else(|| STORAGE_ERROR.to_string())
            };
            let now = get(0)?
                .parse::<u64>()
                .map_err(|_| STORAGE_ERROR.to_string())?;
            if get(1)? != request.identity.subject || get(2)? != request.identity.event_jti {
                return Err(STORAGE_ERROR.to_string());
            }
            let logged_out_at = get(3)?
                .parse::<u64>()
                .map_err(|_| STORAGE_ERROR.to_string())?;
            if now < logged_out_at {
                return Err(STORAGE_ERROR.to_string());
            }
            if snapshot[4].is_none() {
                return Ok(Outcome::LegacyUnknown);
            }
            if get(4)? != VERSION {
                return Err(STORAGE_ERROR.to_string());
            }
            let parent = Parent {
                user_id: get(1)?.to_string(),
                event_jti: get(2)?.to_string(),
                logged_out_at,
                deadline: get(5)?
                    .parse::<u64>()
                    .map_err(|_| STORAGE_ERROR.to_string())?,
            };
            let fractional = match get(7)? {
                "0" => false,
                "1" => true,
                _ => return Err(STORAGE_ERROR.to_string()),
            };
            let result =
                delivery::transition(&parent, snapshot[6].as_deref(), request, now, fractional)?;
            if now >= result.valid_before {
                return Ok(result.outcome);
            }
            #[cfg(test)]
            if attempt == 0 {
                if let Some(barrier) = &request.before_cas {
                    barrier.wait();
                }
            }
            let started = std::time::Instant::now();
            let code: Vec<i64> = redis::Script::new(SCRIPT)
                .key(&session_key)
                .key(&clients_key)
                .arg("cas")
                .arg(&override_time)
                .arg(&request.identity.client_id)
                .arg(&field)
                .arg(get(1)?)
                .arg(get(2)?)
                .arg(get(3)?)
                .arg(get(4)?)
                .arg(get(5)?)
                .arg(if snapshot[6].is_some() { "1" } else { "0" })
                .arg(snapshot[6].as_deref().unwrap_or(""))
                .arg(now)
                .arg(result.valid_before)
                .arg(if result.record.is_some() { "1" } else { "0" })
                .arg(result.record.as_deref().unwrap_or(""))
                .invoke(&mut connection)
                .map_err(|_| STORAGE_ERROR.to_string())?;
            if let Some(outcome) = cas_outcome(&code, result.outcome, started)? {
                return Ok(outcome);
            }
        }
        Ok(Outcome::Deferred)
    }
}

fn cas_outcome(
    code: &[i64],
    mut outcome: Outcome,
    started: std::time::Instant,
) -> Result<Option<Outcome>, String> {
    if code.len() != 2 {
        return Err(STORAGE_ERROR.to_string());
    }
    if code[0] == 1 {
        if let Outcome::Granted(permit) = &mut outcome {
            let millis = u64::try_from(code[1]).map_err(|_| STORAGE_ERROR.to_string())?;
            let deadline = started
                .checked_add(std::time::Duration::from_millis(millis))
                .ok_or_else(|| STORAGE_ERROR.to_string())?;
            permit.retention_deadline = Some(
                permit
                    .retention_deadline
                    .map_or(deadline, |old| old.min(deadline)),
            );
        }
        Ok(Some(outcome))
    } else if code[0] != 0 {
        Ok(Some(Outcome::Deferred))
    } else {
        Ok(None)
    }
}
