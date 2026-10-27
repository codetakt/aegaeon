use super::RedisOidcSessionBackend;
use crate::oidc::session::delivery::{self, Outcome, Parent, Request, STORAGE_ERROR, VERSION};

const SCRIPT: &str = r#"-- All times stay decimal strings. Never cjson-decode stored state or round u64/i64 through Lua doubles.
local function decimal(value)
  return value and string.match(value, "^%d+$") and (value == "0" or string.sub(value, 1, 1) ~= "0")
end
local function before(left, right)
  if string.len(left) ~= string.len(right) then return string.len(left) < string.len(right) end
  return left < right
end
local now = ARGV[2]
local fractional = "0"
local micros = "0"
if now == "" then
  local time = redis.call("TIME")
  now = time[1]
  micros = time[2]
  if time[2] ~= "0" then fractional = "1" end
end
if not decimal(now) then return redis.error_reply("invalid delivery clock") end
if redis.call("EXISTS", KEYS[1]) == 0 then
  if ARGV[1] == "read" then return {"missing"} else return {-1, 0, now, micros} end
end
local values = redis.call("HMGET", KEYS[1], "user_id", "logout_jti", "logged_out_at_epoch_secs", "logout_delivery_version", "logout_delivery_deadline")
if not values[1] or values[1] == "" or not values[2] or values[2] == "" or not decimal(values[3])
  or before(now, values[3]) or redis.call("PTTL", KEYS[1]) <= 0 or redis.call("PTTL", KEYS[2]) <= 0
  or redis.call("SISMEMBER", KEYS[2], ARGV[3]) ~= 1 then
  return redis.error_reply("invalid delivery parent")
end
if values[4] and (values[4] ~= "1" or not decimal(values[5])) then
  return redis.error_reply("invalid delivery protocol marker")
end
local prior = redis.call("HGET", KEYS[1], ARGV[4])
if ARGV[1] == "read" then
  return {now, values[1], values[2], values[3], values[4], values[5], prior, fractional}
end
if ARGV[1] ~= "cas" then return redis.error_reply("invalid delivery operation") end
for index = 1, 5 do
  if values[index] ~= ARGV[index + 4] then return {0, 0, now, micros} end
end
if values[4] ~= "1" or not decimal(values[5]) or not decimal(ARGV[12]) or not decimal(ARGV[13])
  or before(now, ARGV[12]) or not before(now, values[5]) or not before(now, ARGV[13])
  or before(values[5], ARGV[13]) then return {-1, 0, now, micros} end
if (ARGV[10] == "0" and prior) or (ARGV[10] == "1" and prior ~= ARGV[11]) then return {0, 0, now, micros} end
if ARGV[14] == "1" then redis.call("HSET", KEYS[1], ARGV[4], ARGV[15]) end
-- HSET retains the existing expiry. No EXPIRE, renewal, parent reconstruction or index allocation.
return {1, math.min(redis.call("PTTL", KEYS[1]), redis.call("PTTL", KEYS[2])), now, micros}
"#;

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
            let code: Vec<String> = redis::Script::new(SCRIPT)
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
    code: &[String],
    mut outcome: Outcome,
    started: std::time::Instant,
) -> Result<Option<Outcome>, String> {
    if code.len() != 4 {
        return Err(STORAGE_ERROR.to_string());
    }
    if code[0] == "1" {
        if let Outcome::Granted(permit) = &mut outcome {
            let parse = |index: usize| {
                code[index]
                    .parse::<u64>()
                    .map_err(|_| STORAGE_ERROR.to_string())
            };
            let millis = parse(1)?;
            let seconds = parse(2)?;
            let micros = parse(3)?;
            if millis == 0 || seconds < permit.checked_at || micros >= 1_000_000 {
                return Err(STORAGE_ERROR.to_string());
            }
            let authority_now =
                std::time::Duration::from_secs(seconds) + std::time::Duration::from_micros(micros);
            // PTTL has millisecond resolution; reserve one tick rather than extending
            // the true expiry by its fractional rounding interval.
            permit.bind_send_deadline(
                started,
                authority_now,
                Some(std::time::Duration::from_millis(millis.saturating_sub(1))),
            )?;
        }
        Ok(Some(outcome))
    } else if code[0] != "0" {
        Ok(Some(Outcome::Deferred))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oidc::session::delivery::Permit;
    use std::time::{Duration, Instant};

    fn granted(epoch: u64) -> Outcome {
        Outcome::Granted(Permit {
            owner: "owner".into(),
            attempt: 1,
            deadline: epoch + 7,
            horizon: epoch + 300,
            checked_at: epoch,
            token: "token".into(),
            send_deadline: None,
        })
    }

    #[test]
    fn logout_delivery_cas_clock_binds_fractional_monotonic_budget() {
        let started = Instant::now();
        // Exact server epoch integers, including values above binary64's exact range,
        // have no relationship to the process wall clock.
        for epoch in [100, 1_900_000_000, (1_u64 << 53) + 1] {
            let code = [
                "1".into(),
                "600000".into(),
                epoch.to_string(),
                "750000".into(),
            ];
            let Some(Outcome::Granted(mut permit)) =
                cas_outcome(&code, granted(epoch), started).expect("CAS")
            else {
                panic!("permit")
            };
            let deadline = started + Duration::from_millis(6250);
            assert_eq!(permit.send_deadline, Some(deadline));
            // RPC/processing delay is consumed, not added to the remaining interval.
            assert_eq!(
                deadline.checked_duration_since(started + Duration::from_secs(2)),
                Some(Duration::from_millis(4250))
            );
            assert_eq!(
                deadline.checked_duration_since(started + Duration::from_secs(7)),
                None
            );
            permit
                .bind_send_deadline(
                    started + Duration::from_secs(1),
                    Duration::from_secs(epoch),
                    None,
                )
                .expect("recheck");
            assert_eq!(
                permit.send_deadline,
                Some(deadline),
                "a recheck never renews the budget"
            );
            let short = [
                "1".into(),
                "1250".into(),
                epoch.to_string(),
                "750000".into(),
            ];
            let Some(Outcome::Granted(permit)) =
                cas_outcome(&short, granted(epoch), started).expect("CAS")
            else {
                panic!("permit")
            };
            assert_eq!(
                permit.send_deadline,
                Some(started + Duration::from_millis(1249))
            );
        }
    }

    #[test]
    fn logout_delivery_cas_rejects_invalid_or_exhausted_time() {
        for code in [
            vec!["1", "500", "100"],
            vec!["1", "0", "100", "0"],
            vec!["1", "-1", "100", "0"],
            vec!["1", "500", "99", "0"],
            vec!["1", "500", "100", "1000000"],
            vec!["1", "500", "107", "0"],
            vec!["1", "500", "invalid", "0"],
        ] {
            let code = code.into_iter().map(str::to_string).collect::<Vec<_>>();
            assert!(cas_outcome(&code, granted(100), Instant::now()).is_err());
        }
    }
}
