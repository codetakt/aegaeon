//! Post-work store seals. These methods never confer admission or clear pending.
use super::{Error, Result};
use uuid::Uuid;

pub(super) mod catalog;
fn migration() -> &'static str {
    include_str!("../../../../../tests/organizations/legacy-store-continuity.sql")
}
const KEY: &str = "aegaeon:organization-store-continuity:v1";

const READ: &str = r"
local kind = redis.call('TYPE', KEYS[1]).ok
if kind == 'none' then return false end
if kind ~= 'string' or redis.call('STRLEN', KEYS[1]) ~= 73 or redis.call('PTTL', KEYS[1]) ~= -1 then
  return redis.error_reply('invalid continuity marker type or expiry')
end
return redis.call('GET', KEYS[1])
";
const REPLACE: &str = r"
local kind = redis.call('TYPE', KEYS[1]).ok
if kind ~= 'none' and kind ~= 'string' then
  return redis.error_reply('invalid continuity marker type')
end
if kind == 'string' and redis.call('STRLEN', KEYS[1]) ~= 73 then
  return redis.error_reply('invalid continuity marker length')
end
local current = redis.call('GET', KEYS[1])
if current and redis.call('PTTL', KEYS[1]) ~= -1 then
  return redis.error_reply('continuity marker must not expire')
end
if (current or '') ~= ARGV[1] then
  return redis.error_reply('continuity seal compare-and-swap refused')
end
redis.call('SET', KEYS[1], ARGV[2])
return ARGV[2]
";

pub(super) fn request(deployment: Uuid, replacement: Option<(Option<Uuid>, Uuid)>) -> Result<()> {
    if deployment.is_nil()
        || replacement.is_some_and(|(expected, next)| {
            next.is_nil() || expected.is_some_and(|value| value.is_nil() || value == next)
        })
    {
        return Err(Error::Refused);
    }
    Ok(())
}

pub(super) async fn primary(
    connection: &mut sqlx::PgConnection,
    deployment: Uuid,
    replacement: Option<(Option<Uuid>, Uuid)>,
) -> Result<Option<Uuid>> {
    if let Some((expected, next)) = replacement {
        let changed: Uuid =
            sqlx::query_scalar("SELECT aegaeon.organization_store_continuity_replace_v1($1,$2,$3)")
                .bind(deployment)
                .bind(expected)
                .bind(next)
                .fetch_one(&mut *connection)
                .await?;
        if changed != next {
            return Err(Error::Refused);
        }
    }
    let current: Option<Uuid> =
        sqlx::query_scalar("SELECT aegaeon.organization_store_continuity_read_v1($1)")
            .bind(deployment)
            .fetch_one(connection)
            .await?;
    if current.is_some_and(|value| value.is_nil())
        || replacement.is_some_and(|(_, next)| current != Some(next))
    {
        return Err(Error::Refused);
    }
    Ok(current)
}

fn parse(value: Option<String>, deployment: Uuid) -> Result<Option<Uuid>> {
    let Some(value) = value else { return Ok(None) };
    let (owner, seal) = value.split_once(':').ok_or(Error::Refused)?;
    let seal = Uuid::parse_str(seal).map_err(|_| Error::Refused)?;
    if owner != deployment.to_string() || seal.is_nil() || value != format!("{deployment}:{seal}") {
        return Err(Error::Refused);
    }
    Ok(Some(seal))
}

pub(super) async fn token(
    connection: &mut ::redis::aio::MultiplexedConnection,
    deployment: Uuid,
    replacement: Option<(Option<Uuid>, Uuid)>,
) -> Result<Option<Uuid>> {
    if let Some((expected, next)) = replacement {
        let previous = expected.map_or_else(String::new, |seal| format!("{deployment}:{seal}"));
        let changed: String = ::redis::cmd("EVAL")
            .arg(REPLACE)
            .arg(1)
            .arg(KEY)
            .arg(previous)
            .arg(format!("{deployment}:{next}"))
            .query_async(connection)
            .await?;
        if parse(Some(changed), deployment)? != Some(next) {
            return Err(Error::Refused);
        }
        // WAITAOF is outside MULTI/scripts and follows our own SET on this link.
        let persisted: (i64, i64) = ::redis::cmd("WAITAOF")
            .arg(1)
            .arg(0)
            .arg(4000)
            .query_async(connection)
            .await?;
        if persisted.0 != 1 || persisted.1 < 0 {
            return Err(Error::Refused);
        }
    }
    let value: Option<String> = ::redis::cmd("EVAL")
        .arg(READ)
        .arg(1)
        .arg(KEY)
        .query_async(connection)
        .await?;
    let current = parse(value, deployment)?;
    if replacement.is_some_and(|(_, next)| current != Some(next)) {
        return Err(Error::Refused);
    }
    Ok(current)
}

#[cfg(test)]
mod tests;
