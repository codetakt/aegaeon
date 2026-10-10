use super::super::{
    now_unix_millis, redis_poll_result, scripts, RedisDeviceCodeEntry, RedisDeviceCodeStoreBackend,
    SLOW_DOWN_INCREMENT_SECS,
};
use super::DevicePollAdmission;
use crate::authcode::token::AccessTokenAudiencePolicy;
use crate::device_authz::{DeviceAuthzStatus, DevicePollResult};
use anyhow::{anyhow, ensure, Context, Result};
use std::sync::{Arc, Barrier};

const CLIENT: &str = "device-admission-client";
const SUBJECT: &str = "device-admission-subject";
const RESOURCE: &str = "https://resource.example/approved";

#[derive(Clone)]
struct Fixture {
    backend: RedisDeviceCodeStoreBackend,
    hash: String,
    lookup: String,
}

impl Fixture {
    fn new(url: &str, scope: Option<&str>, resource: Option<&str>) -> Result<Self> {
        let id = aegaeon_crypto::rand::random_base64url(16);
        let backend = RedisDeviceCodeStoreBackend::new_with_prefix(
            url,
            format!("device-admission-test:v2:{{{id}}}"),
        )?;
        let fixture = Self {
            backend,
            hash: format!("hash-{id}"),
            lookup: format!("lookup-{id}"),
        };
        let now = now_unix_millis();
        let scope = scope.map(str::to_owned);
        let entry = RedisDeviceCodeEntry {
            device_code_hash: fixture.hash.clone(),
            user_code_lookup_key: fixture.lookup.clone(),
            client_id: CLIENT.into(),
            scope: scope.clone(),
            resource: resource.map(str::to_owned),
            environment_id: None,
            status: DeviceAuthzStatus::Approved {
                user_id: SUBJECT.into(),
                scope,
            },
            expires_at_ms: now.checked_add(60_000).context("fixture expiry overflow")?,
            last_poll_at_ms: None,
            poll_interval_secs: 0,
            consumed: false,
        };
        ensure!(
            fixture
                .backend
                .insert_entry(&fixture.hash, &fixture.lookup, &entry, now)?,
            "fixture insertion collided"
        );
        Ok(fixture)
    }

    fn capture(
        &self,
        conn: &mut redis::Connection,
        policy: &AccessTokenAudiencePolicy,
    ) -> Result<DevicePollAdmission> {
        Ok(DevicePollAdmission::read(
            conn,
            &self.backend.keyspace.entry_key(&self.hash),
            CLIENT,
            policy,
        )?)
    }

    fn poll(
        &self,
        conn: &mut redis::Connection,
        admission: &DevicePollAdmission,
    ) -> redis::RedisResult<DevicePollResult> {
        // Preserve the captured decision instead of rereading it in backend.poll.
        // This creates the otherwise scheduling-dependent read/consume race.
        let reply = redis::Script::new(scripts::POLL)
            .key(self.backend.keyspace.entry_key(&self.hash))
            .key(self.backend.keyspace.expiries_key())
            .arg(CLIENT)
            .arg("0")
            .arg("")
            .arg("0")
            .arg("")
            .arg(now_unix_millis())
            .arg(SLOW_DOWN_INCREMENT_SECS)
            .arg(&self.hash)
            .arg(self.backend.keyspace.entry_key_prefix())
            .arg(self.backend.keyspace.user_code_key_prefix())
            .arg("1")
            .arg(&admission.scope_present)
            .arg(&admission.scope)
            .arg(&admission.resource_present)
            .arg(&admission.resource)
            .arg(if admission.allowed { "1" } else { "0" })
            .invoke::<Vec<String>>(conn)?;
        Ok(redis_poll_result(&reply))
    }

    fn keys_present(&self, conn: &mut redis::Connection) -> redis::RedisResult<usize> {
        redis::cmd("EXISTS")
            .arg(self.backend.keyspace.entry_key(&self.hash))
            .arg(self.backend.keyspace.user_code_key(&self.lookup))
            .arg(self.backend.keyspace.expiries_key())
            .query(conn)
    }
}

fn redis_url() -> Result<String> {
    let url = std::env::var("AEGAEON_TEST_REDIS_URL")
        .context("AEGAEON_TEST_REDIS_URL is required; this test must execute Redis")?;
    ensure!(!url.trim().is_empty(), "Redis test URL must not be empty");
    Ok(url)
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn changed_admission_fields_retain_approval_until_exact_snapshot_is_restored() -> Result<()> {
    let url = redis_url()?;
    let policy =
        AccessTokenAudiencePolicy::new(true, Some("https://issuer.example/userinfo".into()));
    let cases = [
        (Some("openid"), Some(RESOURCE), "scope_present", "0"),
        (Some("openid"), Some(RESOURCE), "scope", "profile"),
        (Some("openid"), Some(RESOURCE), "resource_present", "0"),
        (
            Some("openid"),
            Some(RESOURCE),
            "resource",
            "https://resource.example/different",
        ),
        // Same empty bytes with a changed flag must still fail the comparison.
        (None, Some(RESOURCE), "scope_present", "1"),
        (Some("openid"), None, "resource_present", "1"),
    ];
    for (scope, resource, field, changed) in cases {
        let fixture = Fixture::new(url.trim(), scope, resource)?;
        let mut conn = fixture.backend.connection()?;
        let admission = fixture.capture(&mut conn, &policy)?;
        ensure!(admission.allowed, "original target must be admitted");
        let entry_key = fixture.backend.keyspace.entry_key(&fixture.hash);
        let original: String = redis::cmd("HGET")
            .arg(&entry_key)
            .arg(field)
            .query(&mut conn)?;
        redis::cmd("HSET")
            .arg(&entry_key)
            .arg(field)
            .arg(changed)
            .query::<usize>(&mut conn)?;
        let error = fixture
            .poll(&mut conn, &admission)
            .err()
            .context("changed snapshot must be rejected before approved consumption")?;
        ensure!(
            error
                .to_string()
                .contains("grant changed during resource admission"),
            "unexpected snapshot rejection: {error}"
        );
        ensure!(
            fixture.keys_present(&mut conn)? == 3,
            "{field}: grant keys were removed"
        );
        let status: String = redis::cmd("HGET")
            .arg(&entry_key)
            .arg("status")
            .query(&mut conn)?;
        ensure!(status == "approved", "{field}: approval was changed");
        let score: Option<u64> = redis::cmd("ZSCORE")
            .arg(fixture.backend.keyspace.expiries_key())
            .arg(&fixture.hash)
            .query(&mut conn)?;
        ensure!(score.is_some(), "{field}: expiry membership was removed");
        redis::cmd("HSET")
            .arg(&entry_key)
            .arg(field)
            .arg(&original)
            .query::<usize>(&mut conn)?;
        ensure!(
            matches!(fixture.poll(&mut conn, &admission)?, DevicePollResult::Approved { user_id, scope: saved_scope, resource: saved_resource, client_id }
                if user_id == SUBJECT && client_id == CLIENT && saved_scope.as_deref() == scope && saved_resource.as_deref() == resource),
            "{field}: exact restoration must redeem the original grant"
        );
        ensure!(
            matches!(
                fixture.poll(&mut conn, &admission)?,
                DevicePollResult::ExpiredToken
            ),
            "{field}: restored grant must remain single use"
        );
        ensure!(
            fixture.keys_present(&mut conn)? == 0,
            "{field}: consumed keys remain"
        );
    }
    Ok(())
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn concurrent_polls_with_same_admitted_snapshot_have_one_consuming_winner() -> Result<()> {
    let url = redis_url()?;
    let fixture = Fixture::new(url.trim(), Some("openid"), Some(RESOURCE))?;
    let policy = AccessTokenAudiencePolicy::new(true, None);
    let mut first = fixture.backend.connection()?;
    let second = fixture.backend.connection()?;
    let admission = Arc::new(fixture.capture(&mut first, &policy)?);
    ensure!(admission.allowed, "original target must be admitted");
    let barrier = Arc::new(Barrier::new(2));
    let workers: Vec<_> = [first, second]
        .into_iter()
        .map(|mut conn| {
            let fixture = fixture.clone();
            let admission = Arc::clone(&admission);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                fixture.poll(&mut conn, &admission)
            })
        })
        .collect();
    let joined: Vec<_> = workers
        .into_iter()
        .map(std::thread::JoinHandle::join)
        .collect();
    let mut approved = 0;
    let mut expired = 0;
    for output in joined {
        match output.map_err(|_| anyhow!("concurrent device poll worker panicked"))?? {
            DevicePollResult::Approved {
                user_id,
                scope,
                resource,
                client_id,
            } if user_id == SUBJECT
                && client_id == CLIENT
                && scope.as_deref() == Some("openid")
                && resource.as_deref() == Some(RESOURCE) =>
            {
                approved += 1
            }
            DevicePollResult::ExpiredToken => expired += 1,
            result => return Err(anyhow!("unexpected concurrent poll result: {result:?}")),
        }
    }
    ensure!(
        approved == 1 && expired == 1,
        "expected one winner, got {approved}/{expired}"
    );
    let mut conn = fixture.backend.connection()?;
    ensure!(
        fixture.keys_present(&mut conn)? == 0,
        "consumed keys remain"
    );
    Ok(())
}
