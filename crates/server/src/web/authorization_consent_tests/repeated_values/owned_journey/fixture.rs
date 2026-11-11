//! Administrative setup and bounded readback for one disposable generation.
use super::*;
use crate::config::{RuntimeRedisAtomicGroup, RuntimeStateNamespace};
use std::collections::BTreeMap;

pub(super) async fn activate(admin: &PgPool, state: &AppState) -> TestResult<Selection> {
    let previous: Option<(Uuid, Uuid)> =
        sqlx::query_as("SELECT deployment_id,generation FROM aegaeon_lifecycle.current")
            .fetch_optional(admin)
            .await?;
    let selected = Selection::new(previous.map_or_else(Uuid::new_v4, |v| v.0), Uuid::new_v4())?;
    // The ordinary fixture provisions the runtime role. Its separate management
    // actor needs only these lifecycle read grants to join the checked runtime.
    let management = state
        .management
        .database
        .as_ref()
        .ok_or("management pool")?;
    let grants: String = sqlx::query_scalar(
        "SELECT format('GRANT USAGE ON SCHEMA aegaeon_lifecycle TO %I; GRANT SELECT ON aegaeon_lifecycle.current TO %I', $1::text, $1::text)",
    )
    .bind(management.connect_options().get_username())
    .fetch_one(admin)
    .await?;
    sqlx::raw_sql(&grants).execute(admin).await?;
    sqlx::query("SELECT aegaeon_lifecycle.activate_v1($1,$2,$3,$4)")
        .bind(selected.deployment_id())
        .bind(previous.map(|v| v.1))
        .bind(selected.generation())
        .bind(Uuid::new_v4())
        .execute(admin)
        .await?;
    Ok(selected)
}

pub(super) async fn bind(state: &mut AppState, selected: Selection) -> TestResult<Arc<Runtime>> {
    let runtime = Runtime::checked_with_management(
        selected,
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .acquire_timeout(Duration::from_secs(2)),
        state.db_pool.connect_options().as_ref().clone(),
        vec![(state.environment_id, state.issuer.to_string())],
        Limits {
            ordinary: 4,
            revocation: 1,
            snapshot: 1,
        },
        state
            .management
            .database
            .as_ref()
            .map(|pool| pool.connect_options().as_ref().clone()),
    )
    .await?;
    let old = std::mem::replace(&mut state.db_pool, runtime.pool().clone());
    crate::organizations::lifecycle::close_pool(&old).await;
    let old = state.management.database.replace(
        runtime
            .management_pool()
            .ok_or("checked management pool")?
            .clone(),
    );
    if let Some(old) = old {
        crate::organizations::lifecycle::close_pool(&old).await;
    }
    Ok(runtime)
}

pub(super) async fn release_fence(admin: &PgPool) -> TestResult {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            // Same lock as lifecycle::Selection::bind; autocommit releases this
            // exclusive probe before reply. A close future alone is insufficient.
            let released: bool =
                sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(1095189836,1)")
                    .fetch_one(admin)
                    .await?;
            if released {
                return Ok::<_, sqlx::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    Ok(())
}

pub(super) fn assert_owner(runtime: &Arc<Runtime>, environment: Uuid) -> TestResult {
    let owner = async_store::current_owner()?;
    assert!(Arc::ptr_eq(
        owner.current_runtime()?.ok_or("checked owner")?,
        runtime
    ));
    assert_eq!(owner.epoch_binding()?.environment_id(), environment);
    owner.require_store_scope()?;
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Snapshot {
    records: BTreeMap<[u8; 32], [u8; 32]>,
    counts: BTreeMap<&'static str, usize>,
}

impl Snapshot {
    pub(super) fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub(super) fn require_surfaces(&self, surfaces: &[&str]) {
        for surface in surfaces {
            assert!(
                self.counts.get(surface).is_some_and(|count| *count > 0),
                "actual key publication missing for {surface}: {:?}",
                self.counts
            );
        }
        eprintln!("checked runtime protocol key counts: {:?}", self.counts);
    }
}

pub(super) fn snapshot(namespace: &RuntimeStateNamespace) -> TestResult<Snapshot> {
    let url =
        crate::config::require_shared_runtime_store_url("PAR fixture", "AEGAEON_PAR_REDIS_URL")?;
    for key in [
        "AEGAEON_REQUEST_OBJECT_JTI_REDIS_URL",
        "AEGAEON_AUTH_CODE_REDIS_URL",
        "AEGAEON_TOKEN_STORE_REDIS_URL",
    ] {
        let other = crate::config::require_shared_runtime_store_url("journey fixture", key)?;
        assert!(crate::config::redis_store_urls_reference_same_endpoint(
            url.as_str(),
            other.as_str()
        ));
    }
    let mut connection =
        redis::Client::open(url.as_str())?.get_connection_with_timeout(Duration::from_secs(2))?;
    connection.set_read_timeout(Some(Duration::from_secs(2)))?;
    connection.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut snapshot = Snapshot {
        records: BTreeMap::new(),
        counts: BTreeMap::new(),
    };
    for (surface, version) in [
        ("par", "v3"),
        ("request-object-jti", "replay:v1"),
        ("authcode", "v3"),
        ("token-store", "v3"),
    ] {
        let prefix = namespace.redis_atomic_group_prefix(
            RuntimeRedisAtomicGroup::AuthorizationCodeGrant,
            surface,
            version,
        );
        let keys: Vec<Vec<u8>> = redis::cmd("KEYS")
            .arg(format!("{prefix}:*"))
            .query(&mut connection)?;
        assert!(keys.len() <= 64, "bounded fixture namespace");
        snapshot.counts.insert(surface, keys.len());
        for key in keys {
            let value: Vec<u8> = redis::cmd("DUMP").arg(&key).query(&mut connection)?;
            assert!(value.len() <= 1_048_576, "bounded fixture record");
            // Failure diagnostics contain hashes, never tokens, JTI or credentials.
            snapshot.records.insert(
                aegaeon_crypto::hash::sha256_digest(&key),
                aegaeon_crypto::hash::sha256_digest(&value),
            );
        }
    }
    Ok(snapshot)
}
