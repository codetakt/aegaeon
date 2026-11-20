//! Shared BFF persistence. Browser handles are selectors, never authority.
//! SQL keys and the restored runtime generation are checked against sealed data.
use super::{oauth, AppState, Error, Flow, Generation, Result};
use aegaeon_crypto::{hash::sha256_digest, mac::HmacSha256Key};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, PgPool, PgTransaction, Row};
use std::{
    collections::BTreeMap,
    io::Read,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    sync::Arc,
    time::Duration,
};
use uuid::Uuid;
use zeroize::Zeroizing;

pub(crate) struct Store {
    pub(super) pool: PgPool,
    wake: Arc<tokio::sync::Notify>,
    key: Zeroizing<[u8; 32]>,
    mac: HmacSha256Key,
    clients: BTreeMap<Uuid, Zeroizing<String>>,
    issuer: String,
    environment: Uuid,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    database_url: String,
    key: String,
    clients: BTreeMap<Uuid, String>,
}

impl Store {
    pub(crate) async fn configured(
        issuer: &str,
        environment: Uuid,
    ) -> anyhow::Result<Option<Arc<Self>>> {
        let Some(path) = std::env::var_os("AEGAEON_HOSTED_INVITATION_CONFIG_FILE") else {
            return Ok(None);
        };
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
            )
            .open(path)?;
        let metadata = file.metadata()?;
        anyhow::ensure!(
            metadata.is_file() && metadata.permissions().mode() & 0o077 == 0,
            "hosted configuration requires a private regular file"
        );
        let mut bytes = Zeroizing::new(Vec::new());
        file.take(65537).read_to_end(&mut bytes)?;
        anyhow::ensure!(
            bytes.len() <= 65536,
            "hosted configuration exceeds its size limit"
        );
        let config: Config = crate::util::deserialize_json_without_duplicate_object_keys(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid hosted configuration"))?;
        let master = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(config.key)
                .map_err(|_| anyhow::anyhow!("invalid hosted key"))?,
        );
        anyhow::ensure!(
            master.len() == 32
                && !config.clients.is_empty()
                && config
                    .clients
                    .values()
                    .all(|s| !s.is_empty() && s.len() <= 4096),
            "invalid hosted credentials"
        );
        let (key, mac) = flow_keys(&master)?;
        let pool = PgPoolOptions::new()
            .max_connections(12)
            .acquire_timeout(Duration::from_secs(3))
            .connect(&config.database_url)
            .await
            .map_err(|_| anyhow::anyhow!("hosted database unavailable"))?;
        sqlx::query("SELECT f.sealed,c.retry_at FROM hosted_invitation.flow f,hosted_invitation.cleanup c LIMIT 0").execute(&pool).await.map_err(|_|anyhow::anyhow!("hosted schema unavailable"))?;
        let store = Arc::new(Self {
            wake: Arc::new(tokio::sync::Notify::new()),
            pool,
            key,
            mac,
            clients: config
                .clients
                .into_iter()
                .map(|(k, v)| (k, Zeroizing::new(v)))
                .collect(),
            issuer: issuer.into(),
            environment,
        });
        let wake = store.wake.clone();
        let weak = Arc::downgrade(&store);
        tokio::spawn(async move {
            loop {
                let Some(store) = weak.upgrade() else { break };
                if store.maintain().await.is_err() {
                    tracing::warn!("hosted invitation cleanup unavailable");
                }
                drop(store);
                let _ = tokio::time::timeout(Duration::from_secs(10), wake.notified()).await;
            }
        });
        Ok(Some(store))
    }
    pub(super) fn wake_cleanup(&self) {
        self.wake.notify_one()
    }
    pub(super) fn secret(&self, domain: Uuid) -> Result<&str> {
        self.clients
            .get(&domain)
            .map(|s| s.as_str())
            .ok_or(Error::Unavailable)
    }
    pub(super) fn mac(&self, context: &str, value: &str) -> String {
        let environment = self.environment.to_string();
        let fields = [context, self.issuer.as_str(), environment.as_str(), value];
        let input = serde_json::Value::from(fields).to_string();
        URL_SAFE_NO_PAD.encode(self.mac.sign(input.as_bytes()))
    }
    fn aad(&self, kind: &str, id: Uuid) -> Result<Vec<u8>> {
        serde_json::to_vec(&("hosted-v1", kind, &self.issuer, self.environment, id))
            .map_err(|_| Error::Unavailable)
    }
    fn seal<T: Serialize>(&self, kind: &str, id: Uuid, value: &T) -> Result<Vec<u8>> {
        let plaintext = Zeroizing::new(serde_json::to_vec(value).map_err(|_| Error::Unavailable)?);
        let mut iv = [0u8; 12];
        aegaeon_crypto::rand::fill_random(&mut iv).map_err(|_| Error::Unavailable)?;
        let mut sealed = iv.to_vec();
        sealed.extend(
            aegaeon_crypto::jwe::encrypt_a256gcm(
                self.key.as_ref(),
                &iv,
                &plaintext,
                &self.aad(kind, id)?,
            )
            .map_err(|_| Error::Unavailable)?,
        );
        Ok(sealed)
    }
    fn open<T: DeserializeOwned>(&self, kind: &str, id: Uuid, sealed: &[u8]) -> Result<T> {
        if !(28..=65536).contains(&sealed.len()) {
            return Err(Error::Refused);
        }
        let (iv, cipher) = sealed.split_at(12);
        let (cipher, tag) = cipher.split_at(cipher.len() - 16);
        let mut key = *self.key;
        let plain = Zeroizing::new(
            aegaeon_crypto::jwe::decrypt_a256gcm(&mut key, iv, cipher, tag, &self.aad(kind, id)?)
                .map_err(|_| Error::Refused)?,
        );
        serde_json::from_slice(&plain).map_err(|_| Error::Unavailable)
    }
    pub(super) async fn begin(&self) -> Result<PgTransaction<'static>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT set_config('lock_timeout','3s',true),set_config('statement_timeout','10s',true),set_config('idle_in_transaction_session_timeout','20s',true)").execute(&mut *tx).await?;
        Ok(tx)
    }
    pub(super) async fn find(
        &self,
        tx: &mut PgTransaction<'_>,
        key: Find<'_>,
    ) -> Result<Option<Flow>> {
        let row = match key {
            Find::Invitation(browser, domain, invitation) => {
                sqlx::query("SELECT id,sealed FROM hosted_invitation.flow
                             WHERE environment=$1 AND browser_tag=$2 AND domain_id=$3 AND invitation=$4
                             FOR UPDATE")
                    .bind(self.environment)
                    .bind(browser)
                    .bind(domain)
                    .bind(invitation)
                    .fetch_optional(&mut **tx)
                    .await?
            }
            Find::Handle(handle) => {
                sqlx::query("SELECT id,sealed FROM hosted_invitation.flow
                             WHERE environment=$1 AND handle=$2 FOR UPDATE")
                    .bind(self.environment)
                    .bind(handle)
                    .fetch_optional(&mut **tx)
                    .await?
            }
            Find::OAuth(state, lock) => {
                let query = if lock {
                    "SELECT id,sealed FROM hosted_invitation.flow WHERE environment=$1 AND oauth_tag=$2 FOR UPDATE"
                } else {
                    "SELECT id,sealed FROM hosted_invitation.flow WHERE environment=$1 AND oauth_tag=$2"
                };
                sqlx::query(query)
                    .bind(self.environment)
                    .bind(hash(state))
                    .fetch_optional(&mut **tx)
                    .await?
            }
        };
        row.map(|r| {
            let id = r.try_get("id")?;
            let data: Vec<u8> = r.try_get("sealed")?;
            let flow: Flow = self.open("flow", id, &data)?;
            let matches = match key {
                Find::Invitation(b, d, i) => {
                    flow.browser == b && flow.domain == d && flow.invitation == i
                }
                Find::Handle(h) => flow.handle == h,
                Find::OAuth(s, _) => flow.authorization.as_ref().is_some_and(|a| a.state == s),
            };
            if flow.id != id || !matches {
                return Err(Error::Refused);
            }
            Ok(flow)
        })
        .transpose()
    }
    pub(super) async fn save(&self, tx: &mut PgTransaction<'_>, flow: &Flow) -> Result<()> {
        let sealed = self.seal("flow", flow.id, flow)?;
        sqlx::query("INSERT INTO hosted_invitation.flow
                     (id,environment,browser_tag,domain_id,invitation,handle,oauth_tag,deadline,sealed)
                     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
                     ON CONFLICT(id) DO UPDATE SET handle=excluded.handle,oauth_tag=excluded.oauth_tag,
                                                   deadline=excluded.deadline,sealed=excluded.sealed")
            .bind(flow.id)
            .bind(self.environment)
            .bind(&flow.browser)
            .bind(flow.domain)
            .bind(flow.invitation)
            .bind(flow.handle)
            .bind(flow.authorization.as_ref().map(|a| hash(&a.state)))
            .bind(flow.purge_at())
            .bind(sealed)
            .execute(&mut **tx)
            .await?;
        Ok(())
    }
    pub(super) async fn lock_invitation(
        &self,
        tx: &mut PgTransaction<'_>,
        browser: &str,
        domain: Uuid,
        invitation: Uuid,
    ) -> Result<()> {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!(
                "hosted-mail:{}:{browser}:{domain}:{invitation}",
                self.environment
            ))
            .execute(&mut **tx)
            .await?;
        Ok(())
    }
    pub(super) async fn reserve(&self, tx: &mut PgTransaction<'_>) -> Result<()> {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!("hosted-flow:{}", self.environment))
            .execute(&mut **tx)
            .await?;
        let n: i64 =
            sqlx::query_scalar("SELECT count(*) FROM hosted_invitation.flow WHERE environment=$1")
                .bind(self.environment)
                .fetch_one(&mut **tx)
                .await?;
        if n >= 10000 {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
    pub(super) async fn cleanup(
        &self,
        tx: &mut PgTransaction<'_>,
        domain: Uuid,
        cleanup: &oauth::Cleanup,
    ) -> Result<()> {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO hosted_invitation.cleanup(id,environment,deadline,sealed) VALUES($1,$2,$3,$4)").bind(id).bind(self.environment).bind(cleanup.deadline).bind(self.seal("cleanup",id,&(domain,cleanup))?).execute(&mut **tx).await?;
        Ok(())
    }
    async fn maintain(&self) -> Result<()> {
        self.maintain_at(super::now()?).await
    }
    async fn maintain_at(&self, now: i64) -> Result<()> {
        // The issuer independently bounds each family and root to this deadline.
        // At verified wall-clock expiry there is no remaining grant to revoke.
        let mut due = self.begin().await?;
        let rows = sqlx::query(
            "SELECT id,sealed FROM hosted_invitation.flow
                                WHERE environment=$1 AND deadline <= $2
                                ORDER BY deadline LIMIT 128 FOR UPDATE SKIP LOCKED",
        )
        .bind(self.environment)
        .bind(now)
        .fetch_all(&mut *due)
        .await?;
        for row in rows {
            let id: Uuid = row.try_get("id")?;
            let mut keep = false;
            if let Ok(mut f) = self.open::<Flow>("flow", id, &row.try_get::<Vec<u8>, _>("sealed")?)
            {
                if f.id == id && f.invitation_expiry > now && f.step != super::flow::Step::Complete
                {
                    if f.session.is_some() && now >= f.session_until || now >= f.deadline {
                        // The original session may be shorter than the root. Enqueue the
                        // isolated family before erasing the encrypted grant.
                        let uncertain = f.step == super::flow::Step::AcceptPending
                            || f.step == super::flow::Step::Unconfirmed;
                        f.retire(self, &mut due).await?;
                        f.clear(if uncertain {
                            super::flow::Step::Unconfirmed
                        } else {
                            super::flow::Step::Closed
                        });
                        f.session = None;
                        f.session_subject = None;
                    } else {
                        f.expire_interactive(now);
                        if f.step == super::flow::Step::Unconfirmed {
                            f.retire(self, &mut due).await?;
                            f.clear(super::flow::Step::Unconfirmed);
                        }
                    }
                    self.save(&mut due, &f).await?;
                    keep = true;
                }
            }
            if !keep {
                sqlx::query("DELETE FROM hosted_invitation.flow WHERE environment=$1 AND id=$2")
                    .bind(self.environment)
                    .bind(id)
                    .execute(&mut *due)
                    .await?;
            }
        }
        due.commit().await?;
        sqlx::query("DELETE FROM hosted_invitation.cleanup WHERE id IN
                     (SELECT id FROM hosted_invitation.cleanup WHERE environment=$1 AND deadline <= $2
                      ORDER BY deadline LIMIT 256 FOR UPDATE SKIP LOCKED)")
            .bind(self.environment)
            .bind(now)
            .execute(&self.pool)
            .await?;
        for _ in 0..16 {
            let mut tx = self.begin().await?;
            let row = sqlx::query(
                "SELECT id,sealed FROM hosted_invitation.cleanup
                                   WHERE environment=$1 AND retry_at <= $2 AND deadline > $2
                                   ORDER BY retry_at LIMIT 1 FOR UPDATE SKIP LOCKED",
            )
            .bind(self.environment)
            .bind(now)
            .fetch_optional(&mut *tx)
            .await?;
            let Some(row) = row else { break };
            let id: Uuid = row.try_get("id")?;
            let handle = self.open::<(Uuid, oauth::Cleanup)>(
                "cleanup",
                id,
                &row.try_get::<Vec<u8>, _>("sealed")?,
            );
            let acknowledged = match handle {
                Ok((domain, handle)) if handle.deadline > now => match self.secret(domain) {
                    Ok(secret) => oauth::revoke(&self.issuer, secret, &handle).await.is_ok(),
                    Err(_) => false,
                },
                _ => false,
            };
            if acknowledged {
                sqlx::query("DELETE FROM hosted_invitation.cleanup WHERE id=$1")
                    .bind(id)
                    .execute(&mut *tx)
                    .await?;
            } else {
                sqlx::query("UPDATE hosted_invitation.cleanup SET retry_at=$2 WHERE id=$1")
                    .bind(id)
                    .bind(now + 30)
                    .execute(&mut *tx)
                    .await?;
            }
            tx.commit().await?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(super) enum Find<'a> {
    Invitation(&'a str, Uuid, Uuid),
    Handle(Uuid),
    OAuth(&'a str, bool),
}

fn flow_keys(master: &[u8]) -> anyhow::Result<(Zeroizing<[u8; 32]>, HmacSha256Key)> {
    let root = HmacSha256Key::new(master);
    let encryption_key = Zeroizing::new(root.sign(b"aegaeon hosted flow AEAD v1"));
    let mac_key = Zeroizing::new(root.sign(b"aegaeon hosted browser MAC v1"));
    Ok((
        Zeroizing::new(encryption_key.as_slice().try_into()?),
        HmacSha256Key::new(&mac_key),
    ))
}

pub(super) fn hash(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(sha256_digest(value.as_bytes()))
}
pub(super) fn generation(state: &AppState) -> Result<Generation> {
    let owner =
        crate::organizations::request_work::async_store::current_epoch_owner(state.environment_id)
            .map_err(|_| Error::Unavailable)?;
    let selection = owner
        .epoch_binding()
        .map_err(|_| Error::Unavailable)?
        .runtime_selection()
        .map_err(|_| Error::Unavailable)?;
    Ok(Generation {
        deployment: selection.deployment_id(),
        generation: selection.generation(),
    })
}

#[cfg(test)]
mod tests;
