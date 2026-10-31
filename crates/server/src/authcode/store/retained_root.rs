//! Read-only liveness of authority retained by a separately authenticated operation.
//! These references are not credentials and cannot authenticate a network caller.
use super::{TokenStore, TokenStoreBackend};
use crate::authcode::types::RefreshGrantRef;
use crate::policy::token_exchange::ExchangeRoot;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetainedRoot {
    pub root: ExchangeRoot,
    pub refresh_grant: Option<RefreshGrantRef>,
    pub client: String,
    pub subject: String,
}

impl TokenStore {
    #[cfg(test)]
    pub(crate) fn retained_root_fault_key_for_tests(
        &self,
        root: &str,
    ) -> Result<(crate::redis_io::Connection, String), String> {
        let TokenStoreBackend::Redis(backend) = &self.backend else {
            return Err("actual Redis is required".into());
        };
        Ok((
            backend.connection().map_err(|error| error.to_string())?,
            backend.keyspace_for_tests().revoked_key(root),
        ))
    }

    pub(crate) fn retained_root_deadline(
        &self,
        retained: &RetainedRoot,
    ) -> Result<Option<SystemTime>, String> {
        let now = SystemTime::now();
        if now >= retained.root.expires_at
            || retained.client.is_empty()
            || retained.subject.is_empty()
            || retained
                .root
                .id
                .strip_prefix("exchange-root:")
                .and_then(|id| uuid::Uuid::parse_str(id).ok())
                .is_none_or(|id| id.is_nil() || format!("exchange-root:{id}") != retained.root.id)
        {
            return Ok(None);
        }
        match &self.backend {
            #[cfg(test)]
            TokenStoreBackend::InMemory(state) => {
                let state = super::read_lock(state, "retained_root")?;
                if state
                    .revoked_tokens
                    .get(&retained.root.id)
                    .is_some_and(|expiry| now < *expiry)
                {
                    return Ok(None);
                }
                Ok(match &retained.refresh_grant {
                    None => Some(retained.root.expires_at),
                    Some(reference) => state
                        .refresh_grants
                        .get(&reference.id)
                        .filter(|record| {
                            record.active(reference, &retained.client, &retained.subject, now)
                        })
                        .map(|record| retained.root.expires_at.min(record.retain_until)),
                })
            }
            TokenStoreBackend::Redis(backend) => backend
                .retained_root_deadline(retained)
                .map_err(|error| super::token_storage_error_message(&error, "retained_root")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authcode::store::redis_backend::RedisTokenStoreBackend;
    use crate::authcode::store::redis_support::RedisRevokedTokenRecord;
    use crate::authcode::types::RefreshGrantRecord;
    use std::time::Duration;

    #[test]
    #[ignore = "requires isolated Redis"]
    fn redis_organization_retained_root_requires_current_family_and_refuses_store_faults(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let backend =
            RedisTokenStoreBackend::new_for_tests(&std::env::var("AEGAEON_TEST_REDIS_URL")?)?;
        let root = ExchangeRoot {
            id: format!("exchange-root:{}", uuid::Uuid::new_v4()),
            expires_at: SystemTime::now() + Duration::from_secs(120),
        };
        let reference = RefreshGrantRef::new();
        let revoked_key = backend.keyspace_for_tests().revoked_key(&root.id);
        let family_key = backend
            .keyspace_for_tests()
            .refresh_grant_key(&reference.id);
        let mut connection = backend.connection()?;
        let store = TokenStore {
            backend: TokenStoreBackend::Redis(backend),
        };
        let mut retained = RetainedRoot {
            root: root.clone(),
            refresh_grant: None,
            client: "owned-fixture-client".into(),
            subject: "owned-fixture-subject".into(),
        };
        let result = (|| -> Result<(), Box<dyn std::error::Error>> {
            assert_eq!(
                store.retained_root_deadline(&retained)?,
                Some(root.expires_at)
            );
            retained.refresh_grant = Some(reference.clone());
            assert!(
                store.retained_root_deadline(&retained)?.is_none(),
                "absence cannot create a refresh-family grant"
            );
            let mut record = RefreshGrantRecord {
                version: 1,
                reference,
                client_id: retained.client.clone(),
                user_id: retained.subject.clone(),
                revoked: false,
                retain_until: root.expires_at,
            };
            let write = |conn: &mut crate::redis_io::Connection,
                         record: &RefreshGrantRecord|
             -> Result<(), Box<dyn std::error::Error>> {
                redis::cmd("SET")
                    .arg(&family_key)
                    .arg(serde_json::to_string(record)?)
                    .query::<()>(conn)?;
                Ok(())
            };
            write(&mut connection, &record)?;
            assert_eq!(
                store.retained_root_deadline(&retained)?,
                Some(root.expires_at)
            );
            record.user_id = "another-subject".into();
            write(&mut connection, &record)?;
            assert_eq!(store.retained_root_deadline(&retained)?, None);
            record.user_id = retained.subject.clone();
            record.retain_until -= Duration::from_secs(1);
            write(&mut connection, &record)?;
            assert_eq!(
                store.retained_root_deadline(&retained)?,
                Some(record.retain_until)
            );
            record.retain_until = root.expires_at;
            record.revoked = true;
            write(&mut connection, &record)?;
            assert_eq!(store.retained_root_deadline(&retained)?, None);
            record.revoked = false;
            write(&mut connection, &record)?;
            redis::cmd("SET")
                .arg(&revoked_key)
                .arg("malformed-authority")
                .query::<()>(&mut connection)?;
            assert!(
                store.retained_root_deadline(&retained).is_err(),
                "malformed required store data must not permit"
            );
            redis::cmd("DEL")
                .arg(&revoked_key)
                .query::<()>(&mut connection)?;
            assert!(
                store.retained_root_deadline(&retained)?.is_some(),
                "actual store repair restores the original valid authority"
            );
            let denied = RedisRevokedTokenRecord {
                token: root.id.clone(),
                expires_at: root.expires_at,
            };
            redis::cmd("SET")
                .arg(&revoked_key)
                .arg(serde_json::to_string(&denied)?)
                .query::<()>(&mut connection)?;
            assert_eq!(store.retained_root_deadline(&retained)?, None);
            Ok(())
        })();
        redis::cmd("DEL")
            .arg(&revoked_key)
            .arg(&family_key)
            .query::<()>(&mut connection)?;
        result
    }
}
