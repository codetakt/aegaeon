use super::RedisTokenStoreBackend;
use crate::authcode::store::{retained_root::RetainedRoot, TokenStoreStorageError};
use std::time::SystemTime;

impl RedisTokenStoreBackend {
    pub(in crate::authcode::store) fn retained_root_deadline(
        &self,
        retained: &RetainedRoot,
    ) -> Result<Option<SystemTime>, TokenStoreStorageError> {
        let mut connection = self.connection()?;
        let now = SystemTime::now();
        if !self.exchange_root_active(&mut connection, Some(&retained.root), now)? {
            return Ok(None);
        }
        let Some(reference) = &retained.refresh_grant else {
            return Ok(Some(retained.root.expires_at));
        };
        Ok(self
            .refresh_grant_raw(&mut connection, reference)?
            .filter(|(_, record)| {
                record.active(reference, &retained.client, &retained.subject, now)
            })
            .map(|(_, record)| retained.root.expires_at.min(record.retain_until)))
    }
}
