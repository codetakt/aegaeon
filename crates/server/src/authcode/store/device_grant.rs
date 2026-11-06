use super::{TokenStore, TokenStoreBackend};
use crate::authcode::types::{AccessToken, BearerTokenMeta};
impl TokenStore {
    pub(crate) async fn store_device_grant_async(
        &self,
        access: AccessToken,
        meta: BearerTokenMeta,
        commit: Option<crate::device_authz::PostgresDeviceGrantCommit>,
    ) -> Result<String, String> {
        if let Some(commit) = commit {
            #[cfg(not(kani))]
            if let TokenStoreBackend::Postgres(backend) = &self.backend {
                return backend.redeem_device(access, meta, commit).await;
            }
            return Err("device/token grant stores do not share a SQL transaction".into());
        }
        self.store_issued_grant_async(access, None, meta)
            .await
            .map(|r| r.0)
    }
}
