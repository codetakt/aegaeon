use super::*;
use crate::device_authz::{
    codes::{
        format_user_code, generate_device_code, generate_user_code, USER_CODE_GENERATION_ATTEMPTS,
    },
    DeviceAuthorizationResponse,
};
pub(in crate::device_authz) struct CreateRequest<'a> {
    pub client: &'a str,
    pub scope: Option<&'a str>,
    pub resource: Option<&'a str>,
    pub environment: Option<&'a str>,
    pub verification: &'a str,
    pub ttl: u64,
    pub interval: u64,
}
impl PostgresDeviceCodeStore {
    pub(in crate::device_authz) async fn create(
        &self,
        request: CreateRequest<'_>,
    ) -> Result<Option<DeviceAuthorizationResponse>, String> {
        let CreateRequest {
            client,
            scope,
            resource,
            environment,
            verification,
            ttl,
            interval,
        } = request;
        let mut connection = AdmittedConnection::acquire(&self.database.pool)
            .await
            .map_err(|_| unavailable())?;
        let result=tokio::time::timeout(Duration::from_secs(5),async {
            crate::organizations::request_work::async_store::admit_current_commit().map_err(|_|unavailable())?;
            for _ in 0..USER_CODE_GENERATION_ATTEMPTS {
                let device=generate_device_code()?;let user=generate_user_code()?;
                let conn=connection.as_mut().map_err(|_|unavailable())?;
                let now=clock(conn).await?;
                let deadline=now.checked_add(i64::try_from(ttl).ok().and_then(|v|v.checked_mul(1_000_000)).ok_or_else(unavailable)?).ok_or_else(unavailable)?;
                // An expired collision is reclaimed only by its exact unique selector.
                // No broad cleanup runs on the request path.
                let mut tx=conn.begin().await.map_err(|_|unavailable())?;
                sqlx::query("DELETE FROM aegaeon.runtime_device_codes WHERE namespace=$1 AND user_digest=$2 AND expires_us<=$3")
                    .bind(self.database.namespace.as_ref()).bind(sha256_digest(user.as_bytes()).as_slice()).bind(now).execute(&mut *tx).await.map_err(|_|unavailable())?;
                let inserted=sqlx::query("INSERT INTO aegaeon.runtime_device_codes(namespace,device_digest,user_digest,client_id,scope,resource,environment_id,expires_us,interval_secs) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING")
                    .bind(self.database.namespace.as_ref()).bind(sha256_digest(device.as_bytes()).as_slice()).bind(sha256_digest(user.as_bytes()).as_slice()).bind(client).bind(scope).bind(resource).bind(environment).bind(deadline).bind(i64::try_from(interval).map_err(|_|unavailable())?).execute(&mut *tx).await.map_err(|_|unavailable())?.rows_affected();
                if inserted==0 {tx.rollback().await.map_err(|_|unavailable())?;continue;}
                if clock(&mut tx).await?>=deadline {return Err(unavailable());}
                tx.commit().await.map_err(|_|unavailable())?;
                let user=format_user_code(&user);
                return Ok(Some(DeviceAuthorizationResponse{device_code:device,user_code:user.clone(),verification_uri:verification.into(),verification_uri_complete:Some(format!("{verification}?user_code={user}")),expires_in:ttl,interval}));
            }
            Ok(None)
        }).await.map_err(|_|unavailable()).and_then(|r|r);
        connection.release().await;
        result
    }
}
