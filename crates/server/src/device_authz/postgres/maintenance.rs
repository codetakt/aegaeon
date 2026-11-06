use super::*;
impl PostgresDeviceCodeStore {
    pub(in crate::device_authz) async fn cleanup(&self) -> Result<(), String> {
        use crate::runtime_security_cleanup::{cleanup, Kind, PASS_BATCHES};
        cleanup(
            &self.database.pool,
            &self.database.namespace,
            Kind::DeviceCode,
            PASS_BATCHES,
        )
        .await
        .map(|_| ())
    }
    pub(in crate::device_authz) async fn count(&self) -> Result<usize, String> {
        let mut connection = AdmittedConnection::acquire(&self.database.pool)
            .await
            .map_err(|_| unavailable())?;
        let result=tokio::time::timeout(Duration::from_secs(5),async {
            let count:i64=sqlx::query_scalar("SELECT count(*) FROM aegaeon.runtime_device_codes WHERE namespace=$1 AND expires_us>floor(extract(epoch from statement_timestamp())*1000000)::bigint")
                .bind(self.database.namespace.as_ref()).fetch_one(connection.as_mut().map_err(|_|unavailable())?).await.map_err(|_|unavailable())?;
            usize::try_from(count).map_err(|_|unavailable())
        }).await.map_err(|_|unavailable()).and_then(|r|r);
        connection.release().await;
        result
    }
}
