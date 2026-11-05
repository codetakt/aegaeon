use super::*;
use crate::client_registry::jwks_types::FetchedJwks;
impl AdmittedKeys {
    pub(in crate::client_registry) fn from_validated(jwks: &FetchedJwks) -> Result<Self, String> {
        crate::client_registry::jwks_validation::validate_fetched_jwks(jwks)
            .map_err(|_| unavailable())?;
        // Per-key digests are sorted, so an equivalent key-set reordering does not
        // invalidate other nodes. Metadata is included in each serialized key.
        let mut members = jwks
            .keys()
            .iter()
            .map(|key| {
                serde_json::to_vec(key)
                    .map(|raw| sha256_digest(&raw))
                    .map_err(|_| unavailable())
            })
            .collect::<Result<Vec<_>, _>>()?;
        members.sort_unstable();
        let mut hasher = aegaeon_crypto::hash::Sha256Hasher::new();
        hasher.update(b"aegaeon-jwks-admitted-body-v1\0");
        for member in members {
            hasher.update(&member);
        }
        let body_digest = hasher
            .finalize()
            .as_ref()
            .try_into()
            .map_err(|_| unavailable())?;
        Ok(Self {
            fingerprints: crate::client_registry::jwks_validation::build_kid_fingerprints(jwks),
            body_digest,
        })
    }
    pub(in crate::client_registry) fn body_digest(&self) -> [u8; 32] {
        self.body_digest
    }
}
impl PostgresJwksState {
    pub(in crate::client_registry) async fn current_body(
        &self,
        uri: &str,
        digest: &[u8; 32],
    ) -> Result<bool, String> {
        let mut connection = AdmittedConnection::acquire(&self.pool)
            .await
            .map_err(|_| unavailable())?;
        let result=tokio::time::timeout(Duration::from_secs(5),async {
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM aegaeon.runtime_jwks_bindings WHERE namespace=$1 AND uri_digest=$2 AND body_digest=$3 AND admission_expires_us>floor(extract(epoch from clock_timestamp())*1000000)::bigint)")
                .bind(self.namespace.as_ref()).bind(sha256_digest(uri.as_bytes()).as_slice()).bind(digest.as_slice()).fetch_one(connection.as_mut().map_err(|_|unavailable())?).await.map_err(|_|unavailable())
        }).await.map_err(|_|unavailable()).and_then(|r|r);
        connection.release().await;
        result
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn jwks_body_identity_is_order_independent_and_validated() -> anyhow::Result<()> {
        let (mut a, _) = crate::test_utils::jwk_usage::material(jsonwebtoken::Algorithm::RS256);
        let (mut b, _) = crate::test_utils::jwk_usage::material(jsonwebtoken::Algorithm::ES256);
        a["kid"] = serde_json::json!("A");
        b["kid"] = serde_json::json!("B");
        let first: FetchedJwks = serde_json::from_value(serde_json::json!({"keys":[a,b]}))?;
        let reordered: FetchedJwks = serde_json::from_value(serde_json::json!({"keys":[b,a]}))?;
        let one: FetchedJwks = serde_json::from_value(serde_json::json!({"keys":[a]}))?;
        let digest = AdmittedKeys::from_validated(&first)
            .map_err(anyhow::Error::msg)?
            .body_digest();
        anyhow::ensure!(
            digest
                == AdmittedKeys::from_validated(&reordered)
                    .map_err(anyhow::Error::msg)?
                    .body_digest()
        );
        anyhow::ensure!(
            digest
                != AdmittedKeys::from_validated(&one)
                    .map_err(anyhow::Error::msg)?
                    .body_digest()
        );
        let mut invalid = first.clone();
        invalid.keys_mut_for_tests()[0].n = None;
        anyhow::ensure!(AdmittedKeys::from_validated(&invalid).is_err());
        Ok(())
    }
}
