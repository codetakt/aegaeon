use axum::response::Response;
use sqlx::PgPool;

use crate::management::types::Client;

use super::RuntimeClientMutationSync;

impl RuntimeClientMutationSync<'_> {
    pub(in crate::web::management) async fn sync_client(
        self,
        pool: &PgPool,
        _client: &Client,
        request_id: &str,
    ) -> Result<(), Response> {
        self.replace_current_issuer_snapshot(pool, request_id).await
    }

    pub(in crate::web::management) async fn remove_client(
        self,
        pool: &PgPool,
        _client_identifier: &str,
        request_id: &str,
    ) -> Result<(), Response> {
        self.replace_current_issuer_snapshot(pool, request_id).await
    }
}
