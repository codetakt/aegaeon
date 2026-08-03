mod delete;
mod entry;
mod refresh;
mod resolution;

use super::trust_anchors::load_resolvable_trust_anchors as load_resolvable_trust_anchors_inner;
use crate::federation::TrustAnchor;
use axum::response::Response;
pub(in crate::web::management) use delete::delete_federation_trust_chain_row;
pub(in crate::web::management) use entry::load_federation_trust_chain_entry;
pub(in crate::web::management) use refresh::store_refreshed_federation_trust_chain;
pub(in crate::web::management) use resolution::resolve_refreshed_trust_chain_payload;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(in crate::web::management) async fn load_resolvable_trust_anchors(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    request_id: &str,
) -> Result<Vec<TrustAnchor>, Response> {
    load_resolvable_trust_anchors_inner(tx, environment_id, request_id).await
}
