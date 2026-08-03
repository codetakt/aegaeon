use super::federation_entity_cache_handlers::{
    delete_federation_entity_cache_entry, list_federation_entity_cache,
    refresh_federation_entity_cache_entry,
};
use super::AppState;
use axum::{
    routing::{delete, get, post},
    Router,
};

mod trust_anchors;
mod trust_chains;

use trust_anchors::{
    create_federation_trust_anchor, delete_federation_trust_anchor, get_federation_trust_anchor,
    list_federation_trust_anchors,
};
use trust_chains::{
    delete_federation_trust_chain, list_federation_trust_chains, refresh_federation_trust_chain,
};

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/teams/:teamId/environments/:environmentId/federationTrustAnchors",
            get(list_federation_trust_anchors).post(create_federation_trust_anchor),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/federationEntityCache",
            get(list_federation_entity_cache),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/federationEntityCache/:entityCacheId",
            delete(delete_federation_entity_cache_entry),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/federationEntityCache/:entityCacheId/refresh",
            post(refresh_federation_entity_cache_entry),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/federationTrustChains",
            get(list_federation_trust_chains),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/federationTrustChains/:trustChainId",
            delete(delete_federation_trust_chain),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/federationTrustChains/:trustChainId/refresh",
            post(refresh_federation_trust_chain),
        )
        .route(
            "/teams/:teamId/environments/:environmentId/federationTrustAnchors/:trustAnchorId",
            get(get_federation_trust_anchor).delete(delete_federation_trust_anchor),
        )
}
