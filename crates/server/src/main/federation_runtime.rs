use std::sync::Arc;

use aegaeon_server::federation::{
    EntityCacheRepository, FederationCacheConfig, PgEntityCacheRepository, PgTrustAnchorRepository,
    PgTrustChainCacheRepository, TrustAnchorRepository, TrustChainCacheRepository,
};
use aegaeon_server::management::types::PolicyDocument;
use anyhow::Result;
use sqlx::PgPool;

type TrustAnchorRepo = Arc<dyn TrustAnchorRepository>;
type EntityCacheRepo = Arc<dyn EntityCacheRepository>;
type TrustChainCacheRepo = Arc<dyn TrustChainCacheRepository>;

pub(super) struct FederationRuntime {
    pub(super) trust_anchors: TrustAnchorRepo,
    pub(super) entity_cache: EntityCacheRepo,
    pub(super) chain_cache: TrustChainCacheRepo,
    pub(super) cache_config: FederationCacheConfig,
}

pub(super) fn federation_runtime_for_authority(
    db_pool: &PgPool,
    policy: &PolicyDocument,
) -> Result<FederationRuntime> {
    let cache_config = FederationCacheConfig::try_from_management_policy(policy)?;
    let (trust_anchors, entity_cache, chain_cache) =
        pg_federation_repositories(db_pool, &cache_config);

    Ok(FederationRuntime {
        trust_anchors,
        entity_cache,
        chain_cache,
        cache_config,
    })
}

fn pg_federation_repositories(
    db_pool: &PgPool,
    cache_config: &FederationCacheConfig,
) -> (TrustAnchorRepo, EntityCacheRepo, TrustChainCacheRepo) {
    (
        Arc::new(PgTrustAnchorRepository::new(db_pool.clone())),
        Arc::new(PgEntityCacheRepository::with_max_entries(
            db_pool.clone(),
            cache_config.cache_max_entries,
        )),
        Arc::new(PgTrustChainCacheRepository::with_max_entries(
            db_pool.clone(),
            cache_config.cache_max_entries,
        )),
    )
}
