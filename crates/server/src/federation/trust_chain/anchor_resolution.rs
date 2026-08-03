use super::super::{validate_entity_statement, EntityStatement, TrustAnchor};
use super::anchor_policy::validate_anchor_subordinate_metadata_policy;
use super::link::{validate_entity_configuration_link, validate_subordinate_statement_link};
use super::path_constraints::path_constraints_allow;
use super::resolution::{require_fetched_jws, ChainResolutionContext};

pub(super) async fn try_resolve_via_trust_anchor(
    chain: &mut Vec<EntityStatement>,
    current_entity_id: &str,
    authority_id: &str,
    anchor: &TrustAnchor,
    ctx: &ChainResolutionContext<'_>,
    depth: usize,
) -> Option<TrustAnchor> {
    let ta_config = fetch_valid_trust_anchor_configuration(authority_id, anchor, ctx).await?;
    let sub_stmt = fetch_anchor_subordinate_statement(
        current_entity_id,
        authority_id,
        anchor,
        &ta_config,
        ctx,
    )
    .await?;
    if !validate_anchor_subordinate_link(&sub_stmt, &ta_config, current_entity_id, authority_id) {
        return None;
    }
    if !path_constraints_allow(
        &sub_stmt,
        authority_id,
        current_entity_id,
        depth,
        false,
        &ctx.leaf_entity_types,
    ) {
        return None;
    }
    if let Err(e) = validate_anchor_subordinate_metadata_policy(anchor, &sub_stmt) {
        tracing::warn!(
            authority_id,
            current_entity_id,
            error = %e,
            "subordinate statement metadata_policy rejected by anchor policy, skipping"
        );
        return None;
    }

    chain.push(sub_stmt);
    chain.push(ta_config);
    Some(anchor.clone())
}

pub(super) async fn try_resolve_via_trust_anchor_with_jwts(
    chain: &mut Vec<EntityStatement>,
    chain_jwts: &mut Vec<String>,
    current_entity_id: &str,
    authority_id: &str,
    anchor: &TrustAnchor,
    ctx: &ChainResolutionContext<'_>,
    depth: usize,
) -> Option<TrustAnchor> {
    let (ta_config, ta_config_jws) =
        fetch_valid_trust_anchor_configuration_with_jws(authority_id, anchor, ctx).await?;
    let (sub_stmt, sub_stmt_jws) = fetch_anchor_subordinate_statement_with_jws(
        current_entity_id,
        authority_id,
        anchor,
        &ta_config,
        ctx,
    )
    .await?;
    if !validate_anchor_subordinate_link(&sub_stmt, &ta_config, current_entity_id, authority_id) {
        return None;
    }
    if !path_constraints_allow(
        &sub_stmt,
        authority_id,
        current_entity_id,
        depth,
        false,
        &ctx.leaf_entity_types,
    ) {
        return None;
    }
    if let Err(e) = validate_anchor_subordinate_metadata_policy(anchor, &sub_stmt) {
        tracing::warn!(
            authority_id,
            current_entity_id,
            error = %e,
            "subordinate statement metadata_policy rejected by anchor policy, skipping"
        );
        return None;
    }

    chain.push(sub_stmt);
    chain.push(ta_config);
    chain_jwts.push(sub_stmt_jws);
    chain_jwts.push(ta_config_jws);
    Some(anchor.clone())
}

async fn fetch_anchor_subordinate_statement(
    current_entity_id: &str,
    authority_id: &str,
    anchor: &TrustAnchor,
    authority_config: &EntityStatement,
    ctx: &ChainResolutionContext<'_>,
) -> Option<EntityStatement> {
    let sub_stmt = match ctx
        .fetcher
        .fetch_subordinate_statement(
            &anchor.entity_id,
            authority_config,
            current_entity_id,
            &anchor.jwks,
        )
        .await
    {
        Ok(statement) => statement,
        Err(e) => {
            tracing::debug!(
                authority_id,
                current_entity_id,
                error = %e,
                "failed to fetch subordinate statement from trust anchor"
            );
            return None;
        }
    };
    if let Err(e) = validate_entity_statement(&sub_stmt, ctx.now) {
        tracing::debug!(
            authority_id,
            current_entity_id,
            error = %e,
            "subordinate statement from trust anchor failed validation"
        );
        return None;
    }
    Some(sub_stmt)
}

async fn fetch_anchor_subordinate_statement_with_jws(
    current_entity_id: &str,
    authority_id: &str,
    anchor: &TrustAnchor,
    authority_config: &EntityStatement,
    ctx: &ChainResolutionContext<'_>,
) -> Option<(EntityStatement, String)> {
    let fetched = match ctx
        .fetcher
        .fetch_subordinate_statement_with_jws(
            &anchor.entity_id,
            authority_config,
            current_entity_id,
            &anchor.jwks,
        )
        .await
    {
        Ok(statement) => statement,
        Err(e) => {
            tracing::debug!(
                authority_id,
                current_entity_id,
                error = %e,
                "failed to fetch subordinate statement from trust anchor"
            );
            return None;
        }
    };
    let sub_stmt_jws = match require_fetched_jws(
        "trust anchor subordinate statement",
        current_entity_id,
        fetched.subordinate_statement_jws,
    ) {
        Ok(jws) => jws,
        Err(e) => {
            tracing::debug!(
                authority_id,
                current_entity_id,
                error = %e,
                "trust anchor subordinate statement did not retain compact JWS"
            );
            return None;
        }
    };
    if let Err(e) = validate_entity_statement(&fetched.statement, ctx.now) {
        tracing::debug!(
            authority_id,
            current_entity_id,
            error = %e,
            "subordinate statement from trust anchor failed validation"
        );
        return None;
    }
    Some((fetched.statement, sub_stmt_jws))
}

async fn fetch_valid_trust_anchor_configuration(
    _authority_id: &str,
    anchor: &TrustAnchor,
    ctx: &ChainResolutionContext<'_>,
) -> Option<EntityStatement> {
    let ta_config = match ctx
        .fetcher
        .fetch_entity_configuration(&anchor.entity_id)
        .await
    {
        Ok(config) => config,
        Err(e) => {
            tracing::debug!(
                authority_id = anchor.entity_id,
                error = %e,
                "failed to fetch trust anchor entity configuration"
            );
            return None;
        }
    };
    if let Err(e) = validate_entity_statement(&ta_config, ctx.now) {
        tracing::debug!(
            authority_id = anchor.entity_id,
            error = %e,
            "trust anchor entity configuration failed validation"
        );
        return None;
    }
    if let Err(e) = validate_entity_configuration_link(&ta_config, &anchor.entity_id) {
        tracing::debug!(
            authority_id = anchor.entity_id,
            error = %e,
            "trust anchor entity configuration identity mismatch"
        );
        return None;
    }
    Some(ta_config)
}

async fn fetch_valid_trust_anchor_configuration_with_jws(
    _authority_id: &str,
    anchor: &TrustAnchor,
    ctx: &ChainResolutionContext<'_>,
) -> Option<(EntityStatement, String)> {
    let fetched = match ctx
        .fetcher
        .fetch_entity_configuration_with_jws(&anchor.entity_id)
        .await
    {
        Ok(config) => config,
        Err(e) => {
            tracing::debug!(
                authority_id = anchor.entity_id,
                error = %e,
                "failed to fetch trust anchor entity configuration"
            );
            return None;
        }
    };
    let ta_config_jws = match require_fetched_jws(
        "trust anchor entity configuration",
        &anchor.entity_id,
        fetched.entity_configuration_jws,
    ) {
        Ok(jws) => jws,
        Err(e) => {
            tracing::debug!(
                authority_id = anchor.entity_id,
                error = %e,
                "trust anchor entity configuration did not retain compact JWS"
            );
            return None;
        }
    };
    if let Err(e) = validate_entity_statement(&fetched.statement, ctx.now) {
        tracing::debug!(
            authority_id = anchor.entity_id,
            error = %e,
            "trust anchor entity configuration failed validation"
        );
        return None;
    }
    if let Err(e) = validate_entity_configuration_link(&fetched.statement, &anchor.entity_id) {
        tracing::debug!(
            authority_id = anchor.entity_id,
            error = %e,
            "trust anchor entity configuration identity mismatch"
        );
        return None;
    }
    Some((fetched.statement, ta_config_jws))
}

fn validate_anchor_subordinate_link(
    sub_stmt: &EntityStatement,
    ta_config: &EntityStatement,
    current_entity_id: &str,
    authority_id: &str,
) -> bool {
    if let Err(e) = validate_subordinate_statement_link(sub_stmt, ta_config, current_entity_id) {
        tracing::debug!(
            authority_id,
            current_entity_id,
            error = %e,
            "subordinate statement from trust anchor breaks chain continuity"
        );
        false
    } else {
        true
    }
}
