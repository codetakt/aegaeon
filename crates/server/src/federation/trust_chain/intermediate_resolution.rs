use super::super::{validate_entity_statement, EntityStatement, TrustAnchor};
use super::link::{validate_entity_configuration_link, validate_subordinate_statement_link};
use super::path_constraints::path_constraints_allow;
use super::resolution::{
    require_fetched_jws, resolve_chain_up, resolve_chain_up_with_jwts, ChainResolutionContext,
};

struct IntermediateJwsStep {
    authority_config: EntityStatement,
    authority_config_jws: String,
    sub_stmt: EntityStatement,
    sub_stmt_jws: String,
}

pub(super) async fn try_resolve_via_intermediate(
    chain: &mut Vec<EntityStatement>,
    current_entity_id: &str,
    authority_id: &str,
    ctx: &ChainResolutionContext<'_>,
    depth: usize,
) -> Option<TrustAnchor> {
    let authority_config =
        fetch_valid_intermediate_configuration(authority_id, current_entity_id, ctx).await?;
    let sub_stmt = fetch_intermediate_subordinate_statement(
        current_entity_id,
        authority_id,
        &authority_config,
        ctx,
    )
    .await?;
    if !validate_intermediate_subordinate_link(
        &sub_stmt,
        &authority_config,
        current_entity_id,
        authority_id,
    ) {
        return None;
    }
    if !path_constraints_allow(
        &sub_stmt,
        authority_id,
        current_entity_id,
        depth,
        true,
        &ctx.leaf_entity_types,
    ) {
        return None;
    }
    recurse_via_intermediate(
        chain,
        current_entity_id,
        authority_id,
        authority_config,
        sub_stmt,
        ctx,
        depth,
    )
    .await
}

pub(super) async fn try_resolve_via_intermediate_with_jwts(
    chain: &mut Vec<EntityStatement>,
    chain_jwts: &mut Vec<String>,
    current_entity_id: &str,
    authority_id: &str,
    ctx: &ChainResolutionContext<'_>,
    depth: usize,
) -> Option<TrustAnchor> {
    let (authority_config, authority_config_jws) =
        fetch_valid_intermediate_configuration_with_jws(authority_id, current_entity_id, ctx)
            .await?;
    let (sub_stmt, sub_stmt_jws) = fetch_intermediate_subordinate_statement_with_jws(
        current_entity_id,
        authority_id,
        &authority_config,
        ctx,
    )
    .await?;
    if !validate_intermediate_subordinate_link(
        &sub_stmt,
        &authority_config,
        current_entity_id,
        authority_id,
    ) {
        return None;
    }
    if !path_constraints_allow(
        &sub_stmt,
        authority_id,
        current_entity_id,
        depth,
        true,
        &ctx.leaf_entity_types,
    ) {
        return None;
    }
    let step = IntermediateJwsStep {
        authority_config,
        authority_config_jws,
        sub_stmt,
        sub_stmt_jws,
    };
    recurse_via_intermediate_with_jwts(
        chain,
        chain_jwts,
        current_entity_id,
        authority_id,
        step,
        ctx,
        depth,
    )
    .await
}

async fn fetch_valid_intermediate_configuration(
    authority_id: &str,
    current_entity_id: &str,
    ctx: &ChainResolutionContext<'_>,
) -> Option<EntityStatement> {
    let authority_config = match ctx.fetcher.fetch_entity_configuration(authority_id).await {
        Ok(config) => config,
        Err(e) => {
            tracing::debug!(
                authority_id,
                current_entity_id,
                error = %e,
                "failed to fetch intermediate authority entity configuration"
            );
            return None;
        }
    };
    if let Err(e) = validate_entity_statement(&authority_config, ctx.now) {
        tracing::debug!(
            authority_id,
            error = %e,
            "intermediate authority entity configuration failed validation"
        );
        return None;
    }
    if let Err(e) = validate_entity_configuration_link(&authority_config, authority_id) {
        tracing::debug!(
            authority_id,
            error = %e,
            "intermediate authority entity configuration identity mismatch"
        );
        return None;
    }
    Some(authority_config)
}

async fn fetch_valid_intermediate_configuration_with_jws(
    authority_id: &str,
    current_entity_id: &str,
    ctx: &ChainResolutionContext<'_>,
) -> Option<(EntityStatement, String)> {
    let fetched = match ctx
        .fetcher
        .fetch_entity_configuration_with_jws(authority_id)
        .await
    {
        Ok(config) => config,
        Err(e) => {
            tracing::debug!(
                authority_id,
                current_entity_id,
                error = %e,
                "failed to fetch intermediate authority entity configuration"
            );
            return None;
        }
    };
    let authority_config_jws = match require_fetched_jws(
        "intermediate entity configuration",
        authority_id,
        fetched.entity_configuration_jws,
    ) {
        Ok(jws) => jws,
        Err(e) => {
            tracing::debug!(
                authority_id,
                current_entity_id,
                error = %e,
                "intermediate authority entity configuration did not retain compact JWS"
            );
            return None;
        }
    };
    if let Err(e) = validate_entity_statement(&fetched.statement, ctx.now) {
        tracing::debug!(
            authority_id,
            error = %e,
            "intermediate authority entity configuration failed validation"
        );
        return None;
    }
    if let Err(e) = validate_entity_configuration_link(&fetched.statement, authority_id) {
        tracing::debug!(
            authority_id,
            error = %e,
            "intermediate authority entity configuration identity mismatch"
        );
        return None;
    }
    Some((fetched.statement, authority_config_jws))
}

async fn fetch_intermediate_subordinate_statement(
    current_entity_id: &str,
    authority_id: &str,
    authority_config: &EntityStatement,
    ctx: &ChainResolutionContext<'_>,
) -> Option<EntityStatement> {
    let authority_jwks = match authority_config.parse_jwks() {
        Ok(jwks) => jwks,
        Err(e) => {
            tracing::debug!(
                authority_id,
                error = %e,
                "failed to parse intermediate authority JWKS"
            );
            return None;
        }
    };
    let sub_stmt = match ctx
        .fetcher
        .fetch_subordinate_statement(
            authority_id,
            authority_config,
            current_entity_id,
            &authority_jwks,
        )
        .await
    {
        Ok(statement) => statement,
        Err(e) => {
            tracing::debug!(
                authority_id,
                current_entity_id,
                error = %e,
                "failed to fetch subordinate statement from intermediate"
            );
            return None;
        }
    };
    if let Err(e) = validate_entity_statement(&sub_stmt, ctx.now) {
        tracing::debug!(
            authority_id,
            current_entity_id,
            error = %e,
            "subordinate statement from intermediate failed validation"
        );
        return None;
    }
    Some(sub_stmt)
}

async fn fetch_intermediate_subordinate_statement_with_jws(
    current_entity_id: &str,
    authority_id: &str,
    authority_config: &EntityStatement,
    ctx: &ChainResolutionContext<'_>,
) -> Option<(EntityStatement, String)> {
    let authority_jwks = match authority_config.parse_jwks() {
        Ok(jwks) => jwks,
        Err(e) => {
            tracing::debug!(
                authority_id,
                error = %e,
                "failed to parse intermediate authority JWKS"
            );
            return None;
        }
    };
    let fetched = match ctx
        .fetcher
        .fetch_subordinate_statement_with_jws(
            authority_id,
            authority_config,
            current_entity_id,
            &authority_jwks,
        )
        .await
    {
        Ok(statement) => statement,
        Err(e) => {
            tracing::debug!(
                authority_id,
                current_entity_id,
                error = %e,
                "failed to fetch subordinate statement from intermediate"
            );
            return None;
        }
    };
    let sub_stmt_jws = match require_fetched_jws(
        "intermediate subordinate statement",
        current_entity_id,
        fetched.subordinate_statement_jws,
    ) {
        Ok(jws) => jws,
        Err(e) => {
            tracing::debug!(
                authority_id,
                current_entity_id,
                error = %e,
                "intermediate subordinate statement did not retain compact JWS"
            );
            return None;
        }
    };
    if let Err(e) = validate_entity_statement(&fetched.statement, ctx.now) {
        tracing::debug!(
            authority_id,
            current_entity_id,
            error = %e,
            "subordinate statement from intermediate failed validation"
        );
        return None;
    }
    Some((fetched.statement, sub_stmt_jws))
}

fn validate_intermediate_subordinate_link(
    sub_stmt: &EntityStatement,
    authority_config: &EntityStatement,
    current_entity_id: &str,
    authority_id: &str,
) -> bool {
    if let Err(e) =
        validate_subordinate_statement_link(sub_stmt, authority_config, current_entity_id)
    {
        tracing::debug!(
            authority_id,
            current_entity_id,
            error = %e,
            "subordinate statement from intermediate breaks chain continuity"
        );
        false
    } else {
        true
    }
}

async fn recurse_via_intermediate(
    chain: &mut Vec<EntityStatement>,
    current_entity_id: &str,
    authority_id: &str,
    authority_config: EntityStatement,
    sub_stmt: EntityStatement,
    ctx: &ChainResolutionContext<'_>,
    depth: usize,
) -> Option<TrustAnchor> {
    let next_hints = authority_config.authority_hints.clone();
    let Some(ref next_hints) = next_hints else {
        tracing::debug!(
            authority_id,
            "intermediate authority has no authority_hints, cannot continue chain"
        );
        return None;
    };

    chain.push(sub_stmt);
    chain.push(authority_config);

    match resolve_chain_up(
        chain,
        authority_id.to_string(),
        next_hints.clone(),
        ctx,
        depth + 1,
    )
    .await
    {
        Ok(anchor) => Some(anchor),
        Err(e) => {
            tracing::debug!(
                authority_id,
                current_entity_id,
                depth,
                error = %e,
                "backtracking: recursive chain resolution failed via this authority"
            );
            chain.pop();
            chain.pop();
            None
        }
    }
}

async fn recurse_via_intermediate_with_jwts(
    chain: &mut Vec<EntityStatement>,
    chain_jwts: &mut Vec<String>,
    current_entity_id: &str,
    authority_id: &str,
    step: IntermediateJwsStep,
    ctx: &ChainResolutionContext<'_>,
    depth: usize,
) -> Option<TrustAnchor> {
    let next_hints = step.authority_config.authority_hints.clone();
    let Some(ref next_hints) = next_hints else {
        tracing::debug!(
            authority_id,
            "intermediate authority has no authority_hints, cannot continue chain"
        );
        return None;
    };

    chain.push(step.sub_stmt);
    chain.push(step.authority_config);
    chain_jwts.push(step.sub_stmt_jws);
    chain_jwts.push(step.authority_config_jws);

    match resolve_chain_up_with_jwts(
        chain,
        chain_jwts,
        authority_id.to_string(),
        next_hints.clone(),
        ctx,
        depth + 1,
    )
    .await
    {
        Ok(anchor) => Some(anchor),
        Err(e) => {
            tracing::debug!(
                authority_id,
                current_entity_id,
                depth,
                error = %e,
                "backtracking: recursive JWS-backed chain resolution failed via this authority"
            );
            chain.pop();
            chain.pop();
            chain_jwts.pop();
            chain_jwts.pop();
            None
        }
    }
}
