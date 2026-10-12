use super::{
    leaf_entity_types, validate_anchor_subordinate_metadata_policy,
    validate_entity_configuration_link, validate_path_constraints,
    validate_subordinate_statement_link,
};
use crate::federation::{
    validate_entity_statement, verify_entity_configuration, verify_entity_statement,
    EntityStatement, FederationError, TrustAnchor, TrustChain, MAX_CHAIN_DEPTH,
};

/// Verify the retained discovery layout, authorizing normative links from the anchor down.
/// Intermediate self-configurations are discovery artifacts, not endorsed signing authorities.
pub(crate) fn verify_signed_path(
    jwts: &[String],
    leaf_entity_id: &str,
    anchor: &TrustAnchor,
    now: i64,
) -> Result<TrustChain, FederationError> {
    if jwts.len() < 3 || jwts.len().is_multiple_of(2) || jwts.len() / 2 > MAX_CHAIN_DEPTH {
        return Err(FederationError::Validation(
            "invalid signed chain layout or depth".into(),
        ));
    }
    let mut chain = Vec::with_capacity(jwts.len());
    // Self-signatures retain the existing discovery contract. Only raw JWS payloads
    // enter the returned chain; detached fetcher/cache JSON cannot authorize metadata.
    for jwt in jwts.iter().step_by(2) {
        chain.push(verify_entity_configuration(jwt)?);
    }
    // Section 3.2 also requires every subordinate signature to validate with
    // its issuer configuration. This is additional to the superior endorsement
    // checked below, and must hold for custom fetchers and cached paths too.
    for (index, issuer_config) in chain.iter().enumerate().skip(1) {
        verify_entity_statement(&jwts[index * 2 - 1], &issuer_config.parse_jwks()?)?;
    }
    let last = jwts.len() - 1;
    verify_entity_statement(&jwts[last], &anchor.jwks)?;
    let mut endorsed_keys = anchor.jwks.clone();
    let mut subordinates = Vec::with_capacity(jwts.len() / 2);
    for index in (1..last).step_by(2).rev() {
        let statement = verify_entity_statement(&jwts[index], &endorsed_keys)?;
        endorsed_keys = statement.parse_jwks()?;
        subordinates.push(statement);
    }
    verify_entity_statement(&jwts[0], &endorsed_keys)?;
    let mut statements = Vec::with_capacity(jwts.len());
    let mut subordinates = subordinates.into_iter().rev();
    for config in chain {
        statements.push(config);
        if let Some(subordinate) = subordinates.next() {
            statements.push(subordinate);
        }
    }
    let chain = TrustChain {
        chain: statements,
        anchor: anchor.clone(),
    };
    validate_path(&chain, leaf_entity_id, now)?;
    // Policy errors invalidate this candidate before return/cache success. Keep
    // original signed statements intact; resolved metadata remains derived.
    chain.resolved_metadata()?;
    Ok(chain)
}

fn validate_path(
    chain: &TrustChain,
    leaf_entity_id: &str,
    now: i64,
) -> Result<(), FederationError> {
    let (leaf, rest) = chain
        .chain
        .split_first()
        .ok_or_else(|| FederationError::Validation("signed chain is empty".into()))?;
    if rest.is_empty() || rest.len() % 2 != 0 {
        return Err(FederationError::Validation(
            "signed chain must contain subordinate/superior pairs".into(),
        ));
    }
    if leaf_entity_id != leaf.iss || leaf_entity_id != leaf.sub {
        return Err(FederationError::Validation(
            "signed chain leaf does not match requested entity".into(),
        ));
    }
    validate_entity_statement(leaf, now)?;
    validate_entity_configuration_link(leaf, leaf_entity_id)?;
    let leaf_entity_types = leaf_entity_types(leaf);

    let mut subject_config = leaf;
    let mut current_entity_id = subject_config.iss.as_str();
    let mut entities = std::collections::BTreeSet::from([current_entity_id]);
    let mut last_subordinate: Option<&EntityStatement> = None;
    for (depth, pair) in rest.chunks_exact(2).enumerate() {
        let sub_stmt = &pair[0];
        let superior_config = &pair[1];

        validate_entity_statement(sub_stmt, now)?;
        validate_entity_statement(superior_config, now)?;
        crate::federation::profile::validate_superior(superior_config)?;
        validate_subordinate_statement_link(sub_stmt, superior_config, current_entity_id)?;
        // Section 3.2 requires the subject's signed configuration to name its
        // immediate superior, including on cached and custom-fetched paths.
        if !subject_config
            .authority_hints
            .as_ref()
            .is_some_and(|hints| hints.iter().any(|hint| hint == &sub_stmt.iss))
        {
            return Err(FederationError::Validation(
                "subordinate issuer is not in signed subject authority_hints".into(),
            ));
        }
        validate_path_constraints(sub_stmt, &leaf_entity_types, depth)?;

        subject_config = superior_config;
        current_entity_id = subject_config.iss.as_str();
        if !entities.insert(current_entity_id) {
            return Err(FederationError::Validation(
                "signed path contains an entity cycle".into(),
            ));
        }
        last_subordinate = Some(sub_stmt);
    }

    if current_entity_id != chain.anchor.entity_id {
        return Err(FederationError::Validation(
            "signed chain does not terminate at configured trust anchor".into(),
        ));
    }
    let Some(anchor_subordinate) = last_subordinate else {
        return Err(FederationError::Validation(
            "signed chain missing trust-anchor subordinate statement".into(),
        ));
    };
    validate_anchor_subordinate_metadata_policy(&chain.anchor, anchor_subordinate)?;

    Ok(())
}
