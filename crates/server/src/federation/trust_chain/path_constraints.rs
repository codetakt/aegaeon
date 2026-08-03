use super::super::{EntityStatement, FederationError};
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

pub(super) fn enforce_authority_hint_timeout(
    start: Instant,
    current_entity_id: &str,
    depth: usize,
) -> Result<(), FederationError> {
    if start.elapsed() <= Duration::from_secs(30) {
        return Ok(());
    }
    tracing::warn!(
        current_entity_id,
        depth,
        elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
        "authority_hints processing timeout at chain level"
    );
    Err(FederationError::ChainResolution(format!(
        "authority_hints processing timeout for {current_entity_id} at depth {depth}"
    )))
}

pub(in crate::federation) fn leaf_entity_types(leaf: &EntityStatement) -> BTreeSet<String> {
    leaf.metadata
        .as_ref()
        .map(|metadata| metadata.keys().cloned().collect())
        .unwrap_or_default()
}

pub(in crate::federation) fn validate_path_constraints(
    sub_stmt: &EntityStatement,
    leaf_entity_types: &BTreeSet<String>,
    depth: usize,
) -> Result<(), FederationError> {
    if let Some(max_path) = exceeded_max_path_length(sub_stmt, depth) {
        let depth = u32::try_from(depth).map_err(|_| FederationError::ChainTooDeep)?;
        return Err(FederationError::MaxPathLengthExceeded {
            depth,
            max: max_path,
        });
    }

    let Some(allowed_leaf_entity_types) = sub_stmt
        .constraints
        .as_ref()
        .and_then(|constraints| constraints.allowed_leaf_entity_types.as_ref())
    else {
        return Ok(());
    };

    if allowed_leaf_entity_types
        .iter()
        .any(|entity_type| leaf_entity_types.contains(entity_type))
    {
        return Ok(());
    }

    Err(FederationError::Validation(
        "allowed_leaf_entity_types constraint violated".into(),
    ))
}

pub(super) fn path_constraints_allow(
    sub_stmt: &EntityStatement,
    authority_id: &str,
    current_entity_id: &str,
    depth: usize,
    via_intermediate: bool,
    leaf_entity_types: &BTreeSet<String>,
) -> bool {
    match validate_path_constraints(sub_stmt, leaf_entity_types, depth) {
        Ok(()) => true,
        Err(FederationError::MaxPathLengthExceeded { max, .. }) => {
            if via_intermediate {
                tracing::debug!(
                    authority_id,
                    current_entity_id,
                    depth,
                    max_path_length = max,
                    "max_path_length constraint exceeded via intermediate"
                );
            } else {
                tracing::debug!(
                    authority_id,
                    current_entity_id,
                    depth,
                    max_path_length = max,
                    "max_path_length constraint exceeded"
                );
            }
            false
        }
        Err(error) => {
            if via_intermediate {
                tracing::debug!(
                    authority_id,
                    current_entity_id,
                    depth,
                    error = %error,
                    "path constraint rejected leaf entity via intermediate"
                );
            } else {
                tracing::debug!(
                    authority_id,
                    current_entity_id,
                    depth,
                    error = %error,
                    "path constraint rejected leaf entity"
                );
            }
            false
        }
    }
}

fn exceeded_max_path_length(sub_stmt: &EntityStatement, depth: usize) -> Option<u32> {
    let max_path = sub_stmt.constraints.as_ref()?.max_path_length?;
    let depth_exceeds_max_path = match u32::try_from(depth) {
        Ok(depth_u32) => depth_u32 > max_path,
        Err(_) => true,
    };
    depth_exceeds_max_path.then_some(max_path)
}
