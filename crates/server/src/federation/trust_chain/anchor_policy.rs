use super::super::{metadata_policy, EntityStatement, FederationError, TrustAnchor};

/// Check anchor metadata_policy matches the subordinate statement's policy.
///
/// Per OIDF 1.0 §6 and F* anchor_sub_policy_consistent, a trust anchor used
/// for chain validation MUST carry an explicit policy and the subordinate
/// statement MUST carry the same policy (Some vs Some). A missing subordinate
/// policy is rejected even when the anchor policy is empty.
pub(in crate::federation) fn validate_anchor_subordinate_metadata_policy(
    anchor: &TrustAnchor,
    sub_stmt: &EntityStatement,
) -> Result<(), FederationError> {
    let Some(anchor_policy) = anchor.metadata_policy.as_ref() else {
        return Err(FederationError::Validation(
            "trust anchor metadata_policy is required".into(),
        ));
    };
    let Some(sub_mp) = sub_stmt.metadata_policy.as_ref() else {
        return Err(FederationError::Validation(
            "subordinate statement missing metadata_policy required by anchor".into(),
        ));
    };
    let sub_policy_value = serde_json::to_value(sub_mp).map_err(FederationError::from)?;
    if metadata_policy::policy_equiv(anchor_policy, &sub_policy_value) {
        Ok(())
    } else {
        Err(FederationError::Validation(
            "subordinate statement metadata_policy does not match anchor policy".into(),
        ))
    }
}
