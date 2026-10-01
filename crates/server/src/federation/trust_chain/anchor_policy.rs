use super::super::{metadata_policy, EntityStatement, FederationError, TrustAnchor};

/// Enforce an optional local equality pin against the anchor-issued statement.
/// Federation permits absent signed policy; this additional pin is local policy.
pub(in crate::federation) fn validate_anchor_subordinate_metadata_policy(
    anchor: &TrustAnchor,
    sub_stmt: &EntityStatement,
) -> Result<(), FederationError> {
    metadata_policy::validate_metadata_policy_pin(anchor.metadata_policy.as_ref())?;
    let Some(anchor_policy) = anchor.metadata_policy.as_ref() else {
        return Ok(());
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
