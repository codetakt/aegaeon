mod attribute_mapping;
mod claim_release;
mod logout;

pub(in crate::web::management) use attribute_mapping::federation_attribute_mapping_audit_snapshot;
pub(in crate::web::management) use claim_release::federation_claim_release_audit_snapshot;
pub(in crate::web::management) use logout::{
    federation_logout_audit_severity, federation_logout_audit_snapshot,
};

#[derive(Clone, Debug)]
pub(in crate::web::management) struct FederationConfigurationAuditSnapshot {
    pub(in crate::web::management) logout_policy: serde_json::Value,
    pub(in crate::web::management) attribute_mapping: serde_json::Value,
    pub(in crate::web::management) claim_release: serde_json::Value,
}

pub(in crate::web::management) fn federation_configuration_audit_snapshot(
    configuration_document: &serde_json::Value,
) -> FederationConfigurationAuditSnapshot {
    FederationConfigurationAuditSnapshot {
        logout_policy: federation_logout_audit_snapshot(configuration_document),
        attribute_mapping: federation_attribute_mapping_audit_snapshot(configuration_document),
        claim_release: federation_claim_release_audit_snapshot(configuration_document),
    }
}
