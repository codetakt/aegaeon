use axum::response::Response;
use sqlx::{Postgres, Transaction};

use super::super::super::configuration_documents::ConfigurationVersionAuditContext;
use super::super::super::configuration_federation::{
    federation_logout_audit_severity, FederationConfigurationAuditSnapshot,
};
use super::writer::write_configuration_version_transition_audit_event;
use crate::management::types::ActivateConfigurationVersionRequest;

pub(in crate::web::management::configuration_versions) async fn write_configuration_activation_audits(
    tx: &mut Transaction<'_, Postgres>,
    context: &ConfigurationVersionAuditContext<'_>,
    request: &ActivateConfigurationVersionRequest,
    downgraded_fields: &[&'static str],
    previous: &FederationConfigurationAuditSnapshot,
    current: &FederationConfigurationAuditSnapshot,
) -> Result<(), Response> {
    let activation_severity = if downgraded_fields.is_empty() {
        "INFO"
    } else {
        "WARN"
    };
    let audit_data = serde_json::json!({
        "reason": request.reason,
        "allowSecurityDowngrade": request.allow_security_downgrade,
        "securityDowngrade": (!downgraded_fields.is_empty()).then_some(downgraded_fields),
        "federationLogoutPolicyChanged": previous.logout_policy != current.logout_policy,
        "federationLogout": current.logout_policy.clone(),
        "federationAttributeMappingChanged": previous.attribute_mapping != current.attribute_mapping,
        "federationAttributeMapping": current.attribute_mapping.clone(),
        "federationClaimReleaseChanged": previous.claim_release != current.claim_release,
        "federationClaimRelease": current.claim_release.clone(),
    });
    write_configuration_version_transition_audit_event(
        tx,
        context,
        "CONFIGURATION_VERSION_ACTIVATED",
        activation_severity,
        audit_data,
    )
    .await?;

    if previous.logout_policy != current.logout_policy {
        write_configuration_version_transition_audit_event(
            tx,
            context,
            "management.federationLogoutPolicy.changed.v1",
            federation_logout_audit_severity(&current.logout_policy),
            serde_json::json!({
                "reason": request.reason,
                "previous": previous.logout_policy,
                "current": current.logout_policy,
            }),
        )
        .await?;
    }

    if previous.attribute_mapping != current.attribute_mapping {
        write_configuration_version_transition_audit_event(
            tx,
            context,
            "management.federationAttributeMapping.changed.v1",
            "INFO",
            serde_json::json!({
                "reason": request.reason,
                "previous": previous.attribute_mapping,
                "current": current.attribute_mapping,
            }),
        )
        .await?;
    }

    if previous.claim_release != current.claim_release {
        write_configuration_version_transition_audit_event(
            tx,
            context,
            "management.federationClaimRelease.changed.v1",
            "INFO",
            serde_json::json!({
                "reason": request.reason,
                "previous": previous.claim_release,
                "current": current.claim_release,
            }),
        )
        .await?;
    }

    Ok(())
}
