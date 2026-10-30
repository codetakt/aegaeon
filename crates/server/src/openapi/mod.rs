use utoipa::openapi::OpenApi;
use utoipa::OpenApi as _;

mod management;
mod ops;
mod organizations;
#[cfg(test)]
mod snapshot_contract;
mod types;

pub use management::ManagementApiV1;
pub use ops::OpsApiV1;

#[must_use]
pub fn management_openapi() -> OpenApi {
    ManagementApiV1::openapi()
}

#[must_use]
pub fn ops_openapi() -> OpenApi {
    OpsApiV1::openapi()
}

#[must_use]
pub fn organizations_openapi() -> OpenApi {
    organizations::OrganizationsApiV1::openapi()
}

#[cfg(test)]
mod tests {
    #[test]
    fn management_operation_identifiers_are_unique_across_modules() -> anyhow::Result<()> {
        let document = serde_json::to_value(super::management_openapi())?;
        let paths = document["paths"]
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("paths"))?;
        let mut identifiers = std::collections::HashSet::new();
        for (path, methods) in paths {
            for (method, operation) in methods
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("methods"))?
            {
                if !matches!(
                    method.as_str(),
                    "get" | "head" | "post" | "put" | "patch" | "delete" | "options"
                ) {
                    continue;
                }
                let id = operation["operationId"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("operationId"))?;
                assert!(identifiers.insert(id), "duplicate {id}: {method} {path}");
            }
        }
        assert!(!identifiers.is_empty());
        Ok(())
    }

    #[test]
    fn organizations_resource_contract_requires_both_dpop_credentials_and_exact_fields(
    ) -> Result<(), serde_json::Error> {
        let doc = serde_json::to_value(super::organizations_openapi())?;
        let paths = doc["paths"].as_object().unwrap();
        assert_eq!(paths.len(), 12);
        let mut operations = 0;
        for (path, item) in paths {
            for (method, operation) in item.as_object().unwrap() {
                operations += 1;
                if path.ends_with("/identity") {
                    if method == "post" {
                        assert_eq!(
                            operation["security"],
                            serde_json::json!([{"identityCsrfCookie":[]}])
                        );
                        assert_eq!(
                            operation["requestBody"]["content"]
                                ["application/x-www-form-urlencoded"]["schema"]["$ref"],
                            "#/components/schemas/IdentityForm"
                        );
                        assert!(operation["description"]
                            .as_str()
                            .unwrap()
                            .contains("no login session or membership"));
                    } else {
                        assert!(matches!(method.as_str(), "get" | "head"));
                        assert!(operation.get("security").is_none());
                    }
                    continue;
                }
                assert_eq!(
                    operation["security"],
                    if path.starts_with("/organization-support/") {
                        serde_json::json!([{"supportDpopToken":[],"resourceDpopProof":[]}])
                    } else if path.starts_with("/organization-invitations/") {
                        assert_eq!(method, "post");
                        serde_json::json!([{"recipientDpopToken":[],"resourceDpopProof":[]}])
                    } else {
                        serde_json::json!([{"selectedDpopToken":[],"resourceDpopProof":[]}])
                    }
                );
                if method == "head" {
                    assert!(operation["responses"]["200"].get("content").is_none());
                }
            }
        }
        assert_eq!(operations, 20);
        let schemas = &doc["components"]["schemas"];
        for name in ["RecipientChallengeRequest", "AcceptInvitationRequest"] {
            assert_eq!(schemas[name]["additionalProperties"], false);
        }
        assert_eq!(
            schemas["ChallengeResponse"]["properties"]
                .as_object()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            schemas["AcceptanceResponse"]["properties"]
                .as_object()
                .unwrap()
                .len(),
            4
        );

        assert_eq!(
            schemas["MemberUpdateState"]["enum"],
            serde_json::json!(["active", "suspended", "removed"])
        );
        assert_eq!(
            schemas["MemberResponse"]["properties"]
                .as_object()
                .unwrap()
                .len(),
            7
        );
        assert_eq!(
            schemas["UpdateMemberRequest"]["additionalProperties"],
            false
        );
        assert_eq!(
            doc["components"]["securitySchemes"]["selectedDpopToken"]["name"],
            "Authorization"
        );
        assert_eq!(
            doc["components"]["securitySchemes"]["resourceDpopProof"]["name"],
            "DPoP"
        );
        Ok(())
    }

    #[test]
    fn organizations_configuration_contract_uses_actual_cookie_and_explicit_security(
    ) -> Result<(), serde_json::Error> {
        let doc = serde_json::to_value(super::management_openapi())?;
        assert_eq!(
            doc["components"]["securitySchemes"]["managementSessionCookie"]["name"],
            crate::web::management::MGMT_SESSION_COOKIE_NAME
        );
        let mut count = 0;
        for (path, item) in doc["paths"].as_object().unwrap() {
            if !path.contains("/organization-domains/") {
                continue;
            }
            for (method, operation) in item.as_object().unwrap() {
                count += 1;
                if method == "head" {
                    assert_eq!(
                        operation["security"],
                        serde_json::json!([{"managementSessionCookie":[]}])
                    );
                    assert!(operation["responses"]["200"].get("content").is_none());
                    continue;
                }
                if method == "get" {
                    assert_eq!(
                        operation["security"],
                        serde_json::json!([{"managementSessionCookie":[]}])
                    );
                    if path.ends_with("/snapshot") {
                        assert_eq!(
                            operation["responses"]["200"]["content"]["application/x-ndjson"]
                                ["schema"]["type"],
                            "string"
                        );
                        assert!(operation["responses"]["200"]["content"]
                            .get("application/json")
                            .is_none());
                        assert!(operation["parameters"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .all(|p| p["in"] == "path"));
                        continue;
                    }
                    assert_eq!(
                        operation["responses"]["200"]["content"]["application/json"]["schema"]
                            ["$ref"],
                        if path.ends_with("/operators") {
                            "#/components/schemas/OperatorListResponse"
                        } else if path.ends_with("/audit-events/pending") {
                            "#/components/schemas/OrganizationAuditBatch"
                        } else if path.ends_with("/audit-events") {
                            "#/components/schemas/OrganizationAuditPage"
                        } else if path.ends_with("/clients") {
                            "#/components/schemas/OrganizationClientListResponse"
                        } else if path.ends_with("/organizations") {
                            "#/components/schemas/OrganizationListResponse"
                        } else if path.ends_with("/organizations/{organization}") {
                            "#/components/schemas/OrganizationResponse"
                        } else if path.ends_with("/invitations/{invitation}") {
                            "#/components/schemas/Invitation"
                        } else if path.ends_with("/support-policy") {
                            "#/components/schemas/OrganizationSupportConfiguration"
                        } else if path.ends_with("/identity-policy") {
                            "#/components/schemas/OrganizationIdentityConfiguration"
                        } else if path.ends_with("/invitation-delivery") {
                            "#/components/schemas/OrganizationInvitationDeliveryConfiguration"
                        } else if path.ends_with("/role-policy") {
                            "#/components/schemas/RolePolicy"
                        } else {
                            "#/components/schemas/DomainConfiguration"
                        }
                    );
                    continue;
                }
                assert_eq!(
                    operation["security"],
                    serde_json::json!([{"managementSessionCookie":[],"managementCsrfHeader":[]}])
                );
                assert!(operation["parameters"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|p| p["name"] == "Idempotency-Key" && p["required"] == true));
                assert!(operation["responses"]["200"]["headers"]["ETag"].is_object());
            }
        }
        assert_eq!(count, 46);
        assert_eq!(
            doc["components"]["schemas"]["Invitation"]["properties"]
                .as_object()
                .unwrap()
                .len(),
            6
        );
        for (schema, field) in [
            ("OrganizationAuditBatch", "domainId"),
            ("OrganizationAuditReceipt", "actorId"),
            ("OrganizationAuditEventDigest", "id"),
            ("OrganizationAuditEvent", "id"),
            ("OrganizationAuditEvent", "environmentId"),
            ("OrganizationAuditEvent", "domainId"),
            ("OperatorGrantResponse", "id"),
            ("OperatorGrantResponse", "administratorId"),
            ("OperatorGrantResponse", "domainId"),
            ("DefaultDomainResponse", "environmentId"),
            ("DomainConfiguration", "id"),
            ("DomainConfiguration", "environmentId"),
            ("ClientBinding", "id"),
            ("ClientBinding", "clientRegistrationId"),
            ("Recipient", "clientRegistrationId"),
            ("RolePolicy", "id"),
            ("Invitation", "id"),
            ("Invitation", "organizationId"),
            ("OrganizationResponse", "id"),
            ("OrganizationResponse", "environmentId"),
            ("OrganizationResponse", "domainId"),
        ] {
            assert_eq!(
                doc["components"]["schemas"][schema]["properties"][field]["format"],
                "uuid"
            );
        }
        Ok(())
    }

    #[test]
    fn application_projection_response_documents_the_runtime_revision(
    ) -> Result<(), serde_json::Error> {
        let doc = serde_json::to_value(super::management_openapi())?;
        let operation = &doc["paths"]
            ["/api/v1/teams/{teamId}/environments/{environmentId}/application-authorizations"]
            ["post"];
        assert_eq!(
            operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/ApplicationAuthorizationResponse"
        );
        let schema = &doc["components"]["schemas"]["ApplicationAuthorizationResponse"];
        assert_eq!(schema["required"], serde_json::json!(["revision"]));
        assert_eq!(schema["properties"]["revision"]["type"], "integer");
        assert_eq!(schema["properties"]["revision"]["format"], "int64");
        let body = crate::management::types::ApplicationAuthorizationResponse { revision: 2 };
        assert_eq!(
            serde_json::to_value(body)?,
            serde_json::json!({"revision": 2})
        );
        Ok(())
    }
}
