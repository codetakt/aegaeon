use utoipa::openapi::OpenApi;
use utoipa::OpenApi as _;

mod management;
mod ops;
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

#[cfg(test)]
mod tests {
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
