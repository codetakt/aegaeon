// Test suite for RFC 7662 Token Introspection schema validation

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// RFC 7662 Token Introspection Response
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct IntrospectionResponse {
    active: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    token_type: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    iat: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    nbf: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    sub: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    iss: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    jti: Option<String>,

    // Additional claims
    #[serde(flatten)]
    additional_claims: HashMap<String, Value>,
}

impl IntrospectionResponse {
    fn new_inactive() -> Self {
        Self {
            active: false,
            scope: None,
            client_id: None,
            username: None,
            token_type: None,
            exp: None,
            iat: None,
            nbf: None,
            sub: None,
            aud: None,
            iss: None,
            jti: None,
            additional_claims: HashMap::new(),
        }
    }

    fn new_active(client_id: String, exp: u64, iat: u64, sub: String, iss: String) -> Self {
        Self {
            active: true,
            scope: Some("read write".to_string()),
            client_id: Some(client_id),
            username: None,
            token_type: Some("Bearer".to_string()),
            exp: Some(exp),
            iat: Some(iat),
            nbf: Some(iat),
            sub: Some(sub),
            aud: Some(vec!["https://api.example.com".to_string()]),
            iss: Some(iss),
            jti: None,
            additional_claims: HashMap::new(),
        }
    }

    fn validate_schema(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // RFC 7662 Section 2.2: active is REQUIRED
        // (always present in our struct)

        if self.active {
            // When active, certain claims are expected
            if self.exp.is_none() {
                errors.push("Active token should include exp claim".to_string());
            }
            if self.iat.is_none() {
                errors.push("Active token should include iat claim".to_string());
            }
            if self.client_id.is_none() {
                errors.push("Active token should include client_id".to_string());
            }
        } else {
            // When inactive, other claims should be minimal
            if self.scope.is_some() {
                errors.push("Inactive token should not include scope".to_string());
            }
            if self.exp.is_some() {
                errors.push("Inactive token should not include exp".to_string());
            }
        }

        // Validate temporal claims if present
        if let (Some(iat), Some(exp)) = (self.iat, self.exp) {
            if exp <= iat {
                errors.push("exp must be after iat".to_string());
            }
        }

        if let (Some(nbf), Some(exp)) = (self.nbf, self.exp) {
            if exp <= nbf {
                errors.push("exp must be after nbf".to_string());
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

struct IntrospectionService {
    tokens: HashMap<String, IntrospectionResponse>,
}

impl IntrospectionService {
    fn new() -> Self {
        Self {
            tokens: HashMap::new(),
        }
    }

    fn add_token(&mut self, token_id: String, response: IntrospectionResponse) {
        self.tokens.insert(token_id, response);
    }

    fn introspect(&self, token: &str, client_id: &str) -> IntrospectionResponse {
        if let Some(response) = self.tokens.get(token) {
            // Check if client can introspect this token
            if let Some(ref token_client_id) = response.client_id {
                if token_client_id == client_id {
                    return response.clone();
                }
            }
        }

        // Return inactive for unknown tokens or unauthorized clients
        IntrospectionResponse::new_inactive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Display;

    type TestResult = Result<(), String>;

    trait TestContext<T> {
        fn test_context(self, context: &str) -> Result<T, String>;
    }

    impl<T, E: Display> TestContext<T> for Result<T, E> {
        fn test_context(self, context: &str) -> Result<T, String> {
            self.map_err(|err| format!("{context}: {err}"))
        }
    }

    impl<T> TestContext<T> for Option<T> {
        fn test_context(self, context: &str) -> Result<T, String> {
            self.ok_or_else(|| context.to_string())
        }
    }

    fn result_err<T, E>(result: Result<T, E>, context: &str) -> Result<E, String> {
        result.err().test_context(context)
    }

    #[test]
    fn test_inactive_token_schema() {
        let response = IntrospectionResponse::new_inactive();

        assert!(!response.active);
        assert!(response.scope.is_none());
        assert!(response.client_id.is_none());
        assert!(response.exp.is_none());

        // Schema validation should pass
        assert!(response.validate_schema().is_ok());
    }

    #[test]
    fn test_active_token_schema() {
        let now = 1_700_000_000_u64;
        let response = IntrospectionResponse::new_active(
            "client123".to_string(),
            now + 3600, // exp: 1 hour from now
            now,        // iat: now
            "user456".to_string(),
            "https://auth.example.com".to_string(),
        );

        assert!(response.active);
        assert!(response.client_id.is_some());
        assert!(response.exp.is_some());
        assert!(response.iat.is_some());

        // Schema validation should pass
        assert!(response.validate_schema().is_ok());
    }

    #[test]
    fn test_invalid_temporal_claims() -> TestResult {
        let now = 1_700_000_000_u64;
        let mut response = IntrospectionResponse::new_active(
            "client123".to_string(),
            now, // exp: same as iat (invalid)
            now, // iat: now
            "user456".to_string(),
            "https://auth.example.com".to_string(),
        );

        let result = response.validate_schema();
        assert!(result.is_err());
        let errors = result_err(result, "invalid iat/exp should fail")?;
        assert!(errors.iter().any(|e| e.contains("exp must be after iat")));

        // Fix exp but break nbf
        response.exp = Some(now + 3600);
        response.nbf = Some(now + 7200); // nbf after exp (invalid)

        let result = response.validate_schema();
        assert!(result.is_err());
        let errors = result_err(result, "invalid nbf/exp should fail")?;
        assert!(errors.iter().any(|e| e.contains("exp must be after nbf")));
        Ok(())
    }

    #[test]
    fn test_inactive_with_claims_invalid() -> TestResult {
        let mut response = IntrospectionResponse::new_inactive();
        response.scope = Some("read".to_string());
        response.exp = Some(1_700_000_000);

        let result = response.validate_schema();
        assert!(result.is_err());
        let errors = result_err(result, "inactive response with active claims should fail")?;
        assert!(errors
            .iter()
            .any(|e| e.contains("should not include scope")));
        assert!(errors.iter().any(|e| e.contains("should not include exp")));
        Ok(())
    }

    #[test]
    fn test_json_serialization() -> TestResult {
        let response = IntrospectionResponse::new_active(
            "client123".to_string(),
            1_700_003_600,
            1_700_000_000,
            "user456".to_string(),
            "https://auth.example.com".to_string(),
        );

        let json = serde_json::to_string(&response).test_context("serialize response")?;
        let parsed: IntrospectionResponse =
            serde_json::from_str(&json).test_context("parse response")?;

        assert_eq!(response, parsed);
        assert!(json.contains("\"active\":true"));
        assert!(json.contains("\"client_id\":\"client123\""));
        Ok(())
    }

    #[test]
    fn test_minimal_inactive_response() -> TestResult {
        let response = IntrospectionResponse::new_inactive();
        let json = serde_json::to_string(&response).test_context("serialize inactive response")?;

        // Should only contain active: false
        let parsed: Value = serde_json::from_str(&json).test_context("parse inactive response")?;
        assert_eq!(parsed["active"], false);
        let object = parsed
            .as_object()
            .test_context("inactive response must be an object")?;
        assert_eq!(object.len(), 1);
        Ok(())
    }

    #[test]
    fn test_introspection_service() {
        let mut service = IntrospectionService::new();

        // Add an active token
        let active_response = IntrospectionResponse::new_active(
            "client123".to_string(),
            1_700_003_600,
            1_700_000_000,
            "user456".to_string(),
            "https://auth.example.com".to_string(),
        );
        service.add_token("token_abc".to_string(), active_response.clone());

        // Correct client can introspect
        let result = service.introspect("token_abc", "client123");
        assert!(result.active);
        assert_eq!(result.client_id, Some("client123".to_string()));

        // Wrong client gets inactive
        let result = service.introspect("token_abc", "wrong_client");
        assert!(!result.active);

        // Unknown token gets inactive
        let result = service.introspect("unknown_token", "client123");
        assert!(!result.active);
    }

    #[test]
    fn test_dpop_token_introspection() {
        let mut response = IntrospectionResponse::new_active(
            "client123".to_string(),
            1_700_003_600,
            1_700_000_000,
            "user456".to_string(),
            "https://auth.example.com".to_string(),
        );

        // Add DPoP-specific claims
        response.token_type = Some("DPoP".to_string());
        response.jti = Some("unique-jti-123".to_string());
        response.additional_claims.insert(
            "cnf".to_string(),
            serde_json::json!({
                "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
            }),
        );

        assert!(response.validate_schema().is_ok());
        assert_eq!(response.token_type, Some("DPoP".to_string()));
        assert!(response.jti.is_some());
    }

    #[test]
    fn test_audience_claim() -> TestResult {
        let response = IntrospectionResponse::new_active(
            "client123".to_string(),
            1_700_003_600,
            1_700_000_000,
            "user456".to_string(),
            "https://auth.example.com".to_string(),
        );

        assert!(response.aud.is_some());
        let aud = response.aud.test_context("audience claim present")?;
        assert_eq!(aud.len(), 1);
        assert_eq!(aud[0], "https://api.example.com");
        Ok(())
    }

    // ── RFC 9701 JWT Introspection Response Tests ──────────────────────

    /// RFC 9701 JWT introspection wrapper claims
    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct JwtIntrospectionWrapper {
        iss: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        aud: Option<String>,
        iat: u64,
        exp: u64,
        jti: String,
        token_introspection: Value,
    }

    const MAX_JWT_INTROSPECTION_EXP_SECS: u64 = 60;
    const JWT_INTROSPECTION_TYP: &str = "token-introspection+jwt";

    fn build_jwt_introspection_wrapper(
        iss: &str,
        aud: Option<&str>,
        now: u64,
        configured_exp_secs: u64,
        introspection_claims: Value,
    ) -> (Value, JwtIntrospectionWrapper) {
        let clamped_exp = configured_exp_secs.min(MAX_JWT_INTROSPECTION_EXP_SECS);
        let header = serde_json::json!({
            "alg": "HS256",
            "typ": JWT_INTROSPECTION_TYP,
            "kid": "test-key",
        });
        let wrapper = JwtIntrospectionWrapper {
            iss: iss.to_string(),
            aud: aud.map(std::string::ToString::to_string),
            iat: now,
            exp: now + clamped_exp,
            jti: format!("ji-{now}-test"),
            token_introspection: introspection_claims,
        };
        (header, wrapper)
    }

    #[test]
    fn test_jwt_introspection_ji2_exp_clamped() {
        // JI-2: exp must be ≤ 60 seconds from iat even if configured higher
        let now = 1_700_000_000_u64;
        let (_, wrapper) = build_jwt_introspection_wrapper(
            "https://auth.example.com",
            Some("resource-server"),
            now,
            3600, // configured 1 hour
            serde_json::json!({"active": true}),
        );
        assert!(wrapper.exp <= now + MAX_JWT_INTROSPECTION_EXP_SECS);
        assert_eq!(wrapper.exp, now + 60); // clamped to 60
    }

    #[test]
    fn test_jwt_introspection_ji2_exp_short_config() {
        // JI-2: if configured ≤ 60, use configured value
        let now = 1_700_000_000_u64;
        let (_, wrapper) = build_jwt_introspection_wrapper(
            "https://auth.example.com",
            Some("rs"),
            now,
            30, // configured 30s
            serde_json::json!({"active": true}),
        );
        assert_eq!(wrapper.exp, now + 30);
    }

    #[test]
    fn test_jwt_introspection_ji4_distinct_typ() {
        // JI-4: typ must be "token-introspection+jwt", distinct from "at+jwt"
        let (header, _) = build_jwt_introspection_wrapper(
            "https://auth.example.com",
            None,
            1_700_000_000,
            30,
            serde_json::json!({"active": false}),
        );
        assert_eq!(header["typ"], "token-introspection+jwt");
        assert_ne!(header["typ"], "at+jwt");
        assert_ne!(header["typ"], "JWT");
    }

    #[test]
    fn test_jwt_introspection_ji1_aud_binding() {
        // JI-1: aud bound to requesting resource server
        let (_, wrapper) = build_jwt_introspection_wrapper(
            "https://auth.example.com",
            Some("resource-server-client-id"),
            1_700_000_000,
            30,
            serde_json::json!({"active": true, "client_id": "some-client"}),
        );
        assert_eq!(wrapper.aud, Some("resource-server-client-id".to_string()));
    }

    #[test]
    fn test_jwt_introspection_ji6_issuer_present() {
        // JI-6: iss prevents cross-tenant confusion
        let (_, wrapper) = build_jwt_introspection_wrapper(
            "https://tenant-1.auth.example.com",
            None,
            1_700_000_000,
            30,
            serde_json::json!({"active": true}),
        );
        assert_eq!(wrapper.iss, "https://tenant-1.auth.example.com");
        assert!(!wrapper.iss.is_empty());
    }

    #[test]
    fn test_jwt_introspection_inactive_token() {
        // Even inactive tokens get JWT wrapper with security properties
        let now = 1_700_000_000_u64;
        let (header, wrapper) = build_jwt_introspection_wrapper(
            "https://auth.example.com",
            Some("rs"),
            now,
            60,
            serde_json::json!({"active": false}),
        );
        assert_eq!(wrapper.token_introspection["active"], false);
        assert_eq!(header["typ"], JWT_INTROSPECTION_TYP);
        assert!(wrapper.exp <= now + MAX_JWT_INTROSPECTION_EXP_SECS);
    }

    #[test]
    fn test_jwt_introspection_ji5_revocation_window() {
        // JI-5: the revocation information staleness window is bounded by exp - iat
        let now = 1_700_000_000_u64;
        for configured_exp in [1, 10, 30, 60, 120, 3600] {
            let (_, wrapper) = build_jwt_introspection_wrapper(
                "https://auth.example.com",
                None,
                now,
                configured_exp,
                serde_json::json!({"active": true}),
            );
            let window = wrapper.exp - wrapper.iat;
            assert!(
                window <= MAX_JWT_INTROSPECTION_EXP_SECS,
                "Revocation window {window} exceeds {MAX_JWT_INTROSPECTION_EXP_SECS} for configured_exp={configured_exp}"
            );
        }
    }

    #[test]
    fn test_jwt_introspection_content_type() {
        // RFC 9701: Content-Type must be application/token-introspection+jwt
        let ct = "application/token-introspection+jwt";
        assert_ne!(ct, "application/json");
        assert_ne!(ct, "application/jwt");
    }

    #[test]
    fn test_jwt_introspection_jti_uniqueness() {
        // jti must be unique per response
        let now1 = 1_700_000_000_u64;
        let now2 = 1_700_000_001_u64;
        let (_, w1) = build_jwt_introspection_wrapper(
            "https://auth.example.com",
            None,
            now1,
            30,
            serde_json::json!({"active": true}),
        );
        let (_, w2) = build_jwt_introspection_wrapper(
            "https://auth.example.com",
            None,
            now2,
            30,
            serde_json::json!({"active": true}),
        );
        assert_ne!(w1.jti, w2.jti);
    }

    #[test]
    fn test_jwt_introspection_serialization() -> TestResult {
        // Wrapper claims serialize as expected JSON
        let (_, wrapper) = build_jwt_introspection_wrapper(
            "https://auth.example.com",
            Some("rs-client"),
            1_700_000_000,
            30,
            serde_json::json!({"active": true, "scope": "read", "client_id": "c1"}),
        );
        let json = serde_json::to_value(&wrapper).test_context("serialize JWT wrapper")?;
        assert_eq!(json["iss"], "https://auth.example.com");
        assert_eq!(json["aud"], "rs-client");
        assert!(json["token_introspection"]["active"]
            .as_bool()
            .test_context("active claim must be boolean")?);
        assert_eq!(json["token_introspection"]["scope"], "read");
        Ok(())
    }

    // ── End RFC 9701 Tests ───────────────────────────────────────────

    #[test]
    fn test_schema_validation_missing_required_for_active() -> TestResult {
        let response = IntrospectionResponse {
            active: true,
            scope: Some("read".to_string()),
            client_id: None, // Missing required field
            username: None,
            token_type: Some("Bearer".to_string()),
            exp: None, // Missing required field
            iat: None, // Missing required field
            nbf: None,
            sub: Some("user123".to_string()),
            aud: None,
            iss: Some("https://auth.example.com".to_string()),
            jti: None,
            additional_claims: HashMap::new(),
        };

        let result = response.validate_schema();
        assert!(result.is_err());
        let errors = result_err(
            result,
            "active response missing required claims should fail",
        )?;
        assert_eq!(errors.len(), 3);
        assert!(errors.iter().any(|e| e.contains("client_id")));
        assert!(errors.iter().any(|e| e.contains("exp")));
        assert!(errors.iter().any(|e| e.contains("iat")));
        Ok(())
    }
}
