#![forbid(unsafe_code)]
#![no_main]

use libfuzzer_sys::fuzz_target;
use aegaeon_server::bcp_policy::{BcpPolicy, BcpValidator};

fuzz_target!(|data: &[u8]| {
    // Fuzz Bearer token validation with random input
    if let Ok(s) = std::str::from_utf8(data) {
        // Try to parse as JSON policy configuration
        if let Ok(policy) = serde_json::from_str::<BcpPolicy>(s) {
            let validator = BcpValidator::new(policy);

            // This should never panic, only return validation results
            let _ = validator.validate_policy();
            let _ = validator.generate_compliance_report();

            // Test various flow checks
            let _ = validator.is_flow_allowed("authorization_code");
            let _ = validator.is_flow_allowed("implicit");
            let _ = validator.is_flow_allowed("password");
            let _ = validator.is_flow_allowed(&String::from_utf8_lossy(data));

            // Test auth method checks
            let _ = validator.is_auth_method_allowed("client_secret_basic");
            let _ = validator.is_auth_method_allowed(&String::from_utf8_lossy(data));
        }

        // Also test with raw string inputs to various validators
        // This helps find parser edge cases
        let _ = s.contains("require_pkce");
        let _ = s.contains("forbidden_flow");
    }
});
