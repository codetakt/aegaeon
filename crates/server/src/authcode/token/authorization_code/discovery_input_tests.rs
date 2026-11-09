use super::*;

fn input(scope: &str) -> AuthorizationCodeIssueInput {
    let req = serde_json::from_value(serde_json::json!({
        "response_type": "code", "client_id": "discovery-client", "scope": scope,
        "resource": "https://issuer.example.test/organization-discovery",
        "dpop_jkt": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        "code_challenge_method": "S256",
    }))
    .unwrap();
    AuthorizationCodeIssueInput::new(req, "subject".into(), true, 1)
}

#[test]
fn discovery_scope_errors_remain_distinct_from_other_missing_security_input() {
    for scopes in ["organizations:discover", "organizations:discover openid"] {
        assert!(validate_discovery_input(&input(scopes)).is_ok());
    }
    for scopes in [
        "organizations:discover offline_access",
        "organizations:discover documents.read",
    ] {
        assert_eq!(
            validate_discovery_input(&input(scopes))
                .unwrap_err()
                .to_string(),
            "invalid discovery scope combination"
        );
    }
    for missing in ["pkce", "dpop", "resource"] {
        let mut value = input("organizations:discover");
        match missing {
            "pkce" => value.req.code_challenge = None,
            "dpop" => value.req.dpop_jkt = None,
            "resource" => value.req.resource = None,
            _ => unreachable!(),
        }
        assert!(
            matches!(
                validate_discovery_input(&value),
                Err(AuthorizationCodeIssueError::InvalidOrganizationApproval)
            ),
            "{missing}"
        );
    }
}
