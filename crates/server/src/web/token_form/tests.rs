use super::*;

#[test]
fn token_unknown_names_do_not_become_grant_restrictions() {
    for grant in [
        "authorization_code",
        "refresh_token",
        "client_credentials",
        "urn:ietf:params:oauth:grant-type:token-exchange",
        "urn:ietf:params:oauth:grant-type:device_code",
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "unsupported",
        " Refresh_Token ",
    ] {
        let mut params = vec![("grant_type".into(), grant.into())];
        for name in ["organizationId", "Organization_id", "unknown"] {
            params.extend([(name.into(), "one".into()), (name.into(), "two".into())]);
        }
        params.extend((0..2).map(|_| ("organization_id".into(), String::new())));
        let form = token_form_from_params(&params, "https://issuer.example")
            .expect("unknown and empty values ignored");
        assert_eq!(form.grant_type, grant);
        params.push(("organization_id".into(), " ".into()));
        assert_eq!(
            token_form_from_params(&params, "https://issuer.example").is_ok(),
            grant == "urn:ietf:params:oauth:grant-type:token-exchange"
        );
    }
}

#[test]
fn token_canonical_selector_uses_effective_singleton_semantics() {
    for encoded in [
        "organization_id&organization_id=",
        "organization_id=&organization_id=organization_one&organizationId=organization_two",
        "organization_%69d=organization_%6fne&organizationId=a&organizationId=b",
    ] {
        let mut params: Vec<(String, String)> = serde_urlencoded::from_str(encoded).expect("form");
        params.push((
            "grant_type".into(),
            "urn:ietf:params:oauth:grant-type:token-exchange".into(),
        ));
        assert!(token_form_from_params(&params, "https://issuer.example").is_ok());
    }
    let params: Vec<(String, String)> = serde_urlencoded::from_str(
        "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&organization_id=a&organization_%69d=a",
    ).expect("form");
    assert!(token_form_from_params(&params, "https://issuer.example").is_err());
}
