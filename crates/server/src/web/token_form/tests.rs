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

#[test]
fn token_empty_scalar_values_are_absent_before_singleton_checks() {
    for key in [
        "grant_type",
        "code",
        "client_id",
        "client_secret",
        "scope",
        "refresh_token",
        "subject_token",
        "resource",
    ] {
        let values = vec![
            (key.to_owned(), String::new()),
            (key.to_owned(), "value".into()),
            (key.to_owned(), String::new()),
        ];
        assert_eq!(
            effective_token_param(&values, key, "https://issuer.example")
                .expect("effective singleton"),
            Some("value".into())
        );
        let omitted = vec![(key.to_owned(), String::new())];
        assert_eq!(
            effective_token_param(&omitted, key, "https://issuer.example").expect("omission"),
            None
        );
        let mut duplicated = values;
        duplicated.push((key.to_owned(), "value".into()));
        assert!(effective_token_param(&duplicated, key, "https://issuer.example").is_err());
    }
    let missing = vec![("grant_type".into(), String::new())];
    assert!(token_form_from_params(&missing, "https://issuer.example").is_err());
}

#[test]
fn token_empty_omission_preserves_shared_device_parameter_semantics() {
    let empty = vec![("scope".into(), String::new())];
    assert_eq!(
        optional_token_param(&empty, "scope", "https://issuer.example")
            .expect("shared raw semantics"),
        Some(String::new())
    );
    assert_eq!(
        effective_token_param(&empty, "scope", "https://issuer.example").expect("token omission"),
        None
    );
    let duplicate = vec![
        ("client_id".into(), String::new()),
        ("client_id".into(), "client".into()),
    ];
    assert!(optional_token_param(&duplicate, "client_id", "https://issuer.example").is_err());
    assert_eq!(
        effective_token_param(&duplicate, "client_id", "https://issuer.example")
            .expect("token singleton"),
        Some("client".into())
    );
}
