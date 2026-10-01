use super::*;
use axum::http::header;

fn get(endpoint: OidcEndpoint, query: &str) -> Result<OidcParameters, OidcInputError> {
    let uri = format!("/authorize?{query}").parse().expect("test URI");
    admit_oidc_query(endpoint, &uri)
}

#[test]
fn oidc_input_preserves_valid_query_values() {
    let query = "client_id=client&response_type=code&scope=openid+profile&state=%2B%25%26%3D%E6%97%A5%E6%9C%AC&max_age=42";
    let admitted = get(OidcEndpoint::Authorize, query).expect("valid query");
    let raw = RawAuthzQuery::from_admitted(&admitted).expect("typed parameters");
    assert_eq!(raw.scope.as_deref(), Some("openid profile"));
    assert_eq!(raw.state.as_deref(), Some("+%&=日本"));
    assert_eq!(raw.max_age, Some(42));
}

#[test]
fn oidc_input_empty_values_are_omitted_before_singleton_duplicates() {
    for query in [
        "state=&state=value",
        "state=value&state=",
        "state&state=value",
        "state=&state=&state=value",
    ] {
        let parsed = get(OidcEndpoint::Authorize, query).expect("empty values omitted");
        assert_eq!(
            parsed.as_pairs(),
            &[("state".to_string(), "value".to_string())]
        );
    }
    let parsed = get(
        OidcEndpoint::Authorize,
        "max_age=&client_id=&resource=&state",
    )
    .expect("omitted");
    assert!(parsed.as_pairs().is_empty());
    assert!(RawAuthzQuery::from_admitted(&parsed)
        .expect("typed")
        .max_age
        .is_none());
}

#[test]
fn oidc_input_rejects_all_recognized_singleton_duplicates() {
    let authorize = [
        "client_id",
        "response_type",
        "response_mode",
        "iss",
        "redirect_uri",
        "authorization_details",
        "scope",
        "state",
        "nonce",
        "prompt",
        "max_age",
        "acr_values",
        "code_challenge",
        "code_challenge_method",
        "request",
        "request_uri",
        "aeg_par_continue",
    ];
    let logout = [
        "id_token_hint",
        "logout_hint",
        "client_id",
        "post_logout_redirect_uri",
        "state",
        "ui_locales",
    ];
    for (endpoint, names) in [
        (OidcEndpoint::Authorize, authorize.as_slice()),
        (OidcEndpoint::Logout, logout.as_slice()),
    ] {
        for name in names {
            let query = format!("{name}=first&{name}=second");
            assert_eq!(
                get(endpoint, &query).err(),
                Some(OidcInputError::DuplicateParameter),
                "{name}"
            );
        }
    }
    assert_eq!(
        get(OidcEndpoint::Authorize, "state=a&st%61te=b").err(),
        Some(OidcInputError::DuplicateParameter)
    );
}

#[test]
fn oidc_input_preserves_repeated_resources_in_typed_lowering() {
    let parsed = get(OidcEndpoint::Authorize, "resource=https%3A%2F%2Fa.example&resource=&resource=https%3A%2F%2Fb.example&resource=https%3A%2F%2Fa.example").expect("resource is repeatable");
    let raw = RawAuthzQuery::from_admitted(&parsed).expect("typed resources");
    assert_eq!(
        raw.resource,
        [
            "https://a.example",
            "https://b.example",
            "https://a.example"
        ]
    );
    assert_eq!(
        crate::util::parse_single_resource_indicator(&raw.resource)
            .err()
            .as_deref(),
        Some("multiple resource parameters are not supported")
    );
}

#[test]
fn oidc_input_ignores_unknown_duplicates_and_preserves_case() {
    let parsed = get(
        OidcEndpoint::Authorize,
        "unknown=a&unknown=b&State=wrong&state=right",
    )
    .expect("unknown ignored");
    assert_eq!(
        parsed.as_pairs(),
        &[("state".to_string(), "right".to_string())]
    );
    let logout = get(
        OidcEndpoint::Logout,
        "transaction=x&csrf_token=x&decision=yes&ui_locales=en",
    )
    .expect("confirmation is a separate flow");
    assert_eq!(
        logout.as_pairs(),
        &[("ui_locales".to_string(), "en".to_string())]
    );
}

#[test]
fn oidc_input_rejects_invalid_percent_and_utf8_without_replacement() {
    for value in [
        b"%".as_slice(),
        b"%0",
        b"%GG",
        b"%FZ",
        b"%FF",
        b"%C0%AF",
        b"%ED%A0%80",
        b"%F4%90%80%80",
        b"\xff",
        b"\xc2",
    ] {
        let mut body = b"state=".to_vec();
        body.extend(value);
        assert_eq!(
            admit_pairs(OidcEndpoint::Authorize, &body, DEFAULT_QUERY_LIMITS).err(),
            Some(OidcInputError::MalformedEncoding)
        );
    }
    for body in [b"%FF=x".as_slice(), b"unknown=%FF", b"unknown%GG=", b"%="] {
        assert_eq!(
            admit_pairs(OidcEndpoint::Authorize, body, DEFAULT_QUERY_LIMITS).err(),
            Some(OidcInputError::MalformedEncoding)
        );
    }
    let baseline = url::form_urlencoded::parse(b"state=%FF").collect::<Vec<_>>();
    assert_eq!(
        baseline[0].1, "\u{fffd}",
        "negative control: the old lossy decoder accepts replacement text"
    );
}

#[test]
fn oidc_input_checks_every_possible_percent_triplet() {
    for high in 0u8..=255 {
        for low in 0u8..=255 {
            let parsed = decode_component(
                &[b'%', high, low],
                3,
                OidcInputError::ParameterValueTooLarge,
            );
            let digits = [high, low];
            let oracle = std::str::from_utf8(&digits)
                .ok()
                .filter(|s| s.bytes().all(|b| b.is_ascii_hexdigit()))
                .and_then(|s| u8::from_str_radix(s, 16).ok())
                .filter(|b| b.is_ascii());
            match oracle {
                Some(byte) => assert_eq!(parsed.expect("ASCII percent octet").as_bytes(), &[byte]),
                None => assert_eq!(parsed.err(), Some(OidcInputError::MalformedEncoding)),
            }
        }
    }
}

#[test]
fn oidc_input_matches_existing_parameter_budget_boundaries() {
    use super::super::request_admission::validate_raw_query;
    let limits = DEFAULT_QUERY_LIMITS;
    let raws = [
        "&".repeat(limits.max_bytes()),
        "&".repeat(limits.max_bytes() + 1),
        vec!["unknown="; limits.max_params()].join("&"),
        vec!["unknown="; limits.max_params() + 1].join("&"),
        format!("{}=value", "k".repeat(limits.max_key_bytes())),
        format!("{}=value", "k".repeat(limits.max_key_bytes() + 1)),
        format!("state={}", "a".repeat(limits.max_value_bytes())),
        format!("state={}", "a".repeat(limits.max_value_bytes() + 1)),
        format!("unknown={}", "a".repeat(limits.max_value_bytes() + 1)),
    ];
    for raw in raws {
        assert_eq!(
            validate_raw_query(Some(&raw), limits).is_ok(),
            get(OidcEndpoint::Authorize, &raw).is_ok(),
            "same pre-existing budget"
        );
    }
    // Limits use decoded byte lengths, including ignored fields; '%' expansion
    // contributes to raw length rather than decoded name/value length.
    let tiny = BoundedQueryLimits::new(100, 3, 4, 4);
    assert!(admit_pairs(OidcEndpoint::Authorize, b"%73tate=x", tiny).is_err());
    assert!(admit_pairs(
        OidcEndpoint::Authorize,
        b"state=%C3%A9%C3%A9",
        BoundedQueryLimits::new(100, 3, 5, 4)
    )
    .is_ok());
    assert_eq!(
        admit_pairs(
            OidcEndpoint::Authorize,
            b"state=%C3%A9%C3%A9x",
            BoundedQueryLimits::new(100, 3, 5, 4)
        )
        .err(),
        Some(OidcInputError::ParameterValueTooLarge)
    );
}

#[test]
fn oidc_input_typed_lowering_preserves_existing_singleton_values() {
    let query = "client_id=c&response_type=code&response_mode=form_post&iss=https%3A%2F%2Fissuer.example&redirect_uri=https%3A%2F%2Fclient.example%2Fcb&resource=https%3A%2F%2Fresource.example&authorization_details=%5B%5D&scope=openid&state=s&nonce=n&prompt=login&max_age=%2B42&acr_values=urn%3Apwd&code_challenge=ch&code_challenge_method=S256&request=jwt&request_uri=uri&aeg_par_continue=continue";
    let old: RawAuthzQuery = serde_urlencoded::from_str(query).expect("existing serde");
    let new = RawAuthzQuery::from_admitted(&get(OidcEndpoint::Authorize, query).expect("admitted"))
        .expect("lowered");
    macro_rules! same { ($($field:ident),+ $(,)?) => { $(assert_eq!(new.$field, old.$field, stringify!($field));)+ }; }
    same!(
        client_id,
        response_type,
        response_mode,
        iss,
        redirect_uri,
        resource,
        authorization_details,
        scope,
        state,
        nonce,
        prompt,
        max_age,
        acr_values,
        code_challenge,
        code_challenge_method,
        request,
        request_uri,
        aeg_par_continue
    );
    for value in ["-1", "1.0", "18446744073709551616", "abc"] {
        let params =
            get(OidcEndpoint::Authorize, &format!("max_age={value}")).expect("admitted encoding");
        assert_eq!(
            RawAuthzQuery::from_admitted(&params).err(),
            Some(OidcInputError::InvalidParameterValue)
        );
    }
}

#[tokio::test]
async fn oidc_input_error_envelopes_are_no_cache_without_supplied_values() {
    for error in [
        OidcInputError::MalformedEncoding,
        OidcInputError::ParametersTooLarge,
        OidcInputError::TooManyParameters,
        OidcInputError::ParameterNameTooLarge,
        OidcInputError::ParameterValueTooLarge,
        OidcInputError::DuplicateParameter,
        OidcInputError::InvalidParameterValue,
    ] {
        let response = error.into_response("https://issuer.example");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers()[header::CACHE_CONTROL]
            .to_str()
            .expect("cache header")
            .contains("no-store"));
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .expect("bounded body");
        let value: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON");
        assert_eq!(value["error"], "invalid_request");
        assert_eq!(value["iss"], "https://issuer.example");
    }
}

#[test]
fn oidc_input_unicode_round_trip_property() {
    fn round_trip(value: String) -> bool {
        if value.is_empty() {
            return true;
        }
        let encoded = serde_urlencoded::to_string([("state", &value)]).expect("encoding");
        if value.len() > DEFAULT_QUERY_LIMITS.max_value_bytes()
            || encoded.len() > DEFAULT_QUERY_LIMITS.max_bytes()
        {
            return true;
        }
        get(OidcEndpoint::Authorize, &encoded)
            .is_ok_and(|p| p.as_pairs() == [("state".to_string(), value)])
    }
    quickcheck::QuickCheck::new()
        .tests(1000)
        .quickcheck(round_trip as fn(String) -> bool);
}
