use super::*;
use serde_json::json;

#[test]
fn audience_cardinality_is_independent_of_representation() {
    for (audience, expected) in [
        (Audience::Single("client456".into()), false),
        (Audience::Multiple(vec![]), false),
        (Audience::Multiple(vec!["client456".into()]), false),
        (
            Audience::Multiple(vec!["client456".into(), "client456".into()]),
            true,
        ),
        (
            Audience::Multiple(vec!["client456".into(), "other".into()]),
            true,
        ),
    ] {
        assert_eq!(audience.is_multiple(), expected);
    }
}

#[test]
fn id_token_audience_trust_and_supplied_azp_policy() -> TestResult {
    let now = unix_time_now_i64().ok_or_else(|| io::Error::other("system time"))?;
    let mut ctx = IdTokenValidationContext::new("client456", "https://example.com");
    ctx.current_time = Some(now);
    ctx.expected_nonce = Some("test-nonce");
    for (aud, trusted) in [
        (json!("client456"), true),
        (json!(["client456"]), true),
        (json!(["client456", "client456"]), true),
        (json!([]), false),
        (json!(""), false),
        (json!(["other"]), false),
        (json!(["client456", "other"]), false),
        (json!(["other", "client456"]), false),
        (json!(["client456", ""]), false),
        (json!("Client456"), false),
        (json!(" client456"), false),
        (json!("client456 "), false),
        (json!("client%34%35%36"), false),
    ] {
        for azp in [
            None,
            Some("client456"),
            Some("other"),
            Some("Client456"),
            Some("client456 "),
            Some("client%34%35%36"),
            Some(""),
        ] {
            let mut token = test_token_at(now);
            token.claims.aud = serde_json::from_value(aud.clone())?;
            token.claims.azp = azp.map(str::to_string);
            let expected = trusted && azp.is_none_or(|value| value == "client456");
            assert_eq!(
                token.validate_with_context(&ctx).is_ok(),
                expected,
                "aud={aud}, azp={azp:?}"
            );
            assert_eq!(
                token
                    .validate("client456", "https://example.com", Some("test-nonce"))
                    .is_ok(),
                expected,
                "public validate: aud={aud}, azp={azp:?}"
            );
        }
    }
    Ok(())
}

#[test]
fn id_token_audience_decoding_rejects_missing_and_wrong_types() -> TestResult {
    let mut value = serde_json::to_value(test_token_at(1_700_000_000).claims)?;
    for aud in [json!(null), json!(7), json!({}), json!(["client456", 7])] {
        value["aud"] = aud;
        assert!(serde_json::from_value::<IdTokenClaims>(value.clone()).is_err());
    }
    value
        .as_object_mut()
        .ok_or_else(|| io::Error::other("claims object"))?
        .remove("aud");
    assert!(serde_json::from_value::<IdTokenClaims>(value).is_err());
    Ok(())
}
