use aegaeon_jose::jwk::{verification_usage_allowed, Jwk, JwkError, KeyUse};
use serde_json::{json, Value};

type TestResult = Result<(), Box<dyn std::error::Error>>;
fn key() -> Value {
    json!({"kty":"RSA","n":"AQAB","e":"AQAB"})
}
fn operations(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| (*v).into()).collect()
}

#[test]
fn jwk_usage_use_is_exact_and_null_is_not_absent() -> TestResult {
    assert!(Jwk::from_value(key())?.is_signature_capable());
    for value in ["sig", "enc", "SIG", "ENC", " sig", "sig ", "unknown", ""] {
        let mut input = key();
        input["use"] = json!(value);
        let parsed = Jwk::from_value(input)?;
        assert_eq!(parsed.is_signature_capable(), value == "sig");
        if !matches!(value, "sig" | "enc") {
            assert_eq!(parsed.key_use, Some(KeyUse::Other(value.into())));
        }
    }
    for value in [Value::Null, json!(true), json!(1), json!([]), json!({})] {
        let mut input = key();
        input["use"] = value;
        assert_eq!(
            Jwk::from_value(input),
            Err(JwkError::FieldNotString { field: "use" })
        );
    }
    let escaped = serde_json::from_str(
        r#"{"kty":"RSA","n":"AQAB","e":"AQAB","\u0075se":"\u0073ig","key_\u006fps":["ver\u0069fy"]}"#,
    )?;
    assert!(Jwk::from_value(escaped)?.is_signature_capable());
    Ok(())
}

#[test]
fn jwk_usage_operations_are_exact_and_verification_specific() -> TestResult {
    let cases: &[(&[&str], bool)] = &[
        (&[], false),
        (&["sign"], false),
        (&["verify"], true),
        (&["sign", "verify"], true),
        (&["verify", "sign"], true),
        (&["VERIFY"], false),
        (&[" verify"], false),
        (&["verify "], false),
        (&["unknown"], false),
        (&["verify", "unknown"], false),
        (&["verify", "VERIFY"], false),
        (&["verify", "encrypt"], false),
        (&["encrypt"], false),
        (&["deriveBits"], false),
    ];
    for (ops, eligible) in cases {
        let mut input = key();
        input["key_ops"] = json!(ops);
        let parsed = Jwk::from_value(input)?;
        assert_eq!(parsed.key_ops, Some(operations(ops)));
        assert_eq!(parsed.is_signature_capable(), *eligible, "{ops:?}");
    }
    Ok(())
}

#[test]
fn jwk_usage_parser_rejects_duplicate_invalid_and_contradictory_metadata() -> TestResult {
    for value in [
        Value::Null,
        json!("verify"),
        json!(true),
        json!(1),
        json!({}),
        json!([null]),
        json!(["verify", 1]),
    ] {
        let mut input = key();
        input["key_ops"] = value;
        assert_eq!(
            Jwk::from_value(input),
            Err(JwkError::FieldNotStringArray { field: "key_ops" })
        );
    }
    for op in ["verify", "sign", "unknown", "VERIFY"] {
        let mut input = key();
        input["key_ops"] = json!([op, op]);
        assert_eq!(
            Jwk::from_value(input),
            Err(JwkError::DuplicateKeyOperation(op.into()))
        );
    }
    for (usage, ops) in [
        ("sig", vec!["encrypt"]),
        ("sig", vec!["decrypt"]),
        ("sig", vec!["wrapKey"]),
        ("sig", vec!["unwrapKey"]),
        ("sig", vec!["deriveKey"]),
        ("sig", vec!["deriveBits"]),
        ("enc", vec!["sign"]),
        ("enc", vec!["verify"]),
    ] {
        let mut input = key();
        input["use"] = json!(usage);
        input["key_ops"] = json!(ops);
        assert_eq!(Jwk::from_value(input), Err(JwkError::InconsistentKeyUsage));
    }
    let mut enc = key();
    enc["use"] = json!("enc");
    enc["key_ops"] = json!(["encrypt", "decrypt"]);
    assert!(!Jwk::from_value(enc)?.is_signature_capable());
    Ok(())
}

#[test]
fn jwk_usage_mutated_public_fields_cannot_bypass_eligibility() -> TestResult {
    let mut parsed = Jwk::from_value(key())?;
    for usage in [
        Some(KeyUse::Other("sig".into())),
        Some(KeyUse::Other("SIG".into())),
        Some(KeyUse::Encryption),
    ] {
        parsed.key_use = usage;
        assert!(!parsed.is_signature_capable());
    }
    parsed.key_use = Some(KeyUse::Signature);
    for ops in [
        vec!["verify", "verify"],
        vec!["verify", "encrypt"],
        vec!["verify", "unknown"],
        vec!["sign"],
        vec!["VERIFY"],
        vec![],
    ] {
        parsed.key_ops = Some(operations(&ops));
        assert!(!parsed.is_signature_capable(), "{ops:?}");
        assert!(!verification_usage_allowed(
            Some("sig"),
            parsed.key_ops.as_deref()
        ));
    }
    parsed.key_ops = Some(operations(&["verify"]));
    assert!(parsed.is_signature_capable());
    parsed.key_ops = None;
    assert!(parsed.is_signature_capable());
    Ok(())
}
