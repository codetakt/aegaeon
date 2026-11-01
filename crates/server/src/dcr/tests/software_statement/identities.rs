use super::*;
use crate::management::types::PolicyDocument;
use serde_json::json;

const ISSUER: &str = "https://issuer.example/software";
const AUDIENCE: &str = "https://registration.example/register";

fn config(issuer: Option<&str>, audience: Option<&str>) -> Result<DcrValidationConfig, String> {
    DcrValidationConfig::try_from_policy(
        &PolicyDocument {
            ssa_jwt_pem: Some(TEST_RSA_PUBLIC_KEY_PEM.into()),
            ssa_expected_iss: issuer.map(str::to_owned),
            ssa_expected_aud: audience.map(str::to_owned),
            ..Default::default()
        },
        false,
        false,
        false,
        false,
        8192,
    )
    .map_err(|e| e.to_string())
}

fn check_raw(raw: &str, config: &DcrValidationConfig, allowed: bool) -> DcrTestResult {
    let statement = build_raw_rs256_jwt(raw)?;
    let (input, signature) = statement.rsplit_once('.').ok_or("compact JWT")?;
    let key = jsonwebtoken::DecodingKey::from_rsa_pem(TEST_RSA_PUBLIC_KEY_PEM.as_bytes())
        .map_err(|e| e.to_string())?;
    assert!(
        crypto::verify(signature, input.as_bytes(), &key, Algorithm::RS256)
            .map_err(|e| e.to_string())?,
        "fixture must have a valid signature"
    );
    let original = statement.clone();
    let result =
        verify_software_statement_profile_v1_with_config(&statement, config.software_statement());
    assert_eq!(
        result.is_ok(),
        allowed,
        "claim admission result: {result:?}"
    );
    if let Ok(profile) = result {
        let submitted: Value = serde_json::from_str(raw).map_err(|e| e.to_string())?;
        assert_eq!(profile.claims.iss.as_deref(), submitted["iss"].as_str());
        assert_eq!(
            profile.claims.aud,
            submitted.get("aud").filter(|v| !v.is_null()).cloned()
        );
    } else {
        assert!(matches!(
            result,
            Err(SoftwareStatementVerificationError::Invalid(_))
        ));
    }
    assert_eq!(statement, original);
    Ok(())
}

#[test]
fn software_statement_issuer_is_required_without_an_issuer_pin() -> DcrTestResult {
    let _guard = env_lock()?;
    let _raw = raw_json_env_lock()?;
    for expected in [None, Some(ISSUER)] {
        let cfg = config(expected, None)?;
        for issuer in [
            None,
            Some(Value::Null),
            Some(json!("")),
            Some(json!(" \t\n\u{2003}")),
            Some(json!(false)),
            Some(json!(7)),
            Some(json!([])),
            Some(json!({})),
            Some(json!(ISSUER)),
            Some(json!("https://ISSUER.example/software")),
            Some(json!("https://issuer.example/software/")),
            Some(json!(" https://issuer.example/software ")),
        ] {
            let mut claims = json!({"exp":4102444800_u64});
            if let Some(value) = issuer {
                claims["iss"] = value;
            }
            let allowed = claims["iss"].as_str().is_some_and(|value| {
                !value.chars().all(char::is_whitespace) && expected.is_none_or(|pin| pin == value)
            });
            check_raw(&claims.to_string(), &cfg, allowed)?;
        }
    }
    Ok(())
}

#[test]
fn software_statement_audience_uses_the_same_configured_recipient_at_both_stages() -> DcrTestResult
{
    let _guard = env_lock()?;
    let _raw = raw_json_env_lock()?;
    for expected in [None, Some(AUDIENCE)] {
        let cfg = config(None, expected)?;
        for (audience, matching) in [
            (None, false),
            (Some(Value::Null), false),
            (Some(json!(AUDIENCE)), true),
            (Some(json!(["https://other.example", AUDIENCE])), true),
            (Some(json!([AUDIENCE, AUDIENCE, "extension"])), true),
            (Some(json!("https://REGISTRATION.example/register")), false),
            (Some(json!("https://registration.example/register/")), false),
            (
                Some(json!(" https://registration.example/register ")),
                false,
            ),
            (Some(json!("")), false),
            (Some(json!([])), false),
            (Some(json!([""])), false),
            (Some(json!({})), false),
            (Some(json!(false)), false),
            (Some(json!(7)), false),
            (Some(json!([AUDIENCE, null])), false),
            (Some(json!([AUDIENCE, false])), false),
        ] {
            let mut claims = json!({"iss":ISSUER,"exp":4102444800_u64});
            let absent = audience.as_ref().is_none_or(Value::is_null);
            if let Some(value) = audience {
                claims["aud"] = value;
            }
            check_raw(
                &claims.to_string(),
                &cfg,
                if expected.is_some() { matching } else { absent },
            )?;
        }
    }
    Ok(())
}

#[test]
fn software_statement_policy_normalization_does_not_normalize_signed_claims() -> DcrTestResult {
    let _guard = env_lock()?;
    let _raw = raw_json_env_lock()?;
    let mut policy = PolicyDocument {
        ssa_jwt_pem: Some(TEST_RSA_PUBLIC_KEY_PEM.into()),
        ssa_expected_iss: Some(format!(" {ISSUER} ")),
        ssa_expected_aud: Some(format!(" {AUDIENCE} ")),
        ..Default::default()
    };
    let cfg = DcrValidationConfig::try_from_policy(&policy, false, false, false, false, 8192)
        .map_err(|e| e.to_string())?;
    policy.ssa_expected_iss = Some("https://changed.example".into());
    policy.ssa_expected_aud = Some("https://changed.example".into());
    check_raw(
        &json!({"iss":ISSUER,"aud":AUDIENCE,"exp":4102444800_u64}).to_string(),
        &cfg,
        true,
    )?;
    for (issuer, audience) in [
        (format!(" {ISSUER} "), AUDIENCE.to_string()),
        (ISSUER.to_string(), format!(" {AUDIENCE} ")),
    ] {
        check_raw(
            &json!({"iss":issuer,"aud":audience,"exp":4102444800_u64}).to_string(),
            &cfg,
            false,
        )?;
    }
    let changed = DcrValidationConfig::try_from_policy(&policy, false, false, false, false, 8192)
        .map_err(|e| e.to_string())?;
    check_raw(
        &json!({"iss":ISSUER,"aud":AUDIENCE,"exp":4102444800_u64}).to_string(),
        &changed,
        false,
    )?;
    Ok(())
}

#[test]
fn software_statement_identity_fix_preserves_raw_signature_header_and_time_refusals(
) -> DcrTestResult {
    let _guard = env_lock()?;
    let _raw = raw_json_env_lock()?;
    let cfg = config(Some(ISSUER), Some(AUDIENCE))?;
    for raw in [
        format!(r#"{{"iss":"{ISSUER}","iss":"{ISSUER}","aud":"{AUDIENCE}","exp":4102444800}}"#),
        format!(r#"{{"iss":"{ISSUER}","aud":"{AUDIENCE}","aud":"{AUDIENCE}","exp":4102444800}}"#),
        json!({"iss":ISSUER,"aud":AUDIENCE,"exp":1}).to_string(),
        json!({"iss":ISSUER,"aud":AUDIENCE,"exp":4102444800_u64,"nbf":4102444700_u64}).to_string(),
        json!({"iss":ISSUER,"aud":AUDIENCE}).to_string(),
    ] {
        check_raw(&raw, &cfg, false)?;
    }
    let statement = build_raw_rs256_jwt(
        &json!({"iss":ISSUER,"aud":AUDIENCE,"exp":4102444800_u64}).to_string(),
    )?;
    let (input, signature) = statement.rsplit_once('.').ok_or("compact JWT")?;
    let mut bytes = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|e| e.to_string())?;
    bytes[0] ^= 1;
    let tampered = format!("{input}.{}", URL_SAFE_NO_PAD.encode(bytes));
    assert!(matches!(
        verify_software_statement_profile_v1_with_config(&tampered, cfg.software_statement()),
        Err(SoftwareStatementVerificationError::Invalid(_))
    ));
    let key = EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY_PEM.as_bytes())
        .map_err(|e| e.to_string())?;
    let wrong_alg = jsonwebtoken::encode(
        &Header::new(Algorithm::RS384),
        &json!({"iss":ISSUER,"aud":AUDIENCE,"exp":4102444800_u64}),
        &key,
    )
    .map_err(|e| e.to_string())?;
    assert!(matches!(
        verify_software_statement_profile_v1_with_config(&wrong_alg, cfg.software_statement()),
        Err(SoftwareStatementVerificationError::Invalid(_))
    ));
    let limited = DcrValidationConfig::try_from_policy(
        &PolicyDocument {
            ssa_jwt_pem: Some(TEST_RSA_PUBLIC_KEY_PEM.into()),
            ..Default::default()
        },
        false,
        false,
        false,
        false,
        1,
    )
    .map_err(|e| e.to_string())?;
    assert!(matches!(
        verify_software_statement_profile_v1_with_config(&statement, limited.software_statement()),
        Err(SoftwareStatementVerificationError::Invalid(_))
    ));
    Ok(())
}

#[test]
fn software_statement_wrong_trusted_key_refuses_an_otherwise_valid_assertion() -> DcrTestResult {
    let _guard = env_lock()?;
    let _raw = raw_json_env_lock()?;
    let raw = json!({"iss":ISSUER,"aud":AUDIENCE,"exp":4102444800_u64}).to_string();
    check_raw(&raw, &config(Some(ISSUER), Some(AUDIENCE))?, true)?;
    // Preserve valid SPKI DER while changing the RSA public exponent from
    // 65537 to 65539, producing a different configured verification key.
    let encoded = TEST_RSA_PUBLIC_KEY_PEM
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();
    let mut der = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| e.to_string())?;
    assert!(der.ends_with(&[2, 3, 1, 0, 1]));
    *der.last_mut().ok_or("public key DER")? = 3;
    let public = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        base64::engine::general_purpose::STANDARD.encode(der)
    );
    let cfg = DcrValidationConfig::try_from_policy(
        &PolicyDocument {
            ssa_jwt_pem: Some(public),
            ssa_expected_aud: Some(AUDIENCE.into()),
            ..Default::default()
        },
        false,
        false,
        false,
        false,
        8192,
    )
    .map_err(|e| e.to_string())?;
    check_raw(&raw, &cfg, false)?;
    Ok(())
}
