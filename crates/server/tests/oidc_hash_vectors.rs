use aegaeon_server::oidc::IdTokenBuilder;

type TestResult = Result<(), String>;

fn build_builder() -> Result<IdTokenBuilder, String> {
    IdTokenBuilder::try_new(
        "https://issuer.example".to_string(),
        "subject".to_string(),
        "client".to_string(),
    )
    .map_err(|err| err.to_string())
}

#[test]
fn oidc_hash_vector_rs256() -> TestResult {
    let token = build_builder()?
        .access_token_hash("sample-access-token", "RS256")
        .map_err(|err| format!("hash computation: {err}"))?
        .build();

    assert_eq!(
        token.claims.at_hash.as_deref(),
        Some("EN9PvSfRnJ9qwbHAFRGqMw"),
    );
    Ok(())
}

#[test]
fn oidc_hash_vector_rs512() -> TestResult {
    let token = build_builder()?
        .access_token_hash("sample-access-token", "RS512")
        .map_err(|err| format!("hash computation: {err}"))?
        .build();

    assert_eq!(
        token.claims.at_hash.as_deref(),
        Some("kaV9BW4X8QKnv2uo3eN9Uh27bcmgOg2GoEPwQX9QGYI"),
    );
    Ok(())
}

#[test]
fn oidc_hash_ps256_remains_rejected() -> TestResult {
    let err = match build_builder()?.access_token_hash("sample-access-token", "PS256") {
        Ok(_) => return Err("PS256 should remain disabled".to_string()),
        Err(err) => err,
    };

    assert!(err
        .to_string()
        .contains("temporarily disabled due to security vulnerability"));
    Ok(())
}
