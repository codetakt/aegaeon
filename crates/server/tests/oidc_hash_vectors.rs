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
fn oidc_hash_vectors_pss_match_the_sha_family() -> TestResult {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use sha2::{Digest, Sha256, Sha384, Sha512};
    let input = "sample-access-token";
    for (alg, expected) in [
        (
            "PS256",
            URL_SAFE_NO_PAD.encode(&Sha256::digest(input)[..16]),
        ),
        (
            "PS384",
            URL_SAFE_NO_PAD.encode(&Sha384::digest(input)[..24]),
        ),
        (
            "PS512",
            URL_SAFE_NO_PAD.encode(&Sha512::digest(input)[..32]),
        ),
    ] {
        let token = build_builder()?
            .access_token_hash(input, alg)
            .map_err(|err| format!("hash computation: {err}"))?
            .build();
        assert_eq!(token.claims.at_hash.as_deref(), Some(expected.as_str()));
    }
    Ok(())
}
