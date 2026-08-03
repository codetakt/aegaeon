use super::*;

#[test]
fn oidc_issuer_validation_accepts_https_origins_and_paths() {
    for issuer in [
        "https://issuer.example",
        "https://issuer.example/",
        "https://issuer.example/tenant/a",
    ] {
        assert!(
            validate_oidc_issuer(issuer).is_ok(),
            "valid issuer should be accepted: {issuer}"
        );
    }
}

#[test]
fn oidc_issuer_validation_rejects_non_issuer_urls() {
    for issuer in [
        "not-a-url",
        "http://issuer.example",
        "https://",
        "https://user@issuer.example",
        "https://user:password@issuer.example",
        "https://issuer.example?x=1",
        "https://issuer.example#fragment",
    ] {
        assert!(
            validate_oidc_issuer(issuer).is_err(),
            "invalid issuer must be rejected: {issuer}"
        );
    }
}
