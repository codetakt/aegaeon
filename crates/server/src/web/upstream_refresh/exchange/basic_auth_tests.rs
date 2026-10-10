use super::*;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::collections::HashMap;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn fixture(
    id: &str,
    secret: &str,
    method: &str,
) -> Result<UpstreamRefreshLink, Box<dyn std::error::Error>> {
    let token = crate::oidc::IdTokenBuilder::try_new(
        "https://upstream.example".into(),
        "subject".into(),
        id.into(),
    )
    .map_err(std::io::Error::other)?
    .build();
    let subject_hash =
        crate::upstream::upstream_subject_link_hash(&token.claims.iss, &token.claims.sub);
    let original_authentication = crate::web::upstream_refresh_token_envelope::UpstreamRefreshAuthenticationContext::from_validated_id_token(
        &token, id, &token.claims.iss, &subject_hash,
    ).map_err(|e| format!("{e:?}"))?;
    Ok(UpstreamRefreshLink {
        account_link_id: uuid::Uuid::nil(),
        link_env_id: uuid::Uuid::nil(),
        configuration_version_id: uuid::Uuid::nil(),
        upstream_issuer: "https://upstream.example".into(),
        upstream_sub_hash: subject_hash,
        original_authentication,
        upstream_refresh_token_generation: 1,
        upstream_refresh_token: "refresh-token".into(),
        upstream_connection_id: uuid::Uuid::nil(),
        upstream_connection_identifier: "upstream".into(),
        upstream_client_id: id.into(),
        upstream_auth_method: method.into(),
        upstream_client_secret: Some(secret.into()),
        upstream_client_secret_encrypted: None,
    })
}

fn discovery() -> OidcDiscovery {
    OidcDiscovery::new_with_runtime_config(
        "https://upstream.example",
        "https://upstream.example",
        &crate::metadata::MetadataRuntimeConfig::default(),
    )
}

#[test]
fn oauth_basic_refresh_builder_encodes_actual_authorization_header() -> TestResult {
    for (id, secret, expected) in [
        (
            "client: +%&=é",
            "secret: +%&=雪%2B",
            "client%3A+%2B%25%26%3D%C3%A9:secret%3A+%2B%25%26%3D%E9%9B%AA%252B",
        ),
        (
            "generated_ID-1",
            "secret_ID-2",
            "generated_ID-1:secret_ID-2",
        ),
    ] {
        let link = fixture(id, secret, "client_secret_basic")?;
        let form = build_refresh_form(&link, "client_secret_basic");
        let request = build_refresh_token_request(
            &Client::new(),
            &discovery(),
            &link,
            "client_secret_basic",
            &form,
        )
        .build()?;
        assert_eq!(request.url().as_str(), "https://upstream.example/token");
        assert_eq!(request.method(), reqwest::Method::POST);
        assert_eq!(
            request
                .headers()
                .get_all(reqwest::header::AUTHORIZATION)
                .iter()
                .count(),
            1
        );
        let auth = request.headers()[reqwest::header::AUTHORIZATION].to_str()?;
        assert_eq!(
            STANDARD.decode(auth.strip_prefix("Basic ").ok_or("Basic missing")?)?,
            expected.as_bytes()
        );
        let form: HashMap<String, String> = url::form_urlencoded::parse(
            request
                .body()
                .and_then(reqwest::Body::as_bytes)
                .ok_or("body missing")?,
        )
        .into_owned()
        .collect();
        assert_eq!(form["grant_type"], "refresh_token");
        assert_eq!(form["refresh_token"], "refresh-token");
        assert!(!form.contains_key("client_id"));
        assert!(!form.contains_key("client_secret"));
    }
    Ok(())
}

#[test]
fn oauth_basic_refresh_builder_preserves_other_methods() -> TestResult {
    for method in ["client_secret_post", "none"] {
        let link = fixture("client+id", "secret%2B", method)?;
        let request = build_refresh_token_request(
            &Client::new(),
            &discovery(),
            &link,
            method,
            &build_refresh_form(&link, method),
        )
        .build()?;
        assert!(!request
            .headers()
            .contains_key(reqwest::header::AUTHORIZATION));
        let form: HashMap<String, String> = url::form_urlencoded::parse(
            request
                .body()
                .and_then(reqwest::Body::as_bytes)
                .ok_or("body missing")?,
        )
        .into_owned()
        .collect();
        assert_eq!(form["client_id"], "client+id");
        assert_eq!(
            form.get("client_secret").map(String::as_str),
            (method == "client_secret_post").then_some("secret%2B")
        );
    }
    Ok(())
}
