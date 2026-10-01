use super::*;
use crate::web::upstream_endpoint_query::http_fixture::EndpointFixture;

#[tokio::test]
async fn upstream_code_exchange_preserves_raw_endpoint_query_and_body_fields() -> Result<(), String>
{
    let mut fixture =
        EndpointFixture::start(r#"{"access_token":"access","token_type":"Bearer"}"#.into()).await?;
    let client = build_upstream_http_client(&[])?;
    let mut request =
        crate::web::upstream_tests::make_auth_request("state", std::time::Duration::from_secs(60));
    request.token_endpoint = format!(
        "{}/token?vendor=%2f%2F&vendor=two+words&blank=",
        fixture.base
    );
    request.client_auth_method = "client_secret_post".into();
    request.client_secret = Some("secret".into());
    request.code_verifier = Some("verifier".into());
    exchange_upstream_callback_token(&client, &request, "code", "https://as.example", &[])
        .await
        .map_err(|e| e.status().to_string())?;
    let (target, body) = fixture.received().await?;
    assert_eq!(target, "/token?vendor=%2f%2F&vendor=two+words&blank=");
    let form: std::collections::HashMap<_, _> = url::form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect();
    assert_eq!(form.len(), 6);
    for (name, value) in [
        ("grant_type", "authorization_code"),
        ("code", "code"),
        ("redirect_uri", request.redirect_uri.as_str()),
        ("client_id", "client"),
        ("client_secret", "secret"),
        ("code_verifier", "verifier"),
    ] {
        assert_eq!(form.get(name).map(String::as_str), Some(value));
    }
    request.token_endpoint = format!("{}/token?%63ode=other", fixture.base);
    assert!(
        exchange_upstream_callback_token(&client, &request, "code", "https://as.example", &[])
            .await
            .is_err()
    );
    fixture.assert_no_request();
    Ok(())
}
