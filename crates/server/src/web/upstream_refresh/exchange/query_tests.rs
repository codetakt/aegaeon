use super::*;
use crate::web::upstream_endpoint_query::http_fixture::EndpointFixture;
use crate::web::upstream_metadata::build_upstream_http_client;

#[tokio::test]
async fn upstream_refresh_preserves_raw_endpoint_query_and_required_body_fields(
) -> Result<(), String> {
    let mut fixture =
        EndpointFixture::start(r#"{"access_token":"access","token_type":"Bearer"}"#.into()).await?;
    let client = build_upstream_http_client(&[])?;
    let link = super::basic_auth_tests::fixture("client", "secret", "client_secret_post")
        .map_err(|error| error.to_string())?;
    let mut discovery = crate::web::upstream_tests::base_discovery(&link.upstream_issuer)?;
    discovery.token_endpoint = format!("{}/token?route=%2F&route=second&blank=", fixture.base);
    let form = build_refresh_form(&link, &link.upstream_auth_method);
    let request = build_refresh_token_request(
        &client,
        &discovery,
        &link,
        &link.upstream_auth_method,
        &form,
    )?;
    let response = send_refresh_token_request(request, &link, "https://as.example")
        .await
        .map_err(|e| e.status().to_string())?;
    let body = read_refresh_token_response_body(response, "https://as.example")
        .await
        .map_err(|e| e.status().to_string())?;
    parse_validated_refresh_response(&body, "https://as.example")
        .map_err(|e| e.status().to_string())?;
    let (target, body) = fixture.received().await?;
    assert_eq!(target, "/token?route=%2F&route=second&blank=");
    let form: std::collections::HashMap<_, _> = url::form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect();
    assert_eq!(form.len(), 4);
    for (name, value) in [
        ("grant_type", "refresh_token"),
        ("refresh_token", "refresh-token"),
        ("client_id", "client"),
        ("client_secret", "secret"),
    ] {
        assert_eq!(form.get(name).map(String::as_str), Some(value));
    }
    discovery.token_endpoint = format!("{}/token?refresh%5Ftoken=other", fixture.base);
    assert!(build_refresh_token_request(
        &client,
        &discovery,
        &link,
        &link.upstream_auth_method,
        &build_refresh_form(&link, &link.upstream_auth_method)
    )
    .is_err());
    fixture.assert_no_request();
    Ok(())
}
