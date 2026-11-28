use super::*;
use crate::web::upstream_metadata::test_support::tls_relay::TlsRelay;
use axum::{
    http::{header, HeaderMap, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use std::sync::atomic::Ordering;

// Accept the stable product identifier on every attempt, including the request
// that receives the nonce challenge. Do not echo credentials or proof contents.
async fn receive(uri: Uri, headers: HeaderMap) -> Response {
    let mut agents = headers.get_all(header::USER_AGENT).iter();
    if agents.next().and_then(|h| h.to_str().ok()) != Some("Aegaeon-Hosted-Invitations")
        || agents.next().is_some()
    {
        return (StatusCode::FORBIDDEN, Json(json!({"error":"user_agent"}))).into_response();
    }
    let content = headers
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok());
    let is_form = content == Some("application/x-www-form-urlencoded");
    let is_json = content == Some("application/json");
    let dpop = headers.get("DPoP").and_then(|h| h.to_str().ok());
    if uri.path() == "/revoke" && is_form && dpop.is_none() {
        return Json(json!({})).into_response();
    }
    if !((uri.path() == "/token" && is_form) || (uri.path() == "/preview" && is_json)) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let payload = dpop
        .and_then(|p| p.split('.').nth(1))
        .and_then(|p| URL_SAFE_NO_PAD.decode(p).ok())
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
    let Some(payload) = payload else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    match payload.get("nonce").and_then(Value::as_str) {
        None => (
            StatusCode::UNAUTHORIZED,
            [("DPoP-Nonce", "issuer-generated-nonce")],
            Json(json!({"error":"use_dpop_nonce"})),
        )
            .into_response(),
        Some("issuer-generated-nonce") => Json(json!({})).into_response(),
        Some(_) => StatusCode::UNAUTHORIZED.into_response(),
    }
}

#[tokio::test]
async fn issuer_receives_hosted_product_user_agent_on_forms_json_and_nonce_retries(
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let relay = TlsRelay::new(listener.local_addr()?, "example.com")?;
    let app = Router::new().fallback(post(receive));
    let backend = tokio::spawn(async move { axum::serve(listener, app).await });
    let domain = Uuid::new_v4();
    let auth = Authorization::begin(&relay.endpoint, domain, now()? + 300)?;
    let form = [("grant_type", "authorization_code")];
    for path in ["/token", "/preview", "/revoke"] {
        let url = format!("{}{path}", relay.endpoint);
        let (request, proof) = match path {
            "/token" => (
                transport::form(&url, "client", "secret", &form)?,
                Some((&auth.key, None)),
            ),
            "/preview" => (
                transport::json(&url, "access", &json!({}))?,
                Some((&auth.key, Some("access"))),
            ),
            _ => (
                transport::form(&url, "client", "secret", &[("token", "refresh")])?,
                None,
            ),
        };
        // Keep the production request. The fixture client trusts the local TLS
        // relay's certificate and routes the exact HTTPS authority to it.
        let request = reqwest::RequestBuilder::from_parts(relay.client.clone(), request.build()?);
        assert_eq!(transport::send(request, &url, proof).await?.status, 200);
    }
    assert_eq!(relay.requests.load(Ordering::SeqCst), 5);
    backend.abort();
    Ok(())
}
