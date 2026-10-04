use super::*;
use axum::body::to_bytes;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

async fn html(response: Response) -> String {
    String::from_utf8(
        to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}

fn attribute<'a>(body: &'a str, name: &str) -> &'a str {
    body.split(&format!("{name}=\""))
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
}

fn destination(body: &str) -> String {
    attribute(body, "href")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

fn assert_guards(response: &Response) {
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::PRAGMA], "no-cache");
    assert_eq!(response.headers()[header::REFERRER_POLICY], "no-referrer");
    assert_eq!(response.headers()[header::X_FRAME_OPTIONS], "DENY");
    assert_eq!(
        response.headers()[header::X_CONTENT_TYPE_OPTIONS],
        "nosniff"
    );
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/html; charset=utf-8"
    );
    assert!(!response.headers().contains_key(header::LOCATION));
}

fn redirect(target: &str) -> Response {
    let mut response = StatusCode::FOUND.into_response();
    response
        .headers_mut()
        .insert(header::LOCATION, HeaderValue::from_str(target).unwrap());
    response
}

#[tokio::test]
async fn local_continuation_escapes_target_and_keeps_script_static() {
    let target = "/authorize?state=\"'><script>alert('target')</script>&a=%2f%2F&b=+";
    let response = local_response(target).unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_guards(&response);
    let body = html(response).await;
    assert_eq!(destination(&body), target);
    assert!(!body.contains(target));
    assert!(body.contains("&quot;&#39;&gt;&lt;script&gt;"));
    assert_eq!(body.matches("<script").count(), 1);
    assert!(
        body.contains(">Continue</a>"),
        "fallback must be an ordinary anchor"
    );
    assert!(!body.contains("<form"));
    let script = body
        .split(">window.location.replace")
        .nth(1)
        .unwrap()
        .split("</script>")
        .next()
        .unwrap();
    assert_eq!(
        script,
        "(document.getElementById('aegaeon-continuation').getAttribute('href'));"
    );
    assert!(!script.contains("target"));
}

#[tokio::test]
async fn each_continuation_has_a_fresh_16_byte_nonce_and_exact_csp() {
    let mut nonces = Vec::new();
    for _ in 0..2 {
        let response = local_response("/authorize?state=unchanged").unwrap();
        let csp = response.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .to_string();
        let body = html(response).await;
        let nonce = attribute(&body, "nonce");
        assert_eq!(URL_SAFE_NO_PAD.decode(nonce).unwrap().len(), 16);
        assert_eq!(csp, format!("default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; img-src 'none'; script-src 'nonce-{nonce}'"));
        assert!(!csp.contains("unsafe-inline"));
        assert!(!csp.contains('*'));
        nonces.push(nonce.to_string());
    }
    assert_ne!(nonces[0], nonces[1]);
}

#[test]
fn local_continuation_revalidates_exact_relative_return_to() {
    for target in [
        "",
        " ",
        "https://client.example/callback",
        "javascript:alert(1)",
        "//client.example/callback",
        "/\\client.example/callback",
        "/a\tb",
        "/a\nb",
        "/a\0b",
        " /authorize",
        "/authorize ",
    ] {
        let response = local_response(target).unwrap_err();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{target:?}");
        assert_guards(&response);
        assert!(response.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .contains("script-src 'none'"));
    }
}

#[tokio::test]
async fn trusted_authorization_query_result_preserves_exact_bytes_and_headers() {
    let target = "https://client.example/callback?existing=%2f&code=opaque&state=A%2BB%20C&iss=https%3A%2F%2Fissuer.example";
    let mut response = redirect(target);
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_static("first=one; Secure; HttpOnly"),
    );
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_static("second=two; Secure; HttpOnly"),
    );
    response
        .headers_mut()
        .insert("x-request-id", HeaderValue::from_static("request-identity"));
    response
        .headers_mut()
        .insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
    response
        .headers_mut()
        .insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    response.extensions_mut().insert(123_u64);
    let response = authorization_response(response);
    assert_eq!(response.status(), StatusCode::OK);
    assert_guards(&response);
    assert_eq!(
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .count(),
        2
    );
    assert_eq!(response.headers()["x-request-id"], "request-identity");
    assert_eq!(response.extensions().get::<u64>(), Some(&123));
    assert!(!response.headers().contains_key(header::CONTENT_LENGTH));
    assert!(!response.headers().contains_key(header::CONTENT_ENCODING));
    assert_eq!(destination(&html(response).await), target);
}

#[tokio::test]
async fn trusted_denial_keeps_error_state_and_issuer_query() {
    let target = "https://client.example/callback?error=access_denied&error_description=Denied%20once&state=state%2Bvalue&iss=https%3A%2F%2Fissuer.example";
    let response = authorization_response(redirect(target));
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(destination(&html(response).await), target);
}

#[tokio::test]
async fn existing_form_post_response_remains_exact() {
    let response = crate::form_post::authorization_success(
        "https://client.example/callback",
        "code",
        Some("state"),
        "https://issuer.example",
    )
    .unwrap();
    let (parts, body) = response.into_parts();
    let bytes = to_bytes(body, 1024 * 1024).await.unwrap();
    let headers = parts.headers.clone();
    let response = authorization_response(Response::from_parts(parts, Body::from(bytes.clone())));
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers(), &headers);
    assert_eq!(
        to_bytes(response.into_body(), 1024 * 1024).await.unwrap(),
        bytes
    );
}

#[tokio::test]
async fn nonredirect_json_success_and_failure_remain_exact() {
    for status in [
        StatusCode::OK,
        StatusCode::BAD_REQUEST,
        StatusCode::SERVICE_UNAVAILABLE,
    ] {
        let mut response = (status, "original response").into_response();
        response
            .headers_mut()
            .insert("x-request-id", HeaderValue::from_static("unchanged"));
        let headers = response.headers().clone();
        let response = authorization_response(response);
        assert_eq!(response.status(), status);
        assert_eq!(response.headers(), &headers);
        assert_eq!(html(response).await, "original response");
    }
}

#[test]
fn malformed_or_ambiguous_authorization_redirects_fail_closed() {
    for target in [
        "",
        "/authorize",
        "//client.example/callback",
        "javascript:alert(1)",
        "https://user:password@client.example/callback",
        "https://client.example/callback#fragment",
        "https://client.example/\\callback",
        "https://client.example/a\tb",
        " https://client.example/callback",
        "https://client.example/callback ",
        "http://client.example/callback",
    ] {
        let response = authorization_response(redirect(target));
        assert_eq!(
            response.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "{target:?}"
        );
        assert_guards(&response);
    }
    let missing = authorization_response(StatusCode::FOUND.into_response());
    assert_eq!(missing.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_guards(&missing);
    let mut duplicate = redirect("https://client.example/callback");
    duplicate.headers_mut().append(
        header::LOCATION,
        HeaderValue::from_static("https://other.example/callback"),
    );
    let duplicate = authorization_response(duplicate);
    assert_eq!(duplicate.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_guards(&duplicate);
    let mut non_ascii = StatusCode::FOUND.into_response();
    non_ascii.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_bytes(b"https://client.example/\x80").unwrap(),
    );
    assert_eq!(
        authorization_response(non_ascii).status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    for status in [
        StatusCode::OK,
        StatusCode::TEMPORARY_REDIRECT,
        StatusCode::PERMANENT_REDIRECT,
    ] {
        let mut response = redirect("https://client.example/callback");
        *response.status_mut() = status;
        assert_eq!(
            authorization_response(response).status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}

#[tokio::test]
async fn registered_loopback_redirect_remains_supported() {
    let target = "http://127.0.0.1:54321/callback?code=opaque&state=original";
    let response = authorization_response(redirect(target));
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(destination(&html(response).await), target);
}

#[test]
fn authentication_form_csp_still_disallows_scripts() {
    let response =
        crate::web::local_auth_support::local_auth_response(StatusCode::OK, String::new());
    let csp = response.headers()[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap();
    assert!(csp.contains("form-action 'self'"));
    assert!(csp.contains("script-src 'none'"));
    assert!(!csp.contains("nonce-"));
}
