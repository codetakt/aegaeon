use super::*;
use crate::util;

fn plain_code_query() -> Result<RawAuthzQuery, String> {
    let query = format!(
        "response_type=code&client_id=test-client&redirect_uri={}&scope=read&state=abc&code_challenge={}&code_challenge_method=S256",
        util::url_encode_component("https://example.com/callback"),
        util::url_encode_component("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
    );
    serde_urlencoded::from_str(&query).map_err(|err| err.to_string())
}

fn stored_par_request() -> StoredParRequest {
    let request = ParRequest {
        client_id: "test-client".to_string(),
        redirect_uri: "https://example.com/callback".to_string(),
        response_type: "code".to_string(),
        iss: None,
        resource: None,
        state: Some("abc".to_string()),
        code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string()),
        code_challenge_method: Some("S256".to_string()),
        scope: Some("read".to_string()),
        nonce: None,
        acr_values: None,
        max_age: None,
        authorization_details: None,
        client_secret: None,
        client_authenticated: true,
        request_object: None,
        request_object_claims: None,
    };
    StoredParRequest {
        client_id: request.client_id.clone(),
        request,
        expires_at: SystemTime::now() + Duration::from_secs(60),
        authorize_continuation: None,
    }
}

#[test]
fn authorize_query_parses_authorization_details() -> Result<(), String> {
    let details = json!([{"type": "payment", "actions": ["read"]}]).to_string();
    let query = format!(
            "response_type=code&client_id=test-client&redirect_uri={}&scope=read&state=abc&code_challenge={}&code_challenge_method=S256&authorization_details={}",
            util::url_encode_component("https://example.com/callback"),
            util::url_encode_component("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
            util::url_encode_component(&details)
        );
    let raw: RawAuthzQuery = serde_urlencoded::from_str(&query).map_err(|err| err.to_string())?;
    let par_store = ParStore::new_process_local_for_tests();
    let req = parse_authorize_request(
        raw,
        &par_store,
        "https://issuer.example",
        &["payment".to_string()],
    )
    .map_err(|_| "parse authorize request".to_string())?;
    let expected: Value = serde_json::from_str(&details).map_err(|err| err.to_string())?;
    assert_eq!(req.authorization_details, Some(expected));

    let unencoded_query = format!(
            "response_type=code&client_id=test-client&redirect_uri={}&scope=read&state=abc&code_challenge={}&code_challenge_method=S256&authorization_details={}",
            "https://example.com/callback", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", details
        );
    let raw_unencoded: RawAuthzQuery =
        serde_urlencoded::from_str(&unencoded_query).map_err(|err| err.to_string())?;
    assert_eq!(
        raw_unencoded.authorization_details,
        Some(details),
        "unencoded query still parses authorization_details"
    );
    Ok(())
}

#[test]
fn authorize_query_rejects_plain_request_when_par_is_required() -> Result<(), String> {
    let raw = plain_code_query()?;
    let err = parse_authorize_request_with_runtime(
        raw,
        &ParStore::new_process_local_for_tests(),
        "https://issuer.example",
        &[],
        None,
        true,
    )
    .err()
    .ok_or_else(|| "plain authorize request must be rejected when PAR is required".to_string())?;

    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[test]
fn authorize_query_rejects_request_object_when_par_is_required() -> Result<(), String> {
    let raw: RawAuthzQuery =
        serde_urlencoded::from_str("client_id=test-client&request=header.payload.signature")
            .map_err(|err| err.to_string())?;
    let err = parse_authorize_request_with_runtime(
        raw,
        &ParStore::new_process_local_for_tests(),
        "https://issuer.example",
        &[],
        None,
        true,
    )
    .err()
    .ok_or_else(|| "request object must be rejected when PAR is required".to_string())?;

    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[test]
fn authorize_query_accepts_request_uri_when_par_is_required() -> Result<(), String> {
    let par_store = ParStore::new_process_local_for_tests();
    par_store.register_client(ParClient {
        client_id: "test-client".to_string(),
        client_secret: None,
        token_endpoint_auth_method: "none".to_string(),
        redirect_uris: vec!["https://example.com/callback".to_string()],
        allowed_scopes: vec!["read".to_string()],
    });
    let request_uri = ParStore::generate_request_uri();
    par_store.insert_stored_request_for_test(&request_uri, stored_par_request())?;
    let query = format!(
        "client_id=test-client&request_uri={}",
        util::url_encode_component(&request_uri)
    );
    let raw: RawAuthzQuery = serde_urlencoded::from_str(&query).map_err(|err| err.to_string())?;

    let req = parse_authorize_request_with_runtime(
        raw,
        &par_store,
        "https://issuer.example",
        &[],
        None,
        true,
    )
    .map_err(|_| "PAR request_uri should be accepted when PAR is required".to_string())?;

    assert_eq!(req.client_id, "test-client");
    assert_eq!(req.request_uri.as_deref(), Some(request_uri.as_str()));
    Ok(())
}

#[test]
fn authorize_query_rejects_par_request_uri_iss_conflict() -> Result<(), String> {
    let par_store = ParStore::new_process_local_for_tests();
    let request_uri = ParStore::generate_request_uri();
    let mut stored = stored_par_request();
    stored.request.iss = Some("https://stored-issuer.example".to_string());
    par_store.insert_stored_request_for_test(&request_uri, stored)?;
    let query = format!(
        "client_id=test-client&iss={}&request_uri={}",
        util::url_encode_component("https://outer-issuer.example"),
        util::url_encode_component(&request_uri)
    );
    let raw: RawAuthzQuery = serde_urlencoded::from_str(&query).map_err(|err| err.to_string())?;

    let err = parse_authorize_request_with_runtime(
        raw,
        &par_store,
        "https://issuer.example",
        &[],
        None,
        true,
    )
    .err()
    .ok_or_else(|| "PAR request_uri iss conflict must fail closed".to_string())?;

    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    assert_response_no_store(&err);
    Ok(())
}

#[test]
fn authorize_query_parses_single_resource_parameter() -> Result<(), String> {
    let resource = "https://api.example.com";
    let query = format!(
            "response_type=code&client_id=test-client&redirect_uri={}&scope=read&state=abc&code_challenge={}&code_challenge_method=S256&resource={}",
            util::url_encode_component("https://example.com/callback"),
            util::url_encode_component("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
            util::url_encode_component(resource),
        );
    let raw: RawAuthzQuery = serde_urlencoded::from_str(&query).map_err(|err| err.to_string())?;
    let req = parse_authorize_request(
        raw,
        &ParStore::new_process_local_for_tests(),
        "https://issuer.example",
        &[],
    )
    .map_err(|_| "parse authorize request".to_string())?;

    assert_eq!(req.resource.as_deref(), Some(resource));
    Ok(())
}

#[test]
fn authorize_query_rejects_invalid_resource_parameter() -> Result<(), String> {
    let query = format!(
            "response_type=code&client_id=test-client&redirect_uri={}&scope=read&state=abc&code_challenge={}&code_challenge_method=S256&resource={}",
            util::url_encode_component("https://example.com/callback"),
            util::url_encode_component("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
            util::url_encode_component("/relative-resource"),
        );
    let raw: RawAuthzQuery = serde_urlencoded::from_str(&query).map_err(|err| err.to_string())?;
    let err = parse_authorize_request(
        raw,
        &ParStore::new_process_local_for_tests(),
        "https://issuer.example",
        &[],
    )
    .err()
    .ok_or_else(|| "invalid resource parameter should be rejected".to_string())?;

    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[test]
fn authorize_query_rejects_duplicate_singleton_fields() {
    for (field, value) in [
        ("client_id", "test-client"),
        ("response_type", "code"),
        ("response_mode", "query"),
        ("iss", "https%3A%2F%2Fissuer.example"),
        ("redirect_uri", "https%3A%2F%2Fclient.example%2Fcallback"),
        ("authorization_details", "%5B%5D"),
        ("scope", "openid"),
        ("state", "abc"),
        ("nonce", "nonce"),
        ("prompt", "login"),
        ("max_age", "60"),
        ("acr_values", "urn%3Amace%3Aincommon%3Aiap%3Asilver"),
        (
            "code_challenge",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        ),
        ("code_challenge_method", "S256"),
        ("request", "header.payload.signature"),
        ("request_uri", "urn%3Aexample%3Arequest"),
    ] {
        let query = format!("{field}={value}&{field}={value}");
        assert!(
            serde_urlencoded::from_str::<RawAuthzQuery>(&query).is_err(),
            "duplicate authorize query field must be rejected: {field}"
        );
    }
}

#[test]
fn authorize_query_rejects_multiple_resource_parameters() {
    let query = "resource=https%3A%2F%2Fapi-a.example&resource=https%3A%2F%2Fapi-b.example";
    assert!(
        serde_urlencoded::from_str::<RawAuthzQuery>(query).is_err(),
        "multiple authorize resource parameters are not supported and must fail closed"
    );
}
