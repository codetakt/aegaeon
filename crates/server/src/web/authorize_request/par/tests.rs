//! Adapter control independent of the preceding runtime client observation.
use super::*;

#[test]
fn pushed_client_identifier_adapter_preserves_exact_reserve_and_resume(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = ParStore::new_process_local_for_tests();
    store.register_client(crate::par::Client {
        client_id: "exact-client".into(),
        client_secret: None,
        token_endpoint_auth_method: "none".into(),
        redirect_uris: vec!["https://client.example.com/callback".into()],
        allowed_scopes: vec![],
    });
    let request = serde_json::from_value(json!({
        "client_id": "exact-client", "redirect_uri": "https://client.example.com/callback",
        "response_type": "code", "response_mode": "form_post", "state": "retained-state",
        "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        "code_challenge_method": "S256", "dpop_jkt": null
    }))?;
    let pushed = crate::par::process_par_request(&store, request).map_err(|e| e.error)?;
    for selector in [
        None,
        Some(""),
        Some(" exact-client"),
        Some("exact-client "),
        Some("other"),
    ] {
        assert!(authorize_request_from_par(
            &store,
            selector,
            &pushed.request_uri,
            None,
            None,
            "https://issuer.example.com"
        )
        .is_err());
    }
    let exact = authorize_request_from_par(
        &store,
        Some("exact-client"),
        &pushed.request_uri,
        None,
        None,
        "https://issuer.example.com",
    )
    .map_err(|_| "exact reserve")?;
    for selector in [" exact-client", "exact-client ", "other"] {
        assert!(authorize_request_from_par(
            &store,
            Some(selector),
            &pushed.request_uri,
            Some(&exact.continuation),
            None,
            "https://issuer.example.com"
        )
        .is_err());
    }
    let resumed = authorize_request_from_par(
        &store,
        Some("exact-client"),
        &pushed.request_uri,
        Some(&exact.continuation),
        None,
        "https://issuer.example.com",
    )
    .map_err(|_| "exact resume")?;
    assert_eq!(resumed.request.client_id, "exact-client");
    assert_eq!(resumed.request.state.as_deref(), Some("retained-state"));
    assert_eq!(resumed.response_mode.as_deref(), Some("form_post"));
    assert_eq!(resumed.continuation, exact.continuation);
    Ok(())
}

#[tokio::test]
async fn async_par_parser_rejects_outer_discriminators_before_reservation(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::web::authorize_request::{
        parse_authorize_request_with_runtime_blocking, RawAuthzQuery,
    };
    let store = std::sync::Arc::new(ParStore::new_process_local_for_tests());
    store.register_client(crate::par::Client {
        client_id: "exact-client".into(),
        client_secret: None,
        token_endpoint_auth_method: "none".into(),
        redirect_uris: vec!["https://client.example.com/callback".into()],
        allowed_scopes: vec![],
    });
    let request = serde_json::from_value(
        json!({"client_id":"exact-client","redirect_uri":"https://client.example.com/callback","response_type":"code","state":"retained-state","response_mode":"form_post","code_challenge":"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM","code_challenge_method":"S256","dpop_jkt":null}),
    )?;
    let pushed = crate::par::process_par_request(&store, request).map_err(|error| error.error)?;
    for invalid in [
        json!({"request":"outer-jwt"}),
        json!({"response_mode":"query"}),
        json!({"prompt":"login"}),
        json!({"resource":"https://resource.example"}),
        json!({"authorization_details":"[]"}),
    ] {
        let mut input = json!({"client_id":"exact-client","request_uri":pushed.request_uri});
        input
            .as_object_mut()
            .ok_or("input")?
            .extend(invalid.as_object().ok_or("input")?.clone());
        let raw: RawAuthzQuery = serde_json::from_value(input)?;
        assert!(parse_authorize_request_with_runtime_blocking(
            raw,
            store.clone(),
            "https://issuer.example.com".into(),
            vec![],
            None,
            false
        )
        .await
        .is_err());
        assert!(store
            .try_authorize_continuation(&pushed.request_uri)
            .map_err(|error| error.error)?
            .is_none());
    }
    let raw = serde_json::from_value(
        json!({"client_id":"exact-client","request_uri":pushed.request_uri}),
    )?;
    let parsed = parse_authorize_request_with_runtime_blocking(
        raw,
        store.clone(),
        "https://issuer.example.com".into(),
        vec![],
        None,
        true,
    )
    .await
    .map_err(|_| "reservation failed")?;
    assert_eq!(parsed.response_mode.as_deref(), Some("form_post"));
    let continuation = parsed.par_authorize_continuation.ok_or("continuation")?;
    let raw = serde_json::from_value(
        json!({"client_id":"exact-client","request_uri":pushed.request_uri,"aeg_par_continue":continuation}),
    )?;
    let resumed = parse_authorize_request_with_runtime_blocking(
        raw,
        store.clone(),
        "https://issuer.example.com".into(),
        vec![],
        None,
        true,
    )
    .await
    .map_err(|_| "resume failed")?;
    assert_eq!(resumed.request.state.as_deref(), Some("retained-state"));
    Ok(())
}
