#![forbid(unsafe_code)]
#![no_main]

use aegaeon_server::par::{authorize_with_par, process_par_request, Client, ParRequest, ParStore};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

fn mutate_request(request: &mut ParRequest, data: &[u8]) {
    if let Ok(text) = std::str::from_utf8(data) {
        if !text.is_empty() {
            let clipped: String = text.chars().take(64).collect();
            request.state = Some(clipped.clone());
            request.nonce = Some(clipped);

            let scope = text
                .split(|c: char| c.is_whitespace() || c == ',' || c == ';')
                .filter(|s| !s.is_empty())
                .take(4)
                .collect::<Vec<_>>()
                .join(" ");
            if !scope.is_empty() {
                request.scope = Some(scope);
            }
        }
    }

    if data.len() >= 32 {
        request.code_challenge = Some(URL_SAFE_NO_PAD.encode(&data[..32]));
        request.code_challenge_method = Some("S256".to_string());
    } else if !data.is_empty() {
        if let Ok(text) = std::str::from_utf8(data) {
            request.code_challenge = Some(text.to_string());
            request.code_challenge_method = Some("plain".to_string());
        }
    }

    if let Ok(pairs) = serde_urlencoded::from_bytes::<Vec<(String, String)>>(data) {
        for (key, value) in pairs.into_iter().take(8) {
            match key.as_str() {
                "client_id" => request.client_id = value,
                "redirect_uri" => request.redirect_uri = value,
                "response_type" => request.response_type = value,
                "resource" => request.resource = Some(value),
                "state" => request.state = Some(value),
                "scope" => request.scope = Some(value),
                "nonce" => request.nonce = Some(value),
                "acr_values" => request.acr_values = Some(value),
                "max_age" => request.max_age = value.parse::<u64>().ok(),
                "code_challenge" => request.code_challenge = Some(value),
                "code_challenge_method" => request.code_challenge_method = Some(value),
                "client_secret" => request.client_secret = Some(value),
                _ => {}
            }
        }
    }

    if let Ok(json_val) = serde_json::from_slice::<Value>(data) {
        if let Some(obj) = json_val.as_object() {
            if let Some(v) = obj.get("client_id").and_then(|v| v.as_str()) {
                request.client_id = v.to_string();
            }
            if let Some(v) = obj.get("redirect_uri").and_then(|v| v.as_str()) {
                request.redirect_uri = v.to_string();
            }
            if let Some(v) = obj.get("response_type").and_then(|v| v.as_str()) {
                request.response_type = v.to_string();
            }
            if let Some(v) = obj.get("resource").and_then(|v| v.as_str()) {
                request.resource = Some(v.to_string());
            }
            if let Some(v) = obj.get("state").and_then(|v| v.as_str()) {
                request.state = Some(v.to_string());
            }
            if let Some(v) = obj.get("scope").and_then(|v| v.as_str()) {
                request.scope = Some(v.to_string());
            }
            if let Some(v) = obj.get("nonce").and_then(|v| v.as_str()) {
                request.nonce = Some(v.to_string());
            }
            if let Some(v) = obj.get("acr_values").and_then(|v| v.as_str()) {
                request.acr_values = Some(v.to_string());
            }
            if let Some(v) = obj.get("max_age") {
                request.max_age = v
                    .as_u64()
                    .or_else(|| v.as_str().and_then(|text| text.parse::<u64>().ok()));
            }
            if let Some(v) = obj.get("code_challenge").and_then(|v| v.as_str()) {
                request.code_challenge = Some(v.to_string());
            }
            if let Some(v) = obj.get("code_challenge_method").and_then(|v| v.as_str()) {
                request.code_challenge_method = Some(v.to_string());
            }
            if let Some(v) = obj.get("client_secret").and_then(|v| v.as_str()) {
                request.client_secret = Some(v.to_string());
            }
            if let Some(v) = obj.get("authorization_details") {
                request.authorization_details = Some(v.clone());
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let store = ParStore::new_process_local_for_tests();
    store.register_client(Client {
        client_id: "client-a".to_string(),
        client_secret: Some("secret-a".to_string()),
        token_endpoint_auth_method: "client_secret_basic".to_string(),
        redirect_uris: vec!["https://example.com/cb".to_string()],
        allowed_scopes: vec![
            "openid".to_string(),
            "profile".to_string(),
            "read".to_string(),
            "write".to_string(),
        ],
    });
    store.register_client(Client {
        client_id: "client-b".to_string(),
        client_secret: Some("secret-b".to_string()),
        token_endpoint_auth_method: "client_secret_basic".to_string(),
        redirect_uris: vec!["https://example.org/callback".to_string()],
        allowed_scopes: vec!["accounts".to_string(), "transfer".to_string()],
    });

    let mut request = ParRequest {
        client_id: "client-a".to_string(),
        redirect_uri: "https://example.com/cb".to_string(),
        response_type: "code".to_string(),
        iss: None,
        resource: None,
        state: Some("state-123".to_string()),
        code_challenge: Some("challenge".to_string()),
        code_challenge_method: Some("plain".to_string()),
        scope: Some("openid profile".to_string()),
        nonce: Some("nonce-123".to_string()),
        acr_values: None,
        max_age: None,
        authorization_details: None,
        client_secret: Some("secret-a".to_string()),
        client_authenticated: false,
        request_object: None,
        request_object_claims: None,
    };

    mutate_request(&mut request, data);

    match request.client_id.as_str() {
        "client-b" => {
            request.client_secret = Some("secret-b".to_string());
            if request.redirect_uri != "https://example.org/callback" {
                request.redirect_uri = "https://example.org/callback".to_string();
            }
        }
        _ => {
            request.client_id = "client-a".to_string();
            request.client_secret = Some("secret-a".to_string());
            if request.redirect_uri != "https://example.com/cb" {
                request.redirect_uri = "https://example.com/cb".to_string();
            }
        }
    }

    match process_par_request(&store, request.clone()) {
        Ok(resp) => {
            let _ = authorize_with_par(&store, &resp.request_uri);
            let _ = authorize_with_par(&store, &resp.request_uri);
        }
        Err(_) => {
            store.cleanup_expired();
        }
    }

    let mut invalid = request.clone();
    invalid.client_secret = Some("wrong-secret".to_string());
    let _ = process_par_request(&store, invalid);

    if let Ok(text) = std::str::from_utf8(data) {
        let _ = authorize_with_par(&store, text);
    }
});
