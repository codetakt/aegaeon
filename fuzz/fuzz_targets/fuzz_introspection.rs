#![forbid(unsafe_code)]
#![no_main]

use base64::{engine::general_purpose::STANDARD, Engine as _};
use libfuzzer_sys::fuzz_target;
use serde_json::json;
use urlencoding::decode;

fuzz_target!(|data: &[u8]| {
    // Test introspection request/response parsing

    // Test as introspection request
    if let Ok(s) = std::str::from_utf8(data) {
        // Try to parse as form-encoded
        let pairs: Vec<&str> = s.split('&').collect();
        for pair in pairs {
            let parts: Vec<&str> = pair.split('=').collect();
            if parts.len() == 2 {
                let _ = parts[0] == "token";
                let _ = parts[0] == "token_type_hint";

                // URL decode
                let _ = decode(parts[1]);
            }
        }

        // Try as JSON request
        if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(s) {
            let _ = json_val.get("token");
            let _ = json_val.get("token_type_hint");

            // Validate token_type_hint values
            if let Some(hint) = json_val.get("token_type_hint") {
                if let Some(hint_str) = hint.as_str() {
                    let _ = matches!(hint_str, "access_token" | "refresh_token");
                }
            }
        }
    }

    // Test introspection response generation
    let client_suffix = String::from_utf8_lossy(&data[..data.len().min(5)]);
    let response = json!({
        "active": data.len() % 2 == 0,
        "scope": String::from_utf8_lossy(&data[..data.len().min(10)]),
        "client_id": format!("client_{}", client_suffix),
        "username": if data.len() > 5 {
            Some(String::from_utf8_lossy(&data[5..data.len().min(15)]).to_string())
        } else {
            None
        },
        "exp": data.len() as i64 * 1000,
        "iat": data.len() as i64 * 100,
        "nbf": data.len() as i64 * 10,
        "sub": STANDARD.encode(&data[..data.len().min(8)]),
        "aud": vec![String::from_utf8_lossy(&data[..data.len().min(3)])],
        "iss": "https://server.example.com",
        "jti": STANDARD.encode(&data[..data.len().min(16)]),
    });

    // Serialize and deserialize
    let serialized = response.to_string();
    let _ = serde_json::from_str::<serde_json::Value>(&serialized);

    // Test with extreme values
    if data.is_empty() {
        let empty_response = json!({
            "active": false
        });
        let _ = empty_response.to_string();
    }

    if data.len() > 1000 {
        // Test with large token
        let large_token = String::from_utf8_lossy(&data[..1000]);
        let large_response = json!({
            "active": true,
            "token": large_token,
        });
        let _ = large_response.to_string();
    }
});
