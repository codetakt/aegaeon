#![forbid(unsafe_code)]
#![no_main]

use aegaeon_server::middleware::DpopMiddleware;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use http::{HeaderValue, Request};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Create a DPoP middleware instance
    let dpop = DpopMiddleware::new_process_local_for_tests();

    // Build various malformed requests
    let mut request_builder = Request::builder()
        .method("POST")
        .uri("https://server.example.com/token");

    // Add fuzzed DPoP header
    if let Ok(header_value) = HeaderValue::from_bytes(data) {
        request_builder = request_builder.header("DPoP", header_value);
    }

    // Also try with base64-encoded data
    let encoded = STANDARD.encode(data);
    if let Ok(header_value) = HeaderValue::from_str(&encoded) {
        request_builder = request_builder.header("DPoP", header_value);
    }

    // Build and verify - should handle all malformed inputs gracefully
    if let Ok(request) = request_builder.body(()) {
        let _ = dpop.verify(&request);
    }

    // Test with various JWT-like structures
    if data.len() >= 3 {
        let fake_jwt = format!(
            "{}.{}.{}",
            STANDARD.encode(&data[..data.len() / 3]),
            STANDARD.encode(&data[data.len() / 3..2 * data.len() / 3]),
            STANDARD.encode(&data[2 * data.len() / 3..])
        );

        if let Ok(header_value) = HeaderValue::from_str(&fake_jwt) {
            let request = Request::builder()
                .method("POST")
                .uri("https://server.example.com/token")
                .header("DPoP", header_value)
                .body(());

            if let Ok(req) = request {
                let _ = dpop.verify(&req);
            }
        }
    }
});
