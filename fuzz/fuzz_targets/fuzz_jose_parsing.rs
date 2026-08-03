#![forbid(unsafe_code)]
#![no_main]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test JOSE/JWT parsing with various malformed inputs

    // Try as raw JWT
    if let Ok(s) = std::str::from_utf8(data) {
        // Split by dots to simulate JWT structure
        let parts: Vec<&str> = s.split('.').collect();

        if parts.len() == 3 {
            // Try to decode each part
            for part in &parts {
                let _ = URL_SAFE_NO_PAD.decode(part);
            }
        }

        // Test various JOSE header patterns
        if let Some(header) = parts.first() {
            if let Ok(decoded) = URL_SAFE_NO_PAD.decode(header) {
                if let Ok(header_str) = String::from_utf8(decoded) {
                    // Check for required fields
                    let _ = header_str.contains("\"alg\"");
                    let _ = header_str.contains("\"typ\"");
                    let _ = header_str.contains("\"kid\"");

                    // Try to parse as JSON
                    let _ = serde_json::from_str::<serde_json::Value>(&header_str);
                }
            }
        }
    }

    // Test compact serialization
    if data.len() >= 5 {
        // Create fake JWT with fuzzed data
        let header = URL_SAFE_NO_PAD.encode(&data[..2]);
        let payload = URL_SAFE_NO_PAD.encode(&data[2..4]);
        let signature = URL_SAFE_NO_PAD.encode(&data[4..]);

        let jwt = format!("{}.{}.{}", header, payload, signature);

        // This should handle any malformed JWT gracefully
        let _ = jwt.split('.').count();

        // Try to decode
        for part in jwt.split('.') {
            let _ = URL_SAFE_NO_PAD.decode(part);
        }
    }

    // Test JWE patterns (5 parts)
    if data.len() >= 10 {
        let parts = vec![
            URL_SAFE_NO_PAD.encode(&data[..2]),
            URL_SAFE_NO_PAD.encode(&data[2..4]),
            URL_SAFE_NO_PAD.encode(&data[4..6]),
            URL_SAFE_NO_PAD.encode(&data[6..8]),
            URL_SAFE_NO_PAD.encode(&data[8..]),
        ];

        let jwe = parts.join(".");
        let _ = jwe.split('.').count();
    }
});
