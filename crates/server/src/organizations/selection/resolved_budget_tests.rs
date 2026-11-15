use super::*;
use crate::organizations::consent::GrantRequest;

fn selection() -> SelectionRequest {
    SelectionRequest::parse(&serde_json::json!([{
        "type": TYPE, "locations": ["https://api.example.test"],
        "privileges": (0..123).map(|i| format!("{i:03}{}", "p".repeat(125))).collect::<Vec<_>>(),
        "selection": "interactive",
    }]))
    .unwrap()
}

fn explicit(request: &SelectionRequest, identifier: &str) -> Value {
    serde_json::json!([{
        "type": GRANT_TYPE, "locations": request.locations,
        "organizations": [{"identifier": identifier, "privileges": request.privileges}],
    }])
}

#[test]
fn resolved_grants_obey_exact_encoded_byte_boundary() {
    let request = selection();
    let available = request.privileges.iter().cloned().collect();
    let selector = serde_json::to_vec(&serde_json::json!([request])).unwrap();
    assert_eq!(selector.len(), 16_274);
    assert_eq!(
        serde_json::to_vec(&explicit(&request, &"x".repeat(256)))
            .unwrap()
            .len(),
        16_536
    );
    let overhead = serde_json::to_vec(&explicit(&request, "x")).unwrap().len() - 1;
    let boundary = 16 * 1024 - overhead;
    assert!((2..256).contains(&boundary));
    for length in [boundary - 1, boundary, boundary + 1] {
        let identifier = "x".repeat(length);
        let expected = explicit(&request, &identifier);
        assert_eq!(
            serde_json::to_vec(&expected).unwrap().len(),
            overhead + length
        );
        match request.resolve(&identifier, &available) {
            Ok(resolved) => {
                assert!(length <= boundary, "oversized resolved grant was accepted");
                assert_eq!(resolved, expected);
                assert!(GrantRequest::parse(&resolved).is_ok());
                assert!(request.permits(&resolved));
            }
            Err(_) => assert!(
                length > boundary,
                "representable resolved grant was rejected"
            ),
        }
    }
    // The byte budget applies after JSON escaping, not to the source identifier length.
    for identifier in [
        "\"".repeat(boundary),
        "\\".repeat(boundary),
        "é".repeat(boundary),
    ] {
        assert!(identifier.len() <= 256);
        assert!(
            serde_json::to_vec(&explicit(&request, &identifier))
                .unwrap()
                .len()
                > 16 * 1024
        );
        assert!(request.resolve(&identifier, &available).is_err());
    }
    assert_eq!(
        selector,
        serde_json::to_vec(&serde_json::json!([request])).unwrap()
    );
    assert!(request.resolve("invalid\nidentifier", &available).is_err());
    assert!(request.resolve("valid", &BTreeSet::new()).is_err());
}
