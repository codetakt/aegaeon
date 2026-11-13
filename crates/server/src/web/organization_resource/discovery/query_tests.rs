use super::*;

fn encoded(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut result = String::with_capacity(value.len() * 3);
    for byte in value.bytes() {
        result.push('%');
        result.push(char::from(HEX[usize::from(byte >> 4)]));
        result.push(char::from(HEX[usize::from(byte & 15)]));
    }
    result
}

#[test]
fn discovery_query_accepts_both_decoded_limits_with_full_encoding() {
    let audience = format!("https://example.test/{}", "/".repeat(2027));
    assert_eq!(audience.len(), MAX_AUDIENCE_BYTES);
    let cursor = "a".repeat(discovery::MAX_CURSOR_BYTES);
    let raw = format!(
        "{}={}&{}={}",
        encoded("audience"),
        encoded(&audience),
        encoded("cursor"),
        encoded(&cursor)
    );
    assert_eq!(raw.len(), MAX_QUERY_BYTES);
    let query = parse_query(&raw).unwrap();
    assert_eq!(query.audience, audience);
    assert_eq!(query.cursor.as_deref(), Some(cursor.as_str()));
    assert!(parse_query(&(raw + "a")).is_err());
}

#[test]
fn discovery_query_preserves_field_and_decoded_value_bounds() {
    for raw in [
        format!("audience={}", "a".repeat(MAX_AUDIENCE_BYTES + 1)),
        format!(
            "audience=a&cursor={}",
            "a".repeat(discovery::MAX_CURSOR_BYTES + 1)
        ),
        "audience=a&audience=b".into(),
        "audience=a&cursor=b&cursor=c".into(),
        "audience=a&unknown=b".into(),
        "cursor=a".into(),
    ] {
        assert!(parse_query(&raw).is_err(), "accepted {raw}");
    }
    let audience = format!("https://example.test/{}", "é".repeat(1013));
    let raw = serde_urlencoded::to_string([("audience", &audience)]).unwrap();
    assert_eq!(parse_query(&raw).unwrap().audience, audience);
}
