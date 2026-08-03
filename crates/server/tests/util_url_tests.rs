use aegaeon_server::util::{append_code_and_state, append_state, url_encode_component};

#[test]
fn test_url_encode_component() {
    assert_eq!(url_encode_component("abcXYZ-_.~"), "abcXYZ-_.~");
    assert_eq!(url_encode_component("a b"), "a%20b");
}

#[test]
fn test_append_code_and_state() {
    let base = "https://example.com/cb";
    let url = append_code_and_state(base, "code123", Some("st at e"), "https://issuer.example");
    assert!(url.contains("code=code123"));
    assert!(url.contains("state=st%20at%20e"));
    assert!(url.contains("iss=https%3A%2F%2Fissuer.example"));
    let base2 = "https://example.com/cb?x=1";
    let url2 = append_code_and_state(base2, "c", None, "https://issuer.example");
    assert!(url2.contains("code=c"));
    assert!(url2.contains("iss=https%3A%2F%2Fissuer.example"));
}

#[test]
fn test_append_error_and_state() {
    use aegaeon_server::util::append_error_and_state;
    let base = "https://client.example/cb";
    let url = append_error_and_state(
        base,
        "invalid_scope",
        Some("not allowed"),
        Some("xyz"),
        "https://issuer.example",
    );
    assert!(url.contains("error=invalid_scope"));
    assert!(url.contains("error_description=not%20allowed"));
    assert!(url.contains("state=xyz"));
    assert!(url.contains("iss=https%3A%2F%2Fissuer.example"));
}

#[test]
fn test_append_state() {
    let base = "https://example.com/logout";
    assert_eq!(
        append_state(base, Some("st at e")),
        "https://example.com/logout?state=st%20at%20e"
    );
    assert_eq!(append_state(base, None), base);

    let base2 = "https://example.com/logout?x=1";
    assert_eq!(
        append_state(base2, Some("xyz")),
        "https://example.com/logout?x=1&state=xyz"
    );
}
