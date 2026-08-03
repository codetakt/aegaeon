use axum::http::HeaderMap;

const MAX_REQUEST_ID_BYTES: usize = 128;

#[must_use]
pub(in crate::web) fn request_id_from_headers(headers: &HeaderMap) -> String {
    let mut values = headers.get_all("x-request-id").iter();
    match (values.next(), values.next()) {
        (Some(value), None) => value
            .to_str()
            .ok()
            .and_then(sanitize_request_id)
            .map(ToString::to_string)
            .unwrap_or_else(new_request_id),
        _ => new_request_id(),
    }
}

fn sanitize_request_id(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()
        && value.len() <= MAX_REQUEST_ID_BYTES
        && value.as_bytes().iter().all(u8::is_ascii_graphic))
    .then_some(value)
}

fn new_request_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    #[test]
    fn accepts_single_printable_request_id() {
        let mut headers = HeaderMap::new();
        headers.insert("x-request-id", HeaderValue::from_static("req-123"));

        assert_eq!(request_id_from_headers(&headers), "req-123");
    }

    #[test]
    fn replaces_missing_request_id() {
        assert!(uuid::Uuid::parse_str(&request_id_from_headers(&HeaderMap::new())).is_ok());
    }

    #[test]
    fn replaces_request_id_with_whitespace() {
        let mut headers = HeaderMap::new();
        headers.insert("x-request-id", HeaderValue::from_static("req 123"));

        let request_id = request_id_from_headers(&headers);
        assert_ne!(request_id, "req 123");
        assert!(uuid::Uuid::parse_str(&request_id).is_ok());
    }

    #[test]
    fn replaces_oversized_request_id() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-request-id",
            HeaderValue::from_str(&"a".repeat(MAX_REQUEST_ID_BYTES + 1)).unwrap(),
        );

        let request_id = request_id_from_headers(&headers);
        assert_ne!(request_id, "a".repeat(MAX_REQUEST_ID_BYTES + 1));
        assert!(uuid::Uuid::parse_str(&request_id).is_ok());
    }

    #[test]
    fn replaces_ambiguous_duplicate_request_id() {
        let mut headers = HeaderMap::new();
        headers.append("x-request-id", HeaderValue::from_static("req-one"));
        headers.append("x-request-id", HeaderValue::from_static("req-two"));

        let request_id = request_id_from_headers(&headers);
        assert_ne!(request_id, "req-one");
        assert_ne!(request_id, "req-two");
        assert!(uuid::Uuid::parse_str(&request_id).is_ok());
    }
}
