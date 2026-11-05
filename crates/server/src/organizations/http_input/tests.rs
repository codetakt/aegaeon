use super::*;
use axum::http::HeaderValue;
use serde::Deserialize;

fn headers(value: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(IF_MATCH, HeaderValue::from_str(value).unwrap());
    headers
}

#[test]
fn version_precondition_binds_object_and_exact_revision() {
    let id = Uuid::from_u128(0x123456789abc4def8123456789abcdef);
    let original = VersionTag::new(id, 7).unwrap();
    let parsed = required_version(&headers(&original.header_value())).unwrap();
    assert_eq!(parsed.revision(), 7);
    assert_eq!(parsed.require_current(id, 7), Ok(()));
    assert_eq!(
        parsed.require_current(id, 8),
        Err(InputError::PreconditionFailed)
    );
    assert_eq!(
        parsed.require_current(Uuid::new_v4(), 7),
        Err(InputError::PreconditionFailed)
    );
    let max = VersionTag::new(id, i64::MAX).unwrap();
    assert_eq!(required_version(&headers(&max.header_value())), Ok(max));
}

#[test]
fn missing_wildcard_and_weak_versions_never_authorize() {
    assert_eq!(
        required_version(&HeaderMap::new()),
        Err(InputError::PreconditionRequired)
    );
    assert_eq!(
        required_version(&headers("*")),
        Err(InputError::PreconditionRequired)
    );
    let value = VersionTag::new(Uuid::new_v4(), 1).unwrap().header_value();
    assert_eq!(
        required_version(&headers(&format!("W/{value}"))),
        Err(InputError::PreconditionFailed)
    );
    assert_eq!(
        required_version(&headers("W/not-a-tag")),
        Err(InputError::Invalid)
    );
    assert_eq!(
        required_version(&headers(&format!(" \t{value}\t "))),
        required_version(&headers(&value))
    );
}

#[test]
fn noncanonical_overflow_and_multiple_versions_refuse() {
    let id = "12345678-9abc-4def-8123-456789abcdef";
    for value in [
        format!("\"{id}.0\""),
        format!("\"{id}.-1\""),
        format!("\"{id}.01\""),
        format!("\"{id}.+1\""),
        format!("\"{id}.9223372036854775808\""),
        format!("\"{}.1\"", id.to_uppercase()),
        format!("\"{}.1\"", Uuid::nil()),
        format!("\"{id}.1\",\"{id}.2\""),
        format!("\"{id}.1\",*"),
        format!("\"organization_{id}.1\""),
        format!("\"{}.1\"", id.replace('-', "")),
    ] {
        assert_eq!(
            required_version(&headers(&value)),
            Err(InputError::Invalid),
            "{value}"
        );
    }
    let mut duplicate = headers(&format!("\"{id}.1\""));
    duplicate.append(IF_MATCH, duplicate[IF_MATCH].clone());
    assert_eq!(required_version(&duplicate), Err(InputError::Invalid));
    assert_eq!(
        required_version(&headers(&"x".repeat(MAX_PRECONDITION_BYTES + 1))),
        Err(InputError::TooLarge)
    );
}

#[test]
fn idempotency_keys_have_one_exact_bounded_ascii_value() {
    let mut h = HeaderMap::new();
    assert_eq!(idempotency_key(&h), Err(InputError::Invalid));
    let limit = "x".repeat(MAX_IDEMPOTENCY_BYTES);
    h.insert("idempotency-key", HeaderValue::from_str(&limit).unwrap());
    assert_eq!(idempotency_key(&h), Ok(limit.as_str()));
    for value in ["", "a b", " leading", "trailing ", "tab\t"] {
        h.insert("idempotency-key", HeaderValue::from_str(value).unwrap());
        assert_eq!(idempotency_key(&h), Err(InputError::Invalid));
    }
    h.insert(
        "idempotency-key",
        HeaderValue::from_bytes("学校".as_bytes()).unwrap(),
    );
    assert_eq!(idempotency_key(&h), Err(InputError::Invalid));
    h.insert(
        "idempotency-key",
        HeaderValue::from_str(&"x".repeat(MAX_IDEMPOTENCY_BYTES + 1)).unwrap(),
    );
    assert_eq!(idempotency_key(&h), Err(InputError::TooLarge));
    h.insert("idempotency-key", HeaderValue::from_static("same"));
    h.append("idempotency-key", HeaderValue::from_static("same"));
    assert_eq!(idempotency_key(&h), Err(InputError::Invalid));
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Create {
    external_id: String,
}

#[test]
fn strict_json_preserves_external_ids_and_refuses_forged_authority() {
    let body = br#"{"external_id":"exact/\u5b66\u6821/Case"}"#;
    assert_eq!(
        decode_json::<Create>(body).unwrap().external_id,
        "exact/学校/Case"
    );
    for member in ["actor", "binding", "ceiling", "access_basis", "role"] {
        let body = format!(r#"{{"external_id":"exact","{member}":{{}}}}"#);
        assert_eq!(
            decode_json::<Create>(body.as_bytes()),
            Err(InputError::Invalid)
        );
    }
    for body in [b"\xff".as_slice(), b"{} trailing", b"{", b"", b"null"] {
        assert_eq!(decode_json::<Create>(body), Err(InputError::Invalid));
    }
}

#[test]
fn duplicate_members_refuse_even_for_value_decoding() {
    for body in [r#"{"a":1,"a":2}"#, r#"{"nested":{"a":1,"\u0061":2}}"#] {
        assert!(serde_json::from_str::<serde_json::Value>(body).is_ok());
        assert_eq!(
            decode_json::<serde_json::Value>(body.as_bytes()),
            Err(InputError::Invalid)
        );
    }
    let exact = format!("\"{}\"", "x".repeat(MAX_BODY_BYTES - 2));
    assert!(decode_json::<String>(exact.as_bytes()).is_ok());
    assert_eq!(
        decode_json::<String>(format!("{exact} ").as_bytes()),
        Err(InputError::TooLarge)
    );
}

#[test]
fn pagination_never_clamps_or_accepts_unbounded_input() {
    assert_eq!(page_size(None), Ok(50));
    assert_eq!(page_size(Some("1")), Ok(1));
    assert_eq!(page_size(Some("100")), Ok(100));
    for invalid in [
        "0",
        "101",
        "",
        "-1",
        "+1",
        "01",
        " 1",
        "1 ",
        "18446744073709551616",
    ] {
        assert_eq!(page_size(Some(invalid)), Err(InputError::Invalid));
    }
}
