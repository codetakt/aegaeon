use aegaeon_jose::{json_lowstar::JsonError, parse_json_header};
use std::error::Error;

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn public_json_header_parser_normalizes_valid_header() -> TestResult {
    let pairs = parse_json_header(br#"{"alg":"HS256","kid":"key-1"}"#)?;
    assert_eq!(
        pairs,
        vec![
            ("alg".to_string(), "HS256".to_string()),
            ("kid".to_string(), "key-1".to_string())
        ]
    );
    Ok(())
}

#[test]
fn public_json_header_parser_rejects_non_ascii_keys() {
    assert_eq!(
        parse_json_header(br#"{"\u00e5lg":"HS256"}"#),
        Err(JsonError::InvalidKeyEncoding(
            "header key must be ASCII".to_string()
        ))
    );
}

#[test]
fn public_json_header_parser_rejects_trailing_bytes() {
    assert_eq!(
        parse_json_header(br#"{"alg":"HS256"}x"#),
        Err(JsonError::TrailingBytes(
            "trailing bytes after JOSE header JSON object".to_string()
        ))
    );
}
