use super::*;
use axum::http::HeaderValue;

fn selected(values: &[&[u8]], enabled: bool) -> ParseResult<IntrospectionRepresentation> {
    let mut headers = HeaderMap::new();
    for value in values {
        headers.append(
            header::ACCEPT,
            HeaderValue::from_bytes(value).expect("HTTP field bytes"),
        );
    }
    select(&headers, enabled)
}

#[test]
fn accepts_exact_media_types_and_explicit_opt_in() {
    use IntrospectionRepresentation::{Json, Jwt};
    for (values, expected) in [
        (vec![], Json),
        (vec![b"application/json".as_slice()], Json),
        (vec![b"Application/JSON".as_slice()], Json),
        (vec![b"APPLICATION/TOKEN-INTROSPECTION+JWT".as_slice()], Jwt),
        (vec![b"*/*".as_slice()], Json),
        (vec![b"application/*".as_slice()], Json),
        (
            vec![b"application/token-introspection+jwt-extra, application/json".as_slice()],
            Json,
        ),
        (
            vec![
                b"application/json".as_slice(),
                b"application/token-introspection+jwt".as_slice(),
            ],
            Jwt,
        ),
        (
            vec![b" , application/json, ,".as_slice(), b"\t".as_slice()],
            Json,
        ),
        (vec![b"application/json; ; ;".as_slice()], Json),
        (
            vec![b"application/json; , application/token-introspection+jwt;".as_slice()],
            Jwt,
        ),
    ] {
        assert_eq!(selected(&values, true), Ok(expected), "{values:?}");
    }
}

#[test]
fn honors_specificity_quality_duplicates_and_capability() {
    use IntrospectionRepresentation::{Json, Jwt};
    for (value, enabled, expected) in [
        ("application/json;q=0, */*;q=1", true, Err(NegotiationError::NotAcceptable)),
        ("application/json;q=0, application/token-introspection+jwt;q=0, */*", true, Err(NegotiationError::NotAcceptable)),
        ("application/*;q=0, */*", true, Err(NegotiationError::NotAcceptable)),
        ("application/json;q=0.001, application/*;q=1", true, Ok(Json)),
        ("application/json;q=0.9, application/token-introspection+jwt;q=0.1", true, Ok(Json)),
        ("application/json;q=0.1, application/token-introspection+jwt;q=0.9", true, Ok(Jwt)),
        ("application/token-introspection+jwt;q=0.5,application/json;q=0.5", true, Ok(Jwt)),
        ("application/json;q=1,application/json;q=0.1,application/token-introspection+jwt;q=0.5", true, Ok(Jwt)),
        ("application/json;q=0.1,application/json;q=1,application/token-introspection+jwt;q=0.5", true, Ok(Jwt)),
        ("application/token-introspection+jwt;q=1,application/token-introspection+jwt;q=0,application/json;q=0.1", true, Ok(Json)),
        ("application/token-introspection+jwt", false, Err(NegotiationError::NotAcceptable)),
        ("application/token-introspection+jwt,application/json;q=0.001", false, Ok(Json)),
        ("application/token-introspection+jwt;q=0, */*", true, Ok(Json)),
        ("application/token-introspection+jwt;version=1,*/*", true, Ok(Json)),
        ("application/json;version=1,application/token-introspection+jwt", true, Ok(Jwt)),
        ("application/json;version=1", true, Err(NegotiationError::NotAcceptable)),
        ("text/plain", true, Err(NegotiationError::NotAcceptable)),
        ("", true, Err(NegotiationError::NotAcceptable)),
        (", ,\t,", true, Err(NegotiationError::NotAcceptable)),
    ] {
        assert_eq!(selected(&[value.as_bytes()], enabled), expected, "{value}; enabled={enabled}");
    }
    assert_eq!(
        selected(&[b"application/json;q=1", b"application/json;q=0"], true),
        Err(NegotiationError::NotAcceptable)
    );
    assert_eq!(selected(&[], false), Ok(Json));
}

#[test]
fn parses_quality_boundaries_without_rounding() {
    for (value, quality) in [
        ("0", 0),
        ("0.", 0),
        ("0.0", 0),
        ("0.001", 1),
        ("0.01", 10),
        ("0.1", 100),
        ("0.999", 999),
        ("1", 1000),
        ("1.", 1000),
        ("1.0", 1000),
        ("1.00", 1000),
        ("1.000", 1000),
    ] {
        assert_eq!(parse_quality(value.as_bytes()), Ok(quality), "{value}");
        let header = format!("application/json;Q=\"{value}\"");
        let expected = if quality == 0 {
            Err(NegotiationError::NotAcceptable)
        } else {
            Ok(IntrospectionRepresentation::Json)
        };
        assert_eq!(selected(&[header.as_bytes()], true), expected);
    }
    for value in [
        "", "-0", "+1", "01", ".5", "1.001", "2", "0.0000", "1.0000", "NaN", "1e0", "0.1 ", "0..1",
    ] {
        assert_eq!(
            parse_quality(value.as_bytes()),
            Err(NegotiationError::Malformed),
            "{value}"
        );
    }
}

#[test]
fn parses_quoted_parameters_and_all_field_bytes() {
    for values in [
        vec![b"text/plain;note=\"a,b;\\\"c\\\\d\", application/json".as_slice()],
        vec![b"text/plain;note=\"\xff\\\x80\",application/json".as_slice()],
        vec![b"application/json;q=\"0.\\5\"".as_slice()],
        vec![b"text/plain;q=0.5;note=\"x\",application/json".as_slice()],
        // Field lines combine with a comma, even within a quoted value.
        vec![
            b"text/plain;note=\"left".as_slice(),
            b"right\",application/json".as_slice(),
        ],
    ] {
        assert_eq!(
            selected(&values, true),
            Ok(IntrospectionRepresentation::Json),
            "{values:?}"
        );
    }
    for value in [
        b"application/json;x=\xff".as_slice(),
        b"application/\xff".as_slice(),
        b"application/json;q=\"\xff\"".as_slice(),
    ] {
        assert_eq!(selected(&[value], true), Err(NegotiationError::Malformed));
    }
    assert_eq!(
        selected(&[b"application/json;q=1;x=y"], true),
        Err(NegotiationError::NotAcceptable)
    );
}

#[test]
fn rejects_malformed_ranges_parameters_and_quality() {
    for value in [
        "application",
        "application/",
        "/json",
        "application /json",
        "application/ json",
        "application/json application/json",
        "application/json;q",
        "application/json;q=",
        "application/json;x",
        "application/json;x=",
        "application/json;q =1",
        "application/json;q= 1",
        "application/json;q=1;q=0",
        "application/json;q=1;Q=1",
        "application/json;q=\"\"",
        "application/json;q=01",
        "application/json;q=0.0001",
        "application/json;q=1.001",
        "application/json;x=\"unterminated",
        "application/json;x=\"escape\\",
        "application/json;x=\"x\"tail",
        "application/json;(comment)",
        "application/json\r",
        "application/json\n",
        "application/json;x=\"\u{7f}\"",
        "application/json;x=\"\u{1}\"",
        "application/json;x=\"\\\u{7f}\"",
    ] {
        // Raw grammar entry covers controls that HeaderValue itself refuses to construct.
        assert_eq!(
            select_present(value.as_bytes(), true),
            Err(NegotiationError::Malformed),
            "{value:?}"
        );
    }
}

#[test]
fn star_bearing_tokens_are_unknown_types_not_glob_patterns() {
    for value in ["application/*+jwt", "app*/json", "*/json", "application/**"] {
        assert_eq!(
            selected(&[value.as_bytes()], true),
            Err(NegotiationError::NotAcceptable),
            "{value}"
        );
        let combined = format!("{value},application/json");
        assert_eq!(
            selected(&[combined.as_bytes()], true),
            Ok(IntrospectionRepresentation::Json),
            "{value}"
        );
        let with_explicit = format!("{value},application/token-introspection+jwt");
        assert_eq!(
            selected(&[with_explicit.as_bytes()], true),
            Ok(IntrospectionRepresentation::Jwt),
            "{value}"
        );
    }
}
