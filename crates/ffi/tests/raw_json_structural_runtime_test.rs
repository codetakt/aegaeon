#![cfg(not(no_mbedtls))]

use ffi::raw_json_structural::{
    aegaeon_free_raw_json_structural_result, aegaeon_parse_raw_json_structural,
    aegaeon_raw_json_structural_result, parse_raw_json_structural, RawJsonStructuralParseError,
};

fn assert_abi(input: &[u8], accepted: bool) {
    let mut out = aegaeon_raw_json_structural_result {
        members: std::ptr::null_mut(),
        len: 0,
        consumed_len: 0,
        error_code: 0,
        key_bytes: std::ptr::null_mut(),
        key_bytes_len: 0,
    };
    let status = aegaeon_parse_raw_json_structural(input.as_ptr(), input.len(), &raw mut out);
    assert_eq!(status == 0, accepted, "{input:?}: status {status}");
    assert_eq!(out.error_code, status);
    if accepted {
        assert_eq!(out.consumed_len as usize, input.len());
        assert_eq!(out.members.is_null(), out.len == 0);
        assert_eq!(out.key_bytes.is_null(), out.key_bytes_len == 0);
    }
    aegaeon_free_raw_json_structural_result(&raw mut out);
    assert!(out.members.is_null());
    assert!(out.key_bytes.is_null());
    assert_eq!(out.len, 0);
    assert_eq!(out.key_bytes_len, 0);
    aegaeon_free_raw_json_structural_result(&raw mut out);
}

#[test]
fn structural_runtime_strict_separators_and_scalar_grammar() {
    for input in [
        r#"{"x":[1,]}"#,
        r#"{"x":{"y":1,}}"#,
        r#"{"x":1,}"#,
        r#"{"x":"a",}"#,
        r#"{"x":[,]}"#,
        r#"{"x":{,}}"#,
        r#"{"x":[1,,2]}"#,
        r#"{"x":[1 2]}"#,
        r#"{"x":{"a":1 "b":2}}"#,
        r#"{"x":{"a" 1}}"#,
        r#"{"x":[1}}"#,
        r#"{"x":{"a":1]}"#,
        r#"{"x":[}"#,
        r#"{"x":[True]}"#,
        r#"{"x":[truefalse]}"#,
        r#"{"x":[01]}"#,
        r#"{"x":[+1]}"#,
        r#"{"x":[1.]}"#,
        r#"{"x":[1e+]}"#,
        r#"{"x":[NaN]}"#,
        r#"{"x":["\q"]}"#,
        r#"{"x":["\uZZZZ"]}"#,
        r#"{"x":["\u12"]}"#,
        "{\"x\":[\"control\nbyte\"]}",
        "{\"x\":[1]",
        "{\"x\":[\"unfinished]}",
        r#"{"x":[]} {}"#,
    ] {
        assert!(
            parse_raw_json_structural(input.as_bytes()).is_err(),
            "{input}"
        );
        assert_abi(input.as_bytes(), false);
    }
}

#[test]
fn structural_runtime_preserves_valid_spans_unicode_and_large_numbers() {
    for input in [
        "{}",
        r#"{"x":[]}"#,
        r#"{"x":{}}"#,
        r#"{"x":[{},[],{"a":[true,false,null,-1.25e+3]}]}"#,
        r#"{"x":1e9999999999999999999999999999999999999}"#,
        r#"{"x":12345678901234567890123456789012345678901234567890}"#,
        r#"{"拡張":{"雪":["☃","\u2603","\\\"\/"]}}"#,
    ] {
        let parsed = parse_raw_json_structural(input.as_bytes()).expect(input);
        assert!(!parsed.has_trailing_bytes(input.as_bytes()));
        for member in &parsed.members {
            assert!(member.value_slice(input.as_bytes()).is_some());
        }
        assert_abi(input.as_bytes(), true);
    }
    let input = br#" {"x" : [ {}, 1 ] } "#;
    let parsed = parse_raw_json_structural(input).expect("valid spans");
    assert_eq!(parsed.members[0].key, b"x");
    assert_eq!(
        parsed.members[0].value_slice(input),
        Some(&b"[ {}, 1 ]"[..])
    );
}

#[test]
fn structural_runtime_rejects_invalid_utf8_in_ignored_bytes() {
    for input in [
        &b"{\"x\":\"\xff\"}"[..],
        &b"{\"x\":[\"\xc0\xaf\"]}"[..],
        &b"{\"x\":{\"\xff\":0}}"[..],
        &b"{\"\xff\":null}"[..],
    ] {
        assert_eq!(
            parse_raw_json_structural(input),
            Err(RawJsonStructuralParseError::InvalidJson)
        );
        assert_abi(input, false);
    }
}

#[test]
fn structural_runtime_nested_containers_use_bounded_input_stack() {
    // Finite regression, below the default encoded JOSE header limit.
    let depth = 512;
    let input = format!("{{\"x\":{}0{}}}", "[".repeat(depth), "]".repeat(depth));
    let parsed = parse_raw_json_structural(input.as_bytes()).expect("deep valid value");
    assert_eq!(parsed.members.len(), 1);
    assert_abi(input.as_bytes(), true);
}

#[test]
fn structural_runtime_consumes_json_whitespace_without_changing_member_spans() {
    for object in [
        "{}",
        r#"{"x":"value"}"#,
        r#"{"x":null}"#,
        r#"{"x":true}"#,
        r#"{"x":42}"#,
        r#"{"x":[]}"#,
        r#"{"x":{}}"#,
    ] {
        for whitespace in [" ", "\t", "\r", "\n", " \t\r\n"] {
            let prefix = format!("{whitespace}{object}");
            let input = format!("{prefix}{whitespace}");
            let before = parse_raw_json_structural(prefix.as_bytes()).expect("valid prefix");
            let parsed = parse_raw_json_structural(input.as_bytes()).expect("valid JSON text");
            assert_eq!(parsed.members, before.members, "{input:?}");
            assert_eq!(parsed.consumed_len as usize, input.len(), "{input:?}");
            assert!(!parsed.has_trailing_bytes(input.as_bytes()));
            assert_abi(input.as_bytes(), true);
        }
        for suffix in ["\u{000B}", "\u{000C}", "\u{00A0}", "\0", " {}", " null"] {
            let input = format!("{object} \t\r\n{suffix}");
            assert!(
                parse_raw_json_structural(input.as_bytes()).is_err(),
                "{input:?}"
            );
            assert_abi(input.as_bytes(), false);
        }
    }
}
