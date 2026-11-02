//! RFC 9110 Sections 5.3, 5.6.1, 8.8.3 and 13.1.1. Invalid syntax never matches.
use axum::http::{header::IF_MATCH, HeaderMap, HeaderValue};

pub(super) fn matches(headers: &HeaderMap, current: &HeaderValue) -> bool {
    let values: Vec<_> = headers.get_all(IF_MATCH).iter().collect();
    if values.len() == 1 && trim_ows(values[0].as_bytes()) == b"*" {
        return true;
    }
    let mut matched = false;
    for value in values {
        let Some(found) = matches_list(value.as_bytes(), current.as_bytes()) else {
            return false;
        };
        matched |= found;
    }
    matched
}

fn trim_ows(value: &[u8]) -> &[u8] {
    value.trim_ascii_start().trim_ascii_end()
}

fn matches_list(mut value: &[u8], current: &[u8]) -> Option<bool> {
    let mut matched = false;
    loop {
        value = value.trim_ascii_start();
        // Recipients tolerate empty list elements. A wildcard is not a list item.
        if value.first() == Some(&b',') {
            value = &value[1..];
            continue;
        }
        if value.is_empty() {
            return Some(matched);
        }
        let weak = value.starts_with(b"W/");
        if weak {
            value = &value[2..];
        }
        if value.first() != Some(&b'"') {
            return None;
        }
        let end = value[1..].iter().position(|byte| *byte == b'"')? + 1;
        if !value[1..end]
            .iter()
            .all(|byte| *byte == 0x21 || (0x23..=0x7e).contains(byte) || *byte >= 0x80)
        {
            return None;
        }
        matched |= !weak && &value[..=end] == current;
        value = &value[end + 1..];
        value = value.trim_ascii_start();
        if !value.is_empty() && value.first() != Some(&b',') {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combines_field_lines_and_requires_strong_comparison() {
        let current = HeaderValue::from_static("\"current\"");
        let mut headers = HeaderMap::new();
        headers.append(
            IF_MATCH,
            HeaderValue::from_static("W/\"current\", \"stale\""),
        );
        assert!(!matches(&headers, &current));
        headers.append(IF_MATCH, current.clone());
        assert!(matches(&headers, &current));
    }

    #[test]
    fn validates_entire_condition_before_accepting_a_matching_tag() {
        let current = HeaderValue::from_static("\"current\"");
        for invalid in [
            "\"current\", *",
            "*, \"current\"",
            "\"current\", invalid",
            "\"current\"junk",
            "\"current\", \"unterminated",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(IF_MATCH, HeaderValue::from_str(invalid).unwrap());
            assert!(!matches(&headers, &current), "{invalid}");
        }
    }

    #[test]
    fn quoted_commas_are_opaque_and_empty_list_elements_are_tolerated() {
        let current = HeaderValue::from_static("\"a,b\"");
        let mut headers = HeaderMap::new();
        headers.insert(
            IF_MATCH,
            HeaderValue::from_static(" , \"stale\", \"a,b\", , "),
        );
        assert!(matches(&headers, &current));
        headers.insert(IF_MATCH, HeaderValue::from_static("*"));
        assert!(matches(&headers, &current));
        headers.append(IF_MATCH, HeaderValue::from_static("*"));
        assert!(!matches(&headers, &current));
    }
}
