//! RFC 6749 section 2.3.1 / Appendix B credential-component encoding.
//! Decode components independently; these are not form key/value documents.

pub(crate) fn encode_component(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub(crate) fn decode_component(value: &[u8]) -> Option<String> {
    let mut decoded = Vec::with_capacity(value.len());
    let mut bytes = value.iter().copied();
    while let Some(byte) = bytes.next() {
        decoded.push(match byte {
            b'+' => b' ',
            b'%' => (hex_digit(bytes.next()?)? << 4) | hex_digit(bytes.next()?)?,
            other => other,
        });
    }
    String::from_utf8(decoded).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oauth_basic_components_follow_form_encoding() {
        for (logical, encoded) in [
            ("simple_ID-09", "simple_ID-09"),
            (
                "space colon:plus+percent%amp&equals=",
                "space+colon%3Aplus%2Bpercent%25amp%26equals%3D",
            ),
            ("é雪", "%C3%A9%E9%9B%AA"),
            ("%2B%25", "%252B%2525"),
            ("", ""),
        ] {
            assert_eq!(encode_component(logical), encoded);
            assert_eq!(
                decode_component(encoded.as_bytes()).as_deref(),
                Some(logical)
            );
        }
        assert_eq!(decode_component(b"a&b=c").as_deref(), Some("a&b=c"));
        assert_eq!(decode_component(b"%252B").as_deref(), Some("%2B"));
        assert_eq!(decode_component(b"%2b").as_deref(), Some("+"));
    }

    #[test]
    fn oauth_basic_components_reject_bad_percent_and_utf8() {
        for value in [
            b"%".as_slice(),
            b"%2",
            b"%GG",
            b"%0x",
            b"%FF",
            b"%C3%28",
            b"%C0%AF",
            b"%ED%A0%80",
            b"%F4%90%80%80",
            b"\xff",
        ] {
            assert!(decode_component(value).is_none());
        }
    }
}
