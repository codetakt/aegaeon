use super::{CacheControl, Metadata};
use reqwest::header::{HeaderMap, CACHE_CONTROL, VARY};

pub(super) fn trim_ows(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(|b| matches!(*b, b' ' | b'\t')) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(|b| matches!(*b, b' ' | b'\t')) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

pub(super) fn delta_seconds(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    let mut n = 0u64;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        n = n.saturating_mul(10).saturating_add(u64::from(b - b'0'));
    }
    Some(n)
}

fn field_names(bytes: &[u8]) -> bool {
    bytes
        .split(|b| *b == b',')
        .all(|name| trim_ows(name).iter().copied().all(tchar))
}

pub(super) fn vary(headers: &HeaderMap) -> Metadata<bool> {
    if !headers.contains_key(VARY) {
        return Metadata::Absent;
    }
    let mut nonempty = false;
    for value in headers.get_all(VARY) {
        for name in value.as_bytes().split(|b| *b == b',') {
            let name = trim_ows(name);
            if name.is_empty() {
                continue;
            }
            if name != b"*" && !name.iter().copied().all(tchar) {
                return Metadata::Invalid;
            }
            nonempty = true;
        }
    }
    Metadata::Valid(nonempty)
}

// Linear scan over the combined field value. A virtual/actual comma between
// received lines is significant even inside a quoted string. No UTF-8 coercion,
// integer big-number allocation, recursion, or first-valid-value search.
pub(super) fn control(headers: &HeaderMap) -> Metadata<CacheControl> {
    if !headers.contains_key(CACHE_CONTROL) {
        return Metadata::Absent;
    }
    let mut combined = Vec::new();
    for (i, value) in headers.get_all(CACHE_CONTROL).iter().enumerate() {
        if i != 0 {
            combined.push(b',');
        }
        combined.extend_from_slice(value.as_bytes());
    }
    parse(&combined).map_or(Metadata::Invalid, Metadata::Valid)
}

fn parse(bytes: &[u8]) -> Option<CacheControl> {
    let mut cc = CacheControl::default();
    let mut pos = 0;
    while pos < bytes.len() {
        while pos < bytes.len() && matches!(bytes[pos], b' ' | b'\t' | b',') {
            pos += 1;
        }
        if pos == bytes.len() {
            break;
        }
        let start = pos;
        while pos < bytes.len() && tchar(bytes[pos]) {
            pos += 1;
        }
        if start == pos {
            return None;
        }
        let name = &bytes[start..pos];
        let arg = if bytes.get(pos) == Some(&b'=') {
            pos += 1;
            Some(parse_argument(bytes, &mut pos)?)
        } else {
            None
        };
        if name.eq_ignore_ascii_case(b"max-age") || name.eq_ignore_ascii_case(b"s-maxage") {
            let number = delta_seconds(arg.as_deref()?)?;
            let slot = if name.eq_ignore_ascii_case(b"max-age") {
                &mut cc.max_age
            } else {
                &mut cc.s_maxage
            };
            if slot.replace(number).is_some() {
                return None;
            }
        } else if name.eq_ignore_ascii_case(b"no-cache") || name.eq_ignore_ascii_case(b"private") {
            if arg.as_deref().is_some_and(|a| !field_names(a)) {
                return None;
            }
            if name.eq_ignore_ascii_case(b"no-cache") {
                cc.no_cache = true;
            } else {
                cc.private = true;
            }
        } else if [
            b"no-store".as_slice(),
            b"public",
            b"must-revalidate",
            b"proxy-revalidate",
            b"must-understand",
            b"no-transform",
        ]
        .iter()
        .any(|known| name.eq_ignore_ascii_case(known))
        {
            if arg.is_some() {
                return None;
            }
            if name.eq_ignore_ascii_case(b"no-store") {
                cc.no_store = true;
            }
        }
        while pos < bytes.len() && matches!(bytes[pos], b' ' | b'\t') {
            pos += 1;
        }
        if pos < bytes.len() {
            if bytes[pos] != b',' {
                return None;
            }
            pos += 1;
        }
    }
    Some(cc)
}

fn parse_argument(bytes: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    if bytes.get(*pos) == Some(&b'"') {
        *pos += 1;
        let mut decoded = Vec::new();
        loop {
            let b = *bytes.get(*pos)?;
            *pos += 1;
            match b {
                b'"' => break,
                b'\\' => {
                    let quoted = *bytes.get(*pos)?;
                    if !matches!(quoted, b'\t' | b' ' | 0x21..=0x7e | 0x80..=0xff) {
                        return None;
                    }
                    decoded.push(quoted);
                    *pos += 1;
                }
                b'\t' | b' ' | b'!' | 0x23..=0x5b | 0x5d..=0x7e | 0x80..=0xff => decoded.push(b),
                _ => return None,
            }
        }
        Some(decoded)
    } else {
        let start = *pos;
        while *pos < bytes.len() && tchar(bytes[*pos]) {
            *pos += 1;
        }
        if *pos == start {
            return None;
        }
        Some(bytes[start..*pos].to_vec())
    }
}
