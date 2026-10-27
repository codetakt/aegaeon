//! Narrow RFC 3986 HTTP URI comparison for RFC 9449 §4.3.
//!
//! This does not resolve DNS or use browser URL parsing. In particular, numeric
//! host spellings, repeated slashes and escaped reserved delimiters stay distinct.

use std::net::Ipv6Addr;

#[derive(PartialEq, Eq)]
struct HttpUri {
    scheme: String,
    host: String,
    port: Option<u16>,
    path: String,
}

pub(super) fn matches(proof: &str, request: &str) -> bool {
    if proof.contains(['?', '#']) {
        return false;
    }
    match (normalize(proof), normalize(request)) {
        (Some(proof), Some(request)) => proof == request,
        _ => false,
    }
}

fn normalize(uri: &str) -> Option<HttpUri> {
    if !uri.is_ascii()
        || uri
            .bytes()
            .any(|b| b.is_ascii_control() || b == b' ' || b == b'\\')
    {
        return None;
    }
    // Validate even the request components that are excluded from comparison.
    let (uri, fragment) = uri
        .split_once('#')
        .map_or((uri, None), |(u, f)| (u, Some(f)));
    if let Some(fragment) = fragment {
        normalize_component(fragment, |b| is_pchar(b) || b == b'/' || b == b'?', false)?;
    }
    let (uri, query) = uri
        .split_once('?')
        .map_or((uri, None), |(u, q)| (u, Some(q)));
    if let Some(query) = query {
        normalize_component(query, |b| is_pchar(b) || b == b'/' || b == b'?', false)?;
    }
    let (scheme, remainder) = uri.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let path_start = remainder.find('/').unwrap_or(remainder.len());
    let (authority, path) = remainder.split_at(path_start);
    let (host, port) = authority_parts(authority)?;
    let host = if let Some(literal) = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        if !valid_ip_literal(literal) {
            return None;
        }
        host.to_ascii_lowercase()
    } else {
        normalize_component(host, |b| is_unreserved(b) || is_sub_delim(b), true)?
    };
    let port = match port {
        None | Some("") => None,
        Some(value) => {
            if !value.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let number = value.parse::<u16>().ok()?;
            if (scheme == "http" && number == 80) || (scheme == "https" && number == 443) {
                None
            } else {
                Some(number)
            }
        }
    };
    let path = normalize_component(path, |b| is_pchar(b) || b == b'/', false)?;
    let path = if path.is_empty() {
        "/".into()
    } else {
        remove_dot_segments(&path)
    };
    Some(HttpUri {
        scheme,
        host,
        port,
        path,
    })
}

fn authority_parts(authority: &str) -> Option<(&str, Option<&str>)> {
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let (host, port) = if authority.starts_with('[') {
        let end = authority.find(']')? + 1;
        let (host, suffix) = authority.split_at(end);
        let port = if suffix.is_empty() {
            None
        } else {
            Some(suffix.strip_prefix(':')?)
        };
        (host, port)
    } else {
        authority
            .split_once(':')
            .map_or((authority, None), |(h, p)| (h, Some(p)))
    };
    if host.is_empty() {
        None
    } else {
        Some((host, port))
    }
}

fn valid_ip_literal(literal: &str) -> bool {
    if literal.starts_with(['v', 'V']) {
        // RFC 3986 IPvFuture = "v" 1*HEXDIG "." 1*(unreserved / sub-delims / ":").
        let Some((version, address)) = literal[1..].split_once('.') else {
            return false;
        };
        !version.is_empty()
            && version.bytes().all(|b| b.is_ascii_hexdigit())
            && !address.is_empty()
            && address
                .bytes()
                .all(|b| is_unreserved(b) || is_sub_delim(b) || b == b':')
    } else {
        // Use the parser only to validate; retain the original address spelling.
        literal.parse::<Ipv6Addr>().is_ok()
    }
}

fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

fn is_sub_delim(b: u8) -> bool {
    matches!(
        b,
        b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'='
    )
}

fn is_pchar(b: u8) -> bool {
    is_unreserved(b) || is_sub_delim(b) || matches!(b, b':' | b'@')
}

fn normalize_component(
    value: &str,
    allowed: impl Fn(u8) -> bool,
    lowercase: bool,
) -> Option<String> {
    let mut normalized = String::with_capacity(value.len());
    let mut bytes = value.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let high = bytes.next()?;
            let low = bytes.next()?;
            let decoded =
                u8::try_from(char::from(high).to_digit(16)? * 16 + char::from(low).to_digit(16)?)
                    .ok()?;
            if is_unreserved(decoded) {
                normalized.push(char::from(if lowercase {
                    decoded.to_ascii_lowercase()
                } else {
                    decoded
                }));
            } else {
                normalized.push('%');
                normalized.push(char::from(high.to_ascii_uppercase()));
                normalized.push(char::from(low.to_ascii_uppercase()));
            }
        } else if allowed(b) {
            normalized.push(char::from(if lowercase {
                b.to_ascii_lowercase()
            } else {
                b
            }));
        } else {
            return None;
        }
    }
    Some(normalized)
}

fn remove_dot_segments(mut input: &str) -> String {
    // RFC 3986 §5.2.4, steps A–E. Moving segments with their leading slash
    // preserves empty segments and the slash left by a final dot segment.
    let mut output = String::with_capacity(input.len());
    while !input.is_empty() {
        if let Some(rest) = input
            .strip_prefix("../")
            .or_else(|| input.strip_prefix("./"))
        {
            input = rest;
        } else if input.starts_with("/./") {
            input = &input[2..];
        } else if input == "/." {
            input = "/";
        } else if input.starts_with("/../") || input == "/.." {
            input = if input == "/.." { "/" } else { &input[3..] };
            output.truncate(output.rfind('/').unwrap_or(0));
        } else if input == "." || input == ".." {
            input = "";
        } else {
            let start = usize::from(input.starts_with('/'));
            let end = input[start..].find('/').map_or(input.len(), |i| start + i);
            output.push_str(&input[..end]);
            input = &input[end..];
        }
    }
    output
}
