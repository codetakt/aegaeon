use crate::config::TransportSecurityConfig;
use crate::middleware::tls::TransportRejectionKind;
use crate::util;
use http::HeaderMap;
use std::net::{IpAddr, SocketAddr};

const MAX_FORWARDED_HEADER_BYTES: usize = 8 * 1024;

pub(super) fn extract_proto(
    cfg: &TransportSecurityConfig,
    headers: &HeaderMap,
) -> Result<String, TransportRejectionKind> {
    if let Some(value) = util::single_header_str(headers, "forwarded")
        .map_err(|_| TransportRejectionKind::MalformedForwardedHeader)?
    {
        if let Some(proto) = parse_forwarded_proto(value, cfg.max_proxy_hops) {
            return Ok(proto);
        }
        return Err(TransportRejectionKind::MalformedForwardedHeader);
    }

    if let Some(value) = util::single_header_str(headers, "x-forwarded-proto")
        .map_err(|_| TransportRejectionKind::MalformedForwardedHeader)?
    {
        if let Some(proto) = parse_x_forwarded_proto(value, cfg.max_proxy_hops) {
            return Ok(proto);
        }
        return Err(TransportRejectionKind::MalformedForwardedHeader);
    }

    Err(TransportRejectionKind::MissingForwardedHeader)
}

fn forwarded_entries(value: &str, max_hops: u8) -> Option<Vec<&str>> {
    split_forwarded_header(value, ',', usize::from(max_hops.max(1)))
}

fn split_forwarded_header(value: &str, delimiter: char, max_parts: usize) -> Option<Vec<&str>> {
    if value.is_empty() || value.len() > MAX_FORWARDED_HEADER_BYTES || max_parts == 0 {
        return None;
    }

    let mut parts = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (idx, character) in value.char_indices() {
        if !character.is_ascii() || character.is_control() {
            return None;
        }
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' if quoted => escaped = true,
            '\\' => return None,
            '"' => quoted = !quoted,
            character if character == delimiter && !quoted => {
                push_forwarded_part(&mut parts, value[start..idx].trim(), max_parts)?;
                start = idx + character.len_utf8();
            }
            _ => {}
        }
    }
    if quoted || escaped {
        return None;
    }
    push_forwarded_part(&mut parts, value[start..].trim(), max_parts)?;
    Some(parts)
}

fn push_forwarded_part<'a>(
    parts: &mut Vec<&'a str>,
    part: &'a str,
    max_parts: usize,
) -> Option<()> {
    if part.is_empty() || parts.len() >= max_parts {
        None
    } else {
        parts.push(part);
        Some(())
    }
}

fn forwarded_pair_value(entry: &str, requested_key: &str) -> Option<String> {
    split_forwarded_header(entry, ';', usize::MAX)?
        .into_iter()
        .try_fold(None, |found, pair| {
            let (key, value) = parse_forwarded_pair(pair)?;
            if key.eq_ignore_ascii_case(requested_key) {
                found.is_none().then_some(Some(value)).flatten().map(Some)
            } else {
                Some(found)
            }
        })
        .flatten()
}

fn parse_forwarded_pair(pair: &str) -> Option<(&str, String)> {
    let (key, raw_value) = pair.split_once('=')?;
    let key = key.trim();
    let raw_value = raw_value.trim();
    if !is_forwarded_token(key) || raw_value.is_empty() {
        return None;
    }
    parse_forwarded_value(raw_value).map(|value| (key, value))
}

fn parse_forwarded_value(raw_value: &str) -> Option<String> {
    if raw_value.starts_with('"') {
        parse_quoted_forwarded_value(raw_value)
    } else {
        raw_value
            .chars()
            .all(is_unquoted_forwarded_value_char)
            .then(|| raw_value.to_string())
    }
}

fn parse_quoted_forwarded_value(raw_value: &str) -> Option<String> {
    if !raw_value.ends_with('"') || raw_value.len() < 2 {
        return None;
    }
    let mut value = String::new();
    let mut escaped = false;
    for character in raw_value[1..raw_value.len() - 1].chars() {
        if !character.is_ascii() || character.is_control() {
            return None;
        }
        if escaped {
            value.push(character);
            escaped = false;
            continue;
        }
        match character {
            '\\' => escaped = true,
            '"' => return None,
            _ => value.push(character),
        }
    }
    (!escaped && !value.is_empty()).then_some(value)
}

fn is_forwarded_token(value: &str) -> bool {
    !value.is_empty()
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric()
                || matches!(
                    character,
                    '!' | '#'
                        | '$'
                        | '%'
                        | '&'
                        | '\''
                        | '*'
                        | '+'
                        | '-'
                        | '.'
                        | '^'
                        | '_'
                        | '`'
                        | '|'
                        | '~'
                )
        })
}

fn is_unquoted_forwarded_value_char(character: char) -> bool {
    character.is_ascii()
        && !character.is_ascii_whitespace()
        && !character.is_control()
        && !matches!(character, '"' | '\\' | ',' | ';' | '=')
}

fn parse_forwarded_proto(value: &str, max_hops: u8) -> Option<String> {
    let entries = forwarded_entries(value, max_hops)?;
    let nearest = entries.last()?;
    forwarded_pair_value(nearest, "proto")
        .and_then(|proto| is_forwarded_token(&proto).then(|| proto.to_ascii_lowercase()))
}

fn parse_x_forwarded_proto(value: &str, max_hops: u8) -> Option<String> {
    let values = value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .collect::<Vec<_>>();
    if values.is_empty() || values.len() > usize::from(max_hops.max(1)) {
        return None;
    }
    values.last().map(|proto| proto.to_ascii_lowercase())
}

fn normalize_forwarded_for(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value.starts_with('_') {
        return None;
    }

    if let Some(rest) = value.strip_prefix('[') {
        let (host, _) = rest.split_once(']')?;
        return host.parse::<IpAddr>().ok().map(|ip| ip.to_string());
    }

    if let Ok(ip) = value.parse::<IpAddr>() {
        return Some(ip.to_string());
    }

    value
        .split_once(':')
        .and_then(|(host, _)| host.parse::<IpAddr>().ok())
        .map(|ip| ip.to_string())
}

fn parse_forwarded_for(value: &str, max_hops: u8) -> Option<String> {
    let entries = forwarded_entries(value, max_hops)?;
    let nearest = entries.last()?;
    forwarded_pair_value(nearest, "for")
        .as_deref()
        .and_then(normalize_forwarded_for)
}

pub(super) fn rate_limit_subject(
    cfg: &TransportSecurityConfig,
    remote: Option<SocketAddr>,
    headers: &HeaderMap,
) -> Result<String, TransportRejectionKind> {
    let remote_addr = remote.ok_or(TransportRejectionKind::MissingRemoteAddr)?;
    let remote_ip = remote_addr.ip();
    if !cfg.require_tls_proxy {
        return Ok(remote_ip.to_string());
    }
    if !super::is_trusted_proxy(&cfg.trusted_proxies, &remote_ip) {
        return Err(TransportRejectionKind::UntrustedProxy);
    }
    let Some(forwarded) = util::single_header_str(headers, "forwarded")
        .map_err(|_| TransportRejectionKind::MalformedForwardedHeader)?
    else {
        return Ok(remote_ip.to_string());
    };
    parse_forwarded_for(forwarded, cfg.max_proxy_hops)
        .ok_or(TransportRejectionKind::MalformedForwardedHeader)
}

pub(super) fn sanitize_header_value(value: &str) -> String {
    const MAX_LEN: usize = 256;
    if value.len() <= MAX_LEN {
        value.to_owned()
    } else {
        let mut truncated = value[..MAX_LEN].to_owned();
        truncated.push_str("...");
        truncated
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TransportSecurityConfig;
    use ipnet::IpNet;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn parses_forwarded_proto_nearest_entry() {
        let proto = parse_forwarded_proto(
            "for=1.2.3.4;proto=https;by=proxy, for=5.6.7.8;proto=http",
            2,
        );
        assert_eq!(proto, Some("http".to_string()));
    }

    #[test]
    fn parse_forwarded_proto_respects_hop_limit() {
        let proto = parse_forwarded_proto("for=1.2.3.4;proto=http, for=5.6.7.8;proto=https", 1);
        assert_eq!(proto, None);

        let proto = parse_forwarded_proto("for=1.2.3.4;proto=http, for=5.6.7.8;proto=https", 2);
        assert_eq!(proto, Some("https".to_string()));
    }

    #[test]
    fn parse_forwarded_proto_ignores_quoted_delimiters() {
        let proto = parse_forwarded_proto(
            "for=\"198.51.100.10, still-one-hop\";proto=http, for=203.0.113.20;proto=https",
            2,
        );
        assert_eq!(proto, Some("https".to_string()));

        let proto = parse_forwarded_proto("for=\"198.51.100.10;not-a-pair\";proto=\"https\"", 1);
        assert_eq!(proto, Some("https".to_string()));
    }

    #[test]
    fn parse_forwarded_proto_rejects_malformed_pairs_and_quotes() {
        for value in [
            "for=\"198.51.100.10;proto=http, for=203.0.113.20;proto=https",
            "for=198.51.100.10;proto=https;broken",
            "for=198.51.100.10;proto=\"https",
            "for=198.51.100.10;proto=ht\\tps",
        ] {
            assert_eq!(parse_forwarded_proto(value, 2), None, "{value}");
        }
    }

    #[test]
    fn rate_limit_subject_accepts_quoted_forwarded_for() {
        let cfg = TransportSecurityConfig {
            trusted_proxies: vec![IpNet::from(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            require_tls_proxy: true,
            max_proxy_hops: 1,
            require_proxy_mtls: false,
            log_forwarded_values: false,
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            "forwarded",
            "for=\"[2001:4860:4860::8888]:443\";proto=https"
                .parse()
                .expect("test header value"),
        );

        assert_eq!(
            rate_limit_subject(&cfg, Some(([127, 0, 0, 1], 1234).into()), &headers),
            Ok("2001:4860:4860::8888".to_string())
        );
    }

    #[test]
    fn rate_limit_subject_uses_nearest_forwarded_for() {
        let mut cfg = TransportSecurityConfig {
            trusted_proxies: vec![IpNet::from(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            require_tls_proxy: true,
            max_proxy_hops: 2,
            require_proxy_mtls: false,
            log_forwarded_values: false,
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            "forwarded",
            "for=198.51.100.10;proto=https, for=203.0.113.20;proto=https"
                .parse()
                .expect("test header value"),
        );
        assert_eq!(
            rate_limit_subject(&cfg, Some(([127, 0, 0, 1], 1234).into()), &headers),
            Ok("203.0.113.20".to_string())
        );

        cfg.max_proxy_hops = 1;
        assert_eq!(
            rate_limit_subject(&cfg, Some(([127, 0, 0, 1], 1234).into()), &headers),
            Err(TransportRejectionKind::MalformedForwardedHeader)
        );
    }
}
