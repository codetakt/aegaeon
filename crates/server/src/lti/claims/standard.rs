//! Generation profile for optional OIDC claims carried by LTI (Core 5.3.6).
//! Values are validated after mapping and are never silently rewritten.
mod time_zones;

pub(super) fn valid(name: &str, value: &str) -> bool {
    match name {
        "profile" | "picture" | "website" => super::super::validation::resource_url(value),
        "email" => email(value),
        "locale" => crate::metadata::language_tags::is_valid(value),
        "zoneinfo" => time_zones::NAMES.binary_search(&value).is_ok(),
        _ => true,
    }
}

fn atom(value: &str) -> bool {
    value.split('.').all(|part| {
        !part.is_empty()
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~".contains(&byte))
    })
}

fn quoted(value: &str) -> bool {
    let Some(inner) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) else {
        return false;
    };
    let mut escaped = false;
    for byte in inner.bytes() {
        if escaped {
            if !matches!(byte, b'\t' | 32..=126) {
                return false;
            }
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if !matches!(byte, b'\t' | 32..=33 | 35..=91 | 93..=126) {
            return false;
        }
    }
    !escaped
}

/// RFC5322 3.4.1 generation subset: dot-atom or quoted local part; domain
/// dot-atom or literal. No comments, folding, display name or obsolete syntax.
/// This establishes syntax, not mailbox control or deliverability.
fn email(value: &str) -> bool {
    if value.len() > 4096 || !value.is_ascii() {
        return false;
    }
    let Some((local, domain)) = value.rsplit_once('@') else {
        return false;
    };
    let literal = domain
        .strip_prefix('[')
        .and_then(|v| v.strip_suffix(']'))
        .is_some_and(|v| !v.is_empty() && v.bytes().all(|b| matches!(b, 33..=90 | 94..=126)));
    (atom(local) || quoted(local)) && (atom(domain) || literal)
}
