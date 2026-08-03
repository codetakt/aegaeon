#[must_use]
pub fn url_encode_component(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => vec![c.to_string()],
            _ => {
                let mut buf = [0u8; 4];
                c.encode_utf8(&mut buf);
                buf[..c.len_utf8()]
                    .iter()
                    .map(|b| format!("%{b:02X}"))
                    .collect::<Vec<_>>()
            }
        })
        .collect::<String>()
}

#[must_use]
pub fn append_code_and_state(base: &str, code: &str, state: Option<&str>, issuer: &str) -> String {
    let sep = if base.contains('?') { '&' } else { '?' };
    let mut out = format!("{}{}code={}", base, sep, url_encode_component(code));
    if let Some(s) = state {
        out.push_str("&state=");
        out.push_str(&url_encode_component(s));
    }
    out.push_str("&iss=");
    out.push_str(&url_encode_component(issuer));
    out
}

#[must_use]
pub fn append_error_and_state(
    base: &str,
    error: &str,
    error_description: Option<&str>,
    state: Option<&str>,
    issuer: &str,
) -> String {
    let sep = if base.contains('?') { '&' } else { '?' };
    let mut out = format!("{}{}error={}", base, sep, url_encode_component(error));
    if let Some(desc) = error_description {
        out.push_str("&error_description=");
        out.push_str(&url_encode_component(desc));
    }
    if let Some(s) = state {
        out.push_str("&state=");
        out.push_str(&url_encode_component(s));
    }
    out.push_str("&iss=");
    out.push_str(&url_encode_component(issuer));
    out
}

#[must_use]
pub fn append_state(base: &str, state: Option<&str>) -> String {
    let Some(state) = state else {
        return base.to_string();
    };
    let sep = if base.contains('?') { '&' } else { '?' };
    format!("{}{}state={}", base, sep, url_encode_component(state))
}
