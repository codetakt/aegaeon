use super::{invalid, FederationError};

fn validate_https(value: &str) -> Result<url::Url, FederationError> {
    if value
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || c == '\\')
    {
        return Err(invalid("URL syntax"));
    }
    let (scheme, rest) = value
        .split_once("://")
        .ok_or_else(|| invalid("URL authority"))?;
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .ok_or_else(|| invalid("URL authority"))?;
    if !scheme.eq_ignore_ascii_case("https") || authority.is_empty() || authority.contains('@') {
        return Err(invalid("URL authority"));
    }
    let parsed = url::Url::parse(value).map_err(|_| invalid("URL syntax"))?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(invalid("URL syntax"));
    }
    Ok(parsed)
}

pub(in crate::federation) fn validate_identifier(value: &str) -> Result<(), FederationError> {
    if validate_https(value)?.query().is_some() {
        return Err(invalid("Entity Identifier"));
    }
    Ok(())
}

pub(in crate::federation) fn validate_endpoint(value: &str) -> Result<url::Url, FederationError> {
    validate_https(value)
}
