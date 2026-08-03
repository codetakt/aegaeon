use axum::http::HeaderValue;
use url::Url;

pub(in crate::web::management) fn normalize_management_allowed_origin(
    raw: &str,
) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("origin must not be empty".to_string());
    }

    let parsed = Url::parse(trimmed).map_err(|err| format!("origin is not a URL: {err}"))?;
    if parsed.scheme() != "https" {
        return Err("origin must use https".to_string());
    }
    if parsed.host_str().is_none() {
        return Err("origin must include a host".to_string());
    }
    if crate::ssrf::validate_url_host_not_non_routable_literal(&parsed).is_err() {
        return Err("origin must not target non-routable hosts".to_string());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("origin must not include userinfo".to_string());
    }
    if parsed.query().is_some() {
        return Err("origin must not include a query".to_string());
    }
    if parsed.fragment().is_some() {
        return Err("origin must not include a fragment".to_string());
    }
    if parsed.path() != "/" {
        return Err("origin must not include a path".to_string());
    }

    let origin = parsed.origin().ascii_serialization();
    HeaderValue::from_str(&origin).map_err(|err| format!("origin is not a header value: {err}"))?;
    Ok(origin)
}
