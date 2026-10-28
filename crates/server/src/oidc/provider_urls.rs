//! Supplied provider URLs: representation admission, never outbound authorization.
use super::OidcDiscovery;
use serde_json::{Map, Value};

const ENDPOINTS: &[&str] = &[
    "authorization_endpoint",
    "token_endpoint",
    "jwks_uri",
    "registration_endpoint",
    "revocation_endpoint",
    "introspection_endpoint",
    "pushed_authorization_request_endpoint",
    "device_authorization_endpoint",
];
const OP_ENDPOINTS: &[&str] = &["userinfo_endpoint", "end_session_endpoint"];
const INFORMATIONAL: &[&str] = &["service_documentation", "op_policy_uri", "op_tos_uri"];
const ALIASES: &[&str] = &[
    "token_endpoint",
    "revocation_endpoint",
    "introspection_endpoint",
    "pushed_authorization_request_endpoint",
    "registration_endpoint",
    "device_authorization_endpoint",
];

#[derive(Clone, Copy)]
enum Kind {
    Issuer,
    Endpoint,
    Informational,
}

fn valid(value: &str, kind: Kind) -> bool {
    if value
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || c == '\\')
    {
        return false;
    }
    let Ok(parsed) = url::Url::parse(value) else {
        return false;
    };
    if matches!(kind, Kind::Informational) {
        return true;
    }
    let Some((scheme, rest)) = value.split_once("://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    scheme.eq_ignore_ascii_case("https")
        && !authority.is_empty()
        && !authority.contains('@')
        && parsed.scheme() == "https"
        && parsed.host_str().is_some_and(|host| !host.is_empty())
        && parsed.username().is_empty()
        && parsed.password().is_none()
        && parsed.fragment().is_none()
        && (!matches!(kind, Kind::Issuer) || parsed.query().is_none())
}

fn supplied(
    parameters: &Map<String, Value>,
    field: &'static str,
    kind: Kind,
) -> Result<(), &'static str> {
    if parameters
        .get(field)
        .is_some_and(|value| !value.as_str().is_some_and(|value| valid(value, kind)))
    {
        return Err(field);
    }
    Ok(())
}

/// Partial roles may omit fields. Known optional nulls are rejected at source
/// admission; unknown nested values stay opaque, including alias extensions.
pub(crate) fn validate_supplied(
    role: &str,
    parameters: &Map<String, Value>,
) -> Result<(), &'static str> {
    let extras = match role {
        "openid_provider" => OP_ENDPOINTS,
        "oauth_authorization_server" => &[],
        _ => return Ok(()),
    };
    supplied(parameters, "issuer", Kind::Issuer)?;
    for field in ENDPOINTS.iter().chain(extras) {
        supplied(parameters, field, Kind::Endpoint)?;
    }
    for field in INFORMATIONAL {
        supplied(parameters, field, Kind::Informational)?;
    }
    if let Some(value) = parameters.get("mtls_endpoint_aliases") {
        let aliases = value
            .as_object()
            .filter(|aliases| !aliases.is_empty())
            .ok_or("mtls_endpoint_aliases")?;
        for field in ALIASES
            .iter()
            .copied()
            .chain((role == "openid_provider").then_some("userinfo_endpoint"))
        {
            supplied(aliases, field, Kind::Endpoint).map_err(|_| "mtls_endpoint_aliases")?;
        }
    }
    Ok(())
}

/// A typed alias object with no retained fields may originate from a legal
/// unknown-only raw object. Recheck retained values, never reconstruct its shape.
pub(crate) fn validate_typed(discovery: &OidcDiscovery) -> Result<(), &'static str> {
    for (field, value, kind) in [
        ("issuer", Some(discovery.issuer.as_str()), Kind::Issuer),
        (
            "authorization_endpoint",
            Some(discovery.authorization_endpoint.as_str()),
            Kind::Endpoint,
        ),
        (
            "token_endpoint",
            Some(discovery.token_endpoint.as_str()),
            Kind::Endpoint,
        ),
        (
            "jwks_uri",
            Some(discovery.jwks_uri.as_str()),
            Kind::Endpoint,
        ),
        (
            "userinfo_endpoint",
            discovery.userinfo_endpoint.as_deref(),
            Kind::Endpoint,
        ),
        (
            "registration_endpoint",
            discovery.registration_endpoint.as_deref(),
            Kind::Endpoint,
        ),
        (
            "end_session_endpoint",
            discovery.end_session_endpoint.as_deref(),
            Kind::Endpoint,
        ),
        (
            "revocation_endpoint",
            discovery.revocation_endpoint.as_deref(),
            Kind::Endpoint,
        ),
        (
            "introspection_endpoint",
            discovery.introspection_endpoint.as_deref(),
            Kind::Endpoint,
        ),
        (
            "pushed_authorization_request_endpoint",
            discovery.pushed_authorization_request_endpoint.as_deref(),
            Kind::Endpoint,
        ),
        (
            "device_authorization_endpoint",
            discovery.device_authorization_endpoint.as_deref(),
            Kind::Endpoint,
        ),
        (
            "service_documentation",
            discovery.service_documentation.as_deref(),
            Kind::Informational,
        ),
        (
            "op_policy_uri",
            discovery.op_policy_uri.as_deref(),
            Kind::Informational,
        ),
        (
            "op_tos_uri",
            discovery.op_tos_uri.as_deref(),
            Kind::Informational,
        ),
    ] {
        if value.is_some_and(|value| !valid(value, kind)) {
            return Err(field);
        }
    }
    if let Some(aliases) = &discovery.mtls_endpoint_aliases {
        for value in [
            &aliases.token_endpoint,
            &aliases.revocation_endpoint,
            &aliases.introspection_endpoint,
            &aliases.pushed_authorization_request_endpoint,
        ] {
            if value
                .as_deref()
                .is_some_and(|value| !valid(value, Kind::Endpoint))
            {
                return Err("mtls_endpoint_aliases");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod test_contract;
