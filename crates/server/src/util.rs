use std::net::IpAddr;

mod bearer;
mod clock;
mod dpop_thumbprint;
mod http_headers;
mod json_admission;
mod redirect;
mod resource;
mod secrets;
pub use bearer::{
    bearer_invalid_token_response, extract_bearer_token, invalid_client_response,
    parse_bearer_authorization_header, BearerTokenError,
};
pub use clock::{
    log_clock_error, now_unix_epoch_secs, now_unix_epoch_secs_i64, unix_epoch_secs,
    unix_epoch_secs_i64, UnixEpochSecsError,
};
#[cfg(test)]
pub use dpop_thumbprint::compute_dpop_jkt_from_proof;
pub use dpop_thumbprint::{
    compute_dpop_jkt_from_proof_with_max_len, jwk_thumbprint_matches, jwk_thumbprint_uri_from_jkt,
};
pub use http_headers::{
    apply_auth_html_security_headers, apply_no_cache_headers, single_header_str, SingleHeaderError,
};
#[cfg(test)]
pub use json_admission::decode_compact_jwt_header_without_duplicate_keys;
pub(crate) use json_admission::signed_assertion_claims_error_from_jwt_claims_decode;
pub use json_admission::{
    decode_compact_jwt_header_without_duplicate_keys_with_max_len, decode_compact_jwt_payload,
    deserialize_json_without_duplicate_object_keys, validate_json_without_duplicate_object_keys,
    verify_signed_assertion_registered_claims, JsonAdmissionError, JsonObjectParseError,
    SignedAssertionClaimsError,
};
#[cfg(test)]
pub(crate) use json_admission::{
    deserialize_compat_json_object_without_duplicate_keys_result_for_surface,
    deserialize_compat_json_object_without_duplicate_keys_result_with_backend_for_surface,
};
pub use redirect::{
    append_code_and_state, append_error_and_state, append_state, url_encode_component,
};
pub use resource::{
    parse_authorization_details, parse_single_resource_indicator, validate_authorization_details,
    validate_resource_indicator,
};
pub use secrets::{constant_time_eq, secret_log_fingerprint};

pub(crate) fn is_loopback_host(host: &str) -> bool {
    let host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

pub(crate) fn canonical_url_host_port(url: &url::Url) -> Option<String> {
    let host = match url.host()? {
        url::Host::Domain(host) => host.to_ascii_lowercase(),
        url::Host::Ipv4(host) => host.to_string(),
        url::Host::Ipv6(host) => format!("[{host}]"),
    };
    let port = url.port();
    Some(match port {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

#[cfg(test)]
pub(crate) static SERVER_TEST_ENV_GUARD: std::sync::LazyLock<std::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(()));

#[cfg(test)]
pub(crate) static RAW_JSON_ENV_GUARD: std::sync::LazyLock<std::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(()));

#[cfg(test)]
pub(crate) static KEY_ENCRYPTION_KEY_ENV_GUARD: std::sync::LazyLock<std::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(()));

#[cfg(test)]
pub(crate) static KEY_ENCRYPTION_KEY_ASYNC_ENV_GUARD: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

#[cfg(test)]
mod tests;
