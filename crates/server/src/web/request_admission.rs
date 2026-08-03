use super::{no_cache_header_error, no_cache_json_error_with_iss};
use crate::util;
use axum::http::{self, header, HeaderMap, StatusCode, Uri};
use axum::response::Response;
use url::form_urlencoded;

pub(in crate::web) const DEFAULT_QUERY_LIMITS: BoundedQueryLimits =
    BoundedQueryLimits::new(16 * 1024, 64, 64, 8 * 1024);

fn normalize_content_type(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let media_type = trimmed.split(';').next().unwrap_or("").trim();
    if media_type.is_empty() {
        return None;
    }
    Some(media_type.to_ascii_lowercase())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::web) struct BoundedQueryLimits {
    max_bytes: usize,
    max_params: usize,
    max_key_bytes: usize,
    max_value_bytes: usize,
}

impl BoundedQueryLimits {
    pub(in crate::web) const fn new(
        max_bytes: usize,
        max_params: usize,
        max_key_bytes: usize,
        max_value_bytes: usize,
    ) -> Self {
        Self {
            max_bytes,
            max_params,
            max_key_bytes,
            max_value_bytes,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::web) enum BoundedQueryRejection {
    QueryTooLarge,
    TooManyParameters,
    KeyTooLarge,
    ValueTooLarge,
}

impl BoundedQueryRejection {
    pub(in crate::web) fn description(self, label: &str) -> String {
        match self {
            Self::QueryTooLarge => format!("{label} query is too large"),
            Self::TooManyParameters => format!("too many {label} query parameters"),
            Self::KeyTooLarge => format!("{label} query parameter name is too large"),
            Self::ValueTooLarge => format!("{label} query parameter value is too large"),
        }
    }
}

pub(in crate::web) fn validate_raw_query(
    raw_query: Option<&str>,
    limits: BoundedQueryLimits,
) -> Result<(), BoundedQueryRejection> {
    let Some(query) = raw_query else {
        return Ok(());
    };
    if query.len() > limits.max_bytes {
        return Err(BoundedQueryRejection::QueryTooLarge);
    }

    form_urlencoded::parse(query.as_bytes()).try_fold(0usize, |count, (key, value)| {
        let count = count.saturating_add(1);
        if count > limits.max_params {
            return Err(BoundedQueryRejection::TooManyParameters);
        }
        if key.len() > limits.max_key_bytes {
            return Err(BoundedQueryRejection::KeyTooLarge);
        }
        if value.len() > limits.max_value_bytes {
            return Err(BoundedQueryRejection::ValueTooLarge);
        }
        Ok(count)
    })?;
    Ok(())
}

#[cfg(test)]
pub(in crate::web) fn bounded_query_pairs(
    raw_query: Option<&str>,
    limits: BoundedQueryLimits,
) -> Result<Vec<(String, String)>, BoundedQueryRejection> {
    validate_raw_query(raw_query, limits)?;
    Ok(raw_query
        .into_iter()
        .flat_map(|query| form_urlencoded::parse(query.as_bytes()))
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect())
}

fn bounded_query_error_response(error: BoundedQueryRejection, issuer_base: &str) -> Response {
    no_cache_json_error_with_iss(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        Some(&error.description("request")),
        issuer_base,
    )
}

#[derive(Clone, Copy)]
pub(super) struct QueryCredentialPolicy {
    allowed_sensitive_keys: &'static [&'static str],
}

impl QueryCredentialPolicy {
    pub(super) const fn reject_all() -> Self {
        Self {
            allowed_sensitive_keys: &[],
        }
    }

    pub(super) const fn allow(allowed_sensitive_keys: &'static [&'static str]) -> Self {
        Self {
            allowed_sensitive_keys,
        }
    }

    pub(super) fn permits(self, key: &str) -> bool {
        self.allowed_sensitive_keys
            .iter()
            .any(|allowed| key.eq_ignore_ascii_case(allowed))
    }
}

fn is_uri_credential_key(key: &str) -> bool {
    let canonical = key
        .chars()
        .filter(|ch| *ch != '_' && *ch != '-')
        .flat_map(char::to_lowercase)
        .collect::<String>();

    matches!(
        canonical.as_str(),
        "accesstoken"
            | "activationtoken"
            | "actortoken"
            | "actortokentype"
            | "apikey"
            | "apikeyvalue"
            | "assertion"
            | "bootstraptoken"
            | "clientassertion"
            | "clientassertiontype"
            | "clientsecret"
            | "clientsecretvalue"
            | "code"
            | "codeverifier"
            | "csrftoken"
            | "devicecode"
            | "idtoken"
            | "idtokenhint"
            | "keyhandle"
            | "password"
            | "passwordconfirmation"
            | "passwordhash"
            | "privatekey"
            | "privatekeypem"
            | "rawtoken"
            | "recoverytoken"
            | "redeemurl"
            | "refreshtoken"
            | "registrationaccesstoken"
            | "request"
            | "secretkey"
            | "subjecttoken"
            | "token"
            | "usercode"
    )
}

fn contains_disallowed_uri_credential_key(query: &str, policy: QueryCredentialPolicy) -> bool {
    !query.trim().is_empty()
        && form_urlencoded::parse(query.as_bytes()).any(|(key, _)| {
            let key = key.trim();
            is_uri_credential_key(key) && !policy.permits(key)
        })
}

pub(super) fn enforce_no_credentials_in_uri_with_policy(
    uri: &Uri,
    issuer_base: &str,
    policy: QueryCredentialPolicy,
) -> Result<(), Response> {
    let query = uri.query().unwrap_or("");
    validate_raw_query(uri.query(), DEFAULT_QUERY_LIMITS)
        .map_err(|error| bounded_query_error_response(error, issuer_base))?;
    if contains_disallowed_uri_credential_key(query, policy) {
        return Err(no_cache_json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("credentials or tokens must not be included in the request URI"),
            issuer_base,
        ));
    }
    Ok(())
}

pub(super) fn enforce_no_credentials_in_uri(uri: &Uri, issuer_base: &str) -> Result<(), Response> {
    enforce_no_credentials_in_uri_with_policy(uri, issuer_base, QueryCredentialPolicy::reject_all())
}

pub(super) fn is_upstream_callback_path(path: &str) -> bool {
    path.strip_prefix("/oauth/upstream/")
        .and_then(|rest| rest.split_once('/'))
        .is_some_and(|(connection, tail)| !connection.is_empty() && tail == "callback")
}

pub(super) fn uri_credential_policy_for_request(
    method: &http::Method,
    path: &str,
) -> QueryCredentialPolicy {
    match (method, path) {
        (&http::Method::GET, "/authorize") => QueryCredentialPolicy::allow(&["request"]),
        (&http::Method::GET, "/logout") => QueryCredentialPolicy::allow(&["id_token_hint"]),
        (&http::Method::GET, "/auth/activate" | "/auth/password/reset") => {
            QueryCredentialPolicy::allow(&["token"])
        }
        (&http::Method::GET, "/device") => QueryCredentialPolicy::allow(&["user_code"]),
        (&http::Method::GET, path) if is_upstream_callback_path(path) => {
            QueryCredentialPolicy::allow(&["code"])
        }
        _ => QueryCredentialPolicy::reject_all(),
    }
}

pub(super) fn enforce_no_credentials_in_request_uri(
    method: &http::Method,
    uri: &Uri,
    issuer_base: &str,
) -> Result<(), Response> {
    enforce_no_credentials_in_uri_with_policy(
        uri,
        issuer_base,
        uri_credential_policy_for_request(method, uri.path()),
    )
}

pub(super) fn enforce_no_credentials_in_authorize_uri(
    uri: &Uri,
    issuer_base: &str,
) -> Result<(), Response> {
    enforce_no_credentials_in_uri_with_policy(
        uri,
        issuer_base,
        QueryCredentialPolicy::allow(&["request"]),
    )
}

pub(super) fn enforce_no_credentials_in_logout_uri(
    uri: &Uri,
    issuer_base: &str,
) -> Result<(), Response> {
    enforce_no_credentials_in_uri_with_policy(
        uri,
        issuer_base,
        QueryCredentialPolicy::allow(&["id_token_hint"]),
    )
}

pub(super) fn enforce_no_credentials_in_callback_uri(
    uri: &Uri,
    issuer_base: &str,
) -> Result<(), Response> {
    enforce_no_credentials_in_uri_with_policy(
        uri,
        issuer_base,
        QueryCredentialPolicy::allow(&["code"]),
    )
}

pub(super) fn enforce_content_type(
    headers: &HeaderMap,
    expected: &'static str,
    issuer_base: &str,
) -> Result<(), Response> {
    let value = util::single_header_str(headers, header::CONTENT_TYPE.as_str())
        .map_err(|err| no_cache_header_error(issuer_base, "Content-Type", err))?
        .and_then(normalize_content_type);
    match value {
        Some(actual) if actual.eq_ignore_ascii_case(expected) => Ok(()),
        _ => Err(no_cache_json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some(&format!("Content-Type must be {expected}")),
            issuer_base,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), String>;

    #[test]
    fn bounded_query_rejects_oversized_inputs() -> TestResult {
        let limits = BoundedQueryLimits::new(64, 2, 4, 4);
        let oversized_query = format!("a={}", "1".repeat(65));
        for (query, expected) in [
            (
                oversized_query.as_str(),
                BoundedQueryRejection::QueryTooLarge,
            ),
            ("a=1&b=2&c=3", BoundedQueryRejection::TooManyParameters),
            ("abcde=1", BoundedQueryRejection::KeyTooLarge),
            ("a=12345", BoundedQueryRejection::ValueTooLarge),
        ] {
            let actual = validate_raw_query(Some(query), limits)
                .err()
                .ok_or_else(|| format!("query {query:?} must be rejected"))?;
            assert_eq!(actual, expected);
        }
        Ok(())
    }
}
