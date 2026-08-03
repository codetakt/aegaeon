use super::oauth_errors::json_error_with_iss;
use crate::util;
use axum::{http::StatusCode, response::Response};
use serde::Deserialize;

#[derive(Deserialize)]
pub(super) struct UpstreamTokenResponse {
    pub(super) id_token: Option<String>,
    pub(super) access_token: Option<String>,
    pub(super) token_type: Option<String>,
    pub(super) expires_in: Option<i64>,
    pub(super) refresh_token: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum UpstreamTokenResponseValidationError {
    MissingAccessToken,
    EmptyAccessToken,
    MissingTokenType,
    EmptyTokenType,
    UnsupportedTokenType,
    NonPositiveExpiresIn,
    EmptyRefreshToken,
    MissingIdToken,
    EmptyIdToken,
}

impl UpstreamTokenResponseValidationError {
    const fn reason(&self) -> &'static str {
        match self {
            Self::MissingAccessToken => "missing access_token",
            Self::EmptyAccessToken => "access_token is empty",
            Self::MissingTokenType => "missing token_type",
            Self::EmptyTokenType => "token_type is empty",
            Self::UnsupportedTokenType => "token_type is unsupported",
            Self::NonPositiveExpiresIn => "expires_in is invalid",
            Self::EmptyRefreshToken => "refresh_token is empty",
            Self::MissingIdToken => "missing id_token",
            Self::EmptyIdToken => "id_token is empty",
        }
    }

    pub(super) fn message(&self, context: UpstreamTokenResponseContext) -> String {
        format!("{} {}", context.description_prefix(), self.reason())
    }
}

#[derive(Clone, Copy)]
pub(super) enum UpstreamTokenResponseContext {
    AuthorizationCode,
    RefreshToken,
}

impl UpstreamTokenResponseContext {
    const fn description_prefix(self) -> &'static str {
        match self {
            Self::AuthorizationCode => "upstream token response",
            Self::RefreshToken => "upstream refresh response",
        }
    }
}

fn validate_upstream_common_token_response_shape(
    token_response: &UpstreamTokenResponse,
) -> Result<(), UpstreamTokenResponseValidationError> {
    match token_response.access_token.as_deref() {
        None => return Err(UpstreamTokenResponseValidationError::MissingAccessToken),
        Some(access_token) if access_token.trim().is_empty() => {
            return Err(UpstreamTokenResponseValidationError::EmptyAccessToken);
        }
        Some(_) => {}
    }
    match token_response.token_type.as_deref() {
        None => return Err(UpstreamTokenResponseValidationError::MissingTokenType),
        Some(token_type) if token_type.trim().is_empty() => {
            return Err(UpstreamTokenResponseValidationError::EmptyTokenType);
        }
        Some(token_type) if !token_type.eq_ignore_ascii_case("Bearer") => {
            return Err(UpstreamTokenResponseValidationError::UnsupportedTokenType);
        }
        Some(_) => {}
    }
    if token_response
        .expires_in
        .is_some_and(|expires_in| expires_in <= 0)
    {
        return Err(UpstreamTokenResponseValidationError::NonPositiveExpiresIn);
    }
    if token_response
        .refresh_token
        .as_deref()
        .is_some_and(|refresh_token| refresh_token.trim().is_empty())
    {
        return Err(UpstreamTokenResponseValidationError::EmptyRefreshToken);
    }
    Ok(())
}

pub(super) fn validate_upstream_authorization_code_token_response_shape(
    token_response: &UpstreamTokenResponse,
) -> Result<(), UpstreamTokenResponseValidationError> {
    validate_upstream_common_token_response_shape(token_response)?;
    match token_response.id_token.as_deref() {
        None => Err(UpstreamTokenResponseValidationError::MissingIdToken),
        Some(id_token) if id_token.trim().is_empty() => {
            Err(UpstreamTokenResponseValidationError::EmptyIdToken)
        }
        Some(_) => Ok(()),
    }
}

pub(super) fn validate_upstream_refresh_token_response_shape(
    token_response: &UpstreamTokenResponse,
) -> Result<(), UpstreamTokenResponseValidationError> {
    validate_upstream_common_token_response_shape(token_response)?;
    if token_response
        .id_token
        .as_deref()
        .is_some_and(|id_token| id_token.trim().is_empty())
    {
        return Err(UpstreamTokenResponseValidationError::EmptyIdToken);
    }
    Ok(())
}

pub(super) fn parse_upstream_token_response_body(
    body: &[u8],
    issuer_base: &str,
    invalid_description: &'static str,
) -> Result<UpstreamTokenResponse, Response> {
    util::deserialize_json_without_duplicate_object_keys::<UpstreamTokenResponse>(body).map_err(
        |_| {
            json_error_with_iss(
                StatusCode::BAD_GATEWAY,
                "server_error",
                Some(invalid_description),
                issuer_base,
            )
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), String>;
    const TEST_ISSUER: &str = "https://issuer.example";

    fn valid_upstream_refresh_token_response() -> UpstreamTokenResponse {
        UpstreamTokenResponse {
            id_token: None,
            access_token: Some("access-token".to_string()),
            token_type: Some("Bearer".to_string()),
            expires_in: Some(300),
            refresh_token: None,
        }
    }

    fn valid_upstream_authorization_code_token_response() -> UpstreamTokenResponse {
        UpstreamTokenResponse {
            id_token: Some("id-token".to_string()),
            access_token: Some("access-token".to_string()),
            token_type: Some("Bearer".to_string()),
            expires_in: Some(300),
            refresh_token: Some("refresh-token".to_string()),
        }
    }

    #[test]
    fn parse_upstream_token_response_body_accepts_valid_response() -> TestResult {
        let parsed = parse_upstream_token_response_body(
            br#"{"access_token":"access-token","token_type":"Bearer","expires_in":300}"#,
            TEST_ISSUER,
            "upstream token response invalid",
        )
        .map_err(|response| format!("unexpected parse failure: {}", response.status()))?;

        assert_eq!(parsed.access_token.as_deref(), Some("access-token"));
        assert_eq!(parsed.token_type.as_deref(), Some("Bearer"));
        Ok(())
    }

    #[test]
    fn parse_upstream_token_response_body_rejects_duplicate_keys() -> TestResult {
        let result = parse_upstream_token_response_body(
            br#"{"access_token":"first","access_token":"second","token_type":"Bearer"}"#,
            TEST_ISSUER,
            "upstream token response invalid",
        );

        let err = result
            .err()
            .ok_or_else(|| "duplicate upstream token response keys must fail closed".to_string())?;

        assert_eq!(err.status(), StatusCode::BAD_GATEWAY);
        Ok(())
    }

    #[test]
    fn upstream_refresh_token_response_requires_access_token() {
        let mut response = valid_upstream_refresh_token_response();
        assert!(validate_upstream_refresh_token_response_shape(&response).is_ok());

        response.access_token = None;
        assert_eq!(
            validate_upstream_refresh_token_response_shape(&response),
            Err(UpstreamTokenResponseValidationError::MissingAccessToken)
        );

        response.access_token = Some(" ".to_string());
        assert_eq!(
            validate_upstream_refresh_token_response_shape(&response),
            Err(UpstreamTokenResponseValidationError::EmptyAccessToken)
        );
    }

    #[test]
    fn upstream_refresh_token_response_rejects_ambiguous_or_empty_fields() {
        let mut response = valid_upstream_refresh_token_response();
        response.token_type = None;
        assert_eq!(
            validate_upstream_refresh_token_response_shape(&response),
            Err(UpstreamTokenResponseValidationError::MissingTokenType)
        );

        let mut response = valid_upstream_refresh_token_response();
        response.token_type = Some(" ".to_string());
        assert_eq!(
            validate_upstream_refresh_token_response_shape(&response),
            Err(UpstreamTokenResponseValidationError::EmptyTokenType)
        );

        let mut response = valid_upstream_refresh_token_response();
        response.token_type = Some("DPoP".to_string());
        assert_eq!(
            validate_upstream_refresh_token_response_shape(&response),
            Err(UpstreamTokenResponseValidationError::UnsupportedTokenType)
        );

        let mut response = valid_upstream_refresh_token_response();
        response.expires_in = Some(0);
        assert_eq!(
            validate_upstream_refresh_token_response_shape(&response),
            Err(UpstreamTokenResponseValidationError::NonPositiveExpiresIn)
        );

        let mut response = valid_upstream_refresh_token_response();
        response.refresh_token = Some("".to_string());
        assert_eq!(
            validate_upstream_refresh_token_response_shape(&response),
            Err(UpstreamTokenResponseValidationError::EmptyRefreshToken)
        );

        let mut response = valid_upstream_refresh_token_response();
        response.id_token = Some(" ".to_string());
        assert_eq!(
            validate_upstream_refresh_token_response_shape(&response),
            Err(UpstreamTokenResponseValidationError::EmptyIdToken)
        );
    }

    #[test]
    fn upstream_authorization_code_token_response_requires_id_token() {
        let mut response = valid_upstream_authorization_code_token_response();
        assert!(validate_upstream_authorization_code_token_response_shape(&response).is_ok());

        response.id_token = None;
        assert_eq!(
            validate_upstream_authorization_code_token_response_shape(&response),
            Err(UpstreamTokenResponseValidationError::MissingIdToken)
        );

        response.id_token = Some(" ".to_string());
        assert_eq!(
            validate_upstream_authorization_code_token_response_shape(&response),
            Err(UpstreamTokenResponseValidationError::EmptyIdToken)
        );
    }
}
