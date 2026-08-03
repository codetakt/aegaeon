use super::super::form_helpers::{form_parse_error_response, singleton_form_field};
use super::super::oauth_errors::no_cache_json_error_with_iss;
use axum::http::StatusCode;
use axum::response::Response;

#[derive(Default)]
pub(in crate::web) struct IntrospectForm {
    pub(super) token: Option<String>,
    pub(super) client_id: Option<String>,
    pub(super) client_secret: Option<String>,
    pub(super) client_assertion_type: Option<String>,
    pub(super) client_assertion: Option<String>,
}

pub(in crate::web) fn parse_introspect_form(
    form: Result<
        axum::extract::Form<Vec<(String, String)>>,
        axum::extract::rejection::FormRejection,
    >,
    issuer_base: &str,
) -> Result<IntrospectForm, Response> {
    let params = form
        .map(|axum::extract::Form(params)| params)
        .map_err(|_| form_parse_error_response(issuer_base))?;
    let _token_type_hint = singleton_form_field(&params, "token_type_hint", issuer_base)?;
    Ok(IntrospectForm {
        token: singleton_form_field(&params, "token", issuer_base)?,
        client_id: singleton_form_field(&params, "client_id", issuer_base)?,
        client_secret: singleton_form_field(&params, "client_secret", issuer_base)?,
        client_assertion_type: singleton_form_field(&params, "client_assertion_type", issuer_base)?,
        client_assertion: singleton_form_field(&params, "client_assertion", issuer_base)?,
    })
}

#[derive(Default)]
pub(in crate::web) struct RevokeForm {
    pub(super) token: Option<String>,
    pub(super) client_id: Option<String>,
    pub(super) client_secret: Option<String>,
    pub(super) client_assertion_type: Option<String>,
    pub(super) client_assertion: Option<String>,
}

pub(in crate::web) fn parse_revoke_form(
    form: Result<
        axum::extract::Form<Vec<(String, String)>>,
        axum::extract::rejection::FormRejection,
    >,
    issuer_base: &str,
) -> Result<RevokeForm, Response> {
    let params = form
        .map(|axum::extract::Form(params)| params)
        .map_err(|_| form_parse_error_response(issuer_base))?;
    let _token_type_hint = singleton_form_field(&params, "token_type_hint", issuer_base)?;
    Ok(RevokeForm {
        token: singleton_form_field(&params, "token", issuer_base)?,
        client_id: singleton_form_field(&params, "client_id", issuer_base)?,
        client_secret: singleton_form_field(&params, "client_secret", issuer_base)?,
        client_assertion_type: singleton_form_field(&params, "client_assertion_type", issuer_base)?,
        client_assertion: singleton_form_field(&params, "client_assertion", issuer_base)?,
    })
}

pub(super) fn required_lifecycle_token(
    token: Option<String>,
    issuer_base: &str,
) -> Result<String, Response> {
    match token {
        Some(token) if !token.trim().is_empty() => Ok(token),
        _ => Err(no_cache_json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("token parameter required"),
            issuer_base,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), String>;

    #[test]
    fn required_lifecycle_token_rejects_missing_token() -> TestResult {
        let response = required_lifecycle_token(None, "https://issuer.example")
            .err()
            .ok_or_else(|| "missing token must fail".to_string())?;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[test]
    fn required_lifecycle_token_rejects_blank_token() -> TestResult {
        let response = required_lifecycle_token(Some("  ".to_string()), "https://issuer.example")
            .err()
            .ok_or_else(|| "blank token must fail".to_string())?;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[test]
    fn required_lifecycle_token_accepts_non_blank_token() -> TestResult {
        assert_eq!(
            required_lifecycle_token(Some("token".to_string()), "https://issuer.example")
                .map_err(|response| format!("token should be accepted: {}", response.status()))?,
            "token"
        );
        Ok(())
    }
}
