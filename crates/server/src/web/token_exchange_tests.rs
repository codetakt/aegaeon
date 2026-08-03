use super::*;
use axum::{
    http::{header, HeaderValue, StatusCode},
    response::Response,
};

struct EnvVarGuard {
    key: &'static str,
    previous: Option<String>,
}

impl EnvVarGuard {
    fn new(key: &'static str, value: Option<&str>) -> Self {
        let previous = std::env::var(key).ok();
        match value {
            Some(value) => std::env::set_var(key, value),
            None => std::env::remove_var(key),
        }
        Self { key, previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        match self.previous.as_deref() {
            Some(value) => std::env::set_var(self.key, value),
            None => std::env::remove_var(self.key),
        }
    }
}

type TokenExchangeTestResult = Result<(), String>;

macro_rules! fail_test {
    ($($arg:tt)*) => {
        return Err(format!($($arg)*))
    };
}

macro_rules! must_ok {
    ($result:expr, $context:expr $(,)?) => {
        match $result {
            Ok(value) => value,
            Err(err) => fail_test!("{}: {:?}", $context, err),
        }
    };
}

macro_rules! must_err {
    ($result:expr, $context:expr $(,)?) => {
        match $result {
            Ok(_) => fail_test!("{}", $context),
            Err(err) => err,
        }
    };
}

macro_rules! must_some {
    ($value:expr, $context:expr $(,)?) => {
        match $value {
            Some(value) => value,
            None => fail_test!("{}", $context),
        }
    };
}

fn assert_response_no_store(response: &Response) {
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL),
        Some(&HeaderValue::from_static("no-store"))
    );
    assert_eq!(
        response.headers().get(header::PRAGMA),
        Some(&HeaderValue::from_static("no-cache"))
    );
}

fn require_error_response<T>(
    result: Result<T, Response>,
    context: &str,
) -> Result<Response, String> {
    match result {
        Err(response) => Ok(response),
        Ok(_) => Err(context.to_string()),
    }
}

fn par_draft(
    redirect_uri: Option<&str>,
    response_type: Option<&str>,
    code_challenge: Option<&str>,
    code_challenge_method: Option<&str>,
) -> ParResolvedDraft {
    ParResolvedDraft {
        resource: None,
        redirect_uri: redirect_uri.map(ToString::to_string),
        response_type: response_type.map(ToString::to_string),
        iss: None,
        state: None,
        code_challenge: code_challenge.map(ToString::to_string),
        code_challenge_method: code_challenge_method.map(ToString::to_string),
        scope: None,
        nonce: None,
        acr_values: None,
        max_age: None,
        authorization_details: None,
        request_object: None,
        request_object_claims: None,
    }
}

mod auth_session;
mod authorize_query;
mod error_responses;
mod expiry;
mod request_object_retention;
mod resource_request;
