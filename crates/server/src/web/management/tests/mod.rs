use axum::{
    http::{header, HeaderValue},
    middleware,
    response::IntoResponse,
    Json, Router,
};

use crate::key_encryption::{
    decrypt_key_handle, encrypt_key_handle, load_key_encryption_key, KeyEncryptionKeyLoadError,
    KeyHandleEncryptionContext, KEY_ENCRYPTION_KEY_ENV, KEY_HANDLE_ENVELOPE_PREFIX,
};

use super::audit_redaction::redact_json_value;
use super::audit_time::decode_audit_cursor;
use super::http_boundary::management_security_middleware;
use super::scope::{role_allows_audit_read, role_allows_manage_lifecycle};

type ManagementTestResult = Result<(), Box<dyn std::error::Error>>;

macro_rules! fail_test {
    ($($arg:tt)*) => {
        return Err(std::io::Error::other(format!($($arg)*)).into())
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

include!("bootstrap_and_profiles.rs");
include!("policy_and_runtime.rs");
