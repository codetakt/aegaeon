use axum::http::StatusCode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::web) enum UpstreamIdTokenSignatureError {
    HeaderInvalid,
    PayloadInvalid,
    AlgNotAllowed,
    AlgNotSupported,
    JwkAlgMismatch,
    RsaKeyInvalid,
    SignatureInvalid,
    CurveMismatch,
    EcKeyInvalid,
    KeyTypeMismatch,
    Internal(String),
    KeySelection(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::web) struct UpstreamIdTokenDecodeError {
    pub(in crate::web) status: StatusCode,
    pub(in crate::web) message: String,
}

impl UpstreamIdTokenDecodeError {
    pub(super) fn bad_gateway(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            message: message.into(),
        }
    }

    pub(super) fn internal(message: impl Into<String>) -> Self {
        let message = message.into();
        tracing::error!(
            target: "oauth",
            error = %message,
            "upstream id_token processing failed internally"
        );
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "upstream id_token processing failed internally".to_string(),
        }
    }
}

fn upstream_id_token_signature_error_message(err: UpstreamIdTokenSignatureError) -> String {
    match err {
        UpstreamIdTokenSignatureError::HeaderInvalid => {
            "upstream id_token header invalid".to_string()
        }
        UpstreamIdTokenSignatureError::PayloadInvalid => {
            "upstream id_token payload invalid".to_string()
        }
        UpstreamIdTokenSignatureError::AlgNotAllowed => {
            "upstream id_token alg not allowed".to_string()
        }
        UpstreamIdTokenSignatureError::AlgNotSupported => {
            "upstream id_token alg not supported".to_string()
        }
        UpstreamIdTokenSignatureError::JwkAlgMismatch => "upstream jwk alg mismatch".to_string(),
        UpstreamIdTokenSignatureError::RsaKeyInvalid => {
            "upstream id_token rsa key invalid".to_string()
        }
        UpstreamIdTokenSignatureError::SignatureInvalid => {
            "upstream id_token signature invalid".to_string()
        }
        UpstreamIdTokenSignatureError::CurveMismatch => {
            "upstream id_token curve mismatch".to_string()
        }
        UpstreamIdTokenSignatureError::EcKeyInvalid => {
            "upstream id_token ec key invalid".to_string()
        }
        UpstreamIdTokenSignatureError::KeyTypeMismatch => {
            "upstream id_token key type mismatch".to_string()
        }
        UpstreamIdTokenSignatureError::Internal(message)
        | UpstreamIdTokenSignatureError::KeySelection(message) => message,
    }
}

fn refreshed_upstream_id_token_signature_error_message(
    err: UpstreamIdTokenSignatureError,
) -> String {
    match err {
        UpstreamIdTokenSignatureError::HeaderInvalid => {
            "upstream refreshed id_token header invalid".to_string()
        }
        UpstreamIdTokenSignatureError::PayloadInvalid => {
            "upstream refreshed id_token payload invalid".to_string()
        }
        UpstreamIdTokenSignatureError::AlgNotAllowed => {
            "upstream refreshed id_token alg not allowed".to_string()
        }
        UpstreamIdTokenSignatureError::AlgNotSupported => {
            "upstream refreshed id_token alg not supported by discovery".to_string()
        }
        UpstreamIdTokenSignatureError::JwkAlgMismatch => {
            "upstream refreshed jwk alg mismatch".to_string()
        }
        UpstreamIdTokenSignatureError::RsaKeyInvalid => {
            "upstream refreshed id_token rsa key invalid".to_string()
        }
        UpstreamIdTokenSignatureError::SignatureInvalid => {
            "upstream refreshed id_token signature invalid".to_string()
        }
        UpstreamIdTokenSignatureError::CurveMismatch => {
            "upstream refreshed id_token curve mismatch".to_string()
        }
        UpstreamIdTokenSignatureError::EcKeyInvalid => {
            "upstream refreshed id_token ec key invalid".to_string()
        }
        UpstreamIdTokenSignatureError::KeyTypeMismatch => {
            "upstream refreshed id_token key type mismatch".to_string()
        }
        UpstreamIdTokenSignatureError::Internal(message) => message,
        UpstreamIdTokenSignatureError::KeySelection(message) => {
            message.strip_prefix("upstream ").map_or_else(
                || "upstream refreshed id_token signature invalid".to_string(),
                |rest| format!("upstream refreshed {rest}"),
            )
        }
    }
}

pub(super) fn upstream_id_token_signature_failure(
    err: UpstreamIdTokenSignatureError,
) -> UpstreamIdTokenDecodeError {
    match err {
        UpstreamIdTokenSignatureError::Internal(message) => {
            UpstreamIdTokenDecodeError::internal(message)
        }
        other => UpstreamIdTokenDecodeError::bad_gateway(
            upstream_id_token_signature_error_message(other),
        ),
    }
}

pub(in crate::web) fn refreshed_upstream_id_token_signature_failure(
    err: UpstreamIdTokenSignatureError,
) -> UpstreamIdTokenDecodeError {
    match err {
        UpstreamIdTokenSignatureError::Internal(message) => {
            UpstreamIdTokenDecodeError::internal(message)
        }
        other => UpstreamIdTokenDecodeError::bad_gateway(
            refreshed_upstream_id_token_signature_error_message(other),
        ),
    }
}
