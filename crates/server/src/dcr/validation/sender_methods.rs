use ffi::dcr::{SenderMethod, SenderMethodsMask};

pub(super) const MAX_SENDER_METHODS: usize = 8;
pub(super) const LABEL_TOKEN_METHOD_UNKNOWN: &str = "token_method_unknown";
pub(super) const LABEL_TOKEN_METHOD_UNIMPLEMENTED: &str = "token_method_unimplemented";
pub(super) const LABEL_SENDER_METHOD_UNKNOWN: &str = "sender_method_unknown";
pub(super) const LABEL_SENDER_METHOD_UNIMPLEMENTED: &str = "sender_method_unimplemented";

pub(crate) const RUNTIME_SUPPORTED_DCR_SENDER_METHODS: &[&str] = &["dpop"];

pub(super) fn runtime_supported_token_endpoint_auth_method(method: &str) -> bool {
    matches!(
        method,
        "none" | "client_secret_basic" | "client_secret_post" | "private_key_jwt"
    )
}

pub(crate) fn runtime_supported_sender_constrained_method(method: &str) -> bool {
    RUNTIME_SUPPORTED_DCR_SENDER_METHODS.contains(&method)
}

pub(super) fn build_sender_methods_mask(methods: &[String]) -> Result<SenderMethodsMask, String> {
    methods
        .iter()
        .map(String::as_str)
        .try_fold(SenderMethodsMask::empty(), |mask, formatted| {
            SenderMethod::from_label(formatted)
                .map(|sender_method| mask.with(sender_method))
                .ok_or_else(|| format!("unsupported sender-constrained method: {formatted}"))
        })
}
