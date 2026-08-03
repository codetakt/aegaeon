use super::super::auth_code_key_digest;
use std::sync::Arc;

#[derive(Clone)]
pub(super) struct RedisAuthCodeKeyspace {
    prefix: Arc<str>,
}

impl RedisAuthCodeKeyspace {
    pub(super) fn new(prefix: String) -> Self {
        Self {
            prefix: Arc::from(prefix.into_boxed_str()),
        }
    }

    #[cfg(test)]
    pub(super) fn for_tests() -> Self {
        Self::new("authcode:v2:{authcode}".to_string())
    }

    pub(super) fn code(&self, code: &str) -> String {
        format!("{}:code:{}", self.prefix, auth_code_key_digest(code))
    }

    pub(super) fn exchange_lock(&self, code: &str) -> String {
        format!(
            "{}:exchange-lock:{}",
            self.prefix,
            auth_code_key_digest(code)
        )
    }

    pub(super) fn state(&self, state: &str) -> String {
        format!("{}:state:{}", self.prefix, auth_code_key_digest(state))
    }

    pub(super) fn nonce(&self, nonce: &str) -> String {
        format!("{}:nonce:{}", self.prefix, auth_code_key_digest(nonce))
    }

    pub(super) fn version(&self) -> String {
        format!("{}:version", self.prefix)
    }

    pub(super) fn state_index(&self) -> String {
        format!("{}:index:state", self.prefix)
    }

    pub(super) fn nonce_index(&self) -> String {
        format!("{}:index:nonce", self.prefix)
    }

    pub(super) fn placeholder(&self, kind: &str) -> String {
        format!("{}:{kind}:none", self.prefix)
    }

    #[cfg(test)]
    pub(super) fn code_scan_pattern(&self) -> String {
        format!("{}:code:*", self.prefix)
    }

    #[cfg(test)]
    pub(super) fn state_scan_pattern(&self) -> String {
        format!("{}:state:*", self.prefix)
    }

    #[cfg(test)]
    pub(super) fn nonce_scan_pattern(&self) -> String {
        format!("{}:nonce:*", self.prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exchange_lock_key_is_authorization_code_scoped_and_hashed() {
        let keyspace = RedisAuthCodeKeyspace::for_tests();

        let first = keyspace.exchange_lock("auth-code-a");
        let second = keyspace.exchange_lock("auth-code-b");

        assert_eq!(
            first,
            format!(
                "authcode:v2:{{authcode}}:exchange-lock:{}",
                auth_code_key_digest("auth-code-a")
            )
        );
        assert_ne!(first, second);
        assert!(!first.contains("auth-code-a"));
        assert!(first.contains(":exchange-lock:"));
    }
}
