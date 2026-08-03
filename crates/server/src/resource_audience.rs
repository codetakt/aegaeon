fn issuer_base(issuer: &str) -> &str {
    issuer.trim_end_matches('/')
}

#[must_use]
pub fn protected_resource(issuer: &str) -> String {
    format!("{}/resource", issuer_base(issuer))
}

#[must_use]
pub fn userinfo(issuer: &str) -> String {
    format!("{}/userinfo", issuer_base(issuer))
}

#[must_use]
pub fn upstream_refresh(issuer: &str) -> String {
    format!("{}/oauth/upstream/refresh", issuer_base(issuer))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_audiences_trim_issuer_trailing_slash() {
        assert_eq!(
            protected_resource("https://issuer.example/"),
            "https://issuer.example/resource"
        );
        assert_eq!(
            userinfo("https://issuer.example/"),
            "https://issuer.example/userinfo"
        );
        assert_eq!(
            upstream_refresh("https://issuer.example/"),
            "https://issuer.example/oauth/upstream/refresh"
        );
    }
}
