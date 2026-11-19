//! Creation-time public identity; runtime selectors never allocate or rename it.

use super::host_validation::normalize_dns_name;

#[derive(Clone, Debug)]
pub(super) struct CanonicalIssuer {
    host: String,
}

impl CanonicalIssuer {
    pub(super) fn from_host(value: &str) -> Result<Self, &'static str> {
        const INVALID: &str = "issuer host must be an unambiguous DNS name";
        let host = normalize_dns_name(value, "issuer host").map_err(|_| INVALID)?;
        let parsed = url::Url::parse(&format!("https://{host}")).map_err(|_| INVALID)?;
        // WHATWG parsing accepts numeric IPv4 spellings that IpAddr rejects.
        // Never persist a DNS-looking host whose public URL names another host.
        if !matches!(parsed.host(), Some(url::Host::Domain(value)) if value == host) {
            return Err(INVALID);
        }
        Ok(Self { host })
    }

    pub(super) fn host(&self) -> &str {
        &self.host
    }

    pub(super) fn url(&self) -> String {
        format!("https://{}", self.host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_issuer_is_independent_of_topology() {
        for (input, expected) in [
            ("auth.example.com", "auth.example.com"),
            (" AUTH.Example.COM ", "auth.example.com"),
            ("xn--bcher-kva.example", "xn--bcher-kva.example"),
        ] {
            let issuer = CanonicalIssuer::from_host(input).unwrap();
            assert_eq!(issuer.host(), expected);
            assert_eq!(issuer.url(), format!("https://{expected}"));
        }
        let longest = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(longest.len(), 253);
        assert!(CanonicalIssuer::from_host(&longest).is_ok());
        assert!(CanonicalIssuer::from_host(&(longest + "d")).is_err());
    }

    #[test]
    fn issuer_rejects_url_components_and_ambiguous_hosts() {
        for input in [
            "",
            " ",
            "https://auth.example.com",
            "user@auth.example.com",
            "auth.example.com:443",
            "auth.example.com:8443",
            "auth.example.com/",
            "auth.example.com/path",
            "auth.example.com?query",
            "auth.example.com#fragment",
            "*.example.com",
            "auth.example.com.",
            "auth..example.com",
            "-auth.example",
            "auth-.example",
            "auth_example.com",
            "bücher.example",
            "localhost",
            "auth.localhost",
            "127.0.0.1",
            "8.8.8.8",
            "[::1]",
            "127.1",
            "0177.0.0.1",
            "0x7f000001",
            "2130706433",
            "123",
            "auth.example\\other",
            "auth.\nexample",
            "auth%2eexample.com",
            "xn--.example",
        ] {
            assert!(
                CanonicalIssuer::from_host(input).is_err(),
                "accepted {input:?}"
            );
        }
        assert!(CanonicalIssuer::from_host(&format!("{}.example", "a".repeat(64))).is_err());
    }
}
