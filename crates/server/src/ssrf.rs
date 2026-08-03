// SSRF Defense Module (P8-SSRF-1, P8-SSRF-2)
//
// Provides IP validation and DNS pre-flight checks to prevent Server-Side
// Request Forgery attacks in the federation fetcher and anywhere else that
// makes outbound HTTP requests to user-influenced URLs.
//
// Blocked ranges:
//   IPv4: loopback (127/8), private (RFC 1918), link-local (169.254/16),
//         CGNAT (100.64/10), documentation (RFC 5737), benchmarking (198.18/15),
//         reserved (240/4), multicast (224/4), broadcast, this-host (0/8)
//   IPv6: loopback (::1), unspecified (::), unique-local (fc00::/7),
//         link-local (fe80::/10), site-local (fec0::/10), documentation
//         (2001:db8::/32), special-use transition/reserved ranges, multicast
//         (ff00::/8), IPv4-mapped private

mod ip_ranges;
mod redirect;
mod resolver;
mod url_validation;

pub use ip_ranges::is_non_routable;
pub use redirect::{build_redirect_policy, host_matches_domain_allowlist};
pub use resolver::NonRoutableDnsResolver;
pub use url_validation::{
    validate_url_host_not_non_routable_literal, validate_url_not_private, SsrfError,
};

#[cfg(test)]
mod tests;
