use std::net::{SocketAddr, ToSocketAddrs};

use super::is_non_routable;

/// DNS resolver for outbound HTTP clients that rejects non-routable results at
/// the same resolution boundary used for the TCP connection.
#[derive(Debug)]
pub struct NonRoutableDnsResolver;

impl reqwest::dns::Resolve for NonRoutableDnsResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addrs = resolve_host_for_outbound_client(&host)?;
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

pub(super) fn resolve_host_for_outbound_client(
    host: &str,
) -> Result<Vec<SocketAddr>, std::io::Error> {
    let addrs = format!("{host}:0")
        .to_socket_addrs()
        .map_err(|err| std::io::Error::other(format!("DNS resolution failed for {host}: {err}")))?
        .collect::<Vec<_>>();

    if addrs.is_empty() {
        return Err(std::io::Error::other(format!(
            "DNS resolution returned no addresses for {host}"
        )));
    }

    if let Some(ip) = addrs
        .iter()
        .map(std::net::SocketAddr::ip)
        .find(|ip| is_non_routable(*ip))
    {
        return Err(std::io::Error::other(format!(
            "DNS resolution for {host} returned non-routable IP: {ip}"
        )));
    }

    Ok(addrs)
}
