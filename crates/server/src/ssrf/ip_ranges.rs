use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Returns true if an IPv4 address is non-globally-routable.
fn is_non_routable_v4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || ip.is_documentation()
        || ip.is_multicast()
        // 100.64.0.0/10 (RFC 6598 — Shared Address Space / CGNAT)
        || (octets[0] == 100 && (octets[1] & 0xC0) == 64)
        // 198.18.0.0/15 (RFC 2544 — Benchmarking)
        || (octets[0] == 198 && (octets[1] & 0xFE) == 18)
        // 240.0.0.0/4 (RFC 1112 — Reserved, excluding broadcast which is covered above)
        || octets[0] >= 240
        // 0.0.0.0/8 (RFC 791 — "This" network)
        || octets[0] == 0
}

/// Returns true if an IPv6 address contains a non-routable IPv4-mapped address.
///
/// Detects `::ffff:x.x.x.x` where the embedded IPv4 is non-routable.
fn is_ipv4_mapped_non_routable(ip: &Ipv6Addr) -> bool {
    let segments = ip.segments();
    if segments[0] == 0
        && segments[1] == 0
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0xFFFF
    {
        let Ok(seg6_hi) = u8::try_from(segments[6] >> 8) else {
            return false;
        };
        let Ok(seg6_lo) = u8::try_from(segments[6] & 0x00FF) else {
            return false;
        };
        let Ok(seg7_hi) = u8::try_from(segments[7] >> 8) else {
            return false;
        };
        let Ok(seg7_lo) = u8::try_from(segments[7] & 0x00FF) else {
            return false;
        };
        let v4 = Ipv4Addr::new(seg6_hi, seg6_lo, seg7_hi, seg7_lo);
        return is_non_routable_v4(v4);
    }
    false
}

fn is_special_use_v6(segments: &[u16; 8]) -> bool {
    // 100::/64 - discard-only prefix (RFC 6666).
    (segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0)
        // 64:ff9b:1::/48 - local-use IPv4/IPv6 translation (RFC 8215).
        || (segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 0x0001)
        // 2001::/32 - Teredo (RFC 4380).
        || (segments[0] == 0x2001 && segments[1] == 0)
        // 2001:2::/48 - benchmarking (RFC 5180).
        || (segments[0] == 0x2001 && segments[1] == 0x0002 && segments[2] == 0)
        // 2001:10::/28 - deprecated ORCHID (RFC 4843).
        || (segments[0] == 0x2001 && (segments[1] & 0xfff0) == 0x0010)
        // 2001:db8::/32 - documentation (RFC 3849).
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        // 2002::/16 - 6to4 (RFC 3056).
        || segments[0] == 0x2002
}

/// Returns true if an IPv6 address is non-globally-routable.
fn is_non_routable_v6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        // fc00::/7 — Unique Local Addresses (RFC 4193)
        || (segments[0] & 0xFE00) == 0xFC00
        // fe80::/10 — Link-Local Unicast (RFC 4291)
        || (segments[0] & 0xFFC0) == 0xFE80
        // fec0::/10 — deprecated Site-Local Unicast, still not globally routable.
        || (segments[0] & 0xFFC0) == 0xFEC0
        || is_special_use_v6(&segments)
        // IPv4-mapped addresses — check embedded v4
        || is_ipv4_mapped_non_routable(&ip)
}

/// Returns true if an IP address is non-globally-routable (private, reserved,
/// loopback, link-local, etc.).
///
/// Used for SSRF defense (P8-SSRF-1) to prevent outbound HTTP requests from
/// connecting to internal/cloud-metadata endpoints.
#[must_use]
pub fn is_non_routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_non_routable_v4(v4),
        IpAddr::V6(v6) => is_non_routable_v6(v6),
    }
}
