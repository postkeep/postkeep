//! Which IP addresses a webhook may reach.
//!
//! Only globally routable unicast addresses are allowed. Everything else
//! (loopback, private and carrier-grade NAT ranges, link-local including
//! cloud metadata at `169.254.169.254` and `fd00:ec2::254`, unique local
//! IPv6 such as Fly's `fdaa::/16` private network, multicast, documentation
//! and reserved ranges) is refused, and IPv6 forms that embed an IPv4
//! address (mapped, compatible, NAT64, 6to4, Teredo) are judged by, or
//! refused because of, the address they carry.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Whether `ip` is a public, globally routable unicast address that a
/// webhook may be delivered to.
#[must_use]
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_v4(ip),
        IpAddr::V6(ip) => is_public_v6(ip),
    }
}

/// `(network, prefix length)` pairs of IPv4 ranges that are never public.
const BLOCKED_V4: &[(u32, u32)] = &[
    (0x0000_0000, 8),  // 0.0.0.0/8 "this network"
    (0x0A00_0000, 8),  // 10.0.0.0/8 private
    (0x6440_0000, 10), // 100.64.0.0/10 carrier-grade NAT (also Alibaba metadata)
    (0x7F00_0000, 8),  // 127.0.0.0/8 loopback
    (0xA9FE_0000, 16), // 169.254.0.0/16 link-local, cloud metadata
    (0xAC10_0000, 12), // 172.16.0.0/12 private
    (0xC000_0000, 24), // 192.0.0.0/24 IETF protocol assignments
    (0xC000_0200, 24), // 192.0.2.0/24 documentation
    (0xC058_6300, 24), // 192.88.99.0/24 6to4 relay anycast
    (0xC0A8_0000, 16), // 192.168.0.0/16 private
    (0xC612_0000, 15), // 198.18.0.0/15 benchmarking
    (0xC633_6400, 24), // 198.51.100.0/24 documentation
    (0xCB00_7100, 24), // 203.0.113.0/24 documentation
    (0xE000_0000, 4),  // 224.0.0.0/4 multicast
    (0xF000_0000, 4),  // 240.0.0.0/4 reserved, broadcast
];

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let bits = u32::from(ip);
    !BLOCKED_V4
        .iter()
        .any(|&(network, len)| bits >> (32 - len) == network >> (32 - len))
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    let bits = u128::from(ip);
    let in_range = |network: u128, len: u32| bits >> (128 - len) == network >> (128 - len);

    // IPv4-mapped (::ffff:a.b.c.d): judged as the IPv4 address.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_public_v4(v4);
    }
    // NAT64 (64:ff9b::/96): the IPv4 address is in the low 32 bits.
    if in_range(0x0064_ff9b_0000_0000_0000_0000_0000_0000, 96) {
        #[expect(
            clippy::cast_possible_truncation,
            reason = "keeps the low 32 bits on purpose"
        )]
        return is_public_v4(Ipv4Addr::from(bits as u32));
    }
    // Only global unicast (2000::/3) can be public. This rules out ::,
    // ::1, IPv4-compatible ::/96, unique local fc00::/7 (Fly 6PN, AWS
    // metadata fd00:ec2::254), link-local fe80::/10, site-local fec0::/10,
    // multicast ff00::/8, discard 100::/64 and local-use 64:ff9b:1::/48.
    if !in_range(0x2000_0000_0000_0000_0000_0000_0000_0000, 3) {
        return false;
    }
    let blocked: &[(u128, u32)] = &[
        (0x2001_0000_0000_0000_0000_0000_0000_0000, 23), // IETF protocol assignments, incl. Teredo 2001::/32
        (0x2001_0db8_0000_0000_0000_0000_0000_0000, 32), // documentation
        (0x2002_0000_0000_0000_0000_0000_0000_0000, 16), // 6to4: carries an IPv4 address
        (0x3fff_0000_0000_0000_0000_0000_0000_0000, 20), // documentation (RFC 9637)
    ];
    !blocked.iter().any(|&(network, len)| in_range(network, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public(text: &str) -> bool {
        is_public(
            text.parse()
                .unwrap_or_else(|_| unreachable!("bad test address {text}")),
        )
    }

    #[test]
    fn public_addresses_are_allowed() {
        for ip in [
            "1.1.1.1",
            "8.8.8.8",
            "17.253.144.10",
            "100.63.255.255",
            "100.128.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "192.169.0.1",
            "223.255.255.255",
            "2606:4700:4700::1111",
            "2a00:1450:4001:80b::200e",
            "::ffff:1.1.1.1",
            "64:ff9b::808:808",
        ] {
            assert!(public(ip), "{ip} should be public");
        }
    }

    #[test]
    fn internal_addresses_are_blocked() {
        for ip in [
            "0.0.0.0",
            "0.1.2.3",
            "10.0.0.1",
            "100.64.0.1",
            "100.100.100.200",
            "127.0.0.1",
            "127.255.255.254",
            "169.254.169.254",
            "169.254.170.2",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.170",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "239.255.255.250",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::127.0.0.1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::ffff:10.0.0.1",
            "64:ff9b::7f00:1",
            "64:ff9b::a9fe:a9fe",
            "64:ff9b:1::1",
            "100::1",
            "fc00::1",
            "fd00:ec2::254",
            "fdaa:0:1::3",
            "fe80::1",
            "fec0::1",
            "ff02::1",
            "2001::1",
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
            "2001:db8::1",
            "2002:7f00:1::1",
            "2002:a9fe:a9fe::1",
            "3fff::1",
        ] {
            assert!(!public(ip), "{ip} should be blocked");
        }
    }
}
