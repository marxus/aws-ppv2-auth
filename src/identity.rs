//! Turning a PROXY protocol header into an IPv6 address that policy can match.
//!
//! The idea: stop trying to pass tenant identity as a string, and synthesize an
//! address from it instead. Every policy engine in this stack already matches on
//! addresses -- Envoy network RBAC on a TCPRoute, HTTP RBAC on an HTTPRoute, and
//! CiliumNetworkPolicy -- but none of them can match a vpce-id.
//!
//! ```text
//! fd2a:5c1b:7e90 : 0001 : e3b1:45a8:c041:e80a
//! └── /48 ULA ──┘  └kind┘  └── 64-bit body ──┘
//!     yours, once     1 = sha256(vpce-id) truncated
//!                     4 = 4via6, client IPv4 in the low 32 bits
//! ```
//!
//! Derived, not mapped, so nothing has to be configured per tenant: adding a
//! tenant is one policy rule and no data-plane change. Reproduce a value with
//!
//! ```text
//! printf %s vpce-028ff61de1d1fea8c | sha256sum | cut -c1-16
//! ```
//!
//! 64 bits is ample. Collisions are accidental-only -- AWS generates the ids, so
//! nobody can grind for one -- and at 10,000 tenants the birthday probability is
//! around 10^-11.
//!
//! THE ADDRESS IS A LABEL, NOT A ROUTE. Nothing is ever sent from it, so there
//! is no spoofing concern, no return path, and nothing for Cilium's source-IP
//! verification to reject. It only has to survive as a declared value.
//!
//! A REAL IPv6 CLIENT IS PASSED THROUGH UNCHANGED, not encoded. Encoding exists
//! to give an identity that is not an address one (the vpce-id), and to lift
//! IPv4 into the v6 space so a single clientCIDRs list covers both. A v6 client
//! already is a v6 address, so synthesizing could only lose information -- and
//! stuffing 32 of its 128 bits into the kind-4 body used to collide with real
//! IPv4 rules, because global unicast 2000::/3 lands in 32.0.0.0-63.255.255.255
//! when read as IPv4. So for that path this filter just does what Envoy's own
//! proxy_protocol filter does: adopt the address the header declares.
//!
//! Everything this module synthesizes is therefore inside the ULA /48, and
//! anything outside it is a real client address.
//!
//! Two coarse rules fall out for free, which is what the kind nibble buys:
//! ```text
//! fd2a:5c1b:7e90:1::/64   any PrivateLink tenant
//! fd2a:5c1b:7e90:4::/64   any IPv4 internet client
//! ```
//! and an IPv4 CIDR /N maps mechanically onto /(96+N) -- unconditionally, now
//! that nothing else shares the kind-4 body.
//!
//! IPv6 clients need no coarse rule: they keep their real addresses, so write
//! ordinary CIDRs for them (2a05:d014:10da:7800::/56).

use crate::ppv2;
use sha2::{Digest, Sha256};
use std::net::Ipv6Addr;

pub const KIND_VPCE: u16 = 1;
pub const KIND_VIA4: u16 = 4;

/// The /48 ULA prefix. Per RFC 4193 this must be `fd` plus 40 random bits,
/// generated once for the deployment -- do not use fd00::/8 directly.
pub type Prefix = [u8; 6];

/// The address policy should match on. Three cases, in this order.
pub fn synthesize(prefix: Prefix, h: &ppv2::Header) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..6].copy_from_slice(&prefix);

    // 1. A vpce-id is not an address, so give it one.
    if !h.vpce.is_empty() {
        out[6..8].copy_from_slice(&KIND_VPCE.to_be_bytes());
        let digest = Sha256::digest(h.vpce);
        out[8..16].copy_from_slice(&digest[..8]);
        return out;
    }

    // 2. A real IPv6 client already is one. Passing it through keeps all 128
    //    bits and keeps kind 4 purely IPv4, which is what makes /(96+N) safe --
    //    see the cross-family collision in the module comment.
    if h.is_v6 {
        return h.src;
    }

    // 3. IPv4, lifted into the v6 space so one clientCIDRs list covers both.
    //    The address goes in the low 32 bits, so a v4 /N becomes a v6 /(96+N).
    //
    //    Always a real address now: the parser rejects AF_UNSPEC and the LOCAL
    //    command, so the bare `<ula>:4::` label is no longer reachable.
    out[6..8].copy_from_slice(&KIND_VIA4.to_be_bytes());
    out[12..16].copy_from_slice(&h.src[..4]);
    out
}

/// Text form for the ABI's set_remote_address, written into a stack buffer.
///
/// `Ipv6Addr::to_string()` is correct and canonical but costs a heap allocation
/// plus fmt machinery -- measured at ~160ns, more than everything else in this
/// filter put together. This keeps std's formatter (so the output is still
/// canonical RFC 5952, unlike the Zig version's hand-rolled group writer) and
/// only removes the allocation. 46 bytes is the longest possible IPv6 text form.
pub struct AddrText {
    buf: [u8; 46],
    len: usize,
}

impl AddrText {
    pub fn as_str(&self) -> &str {
        // The formatter only ever writes ASCII hex digits, ':' and '.'.
        std::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}

impl std::fmt::Write for AddrText {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        let end = self.len + s.len();
        if end > self.buf.len() {
            return Err(std::fmt::Error);
        }
        self.buf[self.len..end].copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

pub fn format(addr: [u8; 16]) -> AddrText {
    use std::fmt::Write;
    let mut t = AddrText {
        buf: [0u8; 46],
        len: 0,
    };
    // Infallible: 46 bytes always suffices, and AddrText only errors on overflow.
    let _ = write!(t, "{}", Ipv6Addr::from(addr));
    t
}

pub fn to_u128(addr: [u8; 16]) -> u128 {
    u128::from_be_bytes(addr)
}

/// Parses "fd2a:5c1b:7e90::/48" into the 6-byte prefix.
pub fn parse_prefix(text: &str) -> Result<Prefix, &'static str> {
    let (ip_text, bits) = match text.split_once('/') {
        Some((ip, b)) => (ip, Some(b.parse::<u8>().map_err(|_| "bad prefix length")?)),
        None => (text, None),
    };
    let ip: Ipv6Addr = ip_text.parse().map_err(|_| "bad IPv6 address")?;
    if let Some(b) = bits {
        if b != 48 {
            return Err("prefix must be /48");
        }
    }
    let o = ip.octets();
    if o[0] & 0xfe != 0xfc {
        return Err("not unique-local");
    }
    let mut p = [0u8; 6];
    p.copy_from_slice(&o[..6]);
    Ok(p)
}

// --------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PREFIX: Prefix = [0xfd, 0x2a, 0x5c, 0x1b, 0x7e, 0x90];

    fn hdr_v4(vpce: &[u8], v4: [u8; 4]) -> ppv2::Header<'_> {
        let mut src = [0u8; 16];
        src[..4].copy_from_slice(&v4);
        ppv2::Header {
            len: 0,
            src,
            src_port: 0,
            is_v6: false,
            vpce,
        }
    }

    fn hdr_v6<'a>(vpce: &'a [u8], addr: &str) -> ppv2::Header<'a> {
        let ip: Ipv6Addr = addr.parse().unwrap();
        ppv2::Header {
            len: 0,
            src: ip.octets(),
            src_port: 0,
            is_v6: true,
            vpce,
        }
    }

    #[test]
    fn vpce_id_hashes_into_the_kind_1_slash_64_stably() {
        let a = synthesize(
            TEST_PREFIX,
            &hdr_v4(b"vpce-028ff61de1d1fea8c", [10, 0, 1, 28]),
        );
        let b = synthesize(
            TEST_PREFIX,
            &hdr_v4(b"vpce-028ff61de1d1fea8c", [9, 9, 9, 9]),
        );
        // Derived from the id alone -- the client address must not perturb it.
        assert_eq!(a, b);
        assert_eq!(u16::from_be_bytes([a[6], a[7]]), KIND_VPCE);
        assert_eq!(format(a).as_str(), "fd2a:5c1b:7e90:1:e3b1:45a8:c041:e80a");
    }

    #[test]
    fn different_tenants_land_on_different_addresses() {
        let a = synthesize(
            TEST_PREFIX,
            &hdr_v4(b"vpce-028ff61de1d1fea8c", [1, 1, 1, 1]),
        );
        let b = synthesize(
            TEST_PREFIX,
            &hdr_v4(b"vpce-0bbbbbbbbbbbbbbbb", [1, 1, 1, 1]),
        );
        assert_ne!(a, b);
        // ...but share the "any PrivateLink tenant" /64.
        assert_eq!(a[..8], b[..8]);
    }

    #[test]
    fn no_vpce_id_falls_back_to_4via6_with_the_client_ipv4_in_the_low_32_bits() {
        let a = synthesize(TEST_PREFIX, &hdr_v4(b"", [18, 199, 230, 161]));
        assert_eq!(u16::from_be_bytes([a[6], a[7]]), KIND_VIA4);
        assert_eq!(&a[12..16], &[18, 199, 230, 161]);
        assert_eq!(format(a).as_str(), "fd2a:5c1b:7e90:4::12c7:e6a1");
    }

    #[test]
    fn the_two_kinds_never_collide() {
        let t = synthesize(TEST_PREFIX, &hdr_v4(b"vpce-abc", [0, 0, 0, 0]));
        let i = synthesize(TEST_PREFIX, &hdr_v4(b"", [18, 199, 230, 161]));
        assert_ne!(
            u16::from_be_bytes([t[6], t[7]]),
            u16::from_be_bytes([i[6], i[7]])
        );
    }

    #[test]
    fn a_real_ipv6_client_is_passed_through_not_encoded() {
        let h = hdr_v6(b"", "2a05:d014:10da:7800:eb7a::5837");
        let a = synthesize(TEST_PREFIX, &h);
        // Byte-identical, all 128 bits, and outside the ULA -- the invariant is
        // that everything this module synthesizes is inside the /48 and nothing
        // else is.
        assert_eq!(a, h.src);
        assert_ne!(a[..6], TEST_PREFIX[..]);

        // A tenant arriving over IPv6 is still a tenant: vpce branch comes first.
        let t = synthesize(
            TEST_PREFIX,
            &hdr_v6(b"vpce-028ff61de1d1fea8c", "2a05:d014::1"),
        );
        assert_eq!(u16::from_be_bytes([t[6], t[7]]), KIND_VPCE);
        assert_eq!(format(t).as_str(), "fd2a:5c1b:7e90:1:e3b1:45a8:c041:e80a");
    }

    #[test]
    fn an_ipv6_client_cannot_collide_with_an_ipv4_rule() {
        // Regression guard. This pair used to synthesize the same address,
        // because both families shared the kind-4 body and 2a:05:d0:14 reads as
        // 42.5.208.20. Global unicast is 2000::/3, so EVERY v6 client landed in
        // IPv4 32-63.x.x.x -- the band holding 34/35 (GCP), 52/54 (AWS) and
        // 42/43 (APNIC).
        let v6 = synthesize(TEST_PREFIX, &hdr_v6(b"", "2a05:d014:10da:7800:eb7a::5837"));
        let v4 = synthesize(TEST_PREFIX, &hdr_v4(b"", [42, 5, 208, 20]));
        assert_ne!(v6, v4);

        // And two v6 clients in one /32 stay distinct, rather than collapsing.
        let other = synthesize(TEST_PREFIX, &hdr_v6(b"", "2a05:d014:ffff:9999::1"));
        assert_ne!(v6, other);
    }

    #[test]
    fn prefix_parsing_insists_on_a_ula_slash_48() {
        assert_eq!(parse_prefix("fd2a:5c1b:7e90::/48").unwrap(), TEST_PREFIX);
        assert!(parse_prefix("fd2a:5c1b:7e90::").is_ok()); // bare form accepted
        assert_eq!(parse_prefix("2001:db8::/48"), Err("not unique-local"));
        assert_eq!(
            parse_prefix("fd2a:5c1b:7e90::/64"),
            Err("prefix must be /48")
        );
    }
}
