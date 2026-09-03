//! Turning a PROXY protocol header into an IPv6 address that policy can match.
//! See README for why. ONE ULA holds all three cases, told apart by the kind in
//! group 4 -- the invariant is that everything inside the /48 was synthesized
//! here and everything outside it is a real client address.
//!
//! ```text
//! fd0b:1003:5ec0 : 0b1a : 0000 : 0007 : 0a00:011c   KIND_SITE, an onboarded tenant
//! fd0b:1003:5ec0 : 0001 : 7b53:e75b   : 0a00:011c   KIND_VPCE, a tenant no site claims
//! fd0b:1003:5ec0 : 0004 : 0000:0000   : 0a00:011c   KIND_ADDR, no vpce-id at all
//! └── /48 ULA ──┘  └kind┘  └ body ───┘  client IPv4
//! ```
//!
//! 0xb1a spells "via" the way tailscale's own 4via6 range does, and the site sits
//! in group 6 where tailscale keeps it -- so a site address is the same SHAPE as
//! a 4via6 address without being one. It deliberately is not: 4via6 translation
//! is keyed to tailscale's own prefix inside the client, so an address here is an
//! identity and never a route. Routes stay tailscale's; identity is ours.
//!
//! The kind-1 hash is 32 bits rather than 64. It only ever labels STRANGERS now
//! -- an onboarded tenant has an allocated site -- and a mined collision costs
//! ~2^32 endpoint creations, so the width buys nothing next to carrying the
//! address that says WHICH machine called.

use crate::cidr;
use crate::ppv2;
use sha2::{Digest, Sha256};
use std::net::{Ipv4Addr, Ipv6Addr};

/// An onboarded tenant. 0xb1a spells "via" the way tailscale's own range does,
/// and it is a KIND here rather than a second prefix -- one /48 holds all three.
pub const KIND_SITE: u16 = 0x0b1a;
pub const KIND_VPCE: u16 = 1;
pub const KIND_ADDR: u16 = 4;

/// The /48 ULA prefix: per RFC 4193, `fd` + 40 random bits, generated once.
pub type Prefix = [u8; 6];

/// One onboarded tenant: the identifiers that resolve to it, and the id they resolve to.
#[derive(Debug)]
pub struct Site {
    pub id: u16,
    /// Exact `vpce-id` matches. AWS-assigned, so a tenant cannot choose one.
    pub vpce: Vec<Box<[u8]>>,
    /// Source prefixes, IPv4 held as ::ffff:a.b.c.d so one Set covers both families.
    pub cidrs: cidr::Set,
}

/// What a header is encoded against. Present iff the filter parses PPv2 itself.
#[derive(Debug)]
pub struct Scheme {
    pub prefix: Prefix,
    /// Empty means nothing is onboarded, so every header falls to kind 1 or 4.
    pub sites: Vec<Site>,
}

/// A resolved site, and whether the header's source is the tenant's OWN address.
struct SiteMatch {
    id: u16,
    inner: bool,
}

/// IPv4 as ::ffff:a.b.c.d, so site prefixes of both families live in one cidr::Set.
fn mapped(h: &ppv2::Header) -> u128 {
    if h.is_v6 {
        return to_u128(h.src);
    }
    let mut out = [0u8; 16];
    out[10] = 0xff;
    out[11] = 0xff;
    out[12..16].copy_from_slice(&h.src[..4]);
    to_u128(out)
}

/// vpce-id first: an AWS-assigned id outranks an address the sender chose.
///
/// A vpce match means the source is the tenant's own machine -- measured, the NLB
/// reports the consumer-side 5-tuple through an endpoint. A CIDR match means it is
/// a NAT in front of them, which is not an address in their space, so `inner` is
/// false and the low 32 bits stay zero.
///
/// Linear over sites, because each cidr::Set rejects out-of-span in one compare.
/// ponytail: fine to low hundreds of tenants; sort the ranges across sites if that
/// stops being true.
fn site_of(sites: &[Site], h: &ppv2::Header) -> Option<SiteMatch> {
    if !h.vpce.is_empty() {
        if let Some(s) = sites.iter().find(|s| s.vpce.iter().any(|v| &**v == h.vpce)) {
            return Some(SiteMatch {
                id: s.id,
                inner: true,
            });
        }
    }
    let addr = mapped(h);
    sites
        .iter()
        .find(|s| s.cidrs.contains(addr))
        .map(|s| SiteMatch {
            id: s.id,
            inner: false,
        })
}

/// Four cases, and the order matters.
pub fn synthesize(scheme: &Scheme, h: &ppv2::Header) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..6].copy_from_slice(&scheme.prefix);

    // An onboarded tenant: kind b1a, then the site, then the machine.
    if let Some(m) = site_of(&scheme.sites, h) {
        out[6..8].copy_from_slice(&KIND_SITE.to_be_bytes());
        out[10..12].copy_from_slice(&m.id.to_be_bytes());
        // Zero unless the source is the tenant's own address: <via>:0:<site>:: reads
        // as "this tenant, machine unknown" and stays inside the tenant's own /96.
        if m.inner && !h.is_v6 {
            out[12..16].copy_from_slice(&h.src[..4]);
        }
        return out;
    }

    // A vpce-id is not an address, so give it one.
    if !h.vpce.is_empty() {
        out[6..8].copy_from_slice(&KIND_VPCE.to_be_bytes());
        let digest = Sha256::digest(h.vpce);
        out[8..12].copy_from_slice(&digest[..4]);
        // The tenant's own machine, same as the site space. Zero for a v6 client.
        if !h.is_v6 {
            out[12..16].copy_from_slice(&h.src[..4]);
        }
        return out;
    }

    // Pass-through keeps kind 4 purely IPv4 -- 2000::/3 read as IPv4 used to collide with real rules.
    if h.is_v6 {
        return h.src;
    }

    // Low 32 bits, so a v4 /N becomes a v6 /(96+N).
    out[6..8].copy_from_slice(&KIND_ADDR.to_be_bytes());
    out[12..16].copy_from_slice(&h.src[..4]);
    out
}

/// RFC 5952 text via std's formatter, in a stack buffer -- no `to_string()` heap alloc.
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
    // Infallible: 46 bytes always suffices.
    let _ = write!(t, "{}", Ipv6Addr::from(addr));
    t
}

/// The raw header source, for the log. IPv4 as dotted quad, not ::ffff: form --
/// what is wanted here is what the tenant's own machine calls itself.
pub fn format_src(src: [u8; 16], is_v6: bool) -> AddrText {
    use std::fmt::Write;
    let mut t = AddrText {
        buf: [0u8; 46],
        len: 0,
    };
    if is_v6 {
        let _ = write!(t, "{}", Ipv6Addr::from(src));
    } else {
        let _ = write!(t, "{}", Ipv4Addr::new(src[0], src[1], src[2], src[3]));
    }
    t
}

pub fn to_u128(addr: [u8; 16]) -> u128 {
    u128::from_be_bytes(addr)
}

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
    // Only the first 6 bytes are kept, so lower bits would vanish silently.
    if o[6..].iter().any(|&b| b != 0) {
        return Err("prefix has bits set below /48");
    }
    let mut p = [0u8; 6];
    p.copy_from_slice(&o[..6]);
    Ok(p)
}
