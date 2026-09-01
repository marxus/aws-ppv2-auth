//! Turning a PROXY protocol header into an IPv6 address that policy can match.
//!
//! Policy engines here match addresses, not vpce-ids, so identity is synthesized
//! into one. Derived rather than mapped: adding a tenant is a policy rule and no
//! data-plane change.
//!
//! ```text
//! fd2a:5c1b:7e90 : 0001 : e3b1:45a8:c041:e80a
//! └── /48 ULA ──┘  └kind┘  └── 64-bit body ──┘
//!                    1 = sha256(vpce-id) truncated
//!                    4 = 4via6, client IPv4 in the low 32 bits
//! ```
//!
//! Reproduce a value: `printf %s vpce-… | sha256sum | cut -c1-16`. 64 bits is
//! ample -- AWS generates the ids so nobody can grind a collision, and at 10,000
//! tenants the birthday probability is ~10^-11.
//!
//! The address is a label, not a route: nothing is ever sent from it, so there is
//! no spoofing concern and no return path.
//!
//! Everything synthesized here is inside the ULA /48 and everything outside it is
//! a real client address. That buys two coarse rules -- `<ula>:1::/64` for any
//! tenant, `<ula>:4::/64` for any IPv4 client -- and lets an IPv4 /N map onto
//! /(96+N). IPv6 clients keep their real addresses, so write ordinary CIDRs.

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

    // 2. A real IPv6 client already is one. Keeps kind 4 purely IPv4, which is
    //    what makes /(96+N) safe: 2000::/3 reads as IPv4 32-63.x and used to
    //    collide with real IPv4 rules.
    if h.is_v6 {
        return h.src;
    }

    // 3. IPv4 in the low 32 bits, so a v4 /N becomes a v6 /(96+N).
    out[6..8].copy_from_slice(&KIND_VIA4.to_be_bytes());
    out[12..16].copy_from_slice(&h.src[..4]);
    out
}

/// Text form for set_remote_address, in a stack buffer.
///
/// Keeps std's formatter so the output stays canonical RFC 5952, but drops the
/// heap allocation `to_string()` would cost. 46 bytes is the longest IPv6 form.
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
    // Only the first 6 bytes are kept, so anything set below /48 would be
    // silently discarded -- and a `ula` that does not mean what it says is the
    // one config error that produces addresses nobody's rules match.
    if o[6..].iter().any(|&b| b != 0) {
        return Err("prefix has bits set below /48");
    }
    let mut p = [0u8; 6];
    p.copy_from_slice(&o[..6]);
    Ok(p)
}
