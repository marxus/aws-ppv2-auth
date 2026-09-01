//! PROXY protocol v2 as AWS Network Load Balancers actually send it.
//!
//! DELIBERATELY NOT A GENERAL PARSER. Everything the NLB never emits is rejected
//! outright rather than handled, because a narrower accepted input is a smaller
//! attack surface and less to get wrong. This module was already AWS-specific --
//! the 0xEA TLV is an AWS extension, not part of the base spec -- so pretending
//! to be general while depending on that TLV was the worst of both.
//!
//! Measured against a live NLB, this is the entire set of headers that arrives:
//!
//! ```text
//!   byte 12  0x21             version 2 + PROXY. Never LOCAL, never anything else.
//!   byte 13  0x11 / 0x21      TCP over IPv4 / IPv6   (header total  84 bytes)
//!            0x12 / 0x22      UDP over IPv4 / IPv6   (header total 112 bytes)
//!   TLVs     0x03 CRC32C, optional 0xEA AWS/0x01 vpce-id, 0x04 NOOP padding
//! ```
//!
//! What that lets us drop, versus a spec-complete parser:
//!
//!   * The command nibble. Only 0x21 is accepted, so the spec's "on LOCAL you
//!     MUST discard the address block and use the real endpoints" rule cannot be
//!     violated -- the block is never reached. Only proxies that health-check
//!     through PPv2 send LOCAL, and ours check :19003, which has no ppv2 filter.
//!   * AF_UNSPEC and AF_UNIX. Neither is reachable, so neither is a case. A
//!     consequence worth having: a kind-4 label now always carries a real IPv4.
//!   * The transport nibble. STREAM vs DGRAM is the *only* difference between the
//!     TCP and UDP headers, and nothing downstream reads it -- the address block
//!     size depends on the family alone.
//!   * A separate `wanted()`. How many bytes are still needed is carried by the
//!     error that says more are needed.
//!
//! What is deliberately KEPT, because AWS's good behaviour is not the threat
//! model -- anything that can reach the listener directly sends what it likes:
//! bounds are checked on every read, and a TLV claiming a length past the end of
//! the buffer stops the walk instead of indexing out of range. Rust would turn
//! that into a panic, and while the SDK's catch_unwind contains it, a panic per
//! hostile datagram is not a parser design.
//!
//! There is no "streaming" mode in PPv2 and the spec forbids the idea: "The
//! receiver must not start to parse an address before the whole address block is
//! received." So this reads incrementally and parses only once complete, never
//! the other way round.
//!
//! # Performance
//!
//! Two shapes in `parse` look like they could be tidier and are not, both
//! measured on a 112-byte PrivateLink header:
//!
//!   * The short-buffer case is handled separately so the common path keeps a
//!     CONSTANT-length signature compare. Folding the two into one
//!     `buf[..n] != SIGNATURE[..n]` reads better and costs 2x (4.4 -> 9.1 ns),
//!     because a runtime length turns the compare into a memcmp call.
//!   * `addr_size` is a runtime value rather than two constant-folded paths for
//!     the two families. That costs ~3ns, because the address copy then takes a
//!     runtime length -- 0.03ms per second at 10k conn/s, and it halves the
//!     function.

pub const SIGNATURE: [u8; 12] = [
    0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
];

pub const TLV_AWS: u8 = 0xea;
pub const AWS_SUBTYPE_VPCE_ID: u8 = 0x01;

/// Signature (12) + version/command (1) + family/transport (1) + length (2).
/// The payload of a complete header starts at `PREAMBLE + body_len`.
pub const PREAMBLE: usize = 16;

/// Version 2 + PROXY. The only 13th byte an NLB ever sends.
const V2_PROXY: u8 = 0x21;

/// A TLV is one type byte plus a two-byte length, then that many value bytes.
const TLV_HEADER: usize = 3;

/// Ceiling on the declared header length.
///
/// NOT a tidiness rule -- it is the only thing bounding memory per connection.
/// `parse` returns `Need(len)` from the declared length, the TCP filter feeds
/// that to `max_read_bytes`, and Envoy answers with
/// `make_unique<uint8_t[]>(len)` per connection (listener_filter_buffer_impl.cc
/// resetCapacity). Uncapped, 16 bytes of attacker input -- signature, 0x21, any
/// two length bytes -- reserves 65,551 of them and holds it until the listener
/// filter timeout. That is 4096x amplification for the cost of one small write.
///
/// Measured against a live NLB the largest header is 112 bytes (UDP over IPv6);
/// TCP is 84. 256 leaves room for TLVs AWS might add and still caps the ratio
/// at 16x.
pub const MAX_HEADER: usize = 256;

/// The address block carries a source and destination port after the addresses.
const PORTS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Not enough bytes yet. Ask Envoy for this many in total.
    Need(usize),
    /// Not a header this module accepts. Drop it, or pass it through when
    /// require_ppv2 is off -- but never label it.
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header<'a> {
    /// Total header length; the payload starts here.
    pub len: usize,
    /// Source address: the first 4 bytes for IPv4, all 16 for IPv6.
    pub src: [u8; 16],
    pub src_port: u16,
    pub is_v6: bool,
    /// The PrivateLink endpoint id from the 0xEA TLV, or empty. Its absence is
    /// itself the signal: measured, 0xEA is present on TCP, TLS and UDP through
    /// an endpoint and never on traffic arriving from the internet.
    pub vpce: &'a [u8],
}

pub fn parse(buf: &[u8]) -> Result<Header<'_>, Error> {
    // Short buffer first and separately -- see the module's Performance note
    // before folding this into the compare below.
    if buf.len() < PREAMBLE {
        // Reject a client that is not speaking PPv2 on its first bytes, rather
        // than stalling until the whole preamble arrives.
        let n = buf.len().min(SIGNATURE.len());
        if buf[..n] != SIGNATURE[..n] {
            return Err(Error::Invalid);
        }
        return Err(Error::Need(PREAMBLE));
    }
    if buf[..12] != SIGNATURE || buf[12] != V2_PROXY {
        return Err(Error::Invalid);
    }

    let len = PREAMBLE + u16::from_be_bytes([buf[14], buf[15]]) as usize;
    // Before Need(len), not after: this is what stops a 16-byte write from
    // reserving 64KB of Envoy's memory. See MAX_HEADER.
    if len > MAX_HEADER {
        return Err(Error::Invalid);
    }
    if buf.len() < len {
        return Err(Error::Need(len));
    }
    let body = &buf[PREAMBLE..len];

    // Byte 13 is family << 4 | transport; only the family is load-bearing.
    let is_v6 = match buf[13] >> 4 {
        0x1 => false,
        0x2 => true,
        _ => return Err(Error::Invalid),
    };
    // The block is src, dst, sport, dport -- so the source port sits at twice
    // the address size, and the whole block is that plus the two ports. One code
    // path for both families, deliberately; see the module's Performance note.
    let addr_size = if is_v6 { 16 } else { 4 };
    let block_len = addr_size * 2 + PORTS;
    if body.len() < block_len {
        return Err(Error::Invalid);
    }

    let mut src = [0u8; 16];
    src[..addr_size].copy_from_slice(&body[..addr_size]);
    let port_off = addr_size * 2;
    let src_port = u16::from_be_bytes([body[port_off], body[port_off + 1]]);

    Ok(Header {
        len,
        src,
        src_port,
        is_v6,
        vpce: find_vpce(&body[block_len..]),
    })
}

/// The AWS endpoint id from the 0xEA TLV, or empty.
///
/// Hostile input, not AWS input, decides the shape of this: a TLV claiming a
/// length past the end of the buffer stops the walk instead of indexing out of
/// range. Failing the whole header instead would be wrong -- AWS pads with NOOP
/// to a fixed size, so a trailer's length alone tells you nothing.
///
/// First match wins and the walk stops. Nothing after it is read, and last-wins
/// let a duplicate 0xEA decide the identity.
fn find_vpce(tlvs: &[u8]) -> &[u8] {
    let mut i = 0;
    while i + TLV_HEADER <= tlvs.len() {
        let value_len = u16::from_be_bytes([tlvs[i + 1], tlvs[i + 2]]) as usize;
        let end = i + TLV_HEADER + value_len;
        if end > tlvs.len() {
            break;
        }
        // value_len > 1 so the subtype byte exists and the id is non-empty.
        if tlvs[i] == TLV_AWS && value_len > 1 && tlvs[i + TLV_HEADER] == AWS_SUBTYPE_VPCE_ID {
            return &tlvs[i + TLV_HEADER + 1..end];
        }
        i = end;
    }
    &[]
}
