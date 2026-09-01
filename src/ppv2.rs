//! PROXY protocol v2, narrowed to what AWS Network Load Balancers actually send:
//! only 0x21, only AF_INET and AF_INET6. Anything reaching the listener directly
//! is hostile input, so every read is bounds-checked.
//!
//! Measured shapes: TCP 84 bytes, UDP 112. TLVs are 0x03 CRC32C, optional
//! 0xEA AWS/0x01 vpce-id, 0x04 NOOP padding.

pub const SIGNATURE: [u8; 12] = [
    0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
];

pub const TLV_AWS: u8 = 0xea;
pub const AWS_SUBTYPE_VPCE_ID: u8 = 0x01;

/// Signature (12) + command (1) + family (1) + length (2).
pub const PREAMBLE: usize = 16;

/// Version 2 + PROXY. Rejecting LOCAL means its address block is never reached.
const V2_PROXY: u8 = 0x21;

/// One type byte plus a two-byte length.
const TLV_HEADER: usize = 3;

/// Bounds memory per connection: `Need(len)` becomes Envoy's per-connection peek
/// buffer, so uncapped, 16 bytes of input reserves 64KB. Real headers are <= 112.
pub const MAX_HEADER: usize = 256;

/// Source and destination port, after the addresses.
const PORTS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Total bytes needed, not the remainder.
    Need(usize),
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header<'a> {
    /// Total header length; the payload starts here.
    pub len: usize,
    /// First 4 bytes for IPv4, all 16 for IPv6.
    pub src: [u8; 16],
    pub src_port: u16,
    pub is_v6: bool,
    /// PrivateLink endpoint id, or empty. Absent on traffic from the internet.
    pub vpce: &'a [u8],
}

pub fn parse(buf: &[u8]) -> Result<Header<'_>, Error> {
    // Separate from the compare below so the common path keeps a constant-length
    // signature compare; folding them costs 2x (4.4 -> 9.1 ns measured).
    if buf.len() < PREAMBLE {
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
    // Before Need(len), not after: see MAX_HEADER.
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
    // One runtime-sized path for both families; two constant-folded ones save
    // ~3ns and double the function.
    let addr_size = if is_v6 { 16 } else { 4 };
    let block_len = addr_size * 2 + PORTS;
    if body.len() < block_len {
        return Err(Error::Invalid);
    }

    // Block is src, dst, sport, dport -- so the source port sits at 2x the size.
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
/// A TLV claiming a length past the end stops the walk rather than failing the
/// header, because AWS pads with NOOP and length alone tells you nothing.
fn find_vpce(tlvs: &[u8]) -> &[u8] {
    let mut i = 0;
    while i + TLV_HEADER <= tlvs.len() {
        let value_len = u16::from_be_bytes([tlvs[i + 1], tlvs[i + 2]]) as usize;
        let end = i + TLV_HEADER + value_len;
        if end > tlvs.len() {
            break;
        }
        // First match wins: last-wins let a duplicate 0xEA decide the identity.
        // value_len > 1 so the subtype byte exists and the id is non-empty.
        if tlvs[i] == TLV_AWS && value_len > 1 && tlvs[i + TLV_HEADER] == AWS_SUBTYPE_VPCE_ID {
            return &tlvs[i + TLV_HEADER + 1..end];
        }
        i = end;
    }
    &[]
}
