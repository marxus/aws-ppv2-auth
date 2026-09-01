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

pub const SIGNATURE: [u8; 12] = [
    0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
];

pub const TLV_AWS: u8 = 0xea;
pub const AWS_SUBTYPE_VPCE_ID: u8 = 0x01;

/// Version 2 + PROXY. The only 13th byte an NLB ever sends.
const V2_PROXY: u8 = 0x21;

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
    // The short-buffer case is handled first and separately, so the common path
    // keeps a CONSTANT-length signature compare. Folding the two into one
    // `buf[..n] != SIGNATURE[..n]` reads better and costs 2x on Parse (4.4 ->
    // 9.1 ns measured), because a runtime length turns it into a memcmp call.
    if buf.len() < 16 {
        // Reject a client that is not speaking PPv2 on its first bytes, rather
        // than stalling until 16 arrive.
        let n = buf.len().min(SIGNATURE.len());
        if buf[..n] != SIGNATURE[..n] {
            return Err(Error::Invalid);
        }
        return Err(Error::Need(16));
    }
    if buf[..12] != SIGNATURE || buf[12] != V2_PROXY {
        return Err(Error::Invalid);
    }

    let len = 16 + u16::from_be_bytes([buf[14], buf[15]]) as usize;
    if buf.len() < len {
        return Err(Error::Need(len));
    }
    let body = &buf[16..len];

    // Byte 13 is family << 4 | transport; only the family is load-bearing.
    let is_v6 = match buf[13] >> 4 {
        0x1 => false,
        0x2 => true,
        _ => return Err(Error::Invalid),
    };
    // The block is src, dst, sport, dport -- so the source port sits at twice
    // the address size, and the whole block is that plus the two ports. One code
    // path for both families rather than two constant-folded ones, which costs
    // ~3ns on Parse because the copy below takes a runtime length. Deliberate:
    // that is 0.03ms per second at 10k conn/s, and it halves this function.
    let addr_size = if is_v6 { 16 } else { 4 };
    let addr_len = addr_size * 2 + 4;
    if body.len() < addr_len {
        return Err(Error::Invalid);
    }

    let mut src = [0u8; 16];
    src[..addr_size].copy_from_slice(&body[..addr_size]);
    let sp = addr_size * 2;
    let src_port = u16::from_be_bytes([body[sp], body[sp + 1]]);

    // Walk the TLVs for the AWS endpoint id. A trailer claiming more than is
    // present stops the walk rather than failing the header: AWS pads with NOOP
    // to a fixed size, so length alone tells you nothing.
    let mut vpce: &[u8] = &[];
    let mut i = addr_len;
    while i + 3 <= body.len() {
        let tl = u16::from_be_bytes([body[i + 1], body[i + 2]]) as usize;
        let end = i + 3 + tl;
        if end > body.len() {
            break;
        }
        if body[i] == TLV_AWS && tl > 1 && body[i + 3] == AWS_SUBTYPE_VPCE_ID {
            vpce = &body[i + 4..end];
        }
        i = end;
    }

    Ok(Header {
        len,
        src,
        src_port,
        is_v6,
        vpce,
    })
}

// --------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// `fam` is the whole 13th byte, so tests can express UDP and bad families.
    fn build(ver_cmd: u8, fam: u8, src: &[u8], vpce: Option<&[u8]>) -> Vec<u8> {
        let addr_len = if fam >> 4 == 0x2 { 36 } else { 12 };
        let mut body = vec![0u8; addr_len];
        let n = src.len().min(addr_len);
        body[..n].copy_from_slice(&src[..n]);
        if let Some(v) = vpce {
            body.push(TLV_AWS);
            body.extend_from_slice(&((1 + v.len()) as u16).to_be_bytes());
            body.push(AWS_SUBTYPE_VPCE_ID);
            body.extend_from_slice(v);
        }
        let mut out = Vec::new();
        out.extend_from_slice(&SIGNATURE);
        out.push(ver_cmd);
        out.push(fam);
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn privatelink_datagram_header_yields_the_vpce_id() {
        // 0x12 = UDP over IPv4, the shape that arrives on the dns listener.
        let buf = build(
            V2_PROXY,
            0x12,
            &[10, 0, 1, 28],
            Some(b"vpce-028ff61de1d1fea8c"),
        );
        let h = parse(&buf).unwrap();
        assert!(!h.is_v6);
        assert_eq!(h.vpce, b"vpce-028ff61de1d1fea8c");
        assert_eq!(&h.src[..4], &[10, 0, 1, 28]);
        assert_eq!(h.len, buf.len());
    }

    #[test]
    fn internet_stream_header_has_no_vpce_id() {
        let buf = build(V2_PROXY, 0x11, &[18, 199, 230, 161], None);
        let h = parse(&buf).unwrap();
        assert!(h.vpce.is_empty());
        assert_eq!(&h.src[..4], &[18, 199, 230, 161]);
    }

    #[test]
    fn ipv6_source_and_port_come_from_the_right_offsets() {
        let addr: [u8; 16] = "2a05:d014:10da:7800:eb7a::5837"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets();
        // src(16) dst(16) sport(2) dport(2) -- sport at offset 32.
        let mut block = Vec::new();
        block.extend_from_slice(&addr);
        block.extend_from_slice(&[0u8; 16]);
        block.extend_from_slice(&40000u16.to_be_bytes());
        let buf = build(V2_PROXY, 0x21, &block, None);
        let h = parse(&buf).unwrap();
        assert!(h.is_v6);
        assert_eq!(h.src, addr);
        assert_eq!(h.src_port, 40000);
    }

    #[test]
    fn the_local_command_is_rejected_outright() {
        // The spec says a receiver must discard a LOCAL header's address block and
        // keep the real endpoints. Rejecting the command means the block is never
        // reached, so that rule cannot be violated. Before this, a LOCAL header
        // carrying 9.9.9.9 had that address adopted as the client's.
        assert_eq!(
            parse(&build(0x20, 0x11, &[9, 9, 9, 9], None)),
            Err(Error::Invalid)
        );
    }

    #[test]
    fn families_and_versions_aws_never_sends_are_rejected() {
        assert_eq!(
            parse(&build(V2_PROXY, 0x00, &[], None)),
            Err(Error::Invalid)
        ); // UNSPEC
        assert_eq!(
            parse(&build(V2_PROXY, 0x31, b"/", None)),
            Err(Error::Invalid)
        ); // AF_UNIX
        assert_eq!(
            parse(&build(0x11, 0x11, &[1, 2, 3, 4], None)),
            Err(Error::Invalid)
        ); // v1
    }

    #[test]
    fn incremental_reads_report_how_much_more_is_needed() {
        let buf = build(V2_PROXY, 0x11, &[1, 2, 3, 4], Some(b"vpce-abc"));
        assert_eq!(parse(&buf[..8]), Err(Error::Need(16)));
        assert_eq!(parse(&buf[..16]), Err(Error::Need(buf.len())));
        assert_eq!(parse(&buf[..buf.len() - 1]), Err(Error::Need(buf.len())));
        assert!(parse(&buf).is_ok());
    }

    #[test]
    fn rejects_non_proxy_protocol_without_waiting_for_more_bytes() {
        assert_eq!(parse(b"GET / HTTP/1.1\r\n\r\n"), Err(Error::Invalid));
        assert_eq!(parse(b"GET "), Err(Error::Invalid));
        assert_eq!(parse(b""), Err(Error::Need(16)));
    }

    #[test]
    fn a_tlv_claiming_more_than_is_present_does_not_panic() {
        // Hostile input, not AWS input: the walk must stop, not index past the end.
        let mut buf = build(V2_PROXY, 0x11, &[1, 2, 3, 4], Some(b"vpce-abc"));
        let claimed = (buf.len() - 16 + 4) as u16;
        buf[14..16].copy_from_slice(&claimed.to_be_bytes());
        buf.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(parse(&buf).unwrap().vpce, b"vpce-abc");

        // A TLV length that runs off the end entirely.
        let mut evil = build(V2_PROXY, 0x11, &[1, 2, 3, 4], None);
        evil.extend_from_slice(&[TLV_AWS, 0xff, 0xff, AWS_SUBTYPE_VPCE_ID]);
        let n = (evil.len() - 16) as u16;
        evil[14..16].copy_from_slice(&n.to_be_bytes());
        assert!(parse(&evil).unwrap().vpce.is_empty());
    }
}
