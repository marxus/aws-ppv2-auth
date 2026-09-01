//! Wire-format tests for the PROXY protocol v2 parser.
//!
//! `0x21` is written literally rather than imported. What is under test is the
//! byte on the wire, so asserting against a constant the parser also uses would
//! only prove it agrees with itself.

use aws_ppv2_identity::ppv2::{self, Error, AWS_SUBTYPE_VPCE_ID, SIGNATURE, TLV_AWS};

/// Version 2 + PROXY. The only 13th byte an NLB ever sends.
const V2_PROXY: u8 = 0x21;

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
    let h = ppv2::parse(&buf).unwrap();
    assert!(!h.is_v6);
    assert_eq!(h.vpce, b"vpce-028ff61de1d1fea8c");
    assert_eq!(&h.src[..4], &[10, 0, 1, 28]);
    assert_eq!(h.len, buf.len());
}

#[test]
fn internet_stream_header_has_no_vpce_id() {
    let buf = build(V2_PROXY, 0x11, &[18, 199, 230, 161], None);
    let h = ppv2::parse(&buf).unwrap();
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
    let h = ppv2::parse(&buf).unwrap();
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
        ppv2::parse(&build(0x20, 0x11, &[9, 9, 9, 9], None)),
        Err(Error::Invalid)
    );
}

#[test]
fn families_and_versions_aws_never_sends_are_rejected() {
    assert_eq!(
        ppv2::parse(&build(V2_PROXY, 0x00, &[], None)),
        Err(Error::Invalid)
    ); // UNSPEC
    assert_eq!(
        ppv2::parse(&build(V2_PROXY, 0x31, b"/", None)),
        Err(Error::Invalid)
    ); // AF_UNIX
    assert_eq!(
        ppv2::parse(&build(0x11, 0x11, &[1, 2, 3, 4], None)),
        Err(Error::Invalid)
    ); // v1
}

#[test]
fn incremental_reads_report_how_much_more_is_needed() {
    let buf = build(V2_PROXY, 0x11, &[1, 2, 3, 4], Some(b"vpce-abc"));
    assert_eq!(ppv2::parse(&buf[..8]), Err(Error::Need(16)));
    assert_eq!(ppv2::parse(&buf[..16]), Err(Error::Need(buf.len())));
    assert_eq!(
        ppv2::parse(&buf[..buf.len() - 1]),
        Err(Error::Need(buf.len()))
    );
    assert!(ppv2::parse(&buf).is_ok());
}

#[test]
fn rejects_non_proxy_protocol_without_waiting_for_more_bytes() {
    assert_eq!(ppv2::parse(b"GET / HTTP/1.1\r\n\r\n"), Err(Error::Invalid));
    assert_eq!(ppv2::parse(b"GET "), Err(Error::Invalid));
    assert_eq!(ppv2::parse(b""), Err(Error::Need(16)));
}

#[test]
fn a_tlv_claiming_more_than_is_present_does_not_panic() {
    // Hostile input, not AWS input: the walk must stop, not index past the end.
    let mut buf = build(V2_PROXY, 0x11, &[1, 2, 3, 4], Some(b"vpce-abc"));
    let claimed = (buf.len() - 16 + 4) as u16;
    buf[14..16].copy_from_slice(&claimed.to_be_bytes());
    buf.extend_from_slice(&[0, 0, 0, 0]);
    assert_eq!(ppv2::parse(&buf).unwrap().vpce, b"vpce-abc");

    // A TLV length that runs off the end entirely.
    let mut evil = build(V2_PROXY, 0x11, &[1, 2, 3, 4], None);
    evil.extend_from_slice(&[TLV_AWS, 0xff, 0xff, AWS_SUBTYPE_VPCE_ID]);
    let n = (evil.len() - 16) as u16;
    evil[14..16].copy_from_slice(&n.to_be_bytes());
    assert!(ppv2::parse(&evil).unwrap().vpce.is_empty());
}
