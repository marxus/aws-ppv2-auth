//! Address synthesis: the three ordered cases, and the invariant that
//! everything synthesized lands inside the ULA /48 and nothing else does.

use ppv2_auth::identity::{self, format, parse_prefix, synthesize, Prefix, KIND_VIA4, KIND_VPCE};
use ppv2_auth::ppv2;
use std::net::Ipv6Addr;

const TEST_PREFIX: Prefix = [0xfd, 0x00, 0xde, 0xad, 0xbe, 0xef];

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
        &hdr_v4(b"vpce-0123456789abcdef0", [10, 0, 1, 28]),
    );
    let b = synthesize(
        TEST_PREFIX,
        &hdr_v4(b"vpce-0123456789abcdef0", [9, 9, 9, 9]),
    );
    // Derived from the id alone -- the client address must not perturb it.
    assert_eq!(a, b);
    assert_eq!(u16::from_be_bytes([a[6], a[7]]), KIND_VPCE);
    assert_eq!(format(a).as_str(), "fd00:dead:beef:1:7b53:e75b:6e3d:cfdb");
}

#[test]
fn different_tenants_land_on_different_addresses() {
    let a = synthesize(
        TEST_PREFIX,
        &hdr_v4(b"vpce-0123456789abcdef0", [1, 1, 1, 1]),
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
    assert_eq!(format(a).as_str(), "fd00:dead:beef:4::12c7:e6a1");
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
    let h = hdr_v6(b"", "2001:db8:10da:7800:eb7a::5837");
    let a = synthesize(TEST_PREFIX, &h);
    // Byte-identical, all 128 bits, and outside the ULA -- the invariant is
    // that everything this module synthesizes is inside the /48 and nothing
    // else is.
    assert_eq!(a, h.src);
    assert_ne!(a[..6], TEST_PREFIX[..]);

    // A tenant arriving over IPv6 is still a tenant: vpce branch comes first.
    let t = synthesize(
        TEST_PREFIX,
        &hdr_v6(b"vpce-0123456789abcdef0", "2001:db8::1"),
    );
    assert_eq!(u16::from_be_bytes([t[6], t[7]]), KIND_VPCE);
    assert_eq!(format(t).as_str(), "fd00:dead:beef:1:7b53:e75b:6e3d:cfdb");
}

#[test]
fn an_ipv6_client_cannot_collide_with_an_ipv4_rule() {
    // Regression guard. This pair used to synthesize the same address,
    // because both families shared the kind-4 body and 2a:05:d0:14 reads as
    // 42.5.208.20. Global unicast is 2000::/3, so EVERY v6 client landed in
    // IPv4 32-63.x.x.x -- the band holding 34/35 (GCP), 52/54 (AWS) and
    // 42/43 (APNIC).
    let v6 = synthesize(TEST_PREFIX, &hdr_v6(b"", "2001:db8:10da:7800:eb7a::5837"));
    let v4 = synthesize(TEST_PREFIX, &hdr_v4(b"", [42, 5, 208, 20]));
    assert_ne!(v6, v4);

    // And two v6 clients in one /32 stay distinct, rather than collapsing.
    let other = synthesize(TEST_PREFIX, &hdr_v6(b"", "2001:db8:ffff:9999::1"));
    assert_ne!(v6, other);
}

#[test]
fn prefix_parsing_insists_on_a_ula_slash_48() {
    assert_eq!(parse_prefix("fd00:dead:beef::/48").unwrap(), TEST_PREFIX);
    assert!(parse_prefix("fd00:dead:beef::").is_ok()); // bare form accepted
    assert_eq!(parse_prefix("2001:db8::/48"), Err("not unique-local"));
    assert_eq!(
        parse_prefix("fd00:dead:beef::/64"),
        Err("prefix must be /48")
    );
}

#[test]
fn to_u128_round_trips_the_wire_order() {
    let a = synthesize(TEST_PREFIX, &hdr_v4(b"", [18, 199, 230, 161]));
    let n = identity::to_u128(a);
    assert_eq!(n.to_be_bytes(), a);
}
