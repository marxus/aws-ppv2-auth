//! Address synthesis: the four ordered cases, and the invariant that everything
//! synthesized lands inside the one ULA /48 and nothing else does.

use ppv2_auth::cidr;
use ppv2_auth::identity::{
    self, format, parse_prefix, synthesize, Prefix, Scheme, Site, KIND_ADDR, KIND_SITE, KIND_VPCE,
};
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

/// No site table: everything falls to the ULA, which is the pre-v0.6.0 behaviour.
fn plain() -> Scheme {
    Scheme::new(TEST_PREFIX, Vec::new())
}

/// Site 7 by endpoint id, site 2 by NAT prefix -- the two ways a tenant is named.
fn with_sites() -> Scheme {
    Scheme::new(
        TEST_PREFIX,
        vec![
            Site {
                id: 7,
                vpce: vec![b"vpce-0123456789abcdef0".to_vec().into_boxed_slice()],
                cidrs: cidr::build("").unwrap(),
            },
            Site {
                id: 2,
                vpce: Vec::new(),
                // ::ffff: form, which is how config.rs lifts an IPv4 prefix.
                cidrs: cidr::build("::ffff:203.0.113.0/120").unwrap(),
            },
        ],
    )
}

// --- the site space ---------------------------------------------------------

#[test]
fn an_onboarded_tenant_becomes_a_real_tailscale_4via6_address() {
    let a = synthesize(
        &with_sites(),
        &hdr_v4(b"vpce-0123456789abcdef0", [10, 0, 1, 28]),
    );
    // Byte-identical to `tailscale debug via 7 10.0.1.28/32`, which is the claim
    // the whole site space rests on -- verified against the real binary.
    assert_eq!(format(a).as_str(), "fd00:dead:beef:b1a:0:7:a00:11c");
    assert_eq!(u16::from_be_bytes([a[10], a[11]]), 7);
    assert_eq!(&a[12..16], &[10, 0, 1, 28]);
    // Bits 64-79 are tailscale's padding and must stay zero, or it is not a via address.
    assert_eq!(&a[8..10], &[0, 0]);
}

#[test]
fn a_site_matched_by_nat_prefix_carries_no_machine() {
    // Over the internet the tenant's own address was rewritten, so there is none
    // to encode. Zero reads as "this tenant, machine unknown" and stays inside
    // the tenant's own /96.
    let a = synthesize(&with_sites(), &hdr_v4(b"", [203, 0, 113, 7]));
    assert_eq!(format(a).as_str(), "fd00:dead:beef:b1a:0:2::");
    assert_eq!(&a[12..16], &[0, 0, 0, 0]);
}

#[test]
fn an_onboarded_tenant_over_ipv6_has_no_ipv4_to_carry() {
    let a = synthesize(
        &with_sites(),
        &hdr_v6(b"vpce-0123456789abcdef0", "2001:db8::1"),
    );
    assert_eq!(format(a).as_str(), "fd00:dead:beef:b1a:0:7::");
    // Still the site, so a /96 rule for that tenant still admits it.
    assert_eq!(u16::from_be_bytes([a[10], a[11]]), 7);
}

#[test]
fn the_whole_site_range_fits_in_group_six() {
    let s = Scheme::new(
        TEST_PREFIX,
        vec![Site {
            id: 65535,
            vpce: vec![b"vpce-0123456789abcdef0".to_vec().into_boxed_slice()],
            cidrs: cidr::build("").unwrap(),
        }],
    );
    let a = synthesize(&s, &hdr_v4(b"vpce-0123456789abcdef0", [10, 0, 1, 28]));
    assert_eq!(format(a).as_str(), "fd00:dead:beef:b1a:0:ffff:a00:11c");
}

#[test]
fn an_empty_site_table_sends_everything_to_the_other_kinds() {
    // There is no second prefix to withhold any more: sites alone decide. Built
    // fresh, not mutated -- Scheme::new bakes the match indices at construction,
    // and `sites` after that is a parse artifact, not the matcher.
    let sc = Scheme::new(TEST_PREFIX, Vec::new());
    let a = synthesize(&sc, &hdr_v4(b"vpce-0123456789abcdef0", [10, 0, 1, 28]));
    assert_eq!(u16::from_be_bytes([a[6], a[7]]), KIND_VPCE);
}

#[test]
fn an_endpoint_id_outranks_a_source_prefix() {
    // A tenant arriving from site 2's NAT range but carrying site 7's endpoint id
    // is site 7: AWS assigned that id and the sender cannot choose it.
    let a = synthesize(
        &with_sites(),
        &hdr_v4(b"vpce-0123456789abcdef0", [203, 0, 113, 7]),
    );
    assert_eq!(u16::from_be_bytes([a[10], a[11]]), 7);
    // And because it matched by id, the source counts as the tenant's own machine.
    assert_eq!(&a[12..16], &[203, 0, 113, 7]);
}

// --- the fallback ULA -------------------------------------------------------

#[test]
fn an_unonboarded_tenant_gets_a_hash_and_its_machine() {
    let a = synthesize(&plain(), &hdr_v4(b"vpce-0123456789abcdef0", [10, 0, 1, 28]));
    assert_eq!(u16::from_be_bytes([a[6], a[7]]), KIND_VPCE);
    assert_eq!(format(a).as_str(), "fd00:dead:beef:1:7b53:e75b:a00:11c");
    assert_eq!(&a[12..16], &[10, 0, 1, 28]);
}

#[test]
fn the_hash_half_depends_on_the_endpoint_id_alone() {
    // The client address moved INTO the address in v0.6.0, so the two are no
    // longer equal -- but the tenant half must still be derived from the id only.
    let a = synthesize(&plain(), &hdr_v4(b"vpce-0123456789abcdef0", [10, 0, 1, 28]));
    let b = synthesize(&plain(), &hdr_v4(b"vpce-0123456789abcdef0", [9, 9, 9, 9]));
    assert_eq!(a[..12], b[..12]);
    assert_ne!(a, b);
    assert_eq!(format(b).as_str(), "fd00:dead:beef:1:7b53:e75b:909:909");
}

#[test]
fn different_tenants_land_on_different_addresses() {
    let a = synthesize(&plain(), &hdr_v4(b"vpce-0123456789abcdef0", [1, 1, 1, 1]));
    let b = synthesize(&plain(), &hdr_v4(b"vpce-0bbbbbbbbbbbbbbbb", [1, 1, 1, 1]));
    assert_ne!(a, b);
    // ...but share the "any un-onboarded PrivateLink tenant" /64.
    assert_eq!(a[..8], b[..8]);
}

#[test]
fn no_vpce_id_falls_back_to_4via6_with_the_client_ipv4_in_the_low_32_bits() {
    let a = synthesize(&plain(), &hdr_v4(b"", [18, 199, 230, 161]));
    assert_eq!(u16::from_be_bytes([a[6], a[7]]), KIND_ADDR);
    assert_eq!(&a[12..16], &[18, 199, 230, 161]);
    // The hash half is zero, which is what distinguishes this from kind 1.
    assert_eq!(&a[8..12], &[0, 0, 0, 0]);
    assert_eq!(format(a).as_str(), "fd00:dead:beef:4::12c7:e6a1");
}

#[test]
fn the_two_kinds_never_collide() {
    let t = synthesize(&plain(), &hdr_v4(b"vpce-abc", [0, 0, 0, 0]));
    let i = synthesize(&plain(), &hdr_v4(b"", [18, 199, 230, 161]));
    assert_ne!(
        u16::from_be_bytes([t[6], t[7]]),
        u16::from_be_bytes([i[6], i[7]])
    );
}

#[test]
fn the_three_kinds_never_collide() {
    // Same tenant, same machine, onboarded or not -- two spaces, two addresses,
    // and neither can be mistaken for the other by a prefix rule.
    let named = synthesize(
        &with_sites(),
        &hdr_v4(b"vpce-0123456789abcdef0", [10, 0, 1, 28]),
    );
    let stranger = synthesize(&plain(), &hdr_v4(b"vpce-0123456789abcdef0", [10, 0, 1, 28]));
    assert_ne!(named, stranger);
    // One /48 now, so what separates them is the kind, not the prefix.
    assert_eq!(named[..6], TEST_PREFIX[..]);
    assert_eq!(stranger[..6], TEST_PREFIX[..]);
    assert_eq!(u16::from_be_bytes([named[6], named[7]]), KIND_SITE);
    assert_eq!(u16::from_be_bytes([stranger[6], stranger[7]]), KIND_VPCE);
}

// --- pass-through -----------------------------------------------------------

#[test]
fn a_real_ipv6_client_is_passed_through_not_encoded() {
    let h = hdr_v6(b"", "2001:db8:10da:7800:eb7a::5837");
    let a = synthesize(&plain(), &h);
    // Byte-identical, all 128 bits, and outside both prefixes -- the invariant is
    // that everything this module synthesizes is inside one of them.
    assert_eq!(a, h.src);
    assert_ne!(a[..6], TEST_PREFIX[..]);

    // A tenant arriving over IPv6 is still a tenant: vpce branch comes first.
    let t = synthesize(&plain(), &hdr_v6(b"vpce-0123456789abcdef0", "2001:db8::1"));
    assert_eq!(u16::from_be_bytes([t[6], t[7]]), KIND_VPCE);
    assert_eq!(format(t).as_str(), "fd00:dead:beef:1:7b53:e75b::");
}

#[test]
fn an_ipv6_client_cannot_collide_with_an_ipv4_rule() {
    // Regression guard. This pair used to synthesize the same address,
    // because both families shared the kind-4 body and 2a:05:d0:14 reads as
    // 42.5.208.20. Global unicast is 2000::/3, so EVERY v6 client landed in
    // IPv4 32-63.x.x.x -- the band holding 34/35 (GCP), 52/54 (AWS) and
    // 42/43 (APNIC).
    let v6 = synthesize(&plain(), &hdr_v6(b"", "2001:db8:10da:7800:eb7a::5837"));
    let v4 = synthesize(&plain(), &hdr_v4(b"", [42, 5, 208, 20]));
    assert_ne!(v6, v4);

    // And two v6 clients in one /32 stay distinct, rather than collapsing.
    let other = synthesize(&plain(), &hdr_v6(b"", "2001:db8:ffff:9999::1"));
    assert_ne!(v6, other);
}

#[test]
fn an_ipv6_site_prefix_matches_a_v6_client() {
    // sites take v6 prefixes too, and a v6 client is tested as itself rather than
    // through the ::ffff: lift.
    let s = Scheme::new(
        TEST_PREFIX,
        vec![Site {
            id: 9,
            vpce: Vec::new(),
            cidrs: cidr::build("2001:db8::/32").unwrap(),
        }],
    );
    let a = synthesize(&s, &hdr_v6(b"", "2001:db8::1"));
    assert_eq!(format(a).as_str(), "fd00:dead:beef:b1a:0:9::");
}

// --- prefixes ---------------------------------------------------------------

#[test]
fn prefix_parsing_insists_on_a_ula_slash_48() {
    assert_eq!(parse_prefix("fd00:dead:beef::/48").unwrap(), TEST_PREFIX);
    assert!(parse_prefix("fd00:dead:beef::").is_ok()); // bare form accepted
    assert_eq!(parse_prefix("2001:db8::/48"), Err("not unique-local"));
    assert_eq!(
        parse_prefix("fd00:dead:beef::/64"),
        Err("prefix must be /48")
    );
    assert_eq!(
        parse_prefix("fd00:dead:beef:1::/48"),
        Err("prefix has bits set below /48")
    );
}

#[test]
fn to_u128_round_trips_the_wire_order() {
    let a = synthesize(&plain(), &hdr_v4(b"", [18, 199, 230, 161]));
    let n = identity::to_u128(a);
    assert_eq!(n.to_be_bytes(), a);
}

// --- config-time encoding meets packet-time synthesis ------------------------

#[test]
fn an_encoded_member_covers_what_the_wire_synthesizes() {
    // THE invariant behind `groups`: authoring "vpce-abc" or "10.1.0.0/16" in an
    // allow list admits exactly the connections whose headers synthesize there.
    let scheme = plain();
    let covers = |member: &str, h: &ppv2::Header| {
        let entry = identity::encode_member(&scheme, member);
        let set = cidr::build(&entry).unwrap();
        set.contains(identity::to_u128(synthesize(&scheme, h)))
    };

    // A label admits any machine behind it, whatever v4 the header carries.
    assert!(covers("vpce-abc", &hdr_v4(b"vpce-abc", [10, 0, 1, 28])));
    assert!(covers("vpce-abc", &hdr_v4(b"vpce-abc", [192, 168, 0, 1])));
    assert!(!covers("vpce-abc", &hdr_v4(b"vpce-other", [10, 0, 1, 28])));

    // A v4 prefix admits the NAT range, bare v4 admits one machine.
    assert!(covers("10.1.0.0/16", &hdr_v4(b"", [10, 1, 200, 9])));
    assert!(!covers("10.1.0.0/16", &hdr_v4(b"", [10, 2, 0, 1])));
    assert!(covers("203.0.113.7", &hdr_v4(b"", [203, 0, 113, 7])));
    assert!(!covers("203.0.113.7", &hdr_v4(b"", [203, 0, 113, 8])));

    // v6 passthrough, both widths.
    assert!(covers("2001:db8::/64", &hdr_v6(b"", "2001:db8::17")));
    assert!(covers("2001:db8::17", &hdr_v6(b"", "2001:db8::17")));
    assert!(!covers("2001:db8::17", &hdr_v6(b"", "2001:db8::18")));
}

#[test]
fn a_site_owned_source_and_the_wire_meet_in_site_space() {
    // The site-table branch of the config/wire invariant: whatever names a site's
    // traffic in an allow list -- !N, the raw vpce, a contained range -- covers
    // exactly the connections whose headers synthesize into that site.
    let scheme = with_sites(); // site 7 by vpce, site 2 by 203.0.113.0/120-mapped prefix
    let covers = |member: &str, h: &ppv2::Header| {
        let entry = identity::encode_member(&scheme, member);
        let set = cidr::build(&entry).unwrap();
        set.contains(identity::to_u128(synthesize(&scheme, h)))
    };

    let vpce = b"vpce-0123456789abcdef0";
    assert!(covers("!7", &hdr_v4(vpce, [10, 0, 1, 28])));
    assert!(covers("vpce-0123456789abcdef0", &hdr_v4(vpce, [10, 0, 1, 28])));
    assert!(!covers("!7", &hdr_v4(b"vpce-other", [10, 0, 1, 28])));

    assert!(covers("!2", &hdr_v4(b"", [203, 0, 113, 9])));
    assert!(covers("203.0.113.0/24", &hdr_v4(b"", [203, 0, 113, 9])));
    assert!(!covers("!2", &hdr_v4(b"", [203, 0, 114, 9])));
}

#[test]
fn overlapping_site_ranges_split_and_the_contest_goes_to_site_0() {
    // Site 9 claims 203.0.113.0/24; site 3 claims the upper half. The flat index
    // splits at the boundary: lower half -> 9 (sole claimant), upper half ->
    // site 0 (contested -- neither claimant's privileges). Wire and config agree
    // everywhere, including the honest answer for a member spanning both zones:
    // nobody -- no single encoding could match.
    let s = Scheme::new(
        TEST_PREFIX,
        vec![
            Site {
                id: 9,
                vpce: Vec::new(),
                cidrs: cidr::build("::ffff:203.0.113.0/120").unwrap(),
            },
            Site {
                id: 3,
                vpce: Vec::new(),
                cidrs: cidr::build("::ffff:203.0.113.128/121").unwrap(),
            },
        ],
    );

    // Wire: sole zone -> the site; contested zone -> quarantine.
    let low = synthesize(&s, &hdr_v4(b"", [203, 0, 113, 5]));
    let high = synthesize(&s, &hdr_v4(b"", [203, 0, 113, 200]));
    assert_eq!(format(low).as_str(), "fd00:dead:beef:b1a:0:9::");
    assert_eq!(format(high).as_str(), "fd00:dead:beef:b1a::");

    // Config: same three answers -- site, quarantine, and a spanning range that
    // encodes as the kind-4 lift because it crosses zones.
    let enc = |m: &str| identity::encode_member(&s, m);
    assert_eq!(enc("203.0.113.0/25"), "fd00:dead:beef:b1a:0:9::/96");
    assert_eq!(enc("203.0.113.128/25"), "fd00:dead:beef:b1a::/96");
    assert_eq!(enc("203.0.113.0/24"), "fd00:dead:beef:4::cb00:7100/120");
}
