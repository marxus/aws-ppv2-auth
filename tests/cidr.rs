//! Allowlist membership: boundaries, collapsing, and the deny-by-default state.

use aws_ppv2_identity::cidr;
use std::net::Ipv6Addr;

fn p(t: &str) -> u128 {
    u128::from_be_bytes(t.parse::<Ipv6Addr>().unwrap().octets())
}

#[test]
fn membership_boundaries_and_gaps() {
    let s = cidr::build("fd2a:5c1b:7e90:1::/64, fd2a:5c1b:7e90:4::12c7:0/112").unwrap();
    assert!(s.contains(p("fd2a:5c1b:7e90:1::1"))); // in /64
    assert!(s.contains(p("fd2a:5c1b:7e90:1:ffff:ffff:ffff:ffff"))); // last of /64
    assert!(!s.contains(p("fd2a:5c1b:7e90:2::1"))); // next /64 out
    assert!(s.contains(p("fd2a:5c1b:7e90:4::12c7:e6a1"))); // in /112
    assert!(!s.contains(p("fd2a:5c1b:7e90:4::a00:11c"))); // outside /112
    assert!(!s.contains(p("fd00:dead::1"))); // unrelated
}

#[test]
fn single_host_slash_128_and_slash_0_edges() {
    let s = cidr::build("fd2a:5c1b:7e90:1::1/128").unwrap();
    assert!(s.contains(p("fd2a:5c1b:7e90:1::1")));
    assert!(!s.contains(p("fd2a:5c1b:7e90:1::2")));
    assert!(!s.contains(p("fd2a:5c1b:7e90:1::0")));

    let all = cidr::build("::/0").unwrap();
    assert!(all.contains(p("2a05:d014::1")));
    assert!(all.contains(0));
    assert!(all.contains(u128::MAX));
}

#[test]
fn overlaps_collapse() {
    let s = cidr::build("fd00::/16, fd00:1::/32, fd00:2::/32").unwrap(); // all inside /16
    assert_eq!(s.len(), 1);
}

#[test]
fn an_empty_list_denies_everything() {
    // Security-group semantics: allowed iff a rule covers it. No rules means
    // nothing is permitted. See config.rs for why there is no enforce flag.
    let s = cidr::build("").unwrap();
    assert!(s.is_empty());
    assert!(!s.contains(p("fd2a:5c1b:7e90:1:e3b1:45a8:c041:e80a")));
}

#[test]
fn ten_thousand_unique_slash_128_host_addresses() {
    let mut list = String::new();
    for i in 0..10_000u32 {
        list.push_str(&format!(
            "fd2a:5c1b:7e90:1:0:0:{:x}:{:x}/128,",
            i >> 16,
            i & 0xffff
        ));
    }
    let s = cidr::build(&list).unwrap();
    assert_eq!(s.len(), 10_000);

    let hit = p("fd2a:5c1b:7e90:1:0:0:0:1388");
    assert!(s.contains(hit));
    // NB: entries here are sequential, so hit^1 is the NEXT entry, not a
    // miss. Flip a high bit to land outside the populated block.
    assert!(!s.contains(hit ^ (1u128 << 100)));
    assert!(!s.contains(p("fe80::1")));
}

#[test]
fn malformed_entries_fail_the_build() {
    // A typo must fail the config rather than silently shrinking the
    // allowlist, which under deny-by-default would lock tenants out with no
    // other symptom.
    assert!(cidr::build("fd00::/16, notanaddress/64").is_err());
    assert!(cidr::build("fd00::/999").is_err());
    assert!(cidr::build("fd00::1").is_err()); // no prefix length
}
