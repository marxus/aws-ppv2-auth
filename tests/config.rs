//! filter_config parsing, and the fail-closed choices that depend on it.

use aws_ppv2_identity::config::Pattern;
use aws_ppv2_identity::{config, identity};

#[test]
fn parses_a_typical_config() {
    let c = config::parse(
        "# tenants\n\
         ula   fd00:dead:beef::/48\n\
         allow fd00:dead:beef:1:7b53:e75b:6e3d:cfdb/128\n\
         \n\
         allow fd00:dead:beef:4::12c7:0/112\n",
    )
    .unwrap();
    assert_eq!(c.prefix, Some([0xfd, 0x00, 0xde, 0xad, 0xbe, 0xef]));
    assert_eq!(c.allow.len(), 2);
    assert!(c.require_ppv2);
}

#[test]
fn an_empty_allow_list_denies_everything_it_does_not_disable_enforcement() {
    let c = config::parse("ula fd00:dead:beef::/48\nrequire_ppv2 false\n").unwrap();
    assert!(!c.require_ppv2);
    // The security-group model: no rule covers it, so nothing is permitted --
    // including a well-formed tenant address. This is the fail-closed
    // direction and the reason there is no `enforce` flag to derive.
    assert!(c.allow.is_empty());
    let tenant = identity::to_u128(
        "fd00:dead:beef:1:7b53:e75b:6e3d:cfdb"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    assert!(!c.allow.contains(tenant));
}

#[test]
fn typos_and_a_bad_ula_are_errors() {
    assert!(config::parse("ula fd2a::/48\nallwo x\n").is_err());
    assert!(config::parse("ula 2001:db8::/48\n").is_err()); // not a ULA
}

#[test]
fn ula_is_required_by_the_filters_that_synthesize_not_by_the_parser() {
    // `auth` on a TLS chain has no `ula`: a preceding `ppv2` filter already
    // labelled the socket, so there is nothing for it to synthesize.
    let c = config::parse("allow fd00:dead:beef:1::/64\n").unwrap();
    assert!(c.prefix.is_none());
    assert!(aws_ppv2_identity::validate_auth(&c).is_ok());

    // A filter that must derive identity itself cannot do without it.
    assert!(aws_ppv2_identity::validate_ppv2(&c).is_err());
    assert!(aws_ppv2_identity::validate_udp_auth(&c).is_err());
}

#[test]
fn ppv2_refuses_to_carry_rules_it_cannot_enforce() {
    // It labels and drains; it never denies. An `allow` here would read as applied
    // and do nothing -- the same footgun `allow` on TCP used to be.
    let c = config::parse("ula fd00:dead:beef::/48\nallow fd00:dead:beef:1::/64\n").unwrap();
    assert!(aws_ppv2_identity::validate_ppv2(&c).is_err());

    let c = config::parse("ula fd00:dead:beef::/48\nsni a.test\nallow fd00:dead:beef:1::/64\n")
        .unwrap();
    assert!(aws_ppv2_identity::validate_ppv2(&c).is_err());

    // Bare, it is exactly what a ppv2 filter should be.
    let c = config::parse("ula fd00:dead:beef::/48\n").unwrap();
    assert!(aws_ppv2_identity::validate_ppv2(&c).is_ok());
}

#[test]
fn sni_on_udp_is_an_error() {
    // No TLS handshake on UDP, so the scope could never match and every datagram
    // would be denied for a reason nobody could see.
    let c = config::parse("ula fd00:dead:beef::/48\nsni a.test\nallow fd00:dead:beef:1::/64\n")
        .unwrap();
    assert!(aws_ppv2_identity::validate_udp_auth(&c).is_err());
}

#[test]
fn sni_opens_a_scope_and_allow_lines_join_it() {
    let c = config::parse(
        "ula   fd00:dead:beef::/48\n\
         allow fd00:dead:beef:9::/64\n\
         sni   l7.mgmt.test\n\
         allow fd00:dead:beef:1::/64\n\
         sni   tcp.mgmt.test\n\
         allow fd00:dead:beef:4::a01:0/112\n\
         allow fd00:dead:beef:1::/64\n",
    )
    .unwrap();

    // The bare `allow` before any `sni` is the flat list, not part of a scope.
    assert_eq!(c.allow.len(), 1);
    assert_eq!(c.scopes.len(), 2);
    assert_eq!(c.scopes[0].0, Pattern::Exact("l7.mgmt.test".into()));
    assert_eq!(c.scopes[0].1.len(), 1);
    assert_eq!(c.scopes[1].0, Pattern::Exact("tcp.mgmt.test".into()));
    // The same identity may appear under several hostnames.
    assert_eq!(c.scopes[1].1.len(), 2);
}

#[test]
fn scopes_are_matched_exactly_and_deny_by_default() {
    let tenant = ip("fd00:dead:beef:1::1");
    let other = ip("fd00:dead:beef:9::1");
    let c = config::parse(
        "ula   fd00:dead:beef::/48\n\
         sni   l7.mgmt.test\n\
         allow fd00:dead:beef:1::/64\n",
    )
    .unwrap();

    assert!(c.permits(b"l7.mgmt.test", tenant));
    assert!(c.permits(b"L7.MGMT.TEST", tenant)); // SNI is case-insensitive
    assert!(!c.permits(b"l7.mgmt.test", other)); // matched, but not on the list
    assert!(!c.permits(b"other.mgmt.test", tenant)); // no scope claims it
    assert!(!c.permits(b"", tenant)); // no SNI at all
    assert!(!c.permits(b"l7.mgmt.test.", tenant)); // exact means exact
}

#[test]
fn an_unmatched_sni_does_not_fall_back_to_the_flat_list() {
    // The distinguishing case. The flat list covers this tenant, and a scope exists
    // for a different hostname. An SNI matching no scope must still be denied --
    // falling back would silently widen every scoped listener to the flat list.
    let tenant = ip("fd00:dead:beef:1::1");
    let c = config::parse(
        "ula   fd00:dead:beef::/48\n\
         allow fd00:dead:beef:1::/64\n\
         sni   l7.mgmt.test\n\
         allow fd00:dead:beef:1::/64\n",
    )
    .unwrap();

    assert!(!c.allow.is_empty()); // the flat list really would admit it
    assert!(c.permits(b"l7.mgmt.test", tenant));
    assert!(!c.permits(b"other.mgmt.test", tenant));
    assert!(!c.permits(b"", tenant));
}

#[test]
fn without_scopes_the_flat_list_applies_whatever_the_sni() {
    let tenant = ip("fd00:dead:beef:1::1");
    let c = config::parse("ula fd00:dead:beef::/48\nallow fd00:dead:beef:1::/64\n").unwrap();
    assert!(c.permits(b"", tenant));
    assert!(c.permits(b"anything.test", tenant));
    assert!(!c.permits(b"anything.test", ip("fd00:dead:beef:9::1")));
}

fn ip(s: &str) -> u128 {
    identity::to_u128(s.parse::<std::net::Ipv6Addr>().unwrap().octets())
}

#[test]
fn require_ppv2_false_cannot_be_combined_with_an_allowlist() {
    // The UDP filter only consults `allow` on a header it parsed; with
    // require_ppv2 off, anything unparseable is passed through instead --
    // straight past every rule. The combination is rejected rather than
    // documented, because an allowlist that is not one is worse than neither.
    assert!(config::parse(
        "ula fd00:dead:beef::/48\n\
         require_ppv2 false\n\
         allow fd00:dead:beef:1::/64\n"
    )
    .is_err());

    // Either alone is still fine.
    assert!(config::parse("ula fd00:dead:beef::/48\nrequire_ppv2 false\n").is_ok());
    assert!(config::parse("ula fd00:dead:beef::/48\nallow fd00:dead:beef:1::/64\n").is_ok());
}

#[test]
fn require_ppv2_rejects_a_value_that_is_neither_true_nor_false() {
    // `require_ppv2 no` used to read as true. It fails closed, but silently
    // meaning the opposite of what it says is found during an incident.
    assert!(config::parse("ula fd00:dead:beef::/48\nrequire_ppv2 no\n").is_err());
    assert!(config::parse("ula fd00:dead:beef::/48\nrequire_ppv2 False\n").is_err());
    assert!(config::parse("ula fd00:dead:beef::/48\nrequire_ppv2 true\n").is_ok());
}

#[test]
fn a_ula_with_bits_below_slash_48_is_rejected() {
    // Only the first 6 bytes are kept, so the :1234 would vanish silently and
    // every synthesized address would sit outside the rules written for it.
    assert!(config::parse("ula fd00:dead:beef:1234::/48\n").is_err());
    assert!(config::parse("ula fd00:dead:beef::1/48\n").is_err());
}

// --- ServerNameMatcher semantics (domain_matcher.h) -------------------------

#[test]
fn a_wildcard_is_stored_with_the_star_dot_stripped() {
    let c = config::parse("sni *.pass.mgmt.test\nallow fd00:dead:beef:1::/64\n").unwrap();
    assert_eq!(c.scopes[0].0, Pattern::Suffix("pass.mgmt.test".into()));
}

#[test]
fn a_wildcard_matches_one_label_and_more_but_never_the_parent() {
    let t = ip("fd00:dead:beef:1::1");
    let c = config::parse("sni *.pass.mgmt.test\nallow fd00:dead:beef:1::/64\n").unwrap();

    assert!(c.permits(b"a.pass.mgmt.test", t));
    // Plain suffix match, not RFC 6125: deeper names match too.
    assert!(c.permits(b"a.b.pass.mgmt.test", t));
    // But the wildcard never matches its own parent.
    assert!(!c.permits(b"pass.mgmt.test", t));
    assert!(!c.permits(b"mgmt.test", t));
    // And it is a LABEL boundary, not a character suffix -- unlike route domains,
    // which would match this via `*bla.com`-style partial wildcards.
    assert!(!c.permits(b"evilpass.mgmt.test", t));
}

#[test]
fn exact_beats_wildcard_regardless_of_config_order() {
    let broad = ip("fd00:dead:beef:4::1");
    let narrow = ip("fd00:dead:beef:1::1");

    // Wildcard declared FIRST, exact second.
    let c = config::parse(
        "sni   *.mgmt.test\n\
         allow fd00:dead:beef:4::/64\n\
         sni   l7.mgmt.test\n\
         allow fd00:dead:beef:1::/64\n",
    )
    .unwrap();
    assert!(c.permits(b"l7.mgmt.test", narrow));
    assert!(!c.permits(b"l7.mgmt.test", broad)); // the exact scope, not the wildcard
    assert!(c.permits(b"other.mgmt.test", broad)); // falls to the wildcard

    // Same config, order reversed. Precedence must not change.
    let c = config::parse(
        "sni   l7.mgmt.test\n\
         allow fd00:dead:beef:1::/64\n\
         sni   *.mgmt.test\n\
         allow fd00:dead:beef:4::/64\n",
    )
    .unwrap();
    assert!(c.permits(b"l7.mgmt.test", narrow));
    assert!(!c.permits(b"l7.mgmt.test", broad));
    assert!(c.permits(b"other.mgmt.test", broad));
}

#[test]
fn wildcards_are_tried_longest_suffix_first() {
    let deep = ip("fd00:dead:beef:1::1");
    let shallow = ip("fd00:dead:beef:4::1");
    let c = config::parse(
        "sni   *.test\n\
         allow fd00:dead:beef:4::/64\n\
         sni   *.mgmt.test\n\
         allow fd00:dead:beef:1::/64\n",
    )
    .unwrap();

    // `a.mgmt.test` probes `mgmt.test` before `test`, so the deeper scope wins even
    // though the shallower one is declared first.
    assert!(c.permits(b"a.mgmt.test", deep));
    assert!(!c.permits(b"a.mgmt.test", shallow));
    // Nothing deeper claims this one.
    assert!(c.permits(b"a.other.test", shallow));
}

#[test]
fn the_config_side_is_case_folded_too() {
    // domain_matcher.h never folds its config, so a pattern written in mixed case
    // silently never matches there -- the SNI always arrives lowercased. We fold
    // both sides, so this works.
    let t = ip("fd00:dead:beef:1::1");
    let c = config::parse("sni L7.MGMT.Test\nallow fd00:dead:beef:1::/64\n").unwrap();
    assert_eq!(c.scopes[0].0, Pattern::Exact("l7.mgmt.test".into()));
    assert!(c.permits(b"l7.mgmt.test", t));
    assert!(c.permits(b"L7.Mgmt.TEST", t));

    let c = config::parse("sni *.PASS.Mgmt.TEST\nallow fd00:dead:beef:1::/64\n").unwrap();
    assert_eq!(c.scopes[0].0, Pattern::Suffix("pass.mgmt.test".into()));
    assert!(c.permits(b"A.Pass.MGMT.test", t));
}

#[test]
fn a_partial_wildcard_is_not_a_wildcard() {
    // Envoy rejects these at config load; we keep them as exact strings so they
    // simply never match, which errs toward deny rather than failing the config.
    let t = ip("fd00:dead:beef:1::1");
    let c = config::parse("sni *bla.mgmt.test\nallow fd00:dead:beef:1::/64\n").unwrap();
    assert_eq!(c.scopes[0].0, Pattern::Exact("*bla.mgmt.test".into()));
    assert!(!c.permits(b"blabla.mgmt.test", t));
    assert!(!c.permits(b"bla.mgmt.test", t));

    let c = config::parse("sni mgmt.*\nallow fd00:dead:beef:1::/64\n").unwrap();
    assert_eq!(c.scopes[0].0, Pattern::Exact("mgmt.*".into()));
    assert!(!c.permits(b"mgmt.test", t));
}

#[test]
fn udp_goes_through_permits_so_scopes_could_never_be_silently_ignored() {
    // udp.rs used to consult `allow` directly. lib.rs rejects `sni` on UDP, so it
    // was correct -- but it was a second enforcement path that would have quietly
    // ignored scopes the day one arrived. Routing through `permits` with an empty
    // name means the scoped case denies instead.
    let t = ip("fd00:dead:beef:1::1");
    let flat = config::parse("ula fd00:dead:beef::/48\nallow fd00:dead:beef:1::/64\n").unwrap();
    assert!(flat.permits(b"", t)); // what UDP actually uses

    let scoped =
        config::parse("ula fd00:dead:beef::/48\nsni a.test\nallow fd00:dead:beef:1::/64\n")
            .unwrap();
    assert!(!scoped.permits(b"", t)); // deny, not "fall back to the scope"
}
