//! filter_config parsing, and the fail-closed choices that depend on it.

use aws_ppv2_identity::config::Pattern;
use aws_ppv2_identity::{config, identity, validate_auth, validate_ppv2};

fn ip(s: &str) -> u128 {
    identity::to_u128(s.parse::<std::net::Ipv6Addr>().unwrap().octets())
}

const TENANT: &str = "fd00:dead:beef:1::1";
const OTHER: &str = "fd00:dead:beef:9::1";

// --- grammar ---------------------------------------------------------------

#[test]
fn scalars_are_key_value_and_lists_are_sections() {
    let c = config::parse(
        "# tenants\n\
         ula fd00:dead:beef::/48\n\
         \n\
         :allow:\n\
         fd00:dead:beef:1:7b53:e75b:6e3d:cfdb/128\n\
         fd00:dead:beef:4::12c7:0/112\n",
    )
    .unwrap();
    assert_eq!(c.prefix, Some([0xfd, 0x00, 0xde, 0xad, 0xbe, 0xef]));
    assert_eq!(c.allow.len(), 2);
    assert!(c.scopes.is_empty());
    assert!(c.require_ppv2);
}

#[test]
fn a_sni_section_may_name_several_hostnames_sharing_one_list() {
    // The shape Envoy's ServerNameMatcher uses: one `domains` list, one action.
    let c = config::parse(
        ":sni:\n\
         l7.mgmt.test\n\
         *.pass.mgmt.test\n\
         :allow:\n\
         fd00:dead:beef:1::/64\n\
         fd00:dead:beef:4::/64\n",
    )
    .unwrap();

    assert_eq!(c.scopes.len(), 1);
    assert_eq!(c.scopes[0].names.len(), 2);
    assert_eq!(c.scopes[0].names[0], Pattern::Exact("l7.mgmt.test".into()));
    assert_eq!(
        c.scopes[0].names[1],
        Pattern::Suffix("pass.mgmt.test".into())
    );
    assert_eq!(c.scopes[0].allow.len(), 2);

    // Both names reach the same list.
    let t = ip(TENANT);
    assert!(c.permits(b"l7.mgmt.test", t));
    assert!(c.permits(b"a.pass.mgmt.test", t));
}

#[test]
fn an_allow_before_any_sni_is_the_flat_list() {
    let c = config::parse(
        "ula fd00:dead:beef::/48\n\
         :allow:\n\
         fd00:dead:beef:9::/64\n\
         :sni:\n\
         a.test\n\
         :allow:\n\
         fd00:dead:beef:1::/64\n",
    )
    .unwrap();
    assert_eq!(c.allow.len(), 1);
    assert_eq!(c.scopes.len(), 1);
    assert_eq!(c.scopes[0].allow.len(), 1);
}

#[test]
fn unknown_sections_and_keys_are_errors() {
    assert!(config::parse(":nope:\nx\n").is_err());
    assert!(config::parse("allwo x\n").is_err());
    assert!(config::parse("ula 2001:db8::/48\n").is_err()); // not a ULA
}

#[test]
fn a_ula_with_bits_below_slash_48_is_rejected() {
    // Only the first 6 bytes are kept, so the :1234 would vanish silently and every
    // synthesized address would sit outside the rules written for it.
    assert!(config::parse("ula fd00:dead:beef:1234::/48\n").is_err());
    assert!(config::parse("ula fd00:dead:beef::1/48\n").is_err());
}

#[test]
fn require_ppv2_rejects_a_value_that_is_neither_true_nor_false() {
    assert!(config::parse("ula fd00:dead:beef::/48\nrequire_ppv2 no\n").is_err());
    assert!(config::parse("ula fd00:dead:beef::/48\nrequire_ppv2 False\n").is_err());
    assert!(config::parse("ula fd00:dead:beef::/48\nrequire_ppv2 true\n").is_ok());
}

#[test]
fn require_ppv2_false_cannot_be_combined_with_an_allowlist() {
    // With require_ppv2 off, unparseable traffic passes through -- straight past
    // every rule. Rejected rather than documented.
    assert!(config::parse(
        "ula fd00:dead:beef::/48\n\
         require_ppv2 false\n\
         :allow:\n\
         fd00:dead:beef:1::/64\n"
    )
    .is_err());

    // Either alone is fine.
    assert!(config::parse("ula fd00:dead:beef::/48\nrequire_ppv2 false\n").is_ok());
    assert!(config::parse("ula fd00:dead:beef::/48\n:allow:\nfd00:dead:beef:1::/64\n").is_ok());
}

// --- which filter takes which shape ----------------------------------------

#[test]
fn ula_and_sni_are_the_two_ways_auth_can_learn_an_identity() {
    // `ula`: parse the header here. The plain TCP and UDP shape.
    let c = config::parse("ula fd00:dead:beef::/48\n:allow:\nfd00:dead:beef:1::/64\n").unwrap();
    assert!(validate_auth(&c).is_ok());

    // `sni`: read the label a preceding `ppv2` filter left. The TLS shape.
    let c = config::parse(":sni:\na.test\n:allow:\nfd00:dead:beef:1::/64\n").unwrap();
    assert!(c.prefix.is_none());
    assert!(validate_auth(&c).is_ok());
    assert!(validate_ppv2(&c).is_err()); // ppv2 still needs its ula

    // Both is the contradiction "I run before tls_inspector and also after it".
    let c = config::parse(
        "ula fd00:dead:beef::/48\n\
         :sni:\n\
         a.test\n\
         :allow:\n\
         fd00:dead:beef:1::/64\n",
    )
    .unwrap();
    assert!(validate_auth(&c).is_err());

    // Neither leaves nothing to derive identity from.
    let c = config::parse(":allow:\nfd00:dead:beef:1::/64\n").unwrap();
    assert!(validate_auth(&c).is_err());
}

#[test]
fn ppv2_takes_only_ula() {
    // It labels and drains; it never denies. Rules here would read as applied and
    // do nothing -- the footgun `allow` on TCP used to be.
    let c = config::parse("ula fd00:dead:beef::/48\n:allow:\nfd00:dead:beef:1::/64\n").unwrap();
    assert!(validate_ppv2(&c).is_err());

    let c =
        config::parse("ula fd00:dead:beef::/48\n:sni:\na.test\n:allow:\nfd00:dead:beef:1::/64\n")
            .unwrap();
    assert!(validate_ppv2(&c).is_err());

    let c = config::parse("ula fd00:dead:beef::/48\n").unwrap();
    assert!(validate_ppv2(&c).is_ok());
}

#[test]
fn auth_has_one_rule_set_whatever_the_transport() {
    // The filter never has to know TCP from UDP: what matters is position in the
    // chain, not transport. Both hooks call validate_auth.
    let ula = config::parse("ula fd00:dead:beef::/48\n:allow:\nfd00:dead:beef:1::/64\n").unwrap();
    let sni = config::parse(":sni:\na.test\n:allow:\nfd00:dead:beef:1::/64\n").unwrap();
    assert!(validate_auth(&ula).is_ok());
    assert!(validate_auth(&sni).is_ok());
}

#[test]
fn an_auth_filter_with_no_allow_is_valid_and_denies_everything() {
    // Security-group semantics: an empty allowlist is deny-all, a real state rather
    // than a mistake. Rejecting it would make "is the list non-empty" load-bearing,
    // and would take the listener down the moment you comment out the last rule.
    let t = ip(TENANT);

    let c = config::parse("ula fd00:dead:beef::/48\n").unwrap();
    assert!(validate_auth(&c).is_ok());
    assert!(!c.permits(b"", t));

    let c = config::parse(":sni:\na.test\n").unwrap();
    assert!(validate_auth(&c).is_ok());
    assert!(!c.permits(b"a.test", t));
}

// --- ServerNameMatcher semantics (domain_matcher.h) -------------------------

#[test]
fn a_wildcard_is_stored_with_the_star_dot_stripped() {
    let c = config::parse(":sni:\n*.pass.mgmt.test\n:allow:\nfd00:dead:beef:1::/64\n").unwrap();
    assert_eq!(
        c.scopes[0].names[0],
        Pattern::Suffix("pass.mgmt.test".into())
    );
}

#[test]
fn a_wildcard_matches_one_label_and_more_but_never_the_parent() {
    let t = ip(TENANT);
    let c = config::parse(":sni:\n*.pass.mgmt.test\n:allow:\nfd00:dead:beef:1::/64\n").unwrap();

    assert!(c.permits(b"a.pass.mgmt.test", t));
    // Plain suffix match, not RFC 6125: deeper names match too.
    assert!(c.permits(b"a.b.pass.mgmt.test", t));
    // The wildcard never matches its own parent.
    assert!(!c.permits(b"pass.mgmt.test", t));
    assert!(!c.permits(b"mgmt.test", t));
    // A LABEL boundary, not a character suffix -- unlike route `domains`, which
    // would match this via a `*bla.com`-style partial wildcard.
    assert!(!c.permits(b"evilpass.mgmt.test", t));
}

#[test]
fn exact_beats_wildcard_regardless_of_config_order() {
    let narrow = ip(TENANT);
    let broad = ip("fd00:dead:beef:4::1");

    // Wildcard declared FIRST.
    let c = config::parse(
        ":sni:\n*.mgmt.test\n:allow:\nfd00:dead:beef:4::/64\n\
         :sni:\nl7.mgmt.test\n:allow:\nfd00:dead:beef:1::/64\n",
    )
    .unwrap();
    assert!(c.permits(b"l7.mgmt.test", narrow));
    assert!(!c.permits(b"l7.mgmt.test", broad));
    assert!(c.permits(b"other.mgmt.test", broad));

    // Same config, order reversed. Precedence must not change.
    let c = config::parse(
        ":sni:\nl7.mgmt.test\n:allow:\nfd00:dead:beef:1::/64\n\
         :sni:\n*.mgmt.test\n:allow:\nfd00:dead:beef:4::/64\n",
    )
    .unwrap();
    assert!(c.permits(b"l7.mgmt.test", narrow));
    assert!(!c.permits(b"l7.mgmt.test", broad));
    assert!(c.permits(b"other.mgmt.test", broad));
}

#[test]
fn wildcards_are_tried_longest_suffix_first() {
    let deep = ip(TENANT);
    let shallow = ip("fd00:dead:beef:4::1");
    let c = config::parse(
        ":sni:\n*.test\n:allow:\nfd00:dead:beef:4::/64\n\
         :sni:\n*.mgmt.test\n:allow:\nfd00:dead:beef:1::/64\n",
    )
    .unwrap();

    // `a.mgmt.test` probes `mgmt.test` before `test`, so the deeper scope wins even
    // though the shallower one is declared first.
    assert!(c.permits(b"a.mgmt.test", deep));
    assert!(!c.permits(b"a.mgmt.test", shallow));
    assert!(c.permits(b"a.other.test", shallow));
}

#[test]
fn the_config_side_is_case_folded_too() {
    // domain_matcher.h never folds its config, so a pattern in mixed case silently
    // never matches there -- the SNI always arrives lowercased. We fold both sides.
    let t = ip(TENANT);
    let c = config::parse(":sni:\nL7.MGMT.Test\n:allow:\nfd00:dead:beef:1::/64\n").unwrap();
    assert_eq!(c.scopes[0].names[0], Pattern::Exact("l7.mgmt.test".into()));
    assert!(c.permits(b"l7.mgmt.test", t));
    assert!(c.permits(b"L7.Mgmt.TEST", t));

    let c = config::parse(":sni:\n*.PASS.Mgmt.TEST\n:allow:\nfd00:dead:beef:1::/64\n").unwrap();
    assert!(c.permits(b"A.Pass.MGMT.test", t));
}

#[test]
fn a_partial_wildcard_is_not_a_wildcard() {
    // Envoy rejects these at config load; we keep them as exact strings so they
    // never match, which errs toward deny rather than failing the config.
    let t = ip(TENANT);
    let c = config::parse(":sni:\n*bla.mgmt.test\n:allow:\nfd00:dead:beef:1::/64\n").unwrap();
    assert_eq!(
        c.scopes[0].names[0],
        Pattern::Exact("*bla.mgmt.test".into())
    );
    assert!(!c.permits(b"blabla.mgmt.test", t));
    assert!(!c.permits(b"bla.mgmt.test", t));

    let c = config::parse(":sni:\nmgmt.*\n:allow:\nfd00:dead:beef:1::/64\n").unwrap();
    assert!(!c.permits(b"mgmt.test", t));
}

#[test]
fn scopes_deny_by_default() {
    let t = ip(TENANT);
    let other = ip(OTHER);
    let c = config::parse(":sni:\nl7.mgmt.test\n:allow:\nfd00:dead:beef:1::/64\n").unwrap();

    assert!(c.permits(b"l7.mgmt.test", t));
    assert!(!c.permits(b"l7.mgmt.test", other)); // matched, but not on the list
    assert!(!c.permits(b"other.mgmt.test", t)); // no scope claims it
    assert!(!c.permits(b"", t)); // no SNI at all
    assert!(!c.permits(b"l7.mgmt.test.", t)); // exact means exact
}

#[test]
fn an_unmatched_sni_does_not_fall_back_to_the_flat_list() {
    // The distinguishing case. The flat list covers this tenant and a scope exists
    // for a different hostname; an SNI matching no scope must still be denied, or
    // every scoped listener silently widens to the flat list.
    let t = ip(TENANT);
    let c = config::parse(
        "ula fd00:dead:beef::/48\n\
         :allow:\n\
         fd00:dead:beef:1::/64\n\
         :sni:\n\
         l7.mgmt.test\n\
         :allow:\n\
         fd00:dead:beef:1::/64\n",
    )
    .unwrap();

    assert!(!c.allow.is_empty()); // the flat list really would admit it
    assert!(c.permits(b"l7.mgmt.test", t));
    assert!(!c.permits(b"other.mgmt.test", t));
    assert!(!c.permits(b"", t));
}

#[test]
fn without_scopes_the_flat_list_applies_whatever_the_sni() {
    let t = ip(TENANT);
    let c = config::parse("ula fd00:dead:beef::/48\n:allow:\nfd00:dead:beef:1::/64\n").unwrap();
    assert!(c.permits(b"", t));
    assert!(c.permits(b"anything.test", t));
    assert!(!c.permits(b"anything.test", ip(OTHER)));
}

#[test]
fn udp_goes_through_permits_so_scopes_could_never_be_silently_ignored() {
    // udp.rs used to consult `allow` directly -- correct, but a second enforcement
    // path that would have quietly ignored scopes the day one arrived. Routing
    // through `permits` with an empty name means the scoped case denies instead.
    let t = ip(TENANT);
    let flat = config::parse("ula fd00:dead:beef::/48\n:allow:\nfd00:dead:beef:1::/64\n").unwrap();
    assert!(flat.permits(b"", t));

    let scoped = config::parse(":sni:\na.test\n:allow:\nfd00:dead:beef:1::/64\n").unwrap();
    assert!(!scoped.permits(b"", t));
}
