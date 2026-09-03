//! filter_config parsing, and the fail-closed choices that depend on it.

use ppv2_auth::config::Pattern;
use ppv2_auth::{config, identity, validate_auth, validate_ppv2, validate_ppv2_auth};

fn ip(s: &str) -> u128 {
    identity::to_u128(s.parse::<std::net::Ipv6Addr>().unwrap().octets())
}

const TENANT: &str = "fd00:dead:beef:1::1";
const OTHER: &str = "fd00:dead:beef:9::1";

// --- shape -----------------------------------------------------------------

#[test]
fn ula_mode_takes_a_flat_allow_list() {
    let c = config::parse(r#"{"ula":"fd00:dead:beef::/48","allow":["fd00:dead:beef:1:7b53:e75b:6e3d:cfdb/128","fd00:dead:beef:4::12c7:0/112"]}"#).unwrap();
    let scheme = c.scheme.as_ref().unwrap();
    assert_eq!(scheme.prefix, [0xfd, 0x00, 0xde, 0xad, 0xbe, 0xef]);
    // No site space configured, so everything falls to the ULA.
    assert!(scheme.via.is_none());
    assert!(scheme.sites.is_empty());
    assert_eq!(c.allow.len(), 2);
    assert!(c.scopes.is_none());
}

#[test]
fn a_scope_may_name_several_hostnames_sharing_one_list() {
    // The shape Envoy's ServerNameMatcher uses: one `domains` list, one action.
    let c = config::parse(
        r#"{"scopes":[{"sni":["l7.mgmt.test","*.pass.mgmt.test"],"allow":["fd00:dead:beef:1::/64","fd00:dead:beef:4::/64"]}]}"#,
    )
    .unwrap();

    let scopes = c.scopes.as_ref().unwrap();
    assert_eq!(scopes.len(), 1);
    assert_eq!(scopes[0].names.len(), 2);
    assert_eq!(scopes[0].names[0], Pattern::Exact("l7.mgmt.test".into()));
    assert_eq!(scopes[0].names[1], Pattern::Suffix("pass.mgmt.test".into()));
    assert_eq!(scopes[0].allow.len(), 2);

    let t = ip(TENANT);
    assert!(c.permits(b"l7.mgmt.test", t));
    assert!(c.permits(b"a.pass.mgmt.test", t));
}

#[test]
fn an_empty_scopes_array_is_sni_mode_that_denies_everything() {
    // The state a base config ships in so tenant CRs have an array to append to.
    // It must NOT fall through to the flat list -- that is the difference between
    // `scopes` absent and `scopes` present but empty.
    let c = config::parse(r#"{"scopes":[]}"#).unwrap();
    assert!(c.scopes.is_some());
    assert!(validate_auth(&c).is_ok());
    assert!(!c.permits(b"anything.test", ip(TENANT)));
    assert!(!c.permits(b"", ip(TENANT)));
}

#[test]
fn a_typo_fails_the_config_rather_than_disabling_enforcement() {
    assert!(config::parse(r#"{"ulaa":"fd00:dead:beef::/48"}"#).is_err());
    assert!(config::parse(r#"{"scopes":[{"snii":["a.test"]}]}"#).is_err());
    assert!(config::parse("not json at all").is_err());
    assert!(config::parse(r#"{"ula":"2001:db8::/48"}"#).is_err()); // not a ULA
}

#[test]
fn a_ula_with_bits_below_slash_48_is_rejected() {
    assert!(config::parse(r#"{"ula":"fd00:dead:beef:1234::/48"}"#).is_err());
    assert!(config::parse(r#"{"ula":"fd00:dead:beef::1/48"}"#).is_err());
}

#[test]
fn require_ppv2_no_longer_exists_and_a_config_carrying_it_fails() {
    // Deleted by design: each filter_name already says what happens to non-PPv2
    // traffic (refused/dropped, always). deny_unknown_fields makes a leftover
    // config fail its listener loudly instead of quietly meaning nothing.
    assert!(config::parse(r#"{"ula":"fd00:dead:beef::/48","require_ppv2":false}"#).is_err());
    assert!(config::parse(r#"{"ula":"fd00:dead:beef::/48","require_ppv2":true}"#).is_err());
}

#[test]
fn a_scope_with_no_sni_names_is_rejected() {
    // Dead config: it can never match. With multi-CR appends this is most likely
    // a tenant's mistake, so it fails the listener rather than sitting inert.
    let c = config::parse(r#"{"scopes":[{"sni":[],"allow":["fd00:dead:beef:1::/64"]}]}"#).unwrap();
    assert!(validate_auth(&c).is_err());
    let c = config::parse(r#"{"scopes":[{"allow":["fd00:dead:beef:1::/64"]}]}"#).unwrap();
    assert!(validate_auth(&c).is_err());
}

// --- which filter takes which shape ----------------------------------------

#[test]
fn each_filter_name_takes_exactly_one_config_shape() {
    let ula = r#"{"ula":"fd00:dead:beef::/48"}"#;
    let ula_allow = r#"{"ula":"fd00:dead:beef::/48","allow":["fd00:dead:beef:1::/64"]}"#;
    let scopes = r#"{"scopes":[{"sni":["a.test"],"allow":["fd00:dead:beef:1::/64"]}]}"#;
    let both = r#"{"ula":"fd00:dead:beef::/48","scopes":[{"sni":["a.test"]}]}"#;

    // ppv2: label and drain only.
    assert!(validate_ppv2(&config::parse(ula).unwrap()).is_ok());
    assert!(validate_ppv2(&config::parse(ula_allow).unwrap()).is_err());
    assert!(validate_ppv2(&config::parse(scopes).unwrap()).is_err());

    // ppv2_auth: parse the header AND enforce. Plain TCP and UDP.
    assert!(validate_ppv2_auth(&config::parse(ula_allow).unwrap()).is_ok());
    assert!(validate_ppv2_auth(&config::parse(ula).unwrap()).is_ok()); // deny-all
    assert!(validate_ppv2_auth(&config::parse(scopes).unwrap()).is_err());
    assert!(validate_ppv2_auth(&config::parse(both).unwrap()).is_err());

    // auth: read the label, scope by SNI. The TLS chain.
    assert!(validate_auth(&config::parse(scopes).unwrap()).is_ok());
    assert!(validate_auth(&config::parse(ula_allow).unwrap()).is_err());
    assert!(validate_auth(&config::parse(both).unwrap()).is_err());
}

#[test]
fn auth_rejects_a_top_level_allow_it_would_never_consult() {
    // Once `scopes` exists the flat list is never reached, so leaving it there
    // would be a rule that reads as applied and does nothing.
    let c = config::parse(
        r#"{"allow":["fd00:dead:beef:1::/64"],"scopes":[{"sni":["a.test"],"allow":["fd00:dead:beef:1::/64"]}]}"#,
    )
    .unwrap();
    assert!(validate_auth(&c).is_err());
}

#[test]
fn an_auth_filter_with_no_allow_is_valid_and_denies_everything() {
    // Security-group semantics: an empty allowlist is deny-all, a real state rather
    // than a mistake. Rejecting it would make "is the list non-empty" load-bearing.
    let t = ip(TENANT);
    let c = config::parse(r#"{"ula":"fd00:dead:beef::/48"}"#).unwrap();
    assert!(validate_ppv2_auth(&c).is_ok());
    assert!(!c.permits(b"", t));
}

// --- ServerNameMatcher semantics (domain_matcher.h) -------------------------

#[test]
fn a_wildcard_matches_one_label_and_more_but_never_the_parent() {
    let t = ip(TENANT);
    let c = config::parse(
        r#"{"scopes":[{"sni":["*.pass.mgmt.test"],"allow":["fd00:dead:beef:1::/64"]}]}"#,
    )
    .unwrap();

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

    let wild_first = config::parse(
        r#"{"scopes":[{"sni":["*.mgmt.test"],"allow":["fd00:dead:beef:4::/64"]},{"sni":["l7.mgmt.test"],"allow":["fd00:dead:beef:1::/64"]}]}"#
    ).unwrap();
    let exact_first = config::parse(
        r#"{"scopes":[{"sni":["l7.mgmt.test"],"allow":["fd00:dead:beef:1::/64"]},{"sni":["*.mgmt.test"],"allow":["fd00:dead:beef:4::/64"]}]}"#
    ).unwrap();

    for c in [&wild_first, &exact_first] {
        assert!(c.permits(b"l7.mgmt.test", narrow));
        assert!(!c.permits(b"l7.mgmt.test", broad));
        assert!(c.permits(b"other.mgmt.test", broad));
    }
}

#[test]
fn wildcards_are_tried_longest_suffix_first() {
    let deep = ip(TENANT);
    let shallow = ip("fd00:dead:beef:4::1");
    let c = config::parse(
        r#"{"scopes":[{"sni":["*.test"],"allow":["fd00:dead:beef:4::/64"]},{"sni":["*.mgmt.test"],"allow":["fd00:dead:beef:1::/64"]}]}"#
    ).unwrap();

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
    let c = config::parse(r#"{"scopes":[{"sni":["L7.MGMT.Test","*.PASS.Mgmt.TEST"],"allow":["fd00:dead:beef:1::/64"]}]}"#).unwrap();
    assert_eq!(
        c.scopes.as_ref().unwrap()[0].names[0],
        Pattern::Exact("l7.mgmt.test".into())
    );
    assert!(c.permits(b"l7.mgmt.test", t));
    assert!(c.permits(b"L7.Mgmt.TEST", t));
    assert!(c.permits(b"A.Pass.MGMT.test", t));
}

#[test]
fn a_partial_wildcard_is_not_a_wildcard() {
    // Envoy rejects these at config load; we keep them as exact strings so they
    // never match, which errs toward deny rather than failing the config.
    let t = ip(TENANT);
    let c = config::parse(
        r#"{"scopes":[{"sni":["*bla.mgmt.test","mgmt.*"],"allow":["fd00:dead:beef:1::/64"]}]}"#,
    )
    .unwrap();
    assert_eq!(
        c.scopes.as_ref().unwrap()[0].names[0],
        Pattern::Exact("*bla.mgmt.test".into())
    );
    assert!(!c.permits(b"blabla.mgmt.test", t));
    assert!(!c.permits(b"bla.mgmt.test", t));
    assert!(!c.permits(b"mgmt.test", t));
}

#[test]
fn scopes_deny_by_default() {
    let t = ip(TENANT);
    let other = ip(OTHER);
    let c =
        config::parse(r#"{"scopes":[{"sni":["l7.mgmt.test"],"allow":["fd00:dead:beef:1::/64"]}]}"#)
            .unwrap();

    assert!(c.permits(b"l7.mgmt.test", t));
    assert!(!c.permits(b"l7.mgmt.test", other)); // matched, but not on the list
    assert!(!c.permits(b"other.mgmt.test", t)); // no scope claims it
    assert!(!c.permits(b"", t)); // no SNI at all
    assert!(!c.permits(b"l7.mgmt.test.", t)); // exact means exact
}

#[test]
fn an_unmatched_sni_does_not_fall_back_to_the_flat_list() {
    // The distinguishing case. A flat `allow` covers this tenant AND a scope exists
    // for a different hostname; an SNI matching no scope must still be denied, or
    // every scoped listener silently widens to the flat list.
    let t = ip(TENANT);
    let c = config::parse(
        r#"{"allow":["fd00:dead:beef:1::/64"],"scopes":[{"sni":["l7.mgmt.test"],"allow":["fd00:dead:beef:1::/64"]}]}"#
    ).unwrap();

    assert!(!c.allow.is_empty()); // the flat list really would admit it
    assert!(c.permits(b"l7.mgmt.test", t));
    assert!(!c.permits(b"other.mgmt.test", t));
    assert!(!c.permits(b"", t));
}

#[test]
fn without_scopes_the_flat_list_applies_whatever_the_sni() {
    let t = ip(TENANT);
    let c = config::parse(r#"{"ula":"fd00:dead:beef::/48","allow":["fd00:dead:beef:1::/64"]}"#)
        .unwrap();
    assert!(c.permits(b"", t));
    assert!(c.permits(b"anything.test", t));
    assert!(!c.permits(b"anything.test", ip(OTHER)));
}

#[test]
fn udp_goes_through_permits_so_scopes_could_never_be_silently_ignored() {
    let t = ip(TENANT);
    let flat = config::parse(r#"{"ula":"fd00:dead:beef::/48","allow":["fd00:dead:beef:1::/64"]}"#)
        .unwrap();
    assert!(flat.permits(b"", t));

    let scoped =
        config::parse(r#"{"scopes":[{"sni":["a.test"],"allow":["fd00:dead:beef:1::/64"]}]}"#)
            .unwrap();
    assert!(!scoped.permits(b"", t));
}

#[test]
fn duplicate_names_take_the_first_scope() {
    // Envoy rejects duplicate domains at config load; we take first-wins rather
    // than fail. Pinned so the behaviour is a decision, not an accident.
    let a = ip("fd00:dead:beef:1::1");
    let b = ip("fd00:dead:beef:4::1");
    let c = config::parse(
        r#"{"scopes":[{"sni":["dup.test"],"allow":["fd00:dead:beef:1::/64"]},{"sni":["dup.test"],"allow":["fd00:dead:beef:4::/64"]}]}"#,
    )
    .unwrap();
    assert!(c.permits(b"dup.test", a));
    assert!(!c.permits(b"dup.test", b));
}

// --- sites -----------------------------------------------------------------

#[test]
fn sites_take_endpoint_ids_and_prefixes_of_either_family() {
    let c = config::parse(
        r#"{"ula":"fd00:dead:beef::/48","via":"fd7a:115c:a1e0:b1a::/64",
             "sites":[{"id":1,"members":["vpce-028ff61de1d1fea8c","3.126.239.93/32"]},
                       {"id":2,"members":["203.0.113.0/24","2001:db8::/32"]},
                       {"id":3,"members":["vpce-0aaa","vpce-0bbb"]}]}"#,
    )
    .unwrap();
    let s = c.scheme.as_ref().unwrap();
    assert!(s.via.is_some());
    assert_eq!(s.sites.len(), 3);

    // Order is the generator's, not ours -- kro sorts the keys before emitting.
    assert_eq!(
        s.sites.iter().map(|x| x.id).collect::<Vec<_>>(),
        vec![1, 2, 3]
    );

    // An id is opaque and kept verbatim; a prefix is lifted into the cidr Set.
    assert_eq!(s.sites[0].vpce.len(), 1);
    assert_eq!(&*s.sites[0].vpce[0], b"vpce-028ff61de1d1fea8c");
    assert!(s.sites[0].cidrs.contains(ip("::ffff:3.126.239.93")));
    assert!(s.sites[1].cidrs.contains(ip("::ffff:203.0.113.7")));
    assert!(s.sites[1].cidrs.contains(ip("2001:db8::1")));
    assert!(!s.sites[1].cidrs.contains(ip("::ffff:203.0.114.1")));
    assert_eq!(s.sites[2].vpce.len(), 2);
    assert!(s.sites[2].cidrs.is_empty());
}

#[test]
fn a_bare_site_address_is_a_single_host() {
    let c = config::parse(
        r#"{"ula":"fd00:dead:beef::/48","via":"fd7a:115c:a1e0:b1a::/64",
             "sites":[{"id":5,"members":["198.51.100.7"]}]}"#,
    )
    .unwrap();
    let s = &c.scheme.as_ref().unwrap().sites[0];
    assert!(s.cidrs.contains(ip("::ffff:198.51.100.7")));
    assert!(!s.cidrs.contains(ip("::ffff:198.51.100.8")));
}

#[test]
fn a_malformed_site_fails_the_config() {
    // Same rule as the allowlist: a typo must fail rather than silently shrink
    // the table, which would quietly demote a tenant to the fallback ULA.
    for bad in [
        r#"{"ula":"fd00:dead:beef::/48","sites":[{"id":"nope","members":["vpce-a"]}]}"#,
        r#"{"ula":"fd00:dead:beef::/48","sites":[{"id":0,"members":["vpce-a"]}]}"#,
        r#"{"ula":"fd00:dead:beef::/48","sites":[{"id":70000,"members":["vpce-a"]}]}"#,
        r#"{"ula":"fd00:dead:beef::/48","sites":[{"id":1,"members":["10.0.0.0/40"]}]}"#,
        r#"{"ula":"fd00:dead:beef::/48","sites":[{"id":1,"members":["10.0.0.0/x"]}]}"#,
    ] {
        assert!(config::parse(bad).is_err(), "accepted {bad}");
    }
}

#[test]
fn via_and_sites_need_a_ula() {
    // They describe how a header is encoded, and only a filter that parses the
    // header does that -- so on `auth`, which has no `ula`, they are dead config.
    assert!(config::parse(r#"{"via":"fd7a:115c:a1e0:b1a::/64"}"#).is_err());
    assert!(config::parse(r#"{"sites":[{"id":1,"members":["vpce-a"]}]}"#).is_err());
    assert!(
        config::parse(r#"{"scopes":[{"sni":["x"]}],"sites":[{"id":1,"members":["vpce-a"]}]}"#)
            .is_err()
    );
}

#[test]
fn the_filters_that_encode_are_the_ones_that_take_sites() {
    let sited = r#"{"ula":"fd00:dead:beef::/48","via":"fd7a:115c:a1e0:b1a::/64","sites":[{"id":1,"members":["vpce-a"]}]}"#;
    // Both header-parsing filters accept it.
    assert!(validate_ppv2(&config::parse(sited).unwrap()).is_ok());
    assert!(validate_ppv2_auth(&config::parse(sited).unwrap()).is_ok());
    // `auth` cannot even express it: no `ula` means parse already refused.
    assert!(
        config::parse(r#"{"scopes":[{"sni":["x"]}],"via":"fd7a:115c:a1e0:b1a::/64"}"#).is_err()
    );
}

#[test]
fn one_id_cannot_appear_twice() {
    // A list can say the same id twice where a map could not, so which members
    // apply would depend on order. Refuse instead.
    assert!(config::parse(
        r#"{"ula":"fd00:dead:beef::/48","sites":[{"id":1,"members":["vpce-a"]},{"id":1,"members":["vpce-b"]}]}"#
    )
    .is_err());
}
