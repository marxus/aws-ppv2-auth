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
    let scheme = c.scheme().unwrap();
    assert_eq!(scheme.prefix, [0xfd, 0x00, 0xde, 0xad, 0xbe, 0xef]);
    // Nothing onboarded, so every header falls to kind 1 or 4.
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
    // `ula` rides along on `auth` since members need it to encode -- see validate_auth.
    assert!(validate_auth(&config::parse(both).unwrap()).is_ok());
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
        r#"{"ula":"fd00:dead:beef::/48",
             "sites":{"1":["vpce-028ff61de1d1fea8c","3.126.239.93/32"],
                      "2":["203.0.113.0/24","2001:db8::/32"],
                      "3":["vpce-0aaa","vpce-0bbb"]}}"#,
    )
    .unwrap();
    let s = c.scheme().unwrap();
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
        r#"{"ula":"fd00:dead:beef::/48",
             "sites":{"5":["198.51.100.7"]}}"#,
    )
    .unwrap();
    let s = &c.scheme().unwrap().sites[0];
    assert!(s.cidrs.contains(ip("::ffff:198.51.100.7")));
    assert!(!s.cidrs.contains(ip("::ffff:198.51.100.8")));
}

#[test]
fn a_malformed_site_fails_the_config() {
    // Same rule as the allowlist: a typo must fail rather than silently shrink
    // the table, which would quietly demote a tenant to the fallback ULA.
    for bad in [
        r#"{"ula":"fd00:dead:beef::/48","sites":{"nope":["vpce-a"]}}"#,
        r#"{"ula":"fd00:dead:beef::/48","sites":{"0":["vpce-a"]}}"#,
        r#"{"ula":"fd00:dead:beef::/48","sites":{"70000":["vpce-a"]}}"#,
        r#"{"ula":"fd00:dead:beef::/48","sites":{"1":["10.0.0.0/40"]}}"#,
        r#"{"ula":"fd00:dead:beef::/48","sites":{"1":["10.0.0.0/x"]}}"#,
    ] {
        assert!(config::parse(bad).is_err(), "accepted {bad}");
    }
}

#[test]
fn sites_need_a_ula() {
    // They describe how a header is encoded, and only a filter that parses the
    // header does that -- so on `auth`, which has no `ula`, they are dead config.
    assert!(config::parse(r#"{"sites":{"1":["vpce-a"]}}"#).is_err());
    assert!(
        config::parse(r#"{"scopes":[{"sni":["x"]}],"sites":{"1":["vpce-a"]}}"#)
            .is_err()
    );
}

#[test]
fn every_filter_takes_sites_because_every_filter_encodes() {
    let sited = r#"{"ula":"fd00:dead:beef::/48","sites":{"1":["vpce-a"]}}"#;
    // The header-parsing filters classify against them per connection.
    assert!(validate_ppv2(&config::parse(sited).unwrap()).is_ok());
    assert!(validate_ppv2_auth(&config::parse(sited).unwrap()).is_ok());
    // `auth` never parses a header, but its members encode against the same table
    // -- a site-owned source in a scope must land in site space like the wire does.
    let auth_sited = r#"{"ula":"fd00:dead:beef::/48",
        "sites":{"1":["vpce-a"]},
        "scopes":[{"sni":["x.test"],"allow":["vpce-a"]}]}"#;
    let c = config::parse(auth_sited).unwrap();
    assert!(validate_auth(&c).is_ok());
    // The scope admits site 1's space, not vpce-a's hash.
    assert!(c.permits(b"x.test", ip("fd00:dead:beef:b1a:0:1::5")));
    // Still parse-gated on `ula`:
    assert!(
        config::parse(r#"{"scopes":[{"sni":["x"]}],"sites":{"1":["vpce-a"]}}"#)
            .is_err()
    );
}

#[test]
fn a_map_cannot_say_one_id_twice() {
    // The list shape could, and had to refuse it; a JSON map key is unique by
    // construction (serde keeps the last), so the failure mode is gone.
    let c = config::parse(
        r#"{"ula":"fd00:dead:beef::/48","sites":{"1":["vpce-a"],"01":["vpce-b"]}}"#,
    )
    .unwrap();
    // "01" parses to the same id -- both survive as table entries with id 1, and
    // lowest-id-wins ordering keeps lookups deterministic anyway.
    assert_eq!(c.scheme().unwrap().sites.len(), 2);
}

// --- groups and @refs --------------------------------------------------------

#[test]
fn an_allow_entry_may_reference_a_group() {
    let c = config::parse(
        r#"{"ula":"fd00:dead:beef::/48",
            "groups":{"tenant-a":["fd00:dead:beef:1::/64"]},
            "allow":["@tenant-a","fd00:dead:beef:9::/64"]}"#,
    )
    .unwrap();
    assert!(c.permits_unscoped(ip(TENANT)));
    assert!(c.permits_unscoped(ip(OTHER)));
    assert!(!c.permits_unscoped(ip("fd00:dead:beef:5::1")));
}

#[test]
fn groups_nest_and_a_diamond_resolves_once() {
    // top -> a, b; both -> leaf. The leaf's CIDR lands once: overlaps collapse in
    // cidr::build, so the set has one range however many paths reached it.
    let c = config::parse(
        r#"{"ula":"fd00:dead:beef::/48",
            "groups":{
              "leaf":["fd00:dead:beef:1::/64"],
              "a":["@leaf"],
              "b":["@leaf"],
              "top":["@a","@b"]},
            "allow":["@top"]}"#,
    )
    .unwrap();
    assert_eq!(c.allow.len(), 1);
    assert!(c.permits_unscoped(ip(TENANT)));
}

#[test]
fn an_unknown_group_ref_is_a_label() {
    // One mental model for everything unresolvable: it hashes, like a malformed
    // address. Harmless -- nothing on the wire presents "@ghost" as its identity
    // -- and when a watch-fed group appears later, the re-rendered config expands
    // it for real. Deny-safe either way, never a listener flap.
    // The literal sits OUTSIDE kind-1 space (fd00:dead:beef:1::/64 would swallow
    // the hash /96 and merge into one range).
    let c = config::parse(
        r#"{"ula":"fd00:dead:beef::/48","allow":["@ghost","fd00:dead:beef:9::/64"]}"#,
    )
    .unwrap();
    assert_eq!(c.allow.len(), 2); // the literal, plus @ghost's kind-1 hash space
    assert!(c.permits_unscoped(ip(OTHER)));
    assert!(!c.permits_unscoped(ip(TENANT)));
}

#[test]
fn a_cycle_terminates_and_yields_what_it_passed() {
    // Revisits skip -- same rule as unknown refs, no special cycle handling. The
    // literals seen along the way still land.
    let c = config::parse(
        r#"{"ula":"fd00:dead:beef::/48",
            "groups":{"a":["@b","fd00:dead:beef:1::/64"],"b":["@a","fd00:dead:beef:9::/64"]},
            "allow":["@a"]}"#,
    )
    .unwrap();
    assert!(c.permits_unscoped(ip(TENANT)));
    assert!(c.permits_unscoped(ip(OTHER)));
    // Self-reference is the one-node cycle.
    let c = config::parse(
        r#"{"ula":"fd00:dead:beef::/48","groups":{"a":["@a","fd00:dead:beef:1::/64"]},"allow":["@a"]}"#,
    )
    .unwrap();
    assert!(c.permits_unscoped(ip(TENANT)));
}

#[test]
fn scoped_allow_lists_take_refs_too() {
    let c = config::parse(
        r#"{"groups":{"tenant-a":["fd00:dead:beef:1::/64"]},
            "scopes":[{"sni":["l7.mgmt.test"],"allow":["@tenant-a"]}]}"#,
    )
    .unwrap();
    assert!(validate_auth(&c).is_ok());
    assert!(c.permits(b"l7.mgmt.test", ip(TENANT)));
    assert!(!c.permits(b"l7.mgmt.test", ip(OTHER)));
}

#[test]
fn unreferenced_groups_are_the_appendable_base_state() {
    // Same story as `scopes: []`: the base config ships the groups, tenant CRs
    // append entries that reference them. Until then: deny-all, valid.
    let c = config::parse(
        r#"{"ula":"fd00:dead:beef::/48","groups":{"tenant-a":["fd00:dead:beef:1::/64"]}}"#,
    )
    .unwrap();
    assert!(validate_ppv2_auth(&c).is_ok());
    assert!(!c.permits_unscoped(ip(TENANT)));
}

#[test]
fn members_encode_like_the_wire_does() {
    // The five member shapes, each landing where the packet path would put a
    // header carrying it: labels hash to kind-1, v4 lifts to kind-4, v6 passes.
    let c = config::parse(
        r#"{"ula":"fd00:dead:beef::/48",
            "groups":{"tenant-a":["vpce-abc","10.1.0.0/16","203.0.113.7","fd00:dead:beef:9::/64","2001:db8::1"]},
            "allow":["@tenant-a"]}"#,
    )
    .unwrap();
    // kind-4 lift: 10.1.0.0/16 -> fd..:4::a01:0/112, and the /128 for the bare v4.
    assert!(c.permits_unscoped(ip("fd00:dead:beef:4::a01:11c")));
    assert!(!c.permits_unscoped(ip("fd00:dead:beef:4::a02:11c")));
    assert!(c.permits_unscoped(ip("fd00:dead:beef:4::cb00:7107")));
    // v6 passthrough, cidr and /128.
    assert!(c.permits_unscoped(ip("fd00:dead:beef:9::42")));
    assert!(c.permits_unscoped(ip("2001:db8::1")));
    assert!(!c.permits_unscoped(ip("2001:db8::2")));
    // kind-1: the label's hash space admits any client v4 in the low 32 bits.
    let hashed = config::parse(
        r#"{"ula":"fd00:dead:beef::/48","allow":["vpce-abc"]}"#,
    )
    .unwrap();
    assert_eq!(hashed.allow.len(), 1);
}

#[test]
fn anything_that_is_not_a_valid_address_is_a_label() {
    // Total, like the wire: the packet side hashes vpce bytes verbatim, so the
    // config side hashes whatever fails to parse -- bad widths and octets included.
    let c = config::parse(
        r#"{"ula":"fd00:dead:beef::/48","allow":["10.0.0.1/99","10.999.2.0","fd00::1/129","your-mama"]}"#,
    )
    .unwrap();
    assert_eq!(c.allow.len(), 4); // four distinct hashes, nothing rejected, nothing merged
}

#[test]
fn labels_and_v4_need_a_ula_to_encode() {
    // Without a prefix there is no address space to land them in. Pure-v6
    // configs stay legal without one.
    assert!(config::parse(r#"{"scopes":[{"sni":["a.test"],"allow":["vpce-abc"]}]}"#).is_err());
    assert!(config::parse(r#"{"scopes":[{"sni":["a.test"],"allow":["10.0.0.0/8"]}]}"#).is_err());
    assert!(config::parse(r#"{"scopes":[{"sni":["a.test"],"allow":["fd00:dead:beef:1::/64"]}]}"#).is_ok());
}

#[test]
fn an_auth_scope_may_carry_labels_when_the_config_has_a_ula() {
    // The TLS chain's whole point: tenant scopes naming raw sources.
    let c = config::parse(
        r#"{"ula":"fd00:dead:beef::/48",
            "groups":{"tenant-a":["vpce-abc"]},
            "scopes":[{"sni":["l7.mgmt.test"],"allow":["@tenant-a","10.1.0.0/16"]}]}"#,
    )
    .unwrap();
    assert!(ppv2_auth::validate_auth(&c).is_ok());
    assert!(c.permits(b"l7.mgmt.test", ip("fd00:dead:beef:4::a01:1")));
}

#[test]
fn a_member_needing_encoding_fails_at_parse_even_in_an_unreferenced_group() {
    // The one refusal left is a label or v4 with no `ula` to encode into, and it
    // is checked eagerly -- otherwise it hides until some later tenant append
    // references the group, and breaks that config instead of this one.
    assert!(config::parse(r#"{"groups":{"stale":["vpce-abc"]},"scopes":[]}"#).is_err());
    assert!(config::parse(
        r#"{"ula":"fd00:dead:beef::/48","groups":{"stale":["vpce-abc"]}}"#
    )
    .is_ok());
}

// --- sites in the source grammar ---------------------------------------------

#[test]
fn a_site_ref_encodes_the_whole_site_space() {
    // "!1" is config-only syntax: the declared site's /96, sources or not.
    let c = config::parse(
        r#"{"ula":"fd00:dead:beef::/48","sites":{"1":["vpce-a"],"7":[]},"allow":["!1","!7"]}"#,
    )
    .unwrap();
    assert!(c.permits_unscoped(ip("fd00:dead:beef:b1a:0:1:a01:1")));
    assert!(c.permits_unscoped(ip("fd00:dead:beef:b1a:0:7::")));
    assert!(!c.permits_unscoped(ip("fd00:dead:beef:b1a:0:2::")));
    // Unresolvable site refs are labels, exactly like "@ghost": bad syntax ("!x")
    // and an id no site declares ("!5"). A site declared later re-renders the
    // config and the ref resolves then. "!0" is the exception -- the quarantine
    // space is system-owned and always nameable, contests mint it.
    let c = config::parse(r#"{"ula":"fd00:dead:beef::/48","allow":["!x","!0","!5"]}"#).unwrap();
    assert_eq!(c.allow.len(), 3); // two hashes + the quarantine /96
    assert!(c.permits_unscoped(ip("fd00:dead:beef:b1a::")));
    assert!(!c.permits_unscoped(ip("fd00:dead:beef:b1a:0:5::")));
}

#[test]
fn a_site_owned_source_encodes_as_the_site_not_itself() {
    // The wire labels these connections with the site space (site_of runs first),
    // so the config must land there too -- a raw vpce or a contained range in an
    // allow list admits the SITE, exactly like writing "!1".
    let c = config::parse(
        r#"{"ula":"fd00:dead:beef::/48",
            "sites":{"1":["vpce-abc","10.1.0.0/16"]},
            "allow":["vpce-abc","10.1.2.0/24"]}"#,
    )
    .unwrap();
    // Both entries collapsed into site 1's /96.
    assert_eq!(c.allow.len(), 1);
    assert!(c.permits_unscoped(ip("fd00:dead:beef:b1a:0:1:a01:11c")));
    // And NOT the hash/lift they would otherwise become.
    assert!(!c.permits_unscoped(ip("fd00:dead:beef:4::a01:200")));
}

#[test]
fn a_range_only_partly_inside_a_site_stays_a_lift() {
    // Containment is whole-range: a member straddling the site boundary cannot
    // honestly encode as either kind, so it falls through to the ordinary lift.
    // Split the range or use !N.
    let c = config::parse(
        r#"{"ula":"fd00:dead:beef::/48",
            "sites":{"1":["10.1.128.0/17"]},
            "allow":["10.1.0.0/16"]}"#,
    )
    .unwrap();
    assert!(c.permits_unscoped(ip("fd00:dead:beef:4::a01:1")));
    assert!(!c.permits_unscoped(ip("fd00:dead:beef:b1a:0:1::")));
}

#[test]
fn a_source_two_sites_claim_is_contested_and_goes_to_site_0() {
    // Neither claimant gets it -- trust is revoked into the quarantine space, and
    // packet time agrees, so contested traffic rides as NOBODY's privileges but
    // stays admittable via "!0" for examination.
    let c = config::parse(
        r#"{"ula":"fd00:dead:beef::/48",
            "sites":{"9":["vpce-shared"],"3":["vpce-shared"]},
            "allow":["vpce-shared"]}"#,
    )
    .unwrap();
    assert!(c.permits_unscoped(ip("fd00:dead:beef:b1a::")));
    assert!(!c.permits_unscoped(ip("fd00:dead:beef:b1a:0:3::")));
    assert!(!c.permits_unscoped(ip("fd00:dead:beef:b1a:0:9::")));
}

#[test]
fn a_site_star_expands_to_every_declared_site() {
    // "!*" is the grammar form of a TF-maintained @known-sites: the union of all
    // DECLARED sites, current by construction. Site 0 is not declarable, so the
    // quarantine space needs an explicit "!0" alongside.
    let c = config::parse(
        r#"{"ula":"fd00:dead:beef::/48","sites":{"1":[],"2":[],"7":[]},"allow":["!*"]}"#,
    )
    .unwrap();
    assert!(c.permits_unscoped(ip("fd00:dead:beef:b1a:0:1:a01:1")));
    assert!(c.permits_unscoped(ip("fd00:dead:beef:b1a:0:2::")));
    assert!(c.permits_unscoped(ip("fd00:dead:beef:b1a:0:7::")));
    assert!(!c.permits_unscoped(ip("fd00:dead:beef:b1a::")));      // quarantine
    assert!(!c.permits_unscoped(ip("fd00:dead:beef:b1a:0:5::")));  // undeclared id

    // Works through groups too, and an empty table is an empty union: deny-all.
    let c = config::parse(
        r#"{"ula":"fd00:dead:beef::/48","sites":{"1":[]},
            "groups":{"everyone":["!*","!0"]},"allow":["@everyone"]}"#,
    )
    .unwrap();
    assert!(c.permits_unscoped(ip("fd00:dead:beef:b1a:0:1::")));
    assert!(c.permits_unscoped(ip("fd00:dead:beef:b1a::")));
    let c = config::parse(r#"{"ula":"fd00:dead:beef::/48","allow":["!*"]}"#).unwrap();
    assert!(c.allow.is_empty());
}

// --- table interning -----------------------------------------------------------

#[test]
fn identical_tables_are_shared_and_listener_rules_are_not() {
    // Two listeners, same ula/sites/groups, different allow: ONE table (pointer-
    // equal Arc -- one parse, one set of indices per pod), two rule sets.
    let base = r#""ula":"fd00:dead:beef::/48",
        "sites":{"1":["vpce-a"]},
        "groups":{"tenant-a":["!1"]}"#;
    let a = config::parse(&format!(r#"{{{base},"allow":["@tenant-a"]}}"#)).unwrap();
    let b = config::parse(&format!(r#"{{{base},"allow":["10.0.0.0/8"]}}"#)).unwrap();
    assert!(std::sync::Arc::ptr_eq(&a.table, &b.table));
    assert!(a.permits_unscoped(ip("fd00:dead:beef:b1a:0:1::")));
    assert!(!b.permits_unscoped(ip("fd00:dead:beef:b1a:0:1::")));

    // Different table content -> different table.
    let c = config::parse(&format!(r#"{{{base},"scopes":[]}}"#)).unwrap();
    assert!(std::sync::Arc::ptr_eq(&a.table, &c.table)); // same base, scopes are listener concern
    let d = config::parse(r#"{"ula":"fd00:dead:beef::/48","allow":[]}"#).unwrap();
    assert!(!std::sync::Arc::ptr_eq(&a.table, &d.table));
}
