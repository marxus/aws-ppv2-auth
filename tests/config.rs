//! Config parsing for both shapes -- the carrier's table and the enforcers'
//! rules -- and the fail-closed choices that depend on them. Grammar/permit
//! checks go through `judge_against` a LOCAL table: the published global is
//! process state shared across test threads, so only the one lifecycle test
//! touches it.

use ppv2_auth::config::{self, Config, Pattern, Table};
use ppv2_auth::{identity, validate_auth, validate_ppv2, validate_ppv2_auth};
use std::sync::Arc;

fn ip(s: &str) -> u128 {
    identity::to_u128(s.parse::<std::net::Ipv6Addr>().unwrap().octets())
}

const TENANT: &str = "fd00:dead:beef:1::1";
const OTHER: &str = "fd00:dead:beef:9::1";

fn table(json: &str) -> Arc<Table> {
    config::parse_table(json).unwrap()
}

fn plain_table() -> Arc<Table> {
    table(r#"{"ula":"fd00:dead:beef::/48"}"#)
}

/// Parse rules, expand them against a local table, judge.
fn judged(rules: &str, t: &Table) -> config::Judged {
    config::parse(rules).unwrap().judge_against(t).unwrap()
}

// --- the two shapes ----------------------------------------------------------

#[test]
fn rules_take_rules_and_the_table_takes_the_table() {
    // An enforcer smuggling table fields fails loudly: the table is the king,
    // and there is exactly one of it, on the carrier.
    for bad in [
        r#"{"ula":"fd00:dead:beef::/48","allow":[]}"#,
        r#"{"sites":{"1":[]},"allow":[]}"#,
        r#"{"groups":{"a":[]},"allow":[]}"#,
        r#"{"subscribe":true,"allow":[]}"#, // the marker era is over; consuming is a given
    ] {
        assert!(config::parse(bad).is_err(), "accepted {bad}");
    }
    // And the mirror: a carrier smuggling rules fails just as loudly.
    for bad in [
        r#"{"ula":"fd00:dead:beef::/48","allow":["10.0.0.0/8"]}"#,
        r#"{"ula":"fd00:dead:beef::/48","scopes":[]}"#,
    ] {
        assert!(config::parse_table(bad).is_err(), "accepted {bad}");
    }
    // The table cannot exist without its ula.
    assert!(config::parse_table(r#"{"sites":{"1":[]}}"#).is_err());
}

#[test]
fn a_typo_fails_the_config_rather_than_disabling_enforcement() {
    assert!(config::parse(r#"{"alloww":[]}"#).is_err());
    assert!(config::parse(r#"{"scopes":[{"snii":["a.test"]}]}"#).is_err());
    assert!(config::parse("not json at all").is_err());
    assert!(config::parse_table(r#"{"ulaa":"fd00:dead:beef::/48"}"#).is_err());
    assert!(config::parse_table(r#"{"ula":"2001:db8::/48"}"#).is_err()); // not a ULA
    assert!(config::parse_table(r#"{"ula":"fd00:dead:beef:1234::/48"}"#).is_err()); // bits below /48
}

#[test]
fn require_ppv2_no_longer_exists_and_a_config_carrying_it_fails() {
    // Deleted by design: each filter_name already says what happens to non-PPv2
    // traffic (refused/dropped, always). deny_unknown_fields makes a leftover
    // config fail its listener loudly instead of quietly meaning nothing.
    assert!(config::parse(r#"{"require_ppv2":false}"#).is_err());
    assert!(config::parse_table(r#"{"ula":"fd00:dead:beef::/48","require_ppv2":true}"#).is_err());
}

// --- which filter takes which rules ------------------------------------------

#[test]
fn each_filter_name_takes_exactly_one_rules_shape() {
    let empty = config::parse("{}").unwrap();
    let flat = config::parse(r#"{"allow":["fd00:dead:beef:1::/64"]}"#).unwrap();
    let scoped =
        config::parse(r#"{"scopes":[{"sni":["a.test"],"allow":["fd00:dead:beef:1::/64"]}]}"#)
            .unwrap();

    // ppv2: label and drain only -- rules would read as applied and do nothing.
    assert!(validate_ppv2(&empty).is_ok());
    assert!(validate_ppv2(&flat).is_err());
    assert!(validate_ppv2(&scoped).is_err());

    // ppv2_auth: the flat list. Empty allow is deny-all, like an empty SG.
    assert!(validate_ppv2_auth(&flat).is_ok());
    assert!(validate_ppv2_auth(&empty).is_ok());
    assert!(validate_ppv2_auth(&scoped).is_err());

    // auth: scopes, and only scopes.
    assert!(validate_auth(&scoped).is_ok());
    assert!(validate_auth(&flat).is_err());
    assert!(validate_auth(&empty).is_err());
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

#[test]
fn an_empty_scopes_array_is_sni_mode_that_denies_everything() {
    // The state a base config ships in so tenant CRs have an array to append to.
    // It must NOT fall through to the flat list -- that is the difference between
    // `scopes` absent and `scopes` present but empty.
    let j = judged(r#"{"scopes":[]}"#, &plain_table());
    assert!(!j.permits(b"anything.test", ip(TENANT)));
    assert!(!j.permits(b"", ip(TENANT)));
}

// --- the source grammar, expanded against a table ------------------------------

#[test]
fn a_flat_allow_list_of_v6_literals() {
    let j = judged(
        r#"{"allow":["fd00:dead:beef:1:7b53:e75b:6e3d:cfdb/128","fd00:dead:beef:4::12c7:0/112"]}"#,
        &plain_table(),
    );
    assert_eq!(j.allow.len(), 2);
    assert!(j.permits_unscoped(ip("fd00:dead:beef:1:7b53:e75b:6e3d:cfdb")));
    assert!(!j.permits_unscoped(ip(OTHER)));
}

#[test]
fn an_allow_entry_may_reference_a_group() {
    let t = table(
        r#"{"ula":"fd00:dead:beef::/48","groups":{"tenant-a":["fd00:dead:beef:1::/64"]}}"#,
    );
    let j = judged(r#"{"allow":["@tenant-a","fd00:dead:beef:9::/64"]}"#, &t);
    assert!(j.permits_unscoped(ip(TENANT)));
    assert!(j.permits_unscoped(ip(OTHER)));
    assert!(!j.permits_unscoped(ip("fd00:dead:beef:5::1")));
}

#[test]
fn groups_nest_and_a_diamond_resolves_once() {
    // top -> a, b; both -> leaf. The leaf's CIDR lands once: overlaps collapse in
    // cidr::build, so the set has one range however many paths reached it.
    let t = table(
        r#"{"ula":"fd00:dead:beef::/48",
            "groups":{
              "leaf":["fd00:dead:beef:1::/64"],
              "a":["@leaf"],
              "b":["@leaf"],
              "top":["@a","@b"]}}"#,
    );
    let j = judged(r#"{"allow":["@top"]}"#, &t);
    assert_eq!(j.allow.len(), 1);
    assert!(j.permits_unscoped(ip(TENANT)));
}

#[test]
fn a_cycle_terminates_and_yields_what_it_passed() {
    // Revisits skip -- same rule as unknown refs, no special cycle handling. The
    // literals seen along the way still land.
    let t = table(
        r#"{"ula":"fd00:dead:beef::/48",
            "groups":{"a":["@b","fd00:dead:beef:1::/64"],"b":["@a","fd00:dead:beef:9::/64"]}}"#,
    );
    let j = judged(r#"{"allow":["@a"]}"#, &t);
    assert!(j.permits_unscoped(ip(TENANT)));
    assert!(j.permits_unscoped(ip(OTHER)));
    // Self-reference is the one-node cycle.
    let t = table(
        r#"{"ula":"fd00:dead:beef::/48","groups":{"a":["@a","fd00:dead:beef:1::/64"]}}"#,
    );
    assert!(judged(r#"{"allow":["@a"]}"#, &t).permits_unscoped(ip(TENANT)));
}

#[test]
fn an_unknown_group_ref_is_a_label() {
    // One mental model for everything unresolvable: it hashes, like a malformed
    // address. Harmless -- nothing on the wire presents "@ghost" as its identity
    // -- and when the group appears later, the re-rendered table expands it for
    // real. Deny-safe either way. The literal sits OUTSIDE kind-1 space
    // (fd00:dead:beef:1::/64 would swallow the hash /96 and merge into one range).
    let j = judged(r#"{"allow":["@ghost","fd00:dead:beef:9::/64"]}"#, &plain_table());
    assert_eq!(j.allow.len(), 2); // the literal, plus @ghost's kind-1 hash space
    assert!(j.permits_unscoped(ip(OTHER)));
    assert!(!j.permits_unscoped(ip(TENANT)));
}

#[test]
fn members_encode_like_the_wire_does() {
    // The five source shapes, each landing where the packet path would put a
    // header carrying it: labels hash to kind-1, v4 lifts to kind-4, v6 passes.
    let t = table(
        r#"{"ula":"fd00:dead:beef::/48",
            "groups":{"tenant-a":["vpce-abc","10.1.0.0/16","203.0.113.7","fd00:dead:beef:9::/64","2001:db8::1"]}}"#,
    );
    let j = judged(r#"{"allow":["@tenant-a"]}"#, &t);
    assert!(j.permits_unscoped(ip("fd00:dead:beef:4::a01:11c")));
    assert!(!j.permits_unscoped(ip("fd00:dead:beef:4::a02:11c")));
    assert!(j.permits_unscoped(ip("fd00:dead:beef:4::cb00:7107")));
    assert!(j.permits_unscoped(ip("fd00:dead:beef:9::42")));
    assert!(j.permits_unscoped(ip("2001:db8::1")));
    assert!(!j.permits_unscoped(ip("2001:db8::2")));
}

#[test]
fn anything_that_is_not_a_valid_address_is_a_label() {
    // Total, like the wire: the packet side hashes vpce bytes verbatim, so the
    // config side hashes whatever fails to parse -- bad widths and octets included.
    let j = judged(
        r#"{"allow":["10.0.0.1/99","10.999.2.0","fd00::1/129","your-mama"]}"#,
        &plain_table(),
    );
    assert_eq!(j.allow.len(), 4); // four distinct hashes, nothing rejected, nothing merged
}

// --- sites in the grammar ------------------------------------------------------

#[test]
fn a_site_ref_encodes_the_whole_site_space() {
    // "!1" is config-only syntax: the declared site's /96, sources or not.
    let t = table(r#"{"ula":"fd00:dead:beef::/48","sites":{"1":["vpce-a"],"7":[]}}"#);
    let j = judged(r#"{"allow":["!1","!7"]}"#, &t);
    assert!(j.permits_unscoped(ip("fd00:dead:beef:b1a:0:1:a01:1")));
    assert!(j.permits_unscoped(ip("fd00:dead:beef:b1a:0:7::")));
    assert!(!j.permits_unscoped(ip("fd00:dead:beef:b1a:0:2::")));

    // Unresolvable site refs are labels, exactly like "@ghost": bad syntax ("!x",
    // "!0"-as-tenant) and an id no site declares ("!5"). "!0" is the exception --
    // the quarantine space is system-owned and always nameable, contests mint it.
    let j = judged(r#"{"allow":["!x","!0","!5"]}"#, &plain_table());
    assert_eq!(j.allow.len(), 3); // two hashes + the quarantine /96
    assert!(j.permits_unscoped(ip("fd00:dead:beef:b1a::")));
    assert!(!j.permits_unscoped(ip("fd00:dead:beef:b1a:0:5::")));
}

#[test]
fn a_site_star_expands_to_every_declared_site() {
    // "!*" is the union of all DECLARED sites, current by construction. Site 0 is
    // not declarable, so the quarantine space needs an explicit "!0" alongside.
    let t = table(r#"{"ula":"fd00:dead:beef::/48","sites":{"1":[],"2":[],"7":[]}}"#);
    let j = judged(r#"{"allow":["!*"]}"#, &t);
    assert!(j.permits_unscoped(ip("fd00:dead:beef:b1a:0:1:a01:1")));
    assert!(j.permits_unscoped(ip("fd00:dead:beef:b1a:0:2::")));
    assert!(j.permits_unscoped(ip("fd00:dead:beef:b1a:0:7::")));
    assert!(!j.permits_unscoped(ip("fd00:dead:beef:b1a::")));
    assert!(!j.permits_unscoped(ip("fd00:dead:beef:b1a:0:5::")));

    // Through groups too, and an empty table is an empty union: deny-all.
    let t2 = table(
        r#"{"ula":"fd00:dead:beef::/48","sites":{"1":[]},"groups":{"everyone":["!*","!0"]}}"#,
    );
    let j = judged(r#"{"allow":["@everyone"]}"#, &t2);
    assert!(j.permits_unscoped(ip("fd00:dead:beef:b1a:0:1::")));
    assert!(j.permits_unscoped(ip("fd00:dead:beef:b1a::")));
    assert!(judged(r#"{"allow":["!*"]}"#, &plain_table()).allow.is_empty());
}

#[test]
fn a_site_owned_source_encodes_as_the_site_not_itself() {
    // The wire labels these connections with the site space (site_of runs first),
    // so the config must land there too -- a raw vpce or a contained range in an
    // allow list admits the SITE, exactly like writing "!1".
    let t = table(r#"{"ula":"fd00:dead:beef::/48","sites":{"1":["vpce-abc","10.1.0.0/16"]}}"#);
    let j = judged(r#"{"allow":["vpce-abc","10.1.2.0/24"]}"#, &t);
    assert_eq!(j.allow.len(), 1); // both entries collapsed into site 1's /96
    assert!(j.permits_unscoped(ip("fd00:dead:beef:b1a:0:1:a01:11c")));
    assert!(!j.permits_unscoped(ip("fd00:dead:beef:4::a01:200")));
}

#[test]
fn a_range_only_partly_inside_a_site_stays_a_lift() {
    // Containment is whole-range: a member straddling the site boundary cannot
    // honestly encode as either kind, so it falls through to the ordinary lift.
    // Split the range or use !N.
    let t = table(r#"{"ula":"fd00:dead:beef::/48","sites":{"1":["10.1.128.0/17"]}}"#);
    let j = judged(r#"{"allow":["10.1.0.0/16"]}"#, &t);
    assert!(j.permits_unscoped(ip("fd00:dead:beef:4::a01:1")));
    assert!(!j.permits_unscoped(ip("fd00:dead:beef:b1a:0:1::")));
}

#[test]
fn a_source_two_sites_claim_is_contested_and_goes_to_site_0() {
    // Neither claimant gets it -- trust is revoked into the quarantine space, and
    // packet time agrees (same indices), so contested traffic rides as NOBODY's
    // privileges but stays admittable via "!0" for examination.
    let t = table(
        r#"{"ula":"fd00:dead:beef::/48","sites":{"9":["vpce-shared"],"3":["vpce-shared"]}}"#,
    );
    let j = judged(r#"{"allow":["vpce-shared"]}"#, &t);
    assert!(j.permits_unscoped(ip("fd00:dead:beef:b1a::")));
    assert!(!j.permits_unscoped(ip("fd00:dead:beef:b1a:0:3::")));
    assert!(!j.permits_unscoped(ip("fd00:dead:beef:b1a:0:9::")));
}

// --- the site table's own shape -------------------------------------------------

#[test]
fn sites_take_endpoint_ids_and_prefixes_of_either_family() {
    let t = table(
        r#"{"ula":"fd00:dead:beef::/48",
            "sites":{"1":["vpce-028ff61de1d1fea8c","3.126.239.93/32"],
                     "2":["203.0.113.0/24","2001:db8::/32"],
                     "3":["vpce-0aaa","vpce-0bbb"]}}"#,
    );
    let s = &t.scheme;
    assert_eq!(s.sites.len(), 3);
    assert_eq!(s.sites.iter().map(|x| x.id).collect::<Vec<_>>(), vec![1, 2, 3]);
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
    let t = table(r#"{"ula":"fd00:dead:beef::/48","sites":{"5":["198.51.100.7"]}}"#);
    let s = &t.scheme.sites[0];
    assert!(s.cidrs.contains(ip("::ffff:198.51.100.7")));
    assert!(!s.cidrs.contains(ip("::ffff:198.51.100.8")));
}

#[test]
fn a_malformed_site_fails_the_config() {
    // Same rule as ever: a typo must fail rather than silently shrink the table,
    // which would quietly demote a tenant to the fallback ULA.
    for bad in [
        r#"{"ula":"fd00:dead:beef::/48","sites":{"nope":["vpce-a"]}}"#,
        r#"{"ula":"fd00:dead:beef::/48","sites":{"0":["vpce-a"]}}"#,
        r#"{"ula":"fd00:dead:beef::/48","sites":{"70000":["vpce-a"]}}"#,
        r#"{"ula":"fd00:dead:beef::/48","sites":{"1":["10.0.0.0/40"]}}"#,
        r#"{"ula":"fd00:dead:beef::/48","sites":{"1":["10.0.0.0/x"]}}"#,
    ] {
        assert!(config::parse_table(bad).is_err(), "accepted {bad}");
    }
}

#[test]
fn a_map_cannot_say_one_id_twice() {
    // A JSON map key is unique by construction; "01" aliases to the same id and
    // both survive as table entries -- the contested tiebreak keeps lookups
    // deterministic anyway.
    let t = table(r#"{"ula":"fd00:dead:beef::/48","sites":{"1":["vpce-a"],"01":["vpce-b"]}}"#);
    assert_eq!(t.scheme.sites.len(), 2);
}

// --- scopes and SNI matching ----------------------------------------------------

#[test]
fn a_scope_may_name_several_hostnames_sharing_one_list() {
    // The shape Envoy's ServerNameMatcher uses: one `domains` list, one action.
    let j = judged(
        r#"{"scopes":[{"sni":["l7.mgmt.test","*.pass.mgmt.test"],"allow":["fd00:dead:beef:1::/64","fd00:dead:beef:4::/64"]}]}"#,
        &plain_table(),
    );
    let scopes = j.scopes.as_ref().unwrap();
    assert_eq!(scopes.len(), 1);
    assert_eq!(scopes[0].names[0], Pattern::Exact("l7.mgmt.test".into()));
    assert_eq!(scopes[0].names[1], Pattern::Suffix("pass.mgmt.test".into()));
    assert!(j.permits(b"l7.mgmt.test", ip(TENANT)));
    assert!(j.permits(b"a.pass.mgmt.test", ip(TENANT)));
}

#[test]
fn scoped_allow_lists_take_the_grammar_too() {
    let t = table(
        r#"{"ula":"fd00:dead:beef::/48",
            "sites":{"1":["vpce-a"]},
            "groups":{"tenant-a":["vpce-abc"]}}"#,
    );
    let j = judged(
        r#"{"scopes":[{"sni":["l7.mgmt.test"],"allow":["@tenant-a","!1","10.1.0.0/16"]}]}"#,
        &t,
    );
    assert!(j.permits(b"l7.mgmt.test", ip("fd00:dead:beef:b1a:0:1::5"))); // !1
    assert!(j.permits(b"l7.mgmt.test", ip("fd00:dead:beef:4::a01:1"))); // the lift
    assert!(!j.permits(b"other.test", ip("fd00:dead:beef:b1a:0:1::5")));
}

#[test]
fn exact_beats_wildcard_regardless_of_config_order() {
    let j = judged(
        r#"{"scopes":[
            {"sni":["*.mgmt.test"],"allow":["fd00:dead:beef:9::/64"]},
            {"sni":["a.mgmt.test"],"allow":["fd00:dead:beef:1::/64"]}]}"#,
        &plain_table(),
    );
    assert!(j.permits(b"a.mgmt.test", ip(TENANT)));
    assert!(!j.permits(b"a.mgmt.test", ip(OTHER)));
    assert!(j.permits(b"b.mgmt.test", ip(OTHER)));
}

#[test]
fn wildcards_are_tried_longest_suffix_first() {
    let j = judged(
        r#"{"scopes":[
            {"sni":["*.test"],"allow":["fd00:dead:beef:9::/64"]},
            {"sni":["*.mgmt.test"],"allow":["fd00:dead:beef:1::/64"]}]}"#,
        &plain_table(),
    );
    assert!(j.permits(b"a.mgmt.test", ip(TENANT)));
    assert!(!j.permits(b"a.mgmt.test", ip(OTHER)));
    assert!(j.permits(b"a.other.test", ip(OTHER)));
}

#[test]
fn a_wildcard_matches_one_label_and_more_but_never_the_parent() {
    let j = judged(
        r#"{"scopes":[{"sni":["*.mgmt.test"],"allow":["fd00:dead:beef:1::/64"]}]}"#,
        &plain_table(),
    );
    assert!(j.permits(b"a.mgmt.test", ip(TENANT)));
    assert!(j.permits(b"a.b.mgmt.test", ip(TENANT)));
    assert!(!j.permits(b"mgmt.test", ip(TENANT)));
}

#[test]
fn a_partial_wildcard_is_not_a_wildcard() {
    // `foo.*` and `*bla` are kept as literal strings rather than rejected, so
    // they never match a real SNI -- erring toward deny.
    let j = judged(
        r#"{"scopes":[{"sni":["foo.*","*bla.test"],"allow":["fd00:dead:beef:1::/64"]}]}"#,
        &plain_table(),
    );
    assert!(!j.permits(b"foo.test", ip(TENANT)));
    assert!(!j.permits(b"xbla.test", ip(TENANT)));
}

#[test]
fn sni_matching_is_case_insensitive_on_both_sides() {
    let j = judged(
        r#"{"scopes":[{"sni":["L7.Mgmt.Test"],"allow":["fd00:dead:beef:1::/64"]}]}"#,
        &plain_table(),
    );
    assert!(j.permits(b"l7.mgmt.test", ip(TENANT)));
    assert!(j.permits(b"L7.MGMT.TEST", ip(TENANT)));
}

#[test]
fn duplicate_names_take_the_first_scope() {
    let j = judged(
        r#"{"scopes":[
            {"sni":["a.test"],"allow":["fd00:dead:beef:1::/64"]},
            {"sni":["a.test"],"allow":["fd00:dead:beef:9::/64"]}]}"#,
        &plain_table(),
    );
    assert!(j.permits(b"a.test", ip(TENANT)));
    assert!(!j.permits(b"a.test", ip(OTHER)));
}

#[test]
fn an_unmatched_sni_does_not_fall_back_to_the_flat_list() {
    // scopes present = SNI mode. The flat allow is not consulted, so a stray
    // scope cannot silently widen an allowlist.
    let j = judged(
        r#"{"scopes":[{"sni":["a.test"],"allow":["fd00:dead:beef:1::/64"]}]}"#,
        &plain_table(),
    );
    assert!(!j.permits(b"other.test", ip(TENANT)));
    assert!(!j.permits(b"", ip(TENANT)));
}

// --- the published table lifecycle (the ONE test that touches the global) -------

#[test]
fn enforcers_follow_the_published_table() {
    // Everything here is relative to this test's own publishes -- other tests
    // never touch the global, so order within it is the only order that matters.
    let consumer = config::parse(r#"{"allow":["@tenant-a","!1"]}"#).unwrap();

    config::publish(table(
        r#"{"ula":"fd00:dead:beef::/48",
            "sites":{"1":["vpce-a"]},
            "groups":{"tenant-a":["203.0.113.7"]}}"#,
    ));
    assert!(consumer.permits_unscoped(ip("fd00:dead:beef:b1a:0:1:a01:1"))); // !1
    assert!(consumer.permits_unscoped(ip("fd00:dead:beef:4::cb00:7107"))); // @tenant-a's lift
    assert!(!consumer.permits_unscoped(ip("fd00:dead:beef:b1a:0:2::")));

    // A new table re-expands the same raw rules: tenant-a moves, site 2 appears.
    config::publish(table(
        r#"{"ula":"fd00:dead:beef::/48",
            "sites":{"1":["vpce-a"],"2":[]},
            "groups":{"tenant-a":["!2"]}}"#,
    ));
    assert!(consumer.permits_unscoped(ip("fd00:dead:beef:b1a:0:2::")));
    assert!(!consumer.permits_unscoped(ip("fd00:dead:beef:4::cb00:7107")));
    assert!(consumer.permits_unscoped(ip("fd00:dead:beef:b1a:0:1:a01:1")));
}
