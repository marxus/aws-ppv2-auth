//! filter_config parsing, and the fail-closed choices that depend on it.

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
    assert_eq!(c.prefix, [0xfd, 0x00, 0xde, 0xad, 0xbe, 0xef]);
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
fn typos_and_a_missing_ula_are_errors() {
    assert!(config::parse("ula fd2a::/48\nallwo x\n").is_err());
    assert!(config::parse("allow fd00::/8\n").is_err()); // no ula
    assert!(config::parse("ula 2001:db8::/48\n").is_err()); // not a ULA
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
