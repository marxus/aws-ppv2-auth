//! filter_config parsing, and the fail-closed choices that depend on it.

use aws_ppv2_identity::{config, identity};

#[test]
fn parses_a_typical_config() {
    let c = config::parse(
        "# tenants\n\
         ula   fd2a:5c1b:7e90::/48\n\
         allow fd2a:5c1b:7e90:1:e3b1:45a8:c041:e80a/128\n\
         \n\
         allow fd2a:5c1b:7e90:4::12c7:0/112\n",
    )
    .unwrap();
    assert_eq!(c.prefix, [0xfd, 0x2a, 0x5c, 0x1b, 0x7e, 0x90]);
    assert_eq!(c.allow.len(), 2);
    assert!(c.require_ppv2);
}

#[test]
fn an_empty_allow_list_denies_everything_it_does_not_disable_enforcement() {
    let c = config::parse("ula fd2a:5c1b:7e90::/48\nrequire_ppv2 false\n").unwrap();
    assert!(!c.require_ppv2);
    // The security-group model: no rule covers it, so nothing is permitted --
    // including a well-formed tenant address. This is the fail-closed
    // direction and the reason there is no `enforce` flag to derive.
    assert!(c.allow.is_empty());
    let tenant = identity::to_u128(
        "fd2a:5c1b:7e90:1:e3b1:45a8:c041:e80a"
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
