//! filter_config, shared by both filters. Arrives as a StringValue, which the
//! proto passes through unwrapped.
//!
//! ```text
//! ula          fd2a:5c1b:7e90::/48
//! allow        fd2a:5c1b:7e90:1:e3b1:45a8:c041:e80a/128
//! require_ppv2 false
//! ```
//!
//! `allow` is read by the UDP filter only -- it has no way to hand an identity
//! downstream, so it enforces here. The TCP filter uses set_remote_address and
//! lets a SecurityPolicy match; leave `allow` unset there.
//!
//! ALLOWLIST ONLY, LIKE A SECURITY GROUP. There is no deny form and no implicit
//! permit: an address is allowed iff some `allow` line covers it. So an empty
//! list denies everything, which is why there is no `enforce` flag -- a flag
//! derived from "is the list non-empty" would turn the one safe state into
//! allow-any, and commenting out the last entry to debug would silently open
//! the listener.
//!
//! filter_config rather than a mounted file, because editing the
//! EnvoyPatchPolicy triggers an LDS update and config_new runs again. A
//! ConfigMap file would need a pod restart.

use crate::{cidr, identity};

#[derive(Debug)]
pub struct Config {
    pub prefix: identity::Prefix,
    /// UDP only. Allowlist semantics: empty denies everything.
    pub allow: cidr::Set,
    /// Drop anything without a PROXY header. Behind an NLB every client has one.
    pub require_ppv2: bool,
}

pub fn parse(text: &str) -> Result<Config, &'static str> {
    let mut prefix: Option<identity::Prefix> = None;
    let mut require_ppv2 = true;
    let mut allow = String::new();

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, val) = match line.split_once(char::is_whitespace) {
            Some((k, v)) => (k, v.trim()),
            None => (line, ""),
        };
        match key {
            "ula" => prefix = Some(identity::parse_prefix(val)?),
            "allow" => {
                allow.push_str(val);
                allow.push(',');
            }
            "require_ppv2" => require_ppv2 = val != "false",
            // Unknown keys are an error rather than ignored, so a typo fails the
            // config instead of silently disabling enforcement.
            _ => return Err("unknown config key"),
        }
    }

    Ok(Config {
        prefix: prefix.ok_or("missing required `ula`")?,
        allow: cidr::build(&allow)?,
        require_ppv2,
    })
}

// --------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_typical_config() {
        let c = parse(
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
        let c = parse("ula fd2a:5c1b:7e90::/48\nrequire_ppv2 false\n").unwrap();
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
        assert!(parse("ula fd2a::/48\nallwo x\n").is_err());
        assert!(parse("allow fd00::/8\n").is_err()); // no ula
        assert!(parse("ula 2001:db8::/48\n").is_err()); // not a ULA
    }
}
