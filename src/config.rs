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
