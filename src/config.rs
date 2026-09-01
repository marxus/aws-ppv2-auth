//! filter_config, shared by both filters. Arrives as an unwrapped StringValue.
//!
//! ```text
//! ula          fd2a:5c1b:7e90::/48
//! allow        fd2a:5c1b:7e90:1:e3b1:45a8:c041:e80a/128
//! require_ppv2 true
//! ```
//!
//! Allowlist only, like a security group: allowed iff some `allow` line covers
//! it, so an empty list denies everything. That is why there is no `enforce`
//! flag -- deriving one from "is the list non-empty" would turn the safe state
//! into allow-any.
//!
//! `allow` is UDP-only, and a TCP config carrying it is rejected rather than
//! silently ignored. `require_ppv2 false` plus a non-empty `allow` is rejected
//! too: the allowlist is only consulted on a header that parsed.
//!
//! filter_config rather than a file, because editing the EnvoyPatchPolicy is an
//! LDS update and reruns config_new; a ConfigMap would need a pod restart.

use crate::{cidr, identity};

#[derive(Debug)]
pub struct Config {
    pub prefix: identity::Prefix,
    /// UDP only. Empty denies everything.
    pub allow: cidr::Set,
    /// Drop anything without a PROXY header.
    pub require_ppv2: bool,
}

pub fn parse(text: &str) -> Result<Config, &'static str> {
    let mut prefix: Option<identity::Prefix> = None;
    let mut require_ppv2 = true;
    let mut allow: Vec<&str> = Vec::new();

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
            "allow" => allow.push(val),
            // Strict, like unknown keys: `require_ppv2 no` silently meaning
            // `true` is found during an incident, not before one.
            "require_ppv2" => {
                require_ppv2 = match val {
                    "true" => true,
                    "false" => false,
                    _ => return Err("require_ppv2 must be true or false"),
                }
            }
            // A typo must fail the config, not silently disable enforcement.
            _ => return Err("unknown config key"),
        }
    }

    let allow = cidr::build_from(allow.into_iter())?;
    // With require_ppv2 off, unparseable traffic passes through -- straight past
    // every `allow` line. Refuse the combination rather than document it.
    if !require_ppv2 && !allow.is_empty() {
        return Err("`require_ppv2 false` passes unparseable traffic straight past `allow`");
    }

    Ok(Config {
        prefix: prefix.ok_or("missing required `ula`")?,
        allow,
        require_ppv2,
    })
}
