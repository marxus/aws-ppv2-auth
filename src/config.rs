//! filter_config, shared by both filters. Arrives as a StringValue, which the
//! proto passes through unwrapped.
//!
//! ```text
//! ula          fd2a:5c1b:7e90::/48
//! allow        fd2a:5c1b:7e90:1:e3b1:45a8:c041:e80a/128
//! require_ppv2 true
//! ```
//!
//! `allow` is read by the UDP filter only -- it has no way to hand an identity
//! downstream, so it enforces here. The TCP filter uses set_remote_address and
//! lets a SecurityPolicy match, and REJECTS a config carrying `allow`: a rule
//! it cannot enforce should fail the listener, not read as applied.
//!
//! `require_ppv2 false` and a non-empty `allow` are rejected together. The
//! allowlist is only consulted on a header that parsed, so passing unparseable
//! traffic through walks straight past every rule.
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
            // Strict, for the same reason unknown keys are: `require_ppv2 no`
            // silently meaning `true` is the kind of thing found during an
            // incident, not before one.
            "require_ppv2" => {
                require_ppv2 = match val {
                    "true" => true,
                    "false" => false,
                    _ => return Err("require_ppv2 must be true or false"),
                }
            }
            // Unknown keys are an error rather than ignored, so a typo fails the
            // config instead of silently disabling enforcement.
            _ => return Err("unknown config key"),
        }
    }

    let allow = cidr::build_from(allow.into_iter())?;
    // The UDP filter only consults the allowlist on a header it parsed. With
    // require_ppv2 off, anything unparseable is passed through instead --
    // straight past every `allow` line. Writing both is asking for an allowlist
    // that is not one, so refuse the combination rather than document it.
    if !require_ppv2 && !allow.is_empty() {
        return Err("`require_ppv2 false` passes unparseable traffic straight past `allow`");
    }

    Ok(Config {
        prefix: prefix.ok_or("missing required `ula`")?,
        allow,
        require_ppv2,
    })
}
