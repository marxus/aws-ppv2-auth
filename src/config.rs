//! filter_config, shared by both filters. Arrives as an unwrapped StringValue.
//! See README for the format and the filter chain shapes.
//!
//! ```text
//! ula   fd00:dead:beef::/48
//! sni   l7.mgmt.test
//! allow fd00:dead:beef:1:7b53:e75b:6e3d:cfdb/128
//! sni   tcp.mgmt.test
//! allow fd00:dead:beef:4::a01:0/112
//! ```
//!
//! `sni` opens a scope: every `allow` after it belongs to that hostname. An `allow`
//! before any `sni` joins the flat list, which is what a listener without SNI uses.
//!
//! `ula` and `sni` are the two ways `auth` can learn an identity and are mutually
//! exclusive -- see validate_auth in lib.rs. `ula` means it runs before
//! tls_inspector and parses the header itself; `sni` means it runs after, and a
//! `ppv2` filter already labelled the socket.
//!
//! Deny by default. No scope matches the SNI, or none covers the identity, and the
//! connection is closed -- which is why there is no `enforce` flag: deriving one
//! from "is the list non-empty" would make the safe state mean allow-any.

use crate::{cidr, identity};

#[derive(Debug)]
pub struct Config {
    /// Present when this filter derives identity itself by parsing PPv2. Absent on
    /// the `auth` filter of a TLS chain, where `ppv2` already labelled the socket.
    pub prefix: Option<identity::Prefix>,
    /// Used when there are no `sni` scopes.
    pub allow: cidr::Set,
    /// Hostname scopes in config order, each with its own list.
    pub scopes: Vec<(Pattern, cidr::Set)>,
    /// Drop anything without a PROXY header.
    pub require_ppv2: bool,
}

impl Config {
    /// Deny by default: false unless a list covers this identity.
    pub fn permits(&self, sni: &[u8], addr: u128) -> bool {
        self.allowlist_for(sni)
            .is_some_and(|set| set.contains(addr))
    }

    /// The list this connection is judged against, or None if no scope claims it.
    ///
    /// Envoy's ServerNameMatcher order (domain_matcher.h:78-101): exact first, then
    /// wildcards longest-suffix-first. The walk consumes through each dot, so the
    /// loop variable IS the next candidate -- `a.b.foo.com` probes `b.foo.com`,
    /// then `foo.com`, then `com`.
    fn allowlist_for(&self, sni: &[u8]) -> Option<&cidr::Set> {
        if self.scopes.is_empty() {
            return Some(&self.allow);
        }
        // Empty SNI claims nothing, per domain_matcher.h:74-76.
        if sni.is_empty() {
            return None;
        }

        if let Some(set) = self.find(|p| matches!(p, Pattern::Exact(e) if eq_fold(e, sni))) {
            return Some(set);
        }
        let mut rest = sni;
        while let Some(i) = rest.iter().position(|&b| b == b'.') {
            rest = &rest[i + 1..];
            if let Some(set) = self.find(|p| matches!(p, Pattern::Suffix(s) if eq_fold(s, rest))) {
                return Some(set);
            }
        }
        None
    }

    fn find(&self, f: impl Fn(&Pattern) -> bool) -> Option<&cidr::Set> {
        self.scopes.iter().find(|(p, _)| f(p)).map(|(_, set)| set)
    }
}

/// A `sni` pattern, stored ASCII-lowercased.
///
/// `Suffix` holds the hostname with `*.` already stripped, so `*.foo.com` becomes
/// `Suffix("foo.com")` -- the shape domain_matcher.h:264-267 uses.
#[derive(Debug, PartialEq, Eq)]
pub enum Pattern {
    Exact(String),
    Suffix(String),
}

impl Pattern {
    fn parse(text: &str) -> Pattern {
        let lower = text.to_ascii_lowercase();
        // Only a whole leading `*.` is a wildcard (domain_matcher.h:225). Anything
        // else -- `foo.*`, `*bla.com` -- stays Exact, so it never matches a real SNI
        // rather than failing the config. Erring toward deny, not toward allow.
        match lower.strip_prefix("*.") {
            Some(rest) if !rest.is_empty() => Pattern::Suffix(rest.to_string()),
            _ => Pattern::Exact(lower),
        }
    }
}

/// Compare a lowercased pattern against raw SNI bytes, folding as we go.
///
/// The fold on the pattern side happens once at parse. Envoy's own domain_matcher
/// never folds its config, so a config written `L7.Mgmt.Test` silently never
/// matches there -- the SNI always arrives lowercased from the socket. We fold both
/// sides. SNI is ASCII by spec, so this needs no allocation and no UTF-8 check.
fn eq_fold(pat: &str, sni: &[u8]) -> bool {
    pat.len() == sni.len()
        && pat
            .bytes()
            .zip(sni.iter())
            .all(|(p, s)| p == s.to_ascii_lowercase())
}

pub fn parse(text: &str) -> Result<Config, &'static str> {
    let mut prefix: Option<identity::Prefix> = None;
    let mut require_ppv2 = true;
    let mut flat: Vec<&str> = Vec::new();
    // The open scope is the last entry, so `allow` appends to it.
    let mut scopes: Vec<(Pattern, Vec<&str>)> = Vec::new();

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
            "sni" => scopes.push((Pattern::parse(val), Vec::new())),
            "allow" => match scopes.last_mut() {
                Some((_, lines)) => lines.push(val),
                None => flat.push(val),
            },
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

    let allow = cidr::build_from(flat.into_iter())?;
    let scopes = scopes
        .into_iter()
        .map(|(pat, lines)| cidr::build_from(lines.into_iter()).map(|set| (pat, set)))
        .collect::<Result<Vec<_>, _>>()?;

    // With require_ppv2 off, unparseable traffic passes through -- straight past
    // every rule. Refuse the combination rather than document it.
    if !require_ppv2 && !(allow.is_empty() && scopes.is_empty()) {
        return Err("`require_ppv2 false` passes unparseable traffic straight past `allow`");
    }

    Ok(Config {
        prefix,
        allow,
        scopes,
        require_ppv2,
    })
}
